"""VIGIL AI Engine.

Listens for AttackState changes on Kafka, generates narratives via Claude,
PATCHes them back to attack-state-engine. Exposes a small REST API for
manual triggers, health, and the runtime kill switch.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Optional

import httpx
import structlog
import uvicorn
from anthropic import Anthropic
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from . import agent_tools
from .budget import CallBudget
from .cache import NarrativeCache
from .config import AIEngineConfig, get_config
from .consumer import NarrativeConsumer, build_consumer
from .narrator import CircuitOpen, Narrator

logger = structlog.get_logger(__name__)


class AIEngine:
    def __init__(self, config: AIEngineConfig):
        self.config = config
        self.narrator: Optional[Narrator] = None
        self.cache: Optional[NarrativeCache] = None
        self.budget: Optional[CallBudget] = None
        self.consumer: Optional[NarrativeConsumer] = None
        self._consumer_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if not self.config.anthropic_enabled:
            logger.warning("ai_engine.anthropic_disabled — returning stub narratives")
        elif not self.config.anthropic_api_key:
            logger.warning("ai_engine.no_api_key — narrator calls will fail")

        # max_retries=0: the SDK retries 2x by default, which silently triples
        # cost on transient errors. We surface failures to the breaker instead.
        client = Anthropic(
            api_key=self.config.anthropic_api_key or "missing",
            max_retries=0,
        )
        self.narrator = Narrator(
            client=client,
            model=self.config.anthropic_model,
            enabled=self.config.anthropic_enabled,
            consecutive_error_limit=self.config.anthropic_consecutive_error_limit,
        )

        self.cache = await NarrativeCache.from_url(
            self.config.redis_url, self.config.narrative_cache_ttl_seconds
        )
        # Reuse the same Redis client for the daily budget — same DB index,
        # different key prefix.
        self.budget = CallBudget(
            self.cache._client,  # noqa: SLF001 — intentional shared client
            self.config.anthropic_daily_call_budget,
        )
        logger.info(
            "ai_engine.budget.configured",
            daily_limit=self.budget.limit,
            consecutive_error_limit=self.config.anthropic_consecutive_error_limit,
        )

        self.consumer = build_consumer(
            narrator=self.narrator, cache=self.cache, budget=self.budget, cfg=self.config
        )
        try:
            self.consumer.connect()
            self._consumer_task = asyncio.create_task(self.consumer.run())
        except Exception as e:
            logger.warning("ai_engine.consumer_unavailable", error=str(e))

        logger.info("ai_engine.started")

    async def stop(self) -> None:
        if self.consumer:
            self.consumer.stop()
            self.consumer.disconnect()
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.cache:
            await self.cache.close()


_engine: Optional[AIEngine] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine
    cfg = get_config()
    _engine = AIEngine(cfg)
    await _engine.start()
    try:
        yield
    finally:
        if _engine:
            await _engine.stop()


def _check_admin(x_internal_key: Optional[str]) -> None:
    cfg = get_config()
    if not x_internal_key or x_internal_key != cfg.internal_api_key:
        raise HTTPException(status_code=401, detail="bad internal key")


def create_app() -> FastAPI:
    app = FastAPI(title="VIGIL AI Engine", version="0.1.0", lifespan=lifespan)

    @app.get("/health")
    async def health():
        if _engine is None:
            return JSONResponse(
                {"status": "starting", "service": "ai-engine", "version": "0.1.0"},
                status_code=503,
            )
        consumer_ok = _engine.consumer is not None and _engine.consumer.is_connected()
        budget_used = await _engine.budget.current() if _engine.budget else 0
        return {
            "status": "ok" if consumer_ok else "degraded",
            "service": "ai-engine",
            "version": "0.1.0",
            "consumer_connected": consumer_ok,
            "processed": _engine.consumer.processed if _engine.consumer else 0,
            "errors": _engine.consumer.errors if _engine.consumer else 0,
            "narrator": {
                "enabled": _engine.narrator._enabled if _engine.narrator else False,
                "circuit_open": _engine.narrator.circuit_open if _engine.narrator else False,
                "consecutive_errors": (
                    _engine.narrator.consecutive_errors if _engine.narrator else 0
                ),
            },
            "budget": {
                "daily_limit": _engine.budget.limit if _engine.budget else 0,
                "used_today": budget_used,
            },
            "agent_retrieval": {
                "enabled": agent_tools.retrieval_enabled(),
                "max_steps": agent_tools.MAX_INVESTIGATION_STEPS,
            },
        }

    @app.post("/generate")
    async def generate_with_body(body: dict):
        """Manual trigger taking the AttackState as the body."""
        if (
            _engine is None
            or _engine.narrator is None
            or _engine.cache is None
            or _engine.budget is None
        ):
            raise HTTPException(status_code=503, detail="Engine not ready")

        attack_id = body.get("attack_id")
        if not attack_id:
            raise HTTPException(status_code=400, detail="attack_id required")

        confidence = float(body.get("confidence") or 0.0)

        cached = await _engine.cache.get(attack_id, confidence)
        if cached is not None:
            logger.info("ai_engine.manual_generate.cache_hit", attack_id=attack_id)
            return cached

        # Budget check BEFORE the Anthropic call. If the cap is hit, return a
        # stub PATCH body — caller still gets a valid response, no spend.
        allowed, count = await _engine.budget.try_consume()
        if not allowed:
            logger.warning(
                "ai_engine.manual_generate.budget_exhausted",
                attack_id=attack_id,
                count=count,
                limit=_engine.budget.limit,
            )
            raise HTTPException(
                status_code=429,
                detail=f"daily Claude budget exhausted ({count}/{_engine.budget.limit})",
            )

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, _engine.narrator.generate, body)
        except CircuitOpen as e:
            raise HTTPException(status_code=503, detail=str(e))
        except Exception as e:
            logger.warning("ai_engine.manual_generate.failed", error_type=type(e).__name__)
            raise HTTPException(status_code=502, detail="Narrative generation failed")

        patch_body = result.to_patch_body()

        cfg = _engine.config
        url = f"{cfg.attack_state_engine_url.rstrip('/')}/attacks/{attack_id}/narrative"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.patch(
                url,
                headers={"X-Internal-Key": cfg.internal_api_key},
                json=patch_body,
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"PATCH failed: {resp.status_code}")

        await _engine.cache.set(attack_id, confidence, patch_body)
        return patch_body

    @app.post("/investigate")
    async def investigate(body: dict, x_internal_key: Optional[str] = Header(default=None)):
        """Agent-less autonomous retrieval (Big Bet 3). Runs a bounded LLM
        tool-use loop to gather telemetry for a hypothesis. Gated behind
        AGENT_RETRIEVAL_ENABLED + the global kill switch, and every Claude call
        goes through the shared daily budget. Returns {enabled:false} with no
        spend when disabled.
        """
        _check_admin(x_internal_key)
        if _engine is None or _engine.narrator is None or _engine.budget is None:
            raise HTTPException(status_code=503, detail="Engine not ready")
        hypothesis = str(body.get("hypothesis") or "").strip()
        if not hypothesis:
            raise HTTPException(status_code=400, detail="hypothesis required")
        result = await agent_tools.run_investigation(
            hypothesis=hypothesis,
            tenant_id=str(body.get("tenant_id") or "-"),
            client=_engine.narrator._client,  # noqa: SLF001 — shared max_retries=0 client
            model=_engine.config.anthropic_model,
            budget=_engine.budget,
            narrator_enabled=_engine.narrator._enabled,  # noqa: SLF001
        )
        return result

    @app.post("/admin/anthropic/disable")
    async def admin_disable(x_internal_key: Optional[str] = Header(default=None)):
        """Runtime kill switch — no redeploy needed. Flips the narrator into
        stub-only mode for this replica. Survives until pod restart, then the
        env var (ANTHROPIC_ENABLED) takes over again. Pair this with setting
        the env to false if you want a permanent stop.
        """
        _check_admin(x_internal_key)
        if _engine is None or _engine.narrator is None:
            raise HTTPException(status_code=503, detail="Engine not ready")
        _engine.narrator.force_disable()
        logger.warning("ai_engine.admin.narrator_force_disabled")
        return {"enabled": False}

    @app.post("/admin/anthropic/enable")
    async def admin_enable(x_internal_key: Optional[str] = Header(default=None)):
        _check_admin(x_internal_key)
        if _engine is None or _engine.narrator is None:
            raise HTTPException(status_code=503, detail="Engine not ready")
        _engine.narrator.force_enable()
        logger.warning("ai_engine.admin.narrator_force_enabled")
        return {"enabled": True, "circuit_open": False}

    return app


app = create_app()


if __name__ == "__main__":
    cfg = get_config()
    uvicorn.run(
        "services.ai_engine.main:app",
        host="0.0.0.0",
        port=cfg.port,
        reload=False,
    )
