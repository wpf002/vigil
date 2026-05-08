"""VIGIL AI Engine.

Listens for AttackState changes on Kafka, generates narratives via Claude,
PATCHes them back to attack-state-engine. Exposes a small REST API for
manual triggers and health.
"""

from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from typing import Optional

import httpx
import structlog
import uvicorn
from anthropic import Anthropic
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .cache import NarrativeCache
from .config import AIEngineConfig, get_config
from .consumer import NarrativeConsumer, build_consumer
from .narrator import Narrator

logger = structlog.get_logger(__name__)


class AIEngine:
    def __init__(self, config: AIEngineConfig):
        self.config = config
        self.narrator: Optional[Narrator] = None
        self.cache: Optional[NarrativeCache] = None
        self.consumer: Optional[NarrativeConsumer] = None
        self._consumer_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if not self.config.anthropic_api_key:
            logger.warning("ai_engine.no_api_key — narrator calls will fail")

        # Anthropic client is sync — narrator wraps it.
        client = Anthropic(api_key=self.config.anthropic_api_key or "missing")
        self.narrator = Narrator(client=client, model=self.config.anthropic_model)

        self.cache = await NarrativeCache.from_url(
            self.config.redis_url, self.config.narrative_cache_ttl_seconds
        )

        self.consumer = build_consumer(narrator=self.narrator, cache=self.cache, cfg=self.config)
        try:
            self.consumer.connect()
            self._consumer_task = asyncio.create_task(self.consumer.run())
        except Exception as e:
            # Don't crash if Kafka isn't up yet — manual /generate still works.
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
        return {
            "status": "ok" if consumer_ok else "degraded",
            "service": "ai-engine",
            "version": "0.1.0",
            "consumer_connected": consumer_ok,
            "processed": _engine.consumer.processed if _engine.consumer else 0,
            "errors": _engine.consumer.errors if _engine.consumer else 0,
        }

    @app.post("/generate")
    async def generate_with_body(body: dict):
        """Manual trigger taking the AttackState as the body. Used by the demo
        seed script and any operator who already has the state in hand.
        """
        if _engine is None or _engine.narrator is None or _engine.cache is None:
            raise HTTPException(status_code=503, detail="Engine not ready")

        attack_id = body.get("attack_id")
        if not attack_id:
            raise HTTPException(status_code=400, detail="attack_id required")

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, _engine.narrator.generate, body)
        except Exception as e:
            logger.warning("ai_engine.manual_generate.failed", error_type=type(e).__name__)
            raise HTTPException(status_code=502, detail="Narrative generation failed")

        # PATCH the result back via the same path the consumer uses.
        cfg = _engine.config
        url = f"{cfg.attack_state_engine_url.rstrip('/')}/attacks/{attack_id}/narrative"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.patch(
                url,
                headers={"X-Internal-Key": cfg.internal_api_key},
                json=result.to_patch_body(),
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"PATCH failed: {resp.status_code}")

        confidence = float(body.get("confidence") or 0.0)
        await _engine.cache.set(attack_id, confidence, result.to_patch_body())
        return result.to_patch_body()

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
