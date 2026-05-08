"""VIGIL Auth Service entrypoint."""

from __future__ import annotations
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .auth_routes import router as auth_router, webhook_router
from .config import APIConfig, get_config
from .key_store import KeyStore
from .onboarding_routes import router as onboarding_router, auth_me_router
from .user_store import UserStore

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg: APIConfig = get_config()
    store = await UserStore.from_dsn(cfg.database_url)
    app.state.user_store = store
    app.state.key_store = KeyStore(store.pool)
    app.state.config = cfg
    logger.info("api.started", port=cfg.port, environment=cfg.environment)
    try:
        yield
    finally:
        await store.close()


def create_app() -> FastAPI:
    app = FastAPI(title="VIGIL API", version="0.1.0", lifespan=lifespan)

    cfg = get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router)
    app.include_router(webhook_router)
    app.include_router(onboarding_router)
    app.include_router(auth_me_router)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(_request: Request, exc: RequestValidationError):
        # Compress pydantic's default error blob into the project's
        # { error, detail } envelope.
        first = exc.errors()[0] if exc.errors() else {"msg": "Invalid request"}
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Bad Request", "detail": first.get("msg", "Invalid request")},
        )

    @app.get("/health")
    async def health(request: Request):
        store: Optional[UserStore] = getattr(request.app.state, "user_store", None)
        if store is None:
            return JSONResponse({"status": "starting"}, status_code=503)
        try:
            async with store.pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return {"status": "ok", "service": "api", "version": "0.1.0"}
        except Exception as e:
            return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)

    return app


app = create_app()
