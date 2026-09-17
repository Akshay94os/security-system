"""
AK Master Security System — FastAPI Application Entry Point
Configures: middleware, CORS, rate limiting, security headers, startup/shutdown.
"""
from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings
from backend.database.engine import close_db, init_db
from backend.security.event_bus import get_event_bus

logger = logging.getLogger(__name__)

settings = get_settings()

# ──────────────────────────────────────────────────────────
# App factory
# ──────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="AK Master Security System",
        description=(
            "Research-grade autonomous AI security platform. "
            "Every action passes through the security pipeline."
        ),
        version=settings.version,
        docs_url="/api/docs" if settings.is_development else None,
        redoc_url="/api/redoc" if settings.is_development else None,
        openapi_url="/api/openapi.json" if settings.is_development else None,
    )

    # ── CORS ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    # ── Security Headers Middleware ──
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        if not settings.is_development:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ── Rate Limiting ──
    try:
        from slowapi import Limiter, _rate_limit_exceeded_handler
        from slowapi.errors import RateLimitExceeded
        from slowapi.util import get_remote_address

        limiter = Limiter(key_func=get_remote_address)
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    except Exception as e:
        logger.warning("Rate limiting setup failed: %s", e)

    # ── Global Exception Handler ──
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s | path=%s", exc, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred.", "request_id": str(uuid.uuid4())},
        )

    # ── Routers ──
    from backend.api.auth_router import router as auth_router
    from backend.api.routers import (
        audit_router, events_router, health_router, nexus_router, tools_router
    )
    from backend.api.security_router import security_router

    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(nexus_router, prefix="/api/v1")
    app.include_router(events_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(tools_router, prefix="/api/v1")
    app.include_router(security_router, prefix="/api/v1")

    # ── Startup / Shutdown ──
    @app.on_event("startup")
    async def startup():
        logging.basicConfig(
            level=getattr(logging, settings.log_level.upper(), logging.INFO),
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        )
        logger.info("AK Master Security System starting up...")
        logger.info("Environment: %s", settings.app_env)
        logger.info("AI Provider configured: %s", settings.ai_provider_configured)

        await init_db()

        event_bus = get_event_bus()
        await event_bus.start()

        # Log startup health
        from backend.security.health_monitor import run_health_check
        health = await run_health_check()
        logger.info("System health on startup: %s", health.overall_status.value)
        for m in health.modules:
            if m.status.value != "OPERATIONAL":
                logger.warning("Module degraded: %s — %s", m.name, m.message)

        logger.info("AK Master Security System ready. API: http://127.0.0.1:8000/api/docs")

    @app.on_event("shutdown")
    async def shutdown():
        logger.info("AK Master Security System shutting down...")
        event_bus = get_event_bus()
        await event_bus.stop()
        await close_db()
        logger.info("Shutdown complete.")

    # ── Root endpoint ──
    @app.get("/")
    async def root():
        return {
            "system": "AK Master Security System",
            "layer2": "AK Nexus",
            "version": settings.version,
            "status": "operational",
            "api_docs": "/api/docs",
        }

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.is_development,
        log_level=settings.log_level.lower(),
    )
