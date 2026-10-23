from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api.routes import router
from app.core.config import get_settings
from app.core.db import get_engine
from app.core.limits import BodySizeLimitMiddleware
from app.services.analysis_service import init_services
from app.services.settings_service import SettingsService

UPLOAD_PATH = "/api/analyses"
JSON_LIMIT = 1024 * 1024
MULTIPART_OVERHEAD = 1024 * 1024


def _body_limit(path: str) -> int:
    if path.rstrip("/") != UPLOAD_PATH:
        return JSON_LIMIT
    with Session(get_engine()) as s:
        return SettingsService(s).get().max_upload_mb * 1024 * 1024 + MULTIPART_OVERHEAD


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    with Session(get_engine()) as s:
        init_services(s)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetSentry",
        version="0.1.0",
        description="Offline PCAP/PCAPNG analysis with explainable, rule-based threat detection. "
        "Detections are heuristics, not proof of an attack.",
        lifespan=lifespan,
    )
    app.add_middleware(BodySizeLimitMiddleware, limit=_body_limit)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origin_list,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )
    app.include_router(router)

    @app.get("/api/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": app.version}

    return app


app = create_app()
