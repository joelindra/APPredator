"""
FastAPI entrypoint for APPredator web UI and API.
Run from repository root: uvicorn web.backend.main:app --host 127.0.0.1 --port 8080
(scripts/start-api.mjs adds --reload only when APPREDATOR_API_RELOAD=1 to avoid multiprocessing shutdown noise.
Windows dev default port 8765 via APPREDATOR_API_PORT in package scripts.)
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from apppredator.bootstrap import configure_runtime
from apppredator.paths import project_root
from web.backend import jobs_store
from web.backend.routers import baselines, config_assets, config_parity, health, rules_meta, scans, settings, ssl_pinning


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_runtime()
    jobs_store.init_db()
    yield


app = FastAPI(title="APPredator API", lifespan=lifespan)

_cors = os.environ.get("APPREDATOR_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
origins = [o.strip() for o in _cors.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(settings.router)
app.include_router(config_parity.router)
app.include_router(config_assets.router)
app.include_router(rules_meta.router)
app.include_router(scans.router)
app.include_router(baselines.router)
app.include_router(ssl_pinning.router)

# Serve production SPA under /ui so /docs, /openapi.json, and /api/* stay usable.
_dist = project_root() / "web" / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/ui", StaticFiles(directory=str(_dist), html=True), name="static")


@app.get("/api")
def api_root() -> dict:
    return {"service": "apppredator", "docs": "/docs", "ui": "/ui/"}


@app.get("/")
def root_to_docs() -> RedirectResponse:
    """Convenient entry when running the API server only."""
    return RedirectResponse(url="/docs")
