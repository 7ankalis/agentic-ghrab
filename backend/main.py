"""
Ghrab VOC — FastAPI backend.

Wraps the deterministic GRS engine, the autonomous attack-path discovery engine,
and the multi-provider agentic AI layer behind a JSON/SSE API consumed by the
React SPA. Run from this directory:  uvicorn main:app --reload
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.logs import router as logs_router
from api.routes import router as rest_router
from api.streams import router as stream_router
from db.session import init_db

app = FastAPI(title="Ghrab VOC API", version="1.0.0")
init_db()

# Dev-friendly CORS: the Vite dev server (5173) + configurable extra origins.
_origins = os.environ.get(
    "VOC_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173",
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(rest_router)
app.include_router(stream_router)
app.include_router(logs_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ghrab-voc"}
