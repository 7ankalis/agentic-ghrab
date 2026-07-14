"""Live + historical feed of every LLM/agent call — the "is the AI actually
working, and which agent is calling what right now" debug panel."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.sse import SSE_HEADERS, sse
from core import call_log

router = APIRouter(prefix="/api")


@router.get("/logs")
def get_logs():
    return {"logs": call_log.history()}


@router.get("/logs/stream")
async def stream_logs():
    """SSE tail. Replays recent history immediately on connect so a freshly
    opened tab isn't empty, then pushes new events as they happen."""
    q = call_log.subscribe()

    async def gen():
        try:
            for entry in call_log.history()[-50:]:
                yield sse("log", entry)
            while True:
                entry = await asyncio.to_thread(q.get)
                yield sse("log", entry)
        finally:
            call_log.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers=SSE_HEADERS)
