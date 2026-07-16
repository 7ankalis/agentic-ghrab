"""Live + historical feed of every LLM/agent call — the "is the AI actually
working, and which agent is calling what right now" debug panel."""
from __future__ import annotations

import asyncio
import queue as queue_mod

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.sse import SSE_HEADERS, sse
from core import call_log

router = APIRouter(prefix="/api")


def _poll(q: queue_mod.Queue, timeout: float):
    """Blocking get bounded by the queue's own timeout (not asyncio.wait_for,
    which would abandon the underlying thread still blocked on q.get() —
    leaking a thread per timeout and risking it stealing a later item)."""
    try:
        return q.get(timeout=timeout)
    except queue_mod.Empty:
        return None


@router.get("/logs")
def get_logs():
    return {"logs": call_log.history()}


@router.delete("/logs")
def clear_logs():
    """Wipe the in-memory log buffer — lets an operator start a clean debug
    session without restarting the backend."""
    call_log.clear()
    return {"ok": True}


@router.get("/logs/stream")
async def stream_logs():
    """SSE tail. Replays recent history immediately on connect so a freshly
    opened tab isn't empty, then pushes new events as they happen.

    Also sends an authoritative "active" snapshot on every connect (including
    reconnects) so a client can resync its "currently running" set to ground
    truth — `history()` is trimmed by count and can silently drop a call's
    `start` event before its `finish` arrives during a busy pipeline run,
    which otherwise strands that row as "running" forever client-side."""
    q = call_log.subscribe()

    async def gen():
        try:
            for entry in call_log.history():
                yield sse("log", entry)
            yield sse("active_snapshot", {"active": call_log.active()})
            while True:
                entry = await asyncio.to_thread(_poll, q, 15)
                if entry is None:
                    yield ": ping\n\n"  # SSE comment — keeps proxies from idling the connection out
                    continue
                yield sse("log", entry)
        finally:
            call_log.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers=SSE_HEADERS)
