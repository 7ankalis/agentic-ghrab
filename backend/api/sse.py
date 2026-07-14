"""Shared Server-Sent-Events helpers used by streams.py and logs.py."""
from __future__ import annotations

import json

SSE_HEADERS = {"Cache-Control": "no-cache", "Connection": "keep-alive",
               "X-Accel-Buffering": "no"}


def sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
