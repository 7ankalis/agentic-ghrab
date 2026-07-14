"""Server-Sent-Events endpoints: live analysis progress + streaming AI chat."""
from __future__ import annotations

import asyncio
import json
import queue
import threading

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agents.triage_agent import answer_question
from api.state import get_analysis, invalidate, runtime_settings

router = APIRouter(prefix="/api")

SSE_HEADERS = {"Cache-Control": "no-cache", "Connection": "keep-alive",
               "X-Accel-Buffering": "no"}


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


class AnalyzeBody(BaseModel):
    force_refresh: bool = False


@router.post("/analyze")
async def analyze(body: AnalyzeBody):
    """Re-run the pipeline, streaming each stage as it completes."""
    q: queue.Queue = queue.Queue()

    def work():
        try:
            invalidate()
            get_analysis(force_refresh=body.force_refresh, progress_cb=lambda m: q.put(("progress", m)))
            q.put(("done", "Analysis complete"))
        except Exception as exc:  # noqa: BLE001
            q.put(("error", str(exc)))

    async def gen():
        threading.Thread(target=work, daemon=True).start()
        while True:
            event, msg = await asyncio.to_thread(q.get)
            yield _sse(event, {"message": msg})
            if event in ("done", "error"):
                break

    return StreamingResponse(gen(), media_type="text/event-stream", headers=SSE_HEADERS)


class ChatBody(BaseModel):
    message: str
    history: list[dict] = []


def _paths_context(result) -> str:
    lines = []
    for p in result.paths[:12]:
        lines.append(p.evidence_line())
    return "\n".join(lines)


@router.post("/chat")
async def chat(body: ChatBody):
    result = get_analysis()
    if not result.ai_enabled:
        async def offline():
            yield _sse("token", {"text": "No AI provider is connected. Add a key in Settings to enable the analyst."})
            yield _sse("done", {})
        return StreamingResponse(offline(), media_type="text/event-stream", headers=SSE_HEADERS)

    answer = await asyncio.to_thread(
        answer_question, body.message, result.df, result.cmdb,
        body.history, runtime_settings, _paths_context(result),
    )

    async def gen():
        # word-by-word delivery for a live typing feel (provider-agnostic)
        for i, word in enumerate(answer.split(" ")):
            yield _sse("token", {"text": ("" if i == 0 else " ") + word})
            await asyncio.sleep(0.012)
        yield _sse("done", {})

    return StreamingResponse(gen(), media_type="text/event-stream", headers=SSE_HEADERS)
