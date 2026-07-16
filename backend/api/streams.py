"""Server-Sent-Events endpoints: live analysis progress + streaming AI chat."""
from __future__ import annotations

import asyncio
import queue
import threading

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agents.triage_agent import answer_question
from api.sse import SSE_HEADERS, sse as _sse
from api.state import get_analysis, invalidate, runtime_settings

router = APIRouter(prefix="/api")


class AnalyzeBody(BaseModel):
    force_refresh: bool = False


# A single in-flight pipeline run is broadcast to every connected client,
# rather than each POST /analyze spinning up its own private queue+thread.
# Without this, a page reload (or a second click before the first request's
# response ever arrives) starts a second, fully redundant `run_pipeline()`
# that queues up behind `api.state`'s global analysis lock — its own SSE
# connection sits on an empty private queue the whole time the first run is
# still going, so the progress card looks permanently frozen even though real
# agent activity is happening (visible only on the unrelated /logs/stream).
class _RunBroadcast:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.lines: list[dict] = []  # progress lines emitted so far by the current/last run
        self.subscribers: list[queue.Queue] = []

    def start(self, force_refresh: bool) -> None:
        with self.lock:
            if self.running:
                return
            self.running = True
            self.lines = []
        threading.Thread(target=self._work, args=(force_refresh,), daemon=True).start()

    def _emit(self, event: str, message: str, level: str = "info") -> None:
        line = {"event": event, "message": message, "level": level}
        with self.lock:
            self.lines.append(line)
            subs = list(self.subscribers)
        for q in subs:
            q.put(line)

    def _work(self, force_refresh: bool) -> None:
        try:
            invalidate()
            get_analysis(
                force_refresh=force_refresh,
                progress_cb=lambda m, level="info": self._emit("progress", m, level),
            )
            self._emit("done", "Analysis complete", "info")
        except Exception as exc:  # noqa: BLE001
            self._emit("error", str(exc), "error")
        finally:
            with self.lock:
                self.running = False

    def subscribe(self) -> tuple[queue.Queue, list[dict]]:
        q: queue.Queue = queue.Queue()
        with self.lock:
            self.subscribers.append(q)
            backlog = list(self.lines)
        return q, backlog

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def status(self) -> dict:
        with self.lock:
            return {"running": self.running, "lines": list(self.lines)}


_broadcast = _RunBroadcast()


@router.get("/analyze/status")
def analyze_status():
    """Lets a freshly loaded page discover an already-in-flight run (or its
    just-finished result) instead of always assuming nothing is happening."""
    return _broadcast.status()


@router.post("/analyze")
async def analyze(body: AnalyzeBody):
    """Kick off (or attach to) the pipeline run, streaming each stage as it
    happens. If a run is already in flight, this attaches to it — replaying
    the progress so far — instead of starting a redundant second run."""
    _broadcast.start(body.force_refresh)
    q, backlog = _broadcast.subscribe()

    async def gen():
        try:
            for line in backlog:
                yield _sse(line["event"], {"message": line["message"], "level": line["level"]})
                if line["event"] in ("done", "error"):
                    return
            while True:
                line = await asyncio.to_thread(q.get)
                yield _sse(line["event"], {"message": line["message"], "level": line["level"]})
                if line["event"] in ("done", "error"):
                    break
        finally:
            _broadcast.unsubscribe(q)

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
