"""Server-Sent-Events endpoints: live analysis progress + streaming AI chat."""
from __future__ import annotations

import asyncio
import queue
import threading

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agents.orchestrator import RunCancelled
from agents.triage_agent import answer_question
from api import serializers as S
from api import state
from api.sse import SSE_HEADERS, sse as _sse
from api.state import get_analysis, runtime_settings
from core.config import active_dataset_key
from db import repository

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
        self.cancel_event = threading.Event()

    def start(self, force_refresh: bool) -> None:
        with self.lock:
            if self.running:
                return
            self.running = True
            self.lines = []
            self.cancel_event.clear()
        threading.Thread(target=self._work, args=(force_refresh,), daemon=True).start()

    def cancel(self) -> bool:
        """Operator kill switch: signals the in-flight run to stop at its next
        agent boundary. Returns whether a run was actually in flight."""
        with self.lock:
            if not self.running:
                return False
            self.cancel_event.set()
        return True

    def _emit(self, event: str, message: str, level: str = "info", **extra) -> None:
        line = {"event": event, "message": message, "level": level, **extra}
        with self.lock:
            self.lines.append(line)
            subs = list(self.subscribers)
        for q in subs:
            q.put(line)

    def _work(self, force_refresh: bool) -> None:
        try:
            # Byte-identical input to the last completed run? Don't touch the
            # agent chain — hand the caller enough to offer reuse-vs-refresh.
            duplicate = state.check_duplicate(force_refresh)
            if duplicate is not None:
                self._emit(
                    "duplicate",
                    "This exact dataset was already analyzed — reuse it or refresh?",
                    "info", run=duplicate,
                )
                return
            state.run_new_analysis(
                force_refresh=force_refresh,
                progress_cb=lambda m, level="info": self._emit("progress", m, level),
                should_cancel=self.cancel_event.is_set,
            )
            self._emit("done", "Analysis complete", "info")
        except RunCancelled:
            self._emit("cancelled", "Analysis stopped by operator", "warn")
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

    def _payload(line: dict) -> dict:
        return {k: v for k, v in line.items() if k != "event"}

    async def gen():
        try:
            for line in backlog:
                yield _sse(line["event"], _payload(line))
                if line["event"] in ("done", "error", "duplicate", "cancelled"):
                    return
            while True:
                line = await asyncio.to_thread(q.get)
                yield _sse(line["event"], _payload(line))
                if line["event"] in ("done", "error", "duplicate", "cancelled"):
                    break
        finally:
            _broadcast.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers=SSE_HEADERS)


@router.post("/analyze/cancel")
def cancel_analysis():
    """Operator kill switch. Signals the in-flight run to stop at its next
    agent boundary; the SSE stream then emits a `cancelled` event. Idempotent —
    a no-op (with running=False) when nothing is currently in flight."""
    was_running = _broadcast.cancel()
    return {"ok": True, "running": was_running}


@router.post("/analyze/reuse/{run_id}")
def reuse_analysis(run_id: str):
    """Adopts a previously persisted run as the active analysis — the
    'reuse previous results' side of the duplicate-detection card. Never
    touches the agent chain."""
    try:
        result = state.reuse_run(run_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"ok": True, "kpis": S.kpis(result)}


@router.get("/analyze/runs")
def list_runs():
    """Run history for the active dataset — findings history / trend data,
    lightweight enough to list without touching the AI blobs."""
    return {"runs": [r.summary() for r in repository.list_runs(active_dataset_key())]}


@router.delete("/analyze/runs/{run_id}")
def delete_run(run_id: str):
    """Deletes one persisted run's history. If it was the active run, the
    in-memory analysis is dropped too — the next request cold-hydrates from
    whatever's now the latest surviving run (or comes up blank)."""
    ok = repository.delete_run(run_id)
    if not ok:
        raise HTTPException(404, f"Run {run_id!r} not found")
    if state.current_run_id() == run_id:
        state.invalidate()
    return {"ok": True}


@router.delete("/analyze/runs")
def clear_runs():
    """Wipes all persisted history for the active dataset and drops the
    in-memory analysis. A fresh Full Analysis starts clean."""
    n = repository.delete_all_runs(active_dataset_key())
    state.invalidate()
    return {"ok": True, "deleted": n}


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
