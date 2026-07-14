"""
In-memory log of every LLM call the platform makes — the "which agent is
working" debug feed. call_llm() runs on background threads (SSE handlers, the
bulk pipeline run), so this uses a plain queue.Queue pub-sub rather than
asyncio primitives, and a simple lock rather than an async-aware one.

Each call gets a `start` event when a provider attempt begins and a matching
`success`/`error` event when it resolves. A UI can therefore show both a live
"currently running" list (starts with no matching finish yet) and a scrolling
history — which is exactly what's needed to see whether the AI layer is
actually being called, which provider served it, and why a fallback happened.
"""
from __future__ import annotations

import itertools
import queue
import threading
import time
from dataclasses import asdict, dataclass

_counter = itertools.count(1)
_lock = threading.Lock()
_history: list[dict] = []
_subscribers: list[queue.Queue] = []
MAX_HISTORY = 300


@dataclass
class CallEvent:
    id: int
    ts: float
    role: str
    provider: str
    model: str
    event: str                    # "start" | "success" | "error"
    duration_ms: float | None = None
    tokens: int | None = None
    error: str | None = None
    detail: str = ""              # short human label, e.g. "remediation QID 90512"


def _publish(ev: CallEvent) -> None:
    d = asdict(ev)
    with _lock:
        _history.append(d)
        if len(_history) > MAX_HISTORY:
            del _history[: len(_history) - MAX_HISTORY]
        subs = list(_subscribers)
    for q in subs:
        q.put(d)


def start(role: str, provider: str, model: str, detail: str = "") -> int:
    call_id = next(_counter)
    _publish(CallEvent(id=call_id, ts=time.time(), role=role, provider=provider,
                        model=model, event="start", detail=detail))
    return call_id


def finish(call_id: int, role: str, provider: str, model: str, ok: bool,
           duration_ms: float, tokens: int | None = None,
           error: str | None = None, detail: str = "") -> None:
    _publish(CallEvent(id=call_id, ts=time.time(), role=role, provider=provider,
                        model=model, event="success" if ok else "error",
                        duration_ms=round(duration_ms, 1), tokens=tokens,
                        error=error, detail=detail))


def history() -> list[dict]:
    with _lock:
        return list(_history)


def subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue()
    with _lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        if q in _subscribers:
            _subscribers.remove(q)
