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
_active: dict[int, dict] = {}  # call_id -> start event, authoritative + never trimmed
_subscribers: list[queue.Queue] = []
_max_started_id = 0            # high-water mark for run-scoped accounting (see marker())
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
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    cost_usd: float | None = None
    attempt: int = 1               # 1-based attempt across the whole logical call (retries + fallbacks)
    group_id: str = ""             # ties start/finish + every retry/fallback attempt of one logical call() together
    error: str | None = None
    detail: str = ""              # short human label, e.g. "remediation QID 90512"


def _publish(ev: CallEvent) -> None:
    global _max_started_id
    d = asdict(ev)
    with _lock:
        if ev.event == "start":
            _max_started_id = ev.id
        _history.append(d)
        if len(_history) > MAX_HISTORY:
            del _history[: len(_history) - MAX_HISTORY]
        # `_active` is the authoritative "currently running" set: unlike
        # `_history` it's never trimmed by count, so a busy pipeline can't
        # evict a call's `start` event before its `finish` arrives and strand
        # it as permanently "running" client-side. Cleared only by a matching
        # finish, so a reconnecting client can always resync to ground truth
        # via active() instead of reconstructing it from a lossy replay.
        if ev.event == "start":
            _active[ev.id] = d
        else:
            _active.pop(ev.id, None)
        subs = list(_subscribers)
    for q in subs:
        q.put(d)


def start(role: str, provider: str, model: str, detail: str = "",
          attempt: int = 1, group_id: str = "") -> int:
    call_id = next(_counter)
    _publish(CallEvent(id=call_id, ts=time.time(), role=role, provider=provider,
                        model=model, event="start", detail=detail,
                        attempt=attempt, group_id=group_id))
    return call_id


def finish(call_id: int, role: str, provider: str, model: str, ok: bool,
           duration_ms: float, tokens: int | None = None,
           prompt_tokens: int | None = None, completion_tokens: int | None = None,
           cost_usd: float | None = None, error: str | None = None, detail: str = "",
           attempt: int = 1, group_id: str = "") -> None:
    _publish(CallEvent(id=call_id, ts=time.time(), role=role, provider=provider,
                        model=model, event="success" if ok else "error",
                        duration_ms=round(duration_ms, 1), tokens=tokens,
                        prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                        cost_usd=cost_usd, error=error, detail=detail,
                        attempt=attempt, group_id=group_id))


def marker() -> int:
    """Opaque high-water mark of the calls seen so far. Pass it to
    `summarize_since()` after a unit of work (e.g. one analysis run) to get real
    token/cost/latency accounting for exactly the calls that happened in between —
    the Phase-5 observability hook that replaces the loop's len/4 estimate."""
    with _lock:
        return _max_started_id


def summarize_since(marker_id: int) -> dict:
    """Aggregate every LLM call that FINISHED after `marker_id` into a compact,
    JSON-serialisable accounting record: totals plus a per-role and per-provider
    breakdown of calls / tokens / cost / latency / errors. Best-effort — token and
    cost fields are None for providers litellm has no usage/pricing data for, and
    are simply skipped. Bounded by MAX_HISTORY: a run firing more than that many
    calls would under-count the earliest, which no real run approaches."""
    with _lock:
        events = [e for e in _history
                  if e["id"] > marker_id and e["event"] in ("success", "error")]

    def _blank() -> dict:
        return {"calls": 0, "ok": 0, "errors": 0, "tokens": 0,
                "prompt_tokens": 0, "completion_tokens": 0,
                "cost_usd": 0.0, "latency_ms": 0.0}

    total = _blank()
    by_role: dict[str, dict] = {}
    by_provider: dict[str, dict] = {}
    for e in events:
        for bucket in (total, by_role.setdefault(e["role"], _blank()),
                       by_provider.setdefault(e["provider"], _blank())):
            bucket["calls"] += 1
            bucket["ok"] += 1 if e["event"] == "success" else 0
            bucket["errors"] += 1 if e["event"] == "error" else 0
            bucket["tokens"] += e.get("tokens") or 0
            bucket["prompt_tokens"] += e.get("prompt_tokens") or 0
            bucket["completion_tokens"] += e.get("completion_tokens") or 0
            bucket["cost_usd"] += e.get("cost_usd") or 0.0
            bucket["latency_ms"] += e.get("duration_ms") or 0.0
    for bucket in [total, *by_role.values(), *by_provider.values()]:
        bucket["cost_usd"] = round(bucket["cost_usd"], 6)
        bucket["latency_ms"] = round(bucket["latency_ms"], 1)
    total["by_role"] = by_role
    total["by_provider"] = by_provider
    return total


def history() -> list[dict]:
    with _lock:
        return list(_history)


def active() -> list[dict]:
    """Authoritative snapshot of in-flight calls (start with no finish yet),
    independent of `_history`'s trimming. Used to resync clients on connect."""
    with _lock:
        return list(_active.values())


def clear() -> None:
    with _lock:
        _history.clear()
        _active.clear()


def subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue()
    with _lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        if q in _subscribers:
            _subscribers.remove(q)
