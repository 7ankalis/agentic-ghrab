"""In-memory IP-based rate limiting for cost-incurring endpoints.

This app has no authentication layer (see AGENTS.md's architecture summary
and `api/state.py`'s process-global, unauthenticated session state) — IP
address is the only identity signal a request carries, so it's what we key
on here. That makes this a stopgap against a runaway client (a stray retry
loop, a script hammering `/analyze` with `force_refresh: true`, a chat
client stuck in a loop) — not a real multi-tenant quota system. IPs are
shared behind NAT/proxies and trivially spoofable by anyone who controls the
client. It's good enough for a single-operator lab tool; real auth would be
needed before this could be trusted as an actual billing/quota boundary.

Deliberately mirrors `core/providers.py`'s outbound throttling style — a
dict of sliding windows guarded by one small lock — rather than pulling in a
library like slowapi or a Redis-backed limiter. This app has zero middleware
and prefers small hand-rolled utilities; a per-process in-memory limiter is
also simply correct here, since the whole app is one uvicorn process with no
horizontal scaling to coordinate across.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

# key -> monotonic timestamps of calls still inside the current window.
_windows: dict[str, list[float]] = {}
_guard = threading.Lock()


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after: float  # seconds until the oldest call in the window expires


def check(key: str, limit: int, window_sec: float) -> RateLimitResult:
    """Sliding-window rate check for `key` (already scoped to an identity +
    endpoint, e.g. "203.0.113.4:analyze"). If under `limit` calls in the
    trailing `window_sec` seconds, records this call and allows it;
    otherwise rejects without recording, so a caller hammering past the
    limit doesn't keep pushing its own window further out."""
    now = time.monotonic()
    with _guard:
        hits = _windows.setdefault(key, [])
        cutoff = now - window_sec
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= limit:
            return RateLimitResult(allowed=False, retry_after=hits[0] + window_sec - now)
        hits.append(now)
        return RateLimitResult(allowed=True, retry_after=0.0)
