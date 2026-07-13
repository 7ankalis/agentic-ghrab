"""Shared error taxonomy every provider adapter normalizes into.

The Orchestrator's retry/back-off/fallback logic (see retry.py) only ever
looks at `ProviderError.error_type` — it never inspects a vendor-specific
exception. Adapters are responsible for translating whatever their SDK raises
into one of these.
"""

from __future__ import annotations

from enum import Enum


class ProviderErrorType(str, Enum):
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    CONTEXT_TOO_LONG = "context_too_long"
    INVALID_RESPONSE = "invalid_response"  # malformed / schema-invalid JSON after repair retry
    UNKNOWN = "unknown"


class ProviderError(Exception):
    def __init__(self, error_type: ProviderErrorType, message: str, *, provider: str, cause: Exception | None = None):
        super().__init__(message)
        self.error_type = error_type
        self.provider = provider
        self.cause = cause

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"ProviderError({self.error_type.value!r}, provider={self.provider!r}, message={str(self)!r})"
