"""Persistence schema for analysis runs.

Deliberately lean: the deterministic layer (GRS scoring, capability
classification, reachability graph, path discovery) is a pure, fast function
of the input files, so it is never stored — only recomputed on load. What
*is* persisted is exactly what's expensive to regenerate (the LLM-enriched
discovery/correlation/compliance/executive-summary layer) plus a small KPI
snapshot captured on every run, complete or deterministic-only, so trend/delta
reporting works even for operators with no AI provider connected.
"""
from __future__ import annotations

import uuid

from sqlalchemy import JSON, Boolean, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _new_id() -> str:
    return uuid.uuid4().hex


class AnalysisRun(Base):
    """One execution of the analysis pipeline against a dataset."""

    __tablename__ = "analysis_run"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    dataset_key: Mapped[str] = mapped_column(String(64), index=True)
    input_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|complete|failed
    ai_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[float] = mapped_column(Float)
    completed_at: Mapped[float | None] = mapped_column(Float, nullable=True)

    # AI-enriched layer — the expensive, LLM-backed part worth caching.
    discovery: Mapped[dict] = mapped_column(JSON, default=dict)
    correlation: Mapped[dict] = mapped_column(JSON, default=dict)
    compliance: Mapped[dict] = mapped_column(JSON, default=dict)
    executive_summary: Mapped[str] = mapped_column(Text, default="")

    # Cheap aggregate snapshot (total findings, band distribution, avg GRS,
    # KEV/DORA counts, discovered path count…) — powers run-history/trend
    # views without deserializing a full findings set.
    kpi_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)

    def summary(self) -> dict:
        return {
            "id": self.id,
            "dataset_key": self.dataset_key,
            "status": self.status,
            "ai_enabled": self.ai_enabled,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "kpi_snapshot": self.kpi_snapshot,
            "error": self.error,
        }
