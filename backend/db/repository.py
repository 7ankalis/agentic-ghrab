"""CRUD + query layer for analysis runs. The only module allowed to touch a
SQLAlchemy Session — everything else deals in AnalysisRun instances or the
plain dicts from .summary()."""
from __future__ import annotations

import time

from db.models import AnalysisRun
from db.session import SessionLocal


def create_run(dataset_key: str, input_fingerprint: str, ai_enabled: bool) -> AnalysisRun:
    with SessionLocal() as s:
        run = AnalysisRun(
            dataset_key=dataset_key,
            input_fingerprint=input_fingerprint,
            ai_enabled=ai_enabled,
            status="running",
            started_at=time.time(),
        )
        s.add(run)
        s.commit()
        s.refresh(run)
        return run


def complete_run(
    run_id: str, *, discovery: dict, correlation: dict, compliance: dict,
    executive_summary: str, kpi_snapshot: dict, ai_enabled: bool,
) -> AnalysisRun:
    with SessionLocal() as s:
        run = s.get(AnalysisRun, run_id)
        if run is None:
            raise ValueError(f"analysis_run {run_id} not found")
        run.status = "complete"
        run.completed_at = time.time()
        run.discovery = discovery
        run.correlation = correlation
        run.compliance = compliance
        run.executive_summary = executive_summary
        run.kpi_snapshot = kpi_snapshot
        run.ai_enabled = ai_enabled
        s.commit()
        s.refresh(run)
        return run


def fail_run(run_id: str, error: str) -> None:
    with SessionLocal() as s:
        run = s.get(AnalysisRun, run_id)
        if run is None:
            return
        run.status = "failed"
        run.error = error
        run.completed_at = time.time()
        s.commit()


def get_run(run_id: str) -> AnalysisRun | None:
    with SessionLocal() as s:
        return s.get(AnalysisRun, run_id)


def latest_complete_run(dataset_key: str, input_fingerprint: str | None = None) -> AnalysisRun | None:
    """Most recent complete run for a dataset — optionally pinned to a
    specific input fingerprint, which is how duplicate detection works."""
    with SessionLocal() as s:
        q = s.query(AnalysisRun).filter_by(dataset_key=dataset_key, status="complete")
        if input_fingerprint is not None:
            q = q.filter_by(input_fingerprint=input_fingerprint)
        return q.order_by(AnalysisRun.completed_at.desc()).first()


def list_runs(dataset_key: str, limit: int = 50) -> list[AnalysisRun]:
    with SessionLocal() as s:
        return (
            s.query(AnalysisRun)
            .filter_by(dataset_key=dataset_key)
            .order_by(AnalysisRun.started_at.desc())
            .limit(limit)
            .all()
        )


def delete_run(run_id: str) -> bool:
    with SessionLocal() as s:
        run = s.get(AnalysisRun, run_id)
        if run is None:
            return False
        s.delete(run)
        s.commit()
        return True


def delete_all_runs(dataset_key: str) -> int:
    with SessionLocal() as s:
        n = s.query(AnalysisRun).filter_by(dataset_key=dataset_key).delete()
        s.commit()
        return n
