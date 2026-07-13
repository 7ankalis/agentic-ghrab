"""The orchestrator: runs Agents 1-5 once and produces an `ExposureContext`.

Deliberately a plain async function, not a DAG framework — at this scope
the real dependency graph is a straight line (2 depends on 1, 3 is
independent of 1/2, 4 depends on 1-3, 5 depends on 1-4) and a hand-written
sequence expresses that exactly as clearly as a graph library would, with
one dependency instead of several (LangGraph/Celery/etc — see the plan's
"deliberately not doing" list). If the agent graph grows non-linear branches
later, promote this to a real DAG then; don't pay for it now.

Runs are cached in-process, keyed by the two input files' mtimes, so
"Run Analysis" is idempotent — re-running against unchanged inputs is a
cache hit, not a re-run. No Postgres/Redis: at ~30-few-thousand findings and
single-process deployment, an in-memory cache is the honest equivalent of
the architecture doc's "resumable runs" idea without adding infrastructure
nobody asked for.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from vmc.agents.attack_paths import run_agent4
from vmc.agents.compliance import run_agent6
from vmc.agents.ingest import run_agent1
from vmc.agents.risk_scoring import run_agent5
from vmc.agents.routing import run_agent7
from vmc.agents.threat_intel import run_agent3
from vmc.agents.topology import run_agent2
from vmc.models import AgentLog, ExposureContext
from vmc.providers.router import ModelRouter

_run_cache: dict[tuple[str, float, str, float], ExposureContext] = {}


def _cache_key(findings_csv: Path, architecture_md: Path) -> tuple[str, float, str, float]:
    return (
        str(findings_csv),
        findings_csv.stat().st_mtime,
        str(architecture_md),
        architecture_md.stat().st_mtime,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_cached_context(findings_csv: str | Path, architecture_md: str | Path) -> ExposureContext | None:
    """Read-only: returns the cached run if one exists, without ever
    executing the pipeline. Every GET endpoint must go through this, not
    `run_pipeline` — a page load or dashboard poll must never accidentally
    trigger Agent 5's AI calls just because the process restarted and the
    in-memory cache is empty. Only the explicit `POST /api/run` action runs
    the pipeline."""
    findings_csv = Path(findings_csv)
    architecture_md = Path(architecture_md)
    return _run_cache.get(_cache_key(findings_csv, architecture_md))


async def run_pipeline(
    findings_csv: str | Path,
    architecture_md: str | Path,
    router: ModelRouter | None,
    *,
    tenant_id: str = "default",
    force: bool = False,
) -> ExposureContext:
    findings_csv = Path(findings_csv)
    architecture_md = Path(architecture_md)
    cache_key = _cache_key(findings_csv, architecture_md)
    if not force and cache_key in _run_cache:
        return _run_cache[cache_key]

    logs: list[AgentLog] = []

    def _log(agent_name: str, started_at: datetime, detail: str = "") -> None:
        logs.append(AgentLog(agent_name=agent_name, started_at=started_at, finished_at=_now(), status="ok", detail=detail))

    t0 = _now()
    findings, assets, teams, topology, dq_issues = run_agent1(findings_csv, architecture_md)
    _log("agent1_ingest", t0, f"{len(findings)} findings, {len(assets)} assets")

    t0 = _now()
    topology, assets, segmentation_findings = run_agent2(findings, assets, topology)
    _log("agent2_topology", t0, f"{len(segmentation_findings)} segmentation findings")

    t0 = _now()
    cve_ids = {f.cve_id for f in findings if f.cve_id}
    enrichment = run_agent3(cve_ids)
    _log("agent3_threat_intel", t0, f"{len(enrichment)} distinct CVEs enriched")

    t0 = _now()
    attack_paths, choke_points, tcm_by_finding = run_agent4(findings, architecture_md, assets)
    _log("agent4_attack_paths", t0, f"{len(attack_paths)} paths, {len(choke_points)} choke points")

    t0 = _now()
    risk_register = await run_agent5(findings, assets, enrichment, tcm_by_finding, topology, router)
    _log("agent5_risk_scoring", t0, f"{len(risk_register)} findings scored")

    t0 = _now()
    compliance_register = run_agent6(findings, assets, risk_register)
    _log("agent6_compliance", t0, f"{len(compliance_register)} findings mapped to frameworks")

    t0 = _now()
    team_briefs = run_agent7(findings, teams, risk_register, choke_points)
    _log("agent7_routing", t0, f"{len(team_briefs)} team briefs built")

    context = ExposureContext(
        run_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        findings=findings,
        assets=assets,
        teams=teams,
        data_quality_issues=dq_issues,
        topology=topology,
        segmentation_findings=segmentation_findings,
        enrichment=enrichment,
        attack_paths=attack_paths,
        choke_points=choke_points,
        risk_register=risk_register,
        compliance_register=compliance_register,
        team_briefs=team_briefs,
        agent_logs=logs,
    )

    _run_cache[cache_key] = context
    return context
