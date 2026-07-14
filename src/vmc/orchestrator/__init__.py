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

import asyncio
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

# ---------------------------------------------------------------------------
# Live progress broadcasting — admin visibility into "which agent is running
# right now," streamed to the UI over SSE (GET /api/run/progress in
# api/main.py). Deliberately a single in-process pub/sub, not a message
# queue: this app runs one pipeline at a time in one process (see the
# module docstring's "no Postgres/Redis" rationale) so a plain list of
# subscriber queues plus one shared "current state" dict is the honest
# equivalent of a progress channel without adding infrastructure.
# ---------------------------------------------------------------------------

AGENT_LABELS: dict[str, str] = {
    "agent1_ingest": "Agent 1 — Ingest & Normalize",
    "agent2_topology": "Agent 2 — Topology & Segmentation",
    "agent3_threat_intel": "Agent 3 — Threat Intel Enrichment",
    "agent4_attack_paths": "Agent 4 — Attack Path Discovery (AI)",
    "agent5_risk_scoring": "Agent 5 — GRS Risk Scoring (AI)",
    "agent6_compliance": "Agent 6 — Compliance Mapping",
    "agent7_routing": "Agent 7 — Team Routing",
}
AGENT_SEQUENCE: list[str] = list(AGENT_LABELS)

# Sentinel agent_name values signalling the run itself finished/errored —
# consumers (the SSE endpoint) stop listening when they see either.
RUN_COMPLETE = "__complete__"
RUN_ERROR = "__error__"

_progress_subscribers: list[asyncio.Queue] = []
_current_progress: dict[str, dict] = {}


def _reset_progress() -> None:
    _current_progress.clear()
    for name, label in AGENT_LABELS.items():
        _current_progress[name] = {"agent_name": name, "label": label, "status": "pending", "detail": ""}


def _publish(event: dict) -> None:
    _current_progress[event["agent_name"]] = event
    for queue in _progress_subscribers:
        queue.put_nowait(event)


def subscribe_progress() -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue()
    _progress_subscribers.append(queue)
    return queue


def unsubscribe_progress(queue: asyncio.Queue) -> None:
    if queue in _progress_subscribers:
        _progress_subscribers.remove(queue)


def get_progress_snapshot() -> list[dict]:
    """Current state of every agent, in pipeline order — sent to a client
    that connects to the SSE stream mid-run so it doesn't have to wait for
    the next event to know where things stand."""
    return [_current_progress[name] for name in AGENT_SEQUENCE if name in _current_progress]


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
        _reset_progress()
        for name in AGENT_SEQUENCE:
            _publish({"agent_name": name, "label": AGENT_LABELS[name], "status": "ok", "detail": "cached run"})
        _publish({"agent_name": RUN_COMPLETE, "label": "", "status": "ok", "detail": _run_cache[cache_key].run_id})
        return _run_cache[cache_key]

    _reset_progress()
    logs: list[AgentLog] = []

    def _start(agent_name: str) -> datetime:
        _publish({"agent_name": agent_name, "label": AGENT_LABELS[agent_name], "status": "running", "detail": ""})
        return _now()

    def _log(agent_name: str, started_at: datetime, detail: str = "", status: str = "ok") -> None:
        logs.append(
            AgentLog(agent_name=agent_name, started_at=started_at, finished_at=_now(), status=status, detail=detail)
        )
        _publish({"agent_name": agent_name, "label": AGENT_LABELS[agent_name], "status": status, "detail": detail})

    try:
        t0 = _start("agent1_ingest")
        findings, assets, teams, topology, dq_issues = run_agent1(findings_csv, architecture_md)
        _log("agent1_ingest", t0, f"{len(findings)} findings, {len(assets)} assets")

        t0 = _start("agent2_topology")
        topology, assets, segmentation_findings = run_agent2(findings, assets, topology)
        _log("agent2_topology", t0, f"{len(segmentation_findings)} segmentation findings")

        t0 = _start("agent3_threat_intel")
        cve_ids = {f.cve_id for f in findings if f.cve_id}
        enrichment = run_agent3(cve_ids)
        _log("agent3_threat_intel", t0, f"{len(enrichment)} distinct CVEs enriched")

        t0 = _start("agent4_attack_paths")
        attack_paths, choke_points, tcm_by_finding, agent4_degraded = await run_agent4(
            findings, assets, topology, segmentation_findings, router
        )
        if agent4_degraded:
            _log(
                "agent4_attack_paths",
                t0,
                "AI provider unavailable/exhausted — no attack paths discovered this run, not a genuine "
                "'no chains found' result. TCM defaulted to the no-chain baseline for every finding.",
                status="degraded",
            )
        else:
            _log(
                "agent4_attack_paths", t0, f"{len(attack_paths)} paths discovered, {len(choke_points)} choke points"
            )

        t0 = _start("agent5_risk_scoring")
        risk_register = await run_agent5(findings, assets, enrichment, tcm_by_finding, topology, router)
        _log("agent5_risk_scoring", t0, f"{len(risk_register)} findings scored")

        t0 = _start("agent6_compliance")
        compliance_register = run_agent6(findings, assets, risk_register)
        _log("agent6_compliance", t0, f"{len(compliance_register)} findings mapped to frameworks")

        t0 = _start("agent7_routing")
        team_briefs = run_agent7(findings, teams, risk_register, choke_points)
        _log("agent7_routing", t0, f"{len(team_briefs)} team briefs built")
    except Exception as exc:
        _publish({"agent_name": RUN_ERROR, "label": "", "status": "failed", "detail": str(exc)})
        raise

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
    _publish({"agent_name": RUN_COMPLETE, "label": "", "status": "ok", "detail": context.run_id})
    return context
