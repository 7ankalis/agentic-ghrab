"""FastAPI backend for the VMC triage board.

One manual action in the whole UX: `POST /api/run` kicks off the full
Agent 1-5 pipeline (ingest -> topology/exposure -> threat intel -> attack
path correlation -> GRS scoring + AI explanation). Every other endpoint just
reads the cached result — no per-finding AI-triage button, no click-through
scoring. `GET /api/run/latest` returns findings pre-sorted by GRS descending
with the full auditable breakdown, so the frontend never has to compute or
re-request anything per row.

Run with:
    .venv/bin/uvicorn vmc.api.main:app --reload
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from vmc.agents.compliance import framework_rollup
from vmc.models import ExposureContext
from vmc.orchestrator import get_cached_context, run_pipeline
from vmc.providers.router import ModelRouter

ROOT = Path(__file__).parent.parent.parent.parent  # vmc-platform/
load_dotenv(ROOT / ".env")

STATIC_DIR = Path(__file__).parent / "static"

FINDINGS_CSV = Path(os.environ.get("VMC_FINDINGS_CSV", ROOT / "docs" / "sample_data" / "ghrab_vulnerabilities.csv"))
ARCHITECTURE_MD = Path(os.environ.get("VMC_ARCHITECTURE_MD", ROOT / "docs" / "sample_data" / "ghrab_architecture.md"))

app = FastAPI(title="VMC — Vulnerability Management Center")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Provider registry — one factory per vendor whose API key/config is present.
# ModelRouter.providers_for() already tolerates a missing entry (skips it and
# falls through the chain), so registering only what's configured is what
# makes `fallback_chain` in model_router.yaml a real fallback instead of a
# theoretical one.
# ---------------------------------------------------------------------------

_router: ModelRouter | None = None


def _build_provider_registry() -> dict:
    registry: dict = {}

    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        from vmc.providers.groq_provider import GroqProvider

        registry["groq"] = lambda model, temperature: GroqProvider(model, temperature, api_key=groq_key)

    gemini_key = os.environ.get("GEMINI_API_KEY")
    if gemini_key:
        from vmc.providers.gemini_provider import GeminiProvider

        registry["gemini"] = lambda model, temperature: GeminiProvider(model, temperature, api_key=gemini_key)

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        from vmc.providers.openai_provider import OpenAIProvider

        registry["openai"] = lambda model, temperature: OpenAIProvider(model, temperature, api_key=openai_key)

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        from vmc.providers.anthropic_provider import AnthropicProvider

        registry["anthropic"] = lambda model, temperature: AnthropicProvider(model, temperature, api_key=anthropic_key)

    # Ollama needs no key — a local daemon is either reachable or it isn't.
    from vmc.providers.ollama_provider import OllamaProvider

    ollama_host = os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
    registry["ollama"] = lambda model, temperature: OllamaProvider(model, temperature, host=ollama_host)

    return registry


def _get_router() -> ModelRouter | None:
    global _router
    if _router is None:
        registry = _build_provider_registry()
        if not registry:
            return None
        _router = ModelRouter.from_yaml(ROOT / "config" / "model_router.yaml", registry)
    return _router


# ---------------------------------------------------------------------------
# Pipeline run endpoints
# ---------------------------------------------------------------------------


class RunResult(BaseModel):
    run_id: str
    finding_count: int


def _require_sample_data() -> None:
    if not FINDINGS_CSV.exists() or not ARCHITECTURE_MD.exists():
        raise HTTPException(
            status_code=500,
            detail=(
                f"sample data not found — expected {FINDINGS_CSV} and {ARCHITECTURE_MD}. "
                "Drop the Ghrab dataset into docs/sample_data/ (see docs/sample_data/README.md)."
            ),
        )


def _get_context() -> ExposureContext:
    """Read-only — never executes the pipeline. Every GET endpoint uses
    this, so a page load or dashboard poll can never accidentally trigger
    Agent 5's AI calls; only `POST /api/run` does that."""
    _require_sample_data()
    context = get_cached_context(FINDINGS_CSV, ARCHITECTURE_MD)
    if context is None:
        raise HTTPException(status_code=409, detail="no analysis run yet — POST /api/run first")
    return context


@app.post("/api/run")
async def start_run() -> RunResult:
    _require_sample_data()
    context = await run_pipeline(FINDINGS_CSV, ARCHITECTURE_MD, _get_router())
    return RunResult(run_id=context.run_id, finding_count=len(context.findings))


@app.get("/api/run/latest")
async def get_latest_run() -> dict:
    context = _get_context()
    rows = []
    for finding in context.findings:
        assessment = context.risk_register.get(finding.finding_id)
        asset = context.assets.get(finding.asset_hostname) or context.assets.get(finding.asset_ip)
        rows.append(
            {
                **finding.model_dump(),
                "risk": assessment.model_dump() if assessment else None,
                "criticality_tier": asset.criticality_tier if asset else None,
                "compliance_scope": asset.compliance_scope if asset else [],
            }
        )
    rows.sort(key=lambda r: (r["risk"]["score"] if r["risk"] else -1), reverse=True)

    return {
        "run_id": context.run_id,
        "findings": rows,
        "attack_paths": {ref: path.model_dump() for ref, path in context.attack_paths.items()},
        "choke_points": [cp.model_dump() for cp in context.choke_points],
        "segmentation_findings": [sf.model_dump() for sf in context.segmentation_findings],
        "agent_logs": [log.model_dump() for log in context.agent_logs],
    }


@app.get("/api/teams")
async def get_teams() -> list[dict]:
    context = _get_context()
    briefs = sorted(
        context.team_briefs.values(),
        key=lambda b: b.band_counts.get("IMMEDIATE", 0) * 1000 + b.band_counts.get("ACT", 0),
        reverse=True,
    )
    return [b.model_dump() for b in briefs]


@app.get("/api/compliance")
async def get_compliance() -> dict:
    context = _get_context()
    rollup = framework_rollup(context.compliance_register, context.risk_register)
    return {
        "frameworks": sorted(rollup.values(), key=lambda r: r["worst_score"], reverse=True),
        "findings": {
            finding_id: cf.model_dump() for finding_id, cf in context.compliance_register.items()
        },
    }


@app.get("/api/summary")
async def get_summary() -> dict:
    context = _get_context()
    findings = context.findings
    band_counts: dict[str, int] = {}
    dora_count = 0
    for finding in findings:
        assessment = context.risk_register.get(finding.finding_id)
        band = assessment.band if assessment else "Unscored"
        band_counts[band] = band_counts.get(band, 0) + 1
        if assessment and assessment.dora_cif_scope:
            dora_count += 1
    return {
        "run_id": context.run_id,
        "total_findings": len(findings),
        "total_assets": len(context.assets),
        "total_teams": len(context.teams),
        "total_zones": len(context.topology.zones),
        "data_quality_issue_count": len(context.data_quality_issues),
        "band_counts": band_counts,
        "dora_cif_scope_count": dora_count,
        "categories": sorted({f.category for f in findings}),
        "teams": sorted({f.responsible_team for f in findings}),
        "zones": sorted({f.zone for f in findings}),
    }


@app.get("/api/data-quality-issues")
async def get_data_quality_issues() -> list[dict]:
    context = _get_context()
    return [issue.model_dump() for issue in context.data_quality_issues]


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
