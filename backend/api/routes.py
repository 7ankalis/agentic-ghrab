"""REST endpoints for the SPA."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from agents.remediation_agent import enrich_remediation
from api import serializers as S
from api.state import get_analysis, invalidate, runtime_settings, switch_dataset
from core import datasets as datasets_mod
from core.config import (
    AGENT_ROLE_LABELS, AGENT_ROLES, DEFAULT_AGENT_PROVIDER, PROVIDERS,
    configured_providers,
)

router = APIRouter(prefix="/api")


# ---- Datasets / enterprise selection ----
def _dataset_json(d, active_key: str) -> dict:
    return {
        "key": d.key, "name": d.name, "sector": d.sector,
        "frameworks": d.frameworks, "findings": d.findings,
        "has_architecture": d.has_architecture, "active": d.key == active_key,
    }


@router.get("/datasets")
def list_datasets():
    """Every enterprise that can be scanned (has both a *_vulnerabilities.csv and
    a *_architecture.md in the data dir), plus which one is currently active."""
    active = datasets_mod.get_active()
    return {
        "active": active.key,
        "datasets": [_dataset_json(d, active.key) for d in datasets_mod.discover()],
    }


class DatasetSelect(BaseModel):
    key: str


@router.post("/datasets/select")
def select_dataset(body: DatasetSelect):
    """Set the active enterprise. Flushes the cached data + analysis so the next
    load rebuilds against the chosen dataset; the operator then runs the pipeline
    from the existing Full Analysis / Re-run controls."""
    try:
        ds = switch_dataset(body.key)
    except KeyError:
        raise HTTPException(404, f"Unknown dataset {body.key!r}")
    return {"ok": True, "active": ds.key, "name": ds.name}


@router.get("/overview")
def overview():
    return S.overview(get_analysis())


@router.get("/kpis")
def kpis():
    return S.kpis(get_analysis())


@router.get("/findings")
def findings():
    r = get_analysis()
    return {"findings": S.findings_list(r), "total": len(r.df)}


@router.get("/findings/{qid}")
def finding(qid: int):
    r = get_analysis()
    match = r.df[r.df["QID"] == qid]
    if match.empty:
        raise HTTPException(404, f"QID {qid} not found")
    return S.finding_detail(match.iloc[0], r.caps)


@router.get("/findings/{qid}/remediation")
def get_remediation(qid: int):
    """Previously generated remediation plan for this QID, if any — lets the
    SPA restore the AI panel on page refresh instead of losing it once the
    in-flight mutation's React state is gone."""
    r = get_analysis()
    cached = r.remediations.get(qid)
    return cached if cached is not None else {"generated": False}


@router.post("/findings/{qid}/remediation")
def remediation(qid: int):
    r = get_analysis()
    match = r.df[r.df["QID"] == qid]
    if match.empty:
        raise HTTPException(404, f"QID {qid} not found")
    if not r.ai_enabled:
        raise HTTPException(409, "No AI provider connected. Add a key in Settings.")
    result = enrich_remediation(match.iloc[0], r.cmdb, runtime_settings)
    if not result.get("error"):
        r.remediations[qid] = result
    return result


@router.get("/attack-paths")
def attack_paths():
    r = get_analysis()
    return {
        "paths": S.attack_paths(r),
        "ai_detected": S.ai_detected_paths(r),
        "toxic_combinations": (r.discovery or {}).get("toxic_combinations", []),
        "summary": (r.discovery or {}).get("summary", ""),
        "documented": [
            {"path_id": c.path_id, "entry": c.entry_point, "target": c.target,
             "hosts": [s.hostname for s in c.steps]}
            for c in r.documented_chains
        ],
        "ai_enabled": r.ai_enabled,
    }


@router.get("/verification")
def verification():
    """Grades engine + AI-agent rediscovery of the held-out documented paths."""
    return S.verification(get_analysis())


@router.get("/graph")
def graph():
    return S.graph_payload(get_analysis())


@router.get("/correlation")
def correlation():
    r = get_analysis()
    return {"correlation": r.correlation, "ai_enabled": r.ai_enabled}


@router.get("/compliance")
def compliance():
    r = get_analysis()
    return {"compliance": r.compliance, "ai_enabled": r.ai_enabled}


@router.get("/teams")
def teams():
    return {"teams": S.team_stats(get_analysis())}


# ---- Settings / providers ----
class ProviderKey(BaseModel):
    provider: str
    api_key: str


class AgentAssignment(BaseModel):
    role: str
    provider: str


@router.get("/settings/providers")
def get_providers():
    configured = set(configured_providers(runtime_settings))
    return {
        "providers": [
            {"key": p.key, "label": p.label, "default_model": p.default_model,
             "docs_hint": p.docs_hint, "configured": p.key in configured}
            for p in PROVIDERS.values()
        ],
        "agents": [
            {"role": role, "label": AGENT_ROLE_LABELS[role],
             "provider": runtime_settings.get(f"agent_provider_{role}",
                                              DEFAULT_AGENT_PROVIDER.get(role))}
            for role in AGENT_ROLES
        ],
    }


@router.post("/settings/providers")
def set_provider(body: ProviderKey):
    if body.provider not in PROVIDERS:
        raise HTTPException(400, "Unknown provider")
    if body.api_key:
        runtime_settings[f"apikey_{body.provider}"] = body.api_key
    else:
        runtime_settings.pop(f"apikey_{body.provider}", None)
    invalidate()  # AI layer may now be available/unavailable
    return {"ok": True, "configured": configured_providers(runtime_settings)}


@router.post("/settings/agent")
def set_agent(body: AgentAssignment):
    if body.role not in AGENT_ROLES or body.provider not in PROVIDERS:
        raise HTTPException(400, "Unknown role or provider")
    runtime_settings[f"agent_provider_{body.role}"] = body.provider
    invalidate()
    return {"ok": True}
