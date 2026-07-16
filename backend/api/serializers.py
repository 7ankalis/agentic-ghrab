"""Pure serializers: turn an AnalysisResult into JSON-safe dicts for the SPA.
Kept separate from the engine so the API layer never leaks numpy/pandas types."""
from __future__ import annotations

import math
from typing import Any

import pandas as pd

from agents.orchestrator import AnalysisResult
from core.attack_graph import INTERNET, HostNode
from core.risk_engine import ACTION_BANDS

BAND_ORDER = ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"]


def _clean(v: Any) -> Any:
    """Coerce numpy/pandas scalars to plain JSON-safe Python."""
    if isinstance(v, (pd.Series,)):
        return [_clean(x) for x in v.tolist()]
    if hasattr(v, "item"):
        try:
            v = v.item()
        except Exception:  # noqa: BLE001
            pass
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return None
    return v


def finding_row(row: pd.Series, caps: dict, path_refs: list[str] | None = None) -> dict:
    qid = int(row["QID"])
    cap = caps.get(qid)
    return {
        "qid": qid,
        "title": str(row["Title"]),
        "severity": int(row["Severity"]),
        "cvss": _clean(row["CVSS_Base"]),
        "cvss_vector": str(row.get("CVSS_Vector", "")),
        "cve": str(row["CVE_ID"]),
        "category": str(row["Category"]),
        "ip": str(row["IP_Address"]),
        "hostname": str(row["Hostname"]),
        "vlan": str(row["VLAN_ID"]),
        "zone": str(row["Zone"]),
        "port": str(row.get("Port", "")),
        "service": str(row.get("Service_Protocol", "")),
        "team": str(row["Responsible_Team"]),
        "status": str(row["Status"]),
        "compliance_ref": str(row["Compliance_Ref"]),
        # The documented answer-key column was removed from the ingested data; a
        # finding's path membership is now whatever the engine *discovered* it in.
        "attack_path_ref": "",
        "discovered_path_refs": path_refs or [],
        "grs": _clean(row["GRS"]),
        "band": str(row["GRS_Band"]),
        "sla": str(row["GRS_SLA"]),
        "impact_score": _clean(row["Impact_Score"]),
        "exposure_tier": str(row["Exposure_Tier"]),
        "exposure_multiplier": _clean(row["Exposure_Multiplier"]),
        "epss": _clean(row["EPSS"]),
        "kev": bool(row["KEV"]),
        "acw": _clean(row["ACW"]),
        "tcm": _clean(row["TCM"]),
        "ccf": _clean(row["CCF"]),
        "dora_cif": bool(row["DORA_CIF"]),
        "dora_sla_capped": bool(row["DORA_SLA_Capped"]),
        "capability": {
            "technique": cap.technique if cap else "",
            "tactic": cap.mitre_tactic if cap else "",
            "effects": cap.effects if cap else [],
            "precondition": cap.precondition if cap else "",
            "is_entry": cap.is_entry if cap else False,
        } if cap else None,
    }


def finding_detail(row: pd.Series, caps: dict) -> dict:
    base = finding_row(row, caps)
    base.update({
        "description": str(row["Description"]),
        "consequence": str(row["Consequence"]),
        "remediation": str(row["Remediation"]),
        "patch_available": str(row.get("Patch_Available", "")),
        "grs_factors": [
            {"label": "CVSS Base", "weight": "30%", "value": _clean(row["CVSS_Base"])},
            {"label": "EPSS", "weight": "15%", "value": _clean(row["EPSS"])},
            {"label": "KEV Listed", "weight": "15%", "value": "Yes" if row["KEV"] else "No"},
            {"label": "Asset Criticality (ACW)", "weight": "20%", "value": _clean(row["ACW"])},
            {"label": "Toxic Combination (TCM)", "weight": "20%", "value": f'{int(row["TCM"])}/10'},
        ],
    })
    return base


def _qid_to_discovered_paths(result: AnalysisResult) -> dict[int, list[str]]:
    """Map each finding QID to the discovered path ids (DISC-xx) whose chain it
    enables — so the Findings table can show engine-derived path membership in
    place of the removed hardcoded Attack_Path_Ref column."""
    out: dict[int, list[str]] = {}
    for p in result.paths:
        for qid in p.enabler_qids:
            out.setdefault(int(qid), []).append(p.path_id)
    return out


def findings_list(result: AnalysisResult) -> list[dict]:
    path_map = _qid_to_discovered_paths(result)
    return [finding_row(r, result.caps, path_map.get(int(r["QID"]), []))
            for _, r in result.df.iterrows()]


def kpis(result: AnalysisResult) -> dict:
    df = result.df
    counts = {b: int((df["GRS_Band"] == b).sum()) for b in BAND_ORDER}
    return {
        "total": int(len(df)),
        "immediate": counts["IMMEDIATE"],
        "act": counts["ACT"],
        "avg_grs": round(float(df["GRS"].mean()), 1),
        "kev": int(df["KEV"].sum()),
        "dora_cif": int(df["DORA_CIF"].sum()),
        "band_distribution": [{"band": b, "count": counts[b]} for b in BAND_ORDER],
        "discovered_paths": len(result.paths),
        "crown_jewels": sum(1 for n in result.nodes.values() if n.is_crown_jewel),
        "ai_enabled": result.ai_enabled,
    }


def team_stats(result: AnalysisResult) -> list[dict]:
    df = result.df.assign(
        Responsible_Team=result.df["Responsible_Team"].str.split(r"\s*/\s*")
    ).explode("Responsible_Team")
    rows = []
    for team, g in df.groupby("Responsible_Team"):
        rows.append({
            "team": team,
            "findings": int(len(g)),
            "avg_grs": round(float(g["GRS"].mean()), 1),
            "max_grs": round(float(g["GRS"].max()), 1),
            "immediate": int((g["GRS_Band"] == "IMMEDIATE").sum()),
            "kev": int(g["KEV"].sum()),
            "dora_cif": int(g["DORA_CIF"].sum()),
        })
    return sorted(rows, key=lambda r: r["max_grs"], reverse=True)


def cvss_vs_grs(result: AnalysisResult) -> list[dict]:
    df = result.df
    return [{
        "qid": int(r["QID"]), "title": str(r["Title"])[:60], "hostname": str(r["Hostname"]),
        "cvss": _clean(r["CVSS_Base"]), "grs": _clean(r["GRS"]), "band": str(r["GRS_Band"]),
    } for _, r in df.iterrows()]


def _title_lookup(df: pd.DataFrame) -> dict[int, dict]:
    return {int(r["QID"]): {"title": str(r["Title"]), "hostname": str(r["Hostname"]),
                            "grs": _clean(r["GRS"]), "band": str(r["GRS_Band"]),
                            "team": str(r["Responsible_Team"])}
            for _, r in df.iterrows()}


def attack_paths(result: AnalysisResult) -> list[dict]:
    lookup = _title_lookup(result.df)
    narratives = (result.discovery or {}).get("paths", {})
    out = []
    for p in result.paths:
        enrich = narratives.get(p.path_id, {})
        d = p.as_dict()
        for s in d["steps"]:
            av, ex = s.get("arrival_via_qid"), s.get("exploit_qid")
            s["arrival_finding"] = lookup.get(av) if av else None
            s["exploit_finding"] = lookup.get(ex) if ex else None
        d["headline"] = enrich.get("headline", "")
        d["narrative"] = enrich.get("narrative", "")
        d["business_impact"] = enrich.get("business_impact", "")
        d["choke_point"] = enrich.get("choke_point", "")
        d["confidence"] = enrich.get("confidence", "")
        d["novelty"] = enrich.get("novelty", "")
        out.append(d)
    return out


def _canon_host(name: str, host_set: set[str]) -> str:
    n = str(name).strip()
    for h in host_set:
        if h == n or (n and (n.lower().startswith(h.lower()) or h.lower() in n.lower())):
            return h
    return n


def verification(result: AnalysisResult) -> dict:
    """Scores whether the held-out documented attack paths (data/oracle, never
    shown to the engine or agents) were independently rediscovered — by the
    deterministic reachability engine and by the Analyst Detection Agent. This is
    the "is my detection system actually working?" view: the answer key exists
    only to grade the system, not to feed it."""
    import networkx as nx

    g = result.graph
    host_set = set(result.nodes)
    engine_targets = {p.target for p in result.paths}
    detected = (result.detected or {}).get("detected_paths", [])
    detected_targets = {
        _canon_host(d.get("target", ""), host_set) for d in detected
    } & host_set

    rows, engine_ok, ai_ok = [], 0, 0
    for c in result.documented_chains:
        entry = _canon_host(c.entry_point, host_set)
        target = _canon_host(c.target, host_set)
        engine_hit = target in engine_targets or (
            entry in g and target in g
            and nx.has_path(g, INTERNET, entry) and nx.has_path(g, entry, target)
        )
        ai_hit = target in detected_targets
        engine_ok += engine_hit
        ai_ok += ai_hit
        rows.append({
            "path_id": c.path_id, "entry": entry, "target": target,
            "engine_rediscovered": bool(engine_hit), "ai_detected": bool(ai_hit),
        })
    total = len(result.documented_chains)
    return {
        "documented_total": total,
        "engine_rediscovered": engine_ok,
        "ai_detected": ai_ok,
        "ai_enabled": result.ai_enabled,
        "paths": rows,
        "note": ("Documented paths are held-out ground truth (data/oracle/), never "
                 "ingested and never shown to the engine or the agents. This grades "
                 "whether they were rediscovered from the raw grounding alone."),
    }


def ai_detected_paths(result: AnalysisResult) -> list[dict]:
    """The Analyst Detection Agent's independently-reasoned paths (already hop-
    verified against real hosts/QIDs in the agent). Enriched with finding titles."""
    lookup = _title_lookup(result.df)
    out = []
    for d in (result.detected or {}).get("detected_paths", []):
        hops = []
        for h in d.get("hops", []):
            via = h.get("via_qid")
            hops.append({**h, "finding": lookup.get(int(via)) if via else None})
        out.append({**d, "hops": hops})
    return out


def graph_payload(result: AnalysisResult) -> dict:
    g, nodes = result.graph, result.nodes
    node_list = [{
        "id": INTERNET, "label": "Internet", "kind": "internet",
        "zone": "External", "vlan": "", "grs": 0, "crown": False,
        "value": 0, "entry": False, "team": "",
    }]
    for h, n in nodes.items():
        node_list.append({
            "id": h, "label": h, "kind": "asset",
            "zone": n.zone, "vlan": n.vlan, "grs": round(n.max_grs, 1),
            "crown": n.is_crown_jewel, "value": n.target_value,
            "entry": n.is_entry, "team": n.team, "role": n.role,
            "qids": n.qids,
        })
    edge_list = []
    for u, v, data in g.edges(data=True):
        edge_list.append({
            "source": u, "target": v, "kind": data.get("kind", "lateral"),
            "qid": data.get("qid"), "technique": data.get("technique", ""),
        })
    return {"nodes": node_list, "edges": edge_list}


def overview(result: AnalysisResult) -> dict:
    df = result.df
    top5 = df.nlargest(5, "GRS")
    return {
        "kpis": kpis(result),
        "executive_summary": result.executive_summary,
        "cvss_vs_grs": cvss_vs_grs(result),
        "top_findings": [finding_row(r, result.caps) for _, r in top5.iterrows()],
        "top_paths": attack_paths(result)[:5],
        "action_bands": [{"low": lo, "high": hi, "band": b, "sla": s}
                         for lo, hi, b, s in ACTION_BANDS],
        "generated_at": result.generated_at,
    }
