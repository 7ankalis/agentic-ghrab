"""Triage / Analyst Agent — powers the AI Analyst chat tab and the executive
one-paragraph synthesis on the Overview tab. Always grounded in the CMDB +
full findings table so it can answer ownership, attack-path, and compliance
questions without hallucinating hosts, CVEs, or teams."""
from __future__ import annotations

import pandas as pd

from agents.base import ask
from core.cmdb import CMDB


def _full_context(df: pd.DataFrame, cmdb: CMDB) -> str:
    cols = ["QID", "Title", "Severity", "CVSS_Base", "CVE_ID", "Hostname", "Zone",
            "Responsible_Team", "GRS", "GRS_Band", "Compliance_Ref", "Status"]
    table = df[cols].to_csv(index=False)
    return f"{cmdb.grounding_context(7000)}\n\nFULL FINDINGS TABLE (CSV, GRS-sorted):\n{table}"


def answer_question(question: str, df: pd.DataFrame, cmdb: CMDB,
                     chat_history: list[dict] | None = None, session_state=None,
                     paths_context: str = "") -> str:
    history_text = ""
    if chat_history:
        history_text = "\n\nPRIOR CONVERSATION:\n" + "\n".join(
            f"{m['role'].upper()}: {m['content']}" for m in chat_history[-6:]
        )
    paths_block = f"\n\nDISCOVERED ATTACK PATHS (engine-derived):\n{paths_context}" if paths_context else ""
    context = _full_context(df, cmdb) + paths_block + history_text
    task = (
        f"Operator question: {question}\n\n"
        "Answer directly and specifically, citing QIDs, hostnames, GRS scores and "
        "team names from the context. For attack-path questions, reason from the "
        "DISCOVERED ATTACK PATHS and the finding/CMDB reachability above — every hop "
        "you cite must map to a real finding and asset in the context; never invent a "
        "host, CVE, or connection. If the answer requires information not present, say "
        "what's missing rather than guessing."
    )
    try:
        return ask("triage", task, context, session_state=session_state, max_tokens=1200,
                   detail=f"chat: {question[:60]}")
    except Exception as exc:  # noqa: BLE001
        return f"AI Analyst unavailable: {exc}"


def _prior_findings_digest(discovery: dict | None, correlation: dict | None,
                            compliance: dict | None) -> str:
    """Compact digest of what the Discovery, Correlation, and Compliance agents
    already concluded. Triage runs last in the pipeline but, without this, it
    re-derives its own view from the raw table in isolation — which lets the
    dashboard's headline synthesis contradict the detail panels underneath it
    (e.g. naming a different 'most urgent finding' than the ranked #1 attack
    path). Feeding prior results in makes this an actual synthesis step."""
    parts: list[str] = []

    disc_paths = (discovery or {}).get("paths") or {}
    if disc_paths:
        top = sorted(disc_paths.values(),
                     key=lambda p: {"high": 0, "medium": 1, "low": 2}.get(p.get("confidence"), 3))[:3]
        lines = [f"  - {p.get('path_id')}: {p.get('headline', '')} "
                 f"(confidence={p.get('confidence', '?')}, choke_point={p.get('choke_point', '?')})"
                 for p in top]
        parts.append("DISCOVERY AGENT — top ranked attack chains (already validated):\n" + "\n".join(lines))
    combos = (discovery or {}).get("toxic_combinations") or []
    if combos:
        parts.append("DISCOVERY AGENT — toxic combinations already flagged:\n" +
                     "\n".join(f"  - {c.get('title')}" for c in combos[:3]))

    top_teams = (correlation or {}).get("top_risk_teams") or []
    if top_teams:
        parts.append("CORRELATION AGENT — top risk-owning teams already identified:\n" +
                     "\n".join(f"  - {t.get('team')}: {t.get('rationale', '')}" for t in top_teams[:3]))

    key_gaps = (compliance or {}).get("key_gaps") or []
    if key_gaps:
        parts.append("COMPLIANCE AGENT — key regulatory gaps already identified:\n" +
                     "\n".join(f"  - {g.get('framework')}: {g.get('gap_description', '')}" for g in key_gaps[:3]))

    return "\n\n".join(parts)


def executive_synthesis(df: pd.DataFrame, cmdb: CMDB, session_state=None,
                        discovery: dict | None = None, correlation: dict | None = None,
                        compliance: dict | None = None) -> str:
    context = _full_context(df, cmdb)
    digest = _prior_findings_digest(discovery, correlation, compliance)
    if digest:
        context += (
            "\n\nPRIOR AGENT FINDINGS (already validated by earlier pipeline stages — "
            f"your briefing must be CONSISTENT with these, not a competing guess):\n{digest}"
        )
    task = (
        "Write a 4-6 sentence executive briefing for the VOC admin dashboard's "
        "Overview tab. Cover: overall posture, the single most urgent finding "
        "(name it), the most exposed team, and one systemic pattern (e.g. a "
        "recurring class of misconfiguration). If PRIOR AGENT FINDINGS are given, "
        "anchor your 'most urgent finding' and 'most exposed team' on them rather "
        "than re-deriving your own answer — you are the final synthesis step, not "
        "an independent analysis. Direct, no filler, no headers."
    )
    try:
        return ask("triage", task, context, session_state=session_state, max_tokens=500,
                   detail="executive synthesis")
    except Exception as exc:  # noqa: BLE001
        return f"AI executive synthesis unavailable ({exc}). Add an API key in Settings to enable it."
