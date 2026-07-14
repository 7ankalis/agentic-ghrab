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
            "Responsible_Team", "GRS", "GRS_Band", "Attack_Path_Ref", "Compliance_Ref", "Status"]
    table = df[cols].to_csv(index=False)
    return f"{cmdb.summary_text(5000)}\n\nFULL FINDINGS TABLE (CSV, GRS-sorted):\n{table}"


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
        return ask("triage", task, context, session_state=session_state, max_tokens=1200)
    except Exception as exc:  # noqa: BLE001
        return f"AI Analyst unavailable: {exc}"


def executive_synthesis(df: pd.DataFrame, cmdb: CMDB, session_state=None) -> str:
    context = _full_context(df, cmdb)
    task = (
        "Write a 4-6 sentence executive briefing for the VOC admin dashboard's "
        "Overview tab. Cover: overall posture, the single most urgent finding "
        "(name it), the most exposed team, and one systemic pattern (e.g. a "
        "recurring class of misconfiguration). Direct, no filler, no headers."
    )
    try:
        return ask("triage", task, context, session_state=session_state, max_tokens=500)
    except Exception as exc:  # noqa: BLE001
        return f"AI executive synthesis unavailable ({exc}). Add an API key in Settings to enable it."
