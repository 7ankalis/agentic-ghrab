"""Correlation Agent — cross-references the full findings set against the CMDB
to surface 'toxic combinations' that aren't already captured as a documented
attack-path chain (e.g. two independently low findings that, combined with an
excessive-privilege misconfig, create a real path). Bounded to the standalone
/ non-chained findings plus the CMDB, so it doesn't re-derive what the
deterministic graph already proves."""
from __future__ import annotations

import pandas as pd

from agents.base import ask_json
from core.cmdb import CMDB


def find_toxic_combinations(df: pd.DataFrame, cmdb: CMDB, session_state=None) -> dict:
    cols = ["QID", "Title", "Hostname", "Zone", "Responsible_Team", "GRS", "Attack_Path_Ref"]
    findings_table = df[cols].to_csv(index=False)
    context = (
        f"{cmdb.summary_text(4000)}\n\nALL FINDINGS (CSV):\n{findings_table[:6000]}"
    )
    task = (
        "Review the findings and CMDB together. Identify correlation insights an "
        "operator would miss scanning the list top-to-bottom. Specifically: "
        "(1) which findings, though not already in a documented Attack_Path_Ref chain, "
        "still meaningfully raise organizational risk when considered together "
        "(only claim this if you can point to a real mechanism — shared asset, "
        "shared team, shared credential, network adjacency in the CMDB); "
        "(2) which teams are the top risk owners by aggregate exposure; "
        "(3) any finding you believe is currently mis-prioritized relative to its "
        "true blast radius. "
        "Respond as JSON with keys: 'cross_findings_insights' (list of strings), "
        "'top_risk_teams' (list of {team, rationale}), "
        "'reprioritization_flags' (list of {qid, hostname, reason})."
    )
    try:
        return ask_json("correlation", task, context, session_state=session_state, max_tokens=1800,
                        detail="cross-reference findings, assets & teams")
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
