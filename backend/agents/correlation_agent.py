"""Correlation Agent — cross-references the full findings set against the CMDB
grounding (asset ownership, zone reachability rules, credential-reuse and
dependency relationships) to surface 'toxic combinations': two or more findings
that are individually unremarkable but, chained through a shared credential,
excessive reachability rule, or dependency, create real organizational risk.

It is NOT given any pre-solved attack path — it reasons the correlations out of
the raw relationships, which is the point of the redesign."""
from __future__ import annotations

import pandas as pd

from agents.base import ask_json
from core.cmdb import CMDB


def find_toxic_combinations(df: pd.DataFrame, cmdb: CMDB, session_state=None) -> dict:
    cols = ["QID", "Title", "Hostname", "Zone", "Responsible_Team", "GRS", "Category"]
    findings_table = df[cols].to_csv(index=False)
    context = (
        f"{cmdb.grounding_context(7000)}\n\nALL FINDINGS (CSV):\n{findings_table[:6000]}"
    )
    task = (
        "Reason over the findings together with the CMDB relationships above. The "
        "CMDB gives you asset ownership, zone-to-zone reachability rules (some marked "
        "Excessive = a misconfiguration that opens a boundary), credential-reuse "
        "relationships, and host/app/db dependencies — but NOT any attack path. Derive "
        "the correlations an operator scanning the list top-to-bottom would miss: "
        "(1) which findings, considered together, meaningfully raise organizational "
        "risk — only claim this when you can name the concrete mechanism that links "
        "them (a shared credential from the identity table, an Excessive reachability "
        "rule, a dependency or hosting relationship); "
        "(2) which teams are the top risk owners by aggregate exposure; "
        "(3) any finding currently mis-prioritized relative to its true blast radius "
        "(e.g. a 'low' finding on an asset that a credential relationship makes a pivot "
        "into a crown jewel). "
        "Respond as JSON with keys: 'cross_findings_insights' (list of strings, each "
        "citing the QIDs and the linking mechanism), "
        "'top_risk_teams' (list of {team, rationale}), "
        "'reprioritization_flags' (list of {qid, hostname, reason})."
    )
    try:
        result = ask_json("correlation", task, context, session_state=session_state, max_tokens=1800,
                          detail="cross-reference findings, assets & teams")
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    known_qids = {int(q) for q in df["QID"]}
    flags = result.get("reprioritization_flags", [])
    verified, dropped = [], 0
    for flag in flags:
        try:
            qid = int(flag.get("qid"))
        except (TypeError, ValueError):
            qid = None
        if qid not in known_qids:
            # Never surface a "mis-prioritized finding" that doesn't exist.
            dropped += 1
            continue
        verified.append(flag)
    result["reprioritization_flags"] = verified
    if dropped:
        result["dropped_reprioritization_flags"] = dropped
    return result
