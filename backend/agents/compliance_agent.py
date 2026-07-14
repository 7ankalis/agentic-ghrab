"""Compliance Agent — reasons over the Compliance_Ref column plus the CMDB's
CDE/SWIFT scope and DORA CIF facts to produce a compliance-posture summary.
Grounded strictly in what's in the data; flags gaps rather than asserting
formal certification status the platform can't know."""
from __future__ import annotations

import pandas as pd

from agents.base import ask_json
from core.cmdb import CMDB


def compliance_summary(df: pd.DataFrame, cmdb: CMDB, session_state=None) -> dict:
    cif_df = df[df["DORA_CIF"] == True]  # noqa: E712
    cols = ["QID", "Title", "Hostname", "Compliance_Ref", "GRS", "GRS_Band", "DORA_CIF", "DORA_SLA_Capped"]
    table = df[cols].to_csv(index=False)
    context = (
        f"{cmdb.summary_text(3000)}\n\n"
        f"FINDINGS WITH COMPLIANCE REFERENCES (CSV):\n{table[:6000]}\n\n"
        f"DORA critical-or-important-function (CIF) scoped findings: {len(cif_df)} of {len(df)} total."
    )
    task = (
        "Produce a compliance posture briefing as JSON with keys: "
        "'frameworks_in_scope' (list of framework names referenced in the data, e.g. "
        "'PCI DSS', 'SWIFT CSP', 'EU DORA', 'CIS'), "
        "'key_gaps' (list of {framework, finding_refs (list of QIDs), gap_description}), "
        "'dora_overlay_note' (1-2 sentences on what the DORA CIF SLA overlay means "
        "operationally for the flagged findings), "
        "'executive_summary' (3-4 sentences an auditor or board member could read)."
    )
    try:
        return ask_json("compliance", task, context, session_state=session_state, max_tokens=1800)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
