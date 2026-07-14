"""Remediation Agent — enriches a single finding's remediation guidance beyond
the raw scanner text: concrete step-by-step actions, validation steps, and
rollback/risk notes. Called on-demand per finding (not in the bulk pipeline)
to keep the one-click ingest fast and cheap."""
from __future__ import annotations

import pandas as pd

from agents.base import ask_json
from core.cmdb import CMDB


def enrich_remediation(finding_row: pd.Series, cmdb: CMDB, session_state=None) -> dict:
    context = (
        f"{cmdb.summary_text(3000)}\n\nFINDING:\n"
        f"QID: {finding_row['QID']}\nTitle: {finding_row['Title']}\n"
        f"CVE: {finding_row['CVE_ID']}\nCVSS: {finding_row['CVSS_Base']}\n"
        f"GRS: {finding_row['GRS']} ({finding_row['GRS_Band']})\n"
        f"Host: {finding_row['Hostname']} ({finding_row['IP_Address']}, "
        f"{finding_row['Zone']})\n"
        f"Description: {finding_row['Description']}\n"
        f"Consequence: {finding_row['Consequence']}\n"
        f"Scanner-provided remediation: {finding_row['Remediation']}\n"
        f"Responsible team: {finding_row['Responsible_Team']}\n"
        f"Compliance ref: {finding_row['Compliance_Ref']}"
    )
    task = (
        "Go beyond the scanner-provided remediation text. Produce a JSON object with: "
        "'analyst_summary' (2-3 sentences, plain-English risk framing for a non-technical "
        "stakeholder), "
        "'step_by_step' (ordered list of concrete remediation steps, more detailed and "
        "operational than the scanner text — include specific commands/settings where "
        "you can responsibly infer them from the finding type), "
        "'validation_steps' (how the responsible team proves the fix worked), "
        "'risk_of_fix' (1-2 sentences on any operational risk the fix itself introduces, "
        "e.g. service restart, or 'Low' if none), "
        "'estimated_effort' (one of: 'Low (<1 day)', 'Medium (1-3 days)', 'High (>3 days, change-managed)')."
    )
    try:
        return ask_json("remediation", task, context, session_state=session_state, max_tokens=1600,
                        detail=f"remediation QID {finding_row['QID']}")
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
