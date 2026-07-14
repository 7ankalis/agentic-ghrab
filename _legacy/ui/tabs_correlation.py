from __future__ import annotations

import streamlit as st

from agents.orchestrator import AnalysisResult
from ui.components import ai_disabled_notice, divider


def render(result: AnalysisResult):
    st.markdown("### Correlation & Toxic Combinations")
    st.caption(
        "The Correlation Agent cross-references every finding against the CMDB looking "
        "for risk that isn't already captured in a documented attack-path chain — shared "
        "assets, shared credentials, or shared teams that combine into something worse "
        "than any single finding suggests."
    )

    corr = result.correlation
    if not result.ai_enabled or not corr or "error" in corr:
        ai_disabled_notice("The Correlation Agent")
        if corr and "error" in corr:
            st.error(corr["error"])
        return

    insights = corr.get("cross_findings_insights", [])
    if insights:
        st.markdown("#### Cross-Finding Insights")
        for i in insights:
            st.markdown(f"- {i}")

    divider()
    st.markdown("#### Top Risk-Owning Teams")
    for t in corr.get("top_risk_teams", []):
        st.markdown(f"**{t.get('team', 'N/A')}** — {t.get('rationale', '')}")

    divider()
    st.markdown("#### Reprioritization Flags")
    flags = corr.get("reprioritization_flags", [])
    if not flags:
        st.caption("No reprioritization flags raised this run.")
    for f in flags:
        st.markdown(
            f"- **QID {f.get('qid', '?')}** ({f.get('hostname', '')}): {f.get('reason', '')}"
        )
