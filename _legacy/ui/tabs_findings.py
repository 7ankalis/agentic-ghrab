from __future__ import annotations

import streamlit as st

from agents.orchestrator import AnalysisResult
from agents.remediation_agent import enrich_remediation
from ui.components import ai_box, divider, status_pill
from ui.styles import STATUS


def render(result: AnalysisResult):
    df = result.df
    st.markdown("### Vulnerability Findings")
    st.caption(
        f"{len(df)} confirmed findings, GRS-ranked. Sort any column by clicking its header; "
        f"use the filters below to narrow the list."
    )

    f1, f2, f3, f4 = st.columns(4)
    with f1:
        bands = st.multiselect("Risk band", ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"])
    with f2:
        teams = st.multiselect("Responsible team", sorted(df["Responsible_Team"].unique()))
    with f3:
        zones = st.multiselect("Zone", sorted(df["Zone"].unique()))
    with f4:
        search = st.text_input("Search (title, host, CVE, QID)", "")

    filtered = df.copy()
    if bands:
        filtered = filtered[filtered["GRS_Band"].isin(bands)]
    if teams:
        filtered = filtered[filtered["Responsible_Team"].isin(teams)]
    if zones:
        filtered = filtered[filtered["Zone"].isin(zones)]
    if search:
        s = search.lower()
        mask = (
            filtered["Title"].str.lower().str.contains(s)
            | filtered["Hostname"].str.lower().str.contains(s)
            | filtered["CVE_ID"].str.lower().str.contains(s)
            | filtered["QID"].astype(str).str.contains(s)
        )
        filtered = filtered[mask]

    st.caption(f"Showing {len(filtered)} of {len(df)} findings")

    display_cols = ["QID", "GRS", "GRS_Band", "Title", "Severity", "CVSS_Base", "CVE_ID",
                     "Hostname", "Zone", "Responsible_Team", "Exposure_Tier", "DORA_CIF", "Status"]
    st.dataframe(
        filtered[display_cols],
        width="stretch", height=420, hide_index=True,
        column_config={
            "GRS": st.column_config.ProgressColumn("GRS", min_value=0, max_value=100, format="%.1f"),
            "CVSS_Base": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "DORA_CIF": st.column_config.CheckboxColumn("DORA CIF"),
        },
    )

    divider()
    st.markdown("#### Finding Detail & AI Deep-Dive")
    qid_options = filtered["QID"].tolist() if len(filtered) else df["QID"].tolist()
    if not qid_options:
        st.info("No findings match the current filters.")
        return

    selected_qid = st.selectbox(
        "Select a finding to inspect",
        qid_options,
        format_func=lambda q: f"QID {q} — {df[df.QID == q].iloc[0]['Title'][:70]}",
    )
    row = df[df["QID"] == selected_qid].iloc[0]
    band = row["GRS_Band"]
    color = STATUS[band]["color"]

    left, right = st.columns([1.4, 1])
    with left:
        st.markdown(
            f'<div class="finding-card" style="border-left:5px solid {color};">'
            f'<div class="title" style="font-size:1.1rem;">{row["Title"]}</div>'
            f'<div class="meta">{status_pill(band)} &nbsp; GRS {row["GRS"]} &nbsp;|&nbsp; '
            f'CVSS {row["CVSS_Base"]} &nbsp;|&nbsp; {row["CVE_ID"]}</div>'
            f'<br><b>Host:</b> {row["Hostname"]} ({row["IP_Address"]}) — {row["Zone"]}<br>'
            f'<b>Responsible team:</b> {row["Responsible_Team"]}<br>'
            f'<b>Attack path ref:</b> {row["Attack_Path_Ref"]}<br>'
            f'<b>Compliance:</b> {row["Compliance_Ref"]}<br><br>'
            f'<b>Description:</b> {row["Description"]}<br><br>'
            f'<b>Consequence:</b> {row["Consequence"]}<br><br>'
            f'<b>Scanner remediation:</b> {row["Remediation"]}'
            f'</div>', unsafe_allow_html=True,
        )

    with right:
        st.markdown("**GRS Decomposition**")
        st.metric("GRS", f"{row['GRS']} / 100", row["GRS_SLA"])
        st.progress(min(row["GRS"] / 100, 1.0))
        st.markdown(
            f"""
| Factor | Value |
|---|---|
| CVSS (30%) | {row['CVSS_Base']} |
| EPSS (15%) | {row['EPSS']:.2f} |
| KEV listed (15%) | {'Yes' if row['KEV'] else 'No'} |
| Asset Criticality — ACW (20%) | {row['ACW']:.2f} |
| Toxic Combination — TCM (20%) | {row['TCM']}/10 |
| Impact Score | {row['Impact_Score']} |
| Exposure Tier | {row['Exposure_Tier']} (×{row['Exposure_Multiplier']}) |
| Compensating Controls (CCF) | ×{row['CCF']} |
| **DORA CIF scope** | {'Yes — SLA capped at 30 days' if row['DORA_CIF'] else 'No'} |
            """
        )

    divider()
    st.markdown("##### AI Remediation Agent — beyond the scanner text")
    cache_key = f"remediation_{selected_qid}"
    if st.button("Generate AI-enhanced remediation plan", key=f"btn_{selected_qid}"):
        with st.spinner("Remediation Agent is drafting an operational plan…"):
            st.session_state[cache_key] = enrich_remediation(row, result.cmdb, st.session_state)

    enrichment = st.session_state.get(cache_key)
    if enrichment:
        if "error" in enrichment:
            st.error(f"Remediation Agent unavailable: {enrichment['error']}")
        else:
            ai_box("Analyst Summary", enrichment.get("analyst_summary", ""))
            st.markdown("**Step-by-step remediation:**")
            for i, step in enumerate(enrichment.get("step_by_step", []), 1):
                st.markdown(f"{i}. {step}")
            st.markdown("**Validation steps:**")
            for step in enrichment.get("validation_steps", []):
                st.markdown(f"- {step}")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**Risk of fix:** {enrichment.get('risk_of_fix', 'N/A')}")
            with c2:
                st.markdown(f"**Estimated effort:** {enrichment.get('estimated_effort', 'N/A')}")
