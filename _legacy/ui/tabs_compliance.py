from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from agents.orchestrator import AnalysisResult
from ui.components import ai_box, ai_disabled_notice, divider
from ui.styles import CATEGORICAL, CHART_FONT_COLOR, GRID_COLOR


def render(result: AnalysisResult):
    df = result.df
    st.markdown("### Compliance & Regulatory Posture")

    cif_df = df[df["DORA_CIF"]]
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("DORA CIF-scoped findings", len(cif_df))
    with c2:
        st.metric("SLA-capped by DORA overlay", int(df["DORA_SLA_Capped"].sum()))
    with c3:
        frameworks = df["Compliance_Ref"].str.split(r"\s*/\s*").explode().str.split(" - ").str[0].str.strip()
        st.metric("Distinct framework references", frameworks.nunique())

    divider()
    st.markdown("#### Findings by Compliance Framework")
    fw_series = (
        df["Compliance_Ref"].str.split(r"\s*/\s*").explode().str.strip()
        .str.extract(r"^([A-Za-z\s\-]+)")[0].str.strip()
    )
    fw_counts = fw_series.value_counts().head(10)
    fig = go.Figure(go.Bar(
        x=fw_counts.values, y=fw_counts.index, orientation="h",
        marker_color=[CATEGORICAL[i % len(CATEGORICAL)] for i in range(len(fw_counts))],
        text=fw_counts.values, textposition="outside",
    ))
    fig.update_layout(
        height=340, margin=dict(l=10, r=30, t=10, b=10),
        xaxis=dict(title="Findings", gridcolor=GRID_COLOR),
        yaxis=dict(title=None, autorange="reversed"),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color=CHART_FONT_COLOR, family="Lato"),
    )
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    divider()
    st.markdown("#### DORA Critical/Important Function (CIF) Findings")
    st.caption(
        "Per EU DORA RTS Article 10: findings on assets supporting a critical or "
        "important function get their SLA capped at 30 days regardless of computed band."
    )
    st.dataframe(
        cif_df[["QID", "GRS", "GRS_Band", "Title", "Hostname", "GRS_SLA", "Responsible_Team"]],
        width="stretch", height=280, hide_index=True,
        column_config={"GRS": st.column_config.ProgressColumn("GRS", min_value=0, max_value=100, format="%.1f")},
    )

    divider()
    st.markdown("#### AI Compliance Briefing")
    briefing = result.compliance
    if not result.ai_enabled or not briefing or "error" in briefing:
        ai_disabled_notice("The compliance briefing")
        if briefing and "error" in briefing:
            st.error(briefing["error"])
        return

    ai_box("Executive Summary", briefing.get("executive_summary", ""))
    st.markdown(f"**DORA overlay note:** {briefing.get('dora_overlay_note', '')}")

    st.markdown("**Key gaps identified:**")
    for gap in briefing.get("key_gaps", []):
        refs = ", ".join(str(q) for q in gap.get("finding_refs", []))
        st.markdown(
            f"- **{gap.get('framework', 'N/A')}** — {gap.get('gap_description', '')} "
            f"(QIDs: {refs})"
        )

    fw_list = briefing.get("frameworks_in_scope", [])
    if fw_list:
        st.markdown(f"**Frameworks in scope:** {', '.join(fw_list)}")
