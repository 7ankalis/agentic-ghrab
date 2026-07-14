from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from agents.orchestrator import AnalysisResult
from ui.components import ai_box, ai_disabled_notice, divider, kpi_card
from ui.styles import CATEGORICAL, CHART_FONT_COLOR, GRID_COLOR, STATUS


def render(result: AnalysisResult):
    df = result.df

    st.markdown("### Executive Overview")

    total = len(df)
    immediate = int((df["GRS_Band"] == "IMMEDIATE").sum())
    act = int((df["GRS_Band"] == "ACT").sum())
    cif = int(df["DORA_CIF"].sum())
    avg_grs = round(df["GRS"].mean(), 1)
    kev_count = int(df["KEV"].sum())

    cols = st.columns(6)
    with cols[0]:
        kpi_card("Total Findings", str(total), "Confirmed, GRS-scored")
    with cols[1]:
        kpi_card("Immediate", str(immediate), "GRS 80-100 · 24-72h SLA")
    with cols[2]:
        kpi_card("Act", str(act), "GRS 60-79 · 7-day SLA")
    with cols[3]:
        kpi_card("Avg GRS", str(avg_grs), "0-100 composite risk score")
    with cols[4]:
        kpi_card("KEV-Listed", str(kev_count), "Actively exploited in the wild")
    with cols[5]:
        kpi_card("DORA CIF Scope", str(cif), "Critical/Important Function assets")

    divider()

    if result.ai_enabled and result.executive_summary:
        ai_box("AI Analyst — Executive Synthesis", result.executive_summary)
        divider()
    elif not result.ai_enabled:
        ai_disabled_notice("The executive synthesis")
        divider()

    c1, c2 = st.columns([1, 1.3])

    with c1:
        st.markdown("#### Risk Band Distribution")
        band_order = ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"]
        counts = df["GRS_Band"].value_counts().reindex(band_order).fillna(0).astype(int)
        colors = [STATUS[b]["color"] for b in band_order]
        fig = go.Figure(go.Bar(
            x=counts.values, y=band_order, orientation="h",
            marker_color=colors, text=counts.values, textposition="outside",
        ))
        fig.update_layout(
            height=280, margin=dict(l=10, r=30, t=10, b=10),
            xaxis=dict(showgrid=True, gridcolor=GRID_COLOR, title=None),
            yaxis=dict(title=None, autorange="reversed"),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CHART_FONT_COLOR, family="Lato"),
        )
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    with c2:
        st.markdown("#### Average GRS by Responsible Team")
        team_avg = df.groupby("Responsible_Team")["GRS"].mean().sort_values(ascending=True)
        fig2 = go.Figure(go.Bar(
            x=team_avg.values, y=team_avg.index, orientation="h",
            marker_color=CATEGORICAL[0],
            text=[f"{v:.1f}" for v in team_avg.values], textposition="outside",
        ))
        fig2.update_layout(
            height=280, margin=dict(l=10, r=30, t=10, b=10),
            xaxis=dict(showgrid=True, gridcolor=GRID_COLOR, title="Avg GRS", range=[0, 100]),
            yaxis=dict(title=None),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CHART_FONT_COLOR, family="Lato"),
        )
        st.plotly_chart(fig2, width="stretch", config={"displayModeBar": False})

    divider()

    c3, c4 = st.columns([1.3, 1])
    with c3:
        st.markdown("#### CVSS vs. GRS — where naive severity sorting gets it wrong")
        fig3 = px.scatter(
            df, x="CVSS_Base", y="GRS", color="GRS_Band",
            color_discrete_map={b: STATUS[b]["color"] for b in STATUS},
            hover_data=["QID", "Title", "Hostname"],
            category_orders={"GRS_Band": ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"]},
        )
        fig3.update_traces(marker=dict(size=11, line=dict(width=1, color="white")))
        fig3.update_layout(
            height=320, margin=dict(l=10, r=10, t=10, b=10),
            xaxis=dict(title="CVSS Base Score", gridcolor=GRID_COLOR, range=[0, 10.5]),
            yaxis=dict(title="Ghrab Risk Score (GRS)", gridcolor=GRID_COLOR, range=[0, 105]),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            legend_title=None, font=dict(color=CHART_FONT_COLOR, family="Lato"),
        )
        st.plotly_chart(fig3, width="stretch", config={"displayModeBar": False})
        st.caption(
            "Points above the diagonal trend are under-rated by CVSS alone (high exposure / "
            "blast radius pushing risk up); points below are over-rated by CVSS alone "
            "(isolated or low blast-radius findings)."
        )

    with c4:
        st.markdown("#### Top 5 Most Urgent Findings")
        top5 = df.nlargest(5, "GRS")[["QID", "Title", "Hostname", "GRS", "GRS_Band", "Responsible_Team"]]
        for _, r in top5.iterrows():
            color = STATUS[r["GRS_Band"]]["color"]
            st.markdown(
                f'<div class="finding-card" style="border-left:4px solid {color};">'
                f'<div class="title">GRS {r["GRS"]} — {r["Title"][:60]}</div>'
                f'<div class="meta">QID {r["QID"]} · {r["Hostname"]} · Owner: {r["Responsible_Team"]}</div>'
                f'</div>', unsafe_allow_html=True,
            )
