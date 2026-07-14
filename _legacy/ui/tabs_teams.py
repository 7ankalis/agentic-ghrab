from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from agents.orchestrator import AnalysisResult
from ui.components import divider, status_pill
from ui.styles import CATEGORICAL, CHART_FONT_COLOR, GRID_COLOR

# In-scope for this build: no team login/auth. This models the assign/alert
# workflow an admin drives from a single pane — the notification itself is a
# UI-visible simulation (toast + session log), ready to wire to email/Slack/
# Teams webhooks once a real notification backend is chosen.
TEAM_CONTACTS = {
    "IT Infrastructure Team": "it-infra-oncall@ghrabfinancial.example",
    "Network Team": "network-oncall@ghrabfinancial.example",
    "AppSec Team": "appsec-oncall@ghrabfinancial.example",
    "DBA Team": "dba-oncall@ghrabfinancial.example",
    "Cloud Team": "cloud-oncall@ghrabfinancial.example",
    "Compliance-GRC Team": "grc-oncall@ghrabfinancial.example",
}


def render(result: AnalysisResult):
    df = result.df
    st.markdown("### Teams & Ownership")
    st.caption(
        "Every team's exposure, at a glance. Assign findings and trigger alerts "
        "directly from here; no per-team login is required for this build."
    )

    # normalize multi-owner rows like "AppSec Team / IT Infrastructure Team"
    exploded = df.assign(
        Responsible_Team=df["Responsible_Team"].str.split(r"\s*/\s*")
    ).explode("Responsible_Team")

    team_stats = (
        exploded.groupby("Responsible_Team")
        .agg(findings=("QID", "count"), avg_grs=("GRS", "mean"), max_grs=("GRS", "max"),
             immediate=("GRS_Band", lambda s: (s == "IMMEDIATE").sum()))
        .reset_index()
        .sort_values("max_grs", ascending=False)
    )

    c1, c2 = st.columns([1.2, 1])
    with c1:
        st.markdown("#### Exposure by Team")
        fig = go.Figure(go.Bar(
            x=team_stats["Responsible_Team"], y=team_stats["findings"],
            marker_color=[CATEGORICAL[i % len(CATEGORICAL)] for i in range(len(team_stats))],
            text=team_stats["findings"], textposition="outside",
        ))
        fig.update_layout(
            height=320, margin=dict(l=10, r=10, t=10, b=90),
            xaxis=dict(title=None, tickangle=-30), yaxis=dict(title="Findings", gridcolor=GRID_COLOR),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color=CHART_FONT_COLOR, family="Lato"),
        )
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    with c2:
        st.markdown("#### Peak Risk by Team")
        for _, r in team_stats.iterrows():
            band = ("IMMEDIATE" if r["max_grs"] >= 80 else "ACT" if r["max_grs"] >= 60
                     else "ATTEND" if r["max_grs"] >= 40 else "TRACK*" if r["max_grs"] >= 20 else "TRACK")
            st.markdown(
                f'<div class="finding-card">'
                f'<div class="title">{r["Responsible_Team"]} {status_pill(band)}</div>'
                f'<div class="meta">{int(r["findings"])} findings · avg GRS {r["avg_grs"]:.1f} · '
                f'{int(r["immediate"])} IMMEDIATE</div></div>', unsafe_allow_html=True,
            )

    divider()
    st.markdown("#### Assign & Alert a Team")
    team = st.selectbox("Team", team_stats["Responsible_Team"].tolist())
    team_findings = exploded[exploded["Responsible_Team"] == team].sort_values("GRS", ascending=False)
    st.dataframe(
        team_findings[["QID", "GRS", "GRS_Band", "Title", "Hostname", "Status"]],
        width="stretch", height=260, hide_index=True,
        column_config={"GRS": st.column_config.ProgressColumn("GRS", min_value=0, max_value=100, format="%.1f")},
    )

    finding_choices = team_findings["QID"].tolist()
    picked = st.multiselect(
        "Findings to include in the alert", finding_choices,
        default=team_findings.nlargest(min(3, len(team_findings)), "GRS")["QID"].tolist(),
        format_func=lambda q: f"QID {q} — {df[df.QID == q].iloc[0]['Title'][:60]}",
    )
    contact = TEAM_CONTACTS.get(team, "unassigned-oncall@ghrabfinancial.example")
    st.text_input("Route to", value=contact, disabled=True)
    note = st.text_area("Note to include (optional)", "")

    if st.button("Send alert to team", type="primary", disabled=not picked):
        log = st.session_state.setdefault("alert_log", [])
        log.append({"team": team, "contact": contact, "qids": picked, "note": note})
        st.toast(f"Alert routed to {team} ({contact}) for {len(picked)} finding(s).")
        st.success(
            f"Alert sent to **{team}** ({contact}) covering QIDs: "
            f"{', '.join(str(q) for q in picked)}."
        )

    log = st.session_state.get("alert_log", [])
    if log:
        divider()
        st.markdown("#### Alert Log (this session)")
        for entry in reversed(log[-10:]):
            st.markdown(
                f'- **{entry["team"]}** → {entry["contact"]} — '
                f'QIDs {", ".join(str(q) for q in entry["qids"])}'
                + (f' — _{entry["note"]}_' if entry["note"] else "")
            )
