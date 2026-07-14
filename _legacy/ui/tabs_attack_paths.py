from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from agents.orchestrator import AnalysisResult
from ui.components import ai_box, ai_disabled_notice, divider, status_pill
from ui.styles import CATEGORICAL, CHART_FONT_COLOR, EDGE_COLOR, NODE_FALLBACK_COLOR, STATUS


def _band_for_grs(grs: float) -> str:
    if grs >= 80: return "IMMEDIATE"
    if grs >= 60: return "ACT"
    if grs >= 40: return "ATTEND"
    if grs >= 20: return "TRACK*"
    return "TRACK"


def render(result: AnalysisResult):
    st.markdown("### Detected Attack Paths")
    st.caption(
        "Reconstructed deterministically from the Attack_Path_Ref chain data — every "
        "step below is a confirmed finding in the ground-truth CSV, not an LLM inference. "
        "The AI narrative explains why the chain works and where to break it."
    )

    chains = result.chains
    if not chains:
        st.info("No multi-step attack chains detected in the current dataset.")
        return

    max_grs_all = max((c.max_grs for c in chains), default=1)

    for chain in chains:
        band = _band_for_grs(chain.max_grs)
        color = STATUS[band]["color"]
        narrative = result.chain_narratives.get(chain.path_id, {})
        headline = narrative.get("headline", "")

        with st.expander(
            f"{chain.path_id} — {chain.entry_point} → {chain.target}  "
            f"(peak GRS {chain.max_grs:.1f})",
            expanded=(chain.max_grs == max_grs_all),
        ):
            c1, c2 = st.columns([1, 1.4])

            with c1:
                st.markdown("**Chain steps (ground truth)**")
                for i, s in enumerate(chain.steps):
                    st.markdown(
                        f'<div class="chain-step">'
                        f'<div class="step-title">Step {s.step_num}: {s.title[:70]}</div>'
                        f'<div class="step-meta">{status_pill(_band_for_grs(s.grs))} '
                        f'GRS {s.grs} &nbsp;·&nbsp; QID {s.qid} &nbsp;·&nbsp; '
                        f'{s.hostname} &nbsp;·&nbsp; Owner: {s.team}</div>'
                        f'</div>', unsafe_allow_html=True,
                    )
                    if i < len(chain.steps) - 1:
                        st.markdown(
                            '<div style="text-align:center;color:var(--ink-faint);'
                            'font-size:0.85rem;">pivot</div>',
                            unsafe_allow_html=True,
                        )

            with c2:
                if "error" in narrative or not narrative:
                    ai_disabled_notice("The Attack Path narrative")
                else:
                    if headline:
                        st.markdown(f"**{headline}**")
                    ai_box("Analyst Narrative", narrative.get("narrative", ""))
                    st.markdown(
                        f"**Business impact:** {narrative.get('business_impact', 'N/A')}"
                    )
                    st.markdown(
                        f"**Primary choke point (fix this to break the chain):** "
                        f"{narrative.get('primary_choke_point', 'N/A')}"
                    )
                    teams = narrative.get("owning_teams", [])
                    if teams:
                        st.markdown(f"**Teams involved:** {', '.join(teams)}")

    divider()
    st.markdown("#### Attack Surface Map")
    st.caption("Node size represents peak GRS reachable through that asset. Edges are confirmed pivot steps.")
    _render_graph(result)


def _render_graph(result: AnalysisResult):
    g = result.graph
    if g.number_of_nodes() == 0:
        st.info("No graph data available.")
        return
    import networkx as nx

    pos = nx.spring_layout(g, seed=42, k=1.1)
    edge_x, edge_y = [], []
    for u, v in g.edges():
        x0, y0 = pos[u]; x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1.4, color=EDGE_COLOR),
                             hoverinfo="none", mode="lines")

    node_x, node_y, node_text, node_size, node_color = [], [], [], [], []
    teams = sorted({d.get("team", "") for _, d in g.nodes(data=True)})
    team_color = {t: CATEGORICAL[i % len(CATEGORICAL)] for i, t in enumerate(teams)}
    for n, d in g.nodes(data=True):
        x, y = pos[n]
        node_x.append(x); node_y.append(y)
        grs = d.get("max_grs", 0)
        node_text.append(f"{n}<br>Zone: {d.get('zone','')}<br>Team: {d.get('team','')}<br>Peak GRS: {grs:.1f}")
        node_size.append(14 + grs / 4)
        node_color.append(team_color.get(d.get("team", ""), NODE_FALLBACK_COLOR))

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        text=[n for n in g.nodes()], textposition="top center",
        textfont=dict(size=9, color=CHART_FONT_COLOR, family="Lato"),
        hovertext=node_text, hoverinfo="text",
        marker=dict(size=node_size, color=node_color, line=dict(width=1.5, color="white")),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        showlegend=False, height=520, margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
