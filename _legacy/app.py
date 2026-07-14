"""
Ghrab VOC — AI-Augmented Vulnerability Operations Center
VOC-admin dashboard: one-click ingest of Qualys export + enterprise CMDB,
deterministic Ghrab Risk Score (GRS) engine, and a multi-provider agentic AI
layer for attack-path narration, correlation, remediation, and compliance.
"""
from __future__ import annotations

import streamlit as st

st.set_page_config(
    page_title="Ghrab VOC — Vulnerability Operations Center",
    layout="wide",
    initial_sidebar_state="expanded",
)

from agents.orchestrator import run_pipeline  # noqa: E402
from core.providers import any_provider_configured  # noqa: E402
from ui import (  # noqa: E402
    ai_widget, tabs_ai_analyst, tabs_attack_paths, tabs_compliance,
    tabs_correlation, tabs_findings, tabs_overview, tabs_settings, tabs_teams,
)
from ui.styles import GLOBAL_CSS  # noqa: E402

st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def render_topbar():
    ai_on = any_provider_configured(st.session_state)
    badge_class = "on" if ai_on else "off"
    badge_text = "AI layer connected" if ai_on else "Deterministic mode"
    st.markdown(
        f'<div class="voc-topbar">'
        f'<div class="voc-brand">'
        f'<span class="mark">GHRAB</span>'
        f'<span class="division">Vulnerability Operations Center</span>'
        f'</div>'
        f'<div class="voc-topbar-right">'
        f'<span class="voc-mode-badge {badge_class}">'
        f'<span class="dot"></span>{badge_text}</span>'
        f'</div></div>',
        unsafe_allow_html=True,
    )


def render_sidebar():
    with st.sidebar:
        st.markdown("### Ingest & Analyze")
        st.caption(
            "Loads the vulnerability export and enterprise CMDB, computes GRS for "
            "every finding, builds the attack-path graph, and — where a provider "
            "is connected — runs the AI agent layer."
        )
        run_clicked = st.button("Run Full Analysis", type="primary", width="stretch")
        force_refresh = st.checkbox("Force AI re-analysis (ignore cache)", value=False)

        if run_clicked or "analysis" not in st.session_state:
            with st.status("Running analysis pipeline…", expanded=True) as status_box:
                def progress_cb(msg: str):
                    status_box.write(msg)

                st.session_state["analysis"] = run_pipeline(
                    session_state=st.session_state,
                    force_refresh=force_refresh or run_clicked,
                    progress_cb=progress_cb,
                )
                status_box.update(label="Analysis complete", state="complete", expanded=False)

        analysis = st.session_state.get("analysis")
        if analysis:
            st.success(f"{len(analysis.df)} findings loaded, {len(analysis.chains)} attack chains mapped.")
            if analysis.ai_enabled:
                st.caption("AI enrichment is cached — use 'Force AI re-analysis' to refresh.")
            else:
                st.caption("Running in deterministic-only mode. Connect a provider in Settings to enable AI agents.")

        st.markdown("---")
        st.caption(
            "GRS methodology: CVSS, EPSS, KEV status, asset criticality, and "
            "toxic-combination blast radius, gated by an exposure/reachability "
            "multiplier. See Settings for provider configuration."
        )
    return st.session_state.get("analysis")


def main():
    render_topbar()
    analysis = render_sidebar()

    if analysis is None:
        st.info("Use **Run Full Analysis** in the sidebar to ingest data and build the dashboard.")
        ai_widget.render(None)
        return

    tabs = st.tabs([
        "Overview", "Findings", "Attack Paths", "Correlation",
        "Teams", "Compliance", "AI Analyst", "Settings",
    ])
    with tabs[0]:
        tabs_overview.render(analysis)
    with tabs[1]:
        tabs_findings.render(analysis)
    with tabs[2]:
        tabs_attack_paths.render(analysis)
    with tabs[3]:
        tabs_correlation.render(analysis)
    with tabs[4]:
        tabs_teams.render(analysis)
    with tabs[5]:
        tabs_compliance.render(analysis)
    with tabs[6]:
        tabs_ai_analyst.render(analysis)
    with tabs[7]:
        tabs_settings.render()

    ai_widget.render(analysis)


if __name__ == "__main__":
    main()
