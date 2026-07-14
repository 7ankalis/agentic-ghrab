from __future__ import annotations

import streamlit as st

from core.config import (
    AGENT_ROLE_LABELS,
    AGENT_ROLES,
    DEFAULT_AGENT_PROVIDER,
    PROVIDERS,
    get_api_key,
)


def render():
    st.markdown("### Settings — Providers & Agent Assignment")
    st.caption(
        "This platform is intentionally provider-agnostic. Add keys for whichever "
        "LLM vendors you have, and assign each AI agent role to a different provider "
        "so a full analysis run spreads cost and load instead of hammering one vendor. "
        "Keys live only in this browser session — nothing is written to disk. You can "
        "also set them as environment variables (see the reference below) to skip this step."
    )

    st.markdown("#### 1. API Keys")
    cols = st.columns(2)
    for i, (key, spec) in enumerate(PROVIDERS.items()):
        with cols[i % 2]:
            current = get_api_key(key, st.session_state)
            status = "Connected" if current else "Not connected"
            st.text_input(
                f"{spec.label} — {status}",
                type="password",
                key=f"apikey_{key}",
                placeholder=f"env: {spec.env_var}",
                help=spec.docs_hint,
            )

    st.markdown("---")
    st.markdown("#### 2. Agent → Provider Assignment")
    st.caption(
        "Defaults are deliberately spread across vendors. Override any role below; "
        "if the chosen provider has no key, the platform automatically falls back "
        "through the other configured providers."
    )

    for role in AGENT_ROLES:
        available = [p for p in PROVIDERS if get_api_key(p, st.session_state)] or list(PROVIDERS)
        default_provider = DEFAULT_AGENT_PROVIDER.get(role, available[0])
        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown(f"**{AGENT_ROLE_LABELS[role]}**")
        with c2:
            options = list(PROVIDERS.keys())
            idx = options.index(default_provider) if default_provider in options else 0
            st.selectbox(
                "Preferred provider", options, index=idx,
                format_func=lambda k: PROVIDERS[k].label,
                key=f"agent_provider_{role}", label_visibility="collapsed",
            )

    st.markdown("---")
    st.markdown("#### 3. Environment Variable Reference")
    st.caption("Set these instead of pasting keys above if you'd rather configure once at deploy time.")
    rows = "\n".join(
        f"| {spec.label} | `{spec.env_var}` | `{spec.default_model}` |"
        for spec in PROVIDERS.values()
    )
    st.markdown(
        "| Provider | Env var | Default model |\n|---|---|---|\n" + rows
    )

    st.markdown("---")
    if st.button("Force-refresh AI analysis on next run (clears cache)"):
        from core.config import ANALYSIS_CACHE_PATH
        if ANALYSIS_CACHE_PATH.exists():
            ANALYSIS_CACHE_PATH.unlink()
        st.session_state["_force_refresh"] = True
        st.success("Cache cleared. Re-run the analysis from the sidebar.")
