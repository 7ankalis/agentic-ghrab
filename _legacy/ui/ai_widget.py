"""
Global floating AI Analyst — a persistent, one-click entry point to the
agentic layer from anywhere in the product, rather than a chat buried inside
a tab. Renders as a pill trigger fixed to the bottom-right corner; clicking
it opens a popover panel with the live conversation. Shares session state
with the full AI Analyst tab, so a conversation started from the widget
carries over there and vice versa.
"""
from __future__ import annotations

import streamlit as st

from agents.orchestrator import AnalysisResult
from agents.triage_agent import answer_question
from core.providers import any_provider_configured


def render(result: AnalysisResult | None):
    with st.container(key="ai_fab"):
        ai_on = result is not None and any_provider_configured(st.session_state)
        label = "Ask the AI Analyst" if ai_on else "AI Analyst — offline"
        with st.popover(label, width="content"):
            st.markdown(
                "<div style='font-family:var(--font-serif);font-weight:700;"
                "font-size:1.05rem;color:var(--forest);margin-bottom:0.1rem;'>"
                "AI Analyst</div>"
                "<div style='font-size:0.8rem;color:var(--ink-muted);"
                "margin-bottom:0.8rem;'>Grounded in the live findings table and "
                "enterprise CMDB — ask about ownership, attack paths, or "
                "compliance scope from any screen.</div>",
                unsafe_allow_html=True,
            )

            if result is None:
                st.caption("Run the analysis from the sidebar first.")
                return
            if not ai_on:
                st.caption(
                    "No LLM provider is connected. Add a key in Settings to "
                    "enable this agent."
                )
                return

            history = st.session_state.setdefault("chat_history", [])
            chat_box = st.container(height=280)
            with chat_box:
                for msg in history[-8:]:
                    with st.chat_message(msg["role"]):
                        st.markdown(msg["content"])

            question = st.chat_input("Ask a question…", key="ai_fab_input")
            if question:
                history.append({"role": "user", "content": question})
                with st.spinner("Analyzing…"):
                    answer = answer_question(
                        question, result.df, result.cmdb, history, st.session_state
                    )
                history.append({"role": "assistant", "content": answer})
                st.rerun()
