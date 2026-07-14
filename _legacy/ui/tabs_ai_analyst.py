from __future__ import annotations

import streamlit as st

from agents.orchestrator import AnalysisResult
from agents.triage_agent import answer_question
from core.providers import any_provider_configured
from ui.components import ai_disabled_notice, divider


SUGGESTED_QUESTIONS = [
    "Is there a path from Guest WiFi to Domain Admin?",
    "Which team should fix the S3 bucket exposure, and why?",
    "What CVEs affect the Finance/Trading Critical Zone and who owns remediation?",
    "What's the fastest path to Domain Admin?",
    "Which findings are DORA CIF-scope and what's their SLA?",
]


def render(result: AnalysisResult):
    st.markdown("### AI Analyst — Ask the VOC")
    st.caption(
        "Grounded in the full findings table and CMDB. Answers cite QIDs, hostnames, and "
        "GRS scores directly from the ingested data — it will say when something isn't "
        "in scope rather than inventing an answer. The same conversation is also "
        "reachable from the floating panel on every screen."
    )

    if not any_provider_configured(st.session_state):
        ai_disabled_notice("The AI Analyst chat")
        return

    st.markdown("**Try asking:**")
    cols = st.columns(len(SUGGESTED_QUESTIONS))
    for i, q in enumerate(SUGGESTED_QUESTIONS):
        with cols[i]:
            if st.button(q, key=f"suggest_{i}", width="stretch"):
                st.session_state["_pending_question"] = q

    divider()

    history = st.session_state.setdefault("chat_history", [])
    for msg in history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    pending = st.session_state.pop("_pending_question", None)
    user_input = st.chat_input("Ask about vulnerabilities, attack paths, ownership, compliance…")
    question = pending or user_input

    if question:
        with st.chat_message("user"):
            st.markdown(question)
        history.append({"role": "user", "content": question})

        with st.chat_message("assistant"):
            with st.spinner("Triage Agent is reasoning over the findings and CMDB…"):
                answer = answer_question(question, result.df, result.cmdb, history, st.session_state)
            st.markdown(answer)
        history.append({"role": "assistant", "content": answer})
