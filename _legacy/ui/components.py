"""Reusable UI building blocks."""
from __future__ import annotations

import streamlit as st

from ui.styles import status_pill_html


def kpi_card(label: str, value: str, sub: str = ""):
 st.markdown(
 f'<div class="kpi-card"><div class="kpi-label">{label}</div>'
 f'<div class="kpi-value">{value}</div>'
 + (f'<div class="kpi-sub">{sub}</div>' if sub else "")
 + "</div>",
 unsafe_allow_html=True,
 )


def ai_box(label: str, content: str):
 st.markdown(
 f'<div class="ai-box"><div class="ai-label">{label}</div>{content}</div>',
 unsafe_allow_html=True,
 )


def status_pill(band: str) -> str:
 return status_pill_html(band)


def divider():
 st.markdown('<hr class="voc-divider">', unsafe_allow_html=True)


def ai_disabled_notice(agent_label: str = "This AI agent"):
 st.info(
 f"{agent_label} needs at least one LLM provider connected. "
 f"Add a key in **Settings** — the rest of the platform (GRS scoring, "
 f"attack-path graph, findings table) already runs fully from the "
 f"deterministic engine, no provider required."
 )
