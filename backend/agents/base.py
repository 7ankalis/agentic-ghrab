"""Shared analyst persona and helpers for all agents."""
from __future__ import annotations

from core.providers import call_llm, call_llm_json

ANALYST_PERSONA = (
    "You are a senior Vulnerability Management analyst at a VOC (Vulnerability "
    "Operations Center) serving Ghrab Financial Group, a financial services firm. "
    "You have deep expertise in offensive security, defensive analysis, network "
    "architecture, cloud security, and regulatory compliance (PCI DSS, SWIFT CSP, "
    "EU DORA). You reason ONLY from the context given to you — the CMDB, the "
    "finding data, and the documented attack-path graph. You NEVER invent CVEs, "
    "hosts, teams, or attack-path connections that are not present in the supplied "
    "context. If you are not confident about something, say so explicitly rather "
    "than guessing. You write like an analyst briefing an operator: precise, "
    "structured, no filler, no marketing language."
)


def ask(role: str, task_prompt: str, context: str, session_state=None,
        max_tokens: int = 1200, detail: str = "") -> str:
    system = ANALYST_PERSONA
    user = f"CONTEXT:\n{context}\n\nTASK:\n{task_prompt}"
    result = call_llm(role, system, user, session_state=session_state,
                      max_tokens=max_tokens, detail=detail)
    return result.text.strip()


def ask_json(role: str, task_prompt: str, context: str, session_state=None,
             max_tokens: int = 1500, detail: str = "") -> dict:
    system = ANALYST_PERSONA + (
        "\n\nYou must respond with ONLY a single valid JSON object — no prose, "
        "no markdown fences, no commentary before or after."
    )
    user = f"CONTEXT:\n{context}\n\nTASK:\n{task_prompt}"
    return call_llm_json(role, system, user, session_state=session_state,
                         max_tokens=max_tokens, detail=detail)
