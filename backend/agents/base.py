"""Shared analyst persona and helpers for all agents."""
from __future__ import annotations

from core.config import active_org, agent_temperature
from core.providers import call_llm, call_llm_json


def analyst_persona() -> str:
    """Built per call so the persona always frames the currently active
    enterprise (its sector + compliance frameworks), not a fixed org."""
    org = active_org()
    return (
        "You are a senior Vulnerability Management analyst at a VOC (Vulnerability "
        f"Operations Center) serving {org['name']}, {org['sector']}. "
        "You have deep expertise in offensive security, defensive analysis, network "
        f"architecture, cloud security, and regulatory compliance ({org['frameworks']}). "
        "You reason ONLY from the context given to you — the CMDB grounding (asset "
        "inventory, ownership, zone reachability rules, credential-reuse and dependency "
        "relationships) and the finding data. Attack paths are NOT handed to you: you "
        "derive them by chaining those relationships, and every hop you assert must "
        "trace to a specific relationship and finding in the context. You NEVER invent "
        "CVEs, hosts, teams, or connections that are not present in the supplied "
        "context. If you are not confident about something, say so explicitly rather "
        "than guessing. You write like an analyst briefing an operator: precise, "
        "structured, no filler, no marketing language."
    )


def ask(role: str, task_prompt: str, context: str, session_state=None,
        max_tokens: int = 1200, detail: str = "") -> str:
    system = analyst_persona()
    user = f"CONTEXT:\n{context}\n\nTASK:\n{task_prompt}"
    result = call_llm(role, system, user, session_state=session_state,
                      max_tokens=max_tokens, detail=detail,
                      temperature=agent_temperature(role))
    return result.text.strip()


def ask_json(role: str, task_prompt: str, context: str, session_state=None,
             max_tokens: int = 1500, detail: str = "") -> dict:
    system = analyst_persona() + (
        "\n\nYou must respond with ONLY a single valid JSON object — no prose, "
        "no markdown fences, no commentary before or after."
    )
    user = f"CONTEXT:\n{context}\n\nTASK:\n{task_prompt}"
    return call_llm_json(role, system, user, session_state=session_state,
                         max_tokens=max_tokens, detail=detail,
                         temperature=agent_temperature(role))
