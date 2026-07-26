"""
Provider-agnostic bounded ReAct loop — the reusable engine behind tool-using agents.

An agent hands this a system prompt (its persona), a task, and a set of `Tool`s
backed by real data (the graph, the CMDB, the findings). The loop then drives a
step-by-step investigation: the model emits one JSON object per turn — either a
tool call `{"action", "args"}` or a `{"final": ...}` answer — and the loop executes
the tool locally (token-free), feeds back the observation, and repeats until the
model finalizes or a hard cap trips.

Why a JSON-action protocol rather than native tool-calling: it works over plain
completions on *any* provider, so the engine never hard-depends on one vendor's
tool-use API (invariant #4). Native tool-calling can later be slotted behind the
same `Tool` registry without touching callers.

Cost is bounded absolutely: a hard iteration cap (each iteration is one LLM
round-trip; tools are free), an estimated-token budget, and a per-call token cap.
Cancellation is cooperative — `should_cancel` is polled every turn. LLM calls go
through `agents.base` (by module attribute) so the no-oracle-leakage guard, which
patches that chokepoint, covers this engine too.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from agents import base
from core.providers import ProviderUnavailable

logger = logging.getLogger(__name__)

# Observations fed back into the transcript are truncated to this many characters
# so a large tool result (a long finding, many candidate paths) can't blow the
# prompt budget. The full, untruncated observation is still kept in the trace.
_OBS_TRUNCATE = 1600
# Consecutive unparseable replies tolerated before giving up (a model that can't
# emit valid JSON twice in a row won't on the third try — stop burning calls).
_MAX_PARSE_FAILURES = 2


@dataclass
class Tool:
    """One read-only capability the agent can call. `func(**args)` must return a
    JSON-serialisable observation (dict/list/str/number) and never raise on bad
    input — but the loop guards against raises anyway."""
    name: str
    signature: str          # arg names for the prompt catalog, e.g. "from_host, to_host"
    description: str         # one line shown to the model
    func: Callable[..., Any]


@dataclass
class LoopResult:
    final: Any = None                     # the model's parsed `final` payload, or None
    trace: list[dict] = field(default_factory=list)  # per-turn action/args/observation
    iterations: int = 0
    tokens: int = 0                       # ESTIMATED (len/4); real accounting is Phase 5
    stopped_reason: str = ""              # final | max_iters | token_budget | cancelled
    #                                       | no_provider | parse_error | error


def _est_tokens(s: str) -> int:
    """Cheap token estimate (~4 chars/token) for budgeting only. Real per-call
    token counts live in core.call_log; surfacing them here is a Phase 5 task."""
    return max(1, len(s) // 4)


def _loads(text: str) -> Any:
    """Parse a JSON object out of a completion, tolerating ``` fences / stray prose."""
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        s, e = t.find("{"), t.rfind("}")
        if s != -1 and e != -1:
            return json.loads(t[s:e + 1])
        raise


def _truncate(s: str, limit: int = _OBS_TRUNCATE) -> str:
    return s if len(s) <= limit else s[:limit] + " …[truncated]"


def _protocol_prompt(tools: dict[str, Tool]) -> str:
    catalog = "\n".join(
        f"  - {t.name}({t.signature}): {t.description}" for t in tools.values()
    )
    return (
        "\n\nYou investigate step by step using tools, like an analyst at a console. "
        "Respond with EXACTLY ONE JSON object per turn and nothing else — no prose, "
        "no markdown fences. Use one of two shapes:\n"
        '  call a tool:  {"thought": "<brief>", "action": "<tool_name>", "args": {<arg>: <value>}}\n'
        '  finish:       {"thought": "<brief>", "final": {<your answer>}}\n'
        "Available tools:\n" + catalog + "\n"
        "Rules: use ONLY these tools and their listed argument names. Every fact you "
        "cite in your final answer must come from a tool observation or the task "
        "context — never invent a host or QID. Prefer to finish in as few turns as "
        "possible; your turns are limited, so investigate only what you still need, "
        "then return your answer under \"final\"."
    )


def run_react_loop(
    role: str,
    system_prompt: str,
    task_prompt: str,
    tools: dict[str, Tool],
    session_state=None,
    max_iters: int = 6,
    token_budget: int = 24000,
    max_tokens: int = 2000,
    temperature: float = 0.0,
    should_cancel: Callable[[], bool] | None = None,
    detail: str = "react loop",
) -> LoopResult:
    """Drive a bounded tool-using investigation. Returns a LoopResult carrying the
    model's `final` payload (or None if it never finalized), the full reasoning
    trace, and why the loop stopped. Never raises for provider/parse problems —
    those become a clean `stopped_reason` so the caller can degrade gracefully."""
    system = system_prompt + _protocol_prompt(tools)
    transcript = [f"TASK:\n{task_prompt}"]
    result = LoopResult()
    parse_failures = 0

    for i in range(1, max_iters + 1):
        if should_cancel and should_cancel():
            result.stopped_reason = "cancelled"
            break

        # On the final allowed turn, force a finalize so a careful, still-exploring
        # model always yields an answer instead of running out of turns with none.
        if i == max_iters:
            suffix = ("\n\nThis is your LAST turn — do NOT call another tool. Return "
                      "your final answer now as a single JSON object: {\"final\": {...}}.")
        else:
            suffix = "\n\nRespond now with your next JSON action, or your final answer."
        user = "\n\n".join(transcript) + suffix
        est_in = _est_tokens(system) + _est_tokens(user)
        if result.tokens + est_in > token_budget:
            result.stopped_reason = "token_budget"
            break

        try:
            res = base.call_llm(role, system, user, session_state=session_state,
                                json_mode=True, max_tokens=max_tokens,
                                temperature=temperature, detail=f"{detail} step {i}")
        except ProviderUnavailable:
            result.stopped_reason = "no_provider"
            break
        except Exception as exc:  # noqa: BLE001 — engine paths still stand
            logger.warning("detection loop call failed at step %d: %s", i, exc)
            result.stopped_reason = "error"
            result.trace.append({"iteration": i, "error": str(exc)[:400]})
            break

        result.iterations = i
        text = getattr(res, "text", "") or ""
        result.tokens += est_in + _est_tokens(text)

        try:
            obj = _loads(text)
        except (json.JSONDecodeError, ValueError):
            parse_failures += 1
            result.trace.append({"iteration": i, "parse_error": _truncate(text, 400)})
            if parse_failures >= _MAX_PARSE_FAILURES:
                result.stopped_reason = "parse_error"
                break
            transcript.append("OBSERVATION: your last reply was not a single valid "
                              "JSON object. Reply with exactly one JSON object.")
            continue
        parse_failures = 0

        if isinstance(obj, dict) and "final" in obj:
            result.final = obj["final"]
            result.trace.append({"iteration": i, "thought": str(obj.get("thought", ""))[:200],
                                 "final": True})
            result.stopped_reason = "final"
            break

        action = obj.get("action") if isinstance(obj, dict) else None
        args = obj.get("args") if isinstance(obj, dict) else None
        if not isinstance(args, dict):
            args = {}
        tool = tools.get(action) if action else None

        if tool is None:
            obs: Any = {"error": f"unknown action {action!r}; valid actions: {list(tools)}"}
        else:
            try:
                obs = tool.func(**args)
            except TypeError as exc:
                obs = {"error": f"bad args for {action}: {exc}"}
            except Exception as exc:  # noqa: BLE001 — a tool never crashes the loop
                obs = {"error": f"{action} failed: {exc}"}

        result.trace.append({"iteration": i, "thought": str(obj.get("thought", ""))[:200],
                             "action": action, "args": args, "observation": obs})
        transcript.append(
            f"ACTION: {action} {json.dumps(args, ensure_ascii=False)}\n"
            f"OBSERVATION: {_truncate(json.dumps(obs, ensure_ascii=False, default=str))}"
        )
    else:
        result.stopped_reason = "max_iters"

    return result
