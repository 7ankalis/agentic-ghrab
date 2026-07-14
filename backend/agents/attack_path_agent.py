"""Attack Path Agent — turns a deterministic chain (from core.graph) into an
analyst-grade narrative: how an attacker actually moves, why each step works,
and the business consequence. The chain structure itself is never invented by
the LLM — it's handed the ground-truth step sequence and asked only to explain it."""
from __future__ import annotations

from agents.base import ask_json
from core.cmdb import CMDB
from core.graph import Chain


def narrate_chain(chain: Chain, cmdb: CMDB, session_state=None) -> dict:
    steps_text = "\n".join(
        f"Step {s.step_num} (QID {s.qid}): {s.title} — asset {s.hostname}, "
        f"GRS {s.grs}, owned by {s.team}"
        for s in chain.steps
    )
    context = (
        f"{cmdb.summary_text(4000)}\n\nATTACK CHAIN {chain.path_id} — ground-truth "
        f"steps (do not add or remove steps, only explain them):\n{steps_text}"
    )
    task = (
        "Produce a JSON object with keys: "
        "'headline' (one sentence naming entry point and ultimate impact), "
        "'narrative' (3-6 sentences, analyst voice, explaining HOW the attacker "
        "pivots step to step and WHY each step succeeds given the misconfiguration "
        "or CVE), "
        "'business_impact' (1-2 sentences on what the organization actually loses), "
        "'primary_choke_point' (the single step where, if fixed, the chain breaks — "
        "name the QID and hostname), "
        "'owning_teams' (list of distinct team names involved across the chain)."
    )
    try:
        return ask_json("attack_path", task, context, session_state=session_state)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
