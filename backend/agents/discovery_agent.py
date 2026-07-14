"""
Attack-Path Discovery Agent — the reasoning layer on top of the deterministic
discovery engine (core/attack_graph.py).

The graph engine *enumerates* candidate attack chains from capabilities; this
agent thinks like an analyst about them: it validates each candidate, assigns a
confidence, judges whether it is a textbook path or a non-obvious one, names the
single choke point that breaks it, writes an operator-grade narrative, and —
crucially — reasons beyond the enumerated set to surface toxic credential/identity
combinations the pathfinder alone would miss. It never fabricates hosts, CVEs,
or edges: the candidate chains are handed to it as ground-truth evidence.

Runs in two bounded passes so it works across every provider (no vendor-specific
tool-calling): (1) validate + narrate the candidate chains, (2) cross-path toxic
combinations + an executive synthesis. Degrades gracefully — if no provider is
connected, the deterministic chains still stand on their own.
"""
from __future__ import annotations

import pandas as pd

from agents.base import ask_json
from core.attack_graph import DiscoveredPath
from core.cmdb import CMDB


def _title_map(df: pd.DataFrame) -> dict[int, str]:
    return {int(r["QID"]): f"{r['Title']} [{r['Hostname']}]" for _, r in df.iterrows()}


def analyze(paths: list[DiscoveredPath], df: pd.DataFrame, cmdb: CMDB,
            session_state=None) -> dict:
    """Return {'paths': {path_id: enrichment}, 'toxic_combinations': [...],
    'summary': str}. Deterministic chains are preserved even if the LLM is off."""
    if not paths:
        return {"paths": {}, "toxic_combinations": [], "summary": ""}

    titles = _title_map(df)
    qid_ref = "\n".join(f"  QID {q}: {t}" for q, t in sorted(titles.items()))
    evidence = "\n".join(p.evidence_line() for p in paths)
    context = (
        f"{cmdb.summary_text(3500)}\n\n"
        f"FINDING REFERENCE (QID -> title [host]):\n{qid_ref}\n\n"
        f"CANDIDATE ATTACK CHAINS discovered by the graph engine (ground truth — "
        f"do not invent new hosts or QIDs; each hop is already justified by a "
        f"finding):\n{evidence}"
    )

    narrate_task = (
        "For EACH candidate chain above, produce an analyst assessment. Respond as "
        "JSON: {'paths': [ {'path_id', 'headline' (one sentence: entry -> ultimate "
        "impact), 'narrative' (3-5 sentences on HOW the attacker pivots hop to hop "
        "and WHY each hop works, in analyst voice), 'business_impact' (1-2 "
        "sentences), 'choke_point' (the single QID+host that, if fixed, breaks the "
        "chain), 'confidence' (one of 'high','medium','low' — how realistic the "
        "chain is), 'novelty' (one of 'textbook','notable','non-obvious' — how "
        "hard a human would be to spot it)} ]}. Include every path_id exactly once."
    )
    combos_task = (
        "Now reason BEYOND the enumerated chains. Identify up to 4 toxic "
        "combinations an operator scanning the list top-to-bottom would miss — "
        "especially shared-credential or shared-identity pivots that cross between "
        "the paths above (e.g. one credential reused across zones, a flat trust "
        "that merges two otherwise-separate chains). Only claim a combination you "
        "can justify from the CMDB/findings. Respond as JSON: {'toxic_combinations': "
        "[ {'title', 'mechanism' (2-3 sentences), 'involved_qids' (list of ints), "
        "'why_it_matters'} ], 'summary' (3-4 sentence executive synthesis of the "
        "overall attack-surface posture)}."
    )

    out: dict = {"paths": {}, "toxic_combinations": [], "summary": ""}
    try:
        narr = ask_json("attack_path", narrate_task, context,
                        session_state=session_state, max_tokens=2600,
                        detail=f"narrate {len(paths)} candidate chains")
        for item in narr.get("paths", []):
            pid = item.get("path_id")
            if pid:
                out["paths"][pid] = item
    except Exception as exc:  # noqa: BLE001 — deterministic chains still stand
        out["paths_error"] = str(exc)
    try:
        combos = ask_json("correlation", combos_task, context,
                          session_state=session_state, max_tokens=1600,
                          detail="cross-path toxic combinations")
        out["toxic_combinations"] = combos.get("toxic_combinations", [])
        out["summary"] = combos.get("summary", "")
    except Exception as exc:  # noqa: BLE001
        out["combos_error"] = str(exc)
    return out
