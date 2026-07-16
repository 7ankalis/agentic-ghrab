"""
Analyst Detection Agent — the "reason it out from scratch" layer.

Where the Discovery Agent validates/narrates the chains the reachability engine
already enumerated, this agent is handed NO candidate chains and NO documented
answer key. It gets only the raw grounding — asset inventory, ownership, zone
reachability rules, credential-reuse and dependency relationships — plus a table
of each finding classified by the capability it grants an attacker. From that it
independently reasons, like a human analyst would, which chains of relationships
carry an attacker from an internet-reachable entry point to a crown jewel.

Every hop the model proposes is then verified against the real asset/finding
set: a hop that cites a host or QID not in scope is dropped, and a path is only
marked `grounded` when all of its hops check out. This is what lets the platform
claim its *agents* detect attack paths, not just its rule engine — and it gives
the verification view a second, independent signal to compare against the
held-out documented paths.
"""
from __future__ import annotations

import re

import pandas as pd

from agents.base import ask_json
from core.capability import Capability
from core.cmdb import CMDB


def _resolve_host(name: str, known: set[str]) -> str | None:
    """Best-effort map an LLM-written host reference to a real asset name."""
    n = str(name).strip().strip("`")
    if n in known:
        return n
    up = n.upper()
    for h in known:
        if h and (h.upper() == up or up.startswith(h.upper()) or h.upper() in up):
            return h
    return None


def _capability_table(df: pd.DataFrame, caps: dict[int, Capability]) -> str:
    lines = []
    for qid in sorted(int(q) for q in df["QID"]):
        c = caps.get(qid)
        if not c:
            continue
        line = (f"QID {qid} on {c.hostname} [{c.vlan}]: {c.technique} "
                f"| gains={', '.join(c.effects) or 'n/a'} | entry={c.is_entry}")
        if c.grants:
            line += f" | grants={', '.join(c.grants)}"
        if c.host_pivots:
            line += f" | reaches={', '.join(c.host_pivots)}"
        lines.append(line)
    return "\n".join(lines)


def detect_attack_paths(df: pd.DataFrame, cmdb: CMDB, caps: dict[int, Capability],
                        nodes: dict, session_state=None) -> dict:
    """Independently detect attack paths from grounding alone, then verify each
    hop against real hosts/QIDs. Returns {'detected_paths': [...]}; degrades to
    an empty list (with an 'error') if no provider is connected."""
    known_hosts = set(nodes)
    known_qids = {int(q) for q in df["QID"]}
    crown = sorted(h for h, n in nodes.items() if getattr(n, "is_crown_jewel", False))
    entries = sorted(h for h, n in nodes.items() if getattr(n, "is_entry", False))

    context = (
        f"{cmdb.grounding_context(7000)}\n\n"
        f"FINDINGS BY CAPABILITY (what an attacker gains from each finding — derived "
        f"from the finding itself, not from any attack path):\n{_capability_table(df, caps)}\n\n"
        f"Internet-reachable entry assets (an attacker can start here): {entries or 'none identified'}\n"
        f"Crown-jewel targets (what the attacker is ultimately after): {crown or 'none identified'}"
    )
    task = (
        "You are given the environment's real infrastructure and, separately, what "
        "each finding lets an attacker do. NO attack paths have been given to you — "
        "reason them out yourself, the way an analyst would.\n\n"
        "Trace the most significant end-to-end attack paths: from an internet-reachable "
        "entry asset, through the network reachability rules / credential-reuse / "
        "dependency relationships, to a crown-jewel target. For EACH path, give the "
        "ordered hops. For every hop cite (a) the QID of the finding that enables it "
        "and (b) the specific enabler from the CMDB — a Rule ID (esp. one marked "
        "Excessive), a credential relationship (CRED-*), or a dependency (REL-*). Do "
        "not assert a hop you cannot justify from the grounding; a hop with no enabler "
        "is not a real hop.\n\n"
        "Respond as compact JSON: {'detected_paths': [ {'name', 'entry', 'target', "
        "'hops': [ {'from', 'to', 'via_qid' (int), 'enabler' (the Rule/CRED/REL id), "
        "'why' (<= 12 words)} ], 'business_impact' (<= 20 words), 'confidence' (one of "
        "'high','medium','low')} ]}. Return the 4-6 most consequential paths only, each "
        "at most 6 hops; prefer distinct crown-jewel targets over near-duplicates. Keep "
        "text terse so the JSON is complete and valid."
    )

    try:
        raw = ask_json("attack_path", task, context, session_state=session_state,
                       max_tokens=4000, detail="independent analyst path detection")
    except Exception as exc:  # noqa: BLE001 — engine paths still stand
        return {"detected_paths": [], "error": str(exc)}

    detected = []
    for p in raw.get("detected_paths", []):
        entry = _resolve_host(p.get("entry", ""), known_hosts)
        target = _resolve_host(p.get("target", ""), known_hosts)
        hops, verified = [], 0
        for h in p.get("hops", []):
            src = _resolve_host(h.get("from", ""), known_hosts)
            dst = _resolve_host(h.get("to", ""), known_hosts)
            try:
                via = int(h.get("via_qid"))
            except (TypeError, ValueError):
                via = None
            hop_ok = bool(dst) and (via in known_qids or via is None)
            if via is not None and via not in known_qids:
                via = None  # fabricated QID — strip it rather than present it as real
            hops.append({
                "from": src or h.get("from", ""), "to": dst or h.get("to", ""),
                "via_qid": via, "enabler": str(h.get("enabler", "")),
                "why": str(h.get("why", "")), "verified": hop_ok,
            })
            verified += hop_ok
        if not hops or target is None:
            # no anchorable hop or the target isn't a real asset → ungrounded, drop it
            continue
        detected.append({
            "name": str(p.get("name", "")), "entry": entry or p.get("entry", ""),
            "target": target, "hops": hops,
            "business_impact": str(p.get("business_impact", "")),
            "confidence": str(p.get("confidence", "")),
            "grounded": verified == len(hops),
            "verified_hops": verified, "total_hops": len(hops),
        })
    return {"detected_paths": detected}
