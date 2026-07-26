"""
Analyst Detection Agent — the "reason it out from scratch" layer.

Where the Discovery Agent validates/narrates the chains the reachability engine
already enumerated, this agent is handed NO candidate chains and NO documented
answer key. It gets only the raw grounding — asset inventory, ownership, zone
reachability rules, credential-reuse and dependency relationships — plus tools to
inspect each finding's capability. From that it independently reasons, like a
human analyst would, which chains of relationships carry an attacker from an
internet-reachable entry point to a crown jewel.

Phase 3 makes this a *tool-using* investigation rather than a single completion:
the agent runs a bounded ReAct loop (agents/agent_loop.py) over real graph+CMDB
tools (agents/detection_tools.py), hypothesising a path and verifying each hop
with `test_hop` before asserting it. Every emitted hop is then re-checked against
the real reachability graph in the finalizer (Phase 4), which labels each path
`grounded` (every hop a real enabling edge forming a connected INTERNET→target
walk — soundness 1.0 by construction), `plausible` (hosts + cited QIDs resolve but
>=1 hop the graph can't confirm, surfaced with the gap flagged) or `rejected` (no
anchorable real host — never emitted). Hallucination stays 0 in every tier, and
paths are ranked by a calibrated, component-exposed score (core/config.py weights).

Setting DETECTION_AGENT_ENABLED=0 falls back to the pre-Phase-3 single-shot
reasoning below. No provider ⇒ either path returns empty (with an `error`) and the
deterministic engine's paths still stand.
"""
from __future__ import annotations

import logging

import networkx as nx
import pandas as pd

from agents.agent_loop import run_react_loop
from agents.base import analyst_persona, ask_json
from agents.detection_tools import build_detection_tools, real_edge, resolve_host
from core import call_log
from core.attack_graph import INTERNET, HostNode
from core.capability import Capability
from core.cmdb import CMDB
from core.config import (
    DETECTION_AGENT_ENABLED, DETECTION_AGENT_MAX_ITERS, DETECTION_AGENT_MAX_TOKENS,
    DETECTION_AGENT_TEMPERATURE, DETECTION_AGENT_TOKEN_BUDGET,
    DETECTION_MAX_EMITTED_PATHS, PATH_CHAIN_IDEAL_HOPS, PATH_GRS_CEILING,
    PATH_PLAUSIBLE_DAMPING, PATH_SCORE_WEIGHTS,
)

logger = logging.getLogger(__name__)

# Cap on how many finalized paths we emit (distinct routes); keeps the output
# terse and the schema payload bounded regardless of how chatty the model is.
# Config-driven (DETECTION_MAX_EMITTED_PATHS); aliased here for terse local use.
_MAX_EMITTED_PATHS = DETECTION_MAX_EMITTED_PATHS


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


# ---------------------------------------------------------------------------
# Tool-using detection (Phase 3)
# ---------------------------------------------------------------------------

_DETECTION_TASK = (
    "No attack paths have been given to you. Trace the most significant end-to-end "
    "attack paths: from an INTERNET-reachable entry asset, through the reachability / "
    "credential-reuse / dependency edges, to a crown-jewel target.\n\n"
    "The candidate routes listed below are ALREADY graph-verified real paths — you may "
    "return them directly, no need to re-check their hops. Spend your tool calls "
    "instead on finding at least one BETTER or NON-OBVIOUS route the pathfinder buries "
    "— credential reuse across zones, hypervisor blast radius, cloud identity "
    "escalation, or an alternate pivot to a target. Use credentials_valid_on and "
    "relationships_of to surface non-network pivots (shared/cached credentials, "
    "Depends-on / Backs-up / DB-link relationships) the shortest-path route skips over, "
    "reachability_rule to confirm an Excessive crossing (and never traverse a "
    "Should-Not-Exist one), and neighbors/shortest_paths + test_hop to confirm any NEW "
    "hop. Then finalize promptly; never assert a hop test_hop does not confirm.\n\n"
    "Finish by returning `final` as: {\"detected_paths\": [ {\"name\", \"entry\", "
    "\"target\", \"hops\": [ {\"from\", \"to\", \"via_qid\" (int), \"enabler\" (the "
    "Rule/CRED/REL id or QID), \"why\" (<= 12 words)} ], \"business_impact\" (<= 20 "
    "words), \"confidence\" (\"high\"|\"medium\"|\"low\")} ] }. Include the entry hop "
    "(from INTERNET) so each path's hops form ONE connected chain. Return the 4-6 most "
    "consequential paths, distinct crown-jewel targets preferred, each at most 6 hops."
)


def _final_paths(final) -> list[dict]:
    """Pull the path list out of the model's `final` payload, tolerating a bare
    list, {detected_paths:[...]}, or {paths:[...]}."""
    if isinstance(final, list):
        return [p for p in final if isinstance(p, dict)]
    if isinstance(final, dict):
        for k in ("detected_paths", "paths", "attack_paths"):
            if isinstance(final.get(k), list):
                return [p for p in final[k] if isinstance(p, dict)]
    return []


def _visited_order(hops: list[dict], host_set: set[str]) -> list[str]:
    """Reduce the model's (from,to) hops to the ordered list of real hosts visited,
    dropping INTERNET and any reference that doesn't resolve to a real asset."""
    order: list[str] = []
    for h in hops:
        a = resolve_host(h.get("from", ""), host_set)
        b = resolve_host(h.get("to", ""), host_set)
        for host in (a, b):
            if host and host != INTERNET and host not in order:
                order.append(host)
    return order


def _endpoint_qids(x: str, y: str, nodes: dict[str, HostNode]) -> set[int]:
    """QIDs that are real findings on either endpoint of a hop — the only QIDs a
    QID-less lateral/adjacency edge may legitimately cite as its enabler."""
    out: set[int] = set()
    for h in (x, y):
        n = nodes.get(h)
        if n is not None:
            out.update(int(q) for q in n.qids)
    return out


def _exploit_signal(row: pd.Series | None) -> float:
    """Strongest in-dataset exploitability signal for one finding, in [0,1].
    KEV > EPSS > CVSS when present; otherwise fall back to GRS/ACW (Phase-4 open
    decision: NO external feeds). Absent/blank columns degrade gracefully to 0."""
    if row is None:
        return 0.0

    def num(col: str) -> float:
        try:
            return float(row.get(col, 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    if bool(row.get("KEV", False)):
        return 1.0
    epss = num("EPSS")
    if epss > 0:
        return min(1.0, epss)
    cvss = num("CVSS_Base")
    if cvss > 0:
        return min(1.0, cvss / 10.0)
    grs = num("GRS") / PATH_GRS_CEILING if PATH_GRS_CEILING else 0.0
    return min(1.0, max(grs, num("ACW")))


def _score_path(label: str, verified_ratio: float, total_hops: int,
                cited_qids: set[int], target_node: HostNode | None,
                df_by_qid: dict[int, pd.Series]) -> tuple[float, dict]:
    """Calibrated path score from four inspectable [0,1] components (weights in
    core/config.py). Returns (scalar, components-dict). A `plausible` path is damped
    so it can never outrank an equal-component `grounded` path; `rejected` scores 0."""
    exploit = max((_exploit_signal(df_by_qid.get(q)) for q in cited_qids), default=0.0)
    ideal = max(1, PATH_CHAIN_IDEAL_HOPS)
    comps = {
        "reachability": round(verified_ratio, 4),
        "exploitability": round(exploit, 4),
        "business_value": round(min(1.0, target_node.target_value if target_node else 0.0), 4),
        "chain_length": round(ideal / max(total_hops, ideal), 4) if total_hops else 0.0,
    }
    raw = sum(PATH_SCORE_WEIGHTS.get(k, 0.0) * v for k, v in comps.items())
    damping = PATH_PLAUSIBLE_DAMPING if label == "plausible" else 1.0
    score = 0.0 if label == "rejected" else round(raw * damping, 4)
    return score, {**comps, "weights": dict(PATH_SCORE_WEIGHTS),
                   "label": label, "plausible_damping": damping, "raw": round(raw, 4)}


def _build_path(p: dict, g: nx.DiGraph, host_set: set[str], known_qids: set[int],
                nodes: dict[str, HostNode], df_by_qid: dict[int, pd.Series]) -> dict | None:
    """Reconstruct one model path as an INTERNET→…→target walk and label it
    `grounded` | `plausible`, or return None (`rejected`) when no real host anchors
    it. A hop is `verified` only if a real enabling edge exists AND its enabler is
    authoritative (the edge's own QID, or — for a QID-less lateral edge — a cited
    QID that is a real finding on an endpoint; a foreign QID is stripped). The path
    is `grounded` only when EVERY hop verifies (a connected real-edge walk); one
    unconfirmable hop makes it `plausible` — surfaced with the gap flagged, never
    asserted as grounded. Nothing asserted is fabricated: hosts are resolved and
    cited QIDs are in scope, so hallucination stays 0 in both tiers."""
    order = _visited_order(p.get("hops", []), host_set)
    if not order:
        return None  # rejected: no anchorable real host
    walk = [INTERNET] + order
    by_dst = {resolve_host(h.get("to", ""), host_set): h for h in p.get("hops", [])}

    hops_out: list[dict] = []
    verified = 0
    cited_qids: set[int] = set()
    for x, y in zip(walk, walk[1:]):
        edge = real_edge(g, x, y)
        model_hop = by_dst.get(y, {})
        try:
            cited = int(model_hop.get("via_qid"))
        except (TypeError, ValueError):
            cited = None
        if edge is not None:
            via = edge.get("via_qid")
            if via is None:
                # QID-less lateral/adjacency edge: the relationship enables it. Only
                # surface a cited QID if it is a real finding on an endpoint host.
                via = cited if (cited in _endpoint_qids(x, y, nodes)) else None
            hop_ok = True
            kind = edge.get("kind", "")
            enabler = str(model_hop.get("enabler", "") or edge.get("enabler", ""))
        else:
            # No real edge — the graph can't confirm this hop. Keep it flagged
            # (plausible), citing only an in-scope QID (else None), never fabricated.
            via = cited if (cited in known_qids) else None
            hop_ok = False
            kind = "unverified"
            enabler = str(model_hop.get("enabler", ""))
        if via is not None:
            cited_qids.add(via)
        verified += hop_ok
        hops_out.append({"from": x, "to": y, "via_qid": via, "enabler": enabler,
                         "why": str(model_hop.get("why", "")), "kind": kind,
                         "verified": hop_ok})

    total = len(hops_out)
    label = "grounded" if verified == total else "plausible"
    target_node = nodes.get(order[-1])
    score, components = _score_path(label, verified / total if total else 0.0,
                                    total, cited_qids, target_node, df_by_qid)
    return {
        "name": str(p.get("name", "")),
        "entry": order[0],
        "target": order[-1],
        "hops": hops_out,
        "business_impact": str(p.get("business_impact", "")),
        "confidence": str(p.get("confidence", "")),
        "label": label,
        "grounded": label == "grounded",
        "verified_hops": verified,
        "total_hops": total,
        "score": score,
        "score_components": components,
    }


def _detect_tool_using(df: pd.DataFrame, cmdb: CMDB, caps: dict[int, Capability],
                       nodes: dict[str, HostNode], graph: nx.DiGraph,
                       session_state=None, should_cancel=None) -> dict:
    """Bounded tool-using ReAct detection. Returns the same schema the single-shot
    path did (`detected_paths`), plus a `reasoning_trace` and loop diagnostics."""
    host_set = set(nodes)
    known_qids = {int(q) for q in df["QID"]}
    df_by_qid = {int(r["QID"]): r for _, r in df.iterrows()}
    tools, seed = build_detection_tools(df, cmdb, caps, graph, nodes)

    acct_marker = call_log.marker()
    loop = run_react_loop(
        role="attack_path",
        system_prompt=analyst_persona(),
        task_prompt=f"{_DETECTION_TASK}\n\n{seed}",
        tools=tools,
        session_state=session_state,
        max_iters=DETECTION_AGENT_MAX_ITERS,
        token_budget=DETECTION_AGENT_TOKEN_BUDGET,
        max_tokens=DETECTION_AGENT_MAX_TOKENS,
        temperature=DETECTION_AGENT_TEMPERATURE,
        should_cancel=should_cancel,
        detail="analyst detection",
    )

    # `tokens_est` is the loop's cheap len/4 budgeting estimate; `accounting` is the
    # REAL usage (tokens/cost/latency) for exactly this loop's calls, from call_log.
    diag = {"reasoning_trace": loop.trace, "stopped_reason": loop.stopped_reason,
            "iterations": loop.iterations, "tokens_est": loop.tokens,
            "accounting": call_log.summarize_since(acct_marker)}
    if loop.stopped_reason == "no_provider":
        return {"detected_paths": [], "error": "no provider connected", **diag}

    # Build every model path into a grounded/plausible path (None ⇒ rejected), dedup,
    # then rank by the calibrated score so documented high-impact paths surface first
    # and plausible paths (damped) can never outrank an equivalent grounded one.
    built: list[dict] = []
    rejected = 0
    seen: set[tuple[str, ...]] = set()
    for p in _final_paths(loop.final):
        vp = _build_path(p, graph, host_set, known_qids, nodes, df_by_qid)
        if vp is None:
            rejected += 1
            continue
        key = tuple([vp["entry"]] + [h["to"] for h in vp["hops"]])
        if key in seen:
            continue
        seen.add(key)
        built.append(vp)

    built.sort(key=lambda d: d["score"], reverse=True)
    emitted = built[:_MAX_EMITTED_PATHS]

    diag["rejected"] = rejected
    # Retain the Phase-3 key (now = unconfirmable-hop paths kept as `plausible`).
    diag["dropped_unverified"] = rejected
    diag["tier_counts"] = {
        "grounded": sum(1 for d in emitted if d["label"] == "grounded"),
        "plausible": sum(1 for d in emitted if d["label"] == "plausible"),
        "rejected": rejected,
    }
    return {"detected_paths": emitted, **diag}


# ---------------------------------------------------------------------------
# Single-shot detection (pre-Phase-3 fallback; DETECTION_AGENT_ENABLED=0)
# ---------------------------------------------------------------------------

def _detect_single_shot(df: pd.DataFrame, cmdb: CMDB, caps: dict[int, Capability],
                        nodes: dict, session_state=None) -> dict:
    """The original single-completion detection: reason paths in one shot, then
    verify each hop only by host/QID existence. Kept as a comparison / safety
    hatch behind DETECTION_AGENT_ENABLED=0."""
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


def detect_attack_paths(df: pd.DataFrame, cmdb: CMDB, caps: dict[int, Capability],
                        nodes: dict, graph: nx.DiGraph, session_state=None,
                        should_cancel=None) -> dict:
    """Independently detect attack paths from grounding alone, verifying every hop
    against the real reachability graph. Drives the tool-using ReAct loop by
    default (DETECTION_AGENT_ENABLED); falls back to the single-shot reasoning when
    disabled. Degrades to an empty list (with an `error`) if no provider answers —
    the deterministic engine's paths are unaffected either way."""
    if DETECTION_AGENT_ENABLED and graph is not None:
        try:
            return _detect_tool_using(df, cmdb, caps, nodes, graph,
                                      session_state=session_state, should_cancel=should_cancel)
        except Exception as exc:  # noqa: BLE001 — never let detection crash the pipeline
            logger.warning("tool-using detection failed, no AI paths emitted: %s", exc)
            return {"detected_paths": [], "error": str(exc)}
    return _detect_single_shot(df, cmdb, caps, nodes, session_state=session_state)
