"""
Phase 3 + 4 — tool-using Analyst Detection Agent tests.

Covers the pieces without spending a real provider call:
  * detection tools (agents/detection_tools.py) tell the truth about the real
    graph/CMDB and leak no oracle text;
  * the bounded ReAct engine (agents/agent_loop.py) honours its iteration / parse
    caps and terminates cleanly;
  * detect_attack_paths drives the loop and (Phase 4) labels each reconstructed
    path grounded/plausible/rejected, tightens the cited-QID rule on lateral hops,
    and ranks emission by a calibrated, component-exposed score;
  * the eval harness scores grounded-only soundness (=1.0) and path ranking.

The provider is always a scripted stub patched onto the agents.base chokepoint —
the same seam the no-oracle-leakage test uses — so these run offline and fast.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import networkx as nx  # noqa: E402
import pytest  # noqa: E402

from agents import base as agent_base  # noqa: E402
from agents.agent_loop import Tool, run_react_loop  # noqa: E402
from agents.analyst_agent import detect_attack_paths  # noqa: E402
from agents.detection_tools import build_detection_tools, resolve_host  # noqa: E402
from core import datasets  # noqa: E402
from core.attack_graph import INTERNET, discover_paths  # noqa: E402
from core.capability import classify_all  # noqa: E402
from core.cmdb import get_cmdb, reset_cmdb  # noqa: E402
from core.graph import build_chains  # noqa: E402
from core.ingestion import get_vulnerabilities, reset_vulnerabilities  # noqa: E402
from core.oracle import attack_path_refs  # noqa: E402
from core.providers import ProviderUnavailable  # noqa: E402

_KEY = "ghrab"


@pytest.fixture(scope="module")
def env():
    """Load the ghrab dataset once and build its deterministic graph."""
    datasets.set_active(_KEY)
    reset_vulnerabilities()
    reset_cmdb()
    df = get_vulnerabilities()
    cmdb = get_cmdb()
    caps = classify_all(df)
    paths, g, nodes = discover_paths(df, cmdb, caps)
    return df, cmdb, caps, g, nodes


def _script(monkeypatch, replies: list[str]):
    """Patch the LLM chokepoint with a scripted sequence of raw completions."""
    calls = {"n": 0}

    def fake_call_llm(role, system_prompt, user_prompt, *a, **k):
        i = calls["n"]
        calls["n"] += 1
        text = replies[i] if i < len(replies) else replies[-1]
        return types.SimpleNamespace(text=text, provider="stub", model="stub")

    monkeypatch.setattr(agent_base, "call_llm", fake_call_llm)
    return calls


def _real_walk_to_crown(g: nx.DiGraph, nodes) -> list[str]:
    """A real INTERNET→crown-jewel walk from the graph, as [INTERNET, h0, …, tgt]."""
    for h, n in nodes.items():
        if n.is_crown_jewel and nx.has_path(g, INTERNET, h):
            return nx.shortest_path(g, INTERNET, h)
    raise AssertionError("fixture has no INTERNET→crown path")


def _walk_to_model_path(walk: list[str]) -> dict:
    """Render a real walk as a model-style path payload (hops of from/to)."""
    hops = [{"from": a, "to": b, "via_qid": g_qid, "enabler": "", "why": "verified"}
            for a, b, g_qid in ((walk[i], walk[i + 1], None)
                                for i in range(len(walk) - 1))]
    return {"name": "T", "entry": walk[1], "target": walk[-1], "hops": hops,
            "business_impact": "x", "confidence": "high"}


# ---------------------------------------------------------------------------
# Detection tools
# ---------------------------------------------------------------------------

def test_test_hop_agrees_with_graph(env):
    df, cmdb, caps, g, nodes = env
    tools, _ = build_detection_tools(df, cmdb, caps, g, nodes)
    test_hop = tools["test_hop"].func
    hosts = [INTERNET] + sorted(nodes)
    checked = 0
    for a in hosts[:12]:
        for b in sorted(nodes)[:12]:
            res = test_hop(from_host=a, to_host=b)
            assert res["edge"] == g.has_edge(a, b), f"test_hop disagrees on {a}->{b}"
            if res["edge"]:
                assert res["kind"] == g[a][b].get("kind", "")
            checked += 1
    assert checked > 0


def test_entry_and_crown_tools_match_nodes(env):
    df, cmdb, caps, g, nodes = env
    tools, _ = build_detection_tools(df, cmdb, caps, g, nodes)
    entries = {e["host"] for e in tools["list_entry_points"].func()}
    crowns = {c["host"] for c in tools["list_crown_jewels"].func()}
    assert entries == {h for h, n in nodes.items() if n.is_entry}
    assert crowns == {h for h, n in nodes.items() if n.is_crown_jewel and g.in_degree(h) > 0}
    # every entry is a real INTERNET successor
    for h in entries:
        assert g.has_edge(INTERNET, h)


def test_neighbors_and_finding_detail_in_scope(env):
    df, cmdb, caps, g, nodes = env
    tools, _ = build_detection_tools(df, cmdb, caps, g, nodes)
    host = next(iter(sorted(nodes)))
    nb = tools["neighbors"].func(host=host.lower())  # fuzzy resolution
    assert nb["host"] == host
    for e in nb["out_edges"]:
        assert g.has_edge(host, e["to"])
    # finding_detail: a real QID resolves, an out-of-scope one errors
    qid = int(df["QID"].iloc[0])
    det = tools["finding_detail"].func(qid=qid)
    assert det["qid"] == qid and "effects" in det
    assert "error" in tools["finding_detail"].func(qid=99999999)


def test_tools_leak_no_oracle_text(env):
    """Invariant #1 on the new tool surface: nothing a tool returns may contain an
    oracle token (documented path ids / Attack_Path_Ref values / the column name)."""
    df, cmdb, caps, g, nodes = env
    forbidden = {v for v in attack_path_refs(_KEY).values() if v}
    forbidden |= {c.path_id for c in build_chains(df)}
    forbidden.add("Attack_Path_Ref")
    forbidden = {t for t in forbidden if t}
    assert forbidden

    tools, seed = build_detection_tools(df, cmdb, caps, g, nodes)
    blobs = [seed, json.dumps(tools["list_entry_points"].func(), default=str),
             json.dumps(tools["list_crown_jewels"].func(), default=str)]
    for h in sorted(nodes):
        blobs.append(json.dumps(tools["neighbors"].func(host=h), default=str))
    for q in df["QID"]:
        blobs.append(json.dumps(tools["finding_detail"].func(qid=int(q)), default=str))
    blob = "\n".join(blobs)
    leaked = sorted(t for t in forbidden if t in blob)
    assert not leaked, f"oracle tokens {leaked} leaked through a detection tool"


# ---------------------------------------------------------------------------
# ReAct loop
# ---------------------------------------------------------------------------

def _echo_tools() -> dict:
    return {"ping": Tool("ping", "", "echo", lambda **k: {"pong": True})}


def test_loop_finalizes_and_traces(monkeypatch):
    _script(monkeypatch, [
        json.dumps({"thought": "look", "action": "ping", "args": {}}),
        json.dumps({"thought": "done", "final": {"answer": 42}}),
    ])
    r = run_react_loop("attack_path", "sys", "task", _echo_tools(), max_iters=5)
    assert r.stopped_reason == "final"
    assert r.final == {"answer": 42}
    assert r.iterations == 2
    assert any(t.get("observation") == {"pong": True} for t in r.trace)


def test_loop_respects_iteration_cap(monkeypatch):
    # never finalizes → must stop at exactly max_iters LLM round-trips
    _script(monkeypatch, [json.dumps({"action": "ping", "args": {}})])
    r = run_react_loop("attack_path", "sys", "task", _echo_tools(), max_iters=3)
    assert r.stopped_reason == "max_iters"
    assert r.iterations == 3


def test_loop_bails_on_repeated_unparseable(monkeypatch):
    _script(monkeypatch, ["not json at all"])
    r = run_react_loop("attack_path", "sys", "task", _echo_tools(), max_iters=6)
    assert r.stopped_reason == "parse_error"
    assert r.iterations <= 2


def test_loop_no_provider_is_clean(monkeypatch):
    def boom(*a, **k):
        raise ProviderUnavailable("no key")
    monkeypatch.setattr(agent_base, "call_llm", boom)
    r = run_react_loop("attack_path", "sys", "task", _echo_tools(), max_iters=4)
    assert r.stopped_reason == "no_provider"
    assert r.final is None


# ---------------------------------------------------------------------------
# detect_attack_paths — verified emission + degradation
# ---------------------------------------------------------------------------

def test_detect_emits_only_verified_paths(env, monkeypatch):
    df, cmdb, caps, g, nodes = env
    walk = _real_walk_to_crown(g, nodes)
    _script(monkeypatch, [
        json.dumps({"final": {"detected_paths": [_walk_to_model_path(walk)]}}),
    ])
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    assert out["detected_paths"], "a real walk should survive verification"
    p = out["detected_paths"][0]
    assert p["grounded"] and p["verified_hops"] == p["total_hops"]
    # every emitted hop is a real graph edge; every host/QID is in scope
    host_set, qid_set = set(nodes), {int(q) for q in df["QID"]}
    for h in p["hops"]:
        assert g.has_edge(h["from"], h["to"])
        assert h["from"] in host_set | {INTERNET} and h["to"] in host_set
        assert h["via_qid"] is None or h["via_qid"] in qid_set
    assert "reasoning_trace" in out


def test_unconfirmable_hop_is_plausible_not_grounded(env, monkeypatch):
    """Phase 4: a path with a hop the graph can't confirm is no longer dropped — it
    surfaces as `plausible` with that hop flagged unverified, and NEVER as grounded."""
    df, cmdb, caps, g, nodes = env
    entry = next(h for h, n in nodes.items() if n.is_entry)
    # a real host the entry does NOT have an edge to → the hop cannot verify
    bad = next(h for h in sorted(nodes)
               if h != entry and not g.has_edge(entry, h) and not nodes[h].is_entry)
    fabricated = {"name": "gap", "entry": entry, "target": bad,
                  "hops": [{"from": INTERNET, "to": entry, "via_qid": None},
                           {"from": entry, "to": bad, "via_qid": None}],
                  "business_impact": "", "confidence": "high"}
    _script(monkeypatch, [json.dumps({"final": {"detected_paths": [fabricated]}})])
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    assert len(out["detected_paths"]) == 1, "the gap path should surface as plausible"
    p = out["detected_paths"][0]
    assert p["label"] == "plausible" and p["grounded"] is False
    assert p["verified_hops"] < p["total_hops"]
    # the specific unconfirmable hop is flagged, not asserted as real
    gap_hop = next(h for h in p["hops"] if h["to"] == bad)
    assert gap_hop["verified"] is False and not g.has_edge(gap_hop["from"], gap_hop["to"])
    assert out["tier_counts"]["plausible"] == 1


def test_grounded_subset_soundness_is_one(env, monkeypatch):
    """Phase-4 acceptance: every hop of a `grounded` path is a real edge — the eval's
    grounded-only soundness must be exactly 1.0 even with a plausible path present."""
    from eval.detection import _ai_detected_views, _soundness_grounded
    df, cmdb, caps, g, nodes = env
    walk = _real_walk_to_crown(g, nodes)
    entry = next(h for h, n in nodes.items() if n.is_entry)
    bad = next(h for h in sorted(nodes)
               if not g.has_edge(entry, h) and not nodes[h].is_entry and h != entry)
    grounded = _walk_to_model_path(walk)
    plausible = {"name": "gap", "entry": entry, "target": bad,
                 "hops": [{"from": INTERNET, "to": entry, "via_qid": None},
                          {"from": entry, "to": bad, "via_qid": None}],
                 "business_impact": "", "confidence": "medium"}
    _script(monkeypatch, [json.dumps({"final": {"detected_paths": [grounded, plausible]}})])
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    labels = {p["label"] for p in out["detected_paths"]}
    assert {"grounded", "plausible"} <= labels
    views = _ai_detected_views(out["detected_paths"], set(nodes))
    rate, v, t = _soundness_grounded(views, g)
    assert rate == 1.0 and t > 0, f"grounded soundness must be 1.0, got {rate} ({v}/{t})"


def test_lateral_hop_strips_foreign_qid_keeps_endpoint_qid(env, monkeypatch):
    """Phase-4 tightening: a QID-less lateral edge may cite a QID only if it is a real
    finding on an endpoint host; a foreign in-scope QID is stripped to None."""
    df, cmdb, caps, g, nodes = env
    # find a real lateral edge (a->b) that carries no enabling QID
    lat = next(((a, b) for a, b in g.edges()
                if a != INTERNET and b != INTERNET and g[a][b].get("qid") is None), None)
    if lat is None:
        pytest.skip("fixture has no QID-less lateral edge")
    a, b = lat
    endpoint_qids = set(nodes[a].qids) | set(nodes[b].qids)
    all_qids = {int(q) for q in df["QID"]}
    foreign = next((q for q in all_qids if q not in endpoint_qids), None)
    home = next(iter(endpoint_qids), None)

    def path_with(qid):
        return {"name": "lat", "entry": a, "target": b,
                "hops": [{"from": a, "to": b, "via_qid": qid, "enabler": "x", "why": "y"}],
                "business_impact": "", "confidence": "low"}

    if foreign is not None:
        _script(monkeypatch, [json.dumps({"final": {"detected_paths": [path_with(foreign)]}})])
        out = detect_attack_paths(df, cmdb, caps, nodes, g)
        hop = next(h for h in out["detected_paths"][0]["hops"] if h["to"] == b)
        assert hop["via_qid"] is None, "a foreign cited QID must be stripped on a lateral hop"
    if home is not None:
        _script(monkeypatch, [json.dumps({"final": {"detected_paths": [path_with(home)]}})])
        out = detect_attack_paths(df, cmdb, caps, nodes, g)
        hop = next(h for h in out["detected_paths"][0]["hops"] if h["to"] == b)
        assert hop["via_qid"] == home, "an endpoint QID must be kept as the lateral enabler"


def test_score_ranks_grounded_above_damped_plausible(env, monkeypatch):
    """The calibrated score exposes its components and damps plausible paths, so a
    plausible path can never outrank an equal-component grounded one; emission is
    ranked by score (grounded first here)."""
    df, cmdb, caps, g, nodes = env
    walk = _real_walk_to_crown(g, nodes)
    entry = next(h for h, n in nodes.items() if n.is_entry)
    bad = next(h for h in sorted(nodes)
               if not g.has_edge(entry, h) and not nodes[h].is_entry and h != entry)
    grounded = _walk_to_model_path(walk)
    plausible = {"name": "gap", "entry": entry, "target": bad,
                 "hops": [{"from": INTERNET, "to": entry, "via_qid": None},
                          {"from": entry, "to": bad, "via_qid": None}],
                 "business_impact": "", "confidence": "high"}
    _script(monkeypatch, [json.dumps({"final": {"detected_paths": [plausible, grounded]}})])
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    scores = [p["score"] for p in out["detected_paths"]]
    assert scores == sorted(scores, reverse=True), "emitted paths must be score-ranked"
    for p in out["detected_paths"]:
        comps = p["score_components"]
        assert set(comps) >= {"reachability", "exploitability", "business_value",
                              "chain_length", "weights", "raw"}
        assert 0.0 <= p["score"] <= 1.0
        if p["label"] == "plausible":
            assert comps["plausible_damping"] < 1.0
        else:
            assert comps["plausible_damping"] == 1.0


def test_unresolvable_host_is_rejected_not_emitted(env, monkeypatch):
    """A path whose hosts don't resolve to any real asset is `rejected`: not emitted,
    counted in tier_counts.rejected, hallucination unaffected."""
    df, cmdb, caps, g, nodes = env
    ghost = {"name": "ghost", "entry": "NOPE-999", "target": "ALSO-NOPE",
             "hops": [{"from": "NOPE-999", "to": "ALSO-NOPE", "via_qid": None}],
             "business_impact": "", "confidence": "high"}
    _script(monkeypatch, [json.dumps({"final": {"detected_paths": [ghost]}})])
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    assert out["detected_paths"] == []
    assert out["tier_counts"]["rejected"] >= 1


def test_ai_paths_zero_hallucination_in_eval(env, monkeypatch):
    """The verified AI paths — including their explicit INTERNET→entry hop — must
    score 0 hallucination through the eval's own measurement (invariant #2)."""
    from eval.detection import _ai_detected_views, _hallucination
    df, cmdb, caps, g, nodes = env
    walk = _real_walk_to_crown(g, nodes)
    _script(monkeypatch, [
        json.dumps({"final": {"detected_paths": [_walk_to_model_path(walk)]}}),
    ])
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    host_set, qid_set = set(nodes), {int(q) for q in df["QID"]}
    views = _ai_detected_views(out["detected_paths"], host_set)
    rate, bad, total = _hallucination(views, host_set, qid_set)
    assert rate == 0.0, f"AI paths hallucinated {bad}/{total} refs"


def test_ranking_floats_documented_targets(env):
    """The eval ranking metric rewards ordering documented crown-jewel targets above
    non-documented noise: a high-scoring documented path above a low-scoring
    non-documented one yields average_precision 1.0."""
    from eval.detection import PathView, _ranking_metrics
    oracle = [PathView(target="DB-CRM01", origin="deterministic")]
    detected = [
        PathView(target="DB-CRM01", origin="ai", label="grounded", score=0.9),
        PathView(target="NOISE-BOX", origin="ai", label="plausible", score=0.2),
    ]
    r = _ranking_metrics(detected, oracle)
    assert r["average_precision"] == 1.0 and r["mrr"] == 1.0
    # invert the scores → the documented target now ranks second
    detected[0].score, detected[1].score = 0.2, 0.9
    r2 = _ranking_metrics(detected, oracle)
    assert r2["mrr"] == 0.5 and r2["average_precision"] < 1.0


def test_detect_degrades_without_provider(env, monkeypatch):
    df, cmdb, caps, g, nodes = env

    def boom(*a, **k):
        raise ProviderUnavailable("no key")
    monkeypatch.setattr(agent_base, "call_llm", boom)
    out = detect_attack_paths(df, cmdb, caps, nodes, g)
    assert out["detected_paths"] == []
    assert out.get("error")
