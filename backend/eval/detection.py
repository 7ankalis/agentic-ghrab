"""
Detection-quality harness — the ruler Phase 0 builds before anything changes.

Run it:

    cd backend && python -m eval.detection            # print the metric table
    cd backend && python -m eval.detection --update-baseline   # (re)commit baselines

What it does, for every shipped dataset that has a held-out oracle file:

  1. Runs the detection pipeline — the deterministic reachability engine always,
     plus the AI Analyst Detection Agent when a provider is configured (graceful
     degradation: no provider ⇒ deterministic-only, which is the committed
     baseline since this repo ships with no keys).
  2. Compares the detected attack paths against the documented oracle at two
     granularities:
       - target level: did we reach each crown jewel the oracle documents?
         → precision / recall / F1 over the set of documented target hosts.
       - hop/edge level: Jaccard overlap of enabler-QID sets and host sequences
         between each oracle path and its best-matching detected path
         → mean Jaccard + edge precision / recall / F1.
  3. Reports soundness (fraction of asserted hops that are a real graph edge —
     must be 1.0 for a grounded engine) and hallucination rate (asserted hosts /
     QIDs not in scope — must be 0).
  4. Emits one JSON per dataset under eval/baselines/ plus a combined snapshot,
     and prints a human-readable table (with the delta vs the committed baseline
     when one exists).

The oracle is the ANSWER KEY: it is read here to *score* detection, never fed to
the engine or any agent (invariant #1 of the brief).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Bootstrap so both `python -m eval.detection` (cwd=backend) and
# `python backend/eval/detection.py` (cwd=repo root) resolve `core.*`/`agents.*`
# the same way the rest of the backend does (backend/ on sys.path, not repo root).
_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import networkx as nx  # noqa: E402

from core import datasets  # noqa: E402
from core.attack_graph import INTERNET, discover_paths  # noqa: E402
from core.capability import classify_all, classify_all_hybrid  # noqa: E402
from core.cmdb import get_cmdb, reset_cmdb  # noqa: E402
from core.graph import build_chains  # noqa: E402
from core.ingestion import get_vulnerabilities, reset_vulnerabilities  # noqa: E402
from core.oracle import _oracle_csv  # noqa: E402
from core.providers import any_provider_configured  # noqa: E402

BASELINE_DIR = Path(__file__).resolve().parent / "baselines"
# Gate metrics may drop by at most this much below baseline before the regression
# test fails; hallucination is gated separately at an absolute 0.
REGRESSION_TOLERANCE = 0.02
# Metrics the regression test enforces as "must not regress" (higher is better).
GATED_METRICS = [
    ("target_level", "recall"),
    ("target_level", "f1"),
    ("edge_level", "qid_jaccard_mean"),
    ("edge_level", "recall"),
    ("soundness", None),
]


# ---------------------------------------------------------------------------
# Dataset iteration
# ---------------------------------------------------------------------------

def datasets_with_oracle() -> list[str]:
    """Dataset keys that ship a held-out oracle file (scoreable), sorted."""
    return sorted(d.key for d in datasets.discover() if _oracle_csv(d.key).exists())


def _load_dataset(key: str):
    """Switch the active enterprise and re-read its (singleton-cached) data."""
    datasets.set_active(key)
    reset_vulnerabilities()
    reset_cmdb()
    df = get_vulnerabilities()
    cmdb = get_cmdb()
    caps = classify_all(df)
    paths, g, nodes = discover_paths(df, cmdb, caps)
    return df, cmdb, caps, paths, g, nodes


# ---------------------------------------------------------------------------
# Normalised path views (detected + oracle) over the real asset set
# ---------------------------------------------------------------------------

@dataclass
class PathView:
    """A detected or documented path reduced to the pieces the metrics need."""
    target: str                       # canonical target host ("" if unresolved)
    hosts: list[str] = field(default_factory=list)   # canonical, real, in order
    qids: set[int] = field(default_factory=set)       # enabler QIDs
    walk: list[str] = field(default_factory=list)     # [INTERNET, h0, h1, ...] for soundness
    raw_hosts: list[str] = field(default_factory=list)  # as-asserted, for hallucination
    raw_qids: list[int] = field(default_factory=list)   # as-asserted, for hallucination
    origin: str = "deterministic"                       # deterministic | ai
    label: str = "grounded"                             # grounded | plausible (Phase 4)
    score: float = 0.0                                  # ranker score (native per origin)


def _canon(name: str, host_set: set[str]) -> str | None:
    """Map a host reference (real or pseudo, e.g. 'VPN-GW01 policy') to a real
    asset name, else None. Mirrors tests/test_rediscovery._canon."""
    n = str(name).strip().strip("`")
    if n in host_set:
        return n
    low = n.lower()
    for h in host_set:
        if h and (h.lower() == low or low.startswith(h.lower()) or h.lower() in low):
            return h
    return None


def _detected_views(paths, host_set: set[str]) -> list[PathView]:
    """Deterministic DiscoveredPath objects → PathViews. Every host already comes
    from the graph, so canonicalisation is a no-op here; it still runs so the
    hallucination measurement is honest rather than assumed."""
    views = []
    for p in paths:
        hosts = [_canon(h, host_set) or h for h in p.hosts]
        real = [h for h in hosts if h in host_set]
        views.append(PathView(
            target=_canon(p.target, host_set) or p.target,
            hosts=real,
            qids=set(int(q) for q in p.enabler_qids),
            walk=[INTERNET] + p.hosts,
            raw_hosts=list(p.hosts),
            raw_qids=[int(q) for q in p.enabler_qids],
            score=float(getattr(p, "score", 0.0)),
        ))
    return views


def _snapshot_views(snapshot_paths: list[dict], host_set: set[str]) -> list[PathView]:
    """A saved deterministic snapshot's `paths` (eval/snapshot_acmebank.py shape:
    {hosts, target, enabler_qids, score}) → PathViews, so the same metric functions
    that score the live pipeline can score a *frozen* run. This is how the Phase-3
    before/after is established: the committed pre-Phase-3 snapshot is scored against
    the identical oracle as the current pipeline, with no re-running of old code."""
    views = []
    for p in snapshot_paths:
        hosts = [_canon(h, host_set) or h for h in p.get("hosts", [])]
        real = [h for h in hosts if h in host_set]
        views.append(PathView(
            target=_canon(p.get("target", ""), host_set) or str(p.get("target", "")),
            hosts=real,
            qids=set(int(q) for q in p.get("enabler_qids", [])),
            walk=[INTERNET] + list(p.get("hosts", [])),
            raw_hosts=list(p.get("hosts", [])),
            raw_qids=[int(q) for q in p.get("enabler_qids", [])],
            score=float(p.get("score", 0.0) or 0.0),
        ))
    return views


def _ai_detected_views(ai_paths: list[dict], host_set: set[str]) -> list[PathView]:
    """AI Analyst Detection Agent output (detect_attack_paths) → PathViews. Its
    hops are (from,to,via_qid); the walk starts at INTERNET so an entry hop that
    does not actually leave the internet is caught by the soundness check."""
    views = []
    for p in ai_paths:
        hops = p.get("hops", [])
        seq: list[str] = []
        raw_hosts: list[str] = []
        raw_qids: list[int] = []
        for h in hops:
            for key in ("from", "to"):
                raw = h.get(key, "")
                if raw:
                    raw_hosts.append(str(raw))
            dst = h.get("to", "")
            c = _canon(dst, host_set)
            if c:
                seq.append(c)
            q = h.get("via_qid")
            if isinstance(q, int):
                raw_qids.append(q)
        views.append(PathView(
            target=_canon(p.get("target", ""), host_set) or str(p.get("target", "")),
            hosts=[h for h in seq if h in host_set],
            qids=set(q for q in raw_qids),
            walk=[INTERNET] + seq,
            raw_hosts=raw_hosts,
            raw_qids=raw_qids,
            origin="ai",
            label=str(p.get("label", "grounded")),
            score=float(p.get("score", 0.0) or 0.0),
        ))
    return views


def _oracle_views(chains, host_set: set[str]) -> list[PathView]:
    """Documented chains (build_chains) → PathViews. Pseudo-hosts that don't
    resolve to a real asset (firewall-policy nodes) are dropped from the host
    set so host-overlap compares real hops only."""
    views = []
    for c in chains:
        raw_hosts = [s.hostname for s in c.steps]
        canon = [_canon(h, host_set) for h in raw_hosts]
        real = [h for h in canon if h]
        views.append(PathView(
            target=_canon(c.target, host_set) or c.target,
            hosts=real,
            qids=set(int(s.qid) for s in c.steps),
            walk=[],
            raw_hosts=raw_hosts,
            raw_qids=[int(s.qid) for s in c.steps],
        ))
    return views


# ---------------------------------------------------------------------------
# Metric primitives
# ---------------------------------------------------------------------------

def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _f1(precision: float, recall: float) -> float:
    return 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)


def _target_metrics(detected: list[PathView], oracle: list[PathView]) -> dict:
    oracle_targets = {o.target for o in oracle if o.target}
    detected_targets = {d.target for d in detected if d.target}
    tp = oracle_targets & detected_targets
    recall = len(tp) / len(oracle_targets) if oracle_targets else 0.0
    precision = len(tp) / len(detected_targets) if detected_targets else 0.0
    return {
        "tp": len(tp),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(_f1(precision, recall), 4),
        "oracle_targets": sorted(oracle_targets),
        "detected_targets": sorted(detected_targets),
        "reached_targets": sorted(tp),
        "missed_targets": sorted(oracle_targets - detected_targets),
    }


def _best_match(view: PathView, candidates: list[PathView]) -> PathView | None:
    """Best counterpart for `view`: prefer same target, then maximise enabler-QID
    Jaccard, tie-broken by host Jaccard."""
    if not candidates:
        return None
    same_target = [c for c in candidates if c.target and c.target == view.target]
    pool = same_target or candidates
    return max(pool, key=lambda c: (_jaccard(view.qids, c.qids),
                                    _jaccard(set(view.hosts), set(c.hosts))))


def _edge_metrics(detected: list[PathView], oracle: list[PathView]) -> dict:
    """Hop/edge overlap. Recall is oracle-anchored (how much of each documented
    chain we recover); precision is detection-anchored (how much of what we assert
    is documented). Both use the best matching path on the other side."""
    qid_jacc, host_jacc, per_oracle_recall = [], [], []
    per_path = {}
    for o in oracle:
        best = _best_match(o, detected)
        qj = _jaccard(o.qids, best.qids) if best else 0.0
        hj = _jaccard(set(o.hosts), set(best.hosts)) if best else 0.0
        rec = (len(o.qids & best.qids) / len(o.qids)) if (best and o.qids) else 0.0
        qid_jacc.append(qj)
        host_jacc.append(hj)
        per_oracle_recall.append(rec)
        per_path[o.target or "?"] = {
            "qid_jaccard": round(qj, 4), "host_jaccard": round(hj, 4),
            "qid_recall": round(rec, 4),
            "recovered_qids": sorted(o.qids & best.qids) if best else [],
            "oracle_qids": sorted(o.qids),
        }

    per_detected_precision = []
    for d in detected:
        best = _best_match(d, oracle)
        prec = (len(d.qids & best.qids) / len(d.qids)) if (best and d.qids) else 0.0
        per_detected_precision.append(prec)

    def mean(xs):
        return round(sum(xs) / len(xs), 4) if xs else 0.0

    recall = mean(per_oracle_recall)
    precision = mean(per_detected_precision)
    return {
        "qid_jaccard_mean": mean(qid_jacc),
        "host_jaccard_mean": mean(host_jacc),
        "recall": recall,
        "precision": precision,
        "f1": round(_f1(precision, recall), 4),
        "per_path": per_path,
    }


def _soundness(detected: list[PathView], g: nx.DiGraph) -> tuple[float, int, int, dict]:
    """Fraction of asserted hops that are a real edge in the reachability graph.
    A hop is (consecutive pair in the walk); INTERNET→entry counts too. Also split
    by origin so the graph-constructed deterministic engine (always 1.0) is not
    conflated with the AI agent's still-weakly-verified hops (Phase 4 target)."""
    verified = total = 0
    by: dict[str, list[int]] = {}
    for d in detected:
        v = t = 0
        for a, b in zip(d.walk, d.walk[1:]):
            t += 1
            if g.has_edge(a, b):
                v += 1
        verified += v
        total += t
        acc = by.setdefault(d.origin, [0, 0])
        acc[0] += v
        acc[1] += t
    by_origin = {o: {"rate": round(v / t, 4) if t else 1.0, "verified": v, "total": t}
                 for o, (v, t) in by.items()}
    return (verified / total if total else 1.0), verified, total, by_origin


def _soundness_grounded(detected: list[PathView], g: nx.DiGraph) -> tuple[float, int, int]:
    """Soundness restricted to paths labeled `grounded` — the Phase-4 acceptance
    bar (must be exactly 1.0: a grounded path is a connected real-edge walk by
    construction). Plausible paths carry a deliberate unconfirmable hop and are
    excluded here; their gap shows up in the overall soundness_by_origin instead."""
    v = t = 0
    for d in detected:
        if d.label != "grounded":
            continue
        for a, b in zip(d.walk, d.walk[1:]):
            t += 1
            if g.has_edge(a, b):
                v += 1
    return (v / t if t else 1.0), v, t


def _ranking_metrics(detected: list[PathView], oracle: list[PathView]) -> dict:
    """Does the calibrated ranker float the documented (oracle) crown-jewel targets
    above non-documented noise? Reduce detected paths to distinct targets by their
    best score (scores are min-max normalised WITHIN each origin so the deterministic
    and AI scales merge fairly), rank descending, and score the ordering with average
    precision / MRR / precision@N over 'target is documented in the oracle'."""
    oracle_targets = {o.target for o in oracle if o.target}
    if not oracle_targets:
        return {"average_precision": 0.0, "mrr": 0.0, "precision_at_n": 0.0,
                "ranked_targets": [], "n_documented_detected": 0}

    by_origin: dict[str, list[PathView]] = {}
    for d in detected:
        by_origin.setdefault(d.origin, []).append(d)
    norm: dict[int, float] = {}
    for views in by_origin.values():
        scores = [v.score for v in views]
        lo, hi = min(scores), max(scores)
        for v in views:
            norm[id(v)] = (v.score - lo) / (hi - lo) if hi > lo else 1.0

    best: dict[str, float] = {}
    for d in detected:
        if not d.target:
            continue
        s = norm[id(d)]
        if d.target not in best or s > best[d.target]:
            best[d.target] = s

    ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
    hits = [t in oracle_targets for t, _ in ranked]
    tp = 0
    ap_sum = 0.0
    for i, hit in enumerate(hits, 1):
        if hit:
            tp += 1
            ap_sum += tp / i
    n_rel = sum(1 for t in oracle_targets if t in best)  # documented targets we detected
    avg_prec = ap_sum / n_rel if n_rel else 0.0
    mrr = next((1 / i for i, hit in enumerate(hits, 1) if hit), 0.0)
    k = len(oracle_targets)
    prec_at_n = sum(hits[:k]) / k if k else 0.0
    return {
        "average_precision": round(avg_prec, 4),
        "mrr": round(mrr, 4),
        "precision_at_n": round(prec_at_n, 4),
        "n_documented_detected": n_rel,
        "ranked_targets": [{"target": t, "score": round(s, 4), "documented": t in oracle_targets}
                           for t, s in ranked],
    }


def _hallucination(detected: list[PathView], host_set: set[str],
                   qid_set: set[int]) -> tuple[float, int, int]:
    """Fraction of asserted host/QID references that are not in scope. Must be 0:
    a real detection never names a host or finding that doesn't exist. INTERNET is
    in scope — it's the graph's attacker-origin node (added explicitly in
    build_graph, and where every deterministic walk starts); the AI paths just name
    it explicitly in a hop's `from` where the deterministic view keeps it implicit."""
    bad = total = 0
    for d in detected:
        for h in d.raw_hosts:
            total += 1
            if str(h).strip().strip("`").upper() != INTERNET and _canon(h, host_set) is None:
                bad += 1
        for q in d.raw_qids:
            total += 1
            if int(q) not in qid_set:
                bad += 1
    return (bad / total if total else 0.0), bad, total


# ---------------------------------------------------------------------------
# Per-dataset evaluation
# ---------------------------------------------------------------------------

def _provenance(caps) -> dict:
    """Distribution of capability sources — how many findings the LLM enriched."""
    dist = {"regex": 0, "llm": 0, "both": 0}
    for c in caps.values():
        dist[getattr(c, "source", "regex")] = dist.get(getattr(c, "source", "regex"), 0) + 1
    return dist


def evaluate_dataset(key: str, include_ai: bool | None = None) -> dict:
    """Score one dataset. `include_ai=None` auto-enables the AI layer only when a
    provider is configured (keeps the committed baseline deterministic and
    reproducible). With AI on, capabilities are the hybrid regex+LLM classification
    and the graph is rebuilt from them, so the metric reflects Phase-1 gains."""
    df, cmdb, caps, paths, g, nodes = _load_dataset(key)
    ai_enabled = any_provider_configured(None) if include_ai is None else include_ai
    ai_error = None
    provenance = _provenance(caps)

    if ai_enabled:
        # Hybrid classification can open reachability edges regex missed → rebuild
        # the graph + paths from the enriched capabilities before scoring. Force
        # use_llm here (independent of the product's default-off CAPABILITY_LLM_ENABLED
        # flag): measuring Phase-1 gains is the whole point of an AI-on eval run.
        caps = classify_all_hybrid(df, cmdb, use_llm=True)
        provenance = _provenance(caps)
        paths, g, nodes = discover_paths(df, cmdb, caps)

    host_set = set(nodes)
    qid_set = {int(q) for q in df["QID"]}
    chains = build_chains(df)

    detected = _detected_views(paths, host_set)
    if ai_enabled:
        # Import lazily so the deterministic path never pulls the agent stack.
        from agents.analyst_agent import detect_attack_paths
        ai = detect_attack_paths(df, cmdb, caps, nodes, g)
        ai_error = ai.get("error")
        detected += _ai_detected_views(ai.get("detected_paths", []), host_set)

    oracle = _oracle_views(chains, host_set)

    soundness, sv, st, soundness_by_origin = _soundness(detected, g)
    sg_rate, sg_v, sg_t = _soundness_grounded(detected, g)
    ranking = _ranking_metrics(detected, oracle)
    hrate, hb, ht = _hallucination(detected, host_set, qid_set)

    return {
        "dataset": key,
        "ai_enabled": bool(ai_enabled),
        "ai_error": ai_error,
        "capability_provenance": provenance,
        "counts": {
            "detected_paths": len(detected),
            "oracle_paths": len(oracle),
            "assets": len(nodes),
            "findings": len(df),
            "graph_edges": g.number_of_edges(),
        },
        "target_level": _target_metrics(detected, oracle),
        "edge_level": _edge_metrics(detected, oracle),
        "soundness": round(soundness, 4),
        "soundness_hops": {"verified": sv, "total": st},
        "soundness_by_origin": soundness_by_origin,
        "soundness_grounded": round(sg_rate, 4),
        "soundness_grounded_hops": {"verified": sg_v, "total": sg_t},
        "ranking": ranking,
        "hallucination_rate": round(hrate, 4),
        "hallucination_refs": {"bad": hb, "total": ht},
    }


def evaluate_all(include_ai: bool | None = None) -> dict:
    keys = datasets_with_oracle()
    return {key: evaluate_dataset(key, include_ai=include_ai) for key in keys}


# ---------------------------------------------------------------------------
# Baseline persistence + reporting
# ---------------------------------------------------------------------------

def _dig(report: dict, section: str, metric: str | None) -> float:
    node = report[section]
    return float(node if metric is None else node[metric])


def _safe_dig(report: dict | None, section: str, metric: str | None) -> float | None:
    """_dig that tolerates a missing section/metric (older committed baselines lack
    the Phase-4 keys) by returning None instead of raising."""
    if report is None:
        return None
    try:
        return _dig(report, section, metric)
    except (KeyError, TypeError, ValueError):
        return None


def load_baseline(key: str) -> dict | None:
    path = BASELINE_DIR / f"{key}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_baselines(results: dict) -> None:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    for key, report in results.items():
        (BASELINE_DIR / f"{key}.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (BASELINE_DIR / "baseline.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8")


def _fmt_delta(cur: float, base: float | None) -> str:
    if base is None:
        return ""
    d = cur - base
    if abs(d) < 1e-9:
        return "  (=)"
    return f"  ({'+' if d > 0 else ''}{d:.3f})"


def render_table(results: dict, baselines: dict | None = None) -> str:
    baselines = baselines or {}
    rows = [
        ("target recall", "target_level", "recall"),
        ("target precision", "target_level", "precision"),
        ("target F1", "target_level", "f1"),
        ("edge QID-Jaccard", "edge_level", "qid_jaccard_mean"),
        ("edge host-Jaccard", "edge_level", "host_jaccard_mean"),
        ("edge recall", "edge_level", "recall"),
        ("edge precision", "edge_level", "precision"),
        ("edge F1", "edge_level", "f1"),
        ("soundness", "soundness", None),
        ("soundness(grounded)", "soundness_grounded", None),
        ("ranking AP", "ranking", "average_precision"),
        ("ranking MRR", "ranking", "mrr"),
        ("hallucination", "hallucination_rate", None),
    ]
    out: list[str] = []
    for key, report in results.items():
        base = (baselines or {}).get(key)
        c = report["counts"]
        out.append(f"\n=== {key} "
                   f"(AI {'ON' if report['ai_enabled'] else 'off'}) — "
                   f"{c['detected_paths']} detected vs {c['oracle_paths']} documented "
                   f"| {c['assets']} assets, {c['findings']} findings ===")
        tl = report["target_level"]
        if tl["missed_targets"]:
            out.append(f"  missed crown jewels: {', '.join(tl['missed_targets'])}")
        for label, section, metric in rows:
            cur = _safe_dig(report, section, metric)
            if cur is None:
                continue
            base_val = _safe_dig(base, section, metric)
            out.append(f"  {label:<20} {cur:6.3f}{_fmt_delta(cur, base_val)}")
    return "\n".join(out)


def check_regressions(results: dict, tolerance: float = REGRESSION_TOLERANCE) -> list[str]:
    """Return a list of human-readable regression failures vs committed baselines
    (empty ⇒ green). Gated 'higher is better' metrics may not drop more than
    `tolerance`; hallucination may not exceed its baseline at all."""
    failures: list[str] = []
    for key, report in results.items():
        base = load_baseline(key)
        if base is None:
            failures.append(f"{key}: no committed baseline (run --update-baseline)")
            continue
        for section, metric in GATED_METRICS:
            cur, prev = _dig(report, section, metric), _dig(base, section, metric)
            if cur < prev - tolerance:
                name = section if metric is None else f"{section}.{metric}"
                failures.append(f"{key}: {name} regressed {prev:.3f} -> {cur:.3f} "
                                f"(tol {tolerance})")
        cur_h = report["hallucination_rate"]
        base_h = base["hallucination_rate"]
        if cur_h > base_h + 1e-9:
            failures.append(f"{key}: hallucination_rate rose {base_h:.3f} -> {cur_h:.3f} "
                            f"(must stay <= baseline)")
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Attack-path detection eval harness")
    ap.add_argument("--update-baseline", action="store_true",
                    help="commit the current metrics as the new baseline snapshot")
    ap.add_argument("--json", action="store_true",
                    help="print the full metrics JSON instead of the table")
    ap.add_argument("--no-ai", action="store_true",
                    help="force deterministic-only even if a provider is configured")
    args = ap.parse_args(argv)

    include_ai = False if args.no_ai else None
    results = evaluate_all(include_ai=include_ai)
    baselines = {k: load_baseline(k) for k in results}

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_table(results, baselines))

    if args.update_baseline:
        write_baselines(results)
        print(f"\nBaseline written to {BASELINE_DIR}")
        return 0

    failures = check_regressions(results)
    if failures:
        print("\nREGRESSIONS:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nNo regressions vs committed baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
