"""Deterministic acmebank snapshot — captures the discovered attack paths, the
crown-jewel set, and every cross-zone graph hop for the acmebank dataset with NO
provider configured. The committed `baselines/acmebank_pre_phase3.json` snapshot is
the Phase-5 before/after reference for the Phase-3 reachability-rule rewiring:
eval/test_acmebank_accuracy.py scores it against the same oracle as the current
pipeline to prove Phase-3 eliminated the forbidden cross-zone hops it fabricated
(acmebank is now in the scored harness via data/oracle/acmebank_attack_paths.csv).

    cd backend && python -m eval.snapshot_acmebank            # print
    cd backend && python -m eval.snapshot_acmebank --write out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from core import datasets  # noqa: E402
from core.attack_graph import INTERNET, discover_paths  # noqa: E402
from core.capability import classify_all  # noqa: E402
from core.cmdb import get_cmdb, reset_cmdb  # noqa: E402
from core.ingestion import get_vulnerabilities, reset_vulnerabilities  # noqa: E402


def build(key: str = "acmebank") -> dict:
    datasets.set_active(key)
    reset_vulnerabilities()
    reset_cmdb()
    df = get_vulnerabilities()
    cmdb = get_cmdb()
    caps = classify_all(df)
    paths, g, nodes = discover_paths(df, cmdb, caps)

    vlan_of = {h: n.vlan for h, n in nodes.items()}
    cross_zone_hops = []
    for a, b, d in g.edges(data=True):
        if a == INTERNET or b == INTERNET:
            continue
        if vlan_of.get(a) != vlan_of.get(b):
            cross_zone_hops.append({
                "src": a, "dst": b, "src_vlan": vlan_of.get(a), "dst_vlan": vlan_of.get(b),
                "kind": d.get("kind"), "qid": d.get("qid"),
                "rule_id": d.get("rule_id"), "rel_id": d.get("rel_id"),
            })
    cross_zone_hops.sort(key=lambda h: (h["src"], h["dst"]))

    return {
        "dataset": key,
        "counts": {
            "paths": len(paths), "assets": len(nodes),
            "graph_edges": g.number_of_edges(), "cross_zone_hops": len(cross_zone_hops),
        },
        "crown_jewels": sorted(h for h, n in nodes.items() if n.is_crown_jewel),
        "paths": [{"path_id": p.path_id, "entry": p.entry, "target": p.target,
                   "hosts": p.hosts, "enabler_qids": p.enabler_qids,
                   "score": p.score} for p in paths],
        "cross_zone_hops": cross_zone_hops,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", type=str, default=None)
    args = ap.parse_args(argv)
    snap = build()
    text = json.dumps(snap, indent=2) + "\n"
    if args.write:
        Path(args.write).write_text(text, encoding="utf-8")
        print(f"wrote {args.write}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
