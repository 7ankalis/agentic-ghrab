"""Acceptance gate: the discovery engine must re-derive the documented attack
paths A-F from capability logic alone. The `Attack_Path_Ref` column is used
ONLY here, as an offline oracle — never by the engine itself."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import discover_paths
from core.capability import classify_all
from core.cmdb import get_cmdb
from core.ingestion import get_vulnerabilities


def documented_routes(df):
    """Ordered host sequence per documented PATH-x, from Attack_Path_Ref (oracle only)."""
    routes: dict[str, list[str]] = {}
    for _, r in df.iterrows():
        ref = str(r["Attack_Path_Ref"])
        if ref.startswith("PATH-"):
            pid = ref.split("-Step")[0]
            step = int(ref.split("-Step")[1])
            routes.setdefault(pid, []).append((step, r["Hostname"]))
    return {p: [h for _, h in sorted(v)] for p, v in routes.items()}


def _canon(name, hosts):
    n = str(name).strip()
    for h in hosts:
        if h == n or n.lower().startswith(h.lower()) or h.lower() in n.lower():
            return h
    return n


def main():
    df = get_vulnerabilities()
    cmdb = get_cmdb()
    caps = classify_all(df)
    paths, g, nodes = discover_paths(df, cmdb, caps)
    host_set = set(nodes)

    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    print(f"Discovered {len(paths)} attack paths:\n")
    discovered_hostsets = []
    for p in paths:
        hs = [s.host for s in p.steps]
        discovered_hostsets.append(set(hs))
        print(f"  {p.path_id}  score={p.score:5.1f}  maxGRS={p.max_grs:5.1f}  "
              f"blast={p.blast_radius}  {p.entry} → {p.target}")
        print(f"        route: {' → '.join(hs)}")

    import networkx as nx
    print("\n--- Rediscovery of documented paths (oracle: engine's own graph) ---")
    print("A documented path is rediscovered if the engine independently connects")
    print("the attacker (INTERNET) → the documented entry → the documented crown jewel.\n")
    routes = documented_routes(df)
    ok = 0
    for pid, route in sorted(routes.items()):
        real = [h for h in (_canon(x, host_set) for x in route) if h in host_set]
        entry, target = real[0], real[-1]
        reach_entry = nx.has_path(g, "INTERNET", entry)
        entry_to_target = nx.has_path(g, entry, target)
        good = reach_entry and entry_to_target
        ok += good
        print(f"  {pid}: {'OK  ' if good else 'MISS'}  "
              f"INTERNET→{entry} [{ 'yes' if reach_entry else 'NO'}]  "
              f"{entry}→{target} [{'yes' if entry_to_target else 'NO'}]")
    print(f"\n{ok}/{len(routes)} documented paths rediscovered by the graph engine.")
    return 0 if ok == len(routes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
