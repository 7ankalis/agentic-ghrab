"""
Detection tools — the read-only instruments the tool-using Analyst Detection Agent
investigates with. Every tool is backed by the *real* reachability graph and CMDB
that the deterministic engine already built, so the agent can only ever observe
things that actually exist: assets in the inventory, findings in scope, and edges
the graph builder derived from capabilities + §3/§4/§5 relationships.

This is what makes the agent's paths groundable rather than imagined — it cannot
name a host, QID, or hop that no tool returned. None of these tools read the
oracle (`Attack_Path_Ref` / documented chains): they see findings, capabilities,
zones, and graph edges only (invariant #1).

`build_detection_tools()` returns the tool registry plus a precomputed seed
(entry points, crown jewels, and k shortest candidate routes) that primes the
loop's first turn so the model usually finalizes in a couple of steps instead of
rediscovering the graph by hand — keeping the run cheap on free tiers.
"""
from __future__ import annotations

import networkx as nx
import pandas as pd

from agents.agent_loop import Tool
from core.attack_graph import INTERNET, HostNode
from core.capability import Capability
from core.cmdb import CMDB
from core.config import DETECTION_AGENT_SHORTEST_K, DETECTION_CMDB_TOOL_MAX_ROWS

# Cap on candidate-route length / enumeration so a dense graph can't make a tool
# call expensive; mirrors the reachability engine's own max_len.
_MAX_PATH_LEN = 8


def resolve_host(name: str, host_set: set[str]) -> str | None:
    """Map an agent-written host reference to a real asset name (or INTERNET),
    else None. Same fuzzy contract the graph builder and eval harness use, so a
    hop the model phrases as 'vpn-gw01' resolves to 'VPN-GW01'."""
    n = str(name).strip().strip("`")
    if n == INTERNET or n in host_set:
        return n
    low = n.lower()
    if low == INTERNET.lower():
        return INTERNET
    for h in host_set:
        if h and (h.lower() == low or low.startswith(h.lower()) or h.lower() in low):
            return h
    return None


def real_edge(g: nx.DiGraph, a: str, b: str) -> dict | None:
    """The graph edge a→b as a plain dict (kind/via_qid/enabler/technique), or None
    if no such edge exists. The single source of truth for hop verification."""
    if not g.has_edge(a, b):
        return None
    ed = g[a][b]
    return {
        "kind": ed.get("kind", ""),
        "via_qid": ed.get("qid"),
        "enabler": ed.get("technique", ""),   # for §4 edges this carries the REL id
        "technique": ed.get("technique", ""),
    }


def _finding_detail(row: pd.Series, cap: Capability | None) -> dict:
    """Full finding text + its extracted capability — what an attacker gains here."""
    def num(col):
        try:
            return float(row.get(col, 0.0))
        except (TypeError, ValueError):
            return 0.0
    detail = {
        "qid": int(row["QID"]),
        "title": str(row.get("Title", "")),
        "category": str(row.get("Category", "")),
        "cvss_vector": str(row.get("CVSS_Vector", "")),
        "cve": str(row.get("CVE_ID", "")),
        "hostname": str(row.get("Hostname", "")),
        "zone": str(row.get("Zone", "")),
        "exposure": str(row.get("Exposure_Tier", "")),
        "grs": round(num("GRS"), 1),
        "epss": num("EPSS"),
        "kev": bool(row.get("KEV", False)),
        "acw": num("ACW"),
        "dora_cif": bool(row.get("DORA_CIF", False)),
        "consequence": str(row.get("Consequence", ""))[:280],
    }
    if cap:
        detail.update({
            "technique": cap.technique,
            "effects": list(cap.effects),
            "grants": list(cap.grants),
            "is_entry": bool(cap.is_entry),
        })
    return detail


def _candidate_routes(g: nx.DiGraph, target: str, k: int) -> list[dict]:
    """Up to k shortest INTERNET→target routes as {hosts, edges} where each edge
    is (from, to, kind, via_qid). Token-free graph computation used both to seed
    the loop and to back the shortest_paths tool."""
    try:
        gen = nx.shortest_simple_paths(g, INTERNET, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []
    routes: list[dict] = []
    for path in gen:
        if len(path) - 1 > _MAX_PATH_LEN:
            break
        if len(routes) >= k:
            break
        edges = []
        for a, b in zip(path, path[1:]):
            ed = g[a][b]
            edges.append({"from": a, "to": b, "kind": ed.get("kind", ""),
                          "via_qid": ed.get("qid")})
        routes.append({"hosts": path, "edges": edges})
    return routes


def build_detection_tools(df: pd.DataFrame, cmdb: CMDB, caps: dict[int, Capability],
                          g: nx.DiGraph, nodes: dict[str, HostNode],
                          ) -> tuple[dict[str, Tool], str]:
    """Construct the read-only tool registry over the real graph+CMDB, plus a
    compact seed string (entries, crown jewels, candidate routes) for turn one."""
    host_set = set(nodes)
    df_by_qid = {int(r["QID"]): r for _, r in df.iterrows()}
    entries = sorted(h for h, n in nodes.items() if n.is_entry)
    crowns = sorted(h for h, n in nodes.items() if n.is_crown_jewel and g.in_degree(h) > 0)

    def list_entry_points() -> list[dict]:
        out = []
        for h in entries:
            ed = real_edge(g, INTERNET, h) or {}
            out.append({"host": h, "zone": nodes[h].zone,
                        "via_qid": ed.get("via_qid"), "technique": ed.get("technique", "")})
        return out

    def list_crown_jewels() -> list[dict]:
        return [{"host": h, "zone": nodes[h].zone, "value": nodes[h].target_value,
                 "dora_cif": nodes[h].dora_cif} for h in crowns]

    def neighbors(host: str) -> dict:
        h = resolve_host(host, host_set)
        if h is None:
            return {"error": f"unknown host {host!r}"}
        out = []
        for nb in g.successors(h):
            ed = g[h][nb]
            out.append({"to": nb, "kind": ed.get("kind", ""),
                        "via_qid": ed.get("qid"), "technique": ed.get("technique", "")})
        return {"host": h, "zone": nodes[h].zone, "out_edges": out}

    def finding_detail(qid) -> dict:
        try:
            q = int(qid)
        except (TypeError, ValueError):
            return {"error": f"qid must be an integer, got {qid!r}"}
        row = df_by_qid.get(q)
        if row is None:
            return {"error": f"QID {q} is not in scope"}
        return _finding_detail(row, caps.get(q))

    def test_hop(from_host: str, to_host: str) -> dict:
        a, b = resolve_host(from_host, host_set), resolve_host(to_host, host_set)
        if a is None:
            return {"edge": False, "error": f"unknown host {from_host!r}"}
        if b is None:
            return {"edge": False, "error": f"unknown host {to_host!r}"}
        ed = real_edge(g, a, b)
        if ed is None:
            return {"edge": False, "from": a, "to": b,
                    "reason": "no enabling edge in the reachability graph"}
        return {"edge": True, "from": a, "to": b, **ed}

    def shortest_paths(from_host: str, to_host: str, k: int = DETECTION_AGENT_SHORTEST_K) -> dict:
        a, b = resolve_host(from_host, host_set), resolve_host(to_host, host_set)
        if a is None or b is None:
            return {"error": f"unknown host in ({from_host!r}, {to_host!r})"}
        try:
            k = max(1, min(int(k), 5))
        except (TypeError, ValueError):
            k = DETECTION_AGENT_SHORTEST_K
        try:
            gen = nx.shortest_simple_paths(g, a, b)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return {"from": a, "to": b, "routes": []}
        routes = []
        for path in gen:
            if len(path) - 1 > _MAX_PATH_LEN or len(routes) >= k:
                break
            routes.append({"hosts": path,
                           "edges": [{"from": x, "to": y, "kind": g[x][y].get("kind", ""),
                                      "via_qid": g[x][y].get("qid")}
                                     for x, y in zip(path, path[1:])]})
        return {"from": a, "to": b, "routes": routes}

    # --- Phase 4: structured-CMDB query tools -----------------------------------
    # Read typed records straight off cmdb.structured on demand, so accuracy no
    # longer depends on what fit in grounding_context's 7 KB truncation. Every tool
    # resolves an agent-written reference to a REAL ci_id (Phase-3 exact-resolution
    # discipline — the model can't name a CI no record defines) and degrades to an
    # empty list, never a crash, for markdown datasets where cmdb.structured is None.
    s = getattr(cmdb, "structured", None)
    _cap = DETECTION_CMDB_TOOL_MAX_ROWS
    ci_by_id = {ci.ci_id: ci for ci in s.cis} if s else {}
    name_by_id = {ci.ci_id: ci.name for ci in ci_by_id.values()}
    segments = {ci.ci_id for ci in ci_by_id.values() if ci.ci_class == "cmdb_ci_network_segment"}

    def _resolve_ci(ref):
        """An agent-written CI reference (real asset name or ci_id) → the CI record,
        else None. Exact then case-insensitive on name/id — no fuzzy substring, so a
        pivot can only ever cite a CI that exists."""
        n = str(ref).strip().strip("`")
        if n in ci_by_id:
            return ci_by_id[n]
        low = n.lower()
        for ci in ci_by_id.values():
            if ci.name.lower() == low or ci.ci_id.lower() == low:
                return ci
        return None

    def _resolve_segment(ref):
        """Resolve a zone reference to a network-segment ci_id: a host resolves to its
        containing segment; a segment name / ci_id / VLAN label resolves directly."""
        ci = _resolve_ci(ref)
        if ci is not None:
            if ci.ci_class == "cmdb_ci_network_segment":
                return ci.ci_id
            if ci.zone in segments:
                return ci.zone
        n = str(ref).strip().strip("`")
        for seg_id in segments:
            if s.segment_vlan.get(seg_id, "") == n:
                return seg_id
        return None

    def _seg_label(seg_id):
        vlan = s.segment_vlan.get(seg_id, "") if s else ""
        return f"{seg_id} (VLAN {vlan})" if vlan else seg_id

    def reachability_rule(src, dst) -> dict:
        if s is None:
            return {"rules": []}
        a, b = _resolve_segment(src), _resolve_segment(dst)
        if a is None or b is None:
            return {"error": f"could not resolve zone(s) ({src!r}->{dst!r}) to a network segment",
                    "rules": []}
        rows = [{"rule_id": r.rule_id, "src_zone": _seg_label(r.src_zone),
                 "dst_zone": _seg_label(r.dst_zone), "port": r.port, "status": r.status.value,
                 "enabling_qid": r.enabling_qid, "notes": r.notes}
                for r in s.reachability if r.src_zone == a and r.dst_zone == b]
        return {"src_zone": _seg_label(a), "dst_zone": _seg_label(b),
                "rules": rows[:_cap], "truncated": len(rows) > _cap}

    def relationships_of(ci) -> dict:
        if s is None:
            return {"relationships": []}
        c = _resolve_ci(ci)
        if c is None:
            return {"error": f"unknown CI {ci!r}", "relationships": []}
        out = [{"rel_id": r.rel_id, "rel_type": r.rel_type,
                "source": name_by_id.get(r.source_ci, r.source_ci),
                "target": name_by_id.get(r.target_ci, r.target_ci),
                "direction": "out" if r.source_ci == c.ci_id else "in",
                "port": r.port, "flag": r.flag, "enabling_qid": r.enabling_qid}
               for r in s.relationships if c.ci_id in (r.source_ci, r.target_ci)]
        return {"ci": c.ci_id, "name": c.name, "relationships": out[:_cap],
                "truncated": len(out) > _cap}

    def credentials_valid_on(ci) -> dict:
        if s is None:
            return {"credentials": []}
        c = _resolve_ci(ci)
        if c is None:
            return {"error": f"unknown CI {ci!r}", "credentials": []}
        out = [{"rel_id": cr.rel_id, "identity": name_by_id.get(cr.identity_ci, cr.identity_ci),
                "valid_on": [name_by_id.get(h, h) for h in cr.valid_on],
                "access_level": cr.access_level, "enabling_qid": cr.enabling_qid, "issue": cr.issue}
               for cr in s.credentials if c.ci_id == cr.identity_ci or c.ci_id in cr.valid_on]
        return {"ci": c.ci_id, "name": c.name, "credentials": out[:_cap],
                "truncated": len(out) > _cap}

    def business_service_of(ci) -> dict:
        if s is None:
            return {"business_service": None, "peers": []}
        c = _resolve_ci(ci)
        if c is None:
            return {"error": f"unknown CI {ci!r}"}
        bs = c.business_service or None
        peers = ([x.name for x in ci_by_id.values()
                  if x.business_service and x.business_service == bs and x.ci_id != c.ci_id]
                 if bs else [])
        return {"ci": c.ci_id, "name": c.name, "business_service": bs,
                "peers": peers[:_cap], "truncated": len(peers) > _cap}

    tools = {t.name: t for t in [
        Tool("list_entry_points", "", "internet-reachable assets an attacker can start from",
             list_entry_points),
        Tool("list_crown_jewels", "", "the high-value targets an attacker is after",
             list_crown_jewels),
        Tool("neighbors", "host", "outbound reachability edges from a host (to, kind, enabling QID)",
             neighbors),
        Tool("finding_detail", "qid", "full finding text + extracted attacker capability for a QID",
             finding_detail),
        Tool("test_hop", "from_host, to_host",
             "is there a REAL enabling edge from_host→to_host, and which QID/relationship justifies it",
             test_hop),
        Tool("shortest_paths", "from_host, to_host, k",
             "up to k graph-computed candidate routes between two hosts", shortest_paths),
        Tool("reachability_rule", "src, dst",
             "authoritative net_reachability rows between two zones/hosts "
             "(rule_id, status Intended/Excessive/Should-Not-Exist, enabling QID)",
             reachability_rule),
        Tool("relationships_of", "ci",
             "typed CMDB relationships (Depends on / Hosted on / Backs up / Linked to …) "
             "into and out of a CI, with rel_id + enabling QID", relationships_of),
        Tool("credentials_valid_on", "ci",
             "credential/identity CIs valid on this host — non-network lateral pivots "
             "(shared/cached creds), with the other hosts they reach", credentials_valid_on),
        Tool("business_service_of", "ci",
             "the business service a CI belongs to and its peer CIs (blast-radius anchor)",
             business_service_of),
    ]}

    # Seed: precomputed candidate routes to each crown jewel (token-free) so the
    # model starts from the graph's own best guesses and verifies/expands them,
    # rather than spending calls to rediscover reachability by hand.
    seed_lines = [
        f"Entry points (INTERNET-reachable): {entries or 'none'}",
        f"Crown-jewel targets: {crowns or 'none'}",
        "Candidate routes the reachability graph already found "
        "(verify each hop with test_hop; expand or find better, non-obvious ones):",
        "Non-network pivots the shortest-path seed buries — inspect them with the "
        "structured-CMDB tools: credentials_valid_on(host) for shared/cached-credential "
        "lateral moves, relationships_of(host) for Depends-on/Backs-up/DB-link pivots, "
        "and reachability_rule(src,dst) to confirm an Excessive rule (never assert a hop "
        "across a Should-Not-Exist rule).",
    ]
    for tgt in crowns:
        for r in _candidate_routes(g, tgt, DETECTION_AGENT_SHORTEST_K):
            chain = " -> ".join(
                f"{e['to']}(via {e['kind']}" + (f" QID{e['via_qid']}" if e['via_qid'] else "") + ")"
                for e in r["edges"])
            seed_lines.append(f"  → {tgt}: INTERNET -> {chain}")
    seed = "\n".join(seed_lines)
    return tools, seed
