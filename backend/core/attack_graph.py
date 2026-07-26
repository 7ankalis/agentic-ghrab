"""
Autonomous attack-path discovery — the second half of the discovery engine.

This composes the per-finding capabilities from core/capability.py into a
directed reachability graph over the *real asset inventory* (from the CMDB),
then enumerates attack chains from attacker-reachable entry points to the
organization's crown jewels. It NEVER reads the `Attack_Path_Ref` column — the
chains are derived purely from (a) where the attacker can start, (b) which
findings open network boundaries or hand over credentials, and (c) which
findings compromise a host. The result is that the engine re-discovers the
documented attack paths (and can surface undocumented ones) on its own.

Edges carry the enabling finding, so every hop is explainable and auditable;
the LLM discovery agent (agents/discovery_agent.py) then validates, ranks, and
narrates these candidate chains rather than inventing them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

from core.capability import (
    Capability, CREDENTIAL_THEFT, GRANT_CLOUD_ADMIN, GRANT_DOMAIN_ADMIN,
    IMPACT, SEGMENTATION_BREAK, classify,
)
from core.cmdb import CMDB
from core.config import (
    CROWN_ACW_THRESHOLD, DISC_SCORE_BLAST_W, DISC_SCORE_GRS_W,
    DISC_SCORE_IDEAL_HOPS, DISC_SCORE_LENGTH_PENALTY, DISC_SCORE_TARGET_VALUE_W,
    EDGE_KIND_REACHABILITY, REACHABILITY_BLOCKED_STATUS,
    REACHABILITY_TRAVERSABLE_STATUSES,
    criticality_is_crown, platform_is_ad_joined, zone_is_critical, zone_is_internal,
)

INTERNET = "INTERNET"

# §4 dependency relationship type (lowercased) → attack-graph edge kind. These
# architectural relations ARE the real host-to-host pivots (app→db, DB links,
# hypervisor management, backup reach, cloud identity), read from the CMDB rather
# than assumed from VLAN numbering. 'Authenticates To' (domain join) is not a
# direct edge — it flags AD-joined hosts for the domain-admin blast radius.
_DEP_EDGE_KIND = {
    "depends on": "lateral",
    "linked to (db link)": "segmentation",
    "linked to": "segmentation",
    "manages": "lateral",
    "backs up": "lateral",
    "grants session to": "segmentation",
    "has access to": "segmentation",
    "forwards to": "lateral",
}


@dataclass
class Step:
    host: str
    zone: str
    arrival_via_qid: int | None       # finding that let the attacker reach this host
    arrival_technique: str
    arrival_kind: str                 # entry | reachability | segmentation | credential | lateral | domain
    exploit_qid: int | None           # finding compromised ON this host
    exploit_technique: str
    grs: float
    arrival_rule_id: str = ""         # authoritative net_reachability rule for a cross-zone network hop
    arrival_rel_id: str = ""          # authoritative cmdb_rel_ci relationship for a non-network pivot


@dataclass
class DiscoveredPath:
    path_id: str
    entry: str
    target: str
    steps: list[Step] = field(default_factory=list)
    score: float = 0.0
    max_grs: float = 0.0
    blast_radius: int = 0             # distinct crown-jewel/high-value hosts touched
    target_value: float = 0.0
    enabler_qids: list[int] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.steps)

    def as_dict(self) -> dict:
        return {
            "path_id": self.path_id, "entry": self.entry, "target": self.target,
            "score": self.score, "max_grs": self.max_grs,
            "blast_radius": self.blast_radius, "target_value": self.target_value,
            "enabler_qids": self.enabler_qids, "hosts": self.hosts,
            "length": self.length,
            "steps": [{
                "host": s.host, "zone": s.zone, "arrival_via_qid": s.arrival_via_qid,
                "arrival_technique": s.arrival_technique, "arrival_kind": s.arrival_kind,
                "arrival_rule_id": s.arrival_rule_id, "arrival_rel_id": s.arrival_rel_id,
                "exploit_qid": s.exploit_qid, "exploit_technique": s.exploit_technique,
                "grs": s.grs,
            } for s in self.steps],
        }

    def evidence_line(self) -> str:
        chain = " -> ".join(
            f"{s.host}(via {s.arrival_kind}"
            + (f" {s.arrival_rule_id}" if s.arrival_rule_id else "")
            + (f" {s.arrival_rel_id}" if s.arrival_rel_id else "")
            + (f" QID{s.arrival_via_qid}" if s.arrival_via_qid else "")
            + (f", exploit QID{s.exploit_qid}" if s.exploit_qid else "") + ")"
            for s in self.steps
        )
        return (f"{self.path_id}: INTERNET -> {chain} | target={self.target} "
                f"value={self.target_value} maxGRS={self.max_grs} blast={self.blast_radius}")


@dataclass
class HostNode:
    hostname: str
    vlan: str
    zone: str
    role: str
    trust: str = ""          # zone trust level (semantic, from the CMDB)
    criticality: str = ""    # asset criticality label (e.g. "Crown Jewel")
    team: str = ""
    max_grs: float = 0.0
    acw: float = 0.0
    dora_cif: bool = False
    is_entry: bool = False
    is_crown_jewel: bool = False
    target_value: float = 0.0
    caps: list[Capability] = field(default_factory=list)
    qids: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Model construction
# ---------------------------------------------------------------------------

def _resolve_host(name: str, assets: dict[str, str]) -> str | None:
    """Map a finding's Hostname to a canonical asset. Boundary/policy pseudo-hosts
    (e.g. 'VPN-GW01 policy', 'Finance/Trading Critical Zone') resolve to their
    underlying asset when possible, else None (they still contribute edges)."""
    n = str(name).strip()
    if n in assets:
        return n
    # strip trailing qualifiers like " policy", " (VLAN ...)"
    base = re.split(r"\s+(?:policy|inter|zone)\b", n, flags=re.I)[0].strip()
    if base in assets:
        return base
    for h in assets:
        if h and (h.lower() == base.lower() or base.lower().startswith(h.lower())):
            return h
    return None


class _Resolver:
    """Host-reference resolver. For a CSV-backed CMDB (`cmdb.structured` present)
    every host reference is a real `ci_id` or the CI's exact `name`, so resolution
    is an exact dict lookup — no fuzzy `endswith`/substring guessing that can attach
    an edge to the wrong host (docs/cmdb-accuracy-brief.md §2.4). For a markdown
    dataset there are no ci_ids, so it degrades to the legacy fuzzy `_resolve_host`,
    keeping those datasets byte-identical."""

    def __init__(self, cmdb, asset_names: set[str]):
        self.asset_names = asset_names
        self._fuzzy = {h: h for h in asset_names}
        self.exact = cmdb is not None and getattr(cmdb, "structured", None) is not None
        self.by_id: dict[str, str] = {}
        if self.exact:
            for ci in cmdb.structured.cis:
                if ci.name in asset_names:
                    self.by_id[ci.ci_id] = ci.name

    def resolve(self, ref: str) -> str | None:
        n = str(ref).strip().strip("`")
        if not n:
            return None
        if n in self.asset_names:            # exact name (both modes)
            return n
        if self.exact:
            return self.by_id.get(n)         # exact ci_id — no fuzzy fallback
        return _resolve_host(n, self._fuzzy)  # markdown fallback


def build_host_nodes(df: pd.DataFrame, cmdb: CMDB,
                     caps: dict[int, Capability]) -> dict[str, HostNode]:
    zone_by_vlan = {z.vlan: z.name for z in cmdb.zones}
    trust_by_vlan = {z.vlan: z.trust_level for z in cmdb.zones}
    trust_by_name = {z.name: z.trust_level for z in cmdb.zones}
    nodes: dict[str, HostNode] = {}
    for a in cmdb.assets:
        nodes[a.hostname] = HostNode(
            hostname=a.hostname, vlan=str(a.vlan),
            zone=a.zone_name or zone_by_vlan.get(str(a.vlan), a.zone_name),
            role=a.role,
            trust=trust_by_vlan.get(str(a.vlan)) or trust_by_name.get(a.zone_name, ""),
            criticality=a.notable_issue or "",
        )
    asset_names = set(nodes)
    resolver = _Resolver(cmdb, asset_names)

    for _, row in df.iterrows():
        qid = int(row["QID"])
        # For a CSV CMDB prefer the finding's structured CI_ID (exact) over its
        # free-text Hostname; markdown datasets have no ci_ids, so resolve by
        # Hostname exactly as before (no behaviour change for them).
        host = (resolver.resolve(row.get("CI_ID", "")) if resolver.exact else None) \
            or resolver.resolve(row["Hostname"])
        cap = caps.get(qid)
        if host is None or host not in nodes:
            continue
        n = nodes[host]
        n.qids.append(qid)
        if cap:
            n.caps.append(cap)
        n.max_grs = max(n.max_grs, float(row["GRS"]))
        n.acw = max(n.acw, float(row.get("ACW", 0.0)))
        n.dora_cif = n.dora_cif or bool(row.get("DORA_CIF", False))
        n.team = n.team or str(row.get("Responsible_Team", ""))
        if cap and cap.is_entry:
            n.is_entry = True

    # crown-jewel + target-value scoring (independent of any documented path):
    # derived from CMDB trust level + asset criticality label + business-impact
    # signals, NOT from a hardcoded VLAN set — so it generalises to any environment.
    for n in nodes.values():
        data_impact = any(IMPACT in c.effects for c in n.caps)
        critical_zone = zone_is_critical(n.trust)
        crown_label = criticality_is_crown(n.criticality)
        n.is_crown_jewel = (
            critical_zone or crown_label or n.dora_cif or n.acw >= CROWN_ACW_THRESHOLD
            or (data_impact and re.search(r"database|file server|backup|rds|settlement|swift",
                                          f"{n.role} {n.hostname}", re.I) is not None)
        )
        base = max(n.acw, 0.9 if critical_zone else 0.0,
                   0.9 if crown_label else 0.0, 0.85 if n.dora_cif else 0.0)
        n.target_value = round(min(1.0, base + (0.1 if data_impact else 0.0)), 3)
    return nodes


def build_graph(df: pd.DataFrame, cmdb: CMDB,
                caps: dict[int, Capability]) -> tuple[nx.DiGraph, dict[str, HostNode]]:
    nodes = build_host_nodes(df, cmdb, caps)
    g = nx.DiGraph()
    g.add_node(INTERNET, kind="internet")
    for h, n in nodes.items():
        g.add_node(h, **{"vlan": n.vlan, "zone": n.zone, "max_grs": n.max_grs,
                          "crown": n.is_crown_jewel, "value": n.target_value})

    hosts_in_vlan: dict[str, list[str]] = {}
    for h, n in nodes.items():
        hosts_in_vlan.setdefault(n.vlan, []).append(h)
    vlan_of = {h: n.vlan for h, n in nodes.items()}

    # Phase 3 veto: the (src_vlan, dst_vlan) pairs the CMDB marks Should-Not-Exist.
    # Symmetric — a forbidden boundary must not be crossed in either direction — and
    # applied to EVERY edge kind below (docs/cmdb-accuracy-brief.md §4). Empty for
    # markdown datasets (no reachability_edges), so the veto no-ops there.
    blocked_pairs: set[frozenset[str]] = {
        frozenset({e["src_vlan"], e["dst_vlan"]})
        for e in getattr(cmdb, "reachability_edges", [])
        if e.get("status") == REACHABILITY_BLOCKED_STATUS
        and e.get("src_vlan") and e.get("dst_vlan")
    }

    def _blocked(a: str, b: str) -> bool:
        va, vb = vlan_of.get(a), vlan_of.get(b)
        return bool(va and vb and va != vb and frozenset({va, vb}) in blocked_pairs)

    def add_edge(a: str, b: str, kind: str, qid: int | None, tech: str,
                 rule_id: str = "", rel_id: str = ""):
        if a == b or a not in g or b not in g:
            return
        if _blocked(a, b):               # Should-Not-Exist veto — never crossed
            return
        existing = g.get_edge_data(a, b)
        if existing is not None:
            # Edge specificity, low→high: reachability (a generic network-rule
            # crossing) < lateral (a same-zone/dependency move) < a relationship or
            # identity pivot (segmentation/credential/domain/entry). A reachability
            # edge never overwrites an already-present edge; the specific enablers
            # never get overwritten by anything less specific.
            if kind == EDGE_KIND_REACHABILITY:
                return
            if existing.get("kind") in ("segmentation", "credential", "domain", "entry"):
                return
            # Upgrading a bare reachability edge to an identity/relationship pivot:
            # carry over its authoritative rule_id so the network authority for the
            # crossing isn't lost when a domain/credential pivot lands on the pair.
            if existing.get("kind") == EDGE_KIND_REACHABILITY:
                rule_id = rule_id or existing.get("rule_id", "")
        g.add_edge(a, b, kind=kind, qid=qid, technique=tech,
                   rule_id=rule_id, rel_id=rel_id)

    asset_names = set(nodes)
    resolver = _Resolver(cmdb, asset_names)

    # (1) Entry edges: INTERNET -> host with an entry finding
    for h, n in nodes.items():
        if n.is_entry:
            ecap = next((c for c in n.caps if c.is_entry), None)
            add_edge(INTERNET, h, "entry", ecap.qid if ecap else None,
                     ecap.technique if ecap else "Internet-facing exposure")

    # (2) Same-zone lateral movement (flat L2 within a segment, incl. cloud tenant)
    for vlan, members in hosts_in_vlan.items():
        if vlan == "":
            continue
        for a in members:
            for b in members:
                if a != b:
                    add_edge(a, b, "lateral", None, f"Lateral movement within {nodes[a].zone}")

    # (2b) Architectural pivots from the §4 dependency relations — app→db, DB
    # links, hypervisor management, backup reach, and cloud identity — read
    # straight from the CMDB (each edge keeps its REL id + any enabling QID),
    # instead of being inferred from VLAN-tier numbering. Only the relationship
    # types an attacker can traverse become edges (see _DEP_EDGE_KIND); 'Depends
    # On' correctly links APP-CRM01→DB-CRM01 without connecting unrelated pairs.
    for dep in cmdb.dependency_edges:
        kind = _DEP_EDGE_KIND.get(dep["rtype"].lower())
        if not kind:
            continue
        src = resolver.resolve(dep["src_host"])
        tgt = resolver.resolve(dep["dst_host"])
        if src and tgt:
            add_edge(src, tgt, kind, dep.get("qid"), dep["label"],
                     rel_id=dep.get("rel_id", ""))

    # (2c) Authoritative zone-to-zone reachability (Phase 3). The CSV CMDB's
    # net_reachability.csv IS the reachability graph: every Intended/Excessive rule
    # becomes directed edges from each host in the source segment to each host in
    # the destination segment, carrying its rule_id + enabling_qid, so every
    # cross-zone NETWORK hop is authoritative (docs/cmdb-accuracy-brief.md §2.1).
    # Should-Not-Exist rules never reach here — they seeded `blocked_pairs` above and
    # are vetoed inside add_edge. INET-source rules no-op (no hosts in the internet
    # segment; entry stays finding-driven in step 1). Empty for markdown datasets.
    has_reach_rules = bool(getattr(cmdb, "reachability_edges", []))
    # When two traversable rules connect the same segment pair (e.g. the intended
    # tcp/8443 rule AND the Excessive ANY/ANY misconfiguration replacing it), stamp
    # the finding-backed one — that's the boundary an attacker actually abuses and
    # the QID an analyst reports — so order rules carrying an enabling_qid first.
    traversable_rules = sorted(
        (e for e in getattr(cmdb, "reachability_edges", [])
         if e.get("status") in REACHABILITY_TRAVERSABLE_STATUSES),
        key=lambda e: e.get("enabling_qid") is None)
    for e in traversable_rules:
        src_v, dst_v = e.get("src_vlan", ""), e.get("dst_vlan", "")
        if not src_v or not dst_v or src_v == dst_v:
            continue
        eqid = e.get("enabling_qid")
        tech = (f"Reachability {e['rule_id']} ({e.get('status')})"
                + (f": {e['notes']}" if e.get("notes") else ""))
        for a in hosts_in_vlan.get(src_v, []):
            for b in hosts_in_vlan.get(dst_v, []):
                add_edge(a, b, EDGE_KIND_REACHABILITY, eqid, tech, rule_id=e["rule_id"])

    # (3) Segmentation breaks: a finding opens a boundary between two VLANs.
    # The explicit host→host pivots (e.g. a DB link naming its target) are always
    # honoured — they are relationship-grounded, non-network moves. The VLAN-number
    # `zone_transition` INFERENCE, however, is exactly the un-authoritative crossing
    # the reachability rule base replaces: when the CMDB ships those rules we do NOT
    # infer zone edges from VLAN numbering (step 2c is the source of truth); we keep
    # the inference only for markdown datasets that carry no reachability rules.
    for _, row in df.iterrows():
        cap = caps.get(int(row["QID"]))
        if not cap or SEGMENTATION_BREAK not in cap.effects:
            continue
        # explicit host->host pivot (e.g. DB link)
        for tgt in cap.host_pivots:
            th = resolver.resolve(tgt)
            src = resolver.resolve(cap.hostname)
            if th and src:
                add_edge(src, th, "segmentation", cap.qid, cap.technique)
        if cap.zone_transition and not has_reach_rules:
            src_v, dst_v = cap.zone_transition
            for a in hosts_in_vlan.get(src_v, []):
                for b in hosts_in_vlan.get(dst_v, []):
                    add_edge(a, b, "segmentation", cap.qid, cap.technique)

    # (4) Credential reuse: shared local creds link the named hosts (symmetric)
    for _, row in df.iterrows():
        cap = caps.get(int(row["QID"]))
        if not cap or CREDENTIAL_THEFT not in cap.effects or not cap.host_pivots:
            continue
        src = resolver.resolve(cap.hostname)
        for tgt in cap.host_pivots:
            th = resolver.resolve(tgt)
            if src and th:
                add_edge(src, th, "credential", cap.qid, cap.technique)
                add_edge(th, src, "credential", cap.qid, cap.technique)

    # (5) Domain Admin: a DA-yielding finding reaches every AD-joined host. AD
    # membership is derived from platform (Windows) sitting in an internal-trust
    # zone, plus any host with an explicit 'Authenticates To' (domain join)
    # relation — not from a hardcoded VLAN set.
    ad_joined = {e["src_host"] for e in cmdb.dependency_edges
                 if "authenticates to" in e["rtype"].lower()}
    domain_hosts = [h for h, n in nodes.items()
                    if (platform_is_ad_joined(n.role) and zone_is_internal(n.trust))
                    or h in ad_joined]
    for _, row in df.iterrows():
        cap = caps.get(int(row["QID"]))
        if not cap or GRANT_DOMAIN_ADMIN not in cap.grants:
            continue
        src = resolver.resolve(cap.hostname)
        if not src:
            continue
        for h in domain_hosts:
            add_edge(src, h, "domain", cap.qid, f"{cap.technique} → Domain Admin reach")
    return g, nodes


# ---------------------------------------------------------------------------
# Path enumeration + scoring
# ---------------------------------------------------------------------------

def _best_exploit(node: HostNode) -> Capability | None:
    if not node.caps:
        return None
    priority = ["rce_system", "privilege_escalation", "cloud_priv_esc", "rce_user",
                "credential_theft", "impact", "segmentation_break"]
    def rank(c: Capability) -> int:
        return min((priority.index(e) for e in c.effects if e in priority), default=99)
    return sorted(node.caps, key=lambda c: (rank(c), -c.qid))[0]


def _path_to_steps(path: list[str], g: nx.DiGraph, nodes: dict[str, HostNode],
                   df_by_qid: dict[int, pd.Series]) -> list[Step]:
    steps: list[Step] = []
    for prev, host in zip(path, path[1:]):
        if host == INTERNET:
            continue
        n = nodes[host]
        ed = g[prev][host]
        exploit = _best_exploit(n)
        grs = 0.0
        if exploit and exploit.qid in df_by_qid:
            grs = float(df_by_qid[exploit.qid]["GRS"])
        if ed.get("qid") in df_by_qid:
            grs = max(grs, float(df_by_qid[ed["qid"]]["GRS"]))
        steps.append(Step(
            host=host, zone=n.zone,
            arrival_via_qid=ed.get("qid"), arrival_technique=ed.get("technique", ""),
            arrival_kind=ed.get("kind", "lateral"),
            arrival_rule_id=ed.get("rule_id", ""), arrival_rel_id=ed.get("rel_id", ""),
            exploit_qid=exploit.qid if exploit else None,
            exploit_technique=exploit.technique if exploit else "",
            grs=round(grs, 1),
        ))
    return steps


def discover_paths(df: pd.DataFrame, cmdb: CMDB, caps: dict[int, Capability],
                   max_len: int = 8, k_per_pair: int = 2,
                   top_n: int | None = None) -> tuple[list[DiscoveredPath], nx.DiGraph, dict[str, HostNode]]:
    """Enumerate every distinct entry→crown-jewel attack path the reachability
    graph supports; how many there are is a property of the data, never a fixed
    number. `top_n` is left None so the full set surfaces — pass an int only if a
    caller explicitly wants the ranked list trimmed for display."""
    g, nodes = build_graph(df, cmdb, caps)
    df_by_qid = {int(r["QID"]): r for _, r in df.iterrows()}
    targets = [h for h, n in nodes.items() if n.is_crown_jewel and g.in_degree(h) > 0]

    def _traversable(path: list[str]) -> bool:
        """Every intermediate host must be compromisable — it either carries a
        finding of its own, or is reached by a specific enabler edge (segmentation
        / credential / domain). This prunes transit through empty baseline hosts."""
        for prev, host in zip(path, path[1:]):
            if host == INTERNET:
                continue
            has_finding = bool(nodes[host].qids)
            enabled = g[prev][host].get("qid") is not None or g[prev][host].get("kind") == "entry"
            if not has_finding and not enabled and host != path[-1]:
                return False
        return True

    raw: list[DiscoveredPath] = []
    for tgt in targets:
        try:
            gen = nx.shortest_simple_paths(g, INTERNET, tgt)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        taken = 0
        try:
            for path in gen:
                if len(path) - 1 > max_len:
                    break
                if taken >= k_per_pair:
                    break
                if not _traversable(path):
                    continue
                entry = path[1] if len(path) > 1 else tgt
                steps = _path_to_steps(path, g, nodes, df_by_qid)
                if not steps:
                    continue
                enabler_qids = sorted({s.arrival_via_qid for s in steps if s.arrival_via_qid}
                                      | {s.exploit_qid for s in steps if s.exploit_qid})
                crown_hits = sum(1 for s in steps if nodes[s.host].is_crown_jewel)
                max_grs = max((s.grs for s in steps), default=0.0)
                dp = DiscoveredPath(
                    path_id="", entry=entry, target=tgt, steps=steps,
                    max_grs=max_grs, blast_radius=crown_hits,
                    target_value=nodes[tgt].target_value,
                    enabler_qids=enabler_qids, hosts=[s.host for s in steps],
                )
                dp.score = _score(dp, nodes)
                raw.append(dp)
                taken += 1
        except nx.NetworkXNoPath:
            # shortest_simple_paths is a generator: NetworkXNoPath can surface
            # lazily on the first next() rather than at construction (e.g. a
            # target auto-promoted to crown-jewel by ACW/AD-join heuristics
            # that sits in a component INTERNET never reaches) — no path for
            # this target, not a fatal error for the whole discovery run.
            continue

    # dedupe by (entry, target): keep the highest-scoring representative
    best: dict[tuple[str, str], DiscoveredPath] = {}
    for dp in raw:
        key = (dp.entry, dp.target)
        if key not in best or dp.score > best[key].score:
            best[key] = dp
    candidates = sorted(best.values(), key=lambda d: d.score, reverse=True)

    # Diversify: guarantee each crown-jewel target is represented by its best
    # path before filling remaining slots by score, so distinct objectives (file
    # server, CRM DB, cloud RDS, backups, SWIFT…) all surface — not just the
    # highest-GRS one.
    ranked: list[DiscoveredPath] = []
    used_targets: set[str] = set()
    for dp in candidates:
        if dp.target not in used_targets:
            ranked.append(dp)
            used_targets.add(dp.target)
    for dp in candidates:
        if top_n is not None and len(ranked) >= top_n:
            break
        if dp not in ranked:
            ranked.append(dp)
    if top_n is not None:
        ranked = ranked[:top_n]
    ranked = sorted(ranked, key=lambda d: d.score, reverse=True)
    for i, dp in enumerate(ranked, 1):
        dp.path_id = f"DISC-{i:02d}"
    return ranked, g, nodes


def _score(dp: DiscoveredPath, nodes: dict[str, HostNode]) -> float:
    # Weights are config-driven (core.config.DISC_SCORE_*); defaults reproduce the
    # historical ordering exactly, so this token-free deterministic ranking — and the
    # committed eval baseline built from it — is unchanged.
    length_penalty = max(0, dp.length - DISC_SCORE_IDEAL_HOPS) * DISC_SCORE_LENGTH_PENALTY
    return round(
        dp.target_value * DISC_SCORE_TARGET_VALUE_W
        + dp.max_grs * DISC_SCORE_GRS_W
        + dp.blast_radius * DISC_SCORE_BLAST_W
        - length_penalty, 2
    )
