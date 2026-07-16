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

INTERNET = "INTERNET"
DOMAIN_VLANS = {"10", "40", "50"}   # Windows/AD-joined segments a Domain Admin can reach
CROWN_VLANS = {"40"}                 # Finance/Trading CDE + SWIFT scope


@dataclass
class Step:
    host: str
    zone: str
    arrival_via_qid: int | None       # finding that let the attacker reach this host
    arrival_technique: str
    arrival_kind: str                 # entry | segmentation | credential | lateral | domain
    exploit_qid: int | None           # finding compromised ON this host
    exploit_technique: str
    grs: float


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
                "exploit_qid": s.exploit_qid, "exploit_technique": s.exploit_technique,
                "grs": s.grs,
            } for s in self.steps],
        }

    def evidence_line(self) -> str:
        chain = " -> ".join(
            f"{s.host}(via {s.arrival_kind}"
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


def _tier_key(hostname: str) -> str:
    """Business-function token from an APP-*/DB-* hostname, e.g. 'APP-CRM01' -> 'CRM'."""
    m = re.match(r"(?:APP|DB)-([A-Z]+)\d*$", hostname, re.I)
    return m.group(1).upper() if m else hostname.upper()


def build_host_nodes(df: pd.DataFrame, cmdb: CMDB,
                     caps: dict[int, Capability]) -> dict[str, HostNode]:
    zone_by_vlan = {z.vlan: z.name for z in cmdb.zones}
    nodes: dict[str, HostNode] = {}
    for a in cmdb.assets:
        nodes[a.hostname] = HostNode(
            hostname=a.hostname, vlan=str(a.vlan),
            zone=a.zone_name or zone_by_vlan.get(str(a.vlan), a.zone_name),
            role=a.role,
        )
    asset_names = set(nodes)

    for _, row in df.iterrows():
        qid = int(row["QID"])
        host = _resolve_host(row["Hostname"], {h: h for h in asset_names})
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

    # crown-jewel + target-value scoring (independent of any documented path)
    for n in nodes.values():
        data_impact = any(IMPACT in c.effects for c in n.caps)
        n.is_crown_jewel = (
            n.vlan in CROWN_VLANS or n.dora_cif or n.acw >= 0.88
            or (data_impact and re.search(r"database|file server|backup|rds|settlement|swift",
                                          f"{n.role} {n.hostname}", re.I) is not None)
        )
        base = max(n.acw, 0.9 if n.vlan in CROWN_VLANS else 0.0, 0.85 if n.dora_cif else 0.0)
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

    def add_edge(a: str, b: str, kind: str, qid: int | None, tech: str):
        if a == b or a not in g or b not in g:
            return
        # keep the most "specific" enabler if an edge already exists
        if g.has_edge(a, b) and g[a][b].get("kind") in ("segmentation", "credential", "domain", "entry"):
            return
        g.add_edge(a, b, kind=kind, qid=qid, technique=tech)

    asset_names = set(nodes)
    resolver = {h: h for h in asset_names}

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

    # (2b) Base tier adjacency: an app server can reach ITS OWN database, not the
    # whole db tier — APP-CRM01 talks to DB-CRM01, not DB-TRADE01, even though both
    # pairs sit in the same VLANs. Match by the business-function token in the
    # hostname (CRM, TRADE, ...) so unrelated app/db pairs stay disconnected and
    # noise hosts like APP-HR01 (no matching DB) don't get a fabricated edge.
    app_hosts = hosts_in_vlan.get("21", [])
    db_hosts = hosts_in_vlan.get("30", [])
    for a in app_hosts:
        for b in db_hosts:
            if _tier_key(a) == _tier_key(b):
                add_edge(a, b, "lateral", None, "Application-tier → database-tier connectivity")

    # (3) Segmentation breaks: a finding opens a boundary between two VLANs
    for _, row in df.iterrows():
        cap = caps.get(int(row["QID"]))
        if not cap or SEGMENTATION_BREAK not in cap.effects:
            continue
        # explicit host->host pivot (e.g. DB link)
        for tgt in cap.host_pivots:
            th = _resolve_host(tgt, resolver)
            src = _resolve_host(cap.hostname, resolver)
            if th and src:
                add_edge(src, th, "segmentation", cap.qid, cap.technique)
        if cap.zone_transition:
            src_v, dst_v = cap.zone_transition
            for a in hosts_in_vlan.get(src_v, []):
                for b in hosts_in_vlan.get(dst_v, []):
                    add_edge(a, b, "segmentation", cap.qid, cap.technique)

    # (4) Credential reuse: shared local creds link the named hosts (symmetric)
    for _, row in df.iterrows():
        cap = caps.get(int(row["QID"]))
        if not cap or CREDENTIAL_THEFT not in cap.effects or not cap.host_pivots:
            continue
        src = _resolve_host(cap.hostname, resolver)
        for tgt in cap.host_pivots:
            th = _resolve_host(tgt, resolver)
            if src and th:
                add_edge(src, th, "credential", cap.qid, cap.technique)
                add_edge(th, src, "credential", cap.qid, cap.technique)

    # (5) Domain Admin: a DA-yielding finding reaches every AD-joined host
    domain_hosts = [h for h, n in nodes.items() if n.vlan in DOMAIN_VLANS]
    for _, row in df.iterrows():
        cap = caps.get(int(row["QID"]))
        if not cap or GRANT_DOMAIN_ADMIN not in cap.grants:
            continue
        src = _resolve_host(cap.hostname, resolver)
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
    length_penalty = max(0, dp.length - 2) * 3.0
    return round(
        dp.target_value * 45 + dp.max_grs * 0.45 + dp.blast_radius * 8 - length_penalty, 2
    )
