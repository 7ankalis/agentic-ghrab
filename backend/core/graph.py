"""
Reconstructs the *documented* attack-path chains (PATH-A..F) from the held-out
verification oracle (core/oracle.py), for the "discovered vs ground-truth"
overlay and the rediscovery acceptance test — NOT for detection.

The oracle maps each finding's QID to its documented position (e.g.
"PATH-E-Step3"); consecutive steps within the same path become directed edges.
This never touches the ingested data the engine/agents reason over, so it can't
leak the answer key into detection — it exists purely so an operator (or the
test suite) can check the engine's independently-discovered paths against the
known ones. Standalone findings get no chain edges.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

from core.oracle import attack_path_refs


@dataclass
class ChainStep:
    step_num: int
    qid: int
    title: str
    hostname: str
    grs: float
    team: str


@dataclass
class Chain:
    path_id: str
    steps: list[ChainStep] = field(default_factory=list)

    @property
    def max_grs(self) -> float:
        return max((s.grs for s in self.steps), default=0.0)

    @property
    def entry_point(self) -> str:
        return self.steps[0].hostname if self.steps else ""

    @property
    def target(self) -> str:
        return self.steps[-1].hostname if self.steps else ""


def _parse_ref(ref: str) -> tuple[str, int] | None:
    m = re.match(r"(PATH-[A-Z])-Step(\d+)", str(ref).strip())
    if not m:
        return None
    return m.group(1), int(m.group(2))


def build_chains(df: pd.DataFrame, dataset_key: str | None = None) -> list[Chain]:
    """Documented chains for the active (or given) dataset, sourced from the
    held-out oracle keyed by QID — never from any ingested column."""
    refs = attack_path_refs(dataset_key)
    grouped: dict[str, list[ChainStep]] = {}
    for _, row in df.iterrows():
        parsed = _parse_ref(refs.get(int(row["QID"]), ""))
        if not parsed:
            continue
        path_id, step_num = parsed
        grouped.setdefault(path_id, []).append(ChainStep(
            step_num=step_num, qid=int(row["QID"]), title=row["Title"],
            hostname=row["Hostname"], grs=float(row["GRS"]),
            team=row["Responsible_Team"],
        ))
    chains = []
    for path_id, steps in sorted(grouped.items()):
        steps.sort(key=lambda s: s.step_num)
        chains.append(Chain(path_id=path_id, steps=steps))
    return chains


def build_asset_graph(df: pd.DataFrame) -> nx.DiGraph:
    """Directed graph: asset nodes + chain edges (attacker pivot direction)."""
    g = nx.DiGraph()
    for _, row in df.iterrows():
        host = row["Hostname"]
        if host not in g:
            g.add_node(host, zone=row.get("Zone", ""), team=row.get("Responsible_Team", ""),
                       max_grs=float(row["GRS"]))
        else:
            g.nodes[host]["max_grs"] = max(g.nodes[host]["max_grs"], float(row["GRS"]))

    for chain in build_chains(df):
        for a, b in zip(chain.steps, chain.steps[1:]):
            g.add_edge(a.hostname, b.hostname, path_id=chain.path_id,
                       via_qid=a.qid, label=f"{chain.path_id} step {a.step_num}→{b.step_num}")
    return g
