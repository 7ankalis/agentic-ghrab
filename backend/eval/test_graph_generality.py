"""
Phase 2 generality test. The reachability graph must derive its tiers (entry
zones, crown jewels, domain reach, app→db pivots) from the CMDB's semantic trust
levels, criticality labels, platforms, and §4 relations — NOT from hardcoded VLAN
numbers. This runs the engine against a synthetic environment whose VLAN numbering
(100/200/400) is deliberately unlike the shipped datasets (10/20/40) and asserts a
correct internet→crown-jewel path is still found.

The fixture lives under eval/fixtures/ and is loaded explicitly (never registered
as a selectable dataset), so it exercises the engine without touching the app.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import networkx as nx  # noqa: E402
import pytest  # noqa: E402

from core.attack_graph import INTERNET, discover_paths  # noqa: E402
from core.capability import classify_all  # noqa: E402
from core.cmdb import CMDB  # noqa: E402
from core.ingestion import load_vulnerabilities  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def synthetic():
    cmdb = CMDB().load(path=FIXTURES / "acme_architecture.md")
    df = load_vulnerabilities(path=FIXTURES / "acme_vulnerabilities.csv")
    caps = classify_all(df)
    paths, g, nodes = discover_paths(df, cmdb, caps)
    return cmdb, df, paths, g, nodes


def test_novel_vlan_numbering_is_not_10_20_40(synthetic):
    _, _, _, _, nodes = synthetic
    vlans = {n.vlan for n in nodes.values()}
    assert vlans == {"200", "100", "400"}, (
        "fixture should use novel VLAN numbering to prove the graph isn't keyed to "
        "the shipped datasets' 10/20/40")


def test_crown_jewel_derived_from_trust_and_criticality(synthetic):
    _, _, _, _, nodes = synthetic
    crowns = [h for h, n in nodes.items() if n.is_crown_jewel]
    # VAULT01 sits in VLAN 400 (Critical trust) and is labelled Crown Jewel — the
    # old hardcoded CROWN_VLANS={"40"} would never have caught VLAN 400.
    assert crowns == ["VAULT01"]
    assert nodes["VAULT01"].vlan == "400"


def test_entry_point_derived_from_exposure(synthetic):
    _, _, _, _, nodes = synthetic
    assert nodes["WEBEDGE01"].is_entry
    assert not nodes["VAULT01"].is_entry


def test_internet_to_crown_path_is_found(synthetic):
    _, _, paths, g, _ = synthetic
    assert nx.has_path(g, INTERNET, "VAULT01")
    to_vault = [p for p in paths if p.target == "VAULT01"]
    assert to_vault, "engine found no internet→crown path on novel VLAN numbering"
    path = to_vault[0]
    assert path.hosts == ["WEBEDGE01", "APPX01", "VAULT01"]
    # the app→db-style pivot came from the §4 'Depends On' relation (QID 500004),
    # not from a VLAN-tier assumption
    assert 500004 in path.enabler_qids


def test_every_hop_is_graph_verifiable(synthetic):
    _, _, paths, g, _ = synthetic
    for p in paths:
        walk = [INTERNET] + p.hosts
        for a, b in zip(walk, walk[1:]):
            assert g.has_edge(a, b), f"unsound hop {a}->{b} in {p.path_id}"
