"""
Phase 1 loader + validation tests (docs/cmdb-accuracy-brief.md §1, acceptance §5).

Covers the CSV-backed relational CMDB:
  * the `acmebank` dataset is discovered and loads through the SAME in-memory CMDB
    interface the markdown datasets use (interface stayed stable while the format
    changed underneath);
  * referential-integrity validation FAILS LOUD — it reports exactly the three
    deliberately-seeded data-quality defects and nothing spurious;
  * the held-out oracle never enters the CMDB (no attack paths are loaded);
  * ghrab/velon/elihowa are now ALSO CSV-backed (converted from their markdown to
    the same relational tables), so they too get structured reachability + the
    Phase-4 tools; the legacy markdown parser stays exercised via the flat docs that
    remain on disk as a rendering/fallback.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import pytest  # noqa: E402

from core import cmdb_store, datasets  # noqa: E402
from core.cmdb import CMDB, reset_cmdb  # noqa: E402

CMDB_DIR = Path(__file__).resolve().parent.parent / "data" / "acmebank" / "cmdb"
VULN_CSV = CMDB_DIR.parent / "vulnerabilities.csv"


@pytest.fixture(scope="module")
def acme():
    s = cmdb_store.load_structured(CMDB_DIR)
    rep = cmdb_store.validate(s, "acmebank")
    cmdb_store.validate_findings(rep, s, VULN_CSV)
    return s, rep


# --- discovery ---------------------------------------------------------------

def test_acmebank_is_discovered_as_csv_dataset():
    ds = {d.key: d for d in datasets.discover()}
    assert "acmebank" in ds, "acmebank CSV dataset was not discovered"
    d = ds["acmebank"]
    assert d.cmdb_dir is not None and d.cmdb_dir.is_dir()
    assert d.architecture_md is None          # CSV-backed, no markdown doc
    assert d.has_architecture is True         # but it does have a CMDB to ground on
    assert d.findings > 0


# --- fail-loud validation: exactly the seeded defects ------------------------

def test_seeded_defects_are_all_reported(acme):
    _, rep = acme
    assert rep.ok is False
    kinds = {d["kind"] for d in rep.defects}
    assert kinds == {"dangling_ref", "orphan_ci", "finding_without_ci"}, (
        f"expected exactly the three seeded defect kinds, got {kinds}")


def test_dangling_reference_is_caught(acme):
    _, rep = acme
    assert len(rep.dangling_refs) == 1
    assert "SRV-AB-9999" in rep.dangling_refs[0]["detail"]


def test_orphan_ci_is_caught(acme):
    _, rep = acme
    assert len(rep.orphan_cis) == 1
    assert rep.orphan_cis[0]["ref"] == "SRV-AB-1092"


def test_finding_without_ci_is_caught(acme):
    _, rep = acme
    assert len(rep.findings_without_ci) == 1
    assert str(rep.findings_without_ci[0]["ref"]) == "999001"


def test_no_spurious_defects(acme):
    """Everything else must be clean — otherwise the validator is noisy and the
    'clean except seeded defects' acceptance criterion is meaningless."""
    _, rep = acme
    assert rep.zones_without_rules == []      # every segment appears in a rule
    assert rep.duplicate_ci_ids == []
    assert rep.unknown_rel_types == []        # all rel_types are in the vocabulary


# --- interface stability: CSV loads through the legacy CMDB shape ------------

def test_csv_cmdb_populates_legacy_interface():
    reset_cmdb()
    cmdb = CMDB().load(path=CMDB_DIR)
    assert len(cmdb.zones) == 12
    assert len(cmdb.assets) >= 30
    assert cmdb.teams, "support groups did not project to teams"
    assert cmdb.dependency_edges, "no dependency edges projected for the graph"
    assert cmdb.reachability_rules, "reachability text grounding missing"
    assert cmdb.cred_relations, "credential relationships missing"
    # additive structured field the graph will consume in Phase 3
    assert cmdb.reachability_edges
    statuses = {e["status"] for e in cmdb.reachability_edges}
    assert {"Intended", "Excessive", "Should-Not-Exist"} <= statuses, (
        "the reachability base must carry all three statuses, incl. Should-Not-Exist")
    # grounding must exceed the old 7 KB truncation ceiling (realistic scale)
    assert len(cmdb.grounding_context(10 ** 9)) > 7000


def test_oracle_never_enters_the_cmdb():
    """The held-out oracle/attack_paths.md must not be loaded by the CMDB — the
    engine rediscovers paths; it never reads the answer key."""
    reset_cmdb()
    cmdb = CMDB().load(path=CMDB_DIR)
    assert cmdb.attack_paths == [], "attack paths leaked into the CSV-loaded CMDB"


def test_validation_report_stored_on_instance():
    reset_cmdb()
    cmdb = CMDB().load(path=CMDB_DIR)
    assert cmdb.validation_report is not None
    assert cmdb.validation_report.dataset == "acmebank"
    assert cmdb.structured is not None


# --- ghrab/velon/elihowa are now CSV-backed too ------------------------------

@pytest.mark.parametrize("key", ["ghrab", "velon", "elihowa"])
def test_converted_datasets_are_csv_backed(key):
    """The former markdown datasets now load through the relational CSV path, so
    they get structured reachability (Phase 3) + a validation report + the Phase-4
    tools, exactly like acmebank. Their flat markdown is superseded but not deleted."""
    ds = {d.key: d for d in datasets.discover()}[key]
    assert ds.cmdb_dir is not None and ds.architecture_md is None, (
        f"{key} should be discovered as a CSV-backed dataset")

    datasets.set_active(key)
    reset_cmdb()
    cmdb = CMDB().load()
    assert cmdb.zones and cmdb.assets, f"{key} CSV CMDB failed to load"
    assert cmdb.structured is not None, f"{key} did not build structured records"
    assert cmdb.reachability_edges, f"{key} must populate structured reachability edges"
    statuses = {e["status"] for e in cmdb.reachability_edges}
    assert "Should-Not-Exist" in statuses, f"{key} lost its Should-Not-Exist veto rows"
    rep = cmdb_store.validate_active()
    assert rep is not None and rep.dataset == key
    # authoritative datasets: no dangling/dup/unknown-rel/finding-without-CI defects
    # (orphan CIs — assets with no modeled relationship — are legitimately reported).
    assert rep.dangling_refs == [] and rep.duplicate_ci_ids == []
    assert rep.unknown_rel_types == [] and rep.findings_without_ci == []


@pytest.mark.parametrize("key", ["ghrab", "velon", "elihowa"])
def test_legacy_markdown_parser_still_works(key):
    """The markdown parser is kept as a fallback for any dataset without a CSV dir;
    load the flat architecture doc directly (bypassing discovery) to prove it still
    parses the CI-format tables and never regressed."""
    from core.config import DATA_DIR
    md = DATA_DIR / f"{key}_architecture.md"
    reset_cmdb()
    cmdb = CMDB().load(path=md)
    assert cmdb.zones and cmdb.assets, f"{key} markdown parser regressed"
    assert cmdb.reachability_edges == [], "markdown path must not fake structured edges"
