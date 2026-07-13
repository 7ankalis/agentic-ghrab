"""Regression test against the real Ghrab dataset (docs/sample_data/), as
opposed to test_agent1.py's synthetic fixtures. Skips cleanly if the files
haven't been dropped in yet, so the rest of the suite doesn't depend on them.
"""

from pathlib import Path

import pytest

from vmc.agents.ingest import run_agent1

SAMPLE_DATA_DIR = Path(__file__).parent.parent / "docs" / "sample_data"
CSV_PATH = SAMPLE_DATA_DIR / "ghrab_vulnerabilities.csv"
MD_PATH = SAMPLE_DATA_DIR / "ghrab_architecture.md"

pytestmark = pytest.mark.skipif(
    not (CSV_PATH.exists() and MD_PATH.exists()),
    reason="docs/sample_data/ghrab_vulnerabilities.csv / ghrab_architecture.md not present",
)


def test_run_agent1_ingests_all_32_findings_with_no_unparseable_rows():
    findings, assets, teams, topology, issues = run_agent1(CSV_PATH, MD_PATH)

    assert len(findings) == 32
    assert not [i for i in issues if i.issue_type == "unparseable_row"]

    zerologon = next(f for f in findings if f.cve_id == "CVE-2020-1472")
    assert zerologon.cvss_score == 10.0
    assert zerologon.asset_hostname == "DC01"

    flat_trust = next(f for f in findings if "Flat Trust" in f.title)
    assert flat_trust.cve_id is None  # misconfiguration, not a CVE


def test_run_agent1_resolves_zones_for_most_findings():
    findings, assets, teams, topology, issues = run_agent1(CSV_PATH, MD_PATH)

    assert len(topology.zones) >= 9  # VLANs 10/20/21/30/40/50/60/70/80 + Cloud
    orphaned = [i for i in issues if i.issue_type == "orphaned_ip"]
    # zone resolution is VLAN-ID-based with a name-fallback; a few loosely
    # worded Zone labels in the raw CSV may still not resolve, but the bulk
    # of 32 findings should.
    assert len(orphaned) < len(findings) / 2
