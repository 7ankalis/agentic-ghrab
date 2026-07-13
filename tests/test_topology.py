from pathlib import Path

from vmc.agents.ingest import run_agent1
from vmc.agents.topology import ADJACENT, INTERNAL, INTERNET_FACING, ISOLATED, RESTRICTED, run_agent2

SAMPLE_DATA = Path(__file__).parent.parent / "docs" / "sample_data"
FINDINGS_CSV = SAMPLE_DATA / "ghrab_vulnerabilities.csv"
ARCHITECTURE_MD = SAMPLE_DATA / "ghrab_architecture.md"


def _load():
    findings, assets, teams, topology, _ = run_agent1(FINDINGS_CSV, ARCHITECTURE_MD)
    topology, assets, segmentation_findings = run_agent2(findings, assets, topology)
    return findings, assets, topology, segmentation_findings


def test_exposure_tiers_match_methodology_examples():
    _, _, topology, _ = _load()
    zone_by_name = {z.name: z for z in topology.zones.values()}

    assert zone_by_name["DMZ"].exposure_tier == INTERNET_FACING
    assert zone_by_name["Guest WiFi"].exposure_tier == ADJACENT
    assert zone_by_name["Corporate LAN"].exposure_tier == INTERNAL
    assert zone_by_name["DB Tier"].exposure_tier == RESTRICTED
    assert zone_by_name["Management / Out-of-Band"].exposure_tier == ISOLATED


def test_crown_jewel_assets_get_full_acw():
    _, assets, _, _ = _load()
    # SETTLEMENT01 is only ever referenced as an attack-path pivot target
    # (architecture.md §5), never a CSV finding row of its own, so it's not
    # an Asset — Agent 1 only materializes assets that own a finding.
    for hostname in ("DC01", "TRADE-CORE01", "SWIFT-GATEWAY01"):
        asset = assets[hostname]
        assert asset.acw == 1.0, hostname


def test_segmentation_findings_flag_known_broken_boundaries():
    _, _, _, segmentation_findings = _load()
    flagged_ids = {sf.finding_id for sf in segmentation_findings}
    assert len(flagged_ids) >= 1
    assert all(sf.health == "Red" for sf in segmentation_findings)
