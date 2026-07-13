"""Golden-value regression tests: reproduce ghrab_risk_methodology.md §8's
own worked examples exactly, using the formula's own fully-specified inputs
(CVSS/EPSS/KEV/ACW/TCM/ExposureTier) rather than reverse-engineering them
from the real dataset."""

from datetime import datetime, timezone

from vmc.agents.risk_scoring import compute_grs
from vmc.models import Asset, Finding, NetworkGraph, NetworkZone, ThreatIntel

TOPOLOGY = NetworkGraph(
    zones={
        "isolated_zone": NetworkZone(zone_id="isolated_zone", name="Isolated Zone", exposure_tier=0.15),
        "internet_zone": NetworkZone(zone_id="internet_zone", name="Internet Zone", exposure_tier=1.30),
    }
)


def _finding(**overrides) -> Finding:
    defaults = dict(
        finding_id="F1",
        category="Missing Patch",
        title="t",
        severity_raw="Critical",
        asset_ip="1.1.1.1",
        asset_hostname="ASSET",
        zone="Isolated Zone",
        responsible_team="x",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_vulnerability_a_isolated_high_cvss_scores_low():
    """§8 Vulnerability A: CVSS 10, isolated, no exploitation -> GRS 6.6, TRACK."""
    finding = _finding(cvss_score=10.0, zone="Isolated Zone")
    asset = Asset(hostname="ASSET", ip="1.1.1.1", zone="Isolated Zone", owning_team="x", criticality_tier=1, acw=0.6)
    ti = ThreatIntel(cve_id="CVE-X", epss_score=0.02, in_kev=False, fetched_at=datetime.now(timezone.utc))

    assessment = compute_grs(finding, asset, ti, tcm=1.0, topology=TOPOLOGY)

    assert assessment.score == 6.6
    assert assessment.band == "TRACK"
    assert assessment.sla_days is None


def test_vulnerability_b_internet_facing_lower_cvss_scores_high():
    """§8 Vulnerability B: CVSS 7, internet-facing, actively exploited -> GRS 66.6, ACT."""
    finding = _finding(cvss_score=7.0, category="Web Application", zone="Internet Zone")
    asset = Asset(hostname="ASSET", ip="1.1.1.1", zone="Internet Zone", owning_team="x", criticality_tier=1, acw=0.6)
    ti = ThreatIntel(cve_id="CVE-Y", epss_score=0.55, in_kev=False, fetched_at=datetime.now(timezone.utc))

    assessment = compute_grs(finding, asset, ti, tcm=5.0, topology=TOPOLOGY)

    assert assessment.score == 66.6
    assert assessment.band == "ACT"
    assert assessment.sla_days == 7


def test_reordering_effect_beats_naive_cvss_sort():
    """The whole point of GRS: vulnerability B (lower CVSS) must outrank
    vulnerability A (higher CVSS) once exposure/exploitation context is applied."""
    finding_a = _finding(finding_id="A", cvss_score=10.0, zone="Isolated Zone")
    asset_a = Asset(hostname="ASSET", ip="1.1.1.1", zone="Isolated Zone", owning_team="x", criticality_tier=1, acw=0.6)
    ti_a = ThreatIntel(cve_id="CVE-X", epss_score=0.02, in_kev=False, fetched_at=datetime.now(timezone.utc))
    score_a = compute_grs(finding_a, asset_a, ti_a, tcm=1.0, topology=TOPOLOGY).score

    finding_b = _finding(finding_id="B", cvss_score=7.0, zone="Internet Zone")
    asset_b = Asset(hostname="ASSET", ip="1.1.1.1", zone="Internet Zone", owning_team="x", criticality_tier=1, acw=0.6)
    ti_b = ThreatIntel(cve_id="CVE-Y", epss_score=0.55, in_kev=False, fetched_at=datetime.now(timezone.utc))
    score_b = compute_grs(finding_b, asset_b, ti_b, tcm=5.0, topology=TOPOLOGY).score

    assert score_b > score_a


def test_dora_cif_scope_caps_sla_at_30_days():
    # ATTEND band's default SLA is already 30 days, so use a score that lands
    # in TRACK* (90-day default, no DORA cap) to prove the DORA cap actually bites.
    finding = _finding(cvss_score=2.0, zone="Internet Zone")
    asset = Asset(
        hostname="DC01", ip="1.1.1.1", zone="Internet Zone", owning_team="x", criticality_tier=0,
        acw=1.0, compliance_scope=["PCI DSS"],
    )
    ti = ThreatIntel(cve_id="CVE-Z", epss_score=0.1, in_kev=False, fetched_at=datetime.now(timezone.utc))

    assessment = compute_grs(finding, asset, ti, tcm=1.0, topology=TOPOLOGY)

    assert assessment.dora_cif_scope is True
    assert assessment.sla_days is not None
    assert assessment.sla_days <= 30
