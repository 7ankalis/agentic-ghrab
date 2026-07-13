"""Agent 2 — Topology, Segmentation Health & Exposure Tier (non-AI, deterministic).

Takes Agent 1's output (`NetworkGraph` zones + `Asset` map, both keyed off
`ghrab_architecture.md`) and layers on the two inputs Agent 5's GRS formula
needs that Agent 1 doesn't compute:

- `NetworkZone.exposure_tier` — the reachability multiplier from
  ghrab_risk_methodology.md §5, derived from the zone table's free-text
  "Trust Level" column plus a small set of named overrides for assets whose
  real-world exposure doesn't match their zone's default (the methodology
  doc calls these out explicitly by hostname in §5, e.g. a public S3 bucket
  living in a zone otherwise labelled "Mixed").
- `Asset.acw` — the Asset Criticality Weight from §3, driven by an explicit
  hostname table for the assets the methodology names by name ("crown
  jewels" etc.), falling back to a zone-based default for anything else.

Also produces `SegmentationFinding`s: Green/Yellow/Red segmentation health,
derived from the CSV's own `Category` column (findings categorized as
Segmentation/Firewall/Rules violations are exactly the "deliberately broken"
boundaries architecture.md §2 says the dataset contains — this is more
reliable ground truth than trying to infer trust edges from prose that isn't
actually present in the real file as a bulleted list).
"""

from __future__ import annotations

import re

from vmc.models import Asset, Finding, NetworkGraph, SegmentationFinding

# ---------------------------------------------------------------------------
# Exposure tier — ghrab_risk_methodology.md §5
# ---------------------------------------------------------------------------

INTERNET_FACING = 1.30
ADJACENT = 1.15
INTERNAL = 0.90
RESTRICTED = 0.50
ISOLATED = 0.15

# Zones whose name marks them as the Management/OOB tier regardless of the
# free-text trust label they carry ("Critical (should be)" in the source
# doc) — methodology §5 names JUMP01/VCENTER01/BACKUP-MGR01 Isolated
# explicitly because they sit in this zone.
_MANAGEMENT_ZONE_KEYWORDS = ("management", "out-of-band", "out of band", "oob")

# Asset-level exposure overrides for hosts the methodology §5 calls out by
# name because their zone's default trust label doesn't capture their real
# reachability (mainly the "Mixed"-trust Cloud zone, which contains both a
# public S3 bucket and an internal IAM role).
ASSET_EXPOSURE_OVERRIDES: dict[str, float] = {
    "ghrab-public-assets": INTERNET_FACING,  # public S3 bucket
    "ghrab-finance-rds": INTERNET_FACING,  # publicly accessible RDS
    "ghrab-app-role": ADJACENT,  # IAM role, reachable once keys leak
    "ghrab.onmicrosoft.com": ADJACENT,  # Entra tenant, reachable via any phished credential
}


def _exposure_tier_for_trust_label(trust_label: str | None, zone_name: str) -> float:
    if trust_label is None:
        return INTERNAL
    label = trust_label.lower()
    zone_lower = zone_name.lower()
    if "low" in label or "internet" in label:
        return INTERNET_FACING
    if "untrusted" in label:
        return ADJACENT
    if "medium" in label:
        return INTERNAL
    if "high" in label:
        return RESTRICTED
    if "critical" in label:
        if any(kw in zone_lower for kw in _MANAGEMENT_ZONE_KEYWORDS):
            return ISOLATED
        return RESTRICTED
    if "mixed" in label:
        return ADJACENT  # best-effort zone default; asset-level overrides handle the outliers
    return INTERNAL


# ---------------------------------------------------------------------------
# Asset Criticality Weight — ghrab_risk_methodology.md §3
# ---------------------------------------------------------------------------

CROWN_JEWEL = 1.0
REGULATED_FINANCIAL_DATA = 0.875  # midpoint of the doc's 0.85-0.9 band
HIGH_LEVERAGE_INFRA = 0.75  # midpoint of 0.7-0.8
BUSINESS_IMPORTANT = 0.6  # midpoint of 0.5-0.7
STANDARD_ENDPOINT = 0.35  # midpoint of 0.3-0.4

ASSET_ACW_TABLE: dict[str, float] = {
    # Crown jewel
    "DC01": CROWN_JEWEL,
    "TRADE-CORE01": CROWN_JEWEL,
    "SWIFT-GATEWAY01": CROWN_JEWEL,
    "SETTLEMENT01": CROWN_JEWEL,
    # Regulated financial data
    "DB-FIN01": REGULATED_FINANCIAL_DATA,
    "DB-TRADE01": REGULATED_FINANCIAL_DATA,
    "ghrab-finance-rds": REGULATED_FINANCIAL_DATA,
    "APP-TRADE01": REGULATED_FINANCIAL_DATA,
    # High-leverage infrastructure
    "JUMP01": HIGH_LEVERAGE_INFRA,
    "VCENTER01": HIGH_LEVERAGE_INFRA,
    "BACKUP-MGR01": HIGH_LEVERAGE_INFRA,
    "NAS01": HIGH_LEVERAGE_INFRA,
    "ghrab-app-role": HIGH_LEVERAGE_INFRA,
    "ghrab.onmicrosoft.com": HIGH_LEVERAGE_INFRA,
    # Business-important
    "DB-CRM01": BUSINESS_IMPORTANT,
    "APP-CRM01": BUSINESS_IMPORTANT,
    "FILESRV01": BUSINESS_IMPORTANT,
    "ghrab-public-assets": BUSINESS_IMPORTANT,
    "LB01": BUSINESS_IMPORTANT,
    "VPN-GW01": BUSINESS_IMPORTANT,
    "WEB-PORTAL01": BUSINESS_IMPORTANT,
    "MAIL-RELAY01": BUSINESS_IMPORTANT,
    # Standard endpoint
    "WKS-FIN01": STANDARD_ENDPOINT,
    "WKS-HR02": STANDARD_ENDPOINT,
    "BRANCH-RTR01": STANDARD_ENDPOINT,
    "GUEST-AP-SW01": STANDARD_ENDPOINT,
    "APP-HR01": STANDARD_ENDPOINT,
    "BRANCH-WKS01": STANDARD_ENDPOINT,
    "PRINT01": STANDARD_ENDPOINT,
    "BACKUP-SRV01": STANDARD_ENDPOINT,
}


def _acw_for_asset(asset: Asset, topology: NetworkGraph) -> float:
    if asset.hostname in ASSET_ACW_TABLE:
        return ASSET_ACW_TABLE[asset.hostname]
    if asset.compliance_scope:
        return REGULATED_FINANCIAL_DATA
    zone = _zone_for_asset(asset, topology)
    if zone is not None and zone.exposure_tier in (RESTRICTED, ISOLATED):
        return BUSINESS_IMPORTANT
    return STANDARD_ENDPOINT


def _zone_for_asset(asset: Asset, topology: NetworkGraph):
    for zone in topology.zones.values():
        if asset.vlan_id and asset.vlan_id in zone.vlan_ids:
            return zone
        if zone.name.strip().lower() == asset.zone.strip().lower():
            return zone
    return None


# ---------------------------------------------------------------------------
# Segmentation health
# ---------------------------------------------------------------------------

_SEGMENTATION_CATEGORY_KEYWORDS = ("segmentation", "firewall", "rules")


def _score_segmentation_findings(findings: list[Finding]) -> list[SegmentationFinding]:
    results: list[SegmentationFinding] = []
    for finding in findings:
        category_lower = finding.category.lower()
        if not any(kw in category_lower for kw in _SEGMENTATION_CATEGORY_KEYWORDS):
            continue
        results.append(
            SegmentationFinding(
                finding_id=finding.finding_id,
                source_zone=finding.zone,
                target_zone=_infer_target_zone(finding),
                issue_description=finding.description,
                health="Red",
                remediation=finding.remediation_text,
            )
        )
    return results


_ZONE_MENTION_RE = re.compile(r"\b(VLAN\s*\d+|Corporate LAN|Finance/Trading[\w\s]*|Management(?:\s*/\s*Out-of-Band)?)\b", re.IGNORECASE)


def _infer_target_zone(finding: Finding) -> str:
    """Best-effort: the description/consequence text usually names the zone
    an attacker pivots into (see the CSV's own free-text fields) — fall back
    to 'Unknown' rather than guessing when it doesn't."""
    text = f"{finding.description} {finding.consequence}"
    match = _ZONE_MENTION_RE.search(text)
    return match.group(1) if match else "Unknown"


# ---------------------------------------------------------------------------
# Orchestration entry point
# ---------------------------------------------------------------------------


def run_agent2(
    findings: list[Finding], assets: dict[str, Asset], topology: NetworkGraph
) -> tuple[NetworkGraph, dict[str, Asset], list[SegmentationFinding]]:
    for zone in topology.zones.values():
        zone.exposure_tier = _exposure_tier_for_trust_label(zone.trust_level_raw, zone.name)

    updated_assets: dict[str, Asset] = {}
    for key, asset in assets.items():
        asset.acw = _acw_for_asset(asset, topology)
        updated_assets[key] = asset

    segmentation_findings = _score_segmentation_findings(findings)
    return topology, updated_assets, segmentation_findings


def exposure_tier_for_asset(asset: Asset, topology: NetworkGraph) -> float:
    """The effective exposure multiplier for one asset: an asset-level
    override (methodology §5's named exceptions) wins over its zone's tier."""
    override = ASSET_EXPOSURE_OVERRIDES.get(asset.hostname)
    if override is not None:
        return override
    zone = _zone_for_asset(asset, topology)
    return zone.exposure_tier if zone is not None else INTERNAL
