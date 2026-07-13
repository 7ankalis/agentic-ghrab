"""Agent 1 — Ingestion & Normalization (non-AI, deterministic).

VMC_ARCHITECTURE_OVERVIEW.md §4, Agent 1:
- Multi-format CSV auto-detection (Qualys/Nessus/Rapid7/generic), loads the
  full findings set (CVE, misconfiguration, excessive-access, cloud
  misconfig, compliance-gap rows) — never filtered to a single CVE.
- Parses architecture.md into a typed NetworkGraph.
- Maps every finding's IP/hostname to an Asset (VLAN, zone, team, tier).
- Emits DataQualityIssues for orphaned IPs, ambiguous ownership,
  unparseable rows — surfaced to the operator, never silently dropped.

NOTE on the architecture.md parser: the real `ghrab_architecture.md` has not
been supplied yet, so `parse_architecture_markdown` targets a reasonable,
documented convention (a `| VLAN | Zone | Team | Compliance |` table plus a
`Source -> Target: description` trust-edge bullet list) inferred from
VMC_ARCHITECTURE_OVERVIEW.md and ghrab_risk_methodology.md. Re-check this
against the real file once it's provided — the CSV normalizer is the part
of Agent 1 that's format-robust by design (alias-based column mapping), the
markdown parser is the part most likely to need adjustment.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from vmc.models import Asset, DataQualityIssue, Finding, NetworkGraph, NetworkZone, TeamInfo, TrustEdge

# ---------------------------------------------------------------------------
# CSV normalization
# ---------------------------------------------------------------------------

# canonical Finding field -> header aliases seen across Qualys/Nessus/Rapid7/
# generic exports (lower-cased, spaces and underscores both stripped when
# matching, see `_normalize_header`)
COLUMN_ALIASES: dict[str, list[str]] = {
    "finding_id": ["finding_id", "id", "vulnerability_id", "vuln_id", "qid", "plugin_id"],
    "cve_id": ["cve_id", "cve"],
    "category": ["category", "finding_type", "type"],
    "title": ["title", "name", "vulnerability", "plugin_name", "vulnerability_title", "summary"],
    "severity_raw": ["severity", "risk", "severity_raw", "risk_rating"],
    "cvss_score": [
        "cvss_score", "cvss", "cvss_base", "cvss_base_score", "cvssv3", "cvss3_base_score", "cvss_v3_score",
    ],
    "cvss_vector": ["cvss_vector", "cvssv3_vector", "vector", "cvss_v3_vector"],
    "asset_ip": ["ip_address", "ip", "host_ip", "asset_ip"],
    "asset_hostname": ["hostname", "host_name", "dns_name", "asset_hostname", "host"],
    "vlan_id": ["vlan_id", "vlan"],
    "zone": ["zone", "network_zone"],
    "port": ["port", "ports"],
    "description": ["description", "synopsis", "details"],
    "consequence": ["consequence", "impact", "business_impact"],
    "remediation_text": ["remediation", "solution", "fix", "remediation_text"],
    "patch_available": ["patch_available", "patch"],
    "responsible_team": ["responsible_team", "team", "owning_team", "owner"],
    "attack_path_refs": ["attack_path_ref", "attack_path_refs", "path_ref"],
    "compliance_refs": ["compliance_ref", "compliance_refs", "compliance"],
    "status": ["status", "state"],
    "qid": ["qid"],  # Qualys-signature column, not a Finding field but useful for scanner detection
    "plugin_id": ["plugin_id"],  # Nessus-signature column
}

REQUIRED_FIELDS = ("finding_id", "category", "title", "severity_raw", "asset_ip", "asset_hostname", "responsible_team")

_TRUE_STRINGS = {"true", "yes", "y", "1"}
_FALSE_STRINGS = {"false", "no", "n", "0"}


def _normalize_header(header: str) -> str:
    return re.sub(r"[\s_]+", "_", header.strip().lower())


def _build_header_map(fieldnames: list[str]) -> dict[str, str]:
    """raw CSV header -> canonical Finding field name (only for recognized columns)."""
    normalized_to_raw = {_normalize_header(h): h for h in fieldnames}
    header_map: dict[str, str] = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized_to_raw:
                header_map[canonical] = normalized_to_raw[alias]
                break
    return header_map


def detect_scanner(fieldnames: list[str]) -> str:
    normalized = {_normalize_header(h) for h in fieldnames}
    if "qid" in normalized:
        return "qualys"
    if "plugin_id" in normalized or "plugin_name" in normalized:
        return "nessus"
    if "vulnerability_id" in normalized and "asset_ip_address" in normalized:
        return "rapid7"
    return "generic"


def _parse_bool(value: str | None) -> bool | None:
    if value is None or value.strip() == "":
        return None
    lowered = value.strip().lower()
    if lowered in _TRUE_STRINGS:
        return True
    if lowered in _FALSE_STRINGS:
        return False
    return None


def _parse_float(value: str | None) -> float | None:
    if value is None or value.strip() == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _parse_list(value: str | None) -> list[str]:
    if value is None or value.strip() == "":
        return []
    return [v.strip() for v in re.split(r"[,;]", value) if v.strip()]


def _parse_cve_id(value: str | None) -> str | None:
    """Scanner exports commonly use "N/A (Misconfiguration)"-style placeholders
    in the CVE column for non-CVE findings (misconfig/excessive-access/cloud/
    compliance rows) — normalize those to None rather than storing the
    placeholder text as if it were a real CVE identifier."""
    if value is None or value.strip() == "":
        return None
    if value.strip().upper().startswith("N/A"):
        return None
    return value.strip()


def normalize_row(row: dict[str, str], header_map: dict[str, str], row_index: int) -> tuple[Finding | None, DataQualityIssue | None]:
    def get(field: str) -> str | None:
        raw_header = header_map.get(field)
        if raw_header is None:
            return None
        value = row.get(raw_header)
        return value.strip() if value else value

    missing = [f for f in REQUIRED_FIELDS if not get(f)]
    if missing:
        return None, DataQualityIssue(
            issue_type="unparseable_row",
            raw_row=row,
            detail=f"row {row_index}: missing required field(s) {missing}",
        )

    finding = Finding(
        finding_id=get("finding_id"),
        cve_id=_parse_cve_id(get("cve_id")),
        category=get("category"),
        title=get("title"),
        severity_raw=get("severity_raw"),
        cvss_score=_parse_float(get("cvss_score")),
        cvss_vector=get("cvss_vector"),
        asset_ip=get("asset_ip"),
        asset_hostname=get("asset_hostname"),
        vlan_id=get("vlan_id") or None,
        zone=get("zone") or "Unknown",
        port=get("port") or None,
        description=get("description") or "",
        consequence=get("consequence") or "",
        remediation_text=get("remediation_text") or "",
        patch_available=_parse_bool(get("patch_available")),
        responsible_team=get("responsible_team"),
        attack_path_refs=_parse_list(get("attack_path_refs")),
        compliance_refs=_parse_list(get("compliance_refs")),
        status=get("status") or "Open",
    )
    return finding, None


def parse_findings_csv(path: str | Path) -> tuple[list[Finding], list[DataQualityIssue], str]:
    path = Path(path)
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f"{path} has no header row")
        scanner = detect_scanner(reader.fieldnames)
        header_map = _build_header_map(reader.fieldnames)

        missing_columns = [f for f in REQUIRED_FIELDS if f not in header_map]
        if missing_columns:
            raise ValueError(
                f"{path}: could not locate required column(s) {missing_columns} under any known alias "
                f"(scanner detected as {scanner!r}, headers were {reader.fieldnames})"
            )

        findings: list[Finding] = []
        issues: list[DataQualityIssue] = []
        for row_index, row in enumerate(reader, start=2):  # header is row 1
            finding, issue = normalize_row(row, header_map, row_index)
            if finding is not None:
                findings.append(finding)
            if issue is not None:
                issues.append(issue)

    _flag_duplicate_finding_ids(findings, issues)
    return findings, issues, scanner


def _flag_duplicate_finding_ids(findings: list[Finding], issues: list[DataQualityIssue]) -> None:
    seen: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen:
            issues.append(
                DataQualityIssue(
                    issue_type="other",
                    finding_id=finding.finding_id,
                    detail=f"duplicate finding_id {finding.finding_id!r} — later row overwrote nothing but both are kept",
                )
            )
        seen.add(finding.finding_id)


# ---------------------------------------------------------------------------
# architecture.md -> NetworkGraph
# ---------------------------------------------------------------------------

_TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")
_TRUST_EDGE_RE = re.compile(r"^[-*]\s*(?P<source>.+?)\s*(?:->|→)\s*(?P<target>[^:]+?)\s*(?::\s*(?P<desc>.+))?$")


def parse_architecture_markdown(path: str | Path) -> NetworkGraph:
    """Best-effort parser for `architecture.md`. Looks for a markdown table
    whose header row contains VLAN/Zone/Team/Compliance-ish columns, and a
    bullet list of `Source -> Target: description` trust edges. See module
    docstring — this convention is inferred, not confirmed against the real
    ghrab_architecture.md."""
    text = Path(path).read_text(encoding="utf-8")
    lines = [line.rstrip() for line in text.splitlines()]

    zones = _parse_zone_table(lines)
    trust_edges = _parse_trust_edges(lines)
    return NetworkGraph(zones=zones, trust_edges=trust_edges)


def _parse_zone_table(lines: list[str]) -> dict[str, NetworkZone]:
    zones: dict[str, NetworkZone] = {}
    table_rows: list[list[str]] = []
    in_table = False
    for line in lines:
        match = _TABLE_ROW_RE.match(line)
        if match:
            cells = [c.strip() for c in match.group(1).split("|")]
            if set(cells[0]) <= {"-", " "} or all(set(c) <= {"-", " ", ":"} for c in cells):
                continue  # markdown separator row (---|---|---)
            table_rows.append(cells)
            in_table = True
        elif in_table:
            break  # table ended
    if not table_rows:
        return zones

    header = [h.lower() for h in table_rows[0]]
    col_index = {name: i for i, name in enumerate(header)}
    vlan_col = next((col_index[k] for k in col_index if "vlan" in k), None)
    zone_col = next((col_index[k] for k in col_index if "zone" in k), None)
    team_col = next((col_index[k] for k in col_index if "team" in k or "owner" in k), None)
    compliance_col = next((col_index[k] for k in col_index if "compliance" in k), None)
    trust_col = next((col_index[k] for k in col_index if "trust" in k), None)

    if vlan_col is None and zone_col is None:
        return zones  # not a zone table, don't misinterpret an unrelated table

    used_cols = [c for c in (vlan_col, zone_col, team_col, compliance_col, trust_col) if c is not None]
    for row in table_rows[1:]:
        if len(row) <= max(used_cols, default=0):
            continue
        zone_name = row[zone_col] if zone_col is not None else row[vlan_col]
        vlan_id = row[vlan_col] if vlan_col is not None else None
        zone_id = re.sub(r"\W+", "_", zone_name.strip().lower()).strip("_") or f"zone_{len(zones)}"
        existing = zones.get(zone_id)
        vlan_ids = existing.vlan_ids if existing else []
        if vlan_id and vlan_id not in vlan_ids:
            vlan_ids = [*vlan_ids, vlan_id]
        compliance_scope = (
            _parse_list(row[compliance_col]) if compliance_col is not None else _infer_compliance_from_row(row)
        )
        zones[zone_id] = NetworkZone(
            zone_id=zone_id,
            name=zone_name.strip(),
            vlan_ids=vlan_ids,
            owning_team=(row[team_col].strip() if team_col is not None and row[team_col].strip() else None),
            compliance_scope=compliance_scope,
            trust_level_raw=(row[trust_col].strip() if trust_col is not None and row[trust_col].strip() else None),
        )
    return zones


_COMPLIANCE_KEYWORDS = {
    "cde": "PCI DSS",
    "pci": "PCI DSS",
    "swift": "SWIFT CSP",
}


def _infer_compliance_from_row(row: list[str]) -> list[str]:
    """No explicit Compliance column: fall back to scanning the row's free
    text (e.g. a Purpose cell reading "... — CDE/SWIFT scope") for known
    regulatory-scope keywords, since that's how the real ghrab_architecture.md
    marks compliance scope rather than a dedicated column."""
    row_text = " ".join(row).lower()
    found = {label for keyword, label in _COMPLIANCE_KEYWORDS.items() if keyword in row_text}
    return sorted(found)


def _parse_trust_edges(lines: list[str]) -> list[TrustEdge]:
    edges: list[TrustEdge] = []
    for line in lines:
        match = _TRUST_EDGE_RE.match(line.strip())
        if not match:
            continue
        edges.append(
            TrustEdge(
                source_zone=match.group("source").strip(),
                target_zone=match.group("target").strip(),
                description=(match.group("desc") or "").strip(),
                documented=True,
            )
        )
    return edges


# ---------------------------------------------------------------------------
# Finding -> Asset / Team mapping
# ---------------------------------------------------------------------------


def _primary_vlan_token(vlan_id: str | None) -> str | None:
    """Real-world exports aren't always one-VLAN-per-row: a finding that
    describes a pivot (e.g. "10 -> 40", "10/40") or a cloud row ("Cloud/AWS")
    still needs a best-effort primary VLAN to resolve a zone against. Takes
    the first token before any "->"/"/" separator."""
    if not vlan_id:
        return None
    return re.split(r"\s*(?:->|/)\s*", vlan_id.strip())[0].strip() or None


def _resolve_zone(finding_zone: str, vlan_id: str | None, zone_by_vlan: dict[str, NetworkZone], zone_by_name: dict[str, NetworkZone]) -> NetworkZone | None:
    """Best-effort zone match: prefer VLAN ID (more stable than free-text zone
    labels, see ghrab_vulnerabilities.csv's inconsistent Zone column), then
    exact zone-name match, then a loose substring match either direction."""
    primary_vlan = _primary_vlan_token(vlan_id)
    if primary_vlan and primary_vlan in zone_by_vlan:
        return zone_by_vlan[primary_vlan]

    normalized = finding_zone.strip().lower()
    if normalized in zone_by_name:
        return zone_by_name[normalized]

    for name, zone in zone_by_name.items():
        if name in normalized or normalized in name:
            return zone
    return None


def build_assets_and_teams(
    findings: list[Finding], topology: NetworkGraph
) -> tuple[dict[str, Asset], dict[str, TeamInfo], list[DataQualityIssue]]:
    assets: dict[str, Asset] = {}
    ownership_by_hostname: dict[str, set[str]] = {}
    teams: dict[str, TeamInfo] = {}
    issues: list[DataQualityIssue] = []

    zone_by_name = {z.name.strip().lower(): z for z in topology.zones.values()}
    zone_by_vlan: dict[str, NetworkZone] = {}
    for zone in topology.zones.values():
        for vlan_id in zone.vlan_ids:
            zone_by_vlan.setdefault(vlan_id, zone)

    for finding in findings:
        key = finding.asset_hostname or finding.asset_ip
        ownership_by_hostname.setdefault(key, set()).add(finding.responsible_team)

        zone = _resolve_zone(finding.zone, finding.vlan_id, zone_by_vlan, zone_by_name)
        criticality_tier = _infer_criticality_tier(zone, finding)
        compliance_scope = zone.compliance_scope if zone else list(finding.compliance_refs)

        if key not in assets:
            assets[key] = Asset(
                hostname=finding.asset_hostname,
                ip=finding.asset_ip,
                vlan_id=finding.vlan_id,
                zone=finding.zone,
                owning_team=finding.responsible_team,
                criticality_tier=criticality_tier,
                compliance_scope=compliance_scope,
            )

        if zone is None and finding.zone != "Unknown":
            issues.append(
                DataQualityIssue(
                    issue_type="orphaned_ip",
                    finding_id=finding.finding_id,
                    detail=f"asset {key!r} references zone {finding.zone!r} not found in architecture.md",
                )
            )

        team_id = re.sub(r"\W+", "_", finding.responsible_team.strip().lower()).strip("_")
        team = teams.setdefault(team_id, TeamInfo(team_id=team_id, name=finding.responsible_team))
        if key not in team.owned_assets:
            team.owned_assets.append(key)
        if finding.zone not in team.owned_zones and finding.zone != "Unknown":
            team.owned_zones.append(finding.zone)

    for key, owning_teams in ownership_by_hostname.items():
        if len(owning_teams) > 1:
            issues.append(
                DataQualityIssue(
                    issue_type="ambiguous_ownership",
                    detail=f"asset {key!r} is claimed by multiple responsible teams: {sorted(owning_teams)}",
                )
            )

    return assets, teams, issues


def _infer_criticality_tier(zone: NetworkZone | None, finding: Finding) -> int:
    """0 = crown jewel .. 3 = general purpose. Best-effort until Agent 5's
    policy-driven asset criticality weighting (see ghrab_risk_methodology.md
    §3) replaces this with a proper tenant-configurable table."""
    if zone is not None and zone.compliance_scope:
        return 0
    if finding.compliance_refs:
        return 1
    return 3


# ---------------------------------------------------------------------------
# Orchestration entry point
# ---------------------------------------------------------------------------


def run_agent1(
    findings_csv: str | Path, architecture_md: str | Path
) -> tuple[list[Finding], dict[str, Asset], dict[str, TeamInfo], NetworkGraph, list[DataQualityIssue]]:
    findings, csv_issues, _scanner = parse_findings_csv(findings_csv)
    topology = parse_architecture_markdown(architecture_md)
    assets, teams, mapping_issues = build_assets_and_teams(findings, topology)
    return findings, assets, teams, topology, [*csv_issues, *mapping_issues]
