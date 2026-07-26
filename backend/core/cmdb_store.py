"""
CSV-backed CMDB loader — reads the relational `cmdb_ci_*` + `cmdb_rel_ci` tables
(the shape a real enterprise CMDB exports) into the schema models, validates
referential integrity, and projects them onto the legacy in-memory `CMDB`
interface (`zones` / `assets` / `teams` / `dependency_edges` /
`reachability_rules` / `cred_relations` / …) that `attack_graph.py`, the agents,
and the serializers already consume unchanged.

Why this exists (docs/cmdb-accuracy-brief.md §2.2, §2.5): the markdown parser
returned an empty section with NO error on any renamed header, silently starving
every downstream agent. Here the format is typed and every relationship endpoint
is checked against a real `ci_id`; a dangling reference is REPORTED, never
silently dropped. The report is surfaced by `GET /api/cmdb/validate` and logged
at load so the failure is loud.

This loader does NOT change the deterministic graph. It fills the exact same
fields the markdown path fills, plus one additive structured field
(`reachability_edges`) that Phase 3 will wire into real zone-to-zone edges and
Should-Not-Exist vetoes. Until then the graph behaves identically.
"""
from __future__ import annotations

import csv
from pathlib import Path

from core.cmdb_schema import (
    ConfigurationItem, CredentialRelation, ReachabilityRule, ReachabilityStatus,
    Relationship, ValidationReport,
)

# CI classes whose CIs are real reachable HOSTS in the attack graph (they become
# HostNodes). Applications, service accounts, business services, and support
# groups are grounding/relationship anchors, not traversable hosts.
_HOST_CLASSES = {"cmdb_ci_server", "cmdb_ci_netgear", "cmdb_ci_database", "cmdb_ci_cloud_resource"}
_CLOUD_CLASS = "cmdb_ci_cloud_resource"

# Relationship-type routing (matched case-insensitively on rel_type). Hosting
# types feed the virtualization/blast-radius grounding; "runs on" is an app→server
# mapping (grounding only). Everything else is a host/app/db dependency and is
# projected into `dependency_edges` exactly like the markdown §4 table — so the
# graph's `_DEP_EDGE_KIND` picks up the traversable ones (Depends on, Backs up,
# Manages, Linked to, …) with no change to attack_graph.py.
_HOSTING_TYPES = {"hosted on", "virtualized on"}
_APP_RUNS_TYPES = {"runs on"}

# The per-class CSV files this loader reads. A missing file is tolerated (a
# dataset need not define every class); a present file with a malformed row
# raises loudly via Pydantic.
_CI_FILES = {
    "cmdb_ci_network_segment.csv": "cmdb_ci_network_segment",
    "cmdb_ci_server.csv": "cmdb_ci_server",
    "cmdb_ci_netgear.csv": "cmdb_ci_netgear",
    "cmdb_ci_database.csv": "cmdb_ci_database",
    "cmdb_ci_appl.csv": "cmdb_ci_appl",
    "cmdb_ci_cloud_resource.csv": "cmdb_ci_cloud_resource",
    "cmdb_ci_service_account.csv": "cmdb_ci_service_account",
    "cmdb_ci_business_service.csv": "cmdb_ci_business_service",
    "cmdb_ci_support_group.csv": "cmdb_ci_support_group",
}


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [{(k or "").strip(): (v or "").strip() for k, v in row.items()}
                for row in csv.DictReader(f)]


def _int_or_none(v: str | None) -> int | None:
    v = (v or "").strip()
    if not v:
        return None
    m = "".join(ch for ch in v if ch.isdigit())
    return int(m) if m else None


class _StructuredCMDB:
    """Everything read off disk, pre-projection. Kept as an attribute of the CMDB
    so Phase 3+ and the validation endpoint can read typed records on demand."""

    def __init__(self) -> None:
        self.cis: list[ConfigurationItem] = []
        self.relationships: list[Relationship] = []
        self.reachability: list[ReachabilityRule] = []
        self.credentials: list[CredentialRelation] = []
        self.rel_type_vocab: set[str] = set()
        self.support_groups: list[dict] = []          # {group_id, name, responsible_for}
        # Segment ci_id -> human VLAN label ("20", "Cloud", "INTERNET"). The label
        # is the graph's zone key, not a CI field, so it's tracked separately.
        self.segment_vlan: dict[str, str] = {}


def load_structured(cmdb_dir: Path) -> _StructuredCMDB:
    """Parse every table under `cmdb_dir/` into the schema models. Raises
    (ValidationError / ValueError) on a malformed row — a loud failure, never a
    silent empty section."""
    s = _StructuredCMDB()

    for filename, ci_class in _CI_FILES.items():
        for r in _rows(cmdb_dir / filename):
            if ci_class == "cmdb_ci_support_group":
                s.support_groups.append({
                    "group_id": r.get("group_id", r.get("ci_id", "")),
                    "name": r.get("name", ""),
                    "responsible_for": r.get("responsible_for", ""),
                })
                continue
            if ci_class == "cmdb_ci_network_segment":
                s.cis.append(ConfigurationItem(
                    ci_id=r["ci_id"], ci_class=ci_class, name=r.get("name", ""),
                    zone=r.get("ci_id"), cidr=r.get("cidr"),
                    trust_level=r.get("trust_level"),
                    support_group=r.get("owner_group"),
                    description=r.get("business_purpose"),
                ))
                s.segment_vlan[r["ci_id"]] = r.get("vlan", "").strip()
                continue
            if ci_class == _CLOUD_CLASS:
                s.cis.append(ConfigurationItem(
                    ci_id=r["ci_id"], ci_class=ci_class, name=r.get("name", ""),
                    zone=r.get("zone") or None, platform=r.get("type"),
                    criticality=r.get("criticality"), support_group=r.get("support_group"),
                    business_service=r.get("business_service"),
                    description=r.get("provider"),
                ))
                continue
            if ci_class == "cmdb_ci_appl":
                s.cis.append(ConfigurationItem(
                    ci_id=r["ci_id"], ci_class=ci_class, name=r.get("name", ""),
                    zone=r.get("runs_on") or None, criticality=r.get("criticality"),
                    support_group=r.get("support_group"),
                    business_service=r.get("business_service"),
                ))
                continue
            if ci_class == "cmdb_ci_service_account":
                s.cis.append(ConfigurationItem(
                    ci_id=r["ci_id"], ci_class=ci_class, name=r.get("name", ""),
                    platform=r.get("type"), support_group=r.get("support_group"),
                    description=r.get("issue"),
                ))
                continue
            if ci_class == "cmdb_ci_business_service":
                s.cis.append(ConfigurationItem(
                    ci_id=r["ci_id"], ci_class=ci_class, name=r.get("name", ""),
                    description=r.get("description"),
                ))
                continue
            # server / netgear / database — the reachable hosts
            s.cis.append(ConfigurationItem(
                ci_id=r["ci_id"], ci_class=ci_class, name=r.get("name", ""),
                zone=r.get("zone") or None, ip=r.get("ip"), platform=r.get("platform"),
                criticality=r.get("criticality"), support_group=r.get("support_group"),
                business_service=r.get("business_service"),
            ))

    for r in _rows(cmdb_dir / "cmdb_rel_type.csv"):
        rt = r.get("rel_type", "").strip()
        if rt:
            s.rel_type_vocab.add(rt.lower())

    for r in _rows(cmdb_dir / "cmdb_rel_ci.csv"):
        s.relationships.append(Relationship(
            rel_id=r["rel_id"], rel_type=r.get("rel_type", ""),
            source_ci=r.get("source_ci", ""), target_ci=r.get("target_ci", ""),
            port=r.get("port") or None, flag=r.get("flag") or None,
            enabling_qid=_int_or_none(r.get("enabling_qid")),
            justification=r.get("justification") or None,
        ))

    for r in _rows(cmdb_dir / "net_reachability.csv"):
        s.reachability.append(ReachabilityRule(
            rule_id=r["rule_id"], src_zone=r.get("src_zone", ""),
            dst_zone=r.get("dst_zone", ""), port=r.get("port") or None,
            status=ReachabilityStatus(r.get("status", "Intended").strip()),
            enabling_qid=_int_or_none(r.get("enabling_qid")),
            notes=r.get("notes") or None,
        ))

    for r in _rows(cmdb_dir / "cred_rel.csv"):
        valid_on = [x.strip() for x in (r.get("valid_on", "") or "").split(";") if x.strip()]
        s.credentials.append(CredentialRelation(
            rel_id=r["rel_id"], identity_ci=r.get("identity_ci", ""),
            valid_on=valid_on, access_level=r.get("access_level") or None,
            enabling_qid=_int_or_none(r.get("enabling_qid")),
            issue=r.get("issue") or None,
        ))
    return s


def validate(s: _StructuredCMDB, dataset: str) -> ValidationReport:
    """Referential-integrity check. Every relationship / reachability / credential
    endpoint, every host's zone, every app's runs-on must resolve to a real
    `ci_id`; every network segment should appear in the reachability base; a host
    CI referenced by nothing is an orphan. Findings are validated separately (the
    vuln CSV isn't loaded here) via `validate_findings`."""
    rep = ValidationReport(dataset=dataset, ci_count=len(s.cis),
                           relationship_count=len(s.relationships))
    by_id: dict[str, ConfigurationItem] = {}
    for ci in s.cis:
        if ci.ci_id in by_id:
            rep.duplicate_ci_ids.append({"kind": "duplicate_ci_id", "ref": ci.ci_id,
                                         "detail": f"ci_id {ci.ci_id} defined more than once"})
        by_id[ci.ci_id] = ci
    ids = set(by_id)
    segments = {ci.ci_id for ci in s.cis if ci.ci_class == "cmdb_ci_network_segment"}

    def dangle(ref: str, detail: str) -> None:
        rep.dangling_refs.append({"kind": "dangling_ref", "ref": ref, "detail": detail})

    # hosts/apps must point at a real zone / server
    for ci in s.cis:
        if ci.ci_class in _HOST_CLASSES - {_CLOUD_CLASS} and ci.zone and ci.zone not in segments:
            dangle(ci.ci_id, f"{ci.ci_id} in unknown zone {ci.zone}")
        if ci.ci_class == "cmdb_ci_appl" and ci.zone and ci.zone not in ids:
            dangle(ci.ci_id, f"{ci.ci_id} runs on unknown CI {ci.zone}")

    referenced: set[str] = set()
    for rel in s.relationships:
        if rel.rel_type.lower() not in s.rel_type_vocab and s.rel_type_vocab:
            rep.unknown_rel_types.append({"kind": "unknown_rel_type", "ref": rel.rel_id,
                                          "detail": f"{rel.rel_id} uses undefined rel_type "
                                                    f"'{rel.rel_type}'"})
        for endpoint in (rel.source_ci, rel.target_ci):
            if endpoint not in ids:
                dangle(rel.rel_id, f"{rel.rel_id} endpoint {endpoint} is not a known CI")
            else:
                referenced.add(endpoint)

    zones_with_rules: set[str] = set()
    for rule in s.reachability:
        for endpoint in (rule.src_zone, rule.dst_zone):
            if endpoint not in segments:
                dangle(rule.rule_id, f"{rule.rule_id} zone {endpoint} is not a network segment")
            else:
                zones_with_rules.add(endpoint)

    for cred in s.credentials:
        if cred.identity_ci not in ids:
            dangle(cred.rel_id, f"{cred.rel_id} identity {cred.identity_ci} is not a known CI")
        for host in cred.valid_on:
            if host not in ids:
                dangle(cred.rel_id, f"{cred.rel_id} valid_on {host} is not a known CI")
            else:
                referenced.add(host)

    for seg in segments:
        if seg not in zones_with_rules:
            rep.zones_without_rules.append({"kind": "zone_without_rules", "ref": seg,
                                            "detail": f"segment {seg} appears in no "
                                                      f"net_reachability rule"})

    # Orphan = a reachable HOST CI referenced by no relationship or credential.
    for ci in s.cis:
        if ci.ci_class in _HOST_CLASSES and ci.ci_id not in referenced:
            rep.orphan_cis.append({"kind": "orphan_ci", "ref": ci.ci_id,
                                   "detail": f"{ci.ci_id} ({ci.name}) has no relationship"})
    return rep


def validate_findings(rep: ValidationReport, s: _StructuredCMDB, vuln_csv: Path) -> ValidationReport:
    """Augment a report with findings whose CI_ID resolves to no CI. Kept separate
    because the CMDB loads without the vuln CSV; the endpoint runs both."""
    ids = {ci.ci_id for ci in s.cis}
    names = {ci.name for ci in s.cis}
    for r in _rows(vuln_csv):
        ci_id = (r.get("CI_ID") or "").strip()
        host = (r.get("Hostname") or "").strip()
        if not ci_id and not host:
            continue
        if ci_id and ci_id not in ids and host not in names:
            rep.findings_without_ci.append({
                "kind": "finding_without_ci", "ref": r.get("QID", ""),
                "detail": f"QID {r.get('QID', '?')} cites CI_ID {ci_id!r} / host {host!r} "
                          f"that resolves to no CI"})
    return rep


def project(s: _StructuredCMDB, cmdb) -> None:
    """Fill the legacy in-memory CMDB fields from the structured records. This is
    the compatibility bridge: after this call `cmdb.zones/assets/teams/
    dependency_edges/reachability_rules/cred_relations/...` are populated exactly
    as the markdown parser would, so nothing downstream changes."""
    from core.cmdb import Asset, Team, Zone

    name_by_id = {ci.ci_id: ci.name for ci in s.cis}
    by_id = {ci.ci_id: ci for ci in s.cis}

    # Zones
    for ci in s.cis:
        if ci.ci_class != "cmdb_ci_network_segment":
            continue
        cmdb.zones.append(Zone(
            vlan=s.segment_vlan.get(ci.ci_id, ""), name=ci.name, cidr=ci.cidr or "",
            purpose=ci.description or "", trust_level=ci.trust_level or "",
            owning_team=ci.support_group or "",
        ))
    vlan_of_zone = {ci.ci_id: (s.segment_vlan.get(ci.ci_id, ""), ci.name)
                    for ci in s.cis if ci.ci_class == "cmdb_ci_network_segment"}

    # Assets (reachable hosts) + team→asset grouping
    team_assets: dict[str, list[str]] = {}
    for ci in s.cis:
        if ci.ci_class not in _HOST_CLASSES:
            continue
        if ci.ci_class == _CLOUD_CLASS:
            vlan, zone_name = "Cloud", "Cloud"
        else:
            vlan, zone_name = vlan_of_zone.get(ci.zone or "", ("", ""))
        cmdb.assets.append(Asset(
            hostname=ci.name, ip=ci.ip or "", role=ci.platform or "",
            notable_issue=ci.criticality or "", vlan=vlan, zone_name=zone_name,
        ))
        if ci.support_group:
            team_assets.setdefault(ci.support_group, []).append(ci.name)

    # Teams
    for g in s.support_groups:
        cmdb.teams.append(Team(
            name=g["name"], responsible_for=g["responsible_for"],
            example_assets=", ".join(team_assets.get(g["group_id"], [])),
        ))

    # Relationships → hosting / dependency projections
    for rel in s.relationships:
        rtype = rel.rel_type.strip()
        low = rtype.lower()
        src_name = name_by_id.get(rel.source_ci, rel.source_ci)
        dst_name = name_by_id.get(rel.target_ci, rel.target_ci)
        if low in _HOSTING_TYPES:
            cmdb.hosting_relations.append(f"{src_name} {rtype or 'hosted on'} {dst_name}")
            continue
        if low in _APP_RUNS_TYPES:
            cmdb.dependencies.append(f"{rel.rel_id}: {src_name} --[{rtype}]--> {dst_name}")
            continue
        # host/app/db dependency — the traversable class (graph reads dependency_edges)
        flag = rel.flag or ""
        just = rel.justification or ""
        cmdb.dependencies.append(
            f"{rel.rel_id}: {src_name} --[{rtype}]--> {dst_name}"
            + (f" [{flag}]" if flag else "") + (f" — {just}" if just else ""))
        cmdb.dependency_edges.append({
            "rel_id": rel.rel_id, "src_host": src_name, "dst_host": dst_name,
            "rtype": rtype, "flag": flag, "qid": rel.enabling_qid,
            "label": f"{rel.rel_id}: {rtype}".strip(),
        })

    # Reachability — text (grounding parity) + structured (Phase 3 fuel)
    for rule in s.reachability:
        src_name = name_by_id.get(rule.src_zone, rule.src_zone)
        dst_name = name_by_id.get(rule.dst_zone, rule.dst_zone)
        cmdb.reachability_rules.append(
            f"{rule.rule_id}: {src_name} → {dst_name} ({rule.port or 'N/A'}) "
            f"[{rule.status.value}]" + (f" — {rule.notes}" if rule.notes else ""))
        cmdb.reachability_edges.append({
            "rule_id": rule.rule_id, "src_zone": rule.src_zone, "dst_zone": rule.dst_zone,
            "src_vlan": s.segment_vlan.get(rule.src_zone, ""),
            "dst_vlan": s.segment_vlan.get(rule.dst_zone, ""),
            "port": rule.port or "", "status": rule.status.value,
            "enabling_qid": rule.enabling_qid, "notes": rule.notes or "",
        })

    # Credentials — text grounding (a credential valid on >1 CI is a non-network pivot)
    for cred in s.credentials:
        ident = name_by_id.get(cred.identity_ci, cred.identity_ci)
        valid_on = ", ".join(name_by_id.get(h, h) for h in cred.valid_on)
        cmdb.cred_relations.append(
            f"{cred.rel_id}: {ident} valid on [{valid_on}] → {cred.access_level or '?'}"
            + (f" — {cred.issue}" if cred.issue else ""))


def validate_active() -> ValidationReport | None:
    """Full integrity report for the active dataset (CI/rel/zone/cred + findings),
    or None when the active dataset is markdown-backed (no structural CSV to
    check). Used by GET /api/cmdb/validate and the startup log."""
    from core import datasets
    ds = datasets.get_active()
    if ds.cmdb_dir is None:
        return None
    s = load_structured(ds.cmdb_dir)
    rep = validate(s, ds.key)
    validate_findings(rep, s, ds.vuln_csv)
    return rep


def build_cmdb(cmdb, cmdb_dir: Path, dataset: str) -> ValidationReport:
    """Load `cmdb_dir` into the given (empty) CMDB instance and return the
    integrity report. Stores the structured records + report on the instance for
    the validation endpoint and Phase 3."""
    s = load_structured(cmdb_dir)
    rep = validate(s, dataset)
    project(s, cmdb)
    cmdb.structured = s
    cmdb.validation_report = rep
    return rep
