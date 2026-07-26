"""
Structured CMDB schema — the relational shape a real enterprise CMDB exports
(ServiceNow `cmdb_ci_*` + `cmdb_rel_ci`), as Pydantic models.

This replaces prose-as-database (§2.2 of docs/cmdb-accuracy-brief.md) for the
new CSV-backed datasets: a renamed markdown header used to return an empty
section *with no error*, silently starving every downstream agent. Here the
tables are typed and every relationship endpoint is validated against a real
`ci_id`, so a dangling reference FAILS LOUD instead of vanishing.

These models are the on-disk contract. `core/cmdb_store.py` reads the CSVs into
them, validates referential integrity, then projects them onto the legacy
in-memory `CMDB` interface (`zones` / `assets` / `dependency_edges` / …) that
`attack_graph.py`, the agents, and the serializers already consume unchanged.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class ReachabilityStatus(str, Enum):
    """Status of a zone-to-zone firewall rule in `net_reachability.csv`.

    INTENDED     — as-designed, expected connectivity.
    EXCESSIVE    — a real misconfiguration that opens a boundary an attacker can
                   traverse (carries an `enabling_qid`). Becomes a traversable
                   edge in Phase 3.
    SHOULD_NOT_EXIST — an explicitly forbidden pair. In Phase 3 this is a *veto*:
                   no inferred edge may connect the two zones. Present here so the
                   forbidden set is data, not a hardcoded assumption.
    """

    INTENDED = "Intended"
    EXCESSIVE = "Excessive"
    SHOULD_NOT_EXIST = "Should-Not-Exist"


class ConfigurationItem(BaseModel):
    """A single CI — a server, network segment, application, database, cloud
    resource, service account, or business service. Mirrors the common columns of
    the ServiceNow `cmdb_ci_*` classes; class-specific columns (CIDR for a
    segment, platform for a server) are optional and only populated where they
    apply."""

    ci_id: str
    ci_class: str                       # e.g. cmdb_ci_server, cmdb_ci_network_segment
    name: str
    zone: str | None = None             # ci_id of the containing network segment
    ip: str | None = None
    cidr: str | None = None             # network segments only
    trust_level: str | None = None      # network segments only
    platform: str | None = None
    criticality: str | None = None
    support_group: str | None = None
    business_service: str | None = None
    description: str | None = None

    @field_validator("ci_id", "ci_class", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not str(v).strip():
            raise ValueError("must not be empty")
        return str(v).strip()


class Relationship(BaseModel):
    """A typed edge between two CIs (`cmdb_rel_ci`) — hosting, dependency,
    credential, or network-device relation. `rel_type` is drawn from
    `cmdb_rel_type.csv`'s vocabulary. `enabling_qid` links the relationship to a
    scan finding when the relationship itself is the misconfiguration (e.g. a
    stale DB link)."""

    rel_id: str
    rel_type: str                       # "Depends on", "Hosted on", "Backs up", …
    source_ci: str
    target_ci: str
    port: str | None = None
    flag: str | None = None             # Legitimate / Excessive / …
    enabling_qid: int | None = None
    justification: str | None = None

    @field_validator("rel_id", "rel_type", "source_ci", "target_ci")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not str(v).strip():
            raise ValueError("must not be empty")
        return str(v).strip()


class ReachabilityRule(BaseModel):
    """One row of the firewall rule base (`net_reachability.csv`) — THE
    authoritative zone-to-zone reachability table (§2.1). Both endpoints must be
    real network-segment `ci_id`s (enforced by the loader's integrity check)."""

    rule_id: str
    src_zone: str
    dst_zone: str
    port: str | None = None
    status: ReachabilityStatus
    enabling_qid: int | None = None
    notes: str | None = None


class CredentialRelation(BaseModel):
    """An identity/credential CI valid on more than one host (`cred_rel.csv`) —
    the non-network lateral-movement class a zone-only view misses entirely. Each
    entry in `valid_on` must resolve to a real CI."""

    rel_id: str
    identity_ci: str
    valid_on: list[str] = Field(default_factory=list)
    access_level: str | None = None
    enabling_qid: int | None = None
    issue: str | None = None


class ValidationReport(BaseModel):
    """Structured referential-integrity report for a loaded CMDB. Surfaced by
    `GET /api/cmdb/validate` and logged at load. `ok` is True only when there are
    no defects; the `acmebank` dataset seeds a few deliberate defects to prove
    this fails loud rather than silently dropping the bad rows."""

    dataset: str
    ci_count: int = 0
    relationship_count: int = 0
    # Each defect: {"kind": ..., "detail": ..., "ref": <offending id>}
    dangling_refs: list[dict] = Field(default_factory=list)      # rel/rule/cred endpoint → unknown CI
    orphan_cis: list[dict] = Field(default_factory=list)         # CI with no relationship at all
    zones_without_rules: list[dict] = Field(default_factory=list)  # segment absent from net_reachability
    findings_without_ci: list[dict] = Field(default_factory=list)  # vuln row whose CI_ID resolves to nothing
    duplicate_ci_ids: list[dict] = Field(default_factory=list)
    unknown_rel_types: list[dict] = Field(default_factory=list)  # rel_type not in cmdb_rel_type vocab

    @property
    def defects(self) -> list[dict]:
        out: list[dict] = []
        for bucket in (self.dangling_refs, self.orphan_cis, self.zones_without_rules,
                       self.findings_without_ci, self.duplicate_ci_ids, self.unknown_rel_types):
            out.extend(bucket)
        return out

    @property
    def ok(self) -> bool:
        return not self.defects

    def summary(self) -> str:
        if self.ok:
            return (f"CMDB '{self.dataset}' validated clean "
                    f"({self.ci_count} CIs, {self.relationship_count} relationships).")
        counts = {
            "dangling_refs": len(self.dangling_refs),
            "orphan_cis": len(self.orphan_cis),
            "zones_without_rules": len(self.zones_without_rules),
            "findings_without_ci": len(self.findings_without_ci),
            "duplicate_ci_ids": len(self.duplicate_ci_ids),
            "unknown_rel_types": len(self.unknown_rel_types),
        }
        detail = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
        return (f"CMDB '{self.dataset}' has {len(self.defects)} integrity defect(s): "
                f"{detail} ({self.ci_count} CIs, {self.relationship_count} relationships).")
