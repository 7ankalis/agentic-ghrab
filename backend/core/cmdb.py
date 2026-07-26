"""
CMDB layer: parses the enterprise architecture Markdown doc into structured
records (network zones, assets, teams, attack-path narrative chains) that the
rest of the platform treats as ground truth. Generic pipe-table parsing means
a differently-named architecture.md (same shape) still ingests correctly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.config import active_architecture_md

_PAREN_RE = re.compile(r"\(([^)]+)\)")
_QID_RE = re.compile(r"QID\s*(\d+)", re.I)


def _paren_host(s: str) -> str:
    m = _PAREN_RE.search(str(s))
    return m.group(1).strip() if m else ""


def _first_qid(s: str) -> int | None:
    m = _QID_RE.search(str(s))
    return int(m.group(1)) if m else None


@dataclass
class Zone:
    vlan: str
    name: str
    cidr: str
    purpose: str
    trust_level: str
    owning_team: str


@dataclass
class Asset:
    hostname: str
    ip: str
    role: str
    notable_issue: str
    vlan: str = ""
    zone_name: str = ""


@dataclass
class Team:
    name: str
    responsible_for: str
    example_assets: str


@dataclass
class AttackPath:
    path_id: str          # e.g. "PATH-A"
    title: str
    difficulty: str
    steps: list[str] = field(default_factory=list)   # human-readable step lines
    impact: str = ""


def _split_row(line: str) -> list[str]:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return cells


def _parse_markdown_tables(md_text: str) -> list[list[list[str]]]:
    """Return a list of tables, each a list of rows, each row a list of cells."""
    lines = md_text.splitlines()
    tables = []
    current: list[list[str]] = []
    in_table = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|"):
            if re.match(r"^\|[\s:|-]+\|$", stripped):
                in_table = True
                continue
            current.append(_split_row(stripped))
            in_table = True
        else:
            if in_table and current:
                tables.append(current)
            current = []
            in_table = False
    if current:
        tables.append(current)
    return tables


class CMDB:
    def __init__(self):
        self.zones: list[Zone] = []
        self.assets: list[Asset] = []
        self.teams: list[Team] = []
        self.attack_paths: list[AttackPath] = []
        # Grounding relationships parsed from the architecture doc (§2–§5). These
        # are the raw material an analyst reasons FROM to derive attack paths —
        # they are NOT attack paths themselves. The documented paths live only in
        # the held-out oracle (core/oracle.py); the CMDB never carries them.
        self.hosting_relations: list[str] = []      # §2 virtualization / hosting
        self.reachability_rules: list[str] = []     # §3 zone-to-zone reachability
        self.dependencies: list[str] = []           # §4 host/app/db dependencies
        self.cred_relations: list[str] = []         # §5 identity/credential reuse
        # Structured §4 dependency edges (host→host pivots) with the enabling
        # relationship id + any cited QID, resolved to real asset names. This is
        # what the reachability graph builds app→db / hypervisor / backup / cloud
        # pivots from, instead of hardcoded VLAN-tier assumptions (Phase 2).
        self.dependency_edges: list[dict] = []
        # Structured §3 reachability rows (src/dst zone ci + vlan, status, rule id,
        # enabling qid) from a CSV-backed dataset. Text goes to reachability_rules
        # for grounding parity; this typed list is what Phase 3 turns into real
        # zone-to-zone edges + Should-Not-Exist vetoes. Empty for markdown datasets.
        self.reachability_edges: list[dict] = []
        # Set only for CSV-backed datasets: the raw schema records (core/cmdb_store)
        # and the referential-integrity report surfaced by GET /api/cmdb/validate.
        self.structured = None
        self.validation_report = None
        self.raw_markdown: str = ""

    def _resolve_asset(self, raw: str) -> str:
        """Best-effort map a §4 CI reference ('SRV-GH-1020 (APP-CRM01)',
        'CLD-GH-5001 (S3 ghrab-public-assets)') to a real asset hostname."""
        n = _paren_host(raw) or str(raw).strip()
        names = [a.hostname for a in self.assets]
        if n in names:
            return n
        low = n.lower()
        for h in names:
            if h and (h.lower() == low or low.endswith(h.lower()) or h.lower() in low):
                return h
        return n

    def load(self, path=None) -> "CMDB":
        # Two source-of-truth shapes: a CSV-backed relational CMDB (a directory of
        # cmdb_ci_*.csv + cmdb_rel_ci.csv, the ServiceNow export shape) or the
        # legacy markdown architecture doc. A directory ⇒ CSV; a file ⇒ markdown.
        # With no explicit path we resolve from the active dataset, which knows
        # which kind it is (core/datasets.py).
        if path is None:
            from core.config import active_cmdb_dir
            cmdb_dir = active_cmdb_dir()
            if cmdb_dir is not None:
                return self._load_csv_format(cmdb_dir)
            path = active_architecture_md()
        elif path.is_dir():
            return self._load_csv_format(path)
        text = path.read_text(encoding="utf-8")
        self.raw_markdown = text
        # Two known doc shapes: the legacy "## 3. Asset Inventory" prose-table
        # format, and the newer CI-based "## 1. CI Inventory" ServiceNow-style
        # format (CI ID / Rule ID / Relationship ID cross-referenced). Detect
        # which one this file is rather than assuming — a silent parser/format
        # mismatch here means zones+assets+teams all come back empty, which
        # starves every downstream agent (deterministic graph AND the LLM
        # layer) of grounding without raising any error.
        if re.search(r"^##\s*1\.\s*CI Inventory", text, re.M):
            self._load_ci_format(text)
        else:
            self._load_legacy_format(text)
        self._link_assets_to_zones()
        return self

    def _load_csv_format(self, cmdb_dir) -> "CMDB":
        """Load a relational CSV-backed CMDB. Populates the same fields the
        markdown parsers fill (zones/assets/teams/dependency_edges/…) plus the
        structured reachability_edges + validation_report, then links zones."""
        from pathlib import Path

        from core import cmdb_store
        cmdb_dir = Path(cmdb_dir)
        dataset = cmdb_dir.parent.name
        cmdb_store.build_cmdb(self, cmdb_dir, dataset)
        self._link_assets_to_zones()
        return self

    def _load_legacy_format(self, text: str) -> None:
        tables = _parse_markdown_tables(text)

        for table in tables:
            if not table:
                continue
            header = [h.lower() for h in table[0]]
            rows = table[1:]

            if "vlan" in header and "zone name" in header:
                for r in rows:
                    d = dict(zip(header, r))
                    self.zones.append(Zone(
                        vlan=d.get("vlan", ""), name=d.get("zone name", ""),
                        cidr=d.get("cidr", ""), purpose=d.get("purpose", ""),
                        trust_level=d.get("trust level", ""),
                        owning_team=d.get("owning team", ""),
                    ))
            elif "team" in header and "responsible for" in header:
                for r in rows:
                    d = dict(zip(header, r))
                    self.teams.append(Team(
                        name=d.get("team", ""),
                        responsible_for=d.get("responsible for", ""),
                        example_assets=d.get("example owned assets", ""),
                    ))

        self._parse_assets_with_zones(text)
        self._parse_attack_paths(text)

    # -- CI-based format (§1 CI Inventory / §3 Rule Base / §6 Attack Paths) ----

    def _section(self, text: str, start_pat: str, end_pat: str) -> str | None:
        m = re.search(f"{start_pat}.*?(?={end_pat}|\\Z)", text, re.S)
        return m.group(0) if m else None

    def _load_ci_format(self, text: str) -> None:
        # CI ID -> (vlan number as string, human zone name), built from the
        # Network Segments table so server/cloud rows (which only cite a Zone
        # CI ID) can be resolved to the vlan numbers attack_graph.py keys off.
        zone_map: dict[str, tuple[str, str]] = {}
        seg = self._section(text, r"### 1\.1 Network Segments", r"\n###\s")
        if seg:
            for table in _parse_markdown_tables(seg):
                if not table or "name" not in [h.lower() for h in table[0]]:
                    continue
                header = [h.lower() for h in table[0]]
                for r in table[1:]:
                    d = dict(zip(header, r))
                    ci_id, name = d.get("ci id", "").strip(), d.get("name", "").strip()
                    if not ci_id or not name:
                        continue
                    vlan_m = re.search(r"VLAN\s*(\d+)", name, re.I)
                    if vlan_m:
                        vlan = vlan_m.group(1)
                        zone_name = re.sub(r"^VLAN\s*\d+\s*—\s*", "", name).strip()
                    elif "cloud" in name.lower():
                        vlan, zone_name = "Cloud", name
                    elif "internet" in name.lower():
                        vlan, zone_name = "INTERNET", name
                    else:
                        vlan, zone_name = "", name
                    zone_map[ci_id] = (vlan, zone_name)
                    self.zones.append(Zone(
                        vlan=vlan, name=zone_name, cidr=d.get("cidr", ""), purpose="",
                        trust_level=d.get("trust level", ""),
                        owning_team=d.get("owning support group", ""),
                    ))

        team_assets: dict[str, list[str]] = {}

        srv = self._section(text, r"### 1\.2 Servers", r"\n###\s")
        if srv:
            for table in _parse_markdown_tables(srv):
                if not table or "name" not in [h.lower() for h in table[0]]:
                    continue
                header = [h.lower() for h in table[0]]
                for r in table[1:]:
                    d = dict(zip(header, r))
                    hostname = d.get("name", "").strip().strip("`")
                    if not hostname:
                        continue
                    vlan, zone_name = zone_map.get(d.get("zone", "").strip(), ("", ""))
                    self.assets.append(Asset(
                        hostname=hostname, ip=d.get("ip", ""), role=d.get("platform", ""),
                        notable_issue=d.get("criticality", ""), vlan=vlan, zone_name=zone_name,
                    ))
                    grp = d.get("support group", "").strip()
                    if grp:
                        team_assets.setdefault(grp, []).append(hostname)

        cloud = self._section(text, r"### 1\.4 Cloud Services", r"\n###\s")
        if cloud:
            for table in _parse_markdown_tables(cloud):
                if not table or "name" not in [h.lower() for h in table[0]]:
                    continue
                header = [h.lower() for h in table[0]]
                for r in table[1:]:
                    d = dict(zip(header, r))
                    # cloud CI names are "Blob: velon-imaging-archive" etc — the CSV
                    # Hostname column carries only the resource name after the colon.
                    hostname = d.get("name", "").split(": ", 1)[-1].strip().strip("`")
                    if not hostname:
                        continue
                    self.assets.append(Asset(
                        hostname=hostname, ip="", role=d.get("type", ""),
                        notable_issue=d.get("criticality", ""), vlan="Cloud", zone_name="Cloud",
                    ))
                    grp = d.get("support group", "").strip()
                    if grp:
                        team_assets.setdefault(grp, []).append(hostname)

        grp = self._section(text, r"### 1\.7 Support Groups", r"\n##\s")
        if grp:
            for table in _parse_markdown_tables(grp):
                if not table or "name" not in [h.lower() for h in table[0]]:
                    continue
                header = [h.lower() for h in table[0]]
                for r in table[1:]:
                    d = dict(zip(header, r))
                    name = d.get("name", "").strip()
                    group_id = d.get("group id", "").strip()
                    if not name:
                        continue
                    self.teams.append(Team(
                        name=name, responsible_for=d.get("responsible for", ""),
                        example_assets=", ".join(team_assets.get(group_id, [])),
                    ))

        self._parse_relationships(text)

    def _relationship_table(self, text: str, start_pat: str, require: str):
        """First markdown table inside the given section whose header contains
        `require` (lowercased) — used to pull §2–§5 relationship tables robustly
        regardless of column ordering. Returns (header, rows) or (None, [])."""
        section = self._section(text, start_pat, r"\n## ")
        if not section:
            return None, []
        for table in _parse_markdown_tables(section):
            if not table:
                continue
            header = [h.lower() for h in table[0]]
            if require in header:
                return header, table[1:]
        return None, []

    def _parse_relationships(self, text: str) -> None:
        """Parse the network/identity relationship tables (§2 hosting, §3
        reachability, §4 dependencies, §5 credentials) into condensed, analyst-
        readable lines. This is the grounding an agent needs to independently
        reason out attack paths — deliberately NOT the paths themselves."""
        # §2 Virtualization / Hosting — the hypervisor blast-radius relationship
        header, rows = self._relationship_table(text, r"## 2\. Virtualization", "guest ci")
        for r in rows:
            d = dict(zip(header, r))
            guest, rel, host = d.get("guest ci", ""), d.get("relationship", ""), d.get("host ci", "")
            if guest and host:
                self.hosting_relations.append(f"{guest} {rel or 'hosted on'} {host}")

        # §3 Network Reachability Rule Base — 'Excessive' rows are the misconfigs
        # that actually open a zone boundary; 'Should-Not-Exist' rows are absent paths.
        header, rows = self._relationship_table(text, r"## 3\. Network Reachability", "source zone")
        for r in rows:
            d = dict(zip(header, r))
            rid = d.get("rule id", "")
            src, dst = d.get("source zone", ""), d.get("destination zone", "")
            status, notes = d.get("status", ""), d.get("notes", "")
            port = d.get("port/protocol", d.get("port", ""))
            if src and dst:
                self.reachability_rules.append(
                    f"{rid}: {src} → {dst} ({port}) [{status}]"
                    + (f" — {notes}" if notes else "")
                )

        # §4 Host / App / DB dependency relationships
        header, rows = self._relationship_table(text, r"## 4\. Host, Application", "source ci")
        for r in rows:
            d = dict(zip(header, r))
            rid = d.get("relationship id", "")
            src, rtype, tgt = d.get("source ci", ""), d.get("relationship type", ""), d.get("target ci", "")
            flag, just = d.get("flag", ""), d.get("justification", "")
            if src and tgt:
                self.dependencies.append(
                    f"{rid}: {src} --[{rtype}]--> {tgt}"
                    + (f" [{flag}]" if flag else "") + (f" — {just}" if just else "")
                )
                self.dependency_edges.append({
                    "rel_id": rid,
                    "src_host": self._resolve_asset(src),
                    "dst_host": self._resolve_asset(tgt),
                    "rtype": str(rtype).strip(),
                    "flag": str(flag).strip(),
                    "qid": _first_qid(f"{flag} {just}"),
                    "label": f"{rid}: {rtype}".strip(),
                })

        # §5 Identity & Credential relationships — a credential valid on >1 CI is a
        # non-network pivot, the class of move a zone-only view misses entirely.
        header, rows = self._relationship_table(text, r"## 5\. Identity", "valid on (ci id)")
        for r in rows:
            d = dict(zip(header, r))
            cid = d.get("relationship id", "")
            ident = d.get("credential/identity ci", "")
            valid_on = d.get("valid on (ci id)", "")
            access, issue = d.get("access level granted", ""), d.get("issue", "")
            if ident and valid_on:
                self.cred_relations.append(
                    f"{cid}: {ident} valid on [{valid_on}] → {access}"
                    + (f" — {issue}" if issue else "")
                )

    def _parse_ci_attack_paths(self, text: str) -> None:
        section = self._section(text, r"## 6\. Attack Paths", r"\n## 7\.")
        if not section:
            return
        for block in re.split(r"(?=### PATH )", section):
            m = re.match(r"### (PATH [A-Z]) — (\w[\w/]*): (.+)", block)
            if not m:
                continue
            path_letter, difficulty, title = m.groups()
            steps: list[str] = []
            for table in _parse_markdown_tables(block):
                header = [h.lower() for h in table[0]] if table else []
                if "step" not in header:
                    continue
                for r in table[1:]:
                    d = dict(zip(header, r))
                    enabler = d.get("enabler (type: ref id)", d.get("enabler", ""))
                    steps.append(
                        f"{d.get('step', '')}: {d.get('source ci', '')} "
                        f"--[{enabler}]--> {d.get('target ci', '')} "
                        f"(QID {d.get('finding qid', '')}) => {d.get('access gained', '')}"
                    )
            impact_m = re.search(r"\*\*Impact:\*\*\s*(.+)", block)
            self.attack_paths.append(AttackPath(
                path_id="PATH-" + path_letter.split()[-1], title=title.strip(),
                difficulty=difficulty.strip(), steps=steps,
                impact=impact_m.group(1).strip() if impact_m else "",
            ))

    def _parse_assets_with_zones(self, text: str) -> None:
        """Parse the §3 asset inventory, tracking each `### 3.x Zone (VLAN n)`
        heading so every asset carries its VLAN/zone — including crown-jewel hosts
        (e.g. SETTLEMENT01) that have no scan finding, and the cloud assets whose
        table uses Asset/Type columns instead of Host/IP/Role."""
        inv = re.search(r"## 3\. Asset Inventory.*?(?=\n## 4\.|\Z)", text, re.S)
        if not inv:
            return
        section = inv.group(0)
        # split into 3.x subsections, keeping the heading with its body
        blocks = re.split(r"(?=###\s+3\.\d+)", section)
        for block in blocks:
            head = re.match(r"###\s+3\.\d+\s+(.+)", block)
            if not head:
                continue
            heading = head.group(1)
            vlan_m = re.search(r"VLAN\s*(\w+)", heading)
            vlan = vlan_m.group(1) if vlan_m else ("Cloud" if "cloud" in heading.lower() else "")
            zone_name = re.sub(r"\s*\(.*", "", heading).strip()
            for table in _parse_markdown_tables(block):
                if not table:
                    continue
                header = [h.lower() for h in table[0]]
                name_key = "host" if "host" in header else ("asset" if "asset" in header else None)
                if not name_key:
                    continue
                for r in table[1:]:
                    d = dict(zip(header, r))
                    name = d.get(name_key, "").strip().strip("`")
                    if not name:
                        continue
                    self.assets.append(Asset(
                        hostname=name, ip=d.get("ip", ""),
                        role=d.get("role", d.get("type", "")),
                        notable_issue=d.get("notable issue", ""),
                        vlan=str(vlan), zone_name=zone_name,
                    ))

    def _parse_attack_paths(self, text: str) -> None:
        section_match = re.search(r"## 5\. Attack Paths.*?(?=\n## 6\.|\Z)", text, re.S)
        if not section_match:
            return
        section = section_match.group(0)
        path_blocks = re.split(r"(?=### PATH )", section)
        for block in path_blocks:
            m = re.match(r"### (PATH [A-Z]) — (\w[\w/]*): (.+)", block)
            if not m:
                continue
            path_letter, difficulty, title = m.groups()
            path_id = "PATH-" + path_letter.split()[-1]
            steps = re.findall(r"^\d+\.\s+\*\*(.+?)\*\*\s+—\s+(.+)$", block, re.M)
            impact_m = re.search(r"\*\*Impact:\*\*\s*(.+)", block)
            self.attack_paths.append(AttackPath(
                path_id=path_id, title=title.strip(), difficulty=difficulty.strip(),
                steps=[f"{step_id}: {desc}" for step_id, desc in steps],
                impact=impact_m.group(1).strip() if impact_m else "",
            ))

    def _link_assets_to_zones(self) -> None:
        vlan_by_name = {z.name: z.vlan for z in self.zones}
        for asset in self.assets:
            pass  # zone linkage is done at the finding level via CSV VLAN_ID/Zone columns

    def team_for_asset(self, hostname: str) -> str:
        for team in self.teams:
            if hostname.lower() in team.example_assets.lower():
                return team.name
        return ""

    def grounding_context(self, max_chars: int = 7000) -> str:
        """The CMDB context fed to every LLM agent: the raw asset inventory,
        ownership, and network/identity relationships an analyst reasons FROM —
        and deliberately NOT any attack path. The documented paths are held out
        in the oracle (core/oracle.py); the whole point of the redesign is that
        the agents rediscover chains from this grounding, not read them off a
        pre-solved list. Sections are ordered by how much they drive path
        reasoning, so truncation drops the least critical material first."""
        parts = ["## Network Zones (VLAN — name — trust level — owning team)"]
        for z in self.zones:
            parts.append(f"- VLAN {z.vlan} — {z.name} ({z.cidr}): {z.purpose} | "
                         f"trust={z.trust_level} | owner={z.owning_team}")

        parts.append("\n## Asset Inventory (host — zone — role/platform — criticality — owner)")
        for a in self.assets:
            owner = self.team_for_asset(a.hostname)
            zone = a.zone_name or (f"VLAN {a.vlan}" if a.vlan else "")
            parts.append(
                f"- {a.hostname} — {zone} — {a.role or '?'}"
                + (f" — {a.notable_issue}" if a.notable_issue else "")
                + (f" — owner: {owner}" if owner else "")
            )

        parts.append("\n## Teams / Ownership")
        for t in self.teams:
            parts.append(f"- {t.name}: {t.responsible_for} | owns: {t.example_assets}")

        if self.reachability_rules:
            parts.append("\n## Network Reachability Rules (zone-to-zone; 'Excessive' = a "
                         "misconfiguration that opens a boundary, 'Should-Not-Exist' = no path)")
            parts += [f"- {r}" for r in self.reachability_rules]

        if self.cred_relations:
            parts.append("\n## Identity & Credential Relationships (a credential valid on more "
                         "than one CI is a lateral pivot that involves no network rule)")
            parts += [f"- {c}" for c in self.cred_relations]

        if self.dependencies:
            parts.append("\n## Host / App / DB Dependencies")
            parts += [f"- {d}" for d in self.dependencies]

        if self.hosting_relations:
            parts.append("\n## Virtualization / Hosting (compromise of a host CI implies "
                         "compromise of every guest it hosts)")
            parts += [f"- {h}" for h in self.hosting_relations]

        return "\n".join(parts)[:max_chars]

    # Back-compat alias: some callers still ask for summary_text(). It now returns
    # the grounded context (no attack paths), so nothing can accidentally surface
    # the old pre-solved-paths block to an agent.
    def summary_text(self, max_chars: int = 7000) -> str:
        return self.grounding_context(max_chars)


_cmdb_singleton: CMDB | None = None


def get_cmdb() -> CMDB:
    global _cmdb_singleton
    if _cmdb_singleton is None:
        _cmdb_singleton = CMDB().load()
    return _cmdb_singleton


def reset_cmdb() -> None:
    """Drop the parsed CMDB so the next access re-parses the (now different)
    active dataset's architecture doc. Called when the operator switches enterprise."""
    global _cmdb_singleton
    _cmdb_singleton = None
