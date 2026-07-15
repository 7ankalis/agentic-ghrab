"""
CMDB layer: parses the enterprise architecture Markdown doc into structured
records (network zones, assets, teams, attack-path narrative chains) that the
rest of the platform treats as ground truth. Generic pipe-table parsing means
a differently-named architecture.md (same shape) still ingests correctly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.config import ARCHITECTURE_MD_PATH


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
        self.raw_markdown: str = ""

    def load(self, path=ARCHITECTURE_MD_PATH) -> "CMDB":
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

        self._parse_ci_attack_paths(text)

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

    def summary_text(self, max_chars: int = 6000) -> str:
        """Condensed context block fed to LLM agents (keeps token spend sane)."""
        parts = ["## Network Zones"]
        for z in self.zones:
            parts.append(f"- VLAN {z.vlan} ({z.name}, {z.cidr}): {z.purpose} | "
                          f"Trust={z.trust_level} | Owner={z.owning_team}")
        parts.append("\n## Teams")
        for t in self.teams:
            parts.append(f"- {t.name}: {t.responsible_for} | Assets: {t.example_assets}")
        parts.append("\n## Attack Paths")
        for p in self.attack_paths:
            parts.append(f"- {p.path_id} ({p.difficulty}): {p.title}")
            for s in p.steps:
                parts.append(f"    {s}")
            parts.append(f"    Impact: {p.impact}")
        text = "\n".join(parts)
        return text[:max_chars]


_cmdb_singleton: CMDB | None = None


def get_cmdb() -> CMDB:
    global _cmdb_singleton
    if _cmdb_singleton is None:
        _cmdb_singleton = CMDB().load()
    return _cmdb_singleton
