"""
Capability classification — the first half of autonomous attack-path discovery.

Every finding is mapped to what an attacker actually *gains* from it, expressed
in ATT&CK-style terms (initial access, execution, credential access, privilege
escalation, lateral movement, segmentation break, impact). This is derived
ENTIRELY from the finding's own content — its Category, CVSS vector, CVE, and
the free-text Description/Consequence — and NEVER from the pre-authored
`Attack_Path_Ref` column. The attack graph (core/attack_graph.py) then composes
these capabilities into chains, so the platform *discovers* paths rather than
reading them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

# --- ATT&CK-aligned effect vocabulary --------------------------------------
INITIAL_ACCESS = "initial_access"      # attacker gains a first foothold from outside a boundary
RCE_SYSTEM = "rce_system"              # remote code execution as SYSTEM/root — full host
RCE_USER = "rce_user"                  # code execution at a lower privilege
CREDENTIAL_THEFT = "credential_theft"  # yields credentials usable elsewhere
PRIV_ESC = "privilege_escalation"      # elevates on current host / to domain / cloud admin
LATERAL = "lateral_move"               # explicit host-to-host movement mechanism
SEGMENTATION_BREAK = "segmentation_break"  # opens a network boundary between zones/hosts
CLOUD_PRIV_ESC = "cloud_priv_esc"      # cloud identity escalation (IAM/Entra)
IMPACT = "impact"                       # terminal business impact (data/exfil/settlement)

# --- Preconditions (what the attacker must already hold to use the finding) --
PRE_UNAUTH = "unauthenticated"          # exploitable with no prior access
PRE_ADJACENT = "network_adjacent"       # needs to be on the same segment
PRE_FOOTHOLD = "foothold_on_host"       # needs code exec on the host already
PRE_CREDS = "valid_creds"               # needs stolen/valid credentials
PRE_CLOUD = "cloud_access"              # needs some cloud access token

# --- Grant tokens (abstract capabilities the attacker holds afterward) -------
GRANT_DOMAIN_ADMIN = "domain_admin"     # AD-wide compromise — reaches any domain host
GRANT_CLOUD_ADMIN = "cloud_admin"       # AWS/Entra tenant admin

RCE_CVES = {
    "CVE-2017-0144", "CVE-2017-5638", "CVE-2021-44228", "CVE-2019-0708",
    "CVE-2021-21972", "CVE-2021-34473",
}

# Keyword signals, compiled once.
_KW = {
    "system": re.compile(r"\b(SYSTEM|root|full host compromise|domain admin)\b", re.I),
    "rce": re.compile(r"remote code execution|\bRCE\b|arbitrary code|webshell|exploit", re.I),
    "cred": re.compile(
        r"credential|password (reuse|disclosure)|kerberoast|cached (domain admin|da)|"
        r"hardcoded|default cred|pass-the-hash|mimikatz|NTLM (leak|hash)|leaked cred|"
        r"shared (domain admin|da) credential|weak master password", re.I),
    "priv": re.compile(
        r"AdministratorAccess|Global Admin|db_owner|privilege escalation|escalat|"
        r"runs as (local )?SYSTEM|excessive privilege|Zerologon|domain admin", re.I),
    "seg": re.compile(
        r"VLAN hop|trunk|any-any|any\s*-\s*any|split-tunnel|split tunnel|flat trust|"
        r"segmentation|db link|database link|inter-vlan|firewall rule|not isolated|"
        r"reach the management|routes remote users|bypassing (network )?segmentation", re.I),
    "impact": re.compile(
        r"exfiltrat|data (exposure|breach)|full .*database (compromise|access)|"
        r"settlement|payment|backup archive|HR/payroll|confidential", re.I),
    "cloud": re.compile(r"\bS3\b|IAM|RDS|Entra|AWS|Azure|cloud", re.I),
}

# VLAN transition patterns — appear in the VLAN_ID column, e.g. "20 -> 21", "10/40".
_VLAN_ARROW = re.compile(r"(\d+)\s*(?:->|→|to)\s*(\d+)", re.I)
_VLAN_SLASH = re.compile(r"(\d+)\s*/\s*(\d+)")
_VLAN_ANY = re.compile(r"VLAN\s*(\d+)", re.I)


@dataclass
class Capability:
    qid: int
    hostname: str
    vlan: str
    technique: str                       # short analyst label
    precondition: str
    effects: list[str] = field(default_factory=list)
    grants: list[str] = field(default_factory=list)       # abstract tokens gained
    zone_transition: tuple[str, str] | None = None        # (from_vlan, to_vlan)
    host_pivots: list[str] = field(default_factory=list)  # explicit downstream hosts
    is_entry: bool = False               # can seed an attack (internet/untrusted reachable)
    mitre_tactic: str = ""

    @property
    def is_edge(self) -> bool:
        """True when the finding itself opens movement (segmentation/lateral)."""
        return bool(self.zone_transition) or bool(self.host_pivots) \
            or SEGMENTATION_BREAK in self.effects


def _parse_vector(vec: str) -> dict[str, str]:
    out = {}
    for part in str(vec).split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _extract_hosts(text: str, known_hosts: set[str], exclude: str) -> list[str]:
    """Pull referenced hostnames out of free text (credential-reuse / DB-link targets)."""
    hits = []
    up = text.upper()
    for h in known_hosts:
        if h and h.upper() != exclude.upper() and re.search(rf"\b{re.escape(h.upper())}\b", up):
            hits.append(h)
    return hits


def _zone_transition(vlan: str, blob: str) -> tuple[str, str] | None:
    """Derive a (from_vlan, to_vlan) boundary crossing from the finding's own fields.

    Segmentation findings encode the crossing in the VLAN_ID column as "20 -> 21"
    or "10/40". Guest/VLAN-hop findings name the destination VLAN only in the
    description text, so fall back to the first *other* VLAN number mentioned.
    """
    m = _VLAN_ARROW.search(vlan) or _VLAN_SLASH.search(vlan)
    if m and m.group(1) != m.group(2):
        return (m.group(1), m.group(2))
    src = re.sub(r"\D", "", str(vlan)) or None
    if src:
        for cand in _VLAN_ANY.findall(blob):
            if cand != src:
                return (src, cand)
    return None


def classify(row: pd.Series, known_hosts: set[str]) -> Capability:
    """Map one finding row to its attacker-capability profile (no Attack_Path_Ref)."""
    title = str(row.get("Title", ""))
    category = str(row.get("Category", ""))
    desc = str(row.get("Description", ""))
    conseq = str(row.get("Consequence", ""))
    cve = str(row.get("CVE_ID", ""))
    zone = str(row.get("Zone", ""))
    host = str(row.get("Hostname", ""))
    vlan = str(row.get("VLAN_ID", "")).strip()
    exposure = str(row.get("Exposure_Tier", ""))
    blob = f"{title} {desc} {conseq}"
    vec = _parse_vector(row.get("CVSS_Vector", ""))
    av, pr = vec.get("AV", "N"), vec.get("PR", "N")

    effects: list[str] = []
    grants: list[str] = []

    is_cloud = bool(_KW["cloud"].search(blob)) or "Cloud" in category
    untrusted = "guest" in zone.lower() or "untrusted" in blob.lower()

    # --- Segmentation / lateral (an EDGE-forming capability) ---
    seg_signal = bool(_KW["seg"].search(blob)) or "Firewall" in category \
        or "Segmentation" in category or "Rules" in category
    # Only segmentation-signalled (or guest-hop) findings define a boundary crossing,
    # so an RCE that merely name-drops another VLAN is never mistaken for a pivot.
    zt = _zone_transition(vlan, blob) if (seg_signal or untrusted) else None
    seg = seg_signal or zt is not None
    host_pivots: list[str] = []
    if seg:
        effects.append(SEGMENTATION_BREAK)
        # explicit host-to-host pivots (e.g. DB link -> SETTLEMENT01)
        if re.search(r"db link|database link", blob, re.I):
            host_pivots = _extract_hosts(blob, known_hosts, host)

    # --- Credential access ---
    if _KW["cred"].search(blob) or "Credential" in category or "Default Credentials" in category \
            or "Secrets" in category:
        effects.append(CREDENTIAL_THEFT)
        # Domain-admin-yielding credential theft reaches the whole domain.
        if re.search(r"domain admin|\bDA\b|kerberoast|zerologon", blob, re.I):
            grants.append(GRANT_DOMAIN_ADMIN)
        # Local-credential reuse links the specifically named hosts.
        reuse = _extract_hosts(blob, known_hosts, host)
        if reuse:
            host_pivots = list(dict.fromkeys(host_pivots + reuse))

    # --- Privilege escalation ---
    if _KW["priv"].search(blob):
        effects.append(PRIV_ESC)
        if is_cloud and re.search(r"AdministratorAccess|Global Admin|IAM", blob, re.I):
            effects.append(CLOUD_PRIV_ESC)
            grants.append(GRANT_CLOUD_ADMIN)
        if re.search(r"zerologon|domain admin", blob, re.I):
            grants.append(GRANT_DOMAIN_ADMIN)

    # --- Execution / RCE ---
    is_rce = cve in RCE_CVES or _KW["rce"].search(blob) or "Missing Patch" in category
    if is_rce and any(k in blob.lower() for k in ("code execution", "rce", "exploit", "webshell")) \
            or cve in RCE_CVES:
        if _KW["system"].search(blob) or cve in {"CVE-2017-0144", "CVE-2019-0708", "CVE-2020-1472"}:
            effects.append(RCE_SYSTEM)
        else:
            effects.append(RCE_USER)

    # --- Impact (terminal) ---
    if _KW["impact"].search(blob) or "share" in blob.lower() and "full control" in blob.lower():
        effects.append(IMPACT)

    # --- Entry / initial access ---
    internet = exposure.lower().startswith("internet") or "internet-facing" in zone.lower() \
        or (is_cloud and re.search(r"public", blob, re.I) is not None)
    is_entry = (av == "N" and pr == "N" and internet) or untrusted or \
        (is_cloud and re.search(r"public (read|access)", blob, re.I) is not None)
    if is_entry:
        effects.insert(0, INITIAL_ACCESS)

    # Precondition
    if is_entry:
        precondition = PRE_UNAUTH
    elif av == "L":
        precondition = PRE_FOOTHOLD
    elif pr in ("L", "H"):
        precondition = PRE_CREDS if pr == "H" else PRE_FOOTHOLD
    elif av == "A":
        precondition = PRE_ADJACENT
    else:
        precondition = PRE_ADJACENT
    if is_cloud and not is_entry:
        precondition = PRE_CLOUD

    if not effects:
        effects.append(RCE_USER if is_rce else LATERAL)

    tactic = _primary_tactic(effects)
    return Capability(
        qid=int(row["QID"]), hostname=host, vlan=vlan,
        technique=_technique_label(title), precondition=precondition,
        effects=list(dict.fromkeys(effects)), grants=list(dict.fromkeys(grants)),
        zone_transition=zt, host_pivots=host_pivots, is_entry=is_entry,
        mitre_tactic=tactic,
    )


def _primary_tactic(effects: list[str]) -> str:
    order = [
        (INITIAL_ACCESS, "Initial Access"), (RCE_SYSTEM, "Execution"),
        (RCE_USER, "Execution"), (PRIV_ESC, "Privilege Escalation"),
        (CLOUD_PRIV_ESC, "Privilege Escalation"), (CREDENTIAL_THEFT, "Credential Access"),
        (SEGMENTATION_BREAK, "Lateral Movement"), (LATERAL, "Lateral Movement"),
        (IMPACT, "Impact"),
    ]
    present = {e for e in effects}
    for eff, tac in order:
        if eff in present:
            return tac
    return "Discovery"


def _technique_label(title: str) -> str:
    return re.sub(r"\s*\(.*?\)\s*$", "", title).strip()[:80]


def classify_all(df: pd.DataFrame) -> dict[int, Capability]:
    known = {str(h) for h in df["Hostname"].unique()}
    return {int(r["QID"]): classify(r, known) for _, r in df.iterrows()}
