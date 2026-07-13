"""Agent 3 — Threat Intelligence Enrichment (non-AI here: a static lookup,
not live tool-calling).

ghrab_risk_methodology.md §10 says outright: "EPSS and KEV values in the
scored CSV are representative, chosen using well-established public status
for the real CVEs used in this lab ... In a live pipeline, pull EPSS daily
from the FIRST.org API and KEV status from CISA's published catalog rather
than hardcoding them." This module is exactly that static table — there is
no network egress available in this environment to call FIRST.org/CISA live,
so this ships the same shortcut the methodology doc explicitly sanctions,
with a clearly marked seam (`fetch_live_threat_intel`) for wiring the real
feeds later without touching any caller.

Every CVE below is confirmed on the CISA KEV catalog; EPSS values are
representative point-in-time estimates for well-known, heavily weaponized
vulnerabilities (EternalBlue, Zerologon, Log4Shell, etc. all score in the
0.85-0.97 range in practice). The two WordPress plugin CVEs are low-profile
and not KEV-listed, which is deliberately the doc's own mirror scenario for
"actively exploited but not yet in KEV" (methodology §8's worked example B).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from vmc.models import ThreatIntel

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+")

# cve_id -> (epss_score, in_kev)
STATIC_THREAT_INTEL: dict[str, tuple[float, bool]] = {
    "CVE-2017-0144": (0.97, True),  # EternalBlue
    "CVE-2020-1472": (0.94, True),  # Zerologon
    "CVE-2021-44228": (0.97, True),  # Log4Shell
    "CVE-2019-0708": (0.90, True),  # BlueKeep
    "CVE-2021-34473": (0.94, True),  # ProxyShell
    "CVE-2018-13379": (0.94, True),  # FortiOS SSL-VPN path traversal
    "CVE-2021-21972": (0.85, True),  # vCenter RCE
    "CVE-2023-23397": (0.60, True),  # Outlook NTLM leak
    "CVE-2017-5638": (0.94, True),  # Apache Struts2 (Equifax-class)
    "CVE-2023-30777": (0.55, False),  # WordPress plugin SQLi — low-profile, not KEV-listed
    "CVE-2023-30778": (0.45, False),  # chained webshell upload — low-profile, not KEV-listed
}

_DEFAULT_EPSS = 0.05  # unrecognized/unknown CVE: assume low exploitation likelihood, not zero


def _normalize_cve_id(cve_id: str) -> str | None:
    match = _CVE_ID_RE.search(cve_id)
    return match.group(0) if match else None


def enrich_cve(cve_id: str) -> ThreatIntel:
    normalized = _normalize_cve_id(cve_id)
    epss, in_kev = STATIC_THREAT_INTEL.get(normalized, (_DEFAULT_EPSS, False)) if normalized else (_DEFAULT_EPSS, False)
    return ThreatIntel(
        cve_id=cve_id,
        epss_score=epss,
        in_kev=in_kev,
        exploit_maturity="weaponized" if in_kev else "unknown",
        sources=["static reference table (see agents/threat_intel.py docstring)"],
        fetched_at=datetime.now(timezone.utc),
    )


def run_agent3(cve_ids: set[str]) -> dict[str, ThreatIntel]:
    """Dedup by CVE (methodology's own cost/latency guidance) — a findings
    set with many rows for the same CVE across hosts only needs one lookup."""
    return {cve_id: enrich_cve(cve_id) for cve_id in cve_ids}


async def fetch_live_threat_intel(cve_id: str) -> ThreatIntel:  # pragma: no cover - not wired, documented seam
    """Not implemented: no network egress in this environment. Replace
    `run_agent3`'s static-table lookup with calls to this once FIRST.org's
    EPSS API and CISA's KEV JSON feed are reachable from the deployment."""
    raise NotImplementedError("live EPSS/KEV enrichment is not wired — see module docstring")
