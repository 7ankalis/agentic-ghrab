"""
Deterministic Ghrab Risk Score (GRS) engine — implements ghrab_risk_methodology.md
exactly. This runs with zero API keys: severity, exploitation likelihood (EPSS),
known-exploited status (KEV), asset criticality (ACW), toxic-combination /
blast-radius (TCM) and exposure tier are all derived from the CSV + the
architecture doc's own asset/team/attack-path tables, not guessed by an LLM.
This is deliberately the trust anchor of the whole platform: LLM agents may
*explain* a GRS, they never compute or override it.
"""
from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Per-finding enrichment table (QID -> factors), derived from:
#   - ghrab_risk_methodology.md §3 (Asset Criticality Weight tiers)
#   - ghrab_risk_methodology.md §4 (Toxic Combination Score bands)
#   - ghrab_risk_methodology.md §5 (Exposure/Reachability tiers)
#   - ghrab_architecture.md §5 (attack path chains, used to derive TCM)
#   - Public KEV/EPSS status of the real CVEs used in this lab
# ---------------------------------------------------------------------------

EXPOSURE_TIERS = {
    "internet_facing": 1.30,
    "adjacent": 1.15,
    "internal": 0.90,
    "restricted": 0.50,
    "isolated": 0.15,
}

# KEV = CISA Known Exploited Vulnerabilities catalog membership (binary gate)
KEV_CVES = {
    "CVE-2017-0144", "CVE-2020-1472", "CVE-2021-44228", "CVE-2019-0708",
    "CVE-2021-34473", "CVE-2018-13379", "CVE-2021-21972", "CVE-2023-23397",
    "CVE-2017-5638",
}

# Representative EPSS probabilities (0-1). See methodology §10 caveat: pull
# live from FIRST.org in a production deployment.
EPSS_BY_CVE = {
    "CVE-2017-0144": 0.94, "CVE-2020-1472": 0.97, "CVE-2021-44228": 0.97,
    "CVE-2019-0708": 0.90, "CVE-2021-34473": 0.94, "CVE-2018-13379": 0.93,
    "CVE-2021-21972": 0.85, "CVE-2023-23397": 0.60, "CVE-2017-5638": 0.92,
    "CVE-2023-30777": 0.35,
}

# QID -> (exposure_tier_key, ACW 0-1, TCM 0-10, is_dora_cif)
FINDING_FACTORS: dict[int, tuple[str, float, int, bool]] = {
    105001: ("adjacent", 0.35, 3, False),      # A1 guest VLAN hop
    38689:  ("internal", 0.35, 4, False),      # A2 EternalBlue on WKS-HR02
    90013:  ("internal", 0.60, 4, False),      # A3 local admin reuse -> FILESRV01
    150220: ("internal", 0.60, 5, False),      # A4 HR share exposure
    11827:  ("internet_facing", 0.55, 3, False),  # B1 WordPress SQLi
    11831:  ("internet_facing", 0.55, 4, False),  # B2 webshell upload
    200114: ("adjacent", 0.55, 5, False),      # B3 DMZ->AppTier ANY-ANY
    13398:  ("internal", 0.60, 6, False),      # B4 Struts2 RCE
    200338: ("internal", 0.60, 6, False),      # B5 db_owner excessive on DB-CRM01
    300011: ("internet_facing", 0.60, 5, False),  # C1 public S3 bucket
    300045: ("adjacent", 0.75, 7, False),      # C2 IAM AdministratorAccess
    300067: ("internet_facing", 0.88, 8, True),   # C3 public RDS weak password
    43111:  ("internet_facing", 0.55, 5, False),  # D1 FortiOS path traversal
    200401: ("adjacent", 0.55, 6, False),      # D2 VPN split-tunnel to mgmt
    90211:  ("isolated", 0.75, 7, False),      # D3 cached DA creds on JUMP01
    43287:  ("isolated", 0.75, 8, False),      # D4 vCenter RCE
    200455: ("isolated", 0.75, 8, False),      # D5 Veeam default creds
    90344:  ("internal", 1.00, 7, True),       # E1 Kerberoastable svc_trade
    90512:  ("internal", 1.00, 9, True),       # E2 Zerologon
    200512: ("internal", 1.00, 9, True),       # E3 flat trust corp->finance
    45923:  ("internal", 1.00, 10, True),      # E4 BlueKeep on TRADE-CORE01
    200533: ("internal", 1.00, 10, True),      # E5 SWIFT shared DA credential
    150221: ("internal", 0.88, 8, True),       # F1 Log4Shell on APP-TRADE01
    200601: ("internal", 0.88, 8, True),       # F2 service running as SYSTEM
    150233: ("internal", 0.88, 8, True),       # F3 hardcoded DB creds
    200622: ("internal", 0.88, 9, True),       # F4 excessive DB link -> settlement
    105102: ("restricted", 0.75, 5, False),    # Standalone: anonymous SMB on NAS01
    200711: ("internal", 0.35, 1, False),      # Standalone: any-any on branch router
    43055:  ("internet_facing", 0.55, 2, False),  # Standalone: ProxyShell
    200788: ("adjacent", 0.75, 6, False),      # Standalone: excessive Entra Global Admin
    43602:  ("internal", 0.35, 3, False),      # Standalone: Outlook NTLM leak
    200812: ("adjacent", 1.00, 7, True),       # Standalone: CDE segmentation gap
}

ACTION_BANDS = [
    (80, 100, "IMMEDIATE", "24-72h, emergency change"),
    (60, 79, "ACT", "7 days"),
    (40, 59, "ATTEND", "30 days"),
    (20, 39, "TRACK*", "90 days / next patch cycle"),
    (0, 19, "TRACK", "Monitor only"),
]


@dataclass
class GRSResult:
    grs: float
    band: str
    sla: str
    impact_score: float
    exposure_tier: str
    exposure_multiplier: float
    cvss: float
    epss: float
    kev: bool
    acw: float
    tcm: int
    ccf: float
    is_dora_cif: bool
    dora_sla_capped: bool


def compute_grs(qid: int, cvss: float, cve_id: str) -> GRSResult:
    exposure_key, acw, tcm, is_cif = FINDING_FACTORS.get(
        qid, ("internal", 0.5, 3, False)
    )
    epss = EPSS_BY_CVE.get(cve_id, 0.0)
    kev = cve_id in KEV_CVES
    ccf = 1.0  # no verified compensating controls exist in this environment (methodology §6)

    cvss_norm = cvss
    epss_norm = epss * 10
    kev_norm = 10 if kev else 0
    acw_norm = acw * 10
    tcm_norm = tcm

    impact_score = 10 * (
        0.30 * cvss_norm + 0.15 * epss_norm + 0.15 * kev_norm
        + 0.20 * acw_norm + 0.20 * tcm_norm
    )
    exposure_mult = EXPOSURE_TIERS[exposure_key]
    grs = min(100.0, impact_score * exposure_mult * ccf)

    band, sla = "TRACK", "Monitor only"
    for lo, hi, b, s in ACTION_BANDS:
        if lo <= grs <= hi:
            band, sla = b, s
            break

    dora_capped = False
    if is_cif:
        # DORA RTS Art.10 overlay: SLA capped at 30 days regardless of computed band
        if band in ("TRACK*", "TRACK"):
            sla = "30 days (DORA CIF overlay)"
            dora_capped = True
        elif "30 days" not in sla and "7 days" not in sla and "72h" not in sla:
            dora_capped = True

    return GRSResult(
        grs=round(grs, 1), band=band, sla=sla, impact_score=round(impact_score, 1),
        exposure_tier=exposure_key, exposure_multiplier=exposure_mult,
        cvss=cvss, epss=epss, kev=kev, acw=acw, tcm=tcm, ccf=ccf,
        is_dora_cif=is_cif, dora_sla_capped=dora_capped,
    )


def exposure_tier_label(key: str) -> str:
    return {
        "internet_facing": "Internet-facing", "adjacent": "Adjacent",
        "internal": "Internal", "restricted": "Restricted", "isolated": "Isolated",
    }.get(key, key)
