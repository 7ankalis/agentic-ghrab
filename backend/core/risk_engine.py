"""
Deterministic Ghrab Risk Score (GRS) engine — implements ghrab_risk_methodology.md
exactly. This runs with zero API keys: severity, exploitation likelihood (EPSS),
known-exploited status (KEV), asset criticality (ACW), toxic-combination /
blast-radius (TCM) and exposure tier are all derived from the CSV + the
architecture doc's own asset/team/attack-path tables, not guessed by an LLM.
This is deliberately the trust anchor of the whole platform: LLM agents may
*explain* a GRS, they never compute or override it.

FINDING_FACTORS/EPSS_BY_CVE/KEV_CVES are hand-enriched per finding, so they are
keyed by QID/CVE and hold entries for every lab dataset the platform ships with
(currently Ghrab Financial Group and Velon Health Systems). QID and CVE
namespaces don't collide across labs, so the tables are simply unioned rather
than switched on the active tenant — compute_grs() has no notion of "which lab"
it's scoring, only "which QID/CVE". Adding a new lab means adding its rows here,
derived from that lab's own architecture.md attack-path/CI tables.
"""
from __future__ import annotations

import re
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

# KEV = CISA Known Exploited Vulnerabilities catalog membership (binary gate).
# Ghrab CVEs first, Velon CVEs below — namespaces don't collide.
KEV_CVES = {
    "CVE-2017-0144", "CVE-2020-1472", "CVE-2021-44228", "CVE-2019-0708",
    "CVE-2021-34473", "CVE-2018-13379", "CVE-2021-21972", "CVE-2023-23397",
    "CVE-2017-5638",
    # Velon Health Systems
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2018-7600",   # Drupalgeddon2
    "CVE-2020-14882",  # Oracle WebLogic RCE
    "CVE-2022-40684",  # FortiOS auth bypass
    "CVE-2021-22005",  # vCenter arbitrary file upload RCE
    "CVE-2022-22965",  # Spring4Shell
}

# Representative EPSS probabilities (0-1). See methodology §10 caveat: pull
# live from FIRST.org in a production deployment.
EPSS_BY_CVE = {
    "CVE-2017-0144": 0.94, "CVE-2020-1472": 0.97, "CVE-2021-44228": 0.97,
    "CVE-2019-0708": 0.90, "CVE-2021-34473": 0.94, "CVE-2018-13379": 0.93,
    "CVE-2021-21972": 0.85, "CVE-2023-23397": 0.60, "CVE-2017-5638": 0.92,
    "CVE-2023-30777": 0.35,
    # Velon Health Systems
    "CVE-2021-34527": 0.94,  # PrintNightmare
    "CVE-2018-7600": 0.94,   # Drupalgeddon2
    "CVE-2020-14882": 0.94,  # Oracle WebLogic RCE
    "CVE-2022-40684": 0.93,  # FortiOS auth bypass
    "CVE-2021-22005": 0.92,  # vCenter arbitrary file upload RCE
    "CVE-2020-0796": 0.40,   # SMBGhost — wormable but no confirmed mass ITW
    "CVE-2021-42278": 0.85,  # noPac (sAMAccountName spoofing)
    "CVE-2019-12255": 0.15,  # VxWorks URGENT/11 IPnet — niche OT/IoT exposure
    "CVE-2022-22965": 0.94,  # Spring4Shell
}

# The CSV's CVE_ID column sometimes holds more than a bare CVE ("CVE-x (chained)",
# "CVE-a / CVE-b") — pull out the first CVE token so KEV/EPSS lookups still hit.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _normalize_cve(cve_id: str) -> str:
    match = _CVE_RE.search(cve_id)
    return match.group(0) if match else cve_id

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

    # --- Velon Health Systems (velon_vulnerabilities.csv / velon_architecture.md) ---
    # ACW derived from each finding's primary CI's criticality tier in
    # velon_architecture.md §1.2-§1.4 (Crown Jewel=1.0, High=0.75-0.8,
    # Business-Important=0.6, Standard=0.35). TCM derived from position in the
    # §6 attack-path chains (terminus = highest). is_cif=True marks HIPAA/FDA
    # critical-function scope: EHR, Clinical/Biomed life-safety systems, the AD
    # backbone (DC01), and systems that chain directly into them.
    110001: ("adjacent", 0.35, 3, False),      # A1 guest WiFi trunk -> corp LAN
    46587:  ("internal", 0.35, 4, False),      # A2 PrintNightmare on PRINT01
    91022:  ("internal", 0.60, 4, False),      # A3 local admin reuse -> FILESRV01
    150401: ("internal", 0.60, 5, False),      # A4 patient-scheduling share exposure
    12055:  ("internet_facing", 0.60, 6, False),  # B1 Drupalgeddon2 on PORTAL01
    12061:  ("internet_facing", 0.60, 6, False),  # B2 webshell upload
    200901: ("adjacent", 0.60, 7, False),      # B3 DMZ->AppTier ANY-ANY
    20144:  ("internal", 1.00, 8, True),       # B4 WebLogic RCE on EHR-APP01 (crown jewel)
    200933: ("internal", 1.00, 9, True),       # B5 db_owner excessive -> DB-EHR01 (crown jewel)
    300201: ("internet_facing", 0.60, 5, False),  # C1 public blob container
    300214: ("adjacent", 0.75, 7, False),      # C2 Azure SP subscription Owner
    300228: ("internet_facing", 0.75, 8, True),   # C3 public claims-db weak password
    46840:  ("internet_facing", 0.60, 5, False),  # D1 FortiOS auth bypass
    200955: ("adjacent", 0.60, 6, False),      # D2 VPN split-tunnel to mgmt VLAN
    91145:  ("isolated", 0.75, 7, False),      # D3 cached DA creds on JUMP01
    46912:  ("isolated", 0.80, 9, True),       # D4 vCenter RCE (hosts EHR-APP01/DB-EHR01)
    200977: ("isolated", 0.75, 8, True),       # D5 Veeam default creds (backs up DB-EHR01)
    91260:  ("internal", 1.00, 7, True),       # E1 Kerberoastable svc_clinical on DC01
    91278:  ("internal", 1.00, 9, True),       # E2 noPac on DC01
    200999: ("internal", 1.00, 9, True),       # E3 flat trust corp -> clinical zone
    400012: ("internal", 1.00, 10, True),      # E4 VxWorks IPnet RCE on INFUSION-GW01
    201011: ("internal", 1.00, 10, True),      # E5 shared clinical-admin cred -> pharmacy
    150455: ("internal", 0.75, 7, True),       # F1 Spring4Shell on TELEHEALTH-APP01
    201033: ("internal", 0.75, 7, True),       # F2 telehealth service running as SYSTEM
    150467: ("internal", 0.75, 8, True),       # F3 hardcoded DB creds in telehealth config
    201055: ("internal", 0.85, 9, True),       # F4 excessive DB link -> DB-EHR01
    110102: ("restricted", 0.75, 2, False),    # Standalone: anonymous SMB on IMAGING-NAS01
    201077: ("internal", 0.35, 1, False),      # Standalone: any-any on CLINIC-RTR01
    48113:  ("internal", 0.35, 3, False),      # Standalone: SMBGhost on WKS-CLIN01
    300251: ("adjacent", 0.75, 6, False),      # Standalone: excessive Entra Global Admin
    12078:  ("internet_facing", 0.60, 2, False),  # Standalone: portal admin console missing MFA
    201099: ("adjacent", 1.00, 7, True),       # Standalone: clinical zone segmentation gap
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
    cve_key = _normalize_cve(cve_id)
    epss = EPSS_BY_CVE.get(cve_key, 0.0)
    kev = cve_key in KEV_CVES
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
