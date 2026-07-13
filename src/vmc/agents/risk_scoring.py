"""Agent 5 — GRS Risk Scoring Engine (hybrid: deterministic core + AI
contextualizer) — the crown jewel of the pipeline.

The score itself (`compute_grs`) is pure Python implementing
ghrab_risk_methodology.md §2 term-for-term — no LLM call, fully
reproducible, every weighted term kept in `RiskAssessment.score_breakdown`
so a reader can hand-verify the arithmetic. This is deliberate: the whole
point of GRS over "ask the model for a risk score" is that the number is
auditable independent of any model call.

The one AI step (`_explain_finding`) runs once per finding, in parallel,
as part of the automatic pipeline run — never behind a per-finding button.
It only explains an already-computed score; it cannot change it.
"""

from __future__ import annotations

import asyncio

from pydantic import BaseModel

from vmc.agents.topology import exposure_tier_for_asset
from vmc.models import Asset, Finding, NetworkGraph, RiskAssessment, ThreatIntel
from vmc.providers.retry import generate_json_with_fallback
from vmc.providers.router import ModelRouter

POLICY_VERSION = "grs-v1"  # bump when the weights/tables below change

# ImpactScore weights, ghrab_risk_methodology.md §2
_W_CVSS = 0.30
_W_EPSS = 0.15
_W_KEV = 0.15
_W_ACW = 0.20
_W_TCM = 0.20

_CCF_DEFAULT = 1.0  # no verified compensating controls in this lab, methodology §6

# Action bands, SSVC-aligned, methodology §7: (min_score, band, default_sla_days)
_ACTION_BANDS = (
    (80, "IMMEDIATE", 3),  # 24-72h -> use the upper bound
    (60, "ACT", 7),
    (40, "ATTEND", 30),
    (20, "TRACK*", 90),
    (0, "TRACK", None),  # monitor only
)

_DORA_SLA_CAP_DAYS = 30

# DORA "critical or important function" (CIF) scope, methodology §7: the
# Finance/Trading zone, DC01, the finance database/RDS, and the CDE
# segmentation control itself. Zone-scoped compliance is already captured
# via Asset.compliance_scope; these are the named exceptions that sit
# outside the Finance/Trading zone but are still explicitly CIF per the doc.
_CIF_HOSTNAMES = {"DC01"}


def _band_for_score(score: float) -> tuple[str, int | None]:
    for threshold, band, sla_days in _ACTION_BANDS:
        if score >= threshold:
            return band, sla_days
    return "TRACK", None  # unreachable given the 0 threshold, kept for safety


def _is_dora_cif_scope(asset: Asset | None) -> bool:
    if asset is None:
        return False
    return bool(asset.compliance_scope) or asset.hostname in _CIF_HOSTNAMES


def compute_grs(
    finding: Finding,
    asset: Asset | None,
    threat_intel: ThreatIntel | None,
    tcm: float,
    topology: NetworkGraph,
) -> RiskAssessment:
    cvss_norm = finding.cvss_score if finding.cvss_score is not None else 0.0
    epss_norm = (threat_intel.epss_score * 10) if (threat_intel and threat_intel.epss_score is not None) else 0.0
    kev_norm = 10.0 if (threat_intel and threat_intel.in_kev) else 0.0
    acw_norm = (asset.acw * 10) if asset is not None else 4.0  # STANDARD_ENDPOINT-ish default, unmapped asset
    tcm_norm = tcm

    impact_score = 10 * (
        _W_CVSS * cvss_norm + _W_EPSS * epss_norm + _W_KEV * kev_norm + _W_ACW * acw_norm + _W_TCM * tcm_norm
    )

    exposure_tier = exposure_tier_for_asset(asset, topology) if asset is not None else 0.90
    ccf = _CCF_DEFAULT

    grs = min(100.0, impact_score * exposure_tier * ccf)
    band, sla_days = _band_for_score(grs)

    dora_cif = _is_dora_cif_scope(asset)
    if dora_cif and (sla_days is None or sla_days > _DORA_SLA_CAP_DAYS):
        sla_days = _DORA_SLA_CAP_DAYS

    return RiskAssessment(
        finding_id=finding.finding_id,
        score=round(grs, 1),
        score_breakdown={
            "cvss_norm": round(cvss_norm, 2),
            "epss_norm": round(epss_norm, 2),
            "kev_norm": kev_norm,
            "acw_norm": round(acw_norm, 2),
            "tcm_norm": round(tcm_norm, 2),
            "impact_score": round(impact_score, 2),
            "exposure_tier": exposure_tier,
            "ccf": ccf,
        },
        band=band,
        sla_days=sla_days,
        dora_cif_scope=dora_cif,
        policy_version=POLICY_VERSION,
    )


class _Explanation(BaseModel):
    explanation: str


class _ExplanationBreaker:
    """Fail-fast for the AI explanation sub-step. If every provider in the
    fallback chain is exhausted (e.g. a daily quota, not just a transient
    rate limit) `generate_json_with_fallback`'s own backoff schedule already
    burns several seconds *per finding* before giving up — multiplied across
    a whole dataset that turns "Run Analysis" into a multi-minute hang for a
    step that's explicitly optional (`ai_explanation` is decoration on an
    already-complete, already-auditable score). After a few consecutive
    total-exhaustion results, stop calling out entirely for the rest of this
    run and degrade immediately — same "optional agents degrade gracefully"
    principle the architecture doc already applies to Agent 2's vision
    cross-check and Agent 3's web-search enrichment.
    """

    CONSECUTIVE_FAILURE_LIMIT = 3

    def __init__(self) -> None:
        self.consecutive_failures = 0
        self.tripped = False

    def record(self, succeeded: bool) -> None:
        if succeeded:
            self.consecutive_failures = 0
            return
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.CONSECUTIVE_FAILURE_LIMIT:
            self.tripped = True


async def _explain_finding(
    finding: Finding,
    assessment: RiskAssessment,
    router: ModelRouter | None,
    semaphore: asyncio.Semaphore,
    breaker: _ExplanationBreaker,
) -> str:
    if router is None or breaker.tripped:
        return ""
    async with semaphore:
        if breaker.tripped:  # may have tripped while this task waited on the semaphore
            return ""
        breakdown = assessment.score_breakdown
        prompt = (
            f"Finding: {finding.title}\n"
            f"CVE: {finding.cve_id or 'N/A'}\n"
            f"Asset: {finding.asset_hostname} ({finding.zone})\n"
            f"Computed GRS: {assessment.score}/100 — band {assessment.band}\n"
            f"Breakdown: CVSS={breakdown.get('cvss_norm')}, EPSS={breakdown.get('epss_norm')}, "
            f"KEV={'yes' if breakdown.get('kev_norm') else 'no'}, "
            f"asset criticality={breakdown.get('acw_norm')}/10, "
            f"toxic-combination/blast-radius={breakdown.get('tcm_norm')}/10, "
            f"exposure multiplier={breakdown.get('exposure_tier')}\n"
            f"DORA CIF scope: {'yes' if assessment.dora_cif_scope else 'no'}\n"
            f"Description: {finding.description}\n"
            f"Consequence: {finding.consequence}"
        )
        try:
            providers = router.providers_for("risk_explanation")
        except KeyError:
            breaker.record(succeeded=False)
            return ""
        result = await generate_json_with_fallback(
            providers,
            system=(
                "You are a vulnerability risk analyst. Given a finding and its already-computed Ghrab Risk "
                "Score (GRS) breakdown, write a one-paragraph, plain-English justification of the score. "
                "You explain the score — you do not change it or invent a different one. Ground every claim "
                "in the numbers and text given; do not invent CVEs, hosts, or attack chains not present in the input."
            ),
            prompt=prompt,
            schema=_Explanation,
            temperature=0.2,
            required=False,
        )
        breaker.record(succeeded=result is not None)
        return result.explanation if result is not None else ""


async def run_agent5(
    findings: list[Finding],
    assets: dict[str, Asset],
    enrichment: dict[str, ThreatIntel],
    tcm_by_finding: dict[str, float],
    topology: NetworkGraph,
    router: ModelRouter | None,
    *,
    max_concurrent_ai_calls: int = 5,
) -> dict[str, RiskAssessment]:
    semaphore = asyncio.Semaphore(max_concurrent_ai_calls)
    breaker = _ExplanationBreaker()
    assessments: dict[str, RiskAssessment] = {}
    for finding in findings:
        asset = assets.get(finding.asset_hostname) or assets.get(finding.asset_ip)
        threat_intel = enrichment.get(finding.cve_id) if finding.cve_id else None
        tcm = tcm_by_finding.get(finding.finding_id, 1.0)
        assessments[finding.finding_id] = compute_grs(finding, asset, threat_intel, tcm, topology)

    explanations = await asyncio.gather(
        *(_explain_finding(f, assessments[f.finding_id], router, semaphore, breaker) for f in findings)
    )
    for finding, explanation in zip(findings, explanations):
        assessments[finding.finding_id].ai_explanation = explanation

    return assessments
