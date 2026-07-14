"""Agent 4 — Attack Path Discovery & Correlation (AI, temp≈0.4).

Genuinely discovers multi-step attack chains by reasoning over the raw
findings + network topology + segmentation health — it is never handed
`ghrab_architecture.md`'s §5 narrative or the CSV's `Attack_Path_Ref`
column (see `Finding.attack_path_refs`'s docstring). Those exist only
because this is a synthetic lab dataset; a real scanner export has no
pre-written answer key, so an agent that leaned on them would be
worthless the moment it saw a real customer's data. This is the one piece
of the pipeline where "explainable, deterministic core" gives way to real
LLM reasoning by necessity — reachability chains that depend on judging
which misconfigurations plausibly compose into a foothold are exactly the
kind of correlation a fixed formula can't do, which is why Agent 5 (the
actual risk *score*) still never touches an LLM but Agent 4 (the *shape*
of the attack surface) does.

Trade-off, stated plainly: unlike the rest of the GRS formula, the TCM
term this agent produces is not bit-for-bit reproducible without
re-calling the LLM (temperature=0.4, by design — some creative slack is
the point). `RiskAssessment.score_breakdown` still records the resulting
number, but "recompute by hand" no longer applies to that one input the
way it does to CVSS/EPSS/KEV/ACW. If a fully deterministic path graph is
required in the future, run this once, freeze the output, and treat it as
policy input rather than re-deriving it every run.

Every discovered finding_id/target_asset is validated against the real
dataset after generation — the model can suggest a chain, it cannot
invent a host or finding that doesn't exist. This is the same "propose,
then verify against ground truth" discipline the methodology doc asks the
platform to hold *itself* to (§9: "if it claims a toxic combination or
blast radius that isn't in the documented attack graph, that's a
hallucination signal") — here we enforce it in code instead of hoping the
model gets it right.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from vmc.agents.topology import BUSINESS_IMPORTANT, CROWN_JEWEL, HIGH_LEVERAGE_INFRA
from vmc.models import (
    Asset,
    AttackPath,
    AttackPathStep,
    ChokePoint,
    Finding,
    NetworkGraph,
    SegmentationFinding,
)
from vmc.providers.retry import generate_json_with_fallback
from vmc.providers.router import ModelRouter

# TCM bands, ghrab_risk_methodology.md §4, driven off the discovered path's
# final target asset's ACW (Agent 2, agents/topology.py) — this scoring
# rule itself stays deterministic even though *which* paths exist doesn't.
_TCM_NO_CHAIN = 1.0
_TCM_BUSINESS_IMPORTANT = 4.0  # ACW 0.5-0.7 -> chains to one business-important asset
_TCM_HIGH_LEVERAGE = 7.0  # ACW 0.7-0.9 (regulated data / high-leverage infra)
_TCM_CROWN_JEWEL = 9.5  # ACW >= 1.0 -> direct/near-direct path to a crown jewel

_MIN_STEPS_PER_PATH = 2  # a single finding is not a "chain"
_MAX_FINDINGS_IN_PROMPT = 200  # keeps the prompt bounded on large datasets; see run_agent4


# ---------------------------------------------------------------------------
# LLM-facing response schema — deliberately separate from the domain model
# (AttackPath/AttackPathStep) so the generation contract can stay narrow and
# strict (just enough to reconstruct a chain) while validation/enrichment
# happens in plain Python afterward, not inside the prompt.
# ---------------------------------------------------------------------------


class DiscoveredStep(BaseModel):
    finding_id: str
    rationale: str = Field(description="Why this step follows from the attacker's position after the previous step")


class DiscoveredPath(BaseModel):
    target_asset: str = Field(description="Hostname/asset id of the final asset this chain reaches")
    summary: str = Field(description="One sentence: what an attacker gains by completing this chain")
    steps: list[DiscoveredStep]


class AttackPathDiscovery(BaseModel):
    paths: list[DiscoveredPath] = Field(
        default_factory=list,
        description="Every plausible multi-step attack chain found. Empty if none exist — do not invent one.",
    )


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a red-team-style attack path analyst reviewing a vulnerability scan for the \
first time. You have NOT been given any pre-existing attack path documentation — there is none. Your job is \
to find realistic multi-step attack chains yourself, from the raw findings and infrastructure context alone.

Rules:
1. Every step in a chain must reference exactly one finding_id from the "FINDINGS" list below. Never invent a \
finding_id, CVE, or hostname that isn't in the provided data.
2. A chain needs at least 2 steps and must be causally plausible: each step should follow from the access, \
credentials, or network position an attacker would have gained from the previous step (e.g. a network \
segmentation flaw lets an attacker reach a new zone; a remote-code-execution bug there grants a foothold; \
excessive privileges or credential reuse let them pivot further; a trust relationship or a database link lets \
them reach a downstream system).
3. Do not chain findings together just because they are both severe. The connection must be a real technical \
relationship (same host, adjacent zone reachable via a documented trust/segmentation issue, credential reuse, \
excessive access granting pivot rights, etc.) — grounded in the ZONES/TRUST/SEGMENTATION and ASSETS context given.
4. Prefer chains that start from the least-trusted reachable zone (internet-facing or adjacent) and progress \
toward higher-criticality assets, but only where the data actually supports that path.
5. If you cannot identify any plausible multi-step chain, return an empty "paths" list. An empty, honest \
answer is far better than a fabricated chain — a fabricated chain here directly inflates a real risk score.
6. Do not reuse the same finding_id more than once within a single chain.
"""


def _build_user_prompt(
    findings: list[Finding],
    assets: dict[str, Asset],
    topology: NetworkGraph,
    segmentation_findings: list[SegmentationFinding],
) -> str:
    findings_block = "\n".join(
        f"- id={f.finding_id} cve={f.cve_id or 'N/A'} category={f.category!r} host={f.asset_hostname} "
        f"zone={f.zone} team={f.responsible_team!r} title={f.title!r} "
        f"desc={f.description[:220]!r} consequence={f.consequence[:160]!r}"
        for f in findings[:_MAX_FINDINGS_IN_PROMPT]
    )

    assets_block = "\n".join(
        f"- host={a.hostname} zone={a.zone} team={a.owning_team!r} criticality(0-1)={a.acw} "
        f"compliance_scope={a.compliance_scope}"
        for a in assets.values()
    )

    zones_block = "\n".join(
        f"- zone={z.name!r} trust={z.trust_level_raw or 'unknown'} exposure_tier={z.exposure_tier} "
        f"compliance_scope={z.compliance_scope}"
        for z in topology.zones.values()
    )

    segmentation_block = "\n".join(
        f"- {sf.source_zone} -> {sf.target_zone}: {sf.issue_description} (health={sf.health})"
        for sf in segmentation_findings
    ) or "(no segmentation issues flagged)"

    return (
        f"FINDINGS ({len(findings)} total, {min(len(findings), _MAX_FINDINGS_IN_PROMPT)} shown):\n{findings_block}\n\n"
        f"ASSETS:\n{assets_block}\n\n"
        f"ZONES:\n{zones_block}\n\n"
        f"SEGMENTATION ISSUES (documented ways to cross zone boundaries):\n{segmentation_block}\n\n"
        "Identify the plausible multi-step attack chains in this environment."
    )


# ---------------------------------------------------------------------------
# Post-generation validation — the model proposes, this function verifies.
# ---------------------------------------------------------------------------


def _validate_and_convert(
    discovery: AttackPathDiscovery, findings_by_id: dict[str, Finding], assets: dict[str, Asset]
) -> dict[str, AttackPath]:
    attack_paths: dict[str, AttackPath] = {}
    path_num = 0
    for discovered in discovery.paths:
        seen_finding_ids: set[str] = set()
        steps: list[AttackPathStep] = []
        for discovered_step in discovered.steps:
            finding_id = discovered_step.finding_id
            if finding_id not in findings_by_id or finding_id in seen_finding_ids:
                continue  # hallucinated or duplicate finding_id — drop just this step
            seen_finding_ids.add(finding_id)
            finding = findings_by_id[finding_id]
            steps.append(
                AttackPathStep(
                    step_ref="",  # assigned below once we know the path survives validation
                    finding_id=finding_id,
                    description=f"{finding.asset_hostname}: {finding.title} — {discovered_step.rationale.strip()}",
                )
            )

        if len(steps) < _MIN_STEPS_PER_PATH:
            continue  # not a chain — drop the whole path

        target_asset = discovered.target_asset.strip() if discovered.target_asset else None
        if target_asset not in assets:
            target_asset = None  # hallucinated target — don't propagate a fake asset name

        path_num += 1
        path_ref = f"PATH-{path_num:02d}"
        for ordinal, step in enumerate(steps, start=1):
            step.step_ref = f"{path_ref}-Step{ordinal}"

        attack_paths[path_ref] = AttackPath(
            path_ref=path_ref, steps=steps, target_asset=target_asset, summary=discovered.summary.strip()
        )
    return attack_paths


def _target_acw(target_asset: str, assets: dict[str, Asset]) -> float | None:
    """Some discovered targets may be real hosts that never generated a
    finding of their own (e.g. a pivot destination mentioned only as a
    consequence of another finding) — assets dict only has hosts that own a
    finding. Fall back to the static ACW table (agents/topology.py, a
    business-maintained asset-criticality register, not attack-path data)."""
    target = assets.get(target_asset)
    if target is not None:
        return target.acw
    from vmc.agents.topology import ASSET_ACW_TABLE

    return ASSET_ACW_TABLE.get(target_asset)


def _tcm_for_target_acw(target_acw: float | None) -> float:
    if target_acw is None:
        return _TCM_NO_CHAIN
    if target_acw >= CROWN_JEWEL:
        return _TCM_CROWN_JEWEL
    if target_acw >= HIGH_LEVERAGE_INFRA:
        return _TCM_HIGH_LEVERAGE
    if target_acw >= BUSINESS_IMPORTANT:
        return _TCM_BUSINESS_IMPORTANT
    return _TCM_NO_CHAIN


def compute_tcm_by_finding(
    findings: list[Finding], attack_paths: dict[str, AttackPath], assets: dict[str, Asset]
) -> dict[str, float]:
    finding_id_to_path: dict[str, AttackPath] = {}
    for path in attack_paths.values():
        for step in path.steps:
            if step.finding_id:
                finding_id_to_path[step.finding_id] = path

    tcm_by_finding: dict[str, float] = {}
    for finding in findings:
        path = finding_id_to_path.get(finding.finding_id)
        if path is None or path.target_asset is None:
            tcm_by_finding[finding.finding_id] = _TCM_NO_CHAIN
            continue
        tcm_by_finding[finding.finding_id] = _tcm_for_target_acw(_target_acw(path.target_asset, assets))
    return tcm_by_finding


def compute_choke_points(attack_paths: dict[str, AttackPath]) -> list[ChokePoint]:
    """Each path's entry step (Step 1) is its choke point: fixing it removes
    attacker access to every step discovered after it in that chain."""
    choke_points: list[ChokePoint] = []
    for path_ref, path in attack_paths.items():
        if len(path.steps) < 2 or not path.steps[0].finding_id:
            continue
        downstream_count = len(path.steps) - 1
        choke_points.append(
            ChokePoint(
                finding_id=path.steps[0].finding_id,
                paths_collapsed=[path_ref],
                rationale=(
                    f"entry step of {path_ref}; fixing it removes attacker access to the "
                    f"{downstream_count} step(s) discovered after it in this chain"
                ),
            )
        )
    return choke_points


async def discover_attack_paths(
    findings: list[Finding],
    assets: dict[str, Asset],
    topology: NetworkGraph,
    segmentation_findings: list[SegmentationFinding],
    router: ModelRouter | None,
) -> tuple[dict[str, AttackPath], bool]:
    """Returns (attack_paths, degraded). `degraded=True` means every
    provider in the fallback chain failed (rate limit, quota, unreachable)
    — an empty result in that case is a gap in the run, not a genuine "no
    chains here" finding, and callers (the orchestrator's agent_logs, the
    UI) must be able to tell the two apart rather than showing an identical
    "no attack paths discovered" either way."""
    if router is None:
        return {}, False  # no provider configured at all — a known state, not a failure
    if not findings:
        return {}, False

    try:
        providers = router.providers_for("attack_path_discovery")
    except KeyError:
        return {}, True  # no usable provider configured for this agent at all

    prompt = _build_user_prompt(findings, assets, topology, segmentation_findings)
    result = await generate_json_with_fallback(
        providers,
        system=_SYSTEM_PROMPT,
        prompt=prompt,
        schema=AttackPathDiscovery,
        temperature=0.4,
        required=False,
    )
    if result is None:
        return {}, True  # every provider exhausted — degrade to "no discovered paths", not a crash

    findings_by_id = {f.finding_id: f for f in findings}
    return _validate_and_convert(result, findings_by_id, assets), False


async def run_agent4(
    findings: list[Finding],
    assets: dict[str, Asset],
    topology: NetworkGraph,
    segmentation_findings: list[SegmentationFinding],
    router: ModelRouter | None,
) -> tuple[dict[str, AttackPath], list[ChokePoint], dict[str, float], bool]:
    attack_paths, degraded = await discover_attack_paths(findings, assets, topology, segmentation_findings, router)
    tcm_by_finding = compute_tcm_by_finding(findings, attack_paths, assets)
    choke_points = compute_choke_points(attack_paths)
    return attack_paths, choke_points, tcm_by_finding, degraded
