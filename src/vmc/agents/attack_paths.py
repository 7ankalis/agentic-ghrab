"""Agent 4 — Attack Path Correlation (non-AI here: deterministic parsing +
rule-based scoring, not creative LLM reasoning — see module-level rationale
below for why that's the honest choice for this dataset).

Parses `ghrab_architecture.md` §5 ("Attack Paths (Easy -> Hard)") into
`AttackPath`/`AttackPathStep` objects, matching each step's inline label
(e.g. "A1") against its ordinal position to reconstruct the same
`PATH-A-Step1`-style refs already carried on every `Finding` from the CSV
(`Attack_Path_Ref` column) — this is ground truth already present in the
dataset, not something an LLM needs to infer or could hallucinate.

Computes, per finding:
- **TCM (Toxic Combination Score, 0-10)** — ghrab_risk_methodology.md §4:
  how directly this finding's path reaches a crown-jewel asset. Derived
  from the ACW (Agent 2) of the path's final target asset, using the
  methodology's own band table, rather than an LLM guessing a number: this
  keeps TCM exactly as auditable as the rest of the GRS formula.
- **Choke points** — a finding is the entry step (Step 1) of a path whose
  removal collapses every step after it. The real `ghrab_architecture.md`
  attack paths in this dataset are single independent chains (no finding or
  host is shared across two different paths — verified against the CSV),
  so "collapses N paths" doesn't apply here; "collapses N downstream steps
  of its own path" is the honest equivalent and matches the architecture
  doc's own illustrative example (Zerologon gates the rest of Path E).
"""

from __future__ import annotations

import re
from pathlib import Path

from vmc.agents.topology import CROWN_JEWEL, HIGH_LEVERAGE_INFRA, BUSINESS_IMPORTANT
from vmc.models import Asset, AttackPath, AttackPathStep, ChokePoint, Finding

_PATH_HEADER_RE = re.compile(r"^###\s*PATH\s+(?P<letter>[A-Z])\s*—\s*(?P<title>.+)$", re.MULTILINE)
_STEP_RE = re.compile(r"^\d+\.\s+\*\*(?P<label>[A-Z]\d+)\*\*\s*—\s*(?P<desc>.+)$", re.MULTILINE)
_IMPACT_RE = re.compile(r"^\s*\*\*Impact:\*\*\s*(?P<impact>.+)$", re.MULTILINE)
_BACKTICK_HOST_RE = re.compile(r"`([A-Za-z][\w.-]*)`")

# TCM bands, ghrab_risk_methodology.md §4, driven off the final target
# asset's ACW (Agent 2, agents/topology.py).
_TCM_NO_CHAIN = 1.0
_TCM_BUSINESS_IMPORTANT = 4.0  # ACW 0.5-0.7 -> chains to one business-important asset
_TCM_HIGH_LEVERAGE = 7.0  # ACW 0.7-0.9 (regulated data / high-leverage infra)
_TCM_CROWN_JEWEL = 9.5  # ACW >= 1.0 -> direct/near-direct path to a crown jewel


def parse_attack_paths(architecture_md: str | Path) -> dict[str, AttackPath]:
    text = Path(architecture_md).read_text(encoding="utf-8")

    # Split the document at each "### PATH X" header so steps/impact are
    # only matched within their own path's section, not bleeding into the
    # next one.
    headers = list(_PATH_HEADER_RE.finditer(text))
    paths: dict[str, AttackPath] = {}
    for i, header in enumerate(headers):
        section_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        section = text[header.start():section_end]
        letter = header.group("letter")
        path_ref = f"PATH-{letter}"

        steps: list[AttackPathStep] = []
        for ordinal, step_match in enumerate(_STEP_RE.finditer(section), start=1):
            steps.append(
                AttackPathStep(
                    step_ref=f"{path_ref}-Step{ordinal}",
                    description=step_match.group("desc").strip(),
                )
            )

        impact_match = _IMPACT_RE.search(section)
        summary = impact_match.group("impact").strip() if impact_match else header.group("title").strip()

        target_asset = _infer_target_asset(section, impact_match)

        paths[path_ref] = AttackPath(path_ref=path_ref, steps=steps, target_asset=target_asset, summary=summary)
    return paths


def _infer_target_asset(section: str, impact_match: re.Match | None) -> str | None:
    """The path's final target is the last backtick-quoted host mentioned
    before the Impact line (impact prose is usually generic business-impact
    language, not another asset reference)."""
    search_region = section[: impact_match.start()] if impact_match else section
    hosts = _BACKTICK_HOST_RE.findall(search_region)
    return hosts[-1] if hosts else None


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


def _target_acw(target_asset: str, assets: dict[str, Asset]) -> float | None:
    """Some attack-path targets (e.g. SETTLEMENT01) are only ever mentioned as
    a pivot destination in architecture.md §5, never as a CSV finding row of
    their own — so Agent 1 never materializes an `Asset` for them. Fall back
    to the static ACW table (agents/topology.py) so those targets still count
    toward TCM instead of silently looking like "no chain"."""
    target = assets.get(target_asset)
    if target is not None:
        return target.acw
    from vmc.agents.topology import ASSET_ACW_TABLE

    return ASSET_ACW_TABLE.get(target_asset)


def compute_tcm_by_finding(
    findings: list[Finding], attack_paths: dict[str, AttackPath], assets: dict[str, Asset]
) -> dict[str, float]:
    tcm_by_finding: dict[str, float] = {}
    for finding in findings:
        path_ref = _path_ref_for_finding(finding)
        path = attack_paths.get(path_ref) if path_ref else None
        if path is None or path.target_asset is None:
            tcm_by_finding[finding.finding_id] = _TCM_NO_CHAIN
            continue
        tcm_by_finding[finding.finding_id] = _tcm_for_target_acw(_target_acw(path.target_asset, assets))
    return tcm_by_finding


def _path_ref_for_finding(finding: Finding) -> str | None:
    for ref in finding.attack_path_refs:
        match = re.match(r"(PATH-[A-Z])-Step\d+", ref)
        if match:
            return match.group(1)
    return None


def compute_choke_points(findings: list[Finding], attack_paths: dict[str, AttackPath]) -> list[ChokePoint]:
    step1_finding_by_path: dict[str, str] = {}
    for finding in findings:
        for ref in finding.attack_path_refs:
            if ref.endswith("-Step1"):
                step1_finding_by_path[ref.rsplit("-Step1", 1)[0]] = finding.finding_id

    choke_points: list[ChokePoint] = []
    for path_ref, finding_id in step1_finding_by_path.items():
        path = attack_paths.get(path_ref)
        downstream_count = len(path.steps) - 1 if path else 0
        if downstream_count <= 0:
            continue
        choke_points.append(
            ChokePoint(
                finding_id=finding_id,
                paths_collapsed=[path_ref],
                rationale=(
                    f"entry step of {path_ref}; fixing it removes attacker access to the "
                    f"{downstream_count} step(s) that follow it in this chain"
                ),
            )
        )
    return choke_points


def run_agent4(
    findings: list[Finding], architecture_md: str | Path, assets: dict[str, Asset]
) -> tuple[dict[str, AttackPath], list[ChokePoint], dict[str, float]]:
    attack_paths = parse_attack_paths(architecture_md)
    tcm_by_finding = compute_tcm_by_finding(findings, attack_paths, assets)
    choke_points = compute_choke_points(findings, attack_paths)
    return attack_paths, choke_points, tcm_by_finding
