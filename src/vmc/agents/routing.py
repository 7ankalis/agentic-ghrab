"""Agent 7 — Remediation Routing (non-AI, deterministic).

Groups the already-scored findings by `Responsible_Team` (the CSV's own
ownership column, same ground truth Agent 1 already uses to build
`TeamInfo`) and produces one `TeamBrief` per team: real findings, real GRS
scores, real CSV-sourced remediation text. Deliberately does not invent
effort-hour estimates, cost figures, or schedules — the dataset has no
grounding for those, and the project's whole design philosophy is that
nothing gets fabricated on top of the deterministic core (see Agent 5's
docstring). `brief_text` is a plain-text summary suitable for the "Notify
Team" UI action to copy or hand off — no message actually gets sent
anywhere; there is no chat/email integration wired up, deliberately (see
VOC_PLATFORM_VISION.md's own roadmap, which lists Slack/Teams webhooks as
post-launch, not core).
"""

from __future__ import annotations

from vmc.models import ChokePoint, Finding, RiskAssessment, TeamBrief, TeamInfo


def _build_brief_text(team_name: str, findings_sorted: list[tuple[Finding, RiskAssessment]]) -> str:
    lines = [f"Remediation queue — {team_name}", f"{len(findings_sorted)} open finding(s), sorted by Ghrab Risk Score.", ""]
    for finding, assessment in findings_sorted:
        sla = f"{assessment.sla_days}-day SLA" if assessment.sla_days is not None else "monitor only"
        lines.append(f"[{assessment.score:.1f} {assessment.band}] {finding.title} ({finding.asset_hostname}) — {sla}")
        if finding.remediation_text:
            lines.append(f"    Fix: {finding.remediation_text}")
    return "\n".join(lines)


def run_agent7(
    findings: list[Finding],
    teams: dict[str, TeamInfo],
    risk_register: dict[str, RiskAssessment],
    choke_points: list[ChokePoint],
) -> dict[str, TeamBrief]:
    choke_point_finding_ids = {cp.finding_id for cp in choke_points}

    findings_by_team_id: dict[str, list[tuple[Finding, RiskAssessment]]] = {}
    for finding in findings:
        assessment = risk_register.get(finding.finding_id)
        if assessment is None:
            continue
        team_id = next((tid for tid, t in teams.items() if t.name == finding.responsible_team), finding.responsible_team)
        findings_by_team_id.setdefault(team_id, []).append((finding, assessment))

    briefs: dict[str, TeamBrief] = {}
    for team_id, pairs in findings_by_team_id.items():
        pairs.sort(key=lambda pair: pair[1].score, reverse=True)
        team_name = teams[team_id].name if team_id in teams else team_id

        band_counts: dict[str, int] = {}
        choke_point_count = 0
        for finding, assessment in pairs:
            band_counts[assessment.band] = band_counts.get(assessment.band, 0) + 1
            if finding.finding_id in choke_point_finding_ids:
                choke_point_count += 1

        briefs[team_id] = TeamBrief(
            team_id=team_id,
            team_name=team_name,
            total_findings=len(pairs),
            band_counts=band_counts,
            choke_point_count=choke_point_count,
            top_finding_ids=[f.finding_id for f, _ in pairs[:10]],
            brief_text=_build_brief_text(team_name, pairs),
        )
    return briefs
