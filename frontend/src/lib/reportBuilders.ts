/** Turns already-fetched page data into Markdown/CSV report text — no backend
 * round-trip needed since every page already holds this data via React Query. */
import type {
  AttackPathsResponse, Compliance, Correlation, Finding, Overview, TeamStat,
} from "./types";

const now = () => new Date().toLocaleString();

function h2(title: string): string {
  return `## ${title}\n`;
}

export function buildOverviewReport(data: Overview): string {
  const k = data.kpis;
  const lines: string[] = [
    "# Ghrab VOC — Command Center Report",
    `_Generated ${now()}_\n`,
    h2("Key Metrics"),
    "| Metric | Value |",
    "|---|---|",
    `| Total findings | ${k.total} |`,
    `| Immediate (GRS ≥ 80) | ${k.immediate} |`,
    `| Act (GRS 60–79) | ${k.act} |`,
    `| Average GRS | ${k.avg_grs} |`,
    `| KEV-listed | ${k.kev} |`,
    `| DORA CIF scope | ${k.dora_cif} |`,
    `| Crown jewels | ${k.crown_jewels} |`,
    `| Attack paths discovered | ${k.discovered_paths} |`,
    "",
  ];
  if (data.executive_summary) {
    lines.push(h2("Executive Synthesis"), data.executive_summary, "");
  }
  lines.push(h2("Top Urgent Findings"));
  data.top_findings.forEach((f) => {
    lines.push(`- **GRS ${f.grs} (${f.band})** — ${f.title} — ${f.hostname} · QID ${f.qid} · Owner: ${f.team}`);
  });
  lines.push("", h2("Top Attack Paths"));
  data.top_paths.forEach((p) => {
    lines.push(`- **${p.path_id}** (score ${p.score}) — ${p.entry} → ${p.target}${p.headline ? ` — ${p.headline}` : ""}`);
  });
  return lines.join("\n");
}

export function buildFindingsCSV(findings: Finding[]): string {
  const cols: (keyof Finding)[] = [
    "qid", "title", "band", "grs", "severity", "cvss", "cve", "hostname", "zone",
    "team", "status", "kev", "dora_cif", "compliance_ref", "discovered_path_refs",
  ];
  const esc = (v: unknown) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = [cols.join(",")];
  findings.forEach((f) => rows.push(cols.map((c) => esc(f[c])).join(",")));
  return rows.join("\n");
}

export function buildAttackPathsReport(data: AttackPathsResponse): string {
  const lines: string[] = ["# Ghrab VOC — Attack Path Discovery Report", `_Generated ${now()}_\n`];
  if (data.summary) lines.push(h2("Attack-Surface Synthesis"), data.summary, "");

  lines.push(h2(`Discovered Paths (${data.paths.length})`));
  data.paths.forEach((p) => {
    lines.push(`### ${p.path_id} — ${p.entry} → ${p.target} (score ${p.score})`);
    if (p.headline) lines.push(`**${p.headline}**\n`);
    if (p.narrative) lines.push(p.narrative + "\n");
    if (p.business_impact) lines.push(`**Business impact:** ${p.business_impact}\n`);
    if (p.choke_point) lines.push(`**Choke point:** ${p.choke_point}\n`);
    lines.push(`Confidence: ${p.confidence || "—"} · Novelty: ${p.novelty || "—"} · Blast radius: ${p.blast_radius} · Hops: ${p.length}\n`);
    lines.push("Kill chain: Internet → " + p.steps.map((s) => s.host).join(" → "));
    p.steps.forEach((s, i) => {
      lines.push(`  ${i + 1}. **${s.host}** via ${s.arrival_kind}${s.arrival_via_qid ? ` (QID ${s.arrival_via_qid})` : ""}` +
        (s.exploit_finding ? ` — exploited via ${s.exploit_finding.title}` : ""));
    });
    lines.push("");
  });

  if (data.toxic_combinations.length) {
    lines.push(h2("Toxic Combinations"));
    data.toxic_combinations.forEach((t) => {
      lines.push(`### ${t.title}`, t.mechanism);
      if (t.why_it_matters) lines.push(`**Why it matters:** ${t.why_it_matters}`);
      if (t.involved_qids?.length) lines.push(`QIDs: ${t.involved_qids.join(", ")}`);
      lines.push("");
    });
  }

  if (data.ai_detected?.length) {
    lines.push(h2(`Analyst-Detected Paths (${data.ai_detected.length})`),
      "_Reasoned from the asset/ownership/reachability grounding alone by the Analyst Detection Agent — no candidate list, no answer key. Every hop verified against a real finding._\n");
    data.ai_detected.forEach((d) => {
      lines.push(`### ${d.entry} → ${d.target} — ${d.grounded ? "grounded" : `${d.verified_hops}/${d.total_hops} hops verified`} (confidence ${d.confidence || "—"})`);
      d.hops.forEach((h, i) => {
        lines.push(`  ${i + 1}. ${h.from} → ${h.to}${h.via_qid != null ? ` (QID ${h.via_qid})` : ""}${h.enabler ? ` via ${h.enabler}` : ""}`);
      });
      if (d.business_impact) lines.push(`**Impact:** ${d.business_impact}`);
      lines.push("");
    });
  }

  if (data.documented.length) {
    lines.push(h2("Documented Paths (held-out verification ground truth)"),
      "_Never ingested or shown to the engine/agents — used only to grade rediscovery._\n");
    data.documented.forEach((d) => {
      lines.push(`- **${d.path_id}** — ${d.entry} → ${d.target} (${d.hosts.join(" → ")})`);
    });
  }
  return lines.join("\n");
}

export function buildCorrelationReport(data: Correlation): string {
  const lines: string[] = ["# Ghrab VOC — Correlation & Toxic Combinations Report", `_Generated ${now()}_\n`];
  if (data.cross_findings_insights?.length) {
    lines.push(h2("Cross-Finding Insights"));
    data.cross_findings_insights.forEach((i) => lines.push(`- ${i}`));
    lines.push("");
  }
  if (data.top_risk_teams?.length) {
    lines.push(h2("Top Risk-Owning Teams"));
    data.top_risk_teams.forEach((t) => lines.push(`- **${t.team}** — ${t.rationale}`));
    lines.push("");
  }
  if (data.reprioritization_flags?.length) {
    lines.push(h2("Reprioritization Flags"));
    data.reprioritization_flags.forEach((f) => lines.push(`- QID ${f.qid} (${f.hostname}) — ${f.reason}`));
  }
  return lines.join("\n");
}

export function buildTeamsReport(teams: TeamStat[]): string {
  const lines: string[] = [
    "# Ghrab VOC — Teams & Ownership Report",
    `_Generated ${now()}_\n`,
    "| Team | Findings | Avg GRS | Peak GRS | Immediate | KEV | DORA CIF |",
    "|---|---|---|---|---|---|---|",
  ];
  teams.forEach((t) => {
    lines.push(`| ${t.team} | ${t.findings} | ${t.avg_grs} | ${t.max_grs} | ${t.immediate} | ${t.kev} | ${t.dora_cif} |`);
  });
  return lines.join("\n");
}

export function buildComplianceReport(data: Compliance): string {
  const lines: string[] = ["# Ghrab VOC — Compliance Posture Report", `_Generated ${now()}_\n`];
  if (data.executive_summary) lines.push(h2("Auditor Briefing"), data.executive_summary, "");
  if (data.frameworks_in_scope?.length) {
    lines.push(h2("Frameworks in Scope"), data.frameworks_in_scope.map((f) => `\`${f}\``).join(", "), "");
  }
  if (data.dora_overlay_note) lines.push(h2("DORA CIF Overlay"), data.dora_overlay_note, "");
  if (data.key_gaps?.length) {
    lines.push(h2("Key Gaps"));
    data.key_gaps.forEach((g) => {
      lines.push(`- **[${g.framework}]** ${g.gap_description}` +
        (g.finding_refs?.length ? ` (QIDs: ${g.finding_refs.join(", ")})` : ""));
    });
  }
  return lines.join("\n");
}

export function buildFullReport(parts: {
  overview?: Overview;
  findings?: Finding[];
  attackPaths?: AttackPathsResponse;
  correlation?: Correlation;
  teams?: TeamStat[];
  compliance?: Compliance;
}): string {
  const sections: string[] = [
    "# Ghrab VOC — Full Vulnerability Operations Report",
    `_Generated ${now()}_`,
    "\n---\n",
  ];
  if (parts.overview) sections.push(buildOverviewReport(parts.overview), "\n---\n");
  if (parts.attackPaths) sections.push(buildAttackPathsReport(parts.attackPaths), "\n---\n");
  if (parts.correlation) sections.push(buildCorrelationReport(parts.correlation), "\n---\n");
  if (parts.teams) sections.push(buildTeamsReport(parts.teams), "\n---\n");
  if (parts.compliance) sections.push(buildComplianceReport(parts.compliance), "\n---\n");
  if (parts.findings) {
    sections.push(h2("Findings Summary"),
      `${parts.findings.length} total findings. Export the Findings page separately for the full CSV table.\n`);
  }
  return sections.join("\n");
}
