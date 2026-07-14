export type Band = "IMMEDIATE" | "ACT" | "ATTEND" | "TRACK*" | "TRACK";

export interface LogEntry {
  id: number;
  ts: number;
  role: string;
  provider: string;
  model: string;
  event: "start" | "success" | "error";
  duration_ms: number | null;
  tokens: number | null;
  error: string | null;
  detail: string;
}

export interface Capability {
  technique: string;
  tactic: string;
  effects: string[];
  precondition: string;
  is_entry: boolean;
}

export interface Finding {
  qid: number;
  title: string;
  severity: number;
  cvss: number;
  cvss_vector: string;
  cve: string;
  category: string;
  ip: string;
  hostname: string;
  vlan: string;
  zone: string;
  port: string;
  service: string;
  team: string;
  status: string;
  compliance_ref: string;
  attack_path_ref: string;
  grs: number;
  band: Band;
  sla: string;
  impact_score: number;
  exposure_tier: string;
  exposure_multiplier: number;
  epss: number;
  kev: boolean;
  acw: number;
  tcm: number;
  ccf: number;
  dora_cif: boolean;
  dora_sla_capped: boolean;
  capability: Capability | null;
}

export interface FindingDetail extends Finding {
  description: string;
  consequence: string;
  remediation: string;
  patch_available: string;
  grs_factors: { label: string; weight: string; value: number | string }[];
}

export interface Kpis {
  total: number;
  immediate: number;
  act: number;
  avg_grs: number;
  kev: number;
  dora_cif: number;
  band_distribution: { band: Band; count: number }[];
  discovered_paths: number;
  crown_jewels: number;
  ai_enabled: boolean;
}

export interface StepFindingRef {
  title: string;
  hostname: string;
  grs: number;
  band: Band;
  team: string;
}

export interface PathStep {
  host: string;
  zone: string;
  arrival_via_qid: number | null;
  arrival_technique: string;
  arrival_kind: string;
  exploit_qid: number | null;
  exploit_technique: string;
  grs: number;
  arrival_finding: StepFindingRef | null;
  exploit_finding: StepFindingRef | null;
}

export interface AttackPath {
  path_id: string;
  entry: string;
  target: string;
  score: number;
  max_grs: number;
  blast_radius: number;
  target_value: number;
  enabler_qids: number[];
  hosts: string[];
  length: number;
  steps: PathStep[];
  headline: string;
  narrative: string;
  business_impact: string;
  choke_point: string;
  confidence: string;
  novelty: string;
}

export interface ToxicCombo {
  title: string;
  mechanism: string;
  involved_qids: number[];
  why_it_matters: string;
}

export interface AttackPathsResponse {
  paths: AttackPath[];
  toxic_combinations: ToxicCombo[];
  summary: string;
  documented: { path_id: string; entry: string; target: string; hosts: string[] }[];
  ai_enabled: boolean;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "internet" | "asset";
  zone: string;
  vlan: string;
  grs: number;
  crown: boolean;
  value: number;
  entry: boolean;
  team: string;
  role?: string;
  qids?: number[];
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: string;
  qid: number | null;
  technique: string;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TeamStat {
  team: string;
  findings: number;
  avg_grs: number;
  max_grs: number;
  immediate: number;
  kev: number;
  dora_cif: number;
}

export interface Overview {
  kpis: Kpis;
  executive_summary: string;
  cvss_vs_grs: { qid: number; title: string; hostname: string; cvss: number; grs: number; band: Band }[];
  top_findings: Finding[];
  top_paths: AttackPath[];
  action_bands: { low: number; high: number; band: Band; sla: string }[];
  generated_at: number;
}

export interface Remediation {
  analyst_summary?: string;
  step_by_step?: string[];
  validation_steps?: string[];
  risk_of_fix?: string;
  estimated_effort?: string;
  error?: string;
}

export interface Correlation {
  cross_findings_insights?: string[];
  top_risk_teams?: { team: string; rationale: string }[];
  reprioritization_flags?: { qid: number; hostname: string; reason: string }[];
  error?: string;
}

export interface Compliance {
  frameworks_in_scope?: string[];
  key_gaps?: { framework: string; finding_refs: number[]; gap_description: string }[];
  dora_overlay_note?: string;
  executive_summary?: string;
  error?: string;
}

export interface ProviderInfo {
  key: string;
  label: string;
  default_model: string;
  docs_hint: string;
  configured: boolean;
}

export interface AgentAssignment {
  role: string;
  label: string;
  provider: string;
}

export interface ProvidersResponse {
  providers: ProviderInfo[];
  agents: AgentAssignment[];
}
