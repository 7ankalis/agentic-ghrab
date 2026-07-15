import type { Band } from "./types";

export const BAND_META: Record<Band, { color: string; label: string; text: string }> = {
  IMMEDIATE: { color: "rgb(var(--c-immediate))", label: "Immediate", text: "24–72h" },
  ACT: { color: "rgb(var(--c-act))", label: "Act", text: "7 days" },
  ATTEND: { color: "rgb(var(--c-attend))", label: "Attend", text: "30 days" },
  "TRACK*": { color: "rgb(var(--c-track2))", label: "Track*", text: "90 days" },
  TRACK: { color: "rgb(var(--c-track))", label: "Track", text: "Monitor" },
};

export const BAND_ORDER: Band[] = ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"];

export function bandColor(band: string): string {
  return BAND_META[band as Band]?.color ?? "rgb(var(--c-ink-faint))";
}

export function bandForGrs(grs: number): Band {
  if (grs >= 80) return "IMMEDIATE";
  if (grs >= 60) return "ACT";
  if (grs >= 40) return "ATTEND";
  if (grs >= 20) return "TRACK*";
  return "TRACK";
}

// Edge/kind styling for the attack graph.
export const EDGE_META: Record<string, { color: string; label: string; dashed?: boolean }> = {
  entry: { color: "rgb(var(--c-immediate))", label: "Initial access" },
  segmentation: { color: "rgb(var(--c-act))", label: "Segmentation break", dashed: true },
  credential: { color: "rgb(var(--c-attend))", label: "Credential reuse", dashed: true },
  domain: { color: "rgb(var(--c-purple))", label: "Domain-admin reach", dashed: true },
  lateral: { color: "rgb(var(--c-track2))", label: "Lateral movement" },
};

export const AGENT_LABELS: Record<string, string> = {
  correlation: "Correlation Agent",
  attack_path: "Attack Path Agent",
  remediation: "Remediation Agent",
  compliance: "Compliance Agent",
  triage: "Triage / Analyst Agent",
};

export const PROVIDER_LABELS: Record<string, string> = {
  anthropic: "Anthropic (Claude)",
  openai: "OpenAI (GPT)",
  groq: "Groq",
  mistral: "Mistral",
  gemini: "Google (Gemini)",
  deepseek: "DeepSeek",
  xai: "xAI (Grok)",
};

export const TACTIC_COLOR: Record<string, string> = {
  "Initial Access": "rgb(var(--c-immediate))",
  Execution: "rgb(var(--c-act))",
  "Privilege Escalation": "rgb(var(--c-purple))",
  "Credential Access": "rgb(var(--c-attend))",
  "Lateral Movement": "rgb(var(--c-track2))",
  Impact: "rgb(var(--c-immediate))",
  Discovery: "rgb(var(--c-track))",
};

export function confidenceColor(c: string): string {
  return c === "high" ? "rgb(var(--c-track))" : c === "medium" ? "rgb(var(--c-attend))" : "rgb(var(--c-act))";
}

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

export function initials(name: string): string {
  return name
    .replace(/team/i, "")
    .trim()
    .split(/[\s-]+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}
