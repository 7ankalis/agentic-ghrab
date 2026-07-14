import type { Band } from "./types";

export const BAND_META: Record<Band, { color: string; label: string; text: string }> = {
  IMMEDIATE: { color: "#f0553f", label: "Immediate", text: "24–72h" },
  ACT: { color: "#f7853a", label: "Act", text: "7 days" },
  ATTEND: { color: "#e8bd4a", label: "Attend", text: "30 days" },
  "TRACK*": { color: "#6f97b8", label: "Track*", text: "90 days" },
  TRACK: { color: "#4fae8b", label: "Track", text: "Monitor" },
};

export const BAND_ORDER: Band[] = ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"];

export function bandColor(band: string): string {
  return BAND_META[band as Band]?.color ?? "#6c7d76";
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
  entry: { color: "#f0553f", label: "Initial access" },
  segmentation: { color: "#f7853a", label: "Segmentation break", dashed: true },
  credential: { color: "#e8bd4a", label: "Credential reuse", dashed: true },
  domain: { color: "#c97bd8", label: "Domain-admin reach", dashed: true },
  lateral: { color: "#6f97b8", label: "Lateral movement" },
};

export const TACTIC_COLOR: Record<string, string> = {
  "Initial Access": "#f0553f",
  Execution: "#f7853a",
  "Privilege Escalation": "#c97bd8",
  "Credential Access": "#e8bd4a",
  "Lateral Movement": "#6f97b8",
  Impact: "#f0553f",
  Discovery: "#4fae8b",
};

export function confidenceColor(c: string): string {
  return c === "high" ? "#4fae8b" : c === "medium" ? "#e8bd4a" : "#f7853a";
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
