import type {
  AttackPathsResponse, Compliance, Correlation, DatasetsResponse, FindingDetail,
  GraphPayload, Kpis, LogEntry, Overview, ProvidersResponse, Remediation,
  RunSummary, TeamStat, Verification,
} from "./types";
import type { Finding } from "./types";

const BASE = "/api";

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} — ${path}`);
  return r.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} — ${path}`);
  return r.json() as Promise<T>;
}

async function del<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`, { method: "DELETE" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} — ${path}`);
  return r.json() as Promise<T>;
}

export const api = {
  overview: () => get<Overview>("/overview"),
  kpis: () => get<Kpis>("/kpis"),
  findings: () => get<{ findings: Finding[]; total: number }>("/findings"),
  finding: (qid: number) => get<FindingDetail>(`/findings/${qid}`),
  remediation: (qid: number) => post<Remediation>(`/findings/${qid}/remediation`),
  getRemediation: (qid: number) => get<Remediation & { generated?: boolean }>(`/findings/${qid}/remediation`),
  attackPaths: () => get<AttackPathsResponse>("/attack-paths"),
  verification: () => get<Verification>("/verification"),
  graph: () => get<GraphPayload>("/graph"),
  correlation: () => get<{ correlation: Correlation; ai_enabled: boolean }>("/correlation"),
  compliance: () => get<{ compliance: Compliance; ai_enabled: boolean }>("/compliance"),
  teams: () => get<{ teams: TeamStat[] }>("/teams"),
  datasets: () => get<DatasetsResponse>("/datasets"),
  selectDataset: (key: string) =>
    post<{ ok: boolean; active: string; name: string }>("/datasets/select", { key }),
  providers: () => get<ProvidersResponse>("/settings/providers"),
  setProvider: (provider: string, api_key: string) =>
    post<{ ok: boolean }>("/settings/providers", { provider, api_key }),
  setAgent: (role: string, provider: string) =>
    post<{ ok: boolean }>("/settings/agent", { role, provider }),
  logs: () => get<{ logs: LogEntry[] }>("/logs"),
  clearLogs: () => del<{ ok: boolean }>("/logs"),
  analyzeStatus: () =>
    get<{ running: boolean; lines: { event: string; message: string; level: string }[] }>(
      "/analyze/status",
    ),
  cancelAnalysis: () => post<{ ok: boolean; running: boolean }>("/analyze/cancel"),
  reuseRun: (runId: string) => post<{ ok: boolean; kpis: Kpis }>(`/analyze/reuse/${runId}`),
  runs: () => get<{ runs: RunSummary[] }>("/analyze/runs"),
  deleteRun: (runId: string) => del<{ ok: boolean }>(`/analyze/runs/${runId}`),
  clearRuns: () => del<{ ok: boolean; deleted: number }>("/analyze/runs"),
};

/**
 * Stream Server-Sent Events; calls onEvent(event, data) per frame.
 * Pass `body` for a POST stream (chat, analyze) or omit it for a GET stream
 * (the live agent-activity log).
 */
export async function streamSSE(
  path: string,
  body: unknown | undefined,
  onEvent: (event: string, data: any) => void,
  signal?: AbortSignal,
): Promise<void> {
  const r = await fetch(`${BASE}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  if (!r.body) throw new Error("No stream body");
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const frames = buf.split("\n\n");
    buf = frames.pop() ?? "";
    for (const frame of frames) {
      let event = "message";
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (data) {
        try {
          onEvent(event, JSON.parse(data));
        } catch {
          onEvent(event, data);
        }
      }
    }
  }
}
