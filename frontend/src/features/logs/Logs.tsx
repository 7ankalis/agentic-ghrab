import { useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2 } from "lucide-react";
import { useAgentLog } from "@/lib/agentLog";
import { AGENT_LABELS, cx } from "@/lib/format";
import { SectionTitle } from "@/components/ui";

const STATUS_META: Record<string, { color: string; label: string }> = {
  start: { color: "rgb(var(--c-track2))", label: "calling…" },
  success: { color: "rgb(var(--c-track))", label: "ok" },
  error: { color: "rgb(var(--c-immediate))", label: "error" },
};

function relTime(ts: number): string {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 5) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export default function Logs() {
  const { entries, active } = useAgentLog();
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const roles = useMemo(() => [...new Set(entries.map((e) => e.role))].sort(), [entries]);
  const filtered = useMemo(
    () => entries.filter((e) => (!roleFilter || e.role === roleFilter) && (!statusFilter || e.event === statusFilter)),
    [entries, roleFilter, statusFilter],
  );

  return (
    <div className="animate-fade-up space-y-5">
      <SectionTitle sub="Every LLM call the platform makes, live — which agent, which provider, success or fallback. Use this to confirm the AI layer is actually working.">
        Agent Activity Log
      </SectionTitle>

      <div className="card p-4">
        <div className="label mb-3">Currently Running</div>
        {active.length === 0 ? (
          <p className="text-sm text-ink-faint">No agent calls in flight — trigger an analysis or ask the AI Analyst a question.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {active.map((a) => (
              <div key={a.id} className="flex items-center gap-2 rounded-lg border border-track2/40 bg-track2/10 px-3 py-2 text-sm">
                <Loader2 size={14} className="animate-spin text-track2" />
                <span className="font-medium text-ink">{AGENT_LABELS[a.role] ?? a.role}</span>
                <span className="text-ink-faint">→ {a.provider}</span>
                {a.detail && <span className="text-ink-faint">· {a.detail}</span>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select className="input w-auto" value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
          <option value="">All agents</option>
          {roles.map((r) => <option key={r} value={r}>{AGENT_LABELS[r] ?? r}</option>)}
        </select>
        <select className="input w-auto" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="start">In progress</option>
          <option value="success">Success</option>
          <option value="error">Error / fallback</option>
        </select>
        <span className="ml-auto text-xs text-ink-faint">{filtered.length} events</span>
      </div>

      <div className="card overflow-hidden">
        <div className="max-h-[600px] overflow-y-auto">
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-line">
                {["Time", "Agent", "Provider / Model", "Status", "Duration", "Tokens", "Detail"].map((hd) => (
                  <th key={hd} className="whitespace-nowrap px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wide text-ink-faint">
                    {hd}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => {
                const meta = STATUS_META[e.event];
                return (
                  <tr key={`${e.id}-${e.event}`} className="border-b border-line/60 last:border-0">
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-ink-faint">{relTime(e.ts)}</td>
                    <td className="px-4 py-2 font-medium text-ink">{AGENT_LABELS[e.role] ?? e.role}</td>
                    <td className="whitespace-nowrap px-4 py-2 text-ink-muted">
                      {e.provider} <span className="text-ink-faint">· {e.model}</span>
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className="pill"
                        style={{
                          background: `color-mix(in srgb, ${meta.color} 14%, transparent)`,
                          color: meta.color,
                          border: `1px solid color-mix(in srgb, ${meta.color} 32%, transparent)`,
                        }}
                      >
                        {e.event === "start" ? (
                          <Loader2 size={10} className="animate-spin" />
                        ) : e.event === "success" ? (
                          <CheckCircle2 size={10} />
                        ) : (
                          <AlertTriangle size={10} />
                        )}
                        {meta.label}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-muted">
                      {e.duration_ms != null ? `${e.duration_ms}ms` : "—"}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-muted">{e.tokens ?? "—"}</td>
                    <td
                      className={cx("max-w-xs truncate px-4 py-2 text-xs", e.error ? "text-immediate" : "text-ink-muted")}
                      title={e.error ?? e.detail}
                    >
                      {e.error ?? e.detail ?? "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="p-8 text-center text-sm text-ink-muted">
              No agent calls logged yet — trigger a Full Analysis or ask the AI Analyst a question.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
