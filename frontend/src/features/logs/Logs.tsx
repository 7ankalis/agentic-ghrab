import { Fragment, useMemo, useState } from "react";
import {
  AlertTriangle, CheckCircle2, ChevronDown, Loader2, RotateCcw, Search, Trash2, WifiOff, X,
} from "lucide-react";
import { useAgentLog } from "@/lib/agentLog";
import { AGENT_LABELS, PROVIDER_LABELS, cx } from "@/lib/format";
import { downloadCSV, timestamp } from "@/lib/report";
import { EmptyState, ExportButton, SectionTitle } from "@/components/ui";
import type { LogEntry } from "@/lib/types";

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

function absTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function fmtCost(usd: number | null): string {
  if (usd == null) return "—";
  return usd < 0.01 ? `$${usd.toFixed(5)}` : `$${usd.toFixed(4)}`;
}

const CSV_HEADER = [
  "time_iso", "role", "provider", "model", "event", "attempt", "duration_ms",
  "tokens", "prompt_tokens", "completion_tokens", "cost_usd", "detail", "error", "group_id",
];

function toCSVRow(e: LogEntry): string {
  const cells = [
    new Date(e.ts * 1000).toISOString(), e.role, e.provider, e.model, e.event, e.attempt,
    e.duration_ms ?? "", e.tokens ?? "", e.prompt_tokens ?? "", e.completion_tokens ?? "",
    e.cost_usd ?? "", e.detail ?? "", e.error ?? "", e.group_id,
  ];
  return cells.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",");
}

function StatTile({ label, value, sub, accent }: { label: string; value: string; sub: string; accent?: string }) {
  return (
    <div className="card relative overflow-hidden p-4">
      <div
        className="absolute inset-x-0 top-0 h-[3px]"
        style={{ background: `linear-gradient(90deg, ${accent ?? "rgb(var(--c-sage))"}, transparent)` }}
      />
      <div className="font-display text-2xl font-bold leading-none text-ink">{value}</div>
      <div className="mt-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{label}</div>
      <div className="text-[11px] text-ink-faint">{sub}</div>
    </div>
  );
}

export default function Logs() {
  const { entries, active, connected, clear } = useAgentLog();
  const [roleFilter, setRoleFilter] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const roles = useMemo(() => {
    const seen = new Set([...Object.keys(AGENT_LABELS), ...entries.map((e) => e.role)]);
    return [...seen].sort();
  }, [entries]);
  const providers = useMemo(() => {
    const seen = new Set([...Object.keys(PROVIDER_LABELS), ...entries.map((e) => e.provider)]);
    return [...seen].sort();
  }, [entries]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter((e) => {
      if (roleFilter && e.role !== roleFilter) return false;
      if (providerFilter && e.provider !== providerFilter) return false;
      if (statusFilter && e.event !== statusFilter) return false;
      if (!q) return true;
      return (
        e.role.toLowerCase().includes(q) ||
        e.provider.toLowerCase().includes(q) ||
        e.model.toLowerCase().includes(q) ||
        (e.detail ?? "").toLowerCase().includes(q) ||
        (e.error ?? "").toLowerCase().includes(q)
      );
    });
  }, [entries, roleFilter, providerFilter, statusFilter, search]);

  const hasFilters = !!(roleFilter || providerFilter || statusFilter || search);

  const stats = useMemo(() => {
    const finished = entries.filter((e) => e.event !== "start");
    const successes = finished.filter((e) => e.event === "success").length;
    const errors = finished.filter((e) => e.event === "error").length;
    const durations = finished.map((e) => e.duration_ms).filter((d): d is number => d != null);
    const avgDuration = durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : null;
    const totalTokens = finished.reduce((sum, e) => sum + (e.tokens ?? 0), 0);
    const costs = finished.map((e) => e.cost_usd).filter((c): c is number => c != null);
    const totalCost = costs.length ? costs.reduce((a, b) => a + b, 0) : null;
    return {
      calls: finished.length,
      successRate: finished.length ? Math.round((successes / finished.length) * 100) : null,
      errors,
      avgDuration,
      totalTokens,
      totalCost,
    };
  }, [entries]);

  function exportCSV() {
    const rows = [CSV_HEADER.join(","), ...filtered.map(toCSVRow)];
    downloadCSV(`voc-agent-log-${timestamp()}.csv`, rows.join("\n"));
  }

  function handleClear() {
    if (!confirmClear) {
      setConfirmClear(true);
      setTimeout(() => setConfirmClear(false), 4000);
      return;
    }
    clear();
    setConfirmClear(false);
  }

  return (
    <div className="animate-fade-up space-y-5">
      <SectionTitle
        sub="Every LLM call the platform makes, live — which agent, which provider, success or fallback, at what cost. Use this to confirm the AI layer is actually working and to debug failures."
        right={
          <div className="flex items-center gap-2">
            <span
              className={cx(
                "pill",
                connected ? "text-track" : "text-immediate",
              )}
              style={{
                background: connected
                  ? "color-mix(in srgb, rgb(var(--c-track)) 14%, transparent)"
                  : "color-mix(in srgb, rgb(var(--c-immediate)) 14%, transparent)",
                border: `1px solid color-mix(in srgb, ${connected ? "rgb(var(--c-track))" : "rgb(var(--c-immediate))"} 32%, transparent)`,
              }}
              title={connected ? "Live SSE connection to the backend" : "Reconnecting to the log stream…"}
            >
              {connected ? (
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-track" />
              ) : (
                <WifiOff size={10} />
              )}
              {connected ? "Live" : "Reconnecting…"}
            </span>
            <ExportButton onClick={exportCSV} label="Export CSV" />
            <button
              onClick={handleClear}
              className={cx(
                "btn-ghost !px-3 !py-1.5 text-xs",
                confirmClear && "!border-immediate/50 !text-immediate",
              )}
              title="Clear log history (local + server)"
            >
              <Trash2 size={13} /> {confirmClear ? "Confirm clear?" : "Clear"}
            </button>
          </div>
        }
      >
        Agent Activity Log
      </SectionTitle>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatTile label="Total Calls" value={String(stats.calls)} sub={`${entries.length} events logged`} />
        <StatTile
          label="Success Rate"
          value={stats.successRate != null ? `${stats.successRate}%` : "—"}
          sub={`${stats.errors} error${stats.errors === 1 ? "" : "s"}`}
          accent={stats.successRate != null && stats.successRate < 90 ? "rgb(var(--c-act))" : undefined}
        />
        <StatTile
          label="Errors / Fallbacks"
          value={String(stats.errors)}
          sub="incl. rate-limit retries"
          accent={stats.errors > 0 ? "rgb(var(--c-immediate))" : undefined}
        />
        <StatTile
          label="Avg Duration"
          value={stats.avgDuration != null ? `${Math.round(stats.avgDuration)}ms` : "—"}
          sub="per resolved call"
        />
        <StatTile label="Total Tokens" value={stats.totalTokens.toLocaleString()} sub="prompt + completion" />
        <StatTile
          label="Est. Cost"
          value={stats.totalCost != null ? fmtCost(stats.totalCost) : "—"}
          sub="litellm pricing table"
          accent="rgb(var(--c-purple))"
        />
      </div>

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
                <span className="text-ink-faint">→ {PROVIDER_LABELS[a.provider] ?? a.provider}</span>
                {a.attempt > 1 && <span className="text-ink-faint">· attempt {a.attempt}</span>}
                {a.detail && <span className="text-ink-faint">· {a.detail}</span>}
                <span className="font-mono text-[11px] text-ink-faint">{relTime(a.ts)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="input flex w-auto min-w-[220px] items-center gap-2 !py-1.5">
          <Search size={13} className="text-ink-faint" />
          <input
            className="w-full bg-transparent text-sm outline-none placeholder:text-ink-faint"
            placeholder="Search agent, provider, model, detail, error…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button onClick={() => setSearch("")} className="text-ink-faint hover:text-ink">
              <X size={13} />
            </button>
          )}
        </div>
        <select className="input w-auto" value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
          <option value="">All agents</option>
          {roles.map((r) => <option key={r} value={r}>{AGENT_LABELS[r] ?? r}</option>)}
        </select>
        <select className="input w-auto" value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)}>
          <option value="">All providers</option>
          {providers.map((p) => <option key={p} value={p}>{PROVIDER_LABELS[p] ?? p}</option>)}
        </select>
        <select className="input w-auto" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="start">In progress</option>
          <option value="success">Success</option>
          <option value="error">Error / fallback</option>
        </select>
        {hasFilters && (
          <button
            onClick={() => { setRoleFilter(""); setProviderFilter(""); setStatusFilter(""); setSearch(""); }}
            className="btn-ghost !px-3 !py-1.5 text-xs"
          >
            <RotateCcw size={12} /> Reset filters
          </button>
        )}
        <span className="ml-auto text-xs text-ink-faint">
          {filtered.length} of {entries.length} events
        </span>
      </div>

      {entries.length === 0 ? (
        <EmptyState
          title="No agent calls logged yet"
          hint="Trigger a Full Analysis or ask the AI Analyst a question to see live LLM activity here."
        />
      ) : (
        <div className="card overflow-hidden">
          <div className="max-h-[640px] overflow-y-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 z-10 bg-surface">
                <tr className="border-b border-line">
                  {["", "Time", "Agent", "Provider / Model", "Status", "Duration", "Tokens", "Cost", "Detail"].map((hd) => (
                    <th key={hd} className="whitespace-nowrap px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wide text-ink-faint">
                      {hd}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((e) => {
                  const meta = STATUS_META[e.event];
                  const key = `${e.id}-${e.event}`;
                  const isExpanded = expanded === key;
                  const hasDetail = !!(e.error || e.detail || e.group_id);
                  return (
                    <Fragment key={key}>
                      <tr
                        onClick={() => hasDetail && setExpanded(isExpanded ? null : key)}
                        className={cx(
                          "border-b border-line/60 last:border-0",
                          hasDetail && "cursor-pointer hover:bg-surface-2/60",
                          isExpanded && "bg-surface-2/60",
                        )}
                      >
                        <td className="px-2 py-2 text-ink-faint">
                          {hasDetail && (
                            <ChevronDown size={13} className={cx("transition-transform", isExpanded && "rotate-180")} />
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 text-xs text-ink-faint" title={absTime(e.ts)}>
                          {relTime(e.ts)}
                        </td>
                        <td className="px-4 py-2 font-medium text-ink">{AGENT_LABELS[e.role] ?? e.role}</td>
                        <td className="whitespace-nowrap px-4 py-2 text-ink-muted">
                          {PROVIDER_LABELS[e.provider] ?? e.provider} <span className="text-ink-faint">· {e.model}</span>
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
                          {e.attempt > 1 && (
                            <span className="ml-1.5 text-[11px] text-ink-faint">×{e.attempt}</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-muted">
                          {e.duration_ms != null ? `${e.duration_ms}ms` : "—"}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-muted">
                          {e.tokens ?? "—"}
                          {(e.prompt_tokens != null || e.completion_tokens != null) && (
                            <span className="text-ink-faint"> ({e.prompt_tokens ?? "?"}/{e.completion_tokens ?? "?"})</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-muted">{fmtCost(e.cost_usd)}</td>
                        <td
                          className={cx("max-w-xs truncate px-4 py-2 text-xs", e.error ? "text-immediate" : "text-ink-muted")}
                        >
                          {e.error ?? e.detail ?? "—"}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${key}-detail`} className="border-b border-line/60 bg-surface-2/40 last:border-0">
                          <td colSpan={9} className="px-4 py-3">
                            <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-3">
                              <div>
                                <div className="mb-1 font-semibold uppercase tracking-wide text-ink-faint">Timestamp</div>
                                <div className="font-mono text-ink-muted">{absTime(e.ts)}</div>
                              </div>
                              <div>
                                <div className="mb-1 font-semibold uppercase tracking-wide text-ink-faint">Call ID / Group</div>
                                <div className="font-mono text-ink-muted">#{e.id} · group {e.group_id || "—"} · attempt {e.attempt}</div>
                              </div>
                              <div>
                                <div className="mb-1 font-semibold uppercase tracking-wide text-ink-faint">Model</div>
                                <div className="font-mono text-ink-muted">{e.provider}/{e.model}</div>
                              </div>
                              {e.detail && (
                                <div className="md:col-span-3">
                                  <div className="mb-1 font-semibold uppercase tracking-wide text-ink-faint">Detail</div>
                                  <div className="whitespace-pre-wrap text-ink-muted">{e.detail}</div>
                                </div>
                              )}
                              {e.error && (
                                <div className="md:col-span-3">
                                  <div className="mb-1 font-semibold uppercase tracking-wide text-immediate">Error</div>
                                  <div className="whitespace-pre-wrap text-immediate/90">{e.error}</div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="p-8 text-center text-sm text-ink-muted">
                No events match the current filters.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
