import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, RotateCcw, Trash2, XCircle } from "lucide-react";
import { useRuns } from "@/lib/hooks";
import { api } from "@/lib/api";
import { useToast } from "@/lib/toast";
import { BAND_ORDER, cx } from "@/lib/format";
import { EmptyState, SectionTitle, Skeleton } from "@/components/ui";
import { BandTrendChart, GrsTrendChart, type BandTrendPoint, type GrsTrendPoint } from "@/components/charts";
import type { Kpis, RunSummary } from "@/lib/types";

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const STATUS_META: Record<RunSummary["status"], { icon: typeof CheckCircle2; color: string; label: string }> = {
  complete: { icon: CheckCircle2, color: "rgb(var(--c-track))", label: "Complete" },
  running: { icon: Loader2, color: "rgb(var(--c-track2))", label: "Running" },
  failed: { icon: XCircle, color: "rgb(var(--c-immediate))", label: "Failed" },
};

function hasKpis(run: RunSummary): run is RunSummary & { kpi_snapshot: Kpis } {
  return "avg_grs" in run.kpi_snapshot;
}

export default function Trends() {
  const { data, isLoading } = useRuns();
  const qc = useQueryClient();
  const toast = useToast();
  const [reusingId, setReusingId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [confirmClearAll, setConfirmClearAll] = useState(false);

  if (isLoading || !data) return <Skeleton className="h-96" />;

  // Oldest → newest for the charts; newest-first for the list below so the
  // most recent run is always the first thing an operator sees.
  const chronological = [...data.runs].sort((a, b) => a.started_at - b.started_at);
  const completed = chronological.filter(hasKpis);

  const grsData: GrsTrendPoint[] = completed.map((r) => ({
    label: fmtDate(r.started_at),
    avg_grs: r.kpi_snapshot.avg_grs,
  }));

  const bandData: BandTrendPoint[] = completed.map((r) => {
    const row = { label: fmtDate(r.started_at) } as BandTrendPoint;
    for (const b of BAND_ORDER) {
      row[b] = r.kpi_snapshot.band_distribution.find((d) => d.band === b)?.count ?? 0;
    }
    return row;
  });

  async function handleReuse(runId: string) {
    setReusingId(runId);
    try {
      await api.reuseRun(runId);
      await qc.invalidateQueries();
      toast.success("Reusing run", "Loaded that run's results as the active analysis.");
    } catch (e: any) {
      toast.error("Reuse failed", e?.message ?? "Could not reuse this run.");
    } finally {
      setReusingId(null);
    }
  }

  // Mirrors Logs.tsx's confirmClear pattern: first click arms a 4s
  // confirmation window, second click within it actually deletes.
  async function handleDelete(runId: string) {
    if (confirmDeleteId !== runId) {
      setConfirmDeleteId(runId);
      setTimeout(() => setConfirmDeleteId((c) => (c === runId ? null : c)), 4000);
      return;
    }
    setConfirmDeleteId(null);
    try {
      await api.deleteRun(runId);
      await qc.invalidateQueries();
      toast.success("Run deleted", "That run's history was removed.");
    } catch (e: any) {
      toast.error("Delete failed", e?.message ?? "Could not delete this run.");
    }
  }

  async function handleClearAll() {
    if (!confirmClearAll) {
      setConfirmClearAll(true);
      setTimeout(() => setConfirmClearAll(false), 4000);
      return;
    }
    setConfirmClearAll(false);
    try {
      const res = await api.clearRuns();
      await qc.invalidateQueries();
      toast.success("History cleared", `Deleted ${res.deleted} run${res.deleted === 1 ? "" : "s"}.`);
    } catch (e: any) {
      toast.error("Clear failed", e?.message ?? "Could not clear run history.");
    }
  }

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle
        sub="How risk for this enterprise has moved across every analysis run — spot regressions, confirm remediation is landing."
        right={
          data.runs.length > 0 && (
            <button
              onClick={handleClearAll}
              className={cx("btn-ghost !px-3 !py-1.5 text-xs", confirmClearAll && "!border-immediate/50 !text-immediate")}
              title="Delete all run history for this enterprise"
            >
              <Trash2 size={13} /> {confirmClearAll ? "Confirm clear all?" : "Clear history"}
            </button>
          )
        }
      >
        Risk Trend
      </SectionTitle>

      {data.runs.length === 0 ? (
        <EmptyState
          title="No run history yet"
          hint="Run a Full Analysis to start building a trend — every completed run is snapshotted here."
        />
      ) : completed.length < 2 ? (
        <EmptyState
          title="Not enough completed runs to chart a trend"
          hint="Run the analysis pipeline at least twice (Re-run or Full Analysis) to see risk move over time."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="card p-5">
            <div className="label mb-3">Average GRS Over Time</div>
            <GrsTrendChart data={grsData} />
          </div>
          <div className="card p-5">
            <div className="label mb-3">Risk Band Distribution Over Time</div>
            <BandTrendChart data={bandData} />
          </div>
        </div>
      )}

      {data.runs.length > 0 && (
        <div className="card overflow-hidden">
          <div className="max-h-[560px] overflow-y-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 z-10 bg-surface">
                <tr className="border-b border-line">
                  {["Started", "Status", "Mode", "Findings", "Avg GRS", "Immediate", ""].map((hd) => (
                    <th key={hd} className="whitespace-nowrap px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wide text-ink-faint">
                      {hd}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...chronological].reverse().map((r) => {
                  const meta = STATUS_META[r.status];
                  const StatusIcon = meta.icon;
                  const snap = hasKpis(r) ? r.kpi_snapshot : null;
                  return (
                    <tr
                      key={r.id}
                      className={cx(
                        "border-b border-line/60 transition-colors last:border-0 hover:bg-surface-2/60",
                        r.status !== "complete" && "opacity-60",
                      )}
                    >
                      <td className="whitespace-nowrap px-4 py-2.5 text-xs text-ink-faint" title={new Date(r.started_at * 1000).toISOString()}>
                        {fmtDate(r.started_at)}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className="pill"
                          style={{
                            background: `color-mix(in srgb, ${meta.color} 14%, transparent)`,
                            color: meta.color,
                            border: `1px solid color-mix(in srgb, ${meta.color} 32%, transparent)`,
                          }}
                        >
                          <StatusIcon size={10} className={r.status === "running" ? "animate-spin" : ""} />
                          {meta.label}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-ink-muted">{r.ai_enabled ? "AI-enriched" : "Deterministic"}</td>
                      <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-ink-muted">{snap?.total ?? "—"}</td>
                      <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-ink-muted">{snap?.avg_grs ?? "—"}</td>
                      <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-ink-muted">{snap?.immediate ?? "—"}</td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center justify-end gap-1.5">
                          {r.status === "complete" && (
                            <button
                              onClick={() => handleReuse(r.id)}
                              disabled={reusingId === r.id}
                              className="btn-ghost !px-2 !py-1 text-xs"
                              title="Adopt this run as the active analysis"
                            >
                              {reusingId === r.id ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />}
                              Reuse
                            </button>
                          )}
                          <button
                            onClick={() => handleDelete(r.id)}
                            className={cx("btn-ghost !px-2 !py-1 text-xs", confirmDeleteId === r.id && "!border-immediate/50 !text-immediate")}
                            title="Delete this run"
                          >
                            <Trash2 size={12} /> {confirmDeleteId === r.id ? "Confirm?" : "Delete"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
