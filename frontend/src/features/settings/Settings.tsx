import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Database, KeyRound, Loader2, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useProviders, useRuns } from "@/lib/hooks";
import { cx } from "@/lib/format";
import { useToast } from "@/lib/toast";
import { SectionTitle, Skeleton, Tag } from "@/components/ui";

export default function Settings() {
  const { data, isLoading } = useProviders();
  const qc = useQueryClient();
  const toast = useToast();
  const [keys, setKeys] = useState<Record<string, string>>({});

  const saveKey = useMutation({
    mutationFn: ({ provider, api_key }: { provider: string; api_key: string }) => api.setProvider(provider, api_key),
    onSuccess: (_res, { provider }) => {
      const label = data?.providers.find((p) => p.key === provider)?.label ?? provider;
      setKeys((k) => ({ ...k, [provider]: "" }));
      qc.invalidateQueries();
      toast.success(`${label} connected`, "API key stored server-side for this session.");
    },
    onError: (e: any) => toast.error("Couldn't save key", e?.message ?? "Try again."),
  });
  const saveAgent = useMutation({
    mutationFn: ({ role, provider }: { role: string; provider: string }) => api.setAgent(role, provider),
    onSuccess: () => qc.invalidateQueries(),
    onError: (e: any) => toast.error("Couldn't reassign agent", e?.message ?? "Try again."),
  });

  if (isLoading || !data) return <Skeleton className="h-96" />;

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle sub="No single-vendor lock-in — every agent role can use a different provider, with automatic fallback. Keys are held server-side for this session.">
        Settings
      </SectionTitle>

      <div className="card p-5">
        <div className="mb-4 flex items-center gap-2 font-semibold text-ink">
          <KeyRound size={17} className="text-sage-bright" /> LLM Providers
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {data.providers.map((p) => (
            <div key={p.key} className="rounded-xl border border-line bg-surface-2/50 p-4">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-sm font-semibold text-ink">{p.label}</span>
                {p.configured ? (
                  <Tag color="rgb(var(--c-track))"><Check size={11} className="mr-0.5 inline" /> connected</Tag>
                ) : (
                  <Tag>not set</Tag>
                )}
              </div>
              <div className="mb-2 text-[11px] text-ink-faint">{p.docs_hint} · {p.default_model}</div>
              <div className="flex gap-2">
                <input
                  type="password"
                  className="input"
                  placeholder={p.configured ? "•••••••• (set)" : "Paste API key"}
                  value={keys[p.key] ?? ""}
                  onChange={(e) => setKeys((k) => ({ ...k, [p.key]: e.target.value }))}
                />
                <button
                  className="btn-primary px-3"
                  disabled={saveKey.isPending || !(keys[p.key] ?? "").trim()}
                  onClick={() => saveKey.mutate({ provider: p.key, api_key: keys[p.key] })}
                >
                  {saveKey.isPending ? <Loader2 size={14} className="animate-spin" /> : "Save"}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card p-5">
        <div className="mb-4 font-semibold text-ink">Agent → Provider Assignment</div>
        <div className="space-y-2.5">
          {data.agents.map((a) => (
            <div key={a.role} className="flex flex-col gap-2 rounded-lg border border-line bg-surface-2/50 p-3 sm:flex-row sm:items-center">
              <div className="flex-1">
                <div className="text-sm font-medium text-ink">{a.label.split(" — ")[0]}</div>
                <div className="text-xs text-ink-faint">{a.label.split(" — ")[1]}</div>
              </div>
              <select
                className="input w-auto"
                value={a.provider}
                onChange={(e) => saveAgent.mutate({ role: a.role, provider: e.target.value })}
              >
                {data.providers.map((p) => (
                  <option key={p.key} value={p.key} className={cx(!p.configured && "text-ink-faint")}>
                    {p.label} {p.configured ? "" : "(no key)"}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      </div>

      <AnalysisHistory />
    </div>
  );
}

function AnalysisHistory() {
  const { data, isLoading } = useRuns();
  const qc = useQueryClient();
  const toast = useToast();
  const [pendingId, setPendingId] = useState<string | null>(null);

  const deleteOne = useMutation({
    mutationFn: (runId: string) => api.deleteRun(runId),
    onMutate: (runId) => setPendingId(runId),
    onSuccess: () => {
      qc.invalidateQueries();
      toast.success("Run deleted");
    },
    onError: (e: any) => toast.error("Couldn't delete run", e?.message ?? "Try again."),
    onSettled: () => setPendingId(null),
  });
  const clearAll = useMutation({
    mutationFn: () => api.clearRuns(),
    onSuccess: () => {
      qc.invalidateQueries();
      toast.success("Analysis history cleared");
    },
    onError: (e: any) => toast.error("Couldn't clear history", e?.message ?? "Try again."),
  });

  const runs = data?.runs ?? [];

  return (
    <div className="card p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2 font-semibold text-ink">
          <Database size={17} className="text-sage-bright" /> Analysis History
        </div>
        {runs.length > 0 && (
          <button
            className="btn-ghost !px-3 !py-1.5 text-xs text-immediate"
            disabled={clearAll.isPending}
            onClick={() => {
              if (confirm(`Delete all ${runs.length} stored analysis run(s)? This can't be undone.`)) {
                clearAll.mutate();
              }
            }}
          >
            {clearAll.isPending ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
            Clear all
          </button>
        )}
      </div>

      {isLoading ? (
        <Skeleton className="h-24" />
      ) : runs.length === 0 ? (
        <p className="text-sm text-ink-faint">No stored analysis runs yet — findings history and trend data will show up here once you run an analysis.</p>
      ) : (
        <div className="space-y-2">
          {runs.map((r) => {
            const total = "total" in r.kpi_snapshot ? (r.kpi_snapshot as any).total : undefined;
            const when = r.completed_at
              ? new Date(r.completed_at * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
              : new Date(r.started_at * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
            return (
              <div key={r.id} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-surface-2/50 p-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-sm font-medium text-ink">
                    {when}
                    {r.status !== "complete" && (
                      <Tag color={r.status === "failed" ? "rgb(var(--c-immediate))" : undefined}>{r.status}</Tag>
                    )}
                    {r.ai_enabled && <Tag color="rgb(var(--c-track))">AI-enriched</Tag>}
                  </div>
                  <div className="mt-0.5 text-xs text-ink-faint">
                    {total !== undefined ? `${total} findings` : r.error ?? "—"}
                  </div>
                </div>
                <button
                  className="btn-ghost !px-2.5 !py-1.5 shrink-0 text-xs"
                  disabled={deleteOne.isPending && pendingId === r.id}
                  onClick={() => {
                    if (confirm("Delete this stored analysis run?")) deleteOne.mutate(r.id);
                  }}
                  title="Delete this run"
                >
                  {deleteOne.isPending && pendingId === r.id ? (
                    <Loader2 size={13} className="animate-spin" />
                  ) : (
                    <Trash2 size={13} />
                  )}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
