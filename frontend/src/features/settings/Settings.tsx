import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, KeyRound, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { useProviders } from "@/lib/hooks";
import { cx } from "@/lib/format";
import { SectionTitle, Skeleton, Tag } from "@/components/ui";

export default function Settings() {
  const { data, isLoading } = useProviders();
  const qc = useQueryClient();
  const [keys, setKeys] = useState<Record<string, string>>({});

  const saveKey = useMutation({
    mutationFn: ({ provider, api_key }: { provider: string; api_key: string }) => api.setProvider(provider, api_key),
    onSuccess: () => qc.invalidateQueries(),
  });
  const saveAgent = useMutation({
    mutationFn: ({ role, provider }: { role: string; provider: string }) => api.setAgent(role, provider),
    onSuccess: () => qc.invalidateQueries(),
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
    </div>
  );
}
