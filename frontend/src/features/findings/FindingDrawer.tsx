import { useMutation } from "@tanstack/react-query";
import { RadialBar, RadialBarChart, PolarAngleAxis, ResponsiveContainer } from "recharts";
import { CheckCircle2, Loader2, Sparkles, Wrench } from "lucide-react";
import { api } from "@/lib/api";
import { bandColor } from "@/lib/format";
import { AiBadge, BandPill, Tag } from "@/components/ui";
import Drawer from "@/components/Drawer";
import { useFinding } from "@/lib/hooks";
import { TACTIC_COLOR } from "@/lib/format";
import type { Remediation } from "@/lib/types";

function Gauge({ grs, band }: { grs: number; band: string }) {
  const color = bandColor(band);
  return (
    <div className="relative h-32 w-32">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart innerRadius="72%" outerRadius="100%" data={[{ v: grs }]} startAngle={90} endAngle={-270}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar background={{ fill: "rgba(140,175,160,0.1)" }} dataKey="v" cornerRadius={8} fill={color} isAnimationActive={false} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="font-display text-3xl font-bold" style={{ color }}>{grs}</div>
          <div className="text-[10px] uppercase tracking-wide text-ink-faint">/ 100 GRS</div>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line py-2 text-sm last:border-0">
      <span className="text-ink-faint">{label}</span>
      <span className="text-right font-medium text-ink">{value}</span>
    </div>
  );
}

export default function FindingDrawer({ qid, onClose }: { qid: number | null; onClose: () => void }) {
  const { data: f, isLoading } = useFinding(qid);
  const rem = useMutation<Remediation>({ mutationFn: () => api.remediation(qid!) });

  return (
    <Drawer open={qid != null} onClose={onClose}>
      {isLoading || !f ? (
        <div className="grid h-full place-items-center text-ink-muted">
          <Loader2 className="animate-spin" />
        </div>
      ) : (
        <div className="p-6 pt-14">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <BandPill band={f.band} />
            {f.kev && <Tag color="#f7853a">KEV</Tag>}
            {f.dora_cif && <Tag color="#c97bd8">DORA CIF</Tag>}
            <span className="font-mono text-xs text-ink-faint">QID {f.qid}</span>
          </div>
          <h2 className="font-display text-xl font-semibold leading-snug text-ink">{f.title}</h2>
          <p className="mt-1 text-sm text-ink-faint">
            {f.cve} · {f.cvss_vector}
          </p>

          <div className="mt-5 flex items-center gap-6">
            <Gauge grs={f.grs} band={f.band} />
            <div className="flex-1 space-y-1">
              <div className="text-xs text-ink-faint">SLA</div>
              <div className="text-sm font-semibold text-ink">{f.sla}</div>
              {f.capability && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <Tag color={TACTIC_COLOR[f.capability.tactic] ?? "#55a185"}>{f.capability.tactic}</Tag>
                  {f.capability.effects.slice(0, 3).map((e) => (
                    <Tag key={e}>{e.replace(/_/g, " ")}</Tag>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="mt-6 grid grid-cols-2 gap-x-6">
            <div>
              <Row label="Host" value={`${f.hostname}`} />
              <Row label="IP · Zone" value={`${f.ip} · ${f.zone}`} />
              <Row label="Team" value={f.team} />
              <Row label="Exposure" value={`${f.exposure_tier} (×${f.exposure_multiplier})`} />
            </div>
            <div>
              <Row label="Compliance" value={f.compliance_ref} />
              <Row label="Category" value={f.category} />
              <Row label="Status" value={f.status} />
              <Row label="Patch" value={f.patch_available || "—"} />
            </div>
          </div>

          <div className="mt-6">
            <div className="label mb-2">GRS Decomposition</div>
            <div className="card-2 divide-y divide-line p-3">
              {f.grs_factors.map((g) => (
                <div key={g.label} className="flex items-center justify-between py-1.5 text-sm">
                  <span className="text-ink-muted">
                    {g.label} <span className="text-ink-faint">· {g.weight}</span>
                  </span>
                  <span className="font-mono font-medium text-ink">{g.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-5 space-y-4 text-sm">
            <Block title="Description" body={f.description} />
            <Block title="Consequence" body={f.consequence} />
            <Block title="Scanner Remediation" body={f.remediation} />
          </div>

          {/* AI remediation */}
          <div className="mt-6">
            {!rem.data && (
              <button className="btn-primary w-full" onClick={() => rem.mutate()} disabled={rem.isPending}>
                {rem.isPending ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />}
                Generate AI Remediation Plan
              </button>
            )}
            {rem.isError && (
              <p className="mt-2 text-sm text-immediate">
                {(rem.error as Error).message.includes("409")
                  ? "No AI provider connected — add a key in Settings."
                  : (rem.error as Error).message}
              </p>
            )}
            {rem.data && !rem.data.error && (
              <div className="mt-2 space-y-4 rounded-xl border border-sage/20 bg-sage/[0.06] p-4">
                <div>
                  <AiBadge>Remediation Agent</AiBadge>
                  <p className="text-sm leading-relaxed text-ink-muted">{rem.data.analyst_summary}</p>
                </div>
                {rem.data.step_by_step && (
                  <div>
                    <div className="mb-1.5 flex items-center gap-1.5 text-sm font-semibold text-ink">
                      <Wrench size={14} /> Steps
                    </div>
                    <ol className="space-y-1.5">
                      {rem.data.step_by_step.map((s, i) => (
                        <li key={i} className="flex gap-2 text-sm text-ink-muted">
                          <span className="font-mono text-xs text-sage-bright">{i + 1}.</span>
                          {s}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
                {rem.data.validation_steps && (
                  <div>
                    <div className="mb-1.5 flex items-center gap-1.5 text-sm font-semibold text-ink">
                      <CheckCircle2 size={14} /> Validation
                    </div>
                    <ul className="space-y-1">
                      {rem.data.validation_steps.map((s, i) => (
                        <li key={i} className="text-sm text-ink-muted">· {s}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="flex flex-wrap gap-2 pt-1">
                  {rem.data.risk_of_fix && <Tag>Risk: {rem.data.risk_of_fix}</Tag>}
                  {rem.data.estimated_effort && <Tag color="#7fd0ad">{rem.data.estimated_effort}</Tag>}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </Drawer>
  );
}

function Block({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <div className="label mb-1">{title}</div>
      <p className="leading-relaxed text-ink-muted">{body}</p>
    </div>
  );
}
