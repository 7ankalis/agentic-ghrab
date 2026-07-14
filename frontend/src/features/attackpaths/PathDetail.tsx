import { ArrowDown, KeyRound, ShieldOff, Crosshair, Target, TriangleAlert } from "lucide-react";
import { EDGE_META, bandColor, confidenceColor } from "@/lib/format";
import { AiBadge, Tag } from "@/components/ui";
import type { AttackPath, PathStep } from "@/lib/types";

const KIND_ICON: Record<string, typeof KeyRound> = {
  entry: Crosshair,
  segmentation: ShieldOff,
  credential: KeyRound,
  domain: KeyRound,
  lateral: ArrowDown,
};

function Step({ step, index }: { step: PathStep; index: number }) {
  const meta = EDGE_META[step.arrival_kind] ?? EDGE_META.lateral;
  const Icon = KIND_ICON[step.arrival_kind] ?? ArrowDown;
  const color = step.grs > 0 ? bandColor(step.grs >= 80 ? "IMMEDIATE" : step.grs >= 60 ? "ACT" : step.grs >= 40 ? "ATTEND" : "TRACK*") : "#6c7d76";
  return (
    <div className="relative pl-8">
      <div className="absolute left-0 top-1 grid h-6 w-6 place-items-center rounded-full border-2 bg-surface" style={{ borderColor: color }}>
        <span className="font-mono text-[10px] font-bold" style={{ color }}>{index + 1}</span>
      </div>
      {index > 0 && <div className="absolute -top-3 left-[11px] h-3 w-px bg-line-strong" />}
      <div className="rounded-xl border border-line bg-surface-2/60 p-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold text-ink">{step.host}</span>
          {step.grs > 0 && (
            <span className="rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold" style={{ background: `${color}22`, color }}>
              GRS {step.grs}
            </span>
          )}
        </div>
        <div className="mt-1 flex items-center gap-1.5 text-xs" style={{ color: meta.color }}>
          <Icon size={12} /> {meta.label}
          {step.arrival_via_qid && <span className="text-ink-faint">· QID {step.arrival_via_qid}</span>}
        </div>
        {step.exploit_finding && (
          <div className="mt-1.5 text-xs text-ink-muted">
            <span className="text-ink-faint">exploit: </span>
            {step.exploit_finding.title}
            {step.exploit_qid && <span className="text-ink-faint"> (QID {step.exploit_qid})</span>}
          </div>
        )}
      </div>
    </div>
  );
}

export default function PathDetail({ path }: { path: AttackPath }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.1fr_1fr]">
      {/* narrative */}
      <div className="card p-5">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm text-sage-bright">{path.path_id}</span>
          {path.confidence && (
            <Tag color={confidenceColor(path.confidence)}>confidence: {path.confidence}</Tag>
          )}
          {path.novelty && <Tag>{path.novelty}</Tag>}
          <span className="ml-auto flex items-center gap-1 text-xs text-ink-faint">
            <Target size={12} /> blast radius {path.blast_radius}
          </span>
        </div>
        {path.headline && <h3 className="font-display text-base font-semibold leading-snug text-ink">{path.headline}</h3>}
        {path.narrative ? (
          <div className="mt-3">
            <AiBadge>Discovery Agent Narrative</AiBadge>
            <p className="text-sm leading-relaxed text-ink-muted">{path.narrative}</p>
          </div>
        ) : (
          <p className="mt-3 text-sm text-ink-faint">
            Deterministic chain — connect an AI provider for the analyst narrative.
          </p>
        )}
        {path.business_impact && (
          <div className="mt-3 rounded-lg border border-immediate/20 bg-immediate/[0.06] p-3">
            <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-immediate">
              <TriangleAlert size={13} /> Business Impact
            </div>
            <p className="text-sm text-ink-muted">{path.business_impact}</p>
          </div>
        )}
        {path.choke_point && (
          <div className="mt-3 rounded-lg border border-sage/25 bg-sage/[0.06] p-3">
            <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-sage-bright">
              <ShieldOff size={13} /> Choke Point — fix this to break the chain
            </div>
            <p className="text-sm text-ink-muted">{path.choke_point}</p>
          </div>
        )}
      </div>

      {/* step ladder */}
      <div className="card p-5">
        <div className="label mb-4">Kill Chain · {path.steps.length} steps</div>
        <div className="space-y-3">
          <div className="relative pl-8">
            <div className="absolute left-0 top-1 grid h-6 w-6 place-items-center rounded-full border-2 border-immediate bg-surface">
              <Crosshair size={11} className="text-immediate" />
            </div>
            <div className="pt-1 text-sm font-medium text-ink">Internet — attacker origin</div>
          </div>
          {path.steps.map((s, i) => (
            <Step key={i} step={s} index={i} />
          ))}
        </div>
      </div>
    </div>
  );
}
