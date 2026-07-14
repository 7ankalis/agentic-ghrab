import type { ReactNode } from "react";
import { AlertTriangle, Download, Sparkles } from "lucide-react";
import { BAND_META, bandColor, cx } from "@/lib/format";
import type { Band } from "@/lib/types";

export function ExportButton({ onClick, label = "Export" }: { onClick: () => void; label?: string }) {
  return (
    <button onClick={onClick} className="btn-ghost !px-3 !py-1.5 text-xs">
      <Download size={13} /> {label}
    </button>
  );
}

export function BandPill({ band, className }: { band: string; className?: string }) {
  const c = bandColor(band);
  const label = BAND_META[band as Band]?.label ?? band;
  return (
    <span
      className={cx("pill", className)}
      style={{
        background: `color-mix(in srgb, ${c} 14%, transparent)`,
        color: c,
        border: `1px solid color-mix(in srgb, ${c} 32%, transparent)`,
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {label}
    </span>
  );
}

export function Tag({ children, color }: { children: ReactNode; color?: string }) {
  return (
    <span
      className="pill"
      style={
        color
          ? {
              background: `color-mix(in srgb, ${color} 12%, transparent)`,
              color,
              border: `1px solid color-mix(in srgb, ${color} 28%, transparent)`,
            }
          : undefined
      }
    >
      {children}
    </span>
  );
}

export function SectionTitle({
  children,
  sub,
  right,
}: {
  children: ReactNode;
  sub?: string;
  right?: ReactNode;
}) {
  return (
    <div className="mb-4 flex items-end justify-between gap-4">
      <div>
        <h2 className="font-display text-lg font-semibold tracking-tight text-ink">{children}</h2>
        {sub && <p className="mt-0.5 text-sm text-ink-muted">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function AiBadge({ children }: { children: ReactNode }) {
  return (
    <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-sage-bright">
      <Sparkles size={12} />
      {children}
    </div>
  );
}

export function AiCard({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-sage/20 bg-gradient-to-br from-sage/[0.08] to-transparent p-4">
      <div className="absolute inset-y-0 left-0 w-[3px] bg-gradient-to-b from-sage to-forest-lit" />
      <AiBadge>{label}</AiBadge>
      <div className="text-sm leading-relaxed text-ink-muted">{children}</div>
    </div>
  );
}

export function OfflineNotice({ what }: { what: string }) {
  return (
    <div className="card flex items-start gap-3 p-5 text-sm text-ink-muted">
      <AlertTriangle className="mt-0.5 shrink-0 text-attend" size={18} />
      <div>
        <span className="font-semibold text-ink">{what} needs an AI provider.</span> The
        deterministic engine — GRS scoring, capability classification, and autonomous attack-path
        discovery — already runs without one. Add a key in <b>Settings</b> to enable the narrative
        layer.
      </div>
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("skeleton", className)} />;
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="card grid place-items-center gap-1 p-10 text-center">
      <p className="font-medium text-ink">{title}</p>
      {hint && <p className="text-sm text-ink-muted">{hint}</p>}
    </div>
  );
}
