import type { CSSProperties } from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowRight, Crosshair, GitBranch, Gem, ShieldAlert, Target, TrendingUp, Zap,
} from "lucide-react";
import { useOverview } from "@/lib/hooks";
import { useCountUp } from "@/lib/useCountUp";
import { bandColor, bandForGrs, cx } from "@/lib/format";
import {
  AiCard, BandPill, ExportButton, OfflineNotice, RingGauge, SectionTitle, Skeleton, Tag,
  useSpotlight,
} from "@/components/ui";
import { BandBar, RiskScatter } from "@/components/charts";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildOverviewReport } from "@/lib/reportBuilders";
import type { Band } from "@/lib/types";

const ICONS = { total: Crosshair, immediate: ShieldAlert, avg: TrendingUp, kev: Zap, dora: Target, crown: Gem, paths: GitBranch };

function AnimatedNumber({ value }: { value: number }) {
  const v = useCountUp(value);
  return <>{Number.isInteger(value) ? Math.round(v) : v.toFixed(1)}</>;
}

export default function Overview() {
  const { data, isLoading } = useOverview();
  const nav = useNavigate();
  const spotlight = useSpotlight();

  if (isLoading || !data)
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
          {Array.from({ length: 7 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-32" />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2"><Skeleton className="h-72" /><Skeleton className="h-72" /></div>
      </div>
    );

  const k = data.kpis;
  const avgBandColor = bandColor(bandForGrs(k.avg_grs));
  const tiles = [
    { key: "total", label: "Findings", value: k.total, sub: "Confirmed · GRS-scored", icon: ICONS.total, to: "/findings" },
    { key: "immediate", label: "Immediate", value: k.immediate, sub: "GRS ≥ 80 · 24–72h", icon: ICONS.immediate, accent: bandColor("IMMEDIATE"), to: "/findings" },
    { key: "avg", label: "Avg GRS", value: k.avg_grs, sub: "Composite risk", icon: ICONS.avg, accent: avgBandColor, gauge: true },
    { key: "kev", label: "KEV-listed", value: k.kev, sub: "Exploited in wild", icon: ICONS.kev, accent: bandColor("ACT") },
    { key: "dora", label: "DORA CIF", value: k.dora_cif, sub: "Critical functions", icon: ICONS.dora },
    { key: "crown", label: "Crown Jewels", value: k.crown_jewels, sub: "High-value assets", icon: ICONS.crown, accent: "rgb(var(--c-purple))" },
    { key: "paths", label: "Attack Paths", value: k.discovered_paths, sub: "Autonomously found", icon: ICONS.paths, accent: "rgb(var(--c-sage-bright))", to: "/attack-paths" },
  ] as Array<{
    key: string; label: string; value: number; sub: string;
    icon: typeof Crosshair; accent?: string; to?: string; gauge?: boolean;
  }>;

  return (
    <div className="space-y-6">
      <div className="animate-fade-up">
        <SectionTitle
          sub="Deterministic GRS engine + autonomous attack-path discovery, at a glance."
          right={<ExportButton onClick={() => downloadMarkdown(`ghrab-voc-overview-${timestamp()}.md`, buildOverviewReport(data))} />}
        >
          <span className="text-gradient">Command Center</span>
        </SectionTitle>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
        {tiles.map((t, i) => {
          const Icon = t.icon;
          const accent = t.accent ?? "rgb(var(--c-sage))";
          return (
            <button
              key={t.key}
              onClick={() => t.to && nav(t.to)}
              onMouseMove={spotlight}
              style={{ animationDelay: `${i * 45}ms`, "--spot-color": `color-mix(in srgb, ${accent} 10%, transparent)` } as CSSProperties}
              className={cx(
                "spot group relative overflow-hidden p-4 text-left animate-fade-up",
                t.to ? "card-interactive" : "card",
              )}
            >
              <div
                className="absolute inset-x-0 top-0 h-[3px] opacity-80 transition-opacity group-hover:opacity-100"
                style={{ background: `linear-gradient(90deg, ${accent}, transparent)` }}
              />
              <div className="flex items-start justify-between">
                <div>
                  <span
                    className="mb-2 grid h-7 w-7 place-items-center rounded-lg transition-transform duration-200 group-hover:scale-110"
                    style={{ background: `color-mix(in srgb, ${accent} 12%, transparent)`, color: accent }}
                  >
                    <Icon size={14} />
                  </span>
                  <div className="font-display text-3xl font-bold leading-none tabular-nums text-ink">
                    <AnimatedNumber value={t.value} />
                  </div>
                </div>
                {t.gauge && (
                  <RingGauge value={k.avg_grs} color={accent} size={44} stroke={4} />
                )}
              </div>
              <div className="mt-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{t.label}</div>
              <div className="flex items-center justify-between text-[11px] text-ink-faint">
                <span>{t.sub}</span>
                {t.to && (
                  <ArrowRight
                    size={12}
                    className="-translate-x-1 opacity-0 transition-all duration-200 group-hover:translate-x-0 group-hover:opacity-100"
                    style={{ color: accent }}
                  />
                )}
              </div>
            </button>
          );
        })}
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "180ms" }}>
        {k.ai_enabled && data.executive_summary ? (
          <AiCard label="Executive Synthesis">{data.executive_summary}</AiCard>
        ) : !k.ai_enabled ? (
          <OfflineNotice what="The executive synthesis" />
        ) : null}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card p-5 animate-fade-up" style={{ animationDelay: "220ms" }}>
          <SectionTitle sub="Click a band to filter the findings queue.">Risk Band Distribution</SectionTitle>
          <BandBar data={k.band_distribution} onSelect={(b: Band) => nav(`/findings?band=${encodeURIComponent(b)}`)} />
        </div>
        <div className="card p-5 animate-fade-up" style={{ animationDelay: "260ms" }}>
          <SectionTitle sub="Points above the diagonal are under-rated by CVSS alone.">CVSS vs. GRS</SectionTitle>
          <RiskScatter data={data.cvss_vs_grs} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card p-5 animate-fade-up" style={{ animationDelay: "300ms" }}>
          <SectionTitle right={<Tag>{data.top_findings.length}</Tag>}>Most Urgent Findings</SectionTitle>
          <div className="space-y-2">
            {data.top_findings.map((f, i) => (
              <button
                key={f.qid}
                onClick={() => nav(`/findings?qid=${f.qid}`)}
                onMouseMove={spotlight}
                style={{ "--spot-color": `color-mix(in srgb, ${bandColor(f.band)} 7%, transparent)` } as CSSProperties}
                className="spot group flex w-full items-center gap-3 rounded-lg border border-line bg-surface-2/60 p-3 text-left transition-all duration-200 hover:translate-x-1 hover:border-line-strong hover:bg-surface-2"
              >
                <span className="w-4 shrink-0 text-center font-mono text-[10px] text-ink-faint">{i + 1}</span>
                <div
                  className="grid h-11 w-11 shrink-0 place-items-center rounded-lg font-display text-sm font-bold transition-transform duration-200 group-hover:scale-105"
                  style={{ background: `color-mix(in srgb, ${bandColor(f.band)} 14%, transparent)`, color: bandColor(f.band) }}
                >
                  {f.grs}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-ink">{f.title}</div>
                  <div className="truncate text-xs text-ink-faint">
                    {f.hostname} · QID {f.qid} · {f.team}
                  </div>
                </div>
                <BandPill band={f.band} />
              </button>
            ))}
          </div>
        </div>

        <div className="card p-5 animate-fade-up" style={{ animationDelay: "340ms" }}>
          <SectionTitle right={<Tag color="rgb(var(--c-sage-bright))">{data.top_paths.length}</Tag>}>Top Attack Paths</SectionTitle>
          <div className="space-y-2">
            {data.top_paths.map((p) => (
              <button
                key={p.path_id}
                onClick={() => nav("/attack-paths")}
                onMouseMove={spotlight}
                className="spot group w-full rounded-lg border border-line bg-surface-2/60 p-3 text-left transition-all duration-200 hover:translate-x-1 hover:border-sage/40"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-sage-bright">{p.path_id}</span>
                  <span className="rounded-full border border-line bg-surface px-2 py-0.5 font-mono text-[10px] tabular-nums text-ink-muted">
                    score {p.score}
                  </span>
                </div>
                <div className="mt-1.5 flex items-center gap-1.5 text-sm text-ink">
                  <span className="font-medium">{p.entry}</span>
                  <ArrowRight size={13} className="text-ink-faint transition-transform duration-200 group-hover:translate-x-0.5" />
                  <span className="font-medium text-sage-bright">{p.target}</span>
                </div>
                {p.headline && <div className="mt-1 line-clamp-2 text-xs text-ink-muted">{p.headline}</div>}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
