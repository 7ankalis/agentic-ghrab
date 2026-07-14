import { useNavigate } from "react-router-dom";
import {
  Crosshair, GitBranch, Gem, ShieldAlert, Target, TrendingUp, Zap,
} from "lucide-react";
import { useOverview } from "@/lib/hooks";
import { bandColor, cx } from "@/lib/format";
import { AiCard, BandPill, ExportButton, OfflineNotice, SectionTitle, Skeleton, Tag } from "@/components/ui";
import { BandBar, RiskScatter } from "@/components/charts";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildOverviewReport } from "@/lib/reportBuilders";
import type { Band } from "@/lib/types";

const ICONS = { total: Crosshair, immediate: ShieldAlert, avg: TrendingUp, kev: Zap, dora: Target, crown: Gem, paths: GitBranch };

export default function Overview() {
  const { data, isLoading } = useOverview();
  const nav = useNavigate();

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
  const tiles = [
    { key: "total", label: "Findings", value: k.total, sub: "Confirmed · GRS-scored", icon: ICONS.total, to: "/findings" },
    { key: "immediate", label: "Immediate", value: k.immediate, sub: "GRS ≥ 80 · 24–72h", icon: ICONS.immediate, accent: bandColor("IMMEDIATE"), to: "/findings" },
    { key: "avg", label: "Avg GRS", value: k.avg_grs, sub: "Composite risk", icon: ICONS.avg },
    { key: "kev", label: "KEV-listed", value: k.kev, sub: "Exploited in wild", icon: ICONS.kev, accent: bandColor("ACT") },
    { key: "dora", label: "DORA CIF", value: k.dora_cif, sub: "Critical functions", icon: ICONS.dora },
    { key: "crown", label: "Crown Jewels", value: k.crown_jewels, sub: "High-value assets", icon: ICONS.crown, accent: "rgb(var(--c-purple))" },
    { key: "paths", label: "Attack Paths", value: k.discovered_paths, sub: "Autonomously found", icon: ICONS.paths, accent: "rgb(var(--c-sage-bright))", to: "/attack-paths" },
  ];

  return (
    <div className="space-y-6 animate-fade-up">
      <SectionTitle
        sub="Deterministic GRS engine + autonomous attack-path discovery, at a glance."
        right={<ExportButton onClick={() => downloadMarkdown(`ghrab-voc-overview-${timestamp()}.md`, buildOverviewReport(data))} />}
      >
        Command Center
      </SectionTitle>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
        {tiles.map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.key}
              onClick={() => t.to && nav(t.to)}
              className={cx(
                "card group relative overflow-hidden p-4 text-left transition",
                t.to && "hover:-translate-y-0.5 hover:shadow-glow",
              )}
            >
              <div
                className="absolute inset-x-0 top-0 h-[3px]"
                style={{ background: `linear-gradient(90deg, ${t.accent ?? "rgb(var(--c-sage))"}, transparent)` }}
              />
              <Icon size={16} className="mb-2 text-ink-faint group-hover:text-sage-bright" style={t.accent ? { color: t.accent } : undefined} />
              <div className="font-display text-3xl font-bold leading-none text-ink">{t.value}</div>
              <div className="mt-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{t.label}</div>
              <div className="text-[11px] text-ink-faint">{t.sub}</div>
            </button>
          );
        })}
      </div>

      {k.ai_enabled && data.executive_summary ? (
        <AiCard label="Executive Synthesis">{data.executive_summary}</AiCard>
      ) : !k.ai_enabled ? (
        <OfflineNotice what="The executive synthesis" />
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card p-5">
          <SectionTitle sub="Click a band to filter the findings queue.">Risk Band Distribution</SectionTitle>
          <BandBar data={k.band_distribution} onSelect={(b: Band) => nav(`/findings?band=${encodeURIComponent(b)}`)} />
        </div>
        <div className="card p-5">
          <SectionTitle sub="Points above the diagonal are under-rated by CVSS alone.">CVSS vs. GRS</SectionTitle>
          <RiskScatter data={data.cvss_vs_grs} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card p-5">
          <SectionTitle right={<Tag>{data.top_findings.length}</Tag>}>Most Urgent Findings</SectionTitle>
          <div className="space-y-2">
            {data.top_findings.map((f) => (
              <button
                key={f.qid}
                onClick={() => nav(`/findings?qid=${f.qid}`)}
                className="flex w-full items-center gap-3 rounded-lg border border-line bg-surface-2/60 p-3 text-left transition hover:border-line-strong hover:bg-surface-2"
              >
                <div
                  className="grid h-11 w-11 shrink-0 place-items-center rounded-lg font-display text-sm font-bold"
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

        <div className="card p-5">
          <SectionTitle right={<Tag color="rgb(var(--c-sage-bright))">{data.top_paths.length}</Tag>}>Top Attack Paths</SectionTitle>
          <div className="space-y-2">
            {data.top_paths.map((p) => (
              <button
                key={p.path_id}
                onClick={() => nav("/attack-paths")}
                className="w-full rounded-lg border border-line bg-surface-2/60 p-3 text-left transition hover:border-sage/40"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-sage-bright">{p.path_id}</span>
                  <span className="text-[11px] text-ink-faint">score {p.score}</span>
                </div>
                <div className="mt-1 flex items-center gap-1.5 text-sm text-ink">
                  <span className="font-medium">{p.entry}</span>
                  <GitBranch size={13} className="text-ink-faint" />
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
