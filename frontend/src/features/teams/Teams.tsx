import { useNavigate } from "react-router-dom";
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useTeams } from "@/lib/hooks";
import { bandColor, bandForGrs, initials } from "@/lib/format";
import { useChartColors } from "@/lib/chartColors";
import { BandPill, ExportButton, SectionTitle, Skeleton, useSpotlight } from "@/components/ui";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildTeamsReport } from "@/lib/reportBuilders";

export default function Teams() {
  const { data, isLoading } = useTeams();
  const nav = useNavigate();
  const colors = useChartColors();
  const spotlight = useSpotlight();
  if (isLoading || !data) return <Skeleton className="h-96" />;
  const teams = data.teams;
  const chart = teams.map((t) => ({ team: t.team.replace(/ Team$/, ""), grs: t.max_grs, band: bandForGrs(t.max_grs) }));

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle
        sub="Ownership and exposure by operational team — route remediation to the team that actually owns the fix."
        right={<ExportButton onClick={() => downloadMarkdown(`ghrab-voc-teams-${timestamp()}.md`, buildTeamsReport(teams))} />}
      >
        Teams & Ownership
      </SectionTitle>

      <div className="card p-5">
        <div className="label mb-3">Peak Risk (GRS) by Team</div>
        <ResponsiveContainer width="100%" height={230}>
          <BarChart data={chart} layout="vertical" margin={{ left: 8, right: 30, top: 4, bottom: 4 }}>
            <XAxis type="number" domain={[0, 100]} stroke={colors.axisStroke} fontSize={11} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="team" width={130} stroke={colors.labelFill} fontSize={12} axisLine={false} tickLine={false} />
            <Tooltip
              cursor={{ fill: colors.cursorFill }}
              content={({ active, payload }) =>
                active && payload?.length ? (
                  <div className="rounded-lg border border-line-strong bg-surface-3/95 px-3 py-2 text-xs">
                    <span style={{ color: bandColor(payload[0].payload.band) }}>peak GRS {payload[0].value}</span>
                  </div>
                ) : null
              }
            />
            <Bar dataKey="grs" radius={[0, 4, 4, 0]} barSize={20} isAnimationActive={false}>
              {chart.map((c, i) => <Cell key={i} fill={bandColor(c.band)} />)}
              <LabelList dataKey="grs" position="right" fill={colors.labelFill} fontSize={12} fontWeight={600} formatter={(v: number) => v.toFixed(0)} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {teams.map((t, i) => (
          <button
            key={t.team}
            onClick={() => nav(`/findings?team=${encodeURIComponent(t.team)}`)}
            onMouseMove={spotlight}
            style={{ animationDelay: `${i * 55}ms` }}
            className="spot card-interactive group p-4 text-left animate-fade-up"
          >
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-lg bg-sage/12 font-display text-sm font-bold text-sage-bright transition-transform duration-200 group-hover:scale-110">
                {initials(t.team)}
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-semibold text-ink">{t.team}</div>
                <div className="text-xs text-ink-faint">{t.findings} findings · avg GRS {t.avg_grs}</div>
              </div>
              <BandPill band={bandForGrs(t.max_grs)} />
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              {[
                { k: "Immediate", v: t.immediate, c: bandColor("IMMEDIATE") },
                { k: "KEV", v: t.kev, c: bandColor("ACT") },
                { k: "DORA CIF", v: t.dora_cif, c: "rgb(var(--c-purple))" },
              ].map((m) => (
                <div key={m.k} className="rounded-lg border border-line bg-surface-2/50 py-2">
                  <div className="font-display text-lg font-bold" style={{ color: m.v > 0 ? m.c : "rgb(var(--c-ink-faint))" }}>{m.v}</div>
                  <div className="text-[10px] uppercase tracking-wide text-ink-faint">{m.k}</div>
                </div>
              ))}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
