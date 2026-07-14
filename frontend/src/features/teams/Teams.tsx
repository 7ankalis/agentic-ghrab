import { useNavigate } from "react-router-dom";
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useTeams } from "@/lib/hooks";
import { bandColor, bandForGrs, initials } from "@/lib/format";
import { BandPill, SectionTitle, Skeleton } from "@/components/ui";

export default function Teams() {
  const { data, isLoading } = useTeams();
  const nav = useNavigate();
  if (isLoading || !data) return <Skeleton className="h-96" />;
  const teams = data.teams;
  const chart = teams.map((t) => ({ team: t.team.replace(/ Team$/, ""), grs: t.max_grs, band: bandForGrs(t.max_grs) }));

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle sub="Ownership and exposure by operational team — route remediation to the team that actually owns the fix.">
        Teams & Ownership
      </SectionTitle>

      <div className="card p-5">
        <div className="label mb-3">Peak Risk (GRS) by Team</div>
        <ResponsiveContainer width="100%" height={230}>
          <BarChart data={chart} layout="vertical" margin={{ left: 8, right: 30, top: 4, bottom: 4 }}>
            <XAxis type="number" domain={[0, 100]} stroke="#6c7d76" fontSize={11} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="team" width={130} stroke="#9fb0a9" fontSize={12} axisLine={false} tickLine={false} />
            <Tooltip
              cursor={{ fill: "rgba(140,175,160,0.06)" }}
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
              <LabelList dataKey="grs" position="right" fill="#9fb0a9" fontSize={12} fontWeight={600} formatter={(v: number) => v.toFixed(0)} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {teams.map((t) => (
          <button
            key={t.team}
            onClick={() => nav(`/findings?team=${encodeURIComponent(t.team)}`)}
            className="card p-4 text-left transition hover:-translate-y-0.5 hover:shadow-glow"
          >
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-lg bg-sage/12 font-display text-sm font-bold text-sage-bright">
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
                { k: "DORA CIF", v: t.dora_cif, c: "#c97bd8" },
              ].map((m) => (
                <div key={m.k} className="rounded-lg border border-line bg-surface-2/50 py-2">
                  <div className="font-display text-lg font-bold" style={{ color: m.v > 0 ? m.c : "#6c7d76" }}>{m.v}</div>
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
