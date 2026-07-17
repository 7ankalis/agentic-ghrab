import {
  Area, AreaChart, Bar, BarChart, Cell, LabelList, ReferenceLine, ResponsiveContainer,
  Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis,
} from "recharts";
import { BAND_META, BAND_ORDER, bandColor } from "@/lib/format";
import { useChartColors } from "@/lib/chartColors";
import type { Band, Kpis, Overview } from "@/lib/types";

function TooltipBox({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-line-strong bg-surface-3/95 px-3 py-2 text-xs shadow-pop backdrop-blur">
      {children}
    </div>
  );
}

export function BandBar({ data, onSelect }: { data: Kpis["band_distribution"]; onSelect?: (b: Band) => void }) {
  const colors = useChartColors();
  const AXIS = { stroke: colors.axisStroke, fontSize: 11, fontFamily: "Inter" };
  const rows = BAND_ORDER.map((b) => ({
    band: b,
    label: BAND_META[b].label,
    count: data.find((d) => d.band === b)?.count ?? 0,
  }));
  return (
    <ResponsiveContainer width="100%" height={230}>
      <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 28, top: 4, bottom: 4 }}>
        <XAxis type="number" {...AXIS} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="label" width={78} {...AXIS} axisLine={false} tickLine={false} />
        <Tooltip
          cursor={{ fill: colors.cursorFill }}
          content={({ active, payload }) =>
            active && payload?.length ? (
              <TooltipBox>
                <span className="font-semibold" style={{ color: bandColor(payload[0].payload.band) }}>
                  {payload[0].payload.label}
                </span>
                <span className="text-ink-muted"> · {payload[0].value} findings · SLA {BAND_META[payload[0].payload.band as Band].text}</span>
              </TooltipBox>
            ) : null
          }
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={22} isAnimationActive={false} onClick={(d: any) => onSelect?.(d.band)} cursor="pointer">
          {rows.map((r) => (
            <Cell key={r.band} fill={bandColor(r.band)} />
          ))}
          <LabelList dataKey="count" position="right" fill={colors.labelFill} fontSize={12} fontWeight={600} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function RiskScatter({ data }: { data: Overview["cvss_vs_grs"] }) {
  const colors = useChartColors();
  const AXIS = { stroke: colors.axisStroke, fontSize: 11, fontFamily: "Inter" };
  return (
    <ResponsiveContainer width="100%" height={300}>
      <ScatterChart margin={{ left: 4, right: 16, top: 8, bottom: 18 }}>
        <ReferenceLine
          segment={[{ x: 0, y: 0 }, { x: 10, y: 100 }]}
          stroke={colors.gridStrong}
          strokeDasharray="4 4"
        />
        <XAxis
          type="number" dataKey="cvss" name="CVSS" domain={[0, 10.5]} {...AXIS}
          axisLine={{ stroke: colors.grid }} tickLine={false}
          label={{ value: "CVSS Base", position: "bottom", offset: -4, fill: colors.axisStroke, fontSize: 11 }}
        />
        <YAxis
          type="number" dataKey="grs" name="GRS" domain={[0, 105]} {...AXIS}
          axisLine={{ stroke: colors.grid }} tickLine={false}
          label={{ value: "Ghrab Risk Score", angle: -90, position: "insideLeft", fill: colors.axisStroke, fontSize: 11 }}
        />
        <ZAxis range={[70, 70]} />
        <Tooltip
          cursor={{ stroke: colors.cursorStroke }}
          content={({ active, payload }) =>
            active && payload?.length ? (
              <TooltipBox>
                <div className="font-semibold text-ink">{payload[0].payload.title}</div>
                <div className="text-ink-muted">
                  {payload[0].payload.hostname} · QID {payload[0].payload.qid}
                </div>
                <div className="mt-1" style={{ color: bandColor(payload[0].payload.band) }}>
                  GRS {payload[0].payload.grs} · CVSS {payload[0].payload.cvss}
                </div>
              </TooltipBox>
            ) : null
          }
        />
        {BAND_ORDER.map((b) => (
          <Scatter
            key={b}
            name={BAND_META[b].label}
            data={data.filter((d) => d.band === b)}
            fill={bandColor(b)}
            fillOpacity={0.85}
            stroke={colors.pointStroke}
            strokeWidth={1.5}
            isAnimationActive={false}
          />
        ))}
      </ScatterChart>
    </ResponsiveContainer>
  );
}

export interface GrsTrendPoint { label: string; avg_grs: number }

/** Avg GRS across completed runs, oldest → newest. Used by the Risk Trend
 * screen (features/trends) — kept here alongside the other charts since it
 * shares the same theme-aware color/tooltip conventions. */
export function GrsTrendChart({ data }: { data: GrsTrendPoint[] }) {
  const colors = useChartColors();
  const AXIS = { stroke: colors.axisStroke, fontSize: 11, fontFamily: "Inter" };
  return (
    <ResponsiveContainer width="100%" height={230}>
      <AreaChart data={data} margin={{ left: 4, right: 12, top: 8, bottom: 4 }}>
        <defs>
          <linearGradient id="grsTrendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgb(var(--c-sage-bright))" stopOpacity={0.35} />
            <stop offset="100%" stopColor="rgb(var(--c-sage-bright))" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="label" {...AXIS} axisLine={false} tickLine={false} minTickGap={24} />
        <YAxis domain={[0, 100]} {...AXIS} axisLine={false} tickLine={false} width={28} />
        <Tooltip
          cursor={{ stroke: colors.cursorStroke }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox>
                <div className="text-ink-muted">{label}</div>
                <span className="font-semibold text-ink">avg GRS {payload[0].value}</span>
              </TooltipBox>
            ) : null
          }
        />
        <Area
          type="monotone"
          dataKey="avg_grs"
          stroke="rgb(var(--c-sage-bright))"
          strokeWidth={2}
          fill="url(#grsTrendFill)"
          isAnimationActive={false}
          dot={{ r: 3, fill: "rgb(var(--c-sage-bright))", strokeWidth: 0 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export type BandTrendPoint = { label: string } & Record<Band, number>;

/** Band-distribution counts across completed runs, stacked per run — the
 * Risk Trend screen's second view of the same run history. */
export function BandTrendChart({ data }: { data: BandTrendPoint[] }) {
  const colors = useChartColors();
  const AXIS = { stroke: colors.axisStroke, fontSize: 11, fontFamily: "Inter" };
  return (
    <ResponsiveContainer width="100%" height={230}>
      <BarChart data={data} margin={{ left: 4, right: 12, top: 8, bottom: 4 }}>
        <XAxis dataKey="label" {...AXIS} axisLine={false} tickLine={false} minTickGap={24} />
        <YAxis allowDecimals={false} {...AXIS} axisLine={false} tickLine={false} width={28} />
        <Tooltip
          cursor={{ fill: colors.cursorFill }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox>
                <div className="mb-1 text-ink-muted">{label}</div>
                {[...payload].reverse().map((p) => (
                  <div key={p.dataKey as string} style={{ color: bandColor(p.dataKey as string) }}>
                    {BAND_META[p.dataKey as Band].label}: {p.value}
                  </div>
                ))}
              </TooltipBox>
            ) : null
          }
        />
        {BAND_ORDER.map((b) => (
          <Bar key={b} dataKey={b} stackId="bands" fill={bandColor(b)} isAnimationActive={false} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}
