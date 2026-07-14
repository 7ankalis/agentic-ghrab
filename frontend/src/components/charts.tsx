import {
  Bar, BarChart, Cell, LabelList, ReferenceLine, ResponsiveContainer, Scatter,
  ScatterChart, Tooltip, XAxis, YAxis, ZAxis,
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
