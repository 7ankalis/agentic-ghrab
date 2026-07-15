import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import ReactFlow, {
  Background, BackgroundVariant, BaseEdge, EdgeLabelRenderer, Handle,
  MarkerType, MiniMap, Panel, Position, getBezierPath, useReactFlow,
  type Edge, type EdgeProps, type Node, type NodeProps,
} from "reactflow";
import {
  Crosshair, Focus, Layers, Link2, Maximize2, Minimize2, Pause, Play,
  RotateCcw, Rows3, Search, Target, Tag as TagIcon, Waypoints, X, Zap,
} from "lucide-react";
import { EDGE_META, bandColor, bandForGrs, BAND_META, cx } from "@/lib/format";
import { roleIcon } from "./nodeVisuals";
import type { AttackPath, GraphNode, GraphPayload } from "@/lib/types";

type LayoutMode = "flow" | "zones" | "radial";

interface NodeData {
  label: string;
  zone: string;
  vlan: string;
  grs: number;
  crown: boolean;
  entry: boolean;
  kind: string;
  role: string;
  qidCount: number;
  dim: boolean;
  active: boolean;
  match: boolean;
  stepIndex: number | null;
}

interface EdgeData {
  kind: string;
  onPath: boolean;
  revealed: boolean;
  dim: boolean;
  idle: boolean;
  label: string;
  showLabel: boolean;
}

// ── Node ──────────────────────────────────────────────────────────────────

function nodeColor(d: { crown: boolean; grs: number }): string {
  if (d.crown) return "rgb(var(--c-purple))";
  return d.grs > 0 ? bandColor(bandForGrs(d.grs)) : "rgb(var(--c-ink-faint))";
}

function AssetNode({ data }: NodeProps<NodeData>) {
  if (data.kind === "internet") {
    return (
      <div className={cx("ag-node relative flex flex-col items-center gap-1 transition-opacity", data.dim && "opacity-25")}>
        <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-immediate" />
        <div className="relative grid h-16 w-16 place-items-center">
          <span className="ag-ping absolute inset-0 rounded-full border border-immediate/50" />
          <span className="ag-ping absolute inset-0 rounded-full border border-immediate/40" style={{ animationDelay: "1.1s" }} />
          <div className="relative grid h-14 w-14 place-items-center rounded-full border-2 border-immediate/70 bg-immediate/15 text-immediate shadow-glow">
            <Waypoints size={22} />
          </div>
        </div>
        <span className="text-[11px] font-semibold text-ink">Internet</span>
        <span className="text-[9px] uppercase tracking-widest text-immediate/80">attacker origin</span>
      </div>
    );
  }

  const band = bandForGrs(data.grs);
  const color = nodeColor(data);
  const Icon = roleIcon(data.role, data.label, data.kind);
  const meter = Math.max(5, Math.min(100, data.grs));
  const lit = data.active || data.stepIndex != null;

  return (
    <div className={cx("ag-node group relative transition-opacity duration-200", data.dim ? "opacity-[0.22]" : "opacity-100")}>
      <div
        className={cx(
          "ag-card relative min-w-[186px] max-w-[210px] overflow-hidden rounded-xl border bg-surface-2",
          lit ? "shadow-glow" : "shadow-card group-hover:shadow-pop",
          data.crown && "ag-crown",
        )}
        style={{
          borderColor: data.crown || lit || data.match ? color : "rgb(var(--c-line-strong))",
          // @ts-expect-error — CSS custom property for the crown pulse keyframe
          "--crown": color,
        }}
      >
        {/* risk-band accent bar */}
        <div
          className={cx("absolute inset-x-0 top-0 h-[3px]", lit && "ag-accent-live")}
          style={{
            background: lit
              ? `linear-gradient(90deg, transparent, ${color}, transparent)`
              : color,
            opacity: data.grs > 0 || data.crown ? 1 : 0.35,
          }}
        />
        <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-ink-faint" />
        <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-ink-faint" />

        {/* step-order badge when this node sits on the selected path */}
        {data.stepIndex != null && (
          <span
            className="absolute -left-2.5 -top-2.5 z-10 grid h-5 w-5 place-items-center rounded-full border-2 border-surface-2 font-mono text-[10px] font-bold text-forest"
            style={{ background: color }}
          >
            {data.stepIndex}
          </span>
        )}

        <div className="px-2.5 pb-2 pt-3">
          <div className="flex items-center gap-2">
            <div
              className="relative grid h-8 w-8 shrink-0 place-items-center rounded-lg ring-1 ring-inset"
              style={{ background: `color-mix(in srgb, ${color} 15%, transparent)`, color, borderColor: color }}
            >
              <Icon size={16} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-[12.5px] font-semibold leading-tight text-ink">{data.label}</div>
              <div className="truncate text-[10px] text-ink-faint">
                {data.zone}
                {data.vlan && <span className="text-ink-faint/70"> · VLAN {data.vlan}</span>}
              </div>
            </div>
            {data.qidCount > 0 && (
              <span
                className="shrink-0 rounded-md px-1.5 py-0.5 font-mono text-[9.5px] font-semibold"
                style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}
                title={`${data.qidCount} findings on this host`}
              >
                {data.qidCount}⚑
              </span>
            )}
          </div>

          {/* GRS meter + band label */}
          {data.grs > 0 && (
            <div className="mt-2 flex items-center gap-1.5">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-3">
                <div className="h-full rounded-full transition-[width] duration-700" style={{ width: `${meter}%`, background: color }} />
              </div>
              <span className="font-mono text-[10px] font-semibold tabular-nums" style={{ color }}>{data.grs}</span>
            </div>
          )}

          {/* status chips */}
          {(data.entry || data.crown || data.grs > 0) && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1">
              {data.entry && (
                <span className="inline-flex items-center gap-1 rounded bg-immediate/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-immediate">
                  <Crosshair size={9} /> Entry
                </span>
              )}
              {data.crown && (
                <span className="inline-flex items-center gap-1 rounded bg-purple/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-purple">
                  ★ Crown
                </span>
              )}
              {!data.entry && !data.crown && data.grs > 0 && (
                <span
                  className="inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide"
                  style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}
                >
                  {BAND_META[band].label}
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Edge ──────────────────────────────────────────────────────────────────

function AttackEdge({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, data }: EdgeProps<EdgeData>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.28 });
  const meta = EDGE_META[data?.kind ?? "lateral"] ?? EDGE_META.lateral;
  const onPath = data?.onPath;
  const revealed = data?.revealed;
  const opacity = data?.dim ? 0.06 : onPath && !revealed ? 0.22 : data?.idle ? 0.45 : 1;
  const stroke = onPath || !data?.idle ? meta.color : `color-mix(in srgb, ${meta.color} 60%, transparent)`;

  return (
    <>
      <BaseEdge
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke,
          strokeWidth: onPath ? 2.6 : 1.4,
          strokeDasharray: onPath && revealed ? "5 5" : meta.dashed ? "5 4" : undefined,
          animation: onPath && revealed ? "ag-flow 0.55s linear infinite" : undefined,
          opacity,
          filter: onPath && revealed ? `drop-shadow(0 0 5px ${meta.color})` : undefined,
        }}
      />
      {data?.showLabel && onPath && !data?.dim && data?.label && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-none absolute rounded-md border px-1.5 py-0.5 text-[9px] font-semibold shadow-card"
            style={{
              transform: `translate(-50%,-50%) translate(${labelX}px,${labelY}px)`,
              background: "rgb(var(--c-surface))",
              borderColor: `color-mix(in srgb, ${meta.color} 40%, transparent)`,
              color: meta.color,
            }}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const nodeTypes = { asset: AssetNode };
const edgeTypes = { attack: AttackEdge };

// ── Layouts ─────────────────────────────────────────────────────────────────

function bfsDistance(graph: GraphPayload): Map<string, number> {
  const adj = new Map<string, string[]>();
  graph.edges.forEach((e) => {
    if (!adj.has(e.source)) adj.set(e.source, []);
    adj.get(e.source)!.push(e.target);
  });
  const dist = new Map<string, number>([["INTERNET", 0]]);
  const queue = ["INTERNET"];
  while (queue.length) {
    const n = queue.shift()!;
    for (const m of adj.get(n) ?? []) {
      if (!dist.has(m)) { dist.set(m, dist.get(n)! + 1); queue.push(m); }
    }
  }
  let maxLayer = 0;
  dist.forEach((d) => (maxLayer = Math.max(maxLayer, d)));
  graph.nodes.forEach((n) => { if (!dist.has(n.id)) dist.set(n.id, maxLayer + 1); });
  return dist;
}

/** Layered "kill-chain flow": x = distance from INTERNET, nodes clustered by zone
 *  within each layer (then by descending risk) to minimise edge crossings. */
function layoutFlow(graph: GraphPayload): Map<string, { x: number; y: number }> {
  const dist = bfsDistance(graph);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const layers = new Map<number, string[]>();
  graph.nodes.forEach((n) => {
    const l = dist.get(n.id)!;
    if (!layers.has(l)) layers.set(l, []);
    layers.get(l)!.push(n.id);
  });
  const pos = new Map<string, { x: number; y: number }>();
  const GAP = 158;   // > card height, so vertically-stacked nodes never overlap
  const COL = 360;   // > card width + margin
  layers.forEach((ids, l) => {
    ids.sort((a, b) => {
      const na = byId.get(a)!, nb = byId.get(b)!;
      return na.zone.localeCompare(nb.zone) || nb.grs - na.grs || a.localeCompare(b);
    });
    const h = (ids.length - 1) * GAP;
    ids.forEach((id, i) => pos.set(id, { x: l * COL, y: i * GAP - h / 2 }));
  });
  return pos;
}

/** Zone swim-lanes: each network segment gets a horizontal band, x still tracks
 *  distance from the internet so segmentation boundaries pop visually. */
function layoutZones(graph: GraphPayload): Map<string, { x: number; y: number }> {
  const dist = bfsDistance(graph);
  const zones = Array.from(new Set(graph.nodes.filter((n) => n.kind !== "internet").map((n) => n.zone)));
  const zoneMinLayer = new Map<string, number>();
  graph.nodes.forEach((n) => {
    if (n.kind === "internet") return;
    const d = dist.get(n.id)!;
    zoneMinLayer.set(n.zone, Math.min(zoneMinLayer.get(n.zone) ?? Infinity, d));
  });
  zones.sort((a, b) => (zoneMinLayer.get(a)! - zoneMinLayer.get(b)!) || a.localeCompare(b));
  const laneOf = new Map(zones.map((z, i) => [z, i]));
  const COL = 360;   // horizontal step per BFS layer
  const STEP = 152;  // vertical step between stacked cards (> card height)
  const PAD = 70;    // breathing room between lanes

  const cell = new Map<string, string[]>();
  graph.nodes.forEach((n) => {
    if (n.kind === "internet") return;
    const key = `${n.zone}__${dist.get(n.id)}`;
    if (!cell.has(key)) cell.set(key, []);
    cell.get(key)!.push(n.id);
  });

  const laneStack = new Map<number, number>();
  cell.forEach((ids, key) => {
    const lane = laneOf.get(key.split("__")[0])!;
    laneStack.set(lane, Math.max(laneStack.get(lane) ?? 1, ids.length));
  });
  const laneCenter = new Map<number, number>();
  let cursor = 0;
  zones.forEach((_, i) => {
    const height = (laneStack.get(i) ?? 1) * STEP;
    laneCenter.set(i, cursor + height / 2);
    cursor += height + PAD;
  });

  const pos = new Map<string, { x: number; y: number }>();
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  cell.forEach((ids, key) => {
    const [zone, lStr] = key.split("__");
    const lane = laneOf.get(zone)!;
    const l = Number(lStr);
    ids.sort((a, b) => byId.get(b)!.grs - byId.get(a)!.grs || a.localeCompare(b));
    const spread = (ids.length - 1) * STEP;
    ids.forEach((id, i) => pos.set(id, { x: l * COL, y: laneCenter.get(lane)! + (i * STEP - spread / 2) }));
  });
  pos.set("INTERNET", { x: -COL, y: (cursor - PAD) / 2 });
  return pos;
}

/** Radial "blast radius": INTERNET at the centre, each BFS ring a concentric
 *  circle — reads as how far an attacker can reach from the outside in. */
function layoutRadial(graph: GraphPayload): Map<string, { x: number; y: number }> {
  const dist = bfsDistance(graph);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const rings = new Map<number, string[]>();
  graph.nodes.forEach((n) => {
    if (n.kind === "internet") return;
    const d = Math.max(1, dist.get(n.id)!);
    if (!rings.has(d)) rings.set(d, []);
    rings.get(d)!.push(n.id);
  });
  const pos = new Map<string, { x: number; y: number }>([["INTERNET", { x: 0, y: 0 }]]);
  const RING = 300;      // radial gap per BFS layer
  const MIN_ARC = 150;   // min arc-length between neighbours on a ring
  rings.forEach((ids, d) => {
    ids.sort((a, b) => {
      const na = byId.get(a)!, nb = byId.get(b)!;
      return na.zone.localeCompare(nb.zone) || nb.grs - na.grs || a.localeCompare(b);
    });
    // widen the ring if the cards would crowd, so nothing overlaps
    const r = Math.max(d * RING, (ids.length * MIN_ARC) / (2 * Math.PI));
    const step = (2 * Math.PI) / ids.length;
    const offset = -Math.PI / 2 + (d % 2) * (step / 2); // stagger odd rings
    ids.forEach((id, i) => {
      const a = offset + i * step;
      pos.set(id, { x: Math.cos(a) * r, y: Math.sin(a) * r });
    });
  });
  return pos;
}

const LAYOUTS: Record<LayoutMode, (g: GraphPayload) => Map<string, { x: number; y: number }>> = {
  flow: layoutFlow,
  zones: layoutZones,
  radial: layoutRadial,
};

// ── Hover inspector ──────────────────────────────────────────────────────────

function InspectorRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-ink-faint">{label}</dt>
      <dd className="min-w-0 truncate text-right text-ink-muted">{children}</dd>
    </div>
  );
}

function NodeInspector({
  node, degree, stepIndex, left, top,
}: {
  node: GraphNode; degree: number; stepIndex: number | null; left: number; top: number;
}) {
  if (node.kind === "internet") {
    return (
      <div className="ag-inspector pointer-events-none absolute z-30 w-[210px]" style={{ left, top }}>
        <div className="rounded-xl border border-immediate/40 bg-surface p-3 shadow-pop">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-immediate">
            <Waypoints size={13} /> Internet
          </div>
          <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
            The attacker's starting point. Every discovered chain originates here.
          </p>
        </div>
      </div>
    );
  }
  const band = bandForGrs(node.grs);
  const color = nodeColor(node);
  const Icon = roleIcon(node.role ?? "", node.label, node.kind);
  return (
    <div className="ag-inspector pointer-events-none absolute z-30 w-[248px]" style={{ left, top }}>
      <div className="overflow-hidden rounded-xl border border-line-strong bg-surface shadow-pop">
        <div className="flex items-center gap-2 border-b border-line px-3 py-2.5" style={{ background: `color-mix(in srgb, ${color} 8%, transparent)` }}>
          <div className="grid h-7 w-7 shrink-0 place-items-center rounded-lg" style={{ background: `color-mix(in srgb, ${color} 16%, transparent)`, color }}>
            <Icon size={15} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-xs font-semibold text-ink">{node.label}</div>
            <div className="truncate text-[10px] text-ink-faint">{node.zone}{node.vlan && ` · VLAN ${node.vlan}`}</div>
          </div>
          {stepIndex != null && (
            <span className="shrink-0 rounded-md px-1.5 py-0.5 font-mono text-[9px] font-bold text-forest" style={{ background: color }}>
              STEP {stepIndex}
            </span>
          )}
        </div>
        <dl className="space-y-1.5 px-3 py-2.5 text-[11px]">
          {node.role && <InspectorRow label="Role">{node.role}</InspectorRow>}
          {node.team && <InspectorRow label="Owner">{node.team}</InspectorRow>}
          <InspectorRow label="Peak risk">
            {node.grs > 0
              ? <span className="font-mono font-semibold" style={{ color }}>{node.grs} · {BAND_META[band].label}</span>
              : <span className="text-ink-faint">no findings</span>}
          </InspectorRow>
          {node.grs > 0 && <InspectorRow label="Remediation SLA">{BAND_META[band].text}</InspectorRow>}
          <InspectorRow label="Target value">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-1 w-14 overflow-hidden rounded-full bg-surface-3">
                <span className="block h-full rounded-full bg-purple" style={{ width: `${Math.round((node.value ?? 0) * 100)}%` }} />
              </span>
              <span className="font-mono">{(node.value ?? 0).toFixed(2)}</span>
            </span>
          </InspectorRow>
          <InspectorRow label="Findings">{node.qids?.length ?? 0}</InspectorRow>
          <InspectorRow label="Connections">{degree}</InspectorRow>
        </dl>
        {(node.entry || node.crown) && (
          <div className="flex flex-wrap gap-1 border-t border-line px-3 py-2">
            {node.entry && (
              <span className="inline-flex items-center gap-1 rounded bg-immediate/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-immediate">
                <Crosshair size={9} /> Internet-reachable entry
              </span>
            )}
            {node.crown && (
              <span className="inline-flex items-center gap-1 rounded bg-purple/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-purple">
                ★ Crown jewel
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main ─────────────────────────────────────────────────────────────────

const EDGE_KINDS = ["entry", "segmentation", "credential", "domain", "lateral"] as const;

export default function AttackGraph({
  graph, selected, replayStep, setReplayStep, onClearSelection,
}: {
  graph: GraphPayload;
  selected: AttackPath | null;
  replayStep: number;
  setReplayStep: (n: number) => void;
  onClearSelection: () => void;
}) {
  const { fitView } = useReactFlow();
  const containerRef = useRef<HTMLDivElement>(null);
  const [layoutMode, setLayoutMode] = useState<LayoutMode>("flow");
  const [hovered, setHovered] = useState<{ node: GraphNode; left: number; top: number } | null>(null);
  const [focusOnHover, setFocusOnHover] = useState(true);
  const [showLabels, setShowLabels] = useState(true);
  const [showMiniMap, setShowMiniMap] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [query, setQuery] = useState("");
  const [enabledKinds, setEnabledKinds] = useState<Record<string, boolean>>(
    () => Object.fromEntries(EDGE_KINDS.map((k) => [k, true])),
  );

  const hoveredId = hovered?.node.id ?? null;

  const pos = useMemo(() => LAYOUTS[layoutMode](graph), [graph, layoutMode]);
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);

  // adjacency for hover focus + inspector connection count
  const neighbors = useMemo(() => {
    const m = new Map<string, Set<string>>();
    const link = (a: string, b: string) => {
      if (!m.has(a)) m.set(a, new Set());
      m.get(a)!.add(b);
    };
    graph.edges.forEach((e) => { link(e.source, e.target); link(e.target, e.source); });
    return m;
  }, [graph]);

  const pathNodeIds = useMemo(
    () => (selected ? new Set<string>(["INTERNET", ...selected.steps.map((s) => s.host)]) : null),
    [selected],
  );
  const stepIndexOf = useMemo(() => {
    const m = new Map<string, number>();
    if (selected) {
      m.set("INTERNET", 0);
      selected.steps.forEach((s, i) => m.set(s.host, i + 1));
    }
    return m;
  }, [selected]);

  const pathEdgeKeys = useMemo(() => {
    if (!selected) return [] as string[];
    const seq = ["INTERNET", ...selected.steps.map((s) => s.host)];
    return seq.slice(0, -1).map((s, i) => `${s}__${seq[i + 1]}`);
  }, [selected]);

  const matchSet = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    const s = new Set<string>();
    graph.nodes.forEach((n) => {
      if (`${n.label} ${n.zone} ${n.role ?? ""} ${n.team ?? ""}`.toLowerCase().includes(q)) s.add(n.id);
    });
    return s;
  }, [query, graph]);

  const focusSet = useMemo(() => {
    if (!hoveredId || !focusOnHover || pathNodeIds || matchSet) return null;
    return new Set<string>([hoveredId, ...(neighbors.get(hoveredId) ?? [])]);
  }, [hoveredId, focusOnHover, pathNodeIds, matchSet, neighbors]);

  // Re-fit ONLY when structure/layout changes — never on a hover re-render.
  useEffect(() => {
    const t = setTimeout(() => fitView({ padding: 0.22, duration: 500 }), 60);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layoutMode, graph]);

  function trackHover(e: { clientX: number; clientY: number }, node: Node<NodeData> | GraphNode) {
    const gnode = byId.get(node.id);
    if (!gnode) return;
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const W = 256, H = 260;
    let left = e.clientX - rect.left + 18;
    let top = e.clientY - rect.top + 18;
    if (left + W > rect.width) left = e.clientX - rect.left - W - 12;
    if (top + H > rect.height) top = Math.max(8, rect.height - H - 8);
    setHovered({ node: gnode, left: Math.max(8, left), top: Math.max(8, top) });
  }

  const nodes: Node<NodeData>[] = graph.nodes.map((n) => {
    const onPath = pathNodeIds?.has(n.id) ?? false;
    const inFocus = focusSet?.has(n.id) ?? false;
    const isMatch = matchSet?.has(n.id) ?? false;
    const dim = pathNodeIds ? !onPath : matchSet ? !isMatch : focusSet ? !inFocus : false;
    return {
      id: n.id,
      type: "asset",
      position: pos.get(n.id) ?? { x: 0, y: 0 },
      data: {
        label: n.label, zone: n.zone, vlan: n.vlan, grs: n.grs, crown: n.crown,
        entry: n.entry, kind: n.kind, role: n.role ?? "", qidCount: n.qids?.length ?? 0,
        dim,
        active: pathNodeIds ? onPath : matchSet ? isMatch : inFocus,
        match: isMatch,
        stepIndex: stepIndexOf.has(n.id) ? stepIndexOf.get(n.id)! : null,
      },
      draggable: true,
    };
  });

  const edges: Edge<EdgeData>[] = graph.edges
    .filter((e) => (enabledKinds[e.kind] ?? true) || pathEdgeKeys.includes(`${e.source}__${e.target}`))
    .map((e) => {
      const key = `${e.source}__${e.target}`;
      const onPath = pathEdgeKeys.includes(key);
      const pathIdx = pathEdgeKeys.indexOf(key);
      const revealed = replayStep < 0 || (onPath && pathIdx <= replayStep);
      const touchesHover = focusSet ? focusSet.has(e.source) && focusSet.has(e.target) && (e.source === hoveredId || e.target === hoveredId) : false;
      const bothMatch = matchSet ? matchSet.has(e.source) && matchSet.has(e.target) : false;
      const dim = pathNodeIds ? !onPath : matchSet ? !bothMatch : focusSet ? !touchesHover : false;
      const idle = !pathNodeIds && !focusSet && !matchSet;
      const meta = EDGE_META[e.kind] ?? EDGE_META.lateral;
      return {
        id: key,
        source: e.source,
        target: e.target,
        type: "attack",
        markerEnd: { type: MarkerType.ArrowClosed, color: meta.color, width: 15, height: 15 },
        data: {
          kind: e.kind, onPath, revealed, dim, idle,
          label: onPath && e.qid ? `QID ${e.qid}` : meta.label,
          showLabel: showLabels,
        },
      };
    });

  return (
    <div ref={containerRef} className={cx("relative", fullscreen ? "fixed inset-0 z-[60] bg-base" : "h-full w-full")}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.22 }}
        minZoom={0.12}
        maxZoom={2.2}
        onNodeMouseEnter={(e, node) => trackHover(e, node)}
        onNodeMouseMove={(e, node) => trackHover(e, node)}
        onNodeMouseLeave={() => setHovered(null)}
        onPaneClick={() => setHovered(null)}
        proOptions={{ hideAttribution: true }}
        className="bg-transparent"
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="color-mix(in srgb, rgb(var(--c-ink-faint)) 22%, transparent)" />

        {/* top-left customization panel */}
        <Panel position="top-left" className="!m-3">
          <div className="flex w-[188px] flex-col gap-2 rounded-xl border border-line bg-surface/90 p-2 shadow-card backdrop-blur-md">
            <div className="grid grid-cols-3 gap-1">
              <SegBtn active={layoutMode === "flow"} onClick={() => setLayoutMode("flow")} icon={<Layers size={13} />} label="Flow" />
              <SegBtn active={layoutMode === "zones"} onClick={() => setLayoutMode("zones")} icon={<Rows3 size={13} />} label="Zones" />
              <SegBtn active={layoutMode === "radial"} onClick={() => setLayoutMode("radial")} icon={<Target size={13} />} label="Radial" />
            </div>

            {/* node search */}
            <div className="flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-2 py-1">
              <Search size={12} className="shrink-0 text-ink-faint" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Find host, zone, role…"
                className="w-full bg-transparent text-[11px] text-ink placeholder:text-ink-faint focus:outline-none"
              />
              {query && (
                <button onClick={() => setQuery("")} className="shrink-0 text-ink-faint hover:text-ink"><X size={11} /></button>
              )}
            </div>

            <div className="h-px bg-line" />
            <div className="flex flex-wrap gap-1">
              {EDGE_KINDS.map((k) => (
                <button
                  key={k}
                  onClick={() => setEnabledKinds((s) => ({ ...s, [k]: !s[k] }))}
                  className={cx("flex items-center gap-1 rounded-md px-1.5 py-1 text-[10px] font-semibold transition", enabledKinds[k] ? "text-ink" : "text-ink-faint opacity-50")}
                  style={enabledKinds[k] ? { background: `color-mix(in srgb, ${EDGE_META[k].color} 14%, transparent)` } : undefined}
                  title={`Toggle ${EDGE_META[k].label}`}
                >
                  <span className="h-1.5 w-3 rounded" style={{ background: EDGE_META[k].color, opacity: enabledKinds[k] ? 1 : 0.4 }} />
                  {EDGE_META[k].label}
                </button>
              ))}
            </div>
            <div className="h-px bg-line" />
            <div className="flex gap-1">
              <ToggleBtn active={focusOnHover} onClick={() => setFocusOnHover((v) => !v)} icon={<Focus size={13} />} title="Highlight neighbours on hover" />
              <ToggleBtn active={showLabels} onClick={() => setShowLabels((v) => !v)} icon={<TagIcon size={13} />} title="Edge labels on selected path" />
              <ToggleBtn active={showMiniMap} onClick={() => setShowMiniMap((v) => !v)} icon={<Waypoints size={13} />} title="Toggle minimap" />
              <ToggleBtn active={false} onClick={() => fitView({ padding: 0.22, duration: 400 })} icon={<Crosshair size={13} />} title="Fit to view" />
              <ToggleBtn active={fullscreen} onClick={() => { setFullscreen((v) => !v); setTimeout(() => fitView({ padding: 0.22, duration: 300 }), 80); }} icon={fullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />} title="Fullscreen" />
            </div>
          </div>
        </Panel>

        {/* top-right legend */}
        <Panel position="top-right" className="!m-3">
          <div className="flex flex-col gap-1.5 rounded-xl border border-line bg-surface/90 p-2.5 text-[10px] shadow-card backdrop-blur-md">
            <LegendRow swatch={<span className="grid h-3.5 w-3.5 place-items-center rounded-full border border-purple/70 text-[8px] text-purple">★</span>} label="Crown jewel" />
            <LegendRow swatch={<Crosshair size={12} className="text-immediate" />} label="Internet entry point" />
            <LegendRow swatch={<Zap size={11} className="text-act" />} label="⚑ = live findings on host" />
            <LegendRow swatch={<span className="h-1.5 w-4 rounded" style={{ background: "rgb(var(--c-immediate))" }} />} label="Hotter bar = higher GRS" />
          </div>
        </Panel>

        {/* replay controls */}
        {selected && (
          <Panel position="bottom-center" className="!mb-4">
            <ReplayControls
              steps={selected.steps.length}
              replay={replayStep}
              setReplay={setReplayStep}
              onClose={onClearSelection}
              label={`${selected.entry} → ${selected.target}`}
            />
          </Panel>
        )}
        {!selected && (
          <Panel position="bottom-left" className="!mb-3 !ml-3">
            <div className="pointer-events-none rounded-lg border border-line bg-surface/85 px-3 py-1.5 text-[11px] text-ink-muted backdrop-blur">
              {matchSet
                ? `${matchSet.size} match${matchSet.size === 1 ? "" : "es"} · clear search to reset`
                : "Full attack surface · hover a node to inspect · select a path to trace it"}
            </div>
          </Panel>
        )}

        {showMiniMap && (
          <MiniMap
            pannable
            zoomable
            className="!bottom-3 !right-3"
            maskColor="color-mix(in srgb, rgb(var(--c-base)) 60%, transparent)"
            nodeStrokeWidth={2}
            nodeColor={(n) => {
              const d = n.data as NodeData;
              if (d.kind === "internet") return "rgb(var(--c-immediate))";
              if (d.crown) return "rgb(var(--c-purple))";
              return d.grs > 0 ? bandColor(bandForGrs(d.grs)) : "rgb(var(--c-line-strong))";
            }}
          />
        )}
      </ReactFlow>

      {/* mouse-following hover inspector — lives in the container (not inside a
          transformed react-flow node), so it never triggers the backdrop-filter
          repaint bug that used to blank the canvas on hover. */}
      {hovered && (
        <NodeInspector
          node={hovered.node}
          degree={neighbors.get(hovered.node.id)?.size ?? 0}
          stepIndex={stepIndexOf.has(hovered.node.id) ? stepIndexOf.get(hovered.node.id)! : null}
          left={hovered.left}
          top={hovered.top}
        />
      )}
    </div>
  );
}

// ── Small UI bits ──────────────────────────────────────────────────────────

function SegBtn({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cx("flex items-center justify-center gap-1 rounded-md px-1.5 py-1 text-[11px] font-semibold transition", active ? "bg-sage text-forest" : "text-ink-muted hover:text-ink")}
    >
      {icon} {label}
    </button>
  );
}

function ToggleBtn({ active, onClick, icon, title }: { active: boolean; onClick: () => void; icon: ReactNode; title: string }) {
  return (
    <button
      onClick={onClick}
      title={title}
      className={cx("grid h-7 w-7 place-items-center rounded-md border transition", active ? "border-sage/40 bg-sage/15 text-sage-bright" : "border-line text-ink-muted hover:text-ink")}
    >
      {icon}
    </button>
  );
}

function LegendRow({ swatch, label }: { swatch: ReactNode; label: string }) {
  return (
    <div className="flex items-center gap-2 text-ink-muted">
      <span className="grid w-4 place-items-center">{swatch}</span>
      {label}
    </div>
  );
}

function ReplayControls({
  steps, replay, setReplay, onClose, label,
}: {
  steps: number; replay: number; setReplay: (n: number) => void; onClose: () => void; label: string;
}) {
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    let i = replay < 0 ? 0 : replay;
    setReplay(i);
    const timer = setInterval(() => {
      i += 1;
      if (i >= steps) { clearInterval(timer); setPlaying(false); setReplay(-1); }
      else setReplay(i);
    }, 850);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing]);

  const shown = replay < 0 ? steps : replay + 1;

  return (
    <div className="flex items-center gap-2 rounded-xl border border-line-strong bg-surface/95 px-3 py-2 shadow-pop backdrop-blur-md">
      <button
        onClick={() => setPlaying((p) => !p)}
        className="grid h-8 w-8 place-items-center rounded-lg bg-sage text-forest transition hover:bg-sage-bright"
      >
        {playing ? <Pause size={15} /> : <Play size={15} />}
      </button>
      <button onClick={() => { setPlaying(false); setReplay(-1); }} className="grid h-8 w-8 place-items-center rounded-lg border border-line text-ink-muted hover:text-ink" title="Reset">
        <RotateCcw size={14} />
      </button>
      <div className="flex items-center gap-2 px-1">
        <div className="flex gap-1">
          {Array.from({ length: steps }).map((_, i) => (
            <span key={i} className={cx("h-1.5 w-4 rounded-full transition-colors", i < shown ? "bg-sage" : "bg-surface-3")} />
          ))}
        </div>
        <span className="flex items-center gap-1.5 text-xs font-medium text-ink"><Link2 size={12} className="text-ink-faint" />{label}</span>
      </div>
      <button onClick={onClose} className="ml-1 grid h-7 w-7 place-items-center rounded-lg text-ink-faint hover:text-ink" title="Clear selection">
        <X size={14} />
      </button>
    </div>
  );
}
