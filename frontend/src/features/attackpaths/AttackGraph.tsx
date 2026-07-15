import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJsonBlock } from "cytoscape";
import fcose from "cytoscape-fcose";
import cyNavigator from "cytoscape-navigator";
import "cytoscape-navigator/cytoscape.js-navigator.css";
import {
  Crosshair, Focus, Layers, Link2, Maximize2, Minimize2, Pause, Play,
  RotateCcw, Rows3, Search, Target, Tag as TagIcon, Waypoints, X, Zap,
} from "lucide-react";
import { EDGE_META, bandColor, bandForGrs, BAND_META, cx } from "@/lib/format";
import { useTheme } from "@/lib/theme";
import { roleIcon, iconDataUri } from "./nodeVisuals";
import type { AttackPath, GraphNode, GraphPayload } from "@/lib/types";

let extensionsRegistered = false;
function ensureExtensionsRegistered() {
  if (extensionsRegistered) return;
  cytoscape.use(fcose);
  cyNavigator(cytoscape);
  extensionsRegistered = true;
}

type LayoutMode = "flow" | "zones" | "radial";

const CIRCLED = ["", "①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩", "⑪", "⑫", "⑬", "⑭", "⑮", "⑯", "⑰", "⑱", "⑲", "⑳"];
function circled(n: number): string {
  return CIRCLED[n] ?? `(${n})`;
}

// ── Theme-resolved palette ───────────────────────────────────────────────
// Cytoscape draws on <canvas>, so its stylesheet needs real rgb(...) strings —
// it cannot resolve CSS custom properties the way the DOM cascade does. We
// read the current --c-* values off :root and rebuild this whenever the
// light/dark toggle fires (see lib/theme.ts).
const CSS_VARS = [
  "c-surface", "c-surface-2", "c-surface-3", "c-line", "c-line-strong",
  "c-ink", "c-ink-muted", "c-ink-faint", "c-forest", "c-sage", "c-sage-bright",
  "c-immediate", "c-act", "c-attend", "c-track2", "c-track", "c-purple",
] as const;
type Palette = Record<(typeof CSS_VARS)[number], string>;

function readPalette(): Palette {
  const style = getComputedStyle(document.documentElement);
  const out = {} as Palette;
  CSS_VARS.forEach((name) => {
    const raw = style.getPropertyValue(`--${name}`).trim();
    // Cytoscape's canvas color parser expects legacy comma-separated
    // rgb(r,g,b) — the CSS Color-4 space-separated syntax our custom
    // properties are stored in (e.g. "191 60 41") silently fails to parse
    // there and falls back to a default gray, even though it's valid CSS.
    out[name] = raw ? `rgb(${raw.trim().split(/\s+/).join(",")})` : "rgb(128,128,128)";
  });
  return out;
}

function useResolvedPalette(theme: string): Palette {
  const [palette, setPalette] = useState<Palette>(() => readPalette());
  useEffect(() => setPalette(readPalette()), [theme]);
  return palette;
}

// format.ts's bandColor()/EDGE_META[k].color return "rgb(var(--c-x))" strings
// meant for the DOM's CSS cascade to resolve. Cytoscape draws on <canvas> —
// its stylesheet parser has no notion of custom properties, so those strings
// silently fail to parse there. These maps mirror the same band/kind → hue
// associations but resolve through the already-computed `palette` instead.
const BAND_PALETTE_KEY: Record<string, keyof Palette> = {
  IMMEDIATE: "c-immediate", ACT: "c-act", ATTEND: "c-attend", "TRACK*": "c-track2", TRACK: "c-track",
};
const EDGE_KIND_PALETTE_KEY: Record<string, keyof Palette> = {
  entry: "c-immediate", segmentation: "c-act", credential: "c-attend", domain: "c-purple", lateral: "c-track2",
};

// ── Layout engines (ported from the previous BFS-based scheme) ──────────

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

interface LayoutResult {
  pos: Map<string, { x: number; y: number }>;
  zones?: string[];
  rings?: { d: number; r: number }[];
}

function layoutFlow(graph: GraphPayload): LayoutResult {
  const dist = bfsDistance(graph);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const layers = new Map<number, string[]>();
  graph.nodes.forEach((n) => {
    const l = dist.get(n.id)!;
    if (!layers.has(l)) layers.set(l, []);
    layers.get(l)!.push(n.id);
  });
  const pos = new Map<string, { x: number; y: number }>();
  const GAP = 150;
  const COL = 340;
  layers.forEach((ids, l) => {
    ids.sort((a, b) => {
      const na = byId.get(a)!, nb = byId.get(b)!;
      return na.zone.localeCompare(nb.zone) || nb.grs - na.grs || a.localeCompare(b);
    });
    const h = (ids.length - 1) * GAP;
    ids.forEach((id, i) => pos.set(id, { x: l * COL, y: i * GAP - h / 2 }));
  });
  return { pos };
}

function layoutZones(graph: GraphPayload): LayoutResult {
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
  const COL = 340;
  const STEP = 148;
  const PAD = 110;

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
  return { pos, zones };
}

function layoutRadial(graph: GraphPayload): LayoutResult {
  const dist = bfsDistance(graph);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const ringNodes = new Map<number, string[]>();
  graph.nodes.forEach((n) => {
    if (n.kind === "internet") return;
    const d = Math.max(1, dist.get(n.id)!);
    if (!ringNodes.has(d)) ringNodes.set(d, []);
    ringNodes.get(d)!.push(n.id);
  });
  const pos = new Map<string, { x: number; y: number }>([["INTERNET", { x: 0, y: 0 }]]);
  const RING = 300;
  const MIN_ARC = 150;
  const rings: { d: number; r: number }[] = [];
  ringNodes.forEach((ids, d) => {
    ids.sort((a, b) => {
      const na = byId.get(a)!, nb = byId.get(b)!;
      return na.zone.localeCompare(nb.zone) || nb.grs - na.grs || a.localeCompare(b);
    });
    const r = Math.max(d * RING, (ids.length * MIN_ARC) / (2 * Math.PI));
    rings.push({ d, r });
    const step = (2 * Math.PI) / ids.length;
    const offset = -Math.PI / 2 + (d % 2) * (step / 2);
    ids.forEach((id, i) => {
      const a = offset + i * step;
      pos.set(id, { x: Math.cos(a) * r, y: Math.sin(a) * r });
    });
  });
  return { pos, rings };
}

const LAYOUTS: Record<LayoutMode, (g: GraphPayload) => LayoutResult> = {
  flow: layoutFlow,
  zones: layoutZones,
  radial: layoutRadial,
};

// ── Node inspector (docked, not floating) ────────────────────────────────

function InspectorRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-ink-faint">{label}</dt>
      <dd className="min-w-0 truncate text-right text-ink-muted">{children}</dd>
    </div>
  );
}

function NodeInspector({ node, degree, stepIndex }: { node: GraphNode; degree: number; stepIndex: number | null }) {
  if (node.kind === "internet") {
    return (
      <div className="space-y-2 p-4">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-immediate">
          <Waypoints size={13} /> Internet
        </div>
        <p className="text-[11px] leading-relaxed text-ink-muted">
          The attacker's starting point. Every discovered chain originates here.
        </p>
      </div>
    );
  }
  const band = bandForGrs(node.grs);
  const color = node.crown ? "rgb(var(--c-purple))" : node.grs > 0 ? bandColor(band) : "rgb(var(--c-ink-faint))";
  const Icon = roleIcon(node.role ?? "", node.label, node.kind);
  return (
    <div>
      <div className="flex items-center gap-2 border-b border-line px-4 py-3" style={{ background: `color-mix(in srgb, ${color} 8%, transparent)` }}>
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg" style={{ background: `color-mix(in srgb, ${color} 16%, transparent)`, color }}>
          <Icon size={16} />
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
      <dl className="space-y-1.5 px-4 py-3 text-[11px]">
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
        <div className="flex flex-wrap gap-1 border-t border-line px-4 py-2.5">
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
  const [theme] = useTheme();
  const palette = useResolvedPalette(theme);
  const navMountId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyContainerRef = useRef<HTMLDivElement>(null);
  const navContainerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const navRef = useRef<{ destroy?: () => void } | null>(null);

  const [layoutMode, setLayoutMode] = useState<LayoutMode>("flow");
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [pinnedId, setPinnedId] = useState<string | null>(null);
  const [focusOnHover, setFocusOnHover] = useState(true);
  const [showLabels, setShowLabels] = useState(true);
  const [showMiniMap, setShowMiniMap] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [query, setQuery] = useState("");
  const [enabledKinds, setEnabledKinds] = useState<Record<string, boolean>>(
    () => Object.fromEntries(EDGE_KINDS.map((k) => [k, k !== "lateral"])),
  );

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);

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

  const edgeCounts = useMemo(() => {
    const m: Record<string, number> = {};
    graph.edges.forEach((e) => { m[e.kind] = (m[e.kind] ?? 0) + 1; });
    return m;
  }, [graph.edges]);
  const hiddenEdgeCount = useMemo(
    () => EDGE_KINDS.reduce((sum, k) => sum + (enabledKinds[k] ? 0 : edgeCounts[k] ?? 0), 0),
    [enabledKinds, edgeCounts],
  );

  const matchSet = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    const s = new Set<string>();
    graph.nodes.forEach((n) => {
      if (`${n.label} ${n.zone} ${n.role ?? ""} ${n.team ?? ""}`.toLowerCase().includes(q)) s.add(n.id);
    });
    return s;
  }, [query, graph]);

  const activeId = pinnedId ?? hoveredId;
  const inspectedNode = activeId ? byId.get(activeId) ?? null : null;

  // ── Mount cytoscape once ──────────────────────────────────────────────
  useEffect(() => {
    ensureExtensionsRegistered();
    if (!cyContainerRef.current) return;
    const cy = cytoscape({
      container: cyContainerRef.current,
      elements: [],
      style: [],
      minZoom: 0.15,
      maxZoom: 2.2,
      wheelSensitivity: 0.22,
      pixelRatio: "auto",
    });
    cyRef.current = cy;

    cy.on("mouseover", "node[kind]", (evt) => setHoveredId(evt.target.id()));
    cy.on("mouseout", "node[kind]", () => setHoveredId(null));
    cy.on("tap", "node[kind]", (evt) => {
      const id = evt.target.id();
      setPinnedId((p) => (p === id ? null : id));
    });
    cy.on("tap", (evt) => { if (evt.target === cy) setPinnedId(null); });

    return () => {
      // Navigator lifecycle is owned by the minimap effect below — destroying
      // it here too (its cleanup already ran) double-destroys the same
      // instance and throws inside its internal DOM teardown.
      cy.destroy();
      cyRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Build the stylesheet (theme + label-visibility dependent) ─────────
  const stylesheet = useMemo((): StylesheetJsonBlock[] => {
    const nodeColor = (grs: number, crown: boolean, kind: string): string => {
      if (kind === "internet") return palette["c-immediate"];
      if (crown) return palette["c-purple"];
      return grs > 0 ? palette[BAND_PALETTE_KEY[bandForGrs(grs)]] : palette["c-ink-faint"];
    };
    return [
      {
        selector: "node[kind]",
        style: {
          shape: "round-rectangle",
          width: 58,
          height: 58,
          "background-color": (ele: cytoscape.NodeSingular) =>
            `color-mix(in srgb, ${nodeColor(ele.data("grs"), ele.data("crown"), ele.data("kind"))} 16%, ${palette["c-surface-2"]})`,
          "border-width": (ele: cytoscape.NodeSingular) => (ele.data("grs") > 0 ? 2 + Math.round((ele.data("grs") / 100) * 2) : 2),
          "border-color": (ele: cytoscape.NodeSingular) => nodeColor(ele.data("grs"), ele.data("crown"), ele.data("kind")),
          "border-style": (ele: cytoscape.NodeSingular) => (ele.data("entry") ? "dashed" : "solid"),
          "background-image": (ele: cytoscape.NodeSingular) => ele.data("icon"),
          "background-width": "56%",
          "background-height": "56%",
          "background-fit": "none",
          "background-clip": "none",
          label: (ele: cytoscape.NodeSingular) => ele.data("displayLabel"),
          "font-size": 10,
          "font-weight": 600,
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 8,
          color: palette["c-ink"],
          "text-wrap": "wrap",
          "text-max-width": "96px",
          "text-outline-width": 0,
        },
      },
      {
        selector: "node[kind = 'internet']",
        style: { width: 78, height: 78, shape: "ellipse", "background-width": "48%", "background-height": "48%" },
      },
      {
        selector: "node[?crown]",
        style: { shape: "star", width: 70, height: 70 },
      },
      {
        selector: "node.lane",
        style: {
          shape: "round-rectangle",
          "background-color": palette["c-surface-2"],
          "background-opacity": 0.5,
          "border-width": 1,
          "border-color": palette["c-line"],
          "border-style": "solid",
          "padding": "34px",
          label: "data(displayLabel)",
          "text-valign": "top",
          "text-halign": "center",
          "text-margin-y": -14,
          "font-size": 10,
          "font-weight": 700,
          color: palette["c-ink-faint"],
          "text-transform": "uppercase",
          "text-wrap": "ellipsis",
          "text-max-width": "130px",
          "text-background-color": palette["c-surface"],
          "text-background-opacity": 0.8,
          "text-background-padding": "2px",
        },
      },
      {
        selector: "node.ring",
        style: {
          shape: "ellipse",
          "background-opacity": 0,
          "border-width": 1,
          "border-color": palette["c-line"],
          "border-style": "dashed",
          label: "",
          events: "no",
        },
      },
      {
        selector: "node.ring-label",
        style: {
          "background-opacity": 0,
          "border-width": 0,
          label: "data(displayLabel)",
          "font-size": 10,
          color: palette["c-ink-faint"],
          "text-background-color": palette["c-surface"],
          "text-background-opacity": 0.75,
          "text-background-padding": "2px",
          width: 1,
          height: 1,
        },
      },
      {
        selector: "edge",
        style: {
          "curve-style": "bezier",
          "control-point-step-size": 36,
          width: 1.4,
          "line-color": (ele: cytoscape.EdgeSingular) => palette[EDGE_KIND_PALETTE_KEY[ele.data("kind")] ?? "c-track2"],
          "target-arrow-color": (ele: cytoscape.EdgeSingular) => palette[EDGE_KIND_PALETTE_KEY[ele.data("kind")] ?? "c-track2"],
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.85,
          "line-style": (ele: cytoscape.EdgeSingular) => (EDGE_META[ele.data("kind")]?.dashed ? "dashed" : "solid"),
          opacity: 0.55,
          label: "",
          "font-size": 9,
          "font-weight": 600,
          "text-rotation": "autorotate",
          "text-background-color": palette["c-surface"],
          "text-background-opacity": 0.85,
          "text-background-padding": "2px",
          color: (ele: cytoscape.EdgeSingular) => palette[EDGE_KIND_PALETTE_KEY[ele.data("kind")] ?? "c-track2"],
        },
      },
      {
        selector: "edge.onpath",
        style: {
          width: 3,
          opacity: 1,
          "line-style": "solid",
          label: showLabels ? "data(displayLabel)" : "",
          "z-index": 10,
        },
      },
      { selector: "node.dim, edge.dim", style: { opacity: 0.08 } },
      { selector: "node.match", style: { "border-width": 3 } },
      { selector: "edge.hidden-kind", style: { display: "none" } },
      { selector: "node:selected", style: { "overlay-opacity": 0 } },
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [palette, showLabels]);

  useEffect(() => {
    cyRef.current?.style(stylesheet as never).update();
  }, [stylesheet]);

  // ── Rebuild elements + relayout on graph/layoutMode change ─────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const { pos, zones, rings } = LAYOUTS[layoutMode](graph);
    const elements: ElementDefinition[] = [];

    if (layoutMode === "zones" && zones) {
      zones.forEach((z) => {
        // Lane compounds auto-size to a single narrow node column, so long
        // zone names (e.g. "Clinical/Biomed Critical Zone (HIPAA/FDA scope)")
        // have nowhere to render — shorten just the on-canvas caption.
        const shortZ = z.length > 18 ? `${z.slice(0, 16)}…` : z;
        elements.push({ data: { id: `lane__${z}`, displayLabel: shortZ, fullZone: z }, classes: "lane", grabbable: false, selectable: false });
      });
    }
    if (layoutMode === "radial" && rings) {
      rings.forEach(({ d, r }) => {
        elements.push({ data: { id: `ring__${d}` }, position: { x: 0, y: 0 }, classes: "ring", grabbable: false, selectable: false, style: { width: r * 2, height: r * 2 } as never });
        elements.push({ data: { id: `ringlabel__${d}`, displayLabel: `${d} hop${d === 1 ? "" : "s"}` }, position: { x: 6, y: -r }, classes: "ring-label", grabbable: false, selectable: false });
      });
    }

    graph.nodes.forEach((n) => {
      const Icon = roleIcon(n.role ?? "", n.label, n.kind);
      const color = n.kind === "internet" ? palette["c-immediate"] : n.crown ? palette["c-purple"] : n.grs > 0 ? palette[BAND_PALETTE_KEY[bandForGrs(n.grs)]] : palette["c-ink-faint"];
      const stepIndex = stepIndexOf.get(n.id) ?? null;
      const displayLabel = n.kind === "internet"
        ? "INTERNET"
        : stepIndex != null ? `${circled(stepIndex)} ${n.label}` : n.label;
      elements.push({
        data: {
          id: n.id, kind: n.kind, crown: n.crown, entry: n.entry, grs: n.grs,
          zone: n.zone, icon: iconDataUri(Icon, color), displayLabel,
          parent: layoutMode === "zones" && n.kind !== "internet" ? `lane__${n.zone}` : undefined,
        },
        position: pos.get(n.id) ?? { x: 0, y: 0 },
      });
    });
    graph.edges.forEach((e) => {
      const meta = EDGE_META[e.kind] ?? EDGE_META.lateral;
      elements.push({
        data: {
          id: `${e.source}__${e.target}`, source: e.source, target: e.target, kind: e.kind,
          displayLabel: e.qid ? `QID ${e.qid}` : meta.label,
        },
      });
    });

    cy.elements().remove();
    cy.add(elements);
    cy.layout({ name: "preset", fit: false }).run();
    const t = setTimeout(() => {
      cy.fit(undefined, 48);
      // Zones/radial can be extremely tall or wide relative to the viewport
      // for lopsided datasets — fitting the whole thing can shrink labels
      // past legibility. Floor the zoom and re-center instead of letting
      // fit() zoom out arbitrarily far; panning covers the rest.
      const MIN_ZOOM = 0.42;
      if (cy.zoom() < MIN_ZOOM) {
        cy.zoom({ level: MIN_ZOOM, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
        cy.center();
      }
    }, 40);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, layoutMode, palette]);

  // ── Apply selection / hover / search / filter classes (no rebuild) ────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const focusId = !pathNodeIds && !matchSet && focusOnHover ? hoveredId : null;
    const focusSet = focusId ? new Set<string>([focusId, ...(neighbors.get(focusId) ?? [])]) : null;

    cy.batch(() => {
      cy.nodes("[kind]").forEach((node) => {
        const id = node.id();
        const onPath = pathNodeIds?.has(id) ?? false;
        const isMatch = matchSet?.has(id) ?? false;
        const inFocus = focusSet?.has(id) ?? false;
        const dim = pathNodeIds ? !onPath : matchSet ? !isMatch : focusSet ? !inFocus : false;
        node.toggleClass("dim", dim);
        node.toggleClass("match", isMatch);
        node.toggleClass("onpath", onPath);
      });
      cy.edges().forEach((edge) => {
        const key = edge.id();
        const onPath = pathEdgeKeys.includes(key);
        const idx = pathEdgeKeys.indexOf(key);
        const revealed = replayStep < 0 || (onPath && idx <= replayStep);
        const kindHidden = !(enabledKinds[edge.data("kind")] ?? true) && !onPath;
        const bothMatch = matchSet ? matchSet.has(edge.data("source")) && matchSet.has(edge.data("target")) : false;
        const touchesFocus = focusSet ? focusSet.has(edge.data("source")) && focusSet.has(edge.data("target")) : false;
        const dim = pathNodeIds ? !(onPath && revealed) : matchSet ? !bothMatch : focusSet ? !touchesFocus : false;
        edge.toggleClass("onpath", onPath && revealed);
        edge.toggleClass("dim", dim);
        edge.toggleClass("hidden-kind", kindHidden);
      });
    });
  }, [pathNodeIds, pathEdgeKeys, replayStep, hoveredId, focusOnHover, matchSet, enabledKinds, neighbors]);

  // ── One-shot reveal animation for newly-visible replay edges ───────────
  const prevRevealCount = useRef(-2);
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !selected) { prevRevealCount.current = -2; return; }
    const shown = replayStep < 0 ? pathEdgeKeys.length : replayStep + 1;
    if (shown > prevRevealCount.current && prevRevealCount.current >= -1) {
      const newKey = pathEdgeKeys[shown - 1];
      const ele = newKey ? cy.getElementById(newKey) : null;
      if (ele && ele.length) {
        ele.style("opacity", 0);
        ele.animate({ style: { opacity: 1 } }, { duration: 420, easing: "ease-out-cubic" });
      }
    }
    prevRevealCount.current = shown;
  }, [replayStep, selected, pathEdgeKeys]);

  // ── Minimap ──────────────────────────────────────────────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !navContainerRef.current) return;
    if (!showMiniMap) { navRef.current?.destroy?.(); navRef.current = null; return; }
    navRef.current?.destroy?.();
    navRef.current = (cy as unknown as { navigator: (opts: Record<string, unknown>) => { destroy?: () => void } }).navigator({
      container: `#${navMountId}`,
      // Our mount div is owned by React (it's a JSX element, not created by
      // the plugin) — without this, destroy() rips the div itself out of
      // the DOM instead of just clearing its contents, which then makes a
      // subsequent re-init's getElementById() come up empty.
      removeCustomContainer: false,
      viewLiveFramerate: 0,
      thumbnailEventFramerate: 30,
      rerenderDelay: 80,
    });
    return () => {
      navRef.current?.destroy?.();
      navRef.current = null;
    };
  }, [showMiniMap, graph, layoutMode, navMountId]);

  // ── Fullscreen / container resize ───────────────────────────────────
  useEffect(() => {
    const t = setTimeout(() => { cyRef.current?.resize(); cyRef.current?.fit(undefined, 48); }, 80);
    return () => clearTimeout(t);
  }, [fullscreen]);

  return (
    <div ref={containerRef} className={cx("relative flex", fullscreen ? "fixed inset-0 z-[60] bg-base" : "h-full w-full")}>
      <div className="relative min-w-0 flex-1">
        <div ref={cyContainerRef} className="ag-canvas h-full w-full" />

        {/* top-left control panel */}
        <div className="pointer-events-auto absolute left-3 top-3 z-10 flex w-[192px] flex-col gap-2 rounded-xl border border-line bg-surface/90 p-2 shadow-card backdrop-blur-md">
          <div className="grid grid-cols-3 gap-1">
            <SegBtn active={layoutMode === "flow"} onClick={() => setLayoutMode("flow")} icon={<Layers size={13} />} label="Flow" />
            <SegBtn active={layoutMode === "zones"} onClick={() => setLayoutMode("zones")} icon={<Rows3 size={13} />} label="Zones" />
            <SegBtn active={layoutMode === "radial"} onClick={() => setLayoutMode("radial")} icon={<Target size={13} />} label="Radial" />
          </div>
          <div className="flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-2 py-1">
            <Search size={12} className="shrink-0 text-ink-faint" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find host, zone, role…"
              className="w-full bg-transparent text-[11px] text-ink placeholder:text-ink-faint focus:outline-none"
            />
            {query && <button onClick={() => setQuery("")} className="shrink-0 text-ink-faint hover:text-ink"><X size={11} /></button>}
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
                <span className="text-ink-faint">{edgeCounts[k] ?? 0}</span>
              </button>
            ))}
          </div>
          <div className="h-px bg-line" />
          <div className="flex gap-1">
            <ToggleBtn active={focusOnHover} onClick={() => setFocusOnHover((v) => !v)} icon={<Focus size={13} />} title="Highlight neighbours on hover" />
            <ToggleBtn active={showLabels} onClick={() => setShowLabels((v) => !v)} icon={<TagIcon size={13} />} title="Edge labels on selected path" />
            <ToggleBtn active={showMiniMap} onClick={() => setShowMiniMap((v) => !v)} icon={<Waypoints size={13} />} title="Toggle minimap" />
            <ToggleBtn active={false} onClick={() => cyRef.current?.fit(undefined, 48)} icon={<Crosshair size={13} />} title="Fit to view" />
            <ToggleBtn active={fullscreen} onClick={() => setFullscreen((v) => !v)} icon={fullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />} title="Fullscreen" />
          </div>
        </div>

        {/* top-right legend */}
        <div className="pointer-events-none absolute right-3 top-3 z-10 flex flex-col gap-1.5 rounded-xl border border-line bg-surface/90 p-2.5 text-[10px] shadow-card backdrop-blur-md">
          <LegendRow swatch={<span className="grid h-3.5 w-3.5 place-items-center rounded-full border border-purple/70 text-[8px] text-purple">★</span>} label="Crown jewel (star shape)" />
          <LegendRow swatch={<Crosshair size={12} className="text-immediate" />} label="Dashed ring = internet entry" />
          <LegendRow swatch={<Zap size={11} className="text-act" />} label="Thicker ring = higher GRS" />
          <LegendRow swatch={<span className="h-1.5 w-4 rounded" style={{ background: "rgb(var(--c-immediate))" }} />} label="Ring/icon hue = risk band" />
        </div>

        {/* replay / status bar */}
        {selected && (
          <div className="pointer-events-auto absolute bottom-4 left-1/2 z-10 -translate-x-1/2">
            <ReplayControls
              steps={selected.steps.length}
              replay={replayStep}
              setReplay={setReplayStep}
              onClose={onClearSelection}
              label={`${selected.entry} → ${selected.target}`}
            />
          </div>
        )}
        {!selected && (
          <div className="pointer-events-none absolute bottom-3 left-3 z-10 rounded-lg border border-line bg-surface/85 px-3 py-1.5 text-[11px] text-ink-muted backdrop-blur">
            {matchSet
              ? `${matchSet.size} match${matchSet.size === 1 ? "" : "es"} · clear search to reset`
              : hiddenEdgeCount > 0
                ? `${hiddenEdgeCount} edge${hiddenEdgeCount === 1 ? "" : "s"} hidden for clarity · toggle in the panel to reveal`
                : "Full attack surface · hover a node to inspect · select a path to trace it"}
          </div>
        )}

        {showMiniMap && (
          <div id={navMountId} ref={navContainerRef} className="ag-navigator pointer-events-auto absolute bottom-3 right-3 z-10 h-[120px] w-[170px] overflow-hidden rounded-lg border border-line-strong bg-surface/95 shadow-card" />
        )}
      </div>

      {/* docked inspector */}
      <div className="hidden w-[264px] shrink-0 overflow-y-auto border-l border-line bg-surface/60 lg:block">
        {inspectedNode ? (
          <NodeInspector
            node={inspectedNode}
            degree={neighbors.get(inspectedNode.id)?.size ?? 0}
            stepIndex={stepIndexOf.has(inspectedNode.id) ? stepIndexOf.get(inspectedNode.id)! : null}
          />
        ) : (
          <div className="grid h-full place-items-center p-6 text-center">
            <p className="text-xs text-ink-faint">Hover or click a node to inspect it{pinnedId ? "" : ". Click pins the panel"}.</p>
          </div>
        )}
      </div>
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
