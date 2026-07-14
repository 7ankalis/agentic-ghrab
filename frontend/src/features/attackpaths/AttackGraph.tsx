import { useMemo } from "react";
import ReactFlow, {
  Background, BackgroundVariant, Controls, Handle, MarkerType, Position,
  type Edge, type Node, type NodeProps,
} from "reactflow";
import { Globe, Gem, Server, Radio } from "lucide-react";
import { EDGE_META, bandColor, bandForGrs, cx } from "@/lib/format";
import type { AttackPath, GraphPayload } from "@/lib/types";

interface NodeData {
  label: string;
  zone: string;
  grs: number;
  crown: boolean;
  entry: boolean;
  kind: string;
  dim: boolean;
  active: boolean;
}

function AssetNode({ data }: NodeProps<NodeData>) {
  if (data.kind === "internet") {
    return (
      <div className={cx("flex flex-col items-center gap-1 transition", data.dim && "opacity-25")}>
        <Handle type="source" position={Position.Right} className="!bg-immediate !border-0" />
        <div className="grid h-14 w-14 place-items-center rounded-full border-2 border-immediate/60 bg-immediate/15 shadow-glow">
          <Globe size={22} className="text-immediate" />
        </div>
        <span className="text-[11px] font-semibold text-ink">Internet</span>
      </div>
    );
  }
  const color = data.crown ? "#c97bd8" : bandColor(bandForGrs(data.grs));
  const Icon = data.crown ? Gem : data.entry ? Radio : Server;
  return (
    <div
      className={cx(
        "group relative min-w-[150px] rounded-xl border bg-surface-2 px-3 py-2 transition",
        data.active ? "shadow-glow" : "shadow-card",
        data.dim ? "opacity-20" : "opacity-100",
      )}
      style={{ borderColor: data.active ? color : "rgba(140,175,160,0.18)" }}
    >
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-ink-faint" />
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-ink-faint" />
      <div className="flex items-center gap-2">
        <div className="grid h-7 w-7 shrink-0 place-items-center rounded-lg" style={{ background: `${color}1f` }}>
          <Icon size={15} style={{ color }} />
        </div>
        <div className="min-w-0">
          <div className="truncate text-[13px] font-semibold text-ink">{data.label}</div>
          <div className="truncate text-[10px] text-ink-faint">{data.zone}</div>
        </div>
      </div>
      <div className="mt-1.5 flex items-center gap-1.5">
        {data.grs > 0 && (
          <span className="rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold" style={{ background: `${color}22`, color }}>
            GRS {data.grs}
          </span>
        )}
        {data.entry && <span className="rounded bg-immediate/15 px-1.5 py-0.5 text-[10px] font-semibold text-immediate">ENTRY</span>}
        {data.crown && <span className="rounded bg-[#c97bd8]/15 px-1.5 py-0.5 text-[10px] font-semibold text-[#c97bd8]">CROWN</span>}
      </div>
    </div>
  );
}

const nodeTypes = { asset: AssetNode };

/** BFS layered layout: x = distance from INTERNET, y spread within layer. */
function layout(graph: GraphPayload): Map<string, { x: number; y: number }> {
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
      if (!dist.has(m)) {
        dist.set(m, dist.get(n)! + 1);
        queue.push(m);
      }
    }
  }
  // unreachable nodes: park them in a trailing column by zone
  let maxLayer = 0;
  dist.forEach((d) => (maxLayer = Math.max(maxLayer, d)));
  graph.nodes.forEach((n) => {
    if (!dist.has(n.id)) dist.set(n.id, maxLayer + 1);
  });
  const layers = new Map<number, string[]>();
  graph.nodes.forEach((n) => {
    const l = dist.get(n.id)!;
    if (!layers.has(l)) layers.set(l, []);
    layers.get(l)!.push(n.id);
  });
  const pos = new Map<string, { x: number; y: number }>();
  layers.forEach((ids, l) => {
    ids.sort();
    const h = (ids.length - 1) * 96;
    ids.forEach((id, i) => pos.set(id, { x: l * 260, y: i * 96 - h / 2 }));
  });
  return pos;
}

export default function AttackGraph({
  graph,
  selected,
  replayStep,
}: {
  graph: GraphPayload;
  selected: AttackPath | null;
  replayStep: number; // -1 = show whole path; otherwise reveal up to index
}) {
  const pos = useMemo(() => layout(graph), [graph]);

  const pathNodeIds = useMemo(() => {
    if (!selected) return null;
    return new Set<string>(["INTERNET", ...selected.steps.map((s) => s.host)]);
  }, [selected]);

  // ordered edges along the selected path: INTERNET->h0->h1...
  const pathEdgeKeys = useMemo(() => {
    if (!selected) return [];
    const seq = ["INTERNET", ...selected.steps.map((s) => s.host)];
    return seq.slice(0, -1).map((s, i) => `${s}__${seq[i + 1]}`);
  }, [selected]);

  const nodes: Node<NodeData>[] = graph.nodes.map((n) => ({
    id: n.id,
    type: "asset",
    position: pos.get(n.id) ?? { x: 0, y: 0 },
    data: {
      label: n.label,
      zone: n.zone,
      grs: n.grs,
      crown: n.crown,
      entry: n.entry,
      kind: n.kind,
      dim: !!pathNodeIds && !pathNodeIds.has(n.id),
      active: !!pathNodeIds && pathNodeIds.has(n.id),
    },
    draggable: true,
  }));

  const edges: Edge[] = graph.edges.map((e) => {
    const key = `${e.source}__${e.target}`;
    const onPath = pathEdgeKeys.includes(key);
    const pathIdx = pathEdgeKeys.indexOf(key);
    const revealed = replayStep < 0 || (onPath && pathIdx <= replayStep);
    const meta = EDGE_META[e.kind] ?? EDGE_META.lateral;
    const dim = !!pathNodeIds && !onPath;
    return {
      id: key,
      source: e.source,
      target: e.target,
      animated: onPath && revealed,
      style: {
        stroke: onPath ? meta.color : "rgba(140,175,160,0.16)",
        strokeWidth: onPath ? 2.4 : 1,
        strokeDasharray: meta.dashed ? "5 4" : undefined,
        opacity: dim ? 0.12 : onPath && !revealed ? 0.25 : 1,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: onPath ? meta.color : "rgba(140,175,160,0.2)", width: 14, height: 14 },
    };
  });

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.2}
      maxZoom={1.8}
      proOptions={{ hideAttribution: true }}
      className="bg-transparent"
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="rgba(140,175,160,0.10)" />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}
