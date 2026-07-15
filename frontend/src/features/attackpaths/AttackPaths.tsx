import { Component, useState, type ReactNode } from "react";
import { ChevronRight, ChevronsLeft, ChevronsRight, RefreshCw, Skull } from "lucide-react";
import { useAttackPaths, useGraph } from "@/lib/hooks";
import { EDGE_META, confidenceColor, cx } from "@/lib/format";
import { AiCard, ExportButton, SectionTitle, Skeleton, Tag } from "@/components/ui";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildAttackPathsReport } from "@/lib/reportBuilders";
import AttackGraph from "./AttackGraph";
import PathDetail from "./PathDetail";
import type { AttackPath } from "@/lib/types";

export default function AttackPaths() {
  const { data: paths, isLoading: lp } = useAttackPaths();
  const { data: graph, isLoading: lg } = useGraph();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [replay, setReplay] = useState(-1);
  const [railOpen, setRailOpen] = useState(true);

  if (lp || lg || !paths || !graph)
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-72" />
        <Skeleton className="h-[calc(100vh-220px)] min-h-[640px]" />
      </div>
    );

  const selected = paths.paths.find((p) => p.path_id === selectedId) ?? null;

  function select(p: AttackPath | null) {
    setSelectedId(p?.path_id ?? null);
    setReplay(-1);
  }

  return (
    <div className="animate-fade-up space-y-5">
      <SectionTitle
        sub="Chains discovered autonomously by the reachability engine — never read from a script. Select one to trace it on the map."
        right={
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3 text-[11px] text-ink-muted">
              {Object.entries(EDGE_META).map(([k, m]) => (
                <span key={k} className="flex items-center gap-1.5">
                  <span className="h-0.5 w-4 rounded" style={{ background: m.color, ...(m.dashed && { backgroundImage: "none" }) }} />
                  {m.label}
                </span>
              ))}
            </div>
            <ExportButton onClick={() => downloadMarkdown(`ghrab-voc-attack-paths-${timestamp()}.md`, buildAttackPathsReport(paths))} />
          </div>
        }
      >
        Attack Paths
      </SectionTitle>

      {paths.ai_enabled && paths.summary && <AiCard label="Attack-Surface Synthesis">{paths.summary}</AiCard>}

      {/* Graph canvas — dominant element, with a collapsible ranked-path rail */}
      <div className="relative flex h-[calc(100vh-220px)] min-h-[640px] gap-0 overflow-hidden rounded-2xl border border-line bg-surface/40">
        <div className={cx("flex shrink-0 flex-col border-r border-line bg-surface/60 transition-[width] duration-200", railOpen ? "w-[300px]" : "w-0")}>
          {railOpen && (
            <>
              <div className="flex items-center justify-between border-b border-line px-3 py-2.5">
                <div>
                  <span className="label block">{paths.paths.length} Discovered Paths</span>
                  <span className="text-[10px] text-ink-faint">ranked by risk</span>
                </div>
                <button onClick={() => setRailOpen(false)} className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-ink-faint hover:bg-surface-3 hover:text-ink" title="Collapse path list">
                  <ChevronsLeft size={14} />
                </button>
              </div>
              <div className="flex-1 space-y-2 overflow-y-auto p-2.5">
                {paths.paths.map((p, i) => (
                  <button
                    key={p.path_id}
                    onClick={() => select(selectedId === p.path_id ? null : p)}
                    className={cx(
                      "w-full rounded-xl border p-3 text-left transition",
                      selectedId === p.path_id
                        ? "border-sage/50 bg-sage/[0.08] shadow-glow"
                        : "border-line bg-surface-2/50 hover:border-line-strong",
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="grid h-5 w-5 place-items-center rounded bg-surface-3 font-mono text-[10px] text-ink-muted">{i + 1}</span>
                        <span className="font-mono text-xs text-sage-bright">{p.path_id}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        {p.confidence && (
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: confidenceColor(p.confidence) }} title={`confidence: ${p.confidence}`} />
                        )}
                        <span className="font-mono text-[11px] text-ink-faint">{p.score}</span>
                      </div>
                    </div>
                    <div className="mt-2 flex items-center gap-1.5 text-sm">
                      <span className="font-medium text-ink">{p.entry}</span>
                      <ChevronRight size={13} className="text-ink-faint" />
                      <span className="truncate font-medium text-purple">{p.target}</span>
                    </div>
                    {p.headline && <p className="mt-1.5 line-clamp-2 text-xs text-ink-muted">{p.headline}</p>}
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] text-ink-faint">{p.length} hops</span>
                      {p.novelty && p.novelty !== "textbook" && (
                        <Tag color={p.novelty === "non-obvious" ? "rgb(var(--c-immediate))" : "rgb(var(--c-act))"}>{p.novelty}</Tag>
                      )}
                      {p.max_grs >= 80 && <Tag color="rgb(var(--c-immediate))">peak {p.max_grs}</Tag>}
                    </div>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {!railOpen && (
          <button
            onClick={() => setRailOpen(true)}
            className="absolute left-2 top-2 z-20 flex items-center gap-1.5 rounded-lg border border-line bg-surface/90 px-2 py-1.5 text-[11px] font-semibold text-ink-muted shadow-card backdrop-blur-md hover:text-ink"
            title="Show ranked path list"
          >
            <ChevronsRight size={14} /> {paths.paths.length} Paths
          </button>
        )}

        <div className="relative min-w-0 flex-1">
          <GraphErrorBoundary>
            <AttackGraph
              graph={graph}
              selected={selected}
              replayStep={replay}
              setReplayStep={setReplay}
              onClearSelection={() => select(null)}
            />
          </GraphErrorBoundary>
        </div>
      </div>

      {selected && <PathDetail path={selected} />}

      {/* Toxic combinations */}
      {paths.toxic_combinations.length > 0 && (
        <div>
          <SectionTitle sub="Non-obvious risk the pathfinder alone would miss — reasoned by the discovery agent.">
            Toxic Combinations
          </SectionTitle>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {paths.toxic_combinations.map((t, i) => (
              <div key={i} className="card p-4">
                <div className="mb-2 flex items-center gap-2">
                  <Skull size={16} className="text-immediate" />
                  <h3 className="font-semibold text-ink">{t.title}</h3>
                </div>
                <p className="text-sm leading-relaxed text-ink-muted">{t.mechanism}</p>
                {t.why_it_matters && (
                  <p className="mt-2 text-sm text-ink-muted"><span className="font-semibold text-ink">Why it matters: </span>{t.why_it_matters}</p>
                )}
                {t.involved_qids?.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap gap-1.5">
                    {t.involved_qids.map((q) => <Tag key={q}>QID {q}</Tag>)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** Keeps a rendering error inside the canvas from blanking the whole app —
 *  shows a recoverable fallback with a remount button instead of a white page. */
class GraphErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean; key: number }> {
  state = { failed: false, key: 0 };

  static getDerivedStateFromError() {
    return { failed: true } as { failed: boolean };
  }

  render() {
    if (this.state.failed) {
      return (
        <div className="grid h-full place-items-center p-6 text-center">
          <div className="space-y-3">
            <p className="text-sm text-ink-muted">The graph hit a rendering hiccup.</p>
            <button
              onClick={() => this.setState((s) => ({ failed: false, key: s.key + 1 }))}
              className="btn-primary mx-auto !py-1.5 text-xs"
            >
              <RefreshCw size={13} /> Reload graph
            </button>
          </div>
        </div>
      );
    }
    return <div key={this.state.key} className="h-full w-full">{this.props.children}</div>;
  }
}
