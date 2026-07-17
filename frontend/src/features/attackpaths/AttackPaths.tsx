import { Component, useState, type CSSProperties, type ReactNode } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, ChevronsLeft, ChevronsRight, MoveRight, RefreshCw, ShieldCheck, Skull, Sparkles } from "lucide-react";
import { useAttackPaths, useGraph, useVerification } from "@/lib/hooks";
import { EDGE_META, confidenceColor, cx } from "@/lib/format";
import { AiCard, ExportButton, SectionTitle, Skeleton, Tag, useSpotlight } from "@/components/ui";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildAttackPathsReport } from "@/lib/reportBuilders";
import AttackGraph from "./AttackGraph";
import PathDetail from "./PathDetail";
import type { AttackPath, DetectedPath } from "@/lib/types";

export default function AttackPaths() {
  const { data: paths, isLoading: lp } = useAttackPaths();
  const { data: graph, isLoading: lg } = useGraph();
  const { data: verif } = useVerification();
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

      {/* Verification vs held-out ground truth: did the engine & the analyst agent
          independently rediscover the documented paths (which are never ingested)? */}
      {verif && verif.documented_total > 0 && (
        <div className="card flex flex-wrap items-center gap-x-6 gap-y-3 p-4">
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-sage-bright" />
            <span className="label">Verification vs held-out ground truth</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-lg font-semibold text-ink">
              {verif.engine_rediscovered}/{verif.documented_total}
            </span>
            <span className="text-xs text-ink-muted">rediscovered by the reachability engine</span>
          </div>
          {verif.ai_enabled && (
            <div className="flex items-center gap-2">
              <span className="font-mono text-lg font-semibold text-ink">
                {verif.ai_detected}/{verif.documented_total}
              </span>
              <span className="text-xs text-ink-muted">detected by the analyst agent</span>
            </div>
          )}
          <p className="w-full text-[11px] leading-relaxed text-ink-faint">{verif.note}</p>
        </div>
      )}

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

      {/* AI-detected paths — reasoned from grounding alone by the analyst agent */}
      {paths.ai_detected?.length > 0 && (
        <div>
          <SectionTitle sub="Reasoned from scratch by the Analyst Detection Agent — given only the asset inventory, ownership, and reachability/credential relationships, never a candidate list or a script. Every hop is verified against a real finding.">
            Analyst-Detected Paths
          </SectionTitle>
          <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
            {paths.ai_detected.map((d, i) => (
              <DetectedPathCard key={i} d={d} index={i} />
            ))}
          </div>
        </div>
      )}

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

/** One analyst-detected chain, rendered as a kill-chain timeline: numbered hop
 *  markers on a gradient spine, per-hop evidence chips, and — when the agent
 *  explained itself — expandable reasoning behind each hop. */
function DetectedPathCard({ d, index }: { d: DetectedPath; index: number }) {
  const spotlight = useSpotlight();
  const [openHop, setOpenHop] = useState<number | null>(null);
  const conf = d.confidence ? confidenceColor(d.confidence) : null;
  const pct = d.total_hops > 0 ? Math.round((d.verified_hops / d.total_hops) * 100) : 0;

  return (
    <div
      onMouseMove={spotlight}
      className="card spot group relative animate-fade-up overflow-hidden transition-all duration-200 ease-out hover:-translate-y-0.5 hover:border-purple/30 hover:shadow-card-hover"
      style={{
        animationDelay: `${index * 70}ms`,
        "--spot-color": "color-mix(in srgb, rgb(var(--c-purple)) 7%, transparent)",
      } as CSSProperties}
    >
      {/* Accent seam: entry (sage) bleeding into target (purple) */}
      <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-sage via-purple/70 to-transparent" />

      <div className="p-4">
        {/* Header — route + verdict */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-purple/25 bg-purple/10 text-purple transition-transform duration-300 group-hover:scale-110">
              <Sparkles size={15} />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 text-sm">
                <span className="truncate font-mono font-semibold text-ink">{d.entry}</span>
                <MoveRight size={14} className="shrink-0 text-ink-faint" />
                <span className="truncate font-mono font-semibold text-purple">{d.target}</span>
              </div>
              {d.name && <p className="mt-0.5 truncate text-[11px] text-ink-faint">{d.name}</p>}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {conf && (
              <span
                className="pill !py-0.5"
                style={{
                  color: conf,
                  background: `color-mix(in srgb, ${conf} 10%, transparent)`,
                  border: `1px solid color-mix(in srgb, ${conf} 26%, transparent)`,
                }}
                title={`analyst confidence: ${d.confidence}`}
              >
                {d.confidence}
              </span>
            )}
            <Tag color={d.grounded ? "rgb(var(--c-sage-bright))" : "rgb(var(--c-act))"}>
              <span className={cx("h-1.5 w-1.5 rounded-full bg-current", d.grounded && "animate-pulse-dot")} />
              {d.grounded ? "grounded" : "partial"}
            </Tag>
          </div>
        </div>

        {/* Kill-chain timeline */}
        <ol className="mt-4">
          {d.hops.map((h, j) => {
            const expandable = Boolean(h.why);
            const open = openHop === j;
            return (
              <li key={j} className="relative pl-8 pb-1 last:pb-0">
                {/* Spine segment down to the next marker */}
                {j < d.hops.length - 1 && (
                  <span
                    aria-hidden
                    className="absolute bottom-[-3px] left-[10.5px] top-[23px] w-px bg-gradient-to-b from-line-strong to-line"
                  />
                )}
                {/* Hop marker — number when verified, alert when not */}
                <span
                  className={cx(
                    "absolute left-0 top-0.5 grid h-[21px] w-[21px] place-items-center rounded-full border font-mono text-[10px] font-semibold",
                    h.verified
                      ? "border-sage/40 bg-sage/10 text-sage-bright"
                      : "border-immediate/40 bg-immediate/10 text-immediate",
                  )}
                  title={h.verified ? "verified against a real finding" : "unverified hop"}
                >
                  {h.verified ? j + 1 : "!"}
                </span>

                <button
                  onClick={() => expandable && setOpenHop(open ? null : j)}
                  disabled={!expandable}
                  className={cx(
                    "-mx-1.5 flex w-[calc(100%+12px)] flex-wrap items-center gap-x-1.5 gap-y-1 rounded-lg px-1.5 py-1 text-left text-xs",
                    expandable && "transition-colors hover:bg-surface-2/70",
                  )}
                  title={expandable ? "Show the agent's reasoning for this hop" : undefined}
                >
                  <span className="font-mono font-medium text-ink">{h.from}</span>
                  <ChevronRight size={11} className="shrink-0 text-ink-faint" />
                  <span className="font-mono font-medium text-ink">{h.to}</span>
                  {h.via_qid != null && (
                    <span className="rounded-md border border-line bg-surface-2/80 px-1.5 py-px font-mono text-[10px] text-ink-muted">
                      QID {h.via_qid}
                    </span>
                  )}
                  {h.enabler && h.enabler !== "None" && (
                    <span className="rounded-md bg-attend/10 px-1.5 py-px font-mono text-[10px] text-attend">{h.enabler}</span>
                  )}
                  {expandable && (
                    <ChevronDown
                      size={12}
                      className={cx("ml-auto shrink-0 text-ink-faint transition-transform duration-200", open && "rotate-180")}
                    />
                  )}
                </button>

                {/* The agent's own justification for this hop */}
                {open && h.why && (
                  <p className="mb-1.5 mt-1 animate-row-in rounded-lg border-l-2 border-purple/40 bg-surface-2/60 py-1.5 pl-2.5 pr-2 text-[11px] leading-relaxed text-ink-muted">
                    {h.why}
                  </p>
                )}
              </li>
            );
          })}
        </ol>

        {/* Verification meter + blast radius */}
        <div className="mt-3.5 space-y-2.5 border-t border-line/70 pt-3">
          <div className="flex items-center gap-2.5">
            <div className="h-1 flex-1 overflow-hidden rounded-full bg-surface-3">
              <div
                className={cx(
                  "h-full rounded-full transition-[width] duration-700 ease-out",
                  d.grounded ? "bg-gradient-to-r from-sage to-sage-bright" : "bg-gradient-to-r from-act to-attend",
                )}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="shrink-0 font-mono text-[10px] tabular-nums text-ink-faint">
              {d.verified_hops}/{d.total_hops} hops verified
            </span>
          </div>
          {d.business_impact && (
            <div className="flex items-start gap-2 rounded-lg border border-immediate/15 bg-immediate/[0.05] px-2.5 py-2">
              <AlertTriangle size={13} className="mt-px shrink-0 text-immediate" />
              <p className="text-xs leading-relaxed text-ink-muted">
                <span className="font-semibold text-ink">Impact: </span>
                {d.business_impact}
              </p>
            </div>
          )}
        </div>
      </div>
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
