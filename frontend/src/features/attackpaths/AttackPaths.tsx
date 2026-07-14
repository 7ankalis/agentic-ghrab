import { useState } from "react";
import { ReactFlowProvider } from "reactflow";
import { ChevronRight, Pause, Play, RotateCcw, Skull } from "lucide-react";
import { useAttackPaths, useGraph } from "@/lib/hooks";
import { EDGE_META, confidenceColor, cx } from "@/lib/format";
import { AiBadge, AiCard, ExportButton, SectionTitle, Skeleton, Tag } from "@/components/ui";
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

  if (lp || lg || !paths || !graph)
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-72" />
        <div className="grid grid-cols-[360px_1fr] gap-4"><Skeleton className="h-[560px]" /><Skeleton className="h-[560px]" /></div>
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

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[360px_1fr]">
        {/* Ranked path list */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between px-1">
            <span className="label">{paths.paths.length} Discovered Paths</span>
            <span className="text-[11px] text-ink-faint">ranked by risk</span>
          </div>
          <div className="max-h-[560px] space-y-2.5 overflow-y-auto pr-1">
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
        </div>

        {/* Graph canvas */}
        <div className="relative h-[560px] overflow-hidden rounded-2xl border border-line bg-surface/40">
          <ReactFlowProvider>
            <AttackGraph graph={graph} selected={selected} replayStep={replay} />
          </ReactFlowProvider>

          {selected && (
            <ReplayControls
              steps={selected.steps.length}
              replay={replay}
              setReplay={setReplay}
              onClose={() => select(null)}
              label={`${selected.entry} → ${selected.target}`}
            />
          )}
          {!selected && (
            <div className="pointer-events-none absolute bottom-4 left-4 rounded-lg border border-line bg-surface-2/90 px-3 py-2 text-xs text-ink-muted backdrop-blur">
              Full attack surface · select a path to trace it
            </div>
          )}
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

function ReplayControls({
  steps, replay, setReplay, onClose, label,
}: {
  steps: number; replay: number; setReplay: (n: number) => void; onClose: () => void; label: string;
}) {
  const [playing, setPlaying] = useState(false);

  function play() {
    setPlaying(true);
    let i = 0;
    setReplay(0);
    const timer = setInterval(() => {
      i += 1;
      if (i >= steps) {
        clearInterval(timer);
        setPlaying(false);
        setReplay(-1);
      } else setReplay(i);
    }, 900);
  }

  return (
    <div className="absolute bottom-4 left-1/2 flex -translate-x-1/2 items-center gap-2 rounded-xl border border-line-strong bg-surface-2/95 px-3 py-2 shadow-pop backdrop-blur">
      <button
        onClick={() => (playing ? setPlaying(false) : play())}
        className="grid h-8 w-8 place-items-center rounded-lg bg-sage text-forest transition hover:bg-sage-bright"
      >
        {playing ? <Pause size={15} /> : <Play size={15} />}
      </button>
      <button onClick={() => setReplay(-1)} className="grid h-8 w-8 place-items-center rounded-lg border border-line text-ink-muted hover:text-ink">
        <RotateCcw size={14} />
      </button>
      <span className="px-1 text-xs font-medium text-ink">{label}</span>
      <button onClick={onClose} className="ml-1 text-xs text-ink-faint hover:text-ink">clear</button>
    </div>
  );
}
