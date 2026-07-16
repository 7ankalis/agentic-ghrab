import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, Circle,
  Database, FileDown, FileText, GitBranch, LayoutDashboard, Loader2,
  MessageSquare, Moon, RefreshCw, Network, ScrollText, Settings as SettingsIcon,
  ShieldCheck, Share2, Sparkles, Sun, Tags, Terminal, Users, XCircle, Zap,
} from "lucide-react";
import { api, streamSSE } from "@/lib/api";
import { useAgentLog } from "@/lib/agentLog";
import { useKpis } from "@/lib/hooks";
import { useTheme } from "@/lib/theme";
import { AGENT_LABELS, cx } from "@/lib/format";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildFullReport } from "@/lib/reportBuilders";
import AiDock from "./AiDock";

const NAV = [
  { to: "/", label: "Command Center", icon: LayoutDashboard, end: true },
  { to: "/findings", label: "Findings", icon: ScrollText },
  { to: "/attack-paths", label: "Attack Paths", icon: GitBranch },
  { to: "/correlation", label: "Correlation", icon: Network },
  { to: "/teams", label: "Teams", icon: Users },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/analyst", label: "AI Analyst", icon: MessageSquare },
  { to: "/logs", label: "Agent Logs", icon: Terminal },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

type Level = "info" | "warn" | "error";
type StageStatus = "active" | "done";
interface ProgressLine { message: string; level: Level; status: StageStatus; }

// Ordered milestones the backend orchestrator reports, used to drive a real
// progress bar. Deterministic-mode runs skip straight from "discover paths"
// to "complete", which is intentional — those stages genuinely didn't run.
const CORE_STAGES: RegExp[] = [
  /ingesting vulnerability/i,
  /parsing enterprise cmdb/i,
  /classifying findings/i,
  /discovering attack paths/i,
  /discovery agent/i,
  /correlation agent/i,
  /compliance agent/i,
  /triage agent/i,
  /analysis complete/i,
];

const STAGE_ICONS: { test: RegExp; icon: typeof Database }[] = [
  { test: /ingesting vulnerability/i, icon: Database },
  { test: /parsing enterprise cmdb/i, icon: Network },
  { test: /classifying findings/i, icon: Tags },
  { test: /discovering attack paths/i, icon: GitBranch },
  { test: /cached ai enrichment/i, icon: Zap },
  { test: /discovery agent/i, icon: Sparkles },
  { test: /correlation agent/i, icon: Share2 },
  { test: /compliance agent/i, icon: ShieldCheck },
  { test: /triage agent/i, icon: FileText },
  { test: /analysis complete/i, icon: CheckCircle2 },
];

function iconForStage(message: string) {
  return STAGE_ICONS.find((s) => s.test.test(message))?.icon ?? Circle;
}

function formatElapsed(ms: number): string {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export default function Layout() {
  const qc = useQueryClient();
  const { data: kpis } = useKpis();
  const [running, setRunning] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [progress, setProgress] = useState<ProgressLine[]>([]);
  const aiOn = kpis?.ai_enabled ?? false;

  function settlePrior(lines: ProgressLine[]): ProgressLine[] {
    return lines.map((l) => (l.status === "active" ? { ...l, status: "done" } : l));
  }

  // A run kicked off before a reload keeps going server-side (it's not tied
  // to any one SSE connection's lifetime) — check once on mount so a
  // reloaded tab can reattach to it instead of showing nothing until the
  // user clicks a button again, mismatched against what's actually running.
  const bootstrapped = useRef(false);
  useEffect(() => {
    if (bootstrapped.current) return;
    bootstrapped.current = true;
    api
      .analyzeStatus()
      .then((s) => {
        if (s.running) runAnalysis(false);
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runAnalysis(force: boolean) {
    setRunning(true);
    setProgress([]);
    try {
      await streamSSE("/analyze", { force_refresh: force }, (event, data) => {
        if (event === "progress") {
          const level: Level = data.level ?? "info";
          setProgress((p) => [...settlePrior(p), { message: data.message, level, status: "active" }]);
        } else if (event === "done") {
          setProgress((p) => settlePrior(p));
        } else if (event === "error") {
          setProgress((p) => [...settlePrior(p), { message: data.message, level: "error", status: "done" }]);
        }
      });
    } catch (e: any) {
      setProgress((p) => [...settlePrior(p), { message: `Error: ${e.message}`, level: "error", status: "done" }]);
    } finally {
      await qc.invalidateQueries();
      setTimeout(() => setRunning(false), 900);
    }
  }

  async function exportFullReport() {
    setExporting(true);
    try {
      const [overview, findingsRes, attackPaths, correlationRes, teamsRes, complianceRes] = await Promise.all([
        api.overview(), api.findings(), api.attackPaths(), api.correlation(), api.teams(), api.compliance(),
      ]);
      const md = buildFullReport({
        overview,
        findings: findingsRes.findings,
        attackPaths,
        correlation: correlationRes.correlation,
        teams: teamsRes.teams,
        compliance: complianceRes.compliance,
      });
      downloadMarkdown(`ghrab-voc-full-report-${timestamp()}.md`, md);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-line bg-surface/70 backdrop-blur-xl">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-sage to-forest-lit shadow-glow">
            <Activity size={18} className="text-forest" />
          </div>
          <div className="leading-tight">
            <div className="font-display text-[15px] font-bold tracking-wide text-ink">GHRAB</div>
            <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-faint">
              VOC
            </div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-2">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx(
                  "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition",
                  isActive
                    ? "bg-sage/12 text-ink shadow-[inset_0_0_0_1px_rgba(85,161,133,0.25)]"
                    : "text-ink-muted hover:bg-surface-2 hover:text-ink",
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon size={17} className={cx(isActive ? "text-sage-bright" : "text-ink-faint group-hover:text-ink-muted")} />
                  {label}
                </>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-line px-5 py-4">
          <div className="flex items-center gap-2 text-xs">
            <span
              className={cx(
                "h-2 w-2 rounded-full",
                aiOn ? "bg-sage-bright animate-pulse-dot" : "bg-ink-faint",
              )}
            />
            <span className="text-ink-muted">{aiOn ? "AI layer connected" : "Deterministic mode"}</span>
          </div>
          <ThemeToggle />
        </div>
      </aside>

      {/* Main */}
      <div className="ml-60 flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center justify-between border-b border-line bg-base/70 px-8 py-3.5 backdrop-blur-xl">
          <div>
            <h1 className="font-display text-base font-semibold text-ink">
              Vulnerability Operations Center
            </h1>
            <p className="text-xs text-ink-faint">
              Ghrab Financial Group · {kpis ? `${kpis.total} findings · ${kpis.discovered_paths} attack paths discovered` : "loading…"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <AgentActivityPill />
            <button className="btn-ghost" onClick={exportFullReport} disabled={exporting}>
              {exporting ? <Loader2 size={15} className="animate-spin" /> : <FileDown size={15} />}
              Full Report
            </button>
            <button className="btn-ghost" onClick={() => runAnalysis(false)} disabled={running}>
              {running ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />}
              Re-run
            </button>
            <button className="btn-primary" onClick={() => runAnalysis(true)} disabled={running}>
              {running ? <Loader2 size={15} className="animate-spin" /> : <Activity size={15} />}
              Full Analysis
            </button>
          </div>
        </header>

        <main className="flex-1 px-8 py-7">
          <div className="mx-auto max-w-[1400px]">
            <Outlet />
          </div>
        </main>
      </div>

      {running && <ProgressOverlay lines={progress} />}
      <AiDock aiOn={aiOn} />
    </div>
  );
}

function ProgressOverlay({ lines }: { lines: ProgressLine[] }) {
  const [collapsed, setCollapsed] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const start = Date.now();
    const id = setInterval(() => setElapsed(Date.now() - start), 250);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [lines.length, collapsed]);

  const hasError = lines.some((l) => l.level === "error");
  const stageIndex = CORE_STAGES.reduce(
    (acc, re, i) => (lines.some((l) => re.test(l.message)) ? i : acc),
    -1,
  );
  const isComplete = /analysis complete/i.test(lines[lines.length - 1]?.message ?? "");
  const pct = Math.max(4, Math.min(100, Math.round(((stageIndex + 1) / CORE_STAGES.length) * 100)));
  const activeLine = [...lines].reverse().find((l) => l.status === "active");

  return (
    <div className="fixed bottom-6 left-1/2 z-50 w-[520px] max-w-[92vw] -translate-x-1/2 animate-pop-in">
      <div
        className={cx(
          "card overflow-hidden shadow-pop",
          hasError ? "border-immediate/40" : "border-line-strong",
        )}
      >
        {/* scanning progress hairline */}
        <div className="relative h-[2px] w-full overflow-hidden bg-surface-2">
          <div
            className={cx(
              "absolute inset-y-0 h-full w-1/4 rounded-full blur-[1px]",
              hasError
                ? "bg-gradient-to-r from-transparent via-immediate to-transparent"
                : "bg-gradient-to-r from-transparent via-sage-bright to-transparent",
              !isComplete && "animate-scan-x",
            )}
          />
        </div>

        {/* header */}
        <div className="flex items-center gap-3 px-4 pt-3.5 pb-2.5">
          <div
            className={cx(
              "grid h-9 w-9 shrink-0 place-items-center rounded-xl transition-colors",
              hasError
                ? "bg-immediate/15"
                : isComplete
                ? "bg-sage/20"
                : "bg-gradient-to-br from-sage to-forest-lit shadow-glow",
            )}
          >
            {hasError ? (
              <AlertTriangle size={16} className="text-immediate" />
            ) : isComplete ? (
              <CheckCircle2 size={16} className="text-sage-bright" />
            ) : (
              <Loader2 size={16} className="animate-spin text-forest" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold text-ink">
                {hasError ? "Pipeline hit a snag" : isComplete ? "Analysis complete" : "Running analysis pipeline"}
              </span>
              <span className="shrink-0 font-mono text-[11px] tabular-nums text-ink-faint">
                {formatElapsed(elapsed)}
              </span>
            </div>
            <div className="mt-0.5 truncate text-[11px] text-ink-faint">
              {activeLine?.message ?? lines[lines.length - 1]?.message ?? "Warming up…"}
            </div>
          </div>
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="shrink-0 rounded-md p-1 text-ink-faint transition hover:bg-surface-2 hover:text-ink"
            title={collapsed ? "Expand log" : "Collapse log"}
          >
            {collapsed ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </button>
        </div>

        {/* progress bar */}
        <div className="px-4">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
            <div
              className={cx(
                "h-full rounded-full transition-[width] duration-700 ease-out",
                hasError ? "bg-immediate" : "bg-gradient-to-r from-sage to-sage-bright",
              )}
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="mb-3 mt-1.5 flex items-center justify-between text-[10px] font-medium uppercase tracking-wide text-ink-faint">
            <span>Stage {Math.max(1, Math.min(stageIndex + 1, CORE_STAGES.length))} of {CORE_STAGES.length}</span>
            <span className="tabular-nums">{pct}%</span>
          </div>
        </div>

        {/* stepper log */}
        {!collapsed && (
          <div
            ref={scrollRef}
            className="max-h-56 space-y-0.5 overflow-y-auto border-t border-line px-2.5 py-2.5 font-mono text-[11px]"
          >
            {lines.map((l, i) => {
              const isActive = l.status === "active";
              const isError = l.level === "error";
              const isWarn = l.level === "warn";
              const StatusIcon = isActive ? Loader2 : isError ? XCircle : isWarn ? AlertTriangle : CheckCircle2;
              const StageIcon = iconForStage(l.message);
              return (
                <div
                  key={i}
                  className={cx(
                    "flex items-start gap-2 rounded-md px-2 py-1.5 transition-colors animate-fade-up",
                    isActive && "bg-sage/8",
                  )}
                >
                  <span
                    className={cx(
                      "mt-[1px] grid h-4 w-4 shrink-0 place-items-center rounded-full",
                      isActive
                        ? "text-sage-bright"
                        : isError
                        ? "text-immediate"
                        : isWarn
                        ? "text-attend"
                        : "text-sage/70",
                    )}
                  >
                    <StatusIcon size={12} className={isActive ? "animate-spin" : ""} />
                  </span>
                  <StageIcon size={11} className="mt-[3px] shrink-0 text-ink-faint/60" />
                  <span
                    className={cx(
                      "leading-relaxed",
                      isActive
                        ? "text-ink"
                        : isError
                        ? "text-immediate"
                        : isWarn
                        ? "text-attend"
                        : "text-ink-muted",
                    )}
                  >
                    {l.message}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function ThemeToggle() {
  const [theme, toggle] = useTheme();
  const isDark = theme === "dark";
  return (
    <button
      onClick={toggle}
      className="mt-3 flex w-full items-center justify-between rounded-lg border border-line bg-surface-2 px-3 py-2 text-xs font-medium text-ink-muted transition hover:border-line-strong hover:text-ink"
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
    >
      <span className="flex items-center gap-2">
        {isDark ? <Moon size={14} /> : <Sun size={14} />}
        {isDark ? "Dark theme" : "Light theme"}
      </span>
      <span
        className={cx(
          "relative h-4 w-8 rounded-full transition",
          isDark ? "bg-sage" : "bg-surface-3",
        )}
      >
        <span
          className={cx(
            "absolute top-0.5 h-3 w-3 rounded-full bg-surface shadow-sm transition-transform",
            isDark ? "translate-x-4" : "translate-x-0.5",
          )}
        />
      </span>
    </button>
  );
}

function AgentActivityPill() {
  const { active, entries } = useAgentLog();
  const nav = useNavigate();
  const current = active[0] ?? entries[0];
  const isActive = active.length > 0;
  const isError = !isActive && current?.event === "error";

  return (
    <button
      onClick={() => nav("/logs")}
      className={cx(
        "group relative flex items-center gap-2 overflow-hidden rounded-full border px-3 py-1.5 text-xs transition-all",
        isActive
          ? "border-sage/40 bg-sage/10 text-ink shadow-glow"
          : isError
          ? "border-immediate/30 bg-immediate/10 text-ink"
          : "border-line bg-surface-2 text-ink-muted hover:border-line-strong hover:text-ink",
      )}
      title="View live agent activity log"
    >
      {isActive && (
        <span className="pointer-events-none absolute inset-y-0 left-0 w-1/3 animate-scan-x bg-gradient-to-r from-transparent via-sage-bright/20 to-transparent" />
      )}
      <span
        className={cx(
          "relative grid h-4 w-4 shrink-0 place-items-center rounded-full",
          isActive ? "bg-sage-bright/20" : isError ? "bg-immediate/20" : "bg-surface-3",
        )}
      >
        {isActive ? (
          <Loader2 size={10} className="animate-spin text-sage-bright" />
        ) : isError ? (
          <XCircle size={10} className="text-immediate" />
        ) : current ? (
          <span className="h-1.5 w-1.5 rounded-full bg-sage-bright animate-ring-pulse" />
        ) : (
          <Circle size={9} className="text-ink-faint" />
        )}
      </span>
      <span className="relative font-medium">
        {isActive
          ? `${AGENT_LABELS[active[0].role] ?? active[0].role} → ${active[0].provider}`
          : current
          ? `${AGENT_LABELS[current.role] ?? current.role} ${isError ? "failed" : "ready"}`
          : "No agent activity yet"}
      </span>
    </button>
  );
}
