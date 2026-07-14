import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, CheckCircle2, Circle, FileDown, GitBranch,
  LayoutDashboard, Loader2, MessageSquare, Moon, RefreshCw, Network, ScrollText,
  Settings as SettingsIcon, ShieldCheck, Sun, Terminal, Users, XCircle,
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
  return (
    <div className="fixed bottom-6 left-1/2 z-50 w-[460px] max-w-[90vw] -translate-x-1/2 animate-fade-up">
      <div className="card p-4 shadow-pop">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-ink">
          <Loader2 size={15} className="animate-spin text-sage-bright" />
          Running analysis pipeline
        </div>
        <div className="max-h-52 space-y-1.5 overflow-y-auto font-mono text-[11px]">
          {lines.map((l, i) => {
            const isActive = l.status === "active";
            const isError = l.level === "error";
            const isWarn = l.level === "warn";
            return (
              <div
                key={i}
                className={cx(
                  "flex items-start gap-2",
                  isActive ? "text-sage-bright" : isError ? "text-immediate" : isWarn ? "text-attend" : "text-ink-muted",
                )}
              >
                <span className="mt-[1px] shrink-0">
                  {isActive ? (
                    <Loader2 size={11} className="animate-spin" />
                  ) : isError ? (
                    <XCircle size={11} />
                  ) : isWarn ? (
                    <AlertTriangle size={11} />
                  ) : (
                    <CheckCircle2 size={11} />
                  )}
                </span>
                <span>{l.message}</span>
              </div>
            );
          })}
        </div>
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
  return (
    <button
      onClick={() => nav("/logs")}
      className="flex items-center gap-2 rounded-full border border-line bg-surface-2 px-3 py-1.5 text-xs text-ink-muted transition hover:border-line-strong hover:text-ink"
      title="View live agent activity log"
    >
      {active.length > 0 ? (
        <>
          <Loader2 size={12} className="animate-spin text-track2" />
          <span>{AGENT_LABELS[active[0].role] ?? active[0].role} → {active[0].provider}</span>
        </>
      ) : current ? (
        <>
          <span className={cx("h-1.5 w-1.5 rounded-full", current.event === "error" ? "bg-immediate" : "bg-sage-bright")} />
          <span>
            {AGENT_LABELS[current.role] ?? current.role} {current.event === "error" ? "failed" : "ready"}
          </span>
        </>
      ) : (
        <>
          <Circle size={10} className="text-ink-faint" />
          <span>No agent activity yet</span>
        </>
      )}
    </button>
  );
}
