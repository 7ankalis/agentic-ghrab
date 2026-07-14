import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity, GitBranch, LayoutDashboard, Loader2, MessageSquare, RefreshCw,
  Network, ScrollText, Settings as SettingsIcon, ShieldCheck, Users,
} from "lucide-react";
import { streamSSE } from "@/lib/api";
import { useKpis } from "@/lib/hooks";
import { cx } from "@/lib/format";
import AiDock from "./AiDock";

const NAV = [
  { to: "/", label: "Command Center", icon: LayoutDashboard, end: true },
  { to: "/findings", label: "Findings", icon: ScrollText },
  { to: "/attack-paths", label: "Attack Paths", icon: GitBranch },
  { to: "/correlation", label: "Correlation", icon: Network },
  { to: "/teams", label: "Teams", icon: Users },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/analyst", label: "AI Analyst", icon: MessageSquare },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

export default function Layout() {
  const qc = useQueryClient();
  const { data: kpis } = useKpis();
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const aiOn = kpis?.ai_enabled ?? false;

  async function runAnalysis(force: boolean) {
    setRunning(true);
    setProgress([]);
    try {
      await streamSSE("/analyze", { force_refresh: force }, (event, data) => {
        if (event === "progress" || event === "done" || event === "error")
          setProgress((p) => [...p, data.message]);
      });
    } catch (e: any) {
      setProgress((p) => [...p, `Error: ${e.message}`]);
    } finally {
      await qc.invalidateQueries();
      setTimeout(() => setRunning(false), 700);
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

function ProgressOverlay({ lines }: { lines: string[] }) {
  return (
    <div className="fixed bottom-6 left-1/2 z-50 w-[440px] max-w-[90vw] -translate-x-1/2 animate-fade-up">
      <div className="card p-4 shadow-pop">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-ink">
          <Loader2 size={15} className="animate-spin text-sage-bright" />
          Running analysis pipeline
        </div>
        <div className="max-h-40 space-y-1 overflow-y-auto font-mono text-[11px] text-ink-muted">
          {lines.map((l, i) => (
            <div key={i} className={cx(i === lines.length - 1 && "text-sage-bright")}>
              › {l}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
