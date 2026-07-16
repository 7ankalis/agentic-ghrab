import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Building2, CheckCircle2, FileText, Loader2, ScrollText, X,
} from "lucide-react";
import { api } from "@/lib/api";
import { useDatasets } from "@/lib/hooks";
import { cx } from "@/lib/format";
import { useToast } from "@/lib/toast";

/**
 * Enterprise picker — the operator's "hand" over which company gets scanned.
 * Lists every scannable enterprise the backend found in its data dir (each is a
 * `<name>_vulnerabilities.csv` + `<name>_architecture.md` pair) and, on select,
 * flips the active dataset server-side then invalidates every query so the whole
 * SPA reloads against the newly chosen enterprise. The operator then runs the
 * pipeline from the usual Full Analysis / Re-run controls.
 */
export default function DatasetPicker({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const { data, isLoading } = useDatasets();
  const [switching, setSwitching] = useState<string | null>(null);

  // Escape closes the picker — parity with the command palette and drawers.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  async function select(key: string, active: boolean, name: string) {
    if (active || switching) return;
    setSwitching(key);
    try {
      await api.selectDataset(key);
      // The active enterprise changed under the whole app — drop every cached
      // query (findings, graph, kpis, runs, …) so each view refetches fresh.
      await qc.invalidateQueries();
      toast.success(`Switched to ${name}`, "Run the analysis to populate this enterprise.");
      onClose();
    } catch (e: any) {
      toast.error("Could not switch enterprise", e?.message ?? "Try again.");
    } finally {
      setSwitching(null);
    }
  }

  const datasets = data?.datasets ?? [];

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-base/60 px-4 pt-[12vh] backdrop-blur-sm animate-overlay-in"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Select enterprise to scan"
        className="card w-full max-w-[620px] overflow-hidden border-line-strong shadow-pop animate-cmd-in"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-3 border-b border-line px-5 py-4">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-sage to-forest-lit shadow-glow">
            <Building2 size={17} className="text-forest" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold text-ink">Select enterprise to scan</div>
            <p className="mt-0.5 text-[12px] text-ink-faint">
              Each enterprise is a vulnerabilities export + architecture doc in the data
              directory. Pick one, then run the analysis.
            </p>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded-md p-1 text-ink-faint transition hover:bg-surface-2 hover:text-ink"
            title="Close"
          >
            <X size={16} />
          </button>
        </div>

        <div className="max-h-[56vh] space-y-2 overflow-y-auto p-4">
          {isLoading ? (
            <div className="flex items-center justify-center gap-2 py-12 text-sm text-ink-faint">
              <Loader2 size={15} className="animate-spin" /> Scanning data directory…
            </div>
          ) : datasets.length === 0 ? (
            <div className="px-3 py-12 text-center text-sm text-ink-faint">
              No scannable enterprises found. Drop a matching
              <span className="font-mono text-ink-muted"> name_vulnerabilities.csv </span>
              +<span className="font-mono text-ink-muted"> name_architecture.md </span>
              pair into the backend data directory.
            </div>
          ) : (
            datasets.map((d) => {
              const isSwitching = switching === d.key;
              return (
                <button
                  key={d.key}
                  onClick={() => select(d.key, d.active, d.name)}
                  disabled={switching !== null}
                  className={cx(
                    "group flex w-full items-center gap-4 rounded-xl border px-4 py-3 text-left transition-all",
                    d.active
                      ? "border-sage/40 bg-sage/10 shadow-[inset_0_0_0_1px_rgba(85,161,133,0.2)]"
                      : "border-line bg-surface-2/50 hover:border-line-strong hover:bg-surface-2",
                    switching !== null && !isSwitching && "opacity-50",
                  )}
                >
                  <div
                    className={cx(
                      "grid h-10 w-10 shrink-0 place-items-center rounded-lg border transition-colors",
                      d.active
                        ? "border-sage/30 bg-sage/15 text-sage-bright"
                        : "border-line bg-surface text-ink-faint group-hover:text-ink-muted",
                    )}
                  >
                    <Building2 size={18} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-semibold text-ink">{d.name}</span>
                      <span className="shrink-0 font-mono text-[10px] uppercase tracking-wide text-ink-faint">
                        {d.key}
                      </span>
                    </div>
                    <div className="mt-0.5 truncate text-[12px] text-ink-faint">{d.sector}</div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-faint">
                      <span className="inline-flex items-center gap-1">
                        <ScrollText size={11} /> {d.findings} findings
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <FileText size={11} /> {d.frameworks}
                      </span>
                    </div>
                  </div>
                  <div className="shrink-0">
                    {isSwitching ? (
                      <Loader2 size={17} className="animate-spin text-sage-bright" />
                    ) : d.active ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-sage/30 bg-sage/15 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide text-sage-bright">
                        <CheckCircle2 size={12} /> Active
                      </span>
                    ) : (
                      <span className="text-[11px] font-medium text-ink-faint opacity-0 transition-opacity group-hover:opacity-100">
                        Select →
                      </span>
                    )}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
