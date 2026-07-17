import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  createColumnHelper, flexRender, getCoreRowModel, getSortedRowModel,
  useReactTable, type SortingState,
} from "@tanstack/react-table";
import { ArrowUpDown, ChevronRight, RotateCcw, Search, Zap } from "lucide-react";
import { useFindings } from "@/lib/hooks";
import { BAND_META, BAND_ORDER, bandColor, cx } from "@/lib/format";
import { useToast } from "@/lib/toast";
import { BandPill, ExportButton, SectionTitle, Skeleton } from "@/components/ui";
import { downloadCSV, timestamp } from "@/lib/report";
import { buildFindingsCSV } from "@/lib/reportBuilders";
import FindingDrawer from "./FindingDrawer";
import type { Finding } from "@/lib/types";

const col = createColumnHelper<Finding>();

export default function Findings() {
  const { data, isLoading } = useFindings();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<number | null>(null);
  const [sorting, setSorting] = useState<SortingState>([{ id: "grs", desc: true }]);
  const [search, setSearch] = useState("");
  const [band, setBand] = useState<string>(params.get("band") ?? "");
  const [team, setTeam] = useState<string>("");
  // Keyboard cursor into the visible rows (-1 = nothing highlighted yet).
  const [activeRow, setActiveRow] = useState(-1);

  useEffect(() => {
    const qid = params.get("qid");
    if (qid) setSelected(Number(qid));
  }, [params]);

  const findings = data?.findings ?? [];
  const teams = useMemo(() => [...new Set(findings.map((f) => f.team))].sort(), [findings]);

  const filtered = useMemo(
    () =>
      findings.filter((f) => {
        if (band && f.band !== band) return false;
        if (team && f.team !== team) return false;
        if (search) {
          const s = search.toLowerCase();
          return (
            f.title.toLowerCase().includes(s) ||
            f.hostname.toLowerCase().includes(s) ||
            f.cve.toLowerCase().includes(s) ||
            String(f.qid).includes(s)
          );
        }
        return true;
      }),
    [findings, band, team, search],
  );

  const columns = useMemo(
    () => [
      col.accessor("grs", {
        header: "GRS",
        cell: (c) => {
          const f = c.row.original;
          return (
            <div className="flex items-center gap-2">
              <div className="relative h-1.5 w-12 overflow-hidden rounded-full bg-surface-3">
                <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${f.grs}%`, background: bandColor(f.band) }} />
              </div>
              <span className="font-mono text-sm font-semibold" style={{ color: bandColor(f.band) }}>{f.grs}</span>
            </div>
          );
        },
      }),
      col.accessor("band", { header: "Band", cell: (c) => <BandPill band={c.getValue()} /> }),
      col.accessor("title", {
        header: "Finding",
        cell: (c) => (
          <div className="max-w-md">
            <div className="truncate font-medium text-ink">{c.getValue()}</div>
            <div className="truncate text-xs text-ink-faint">{c.row.original.cve} · QID {c.row.original.qid}</div>
          </div>
        ),
      }),
      col.accessor("hostname", { header: "Asset", cell: (c) => <span className="text-sm text-ink-muted">{c.getValue()}</span> }),
      col.accessor("zone", { header: "Zone", cell: (c) => <span className="text-xs text-ink-faint">{c.getValue()}</span> }),
      col.accessor("team", { header: "Owner", cell: (c) => <span className="text-xs text-ink-muted">{c.getValue()}</span> }),
      col.accessor("cvss", { header: "CVSS", cell: (c) => <span className="font-mono text-sm text-ink-muted">{c.getValue()}</span> }),
      col.accessor("kev", {
        header: "KEV",
        cell: (c) => (c.getValue() ? <Zap size={14} className="text-act" /> : <span className="text-ink-faint">—</span>),
      }),
    ],
    [],
  );

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;
  const hasFilters = !!(search || band || team);

  // Refs so a single stable keydown listener always reads current values.
  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  const activeRef = useRef(activeRow);
  activeRef.current = activeRow;
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  // Reset the cursor whenever the visible set changes underfoot.
  useEffect(() => setActiveRow(-1), [band, team, search, sorting]);

  // ↑/↓ move the highlight, Enter opens it — the power-user path through a long
  // findings queue. Suppressed while typing in a filter or with the drawer open.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (selectedRef.current != null) return;
      const el = document.activeElement;
      if (el && /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) return;
      const rs = rowsRef.current;
      if (rs.length === 0) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveRow((i) => Math.min((i < 0 ? -1 : i) + 1, rs.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveRow((i) => Math.max((i < 0 ? rs.length : i) - 1, 0));
      } else if (e.key === "Enter") {
        const i = activeRef.current;
        if (i >= 0 && i < rs.length) {
          e.preventDefault();
          setSelected(rs[i].original.qid);
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Keep the highlighted row scrolled into view.
  useEffect(() => {
    if (activeRow < 0) return;
    document.querySelector(`[data-row="${activeRow}"]`)?.scrollIntoView({ block: "nearest" });
  }, [activeRow]);

  function resetFilters() {
    setSearch("");
    setBand("");
    setTeam("");
    setParams({});
  }

  function exportCsv() {
    downloadCSV(`ghrab-voc-findings-${timestamp()}.csv`, buildFindingsCSV(filtered));
    toast.success("Findings exported", `${filtered.length} row${filtered.length === 1 ? "" : "s"} saved as CSV.`);
  }

  return (
    <div className="animate-fade-up">
      <SectionTitle
        sub={`${filtered.length} of ${findings.length} findings · use ↑ ↓ to move, ↵ to inspect`}
        right={<ExportButton label="Export CSV" onClick={exportCsv} />}
      >
        Vulnerability Findings
      </SectionTitle>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
          <input className="input pl-9" placeholder="Search title, host, CVE, QID…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-line bg-surface-2/60 p-1">
          <button
            onClick={() => { setBand(""); setParams({}); }}
            className={cx(
              "rounded-md px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide transition-colors",
              band === "" ? "bg-surface text-ink shadow-card" : "text-ink-faint hover:text-ink-muted",
            )}
          >
            All
          </button>
          {BAND_ORDER.map((b) => {
            const active = band === b;
            const c = bandColor(b);
            return (
              <button
                key={b}
                onClick={() => {
                  const next = active ? "" : b;
                  setBand(next);
                  setParams(next ? { band: next } : {});
                }}
                title={`${BAND_META[b].label} · SLA ${BAND_META[b].text}`}
                className={cx(
                  "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide transition-all",
                  active ? "shadow-card" : "text-ink-faint hover:text-ink-muted",
                )}
                style={active ? { background: `color-mix(in srgb, ${c} 14%, rgb(var(--c-surface)))`, color: c } : undefined}
              >
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: c, opacity: active ? 1 : 0.45 }} />
                {BAND_META[b].label}
              </button>
            );
          })}
        </div>
        <select className="input w-auto" value={team} onChange={(e) => setTeam(e.target.value)}>
          <option value="">All teams</option>
          {teams.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        {hasFilters && (
          <button onClick={resetFilters} className="btn-ghost !px-3 !py-1.5 text-xs">
            <RotateCcw size={12} /> Reset
          </button>
        )}
      </div>

      {isLoading ? (
        <Skeleton className="h-96" />
      ) : (
        <div className="card overflow-hidden">
          <div className="max-h-[calc(100vh-290px)] min-h-[280px] overflow-auto">
            <table className="w-full text-left">
              <thead className="sticky top-0 z-10 bg-surface">
                {table.getHeaderGroups().map((hg) => (
                  <tr key={hg.id} className="border-b border-line">
                    {hg.headers.map((h) => (
                      <th
                        key={h.id}
                        onClick={h.column.getToggleSortingHandler()}
                        className="cursor-pointer select-none whitespace-nowrap px-4 py-3 text-[11px] font-semibold uppercase tracking-wide text-ink-faint hover:text-ink-muted"
                      >
                        <span className="inline-flex items-center gap-1">
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          {h.column.getIsSorted() ? (
                            <ArrowUpDown size={11} className="text-sage-bright" />
                          ) : null}
                        </span>
                      </th>
                    ))}
                    <th className="w-8 bg-surface" />
                  </tr>
                ))}
              </thead>
              <tbody>
                {rows.map((r, i) => {
                  const isActive = i === activeRow;
                  return (
                    <tr
                      key={r.id}
                      data-row={i}
                      onClick={() => setSelected(r.original.qid)}
                      onMouseEnter={() => setActiveRow(i)}
                      style={{ animationDelay: `${Math.min(i, 14) * 22}ms` }}
                      className={cx(
                        "group cursor-pointer border-b border-line/60 transition-colors last:border-0 animate-row-in",
                        isActive ? "bg-sage/[0.07]" : "hover:bg-surface-2/70",
                      )}
                    >
                      {r.getVisibleCells().map((cell) => (
                        <td key={cell.id} className="px-4 py-2.5">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                      ))}
                      <td className="w-8 pr-3 text-right">
                        <ChevronRight
                          size={15}
                          className={cx(
                            "inline-block text-sage-bright transition-all",
                            isActive ? "translate-x-0 opacity-100" : "-translate-x-1 opacity-0 group-hover:translate-x-0 group-hover:opacity-60",
                          )}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {filtered.length === 0 && (
            <div className="p-8 text-center text-sm text-ink-muted">
              No findings match the current filters.
            </div>
          )}
        </div>
      )}

      <FindingDrawer qid={selected} onClose={() => { setSelected(null); if (params.get("qid")) setParams(band ? { band } : {}); }} />
    </div>
  );
}
