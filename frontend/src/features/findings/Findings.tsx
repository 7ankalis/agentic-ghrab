import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  createColumnHelper, flexRender, getCoreRowModel, getSortedRowModel,
  useReactTable, type SortingState,
} from "@tanstack/react-table";
import { ArrowUpDown, Search, Zap } from "lucide-react";
import { useFindings } from "@/lib/hooks";
import { bandColor, cx } from "@/lib/format";
import { BandPill, ExportButton, SectionTitle, Skeleton } from "@/components/ui";
import { downloadCSV, timestamp } from "@/lib/report";
import { buildFindingsCSV } from "@/lib/reportBuilders";
import FindingDrawer from "./FindingDrawer";
import type { Finding } from "@/lib/types";

const col = createColumnHelper<Finding>();

export default function Findings() {
  const { data, isLoading } = useFindings();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<number | null>(null);
  const [sorting, setSorting] = useState<SortingState>([{ id: "grs", desc: true }]);
  const [search, setSearch] = useState("");
  const [band, setBand] = useState<string>(params.get("band") ?? "");
  const [team, setTeam] = useState<string>("");

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

  return (
    <div className="animate-fade-up">
      <SectionTitle
        sub={`${filtered.length} of ${findings.length} findings · click any row to inspect`}
        right={
          <ExportButton
            label="Export CSV"
            onClick={() => downloadCSV(`ghrab-voc-findings-${timestamp()}.csv`, buildFindingsCSV(filtered))}
          />
        }
      >
        Vulnerability Findings
      </SectionTitle>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
          <input className="input pl-9" placeholder="Search title, host, CVE, QID…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <select className="input w-auto" value={band} onChange={(e) => { setBand(e.target.value); setParams(e.target.value ? { band: e.target.value } : {}); }}>
          <option value="">All bands</option>
          {["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"].map((b) => <option key={b} value={b}>{b}</option>)}
        </select>
        <select className="input w-auto" value={team} onChange={(e) => setTeam(e.target.value)}>
          <option value="">All teams</option>
          {teams.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {isLoading ? (
        <Skeleton className="h-96" />
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                {table.getHeaderGroups().map((hg) => (
                  <tr key={hg.id} className="border-b border-line">
                    {hg.headers.map((h) => (
                      <th
                        key={h.id}
                        onClick={h.column.getToggleSortingHandler()}
                        className="cursor-pointer select-none px-4 py-3 text-[11px] font-semibold uppercase tracking-wide text-ink-faint hover:text-ink-muted"
                      >
                        <span className="inline-flex items-center gap-1">
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          {h.column.getIsSorted() ? (
                            <ArrowUpDown size={11} className="text-sage-bright" />
                          ) : null}
                        </span>
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => setSelected(r.original.qid)}
                    className="cursor-pointer border-b border-line/60 transition last:border-0 hover:bg-surface-2/70"
                  >
                    {r.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-4 py-2.5">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length === 0 && <div className="p-8 text-center text-sm text-ink-muted">No findings match the current filters.</div>}
        </div>
      )}

      <FindingDrawer qid={selected} onClose={() => { setSelected(null); if (params.get("qid")) setParams(band ? { band } : {}); }} />
    </div>
  );
}
