import { AlertTriangle, Lightbulb, Users } from "lucide-react";
import { useCorrelation } from "@/lib/hooks";
import { ExportButton, OfflineNotice, SectionTitle, Skeleton, Tag } from "@/components/ui";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildCorrelationReport } from "@/lib/reportBuilders";

export default function Correlation() {
  const { data, isLoading } = useCorrelation();
  if (isLoading) return <Skeleton className="h-96" />;
  const c = data?.correlation ?? {};
  if (!data?.ai_enabled || c.error) return <OfflineNotice what="The Correlation Agent" />;

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle
        sub="Risk that isn't captured by any single finding — shared assets, credentials, and ownership the engine cross-references."
        right={<ExportButton onClick={() => downloadMarkdown(`ghrab-voc-correlation-${timestamp()}.md`, buildCorrelationReport(c))} />}
      >
        Correlation & Toxic Combinations
      </SectionTitle>

      {c.cross_findings_insights && c.cross_findings_insights.length > 0 && (
        <div className="card p-5">
          <div className="mb-3 flex items-center gap-2 font-semibold text-ink">
            <Lightbulb size={17} className="text-sage-bright" /> Cross-Finding Insights
          </div>
          <ul className="space-y-2.5">
            {c.cross_findings_insights.map((ins, i) => (
              <li
                key={i}
                style={{ animationDelay: `${i * 70}ms` }}
                className="flex gap-2.5 rounded-lg p-1.5 text-sm text-ink-muted transition-colors animate-row-in hover:bg-surface-2/60"
              >
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-sage" />
                {ins}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {c.top_risk_teams && (
          <div className="card p-5">
            <div className="mb-3 flex items-center gap-2 font-semibold text-ink">
              <Users size={17} className="text-sage-bright" /> Top Risk-Owning Teams
            </div>
            <div className="space-y-3">
              {c.top_risk_teams.map((t, i) => (
                <div
                  key={i}
                  style={{ animationDelay: `${i * 70}ms` }}
                  className="rounded-lg border border-line bg-surface-2/60 p-3 transition-colors animate-row-in hover:border-sage/35"
                >
                  <div className="flex items-center gap-2">
                    <span className="grid h-5 w-5 place-items-center rounded-md bg-sage/12 font-mono text-[10px] font-bold text-sage-bright">
                      {i + 1}
                    </span>
                    <span className="text-sm font-semibold text-ink">{t.team}</span>
                  </div>
                  <p className="mt-1 text-sm text-ink-muted">{t.rationale}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {c.reprioritization_flags && (
          <div className="card p-5">
            <div className="mb-3 flex items-center gap-2 font-semibold text-ink">
              <AlertTriangle size={17} className="text-act" /> Reprioritization Flags
            </div>
            {c.reprioritization_flags.length === 0 ? (
              <p className="text-sm text-ink-faint">No reprioritization flags raised this run.</p>
            ) : (
              <div className="space-y-2.5">
                {c.reprioritization_flags.map((f, i) => (
                  <div
                    key={i}
                    style={{ animationDelay: `${i * 70}ms` }}
                    className="rounded-lg border border-line bg-surface-2/60 p-3 text-sm transition-colors animate-row-in hover:border-act/40"
                  >
                    <div className="mb-1 flex items-center gap-2">
                      <Tag color="rgb(var(--c-act))">QID {f.qid}</Tag>
                      <span className="text-ink-faint">{f.hostname}</span>
                    </div>
                    <p className="text-ink-muted">{f.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
