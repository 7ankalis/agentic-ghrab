import { BookMarked, FileWarning, ScrollText } from "lucide-react";
import { useCompliance } from "@/lib/hooks";
import { AiCard, ExportButton, OfflineNotice, SectionTitle, Skeleton, Tag } from "@/components/ui";
import { downloadMarkdown, timestamp } from "@/lib/report";
import { buildComplianceReport } from "@/lib/reportBuilders";

export default function Compliance() {
  const { data, isLoading } = useCompliance();
  if (isLoading) return <Skeleton className="h-96" />;
  const c = data?.compliance ?? {};
  if (!data?.ai_enabled || c.error) return <OfflineNotice what="The Compliance Agent" />;

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle
        sub="Regulatory posture across PCI DSS, SWIFT CSP, and EU DORA — gaps flagged, not certifications asserted."
        right={<ExportButton onClick={() => downloadMarkdown(`ghrab-voc-compliance-${timestamp()}.md`, buildComplianceReport(c))} />}
      >
        Compliance Posture
      </SectionTitle>

      {c.executive_summary && <AiCard label="Auditor Briefing">{c.executive_summary}</AiCard>}

      {c.frameworks_in_scope && (
        <div className="flex flex-wrap gap-2">
          {c.frameworks_in_scope.map((f, i) => (
            <span
              key={f}
              style={{ animationDelay: `${i * 60}ms` }}
              className="flex items-center gap-1.5 rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink transition-all duration-200 animate-row-in hover:-translate-y-0.5 hover:border-sage/40 hover:shadow-card"
            >
              <BookMarked size={14} className="text-sage-bright" /> {f}
            </span>
          ))}
        </div>
      )}

      {c.dora_overlay_note && (
        <div className="card flex items-start gap-3 p-4">
          <ScrollText size={18} className="mt-0.5 shrink-0 text-purple" />
          <div>
            <div className="text-sm font-semibold text-ink">DORA CIF Overlay</div>
            <p className="mt-0.5 text-sm text-ink-muted">{c.dora_overlay_note}</p>
          </div>
        </div>
      )}

      {c.key_gaps && c.key_gaps.length > 0 && (
        <div>
          <div className="mb-3 flex items-center gap-2 font-semibold text-ink">
            <FileWarning size={17} className="text-act" /> Key Gaps
          </div>
          <div className="space-y-3">
            {c.key_gaps.map((g, i) => (
              <div
                key={i}
                style={{ animationDelay: `${i * 70}ms` }}
                className="card relative overflow-hidden p-4 pl-5 transition-colors animate-row-in hover:border-act/35"
              >
                <span className="absolute inset-y-0 left-0 w-[3px] bg-gradient-to-b from-act/70 to-transparent" />
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <Tag color="rgb(var(--c-act))">{g.framework}</Tag>
                  {g.finding_refs?.map((q) => <Tag key={q}>QID {q}</Tag>)}
                </div>
                <p className="text-sm text-ink-muted">{g.gap_description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
