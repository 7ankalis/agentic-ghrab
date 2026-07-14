import { BookMarked, FileWarning, ScrollText } from "lucide-react";
import { useCompliance } from "@/lib/hooks";
import { AiCard, OfflineNotice, SectionTitle, Skeleton, Tag } from "@/components/ui";

export default function Compliance() {
  const { data, isLoading } = useCompliance();
  if (isLoading) return <Skeleton className="h-96" />;
  const c = data?.compliance ?? {};
  if (!data?.ai_enabled || c.error) return <OfflineNotice what="The Compliance Agent" />;

  return (
    <div className="animate-fade-up space-y-6">
      <SectionTitle sub="Regulatory posture across PCI DSS, SWIFT CSP, and EU DORA — gaps flagged, not certifications asserted.">
        Compliance Posture
      </SectionTitle>

      {c.executive_summary && <AiCard label="Auditor Briefing">{c.executive_summary}</AiCard>}

      {c.frameworks_in_scope && (
        <div className="flex flex-wrap gap-2">
          {c.frameworks_in_scope.map((f) => (
            <span key={f} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink">
              <BookMarked size={14} className="text-sage-bright" /> {f}
            </span>
          ))}
        </div>
      )}

      {c.dora_overlay_note && (
        <div className="card flex items-start gap-3 p-4">
          <ScrollText size={18} className="mt-0.5 shrink-0 text-[#c97bd8]" />
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
              <div key={i} className="card p-4">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <Tag color="#f7853a">{g.framework}</Tag>
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
