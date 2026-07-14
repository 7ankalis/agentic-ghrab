import { useEffect, useRef, useState } from "react";
import { Send, Sparkles } from "lucide-react";
import { streamSSE } from "@/lib/api";
import { useKpis } from "@/lib/hooks";
import { cx } from "@/lib/format";
import { OfflineNotice, SectionTitle } from "@/components/ui";

interface Msg { role: "user" | "assistant"; content: string; }

const PROMPTS = [
  "Trace the fastest path from the internet to the SWIFT gateway and name the choke point.",
  "Which findings are over-rated by CVSS but low real risk, and why?",
  "If I can only fix five things this week, what breaks the most attack paths?",
  "Which team owns the highest aggregate risk, and what should they do first?",
];

export default function Analyst() {
  const { data: kpis } = useKpis();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  async function ask(q: string) {
    if (!q.trim() || busy) return;
    const history = messages.map((m) => ({ role: m.role, content: m.content }));
    setMessages((m) => [...m, { role: "user", content: q }, { role: "assistant", content: "" }]);
    setInput("");
    setBusy(true);
    try {
      await streamSSE("/chat", { message: q, history }, (event, data) => {
        if (event === "token")
          setMessages((m) => {
            const copy = [...m];
            copy[copy.length - 1] = { role: "assistant", content: copy[copy.length - 1].content + data.text };
            return copy;
          });
      });
    } finally {
      setBusy(false);
    }
  }

  if (kpis && !kpis.ai_enabled)
    return (
      <div className="animate-fade-up space-y-4">
        <SectionTitle>AI Analyst</SectionTitle>
        <OfflineNotice what="The AI Analyst" />
      </div>
    );

  return (
    <div className="animate-fade-up">
      <SectionTitle sub="Grounded in the live findings table, CMDB, and discovered attack paths. Every answer cites real QIDs and hosts.">
        AI Analyst
      </SectionTitle>

      <div className="card flex h-[calc(100vh-220px)] flex-col overflow-hidden">
        <div ref={ref} className="flex-1 space-y-4 overflow-y-auto p-6">
          {messages.length === 0 ? (
            <div className="mx-auto max-w-2xl pt-8">
              <div className="mb-4 flex items-center gap-2 text-sage-bright">
                <Sparkles size={18} /> <span className="font-medium">Ask the analyst anything about your exposure.</span>
              </div>
              <div className="grid gap-2.5 sm:grid-cols-2">
                {PROMPTS.map((p) => (
                  <button
                    key={p}
                    onClick={() => ask(p)}
                    className="rounded-xl border border-line bg-surface-2/60 p-4 text-left text-sm text-ink-muted transition hover:border-sage/40 hover:text-ink"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m, i) => (
              <div key={i} className={cx("flex", m.role === "user" ? "justify-end" : "justify-start")}>
                <div
                  className={cx(
                    "max-w-[80%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm leading-relaxed",
                    m.role === "user" ? "bg-sage/15 text-ink" : "border border-line bg-surface-2 text-ink-muted",
                  )}
                >
                  {m.content || <span className="animate-pulse-dot text-ink-faint">▍</span>}
                </div>
              </div>
            ))
          )}
        </div>
        <form onSubmit={(e) => { e.preventDefault(); ask(input); }} className="flex items-center gap-2 border-t border-line p-4">
          <input className="input" placeholder="Ask about attack paths, ownership, remediation priorities…" value={input} disabled={busy} onChange={(e) => setInput(e.target.value)} />
          <button type="submit" className="btn-primary" disabled={busy || !input.trim()}>
            <Send size={15} /> Send
          </button>
        </form>
      </div>
    </div>
  );
}
