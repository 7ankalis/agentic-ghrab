import { useEffect, useRef, useState } from "react";
import { Bot, Send, Sparkles, User } from "lucide-react";
import { streamSSE } from "@/lib/api";
import { useKpis } from "@/lib/hooks";
import { cx } from "@/lib/format";
import { OfflineNotice, SectionTitle, useSpotlight } from "@/components/ui";

interface Msg { role: "user" | "assistant"; content: string; }

const PROMPTS = [
  "Trace the fastest path from the internet to the SWIFT gateway and name the choke point.",
  "Which findings are over-rated by CVSS but low real risk, and why?",
  "If I can only fix five things this week, what breaks the most attack paths?",
  "Which team owns the highest aggregate risk, and what should they do first?",
];

function TypingDots() {
  return (
    <span className="inline-flex items-center gap-1 py-1">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-sage-bright animate-typing-dot"
          style={{ animationDelay: `${i * 0.18}s` }}
        />
      ))}
    </span>
  );
}

function Avatar({ role }: { role: Msg["role"] }) {
  return (
    <span
      className={cx(
        "mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-xl border",
        role === "assistant"
          ? "border-sage/30 bg-gradient-to-br from-sage/20 to-forest-lit/10 text-sage-bright"
          : "border-line bg-surface-2 text-ink-muted",
      )}
    >
      {role === "assistant" ? <Bot size={15} /> : <User size={15} />}
    </span>
  );
}

export default function Analyst() {
  const { data: kpis } = useKpis();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const spotlight = useSpotlight();

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
              <div className="mb-1 flex items-center gap-2.5">
                <span className="grid h-10 w-10 place-items-center rounded-2xl border border-sage/30 bg-gradient-to-br from-sage/20 to-forest-lit/10 text-sage-bright shadow-glow animate-glow-breathe">
                  <Sparkles size={18} />
                </span>
                <div>
                  <div className="font-display font-semibold text-ink">Ask the analyst anything about your exposure.</div>
                  <div className="text-xs text-ink-faint">Streaming answers, grounded in this enterprise's live data.</div>
                </div>
              </div>
              <div className="mt-5 grid gap-2.5 sm:grid-cols-2">
                {PROMPTS.map((p, i) => (
                  <button
                    key={p}
                    onClick={() => ask(p)}
                    onMouseMove={spotlight}
                    style={{ animationDelay: `${120 + i * 60}ms` }}
                    className="spot rounded-xl border border-line bg-surface-2/60 p-4 text-left text-sm text-ink-muted transition-all duration-200 animate-fade-up hover:-translate-y-0.5 hover:border-sage/40 hover:text-ink hover:shadow-card"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m, i) => (
              <div
                key={i}
                className={cx(
                  "flex items-start gap-2.5 animate-row-in",
                  m.role === "user" ? "flex-row-reverse" : "flex-row",
                )}
              >
                <Avatar role={m.role} />
                <div
                  className={cx(
                    "max-w-[78%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm leading-relaxed",
                    m.role === "user"
                      ? "rounded-tr-md border border-sage/25 bg-sage/15 text-ink"
                      : "rounded-tl-md border border-line bg-surface-2 text-ink-muted",
                  )}
                >
                  {m.content || <TypingDots />}
                </div>
              </div>
            ))
          )}
        </div>
        <form
          onSubmit={(e) => { e.preventDefault(); ask(input); }}
          className="flex items-center gap-2 border-t border-line bg-surface/60 p-4 backdrop-blur"
        >
          <input
            className="input transition-shadow focus:shadow-glow"
            placeholder="Ask about attack paths, ownership, remediation priorities…"
            value={input}
            disabled={busy}
            onChange={(e) => setInput(e.target.value)}
          />
          <button type="submit" className="btn-primary" disabled={busy || !input.trim()}>
            <Send size={15} /> Send
          </button>
        </form>
      </div>
    </div>
  );
}
