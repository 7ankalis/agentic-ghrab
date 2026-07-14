import { useEffect, useRef, useState } from "react";
import { MessageSquare, Send, Sparkles, X } from "lucide-react";
import { streamSSE } from "@/lib/api";
import { cx } from "@/lib/format";

interface Msg {
  role: "user" | "assistant";
  content: string;
}

const SUGGESTIONS = [
  "What's the fastest path to the SWIFT gateway?",
  "Which team owns the most critical risk?",
  "Explain the Zerologon finding's blast radius.",
];

export default function AiDock({ aiOn }: { aiOn: boolean }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, open]);

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
            copy[copy.length - 1] = {
              role: "assistant",
              content: copy[copy.length - 1].content + data.text,
            };
            return copy;
          });
      });
    } catch (e: any) {
      setMessages((m) => {
        const copy = [...m];
        copy[copy.length - 1] = { role: "assistant", content: `Error: ${e.message}` };
        return copy;
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        onClick={() => setOpen((o) => !o)}
        className={cx(
          "fixed bottom-6 right-6 z-40 flex items-center gap-2 rounded-full px-5 py-3 text-sm font-semibold shadow-pop transition",
          "bg-gradient-to-br from-sage to-forest-lit text-forest hover:shadow-glow",
        )}
      >
        {open ? <X size={17} /> : <Sparkles size={17} />}
        {open ? "Close" : "Ask the Analyst"}
      </button>

      {open && (
        <div className="fixed bottom-24 right-6 z-40 flex h-[560px] w-[420px] max-w-[92vw] flex-col overflow-hidden rounded-2xl border border-line-strong bg-surface/95 shadow-pop backdrop-blur-xl animate-fade-up">
          <div className="flex items-center gap-2 border-b border-line px-4 py-3">
            <MessageSquare size={16} className="text-sage-bright" />
            <div className="text-sm font-semibold text-ink">AI Analyst</div>
            <span className="ml-auto text-[11px] text-ink-faint">grounded in live findings + CMDB</span>
          </div>

          <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
            {messages.length === 0 && (
              <div className="space-y-3 pt-4">
                <p className="text-sm text-ink-muted">
                  {aiOn
                    ? "Ask about attack paths, ownership, or compliance scope. Every answer cites real QIDs and hosts."
                    : "No AI provider connected — add a key in Settings to enable the analyst."}
                </p>
                {aiOn &&
                  SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      onClick={() => ask(s)}
                      className="block w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-left text-sm text-ink-muted transition hover:border-sage/40 hover:text-ink"
                    >
                      {s}
                    </button>
                  ))}
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={cx("flex", m.role === "user" ? "justify-end" : "justify-start")}>
                <div
                  className={cx(
                    "max-w-[85%] whitespace-pre-wrap rounded-xl px-3 py-2 text-sm leading-relaxed",
                    m.role === "user"
                      ? "bg-sage/15 text-ink"
                      : "border border-line bg-surface-2 text-ink-muted",
                  )}
                >
                  {m.content || <span className="animate-pulse-dot text-ink-faint">▍</span>}
                </div>
              </div>
            ))}
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              ask(input);
            }}
            className="flex items-center gap-2 border-t border-line p-3"
          >
            <input
              className="input"
              placeholder={aiOn ? "Ask a question…" : "AI offline"}
              value={input}
              disabled={!aiOn || busy}
              onChange={(e) => setInput(e.target.value)}
            />
            <button type="submit" className="btn-primary px-3" disabled={!aiOn || busy || !input.trim()}>
              <Send size={15} />
            </button>
          </form>
        </div>
      )}
    </>
  );
}
