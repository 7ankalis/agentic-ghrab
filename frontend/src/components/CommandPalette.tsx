import { useEffect, useMemo, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { CornerDownLeft, Search } from "lucide-react";
import { cx } from "@/lib/format";

export interface Command {
  id: string;
  label: string;
  section: string;
  icon: LucideIcon;
  perform: () => void;
  /** Extra terms to match against, beyond the visible label. */
  keywords?: string;
  /** Short trailing hint, e.g. a keyboard shortcut or status. */
  hint?: string;
  /** Skip this command when true (e.g. an action that isn't available yet). */
  disabled?: boolean;
}

/**
 * ⌘K command palette — the primary keyboard-first way to move around the VOC
 * and fire operator actions (run analysis, toggle theme, export). Purely
 * presentational + list navigation; the commands themselves come from Layout,
 * where the run/export/theme handlers already live.
 */
export default function CommandPalette({
  open,
  onClose,
  commands,
}: {
  open: boolean;
  onClose: () => void;
  commands: Command[];
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const pool = commands.filter((c) => !c.disabled);
    if (!q) return pool;
    return pool.filter((c) =>
      (`${c.label} ${c.section} ${c.keywords ?? ""}`).toLowerCase().includes(q),
    );
  }, [commands, query]);

  // Reset query + selection each time the palette opens, and focus the input.
  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      // defer so the element exists and the browser doesn't eat the focus
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => setActive(0), [query]);

  // Keep the highlighted row in view as arrow keys walk the list.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  function run(cmd: Command | undefined) {
    if (!cmd) return;
    onClose();
    cmd.perform();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (results.length ? (i + 1) % results.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (results.length ? (i - 1 + results.length) % results.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(results[active]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  }

  // Group by section but keep a flat index so arrow-nav is linear.
  let flatIdx = -1;
  const sections = results.reduce<Record<string, Command[]>>((acc, c) => {
    (acc[c.section] ??= []).push(c);
    return acc;
  }, {});

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-base/60 px-4 pt-[14vh] backdrop-blur-sm animate-overlay-in"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="card w-full max-w-[560px] overflow-hidden border-line-strong shadow-pop animate-cmd-in"
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search size={17} className="shrink-0 text-ink-faint" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to a view or run an action…"
            className="w-full bg-transparent py-3.5 text-sm text-ink placeholder:text-ink-faint focus:outline-none"
            spellCheck={false}
            autoComplete="off"
          />
          <kbd className="hidden shrink-0 rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-ink-faint sm:block">
            ESC
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[52vh] overflow-y-auto p-2">
          {results.length === 0 ? (
            <div className="px-3 py-10 text-center text-sm text-ink-faint">
              No matches for “{query}”
            </div>
          ) : (
            Object.entries(sections).map(([section, cmds]) => (
              <div key={section} className="mb-1">
                <div className="px-2.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-faint">
                  {section}
                </div>
                {cmds.map((cmd) => {
                  flatIdx += 1;
                  const idx = flatIdx;
                  const isActive = idx === active;
                  const Icon = cmd.icon;
                  return (
                    <button
                      key={cmd.id}
                      data-idx={idx}
                      onMouseMove={() => setActive(idx)}
                      onClick={() => run(cmd)}
                      className={cx(
                        "group flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left text-sm transition-colors",
                        isActive ? "bg-sage/12 text-ink" : "text-ink-muted",
                      )}
                    >
                      <span
                        className={cx(
                          "grid h-7 w-7 shrink-0 place-items-center rounded-md border transition-colors",
                          isActive
                            ? "border-sage/30 bg-sage/15 text-sage-bright"
                            : "border-line bg-surface-2 text-ink-faint",
                        )}
                      >
                        <Icon size={15} />
                      </span>
                      <span className="flex-1 truncate font-medium">{cmd.label}</span>
                      {cmd.hint && (
                        <span className="shrink-0 font-mono text-[10px] text-ink-faint">{cmd.hint}</span>
                      )}
                      <CornerDownLeft
                        size={13}
                        className={cx(
                          "shrink-0 transition-opacity",
                          isActive ? "opacity-100 text-sage-bright" : "opacity-0",
                        )}
                      />
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="flex items-center gap-4 border-t border-line px-4 py-2.5 text-[11px] text-ink-faint">
          <KbdHint keys={["↑", "↓"]} label="Navigate" />
          <KbdHint keys={["↵"]} label="Select" />
          <KbdHint keys={["esc"]} label="Close" />
        </div>
      </div>
    </div>
  );
}

function KbdHint({ keys, label }: { keys: string[]; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="flex gap-1">
        {keys.map((k) => (
          <kbd
            key={k}
            className="grid min-w-[18px] place-items-center rounded border border-line bg-surface-2 px-1 py-0.5 font-mono text-[10px] text-ink-muted"
          >
            {k}
          </kbd>
        ))}
      </span>
      {label}
    </span>
  );
}
