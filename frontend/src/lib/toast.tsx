import {
  createContext, useCallback, useContext, useMemo, useRef, useState,
  type ReactNode,
} from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { cx } from "./format";

export type ToastKind = "success" | "error" | "info";

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
}

interface ToastApi {
  success: (title: string, description?: string) => void;
  error: (title: string, description?: string) => void;
  info: (title: string, description?: string) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const KIND_META: Record<ToastKind, { icon: typeof Info; color: string }> = {
  success: { icon: CheckCircle2, color: "rgb(var(--c-track))" },
  error: { icon: AlertTriangle, color: "rgb(var(--c-immediate))" },
  info: { icon: Info, color: "rgb(var(--c-sage-bright))" },
};

const DURATION = 4200;

/**
 * App-wide toast provider. Renders a top-right stack that never collides with
 * the AI dock (bottom-right) or the run-progress overlay (bottom-center). Every
 * toast auto-dismisses, and hovering the stack is not required — these are
 * confirmations, not decisions.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  const timers = useRef<Record<number, ReturnType<typeof setTimeout>>>({});

  const dismiss = useCallback((id: number) => {
    setToasts((t) => t.filter((x) => x.id !== id));
    const timer = timers.current[id];
    if (timer) {
      clearTimeout(timer);
      delete timers.current[id];
    }
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, description?: string) => {
      const id = nextId.current++;
      setToasts((t) => [...t, { id, kind, title, description }]);
      timers.current[id] = setTimeout(() => dismiss(id), DURATION);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (title, description) => push("success", title, description),
      error: (title, description) => push("error", title, description),
      info: (title, description) => push("info", title, description),
      dismiss,
    }),
    [push, dismiss],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed right-5 top-[4.75rem] z-[70] flex w-[360px] max-w-[calc(100vw-2.5rem)] flex-col gap-2.5">
        <AnimatePresence initial={false}>
          {toasts.map((t) => {
            const { icon: Icon, color } = KIND_META[t.kind];
            return (
              <motion.div
                key={t.id}
                layout
                initial={{ opacity: 0, x: 24, scale: 0.96 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: 24, scale: 0.96 }}
                transition={{ type: "spring", damping: 26, stiffness: 320 }}
                className="card pointer-events-auto relative flex items-start gap-3 overflow-hidden border-line-strong p-3.5 pr-9"
              >
                <span className="absolute inset-y-0 left-0 w-[3px]" style={{ background: color }} />
                <span
                  className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full"
                  style={{ background: `color-mix(in srgb, ${color} 16%, transparent)`, color }}
                >
                  <Icon size={14} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-ink">{t.title}</div>
                  {t.description && (
                    <div className="mt-0.5 text-[12px] leading-relaxed text-ink-muted">{t.description}</div>
                  )}
                </div>
                <button
                  onClick={() => dismiss(t.id)}
                  className="absolute right-2 top-2 rounded-md p-1 text-ink-faint transition hover:bg-surface-2 hover:text-ink"
                  title="Dismiss"
                >
                  <X size={13} />
                </button>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within a ToastProvider");
  return ctx;
}
