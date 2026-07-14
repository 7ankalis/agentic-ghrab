import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { streamSSE } from "./api";
import type { LogEntry } from "./types";

interface AgentLogState {
  entries: LogEntry[];   // most recent first, capped
  active: LogEntry[];    // "start" events with no matching finish yet
}

const Ctx = createContext<AgentLogState>({ entries: [], active: [] });

const MAX_ENTRIES = 200;

/**
 * Single, app-wide subscription to /api/logs/stream — every LLM call any agent
 * makes, live. Mounted once around the whole app so the header pill and the
 * Agent Logs page share one connection instead of opening a new SSE stream
 * per component.
 */
export function AgentLogProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [active, setActive] = useState<LogEntry[]>([]);
  const startsRef = useRef<Map<number, LogEntry>>(new Map());

  useEffect(() => {
    const ctrl = new AbortController();
    streamSSE("/logs/stream", undefined, (event, data) => {
      if (event !== "log") return;
      const entry = data as LogEntry;
      setEntries((prev) => [entry, ...prev].slice(0, MAX_ENTRIES));
      if (entry.event === "start") {
        startsRef.current.set(entry.id, entry);
      } else {
        startsRef.current.delete(entry.id);
      }
      setActive(Array.from(startsRef.current.values()));
    }, ctrl.signal).catch(() => {
      // stream ended (nav away / server restart) — silent, not a user-facing error
    });
    return () => ctrl.abort();
  }, []);

  return <Ctx.Provider value={{ entries, active }}>{children}</Ctx.Provider>;
}

export const useAgentLog = () => useContext(Ctx);
