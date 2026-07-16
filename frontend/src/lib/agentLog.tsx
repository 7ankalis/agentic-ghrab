import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, streamSSE } from "./api";
import type { LogEntry } from "./types";

interface AgentLogState {
  entries: LogEntry[];    // most recent first, capped
  active: LogEntry[];     // "start" events with no matching finish yet
  connected: boolean;     // is the SSE tail currently live
  clear: () => void;      // wipe local + server-side history
}

const Ctx = createContext<AgentLogState>({
  entries: [],
  active: [],
  connected: false,
  clear: () => {},
});

const MAX_ENTRIES = 300; // matches backend call_log.MAX_HISTORY
const RECONNECT_DELAY_MS = 3000;

/**
 * Single, app-wide subscription to /api/logs/stream — every LLM call any agent
 * makes, live. Mounted once around the whole app so the header pill and the
 * Agent Logs page share one connection instead of opening a new SSE stream
 * per component. Reconnects on drop (server restart, network blip) instead of
 * going silently dead, and dedupes across reconnects since the server replays
 * its full history on every new connection.
 */
export function AgentLogProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [active, setActive] = useState<LogEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const startsRef = useRef<Map<number, LogEntry>>(new Map());
  const seenRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const ctrl = new AbortController();
    let cancelled = false;

    async function run() {
      while (!cancelled) {
        try {
          setConnected(true);
          await streamSSE("/logs/stream", undefined, (event, data) => {
            if (event === "active_snapshot") {
              // Authoritative resync from the server's unbounded in-flight
              // set — history() is trimmed by count and can drop a call's
              // "start" before its "finish" arrives during a busy run,
              // which would otherwise strand that row as "running" forever.
              // Sent on every connect (including reconnects), so this
              // self-heals regardless of how the client got out of sync.
              const snapshot = (data.active as LogEntry[]) ?? [];
              startsRef.current = new Map(snapshot.map((e) => [e.id, e]));
              setActive(Array.from(startsRef.current.values()));
              return;
            }
            if (event !== "log") return;
            const entry = data as LogEntry;
            const key = `${entry.id}-${entry.event}`;
            if (seenRef.current.has(key)) return;
            seenRef.current.add(key);
            setEntries((prev) => [entry, ...prev].slice(0, MAX_ENTRIES));
            if (entry.event === "start") {
              startsRef.current.set(entry.id, entry);
            } else {
              startsRef.current.delete(entry.id);
            }
            setActive(Array.from(startsRef.current.values()));
          }, ctrl.signal);
        } catch {
          // stream ended (nav away / server restart) — fall through to reconnect
        }
        // In dev StrictMode this effect mounts, cleans up, and remounts
        // immediately; the aborted first run must not clobber the second
        // run's "connected" state after the fact.
        if (cancelled) break;
        setConnected(false);
        await new Promise((r) => setTimeout(r, RECONNECT_DELAY_MS));
      }
    }

    run();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  function clear() {
    seenRef.current.clear();
    startsRef.current.clear();
    setEntries([]);
    setActive([]);
    api.clearLogs().catch(() => {
      // best-effort — local view is already cleared regardless
    });
  }

  return <Ctx.Provider value={{ entries, active, connected, clear }}>{children}</Ctx.Provider>;
}

export const useAgentLog = () => useContext(Ctx);
