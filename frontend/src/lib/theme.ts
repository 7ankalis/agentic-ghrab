import { useEffect, useSyncExternalStore } from "react";

export type Theme = "light" | "dark";

const STORAGE_KEY = "voc-theme";
const listeners = new Set<() => void>();

function readTheme(): Theme {
  const attr = document.documentElement.getAttribute("data-theme");
  return attr === "dark" ? "dark" : "light";
}

let current: Theme = typeof document !== "undefined" ? readTheme() : "light";

function emit() {
  listeners.forEach((l) => l());
}

export function setTheme(theme: Theme) {
  current = theme;
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // storage unavailable, theme still applies for this session
  }
  emit();
}

export function toggleTheme() {
  setTheme(current === "dark" ? "light" : "dark");
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): Theme {
  return current;
}

export function useTheme(): [Theme, () => void] {
  const theme = useSyncExternalStore(subscribe, getSnapshot, () => "light" as Theme);
  useEffect(() => {
    current = readTheme();
  }, []);
  return [theme, toggleTheme];
}
