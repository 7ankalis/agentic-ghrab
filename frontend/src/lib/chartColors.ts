import { useTheme } from "@/lib/theme";

export function useChartColors() {
  const [theme] = useTheme();
  const isDark = theme === "dark";
  return {
    axisStroke: isDark ? "#6c7d76" : "#5e756c",
    labelFill: isDark ? "#9fb0a9" : "#3f594f",
    grid: isDark ? "rgba(140,175,160,0.10)" : "rgba(0,60,48,0.10)",
    gridStrong: isDark ? "rgba(140,175,160,0.28)" : "rgba(0,60,48,0.30)",
    cursorFill: isDark ? "rgba(140,175,160,0.06)" : "rgba(0,60,48,0.06)",
    cursorStroke: isDark ? "rgba(140,175,160,0.25)" : "rgba(0,60,48,0.25)",
    pointStroke: isDark ? "#0e1614" : "#ffffff",
  };
}
