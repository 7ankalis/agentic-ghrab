/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Command-center chrome, tinted toward the brand forest green.
        // Values are CSS custom properties so they can swap between light/dark themes.
        base: "rgb(var(--c-base) / <alpha-value>)",
        surface: "rgb(var(--c-surface) / <alpha-value>)",
        "surface-2": "rgb(var(--c-surface-2) / <alpha-value>)",
        "surface-3": "rgb(var(--c-surface-3) / <alpha-value>)",
        line: "rgb(var(--c-line) / <alpha-value>)",
        "line-strong": "rgb(var(--c-line-strong) / <alpha-value>)",
        ink: "rgb(var(--c-ink) / <alpha-value>)",
        "ink-muted": "rgb(var(--c-ink-muted) / <alpha-value>)",
        "ink-faint": "rgb(var(--c-ink-faint) / <alpha-value>)",
        // Brand
        forest: "rgb(var(--c-forest) / <alpha-value>)",
        "forest-lit": "rgb(var(--c-forest-lit) / <alpha-value>)",
        sage: "rgb(var(--c-sage) / <alpha-value>)",
        "sage-bright": "rgb(var(--c-sage-bright) / <alpha-value>)",
        // Status ramp (most → least urgent)
        immediate: "rgb(var(--c-immediate) / <alpha-value>)",
        act: "rgb(var(--c-act) / <alpha-value>)",
        attend: "rgb(var(--c-attend) / <alpha-value>)",
        track2: "rgb(var(--c-track2) / <alpha-value>)",
        track: "rgb(var(--c-track) / <alpha-value>)",
        purple: "rgb(var(--c-purple) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
        display: ["Space Grotesk", "Inter", "sans-serif"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.4), 0 8px 30px rgba(0,0,0,0.25)",
        glow: "0 0 0 1px rgba(85,161,133,0.35), 0 0 32px rgba(85,161,133,0.18)",
        pop: "0 24px 60px rgba(0,0,0,0.55)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-dot": {
          "0%,100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        dash: { to: { strokeDashoffset: "-16" } },
        "scan-x": {
          "0%": { transform: "translateX(-120%)" },
          "100%": { transform: "translateX(420%)" },
        },
        "ring-pulse": {
          "0%,100%": { boxShadow: "0 0 0 0 rgba(85,161,133,0.35)" },
          "50%": { boxShadow: "0 0 0 4px rgba(85,161,133,0)" },
        },
        "pop-in": {
          "0%": { opacity: "0", transform: "translateY(10px) scale(0.98)" },
          "100%": { opacity: "1", transform: "translateY(0) scale(1)" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.4s ease both",
        "pulse-dot": "pulse-dot 1.8s ease-in-out infinite",
        "scan-x": "scan-x 2.2s linear infinite",
        "ring-pulse": "ring-pulse 2s ease-in-out infinite",
        "pop-in": "pop-in 0.35s cubic-bezier(0.16,1,0.3,1) both",
      },
    },
  },
  plugins: [],
};
