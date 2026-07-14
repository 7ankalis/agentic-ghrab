/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Command-center dark chrome, tinted toward the brand forest green.
        base: "#080c0b",
        surface: "#0e1614",
        "surface-2": "#131e1a",
        "surface-3": "#1a2822",
        line: "rgba(140,175,160,0.12)",
        "line-strong": "rgba(140,175,160,0.22)",
        ink: "#e9efec",
        "ink-muted": "#9fb0a9",
        "ink-faint": "#6c7d76",
        // Brand
        forest: "#003c30",
        "forest-lit": "#0b5a48",
        sage: "#55a185",
        "sage-bright": "#7fd0ad",
        // Status ramp (most → least urgent)
        immediate: "#f0553f",
        act: "#f7853a",
        attend: "#e8bd4a",
        track2: "#6f97b8",
        track: "#4fae8b",
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
      },
      animation: {
        "fade-up": "fade-up 0.4s ease both",
        "pulse-dot": "pulse-dot 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
