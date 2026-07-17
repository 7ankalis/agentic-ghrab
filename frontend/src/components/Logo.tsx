/**
 * Ghrab brand mark — "ghrab" (غراب) is Arabic for raven, so the mark is an
 * origami raven built from three facets. Mirrors public/favicon.svg; keep the
 * two in sync if the geometry changes. Renders in currentColor with per-facet
 * opacity so it works on any background (the sidebar badge, overlays, docs).
 */
export function RavenMark({ size = 20, className }: { size?: number; className?: string }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} className={className} aria-hidden="true">
      <polygon points="18,54 22,30 40,36 36,54" fill="currentColor" opacity="0.7" />
      <polygon points="22,30 30,14 46,22 38,32" fill="currentColor" opacity="0.88" />
      <polygon points="46,22 60,30 40,36" fill="currentColor" />
      <circle cx="41" cy="24" r="2.4" fill="rgb(var(--c-forest))" />
    </svg>
  );
}
