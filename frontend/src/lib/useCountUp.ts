import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "framer-motion";

/**
 * Animate a number from its previous value up to `target` with an ease-out
 * curve. Honors the OS reduce-motion setting (snaps straight to the value) and
 * always lands exactly on the target. Used for the Command Center KPI tiles.
 */
export function useCountUp(target: number, duration = 650): number {
  const reduce = useReducedMotion();
  const [value, setValue] = useState(reduce ? target : 0);
  const from = useRef(0);
  const raf = useRef<number>();

  useEffect(() => {
    if (reduce || target === from.current) {
      setValue(target);
      from.current = target;
      return;
    }
    const startVal = from.current;
    const delta = target - startVal;
    const start = performance.now();

    function tick(now: number) {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setValue(startVal + delta * eased);
      if (t < 1) {
        raf.current = requestAnimationFrame(tick);
      } else {
        from.current = target;
      }
    }
    raf.current = requestAnimationFrame(tick);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, [target, duration, reduce]);

  return value;
}
