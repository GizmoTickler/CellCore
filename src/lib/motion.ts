import {
  createElement,
  memo,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type RefObject,
} from "react";
import { useThemeStore, type MotionQuality } from "../stores/theme-store";
import { cn } from "./utils";

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";
const FINE_POINTER_QUERY = "(pointer: fine)";

function prefersOsReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

/**
 * Non-reactive effective motion resolution.
 * Respects OS `prefers-reduced-motion: reduce` over stored preference.
 */
export function resolveEffectiveMotion(): MotionQuality {
  if (prefersOsReducedMotion()) return "reduced";
  const pref = useThemeStore.getState().motionQuality;
  return pref === "reduced" ? "reduced" : pref;
}

/**
 * Reactive hook returning the effective motion quality, subscribing to both
 * the theme store preference and the OS `prefers-reduced-motion` media query.
 */
export function useEffectiveMotion(): MotionQuality {
  const pref = useThemeStore((s) => s.motionQuality);
  const [osReduced, setOsReduced] = useState<boolean>(prefersOsReducedMotion);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(REDUCED_MOTION_QUERY);
    setOsReduced(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setOsReduced(e.matches);
    if (typeof mq.addEventListener === "function") {
      mq.addEventListener("change", onChange);
      return () => mq.removeEventListener("change", onChange);
    }
    mq.addListener(onChange);
    return () => mq.removeListener(onChange);
  }, []);

  return osReduced || pref === "reduced" ? "reduced" : pref;
}

export interface SpringOptions {
  stiffness?: number;
  damping?: number;
  precision?: number;
  initial?: number;
}

/**
 * Critically-damped spring physics driver operating purely via refs & callback.
 * Zero React `setState` inside RAF; sleeps automatically at rest and pauses on hidden tabs.
 */
export function useSpringRef(
  target: number | null | undefined,
  onFrame: (val: number) => void,
  opts?: SpringOptions,
): void {
  const motion = useEffectiveMotion();
  const stiffness = opts?.stiffness ?? 180;
  const damping = opts?.damping ?? 26;
  const precision = opts?.precision ?? 0.01;
  const initial = opts?.initial;

  const onFrameRef = useRef(onFrame);
  onFrameRef.current = onFrame;

  const isValidTarget = typeof target === "number" && Number.isFinite(target);
  const hasExplicitInitial = typeof initial === "number" && Number.isFinite(initial);

  const stateRef = useRef<{
    x: number;
    v: number;
    target: number | null;
    initialized: boolean;
    rafId: number | null;
    lastTime: number | null;
  }>({
    x: hasExplicitInitial ? initial : isValidTarget ? target : 0,
    v: 0,
    target: isValidTarget ? target : null,
    initialized: hasExplicitInitial || isValidTarget,
    rafId: null,
    lastTime: null,
  });

  const paramsRef = useRef({ stiffness, damping, precision });
  paramsRef.current = { stiffness, damping, precision };

  useEffect(() => {
    const state = stateRef.current;

    const cancelLoop = () => {
      if (state.rafId !== null && typeof window !== "undefined") {
        window.cancelAnimationFrame(state.rafId);
      }
      state.rafId = null;
      state.lastTime = null;
    };

    const snapTo = (val: number) => {
      cancelLoop();
      state.x = val;
      state.v = 0;
      state.initialized = true;
      onFrameRef.current(val);
    };

    if (!isValidTarget) {
      cancelLoop();
      state.target = null;
      state.v = 0;
      return;
    }

    const goal = target;
    state.target = goal;

    // First valid value without explicit initial: snap directly so we never animate from 0
    if (!state.initialized) {
      snapTo(goal);
      return;
    }

    // Reduced motion or non-browser environment: snap immediately with zero RAF
    if (motion === "reduced" || typeof window === "undefined") {
      snapTo(goal);
      return;
    }

    // Already within rest threshold
    const { precision: eps } = paramsRef.current;
    if (Math.abs(goal - state.x) < eps && Math.abs(state.v) < eps) {
      snapTo(goal);
      return;
    }

    // Hidden tab: pause until visibilitychange restores focus
    if (typeof document !== "undefined" && document.hidden) {
      cancelLoop();
      return;
    }

    const step = (now: number) => {
      const currentTarget = state.target;
      if (currentTarget === null) {
        cancelLoop();
        return;
      }
      if (typeof document !== "undefined" && document.hidden) {
        cancelLoop();
        return;
      }
      const { stiffness: k, damping: c, precision: p } = paramsRef.current;
      const dt =
        state.lastTime === null ? 1 / 60 : Math.min(Math.max((now - state.lastTime) / 1000, 0), 0.05);
      state.lastTime = now;

      // Symplectic Euler with 2 substeps on coarse frames for unconditional stability
      const substeps = dt > 0.02 ? 2 : 1;
      const h = dt / substeps;
      for (let i = 0; i < substeps; i++) {
        const a = k * (currentTarget - state.x) - c * state.v;
        state.v += a * h;
        state.x += state.v * h;
      }

      if (Math.abs(currentTarget - state.x) < p && Math.abs(state.v) < p) {
        state.x = currentTarget;
        state.v = 0;
        state.rafId = null;
        state.lastTime = null;
        onFrameRef.current(currentTarget);
        return;
      }

      onFrameRef.current(state.x);
      state.rafId = window.requestAnimationFrame(step);
    };

    if (state.rafId === null) {
      state.lastTime = null;
      state.rafId = window.requestAnimationFrame(step);
    }

    return undefined;
  }, [target, isValidTarget, motion]);

  // Pause RAF on tab hide, snap cleanly when tab becomes visible, and cancel on unmount
  useEffect(() => {
    if (typeof document === "undefined" || typeof window === "undefined") return;
    const state = stateRef.current;

    const onVisibilityChange = () => {
      if (document.hidden) {
        if (state.rafId !== null) {
          window.cancelAnimationFrame(state.rafId);
          state.rafId = null;
          state.lastTime = null;
        }
        return;
      }
      if (state.target !== null) {
        if (state.rafId !== null) {
          window.cancelAnimationFrame(state.rafId);
          state.rafId = null;
          state.lastTime = null;
        }
        state.x = state.target;
        state.v = 0;
        state.initialized = true;
        onFrameRef.current(state.target);
      }
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      if (state.rafId !== null) {
        window.cancelAnimationFrame(state.rafId);
        state.rafId = null;
        state.lastTime = null;
      }
    };
  }, []);
}

export interface RollingNumberProps {
  value: number | null | undefined;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  fallback?: string;
  className?: string;
  stiffness?: number;
  damping?: number;
}

function formatRollingValue(val: number, decimals: number, prefix: string, suffix: string): string {
  const zeroThreshold = Math.pow(10, -(decimals + 1));
  const safe = Math.abs(val) < zeroThreshold ? 0 : val;
  return `${prefix}${safe.toFixed(decimals)}${suffix}`;
}

/**
 * Spring-interpolated numeric readout with zero React re-renders per frame.
 * Mutates `spanRef.current.textContent` directly via `useSpringRef`.
 */
export const RollingNumber = memo(function RollingNumber({
  value,
  decimals = 0,
  prefix = "",
  suffix = "",
  fallback = "—",
  className,
  stiffness = 180,
  damping = 26,
}: RollingNumberProps) {
  const spanRef = useRef<HTMLSpanElement | null>(null);
  const isValid = typeof value === "number" && Number.isFinite(value);

  const fmtRef = useRef({ decimals, prefix, suffix, fallback });
  fmtRef.current = { decimals, prefix, suffix, fallback };

  const lastRenderedNumRef = useRef<number | null>(isValid ? value : null);

  // Freeze initial React child so React reconciliation never flashes the target value before RAF runs
  const initialTextRef = useRef<string | null>(null);
  if (initialTextRef.current === null) {
    initialTextRef.current = isValid ? formatRollingValue(value, decimals, prefix, suffix) : fallback;
  }

  const precision = Math.min(0.01, Math.pow(10, -(decimals + 1)));

  useSpringRef(
    isValid ? value : null,
    (v) => {
      lastRenderedNumRef.current = v;
      if (spanRef.current) {
        const f = fmtRef.current;
        spanRef.current.textContent = formatRollingValue(v, f.decimals, f.prefix, f.suffix);
      }
    },
    { stiffness, damping, precision },
  );

  // Sync fallback transitions and formatting prop changes (decimals/prefix/suffix)
  useEffect(() => {
    const el = spanRef.current;
    if (!el) return;
    if (!isValid) {
      lastRenderedNumRef.current = null;
      el.textContent = fallback;
    } else if (lastRenderedNumRef.current !== null) {
      el.textContent = formatRollingValue(lastRenderedNumRef.current, decimals, prefix, suffix);
    }
  }, [isValid, decimals, prefix, suffix, fallback]);

  return createElement(
    "span",
    { ref: spanRef, className: cn("qm-tabular", className) },
    initialTextRef.current,
  );
});

export interface SpringPillResult {
  style: CSSProperties;
  ready: boolean;
  pillRef: RefObject<HTMLSpanElement | null>;
}

interface PillRect {
  left: number;
  top: number;
  width: number;
  height: number;
}

const PILL_TRANSITION =
  "transform 340ms cubic-bezier(0.22, 1, 0.36, 1), width 340ms cubic-bezier(0.22, 1, 0.36, 1), height 340ms cubic-bezier(0.22, 1, 0.36, 1), opacity 180ms ease";

/**
 * Measures the active tab/nav element inside `containerRef` and returns GPU-accelerated
 * `translate3d` positioning styles so an active indicator pill glides seamlessly across items.
 */
export function useSpringPill(
  containerRef: RefObject<HTMLElement | null>,
  activeSelector: string,
  deps: ReadonlyArray<unknown> = [],
): SpringPillResult {
  const motion = useEffectiveMotion();
  const pillRef = useRef<HTMLSpanElement | null>(null);
  const [rect, setRect] = useState<PillRect | null>(null);
  const [animate, setAnimate] = useState(false);
  const hasPositionedRef = useRef(false);

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) {
      setRect(null);
      return;
    }

    let activeEl: HTMLElement | null = null;
    let rafId: number | null = null;

    const measure = () => {
      const c = containerRef.current;
      if (!c) return;
      const nextActive = c.querySelector<HTMLElement>(activeSelector);
      activeEl = nextActive;
      if (!nextActive) {
        hasPositionedRef.current = false;
        setAnimate(false);
        setRect(null);
        return;
      }
      const cRect = c.getBoundingClientRect();
      const aRect = nextActive.getBoundingClientRect();
      if (aRect.width === 0 && aRect.height === 0) {
        hasPositionedRef.current = false;
        setAnimate(false);
        setRect(null);
        return;
      }
      const next: PillRect = {
        left: aRect.left - cRect.left + c.scrollLeft,
        top: aRect.top - cRect.top + c.scrollTop,
        width: aRect.width,
        height: aRect.height,
      };
      setRect((prev) => {
        if (
          prev &&
          Math.abs(prev.left - next.left) < 0.5 &&
          Math.abs(prev.top - next.top) < 0.5 &&
          Math.abs(prev.width - next.width) < 0.5 &&
          Math.abs(prev.height - next.height) < 0.5
        ) {
          return prev;
        }
        return next;
      });
      if (!hasPositionedRef.current) {
        hasPositionedRef.current = true;
        if (typeof window !== "undefined") {
          rafId = window.requestAnimationFrame(() => setAnimate(true));
        }
      }
    };

    measure();

    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(measure);
      ro.observe(container);
      if (activeEl) ro.observe(activeEl);
    }

    const onResize = () => measure();
    if (typeof window !== "undefined") {
      window.addEventListener("resize", onResize, { passive: true });
    }

    return () => {
      if (rafId !== null && typeof window !== "undefined") {
        window.cancelAnimationFrame(rafId);
      }
      ro?.disconnect();
      if (typeof window !== "undefined") {
        window.removeEventListener("resize", onResize);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [containerRef, activeSelector, ...deps]);

  const ready = rect !== null;
  const style: CSSProperties = ready
    ? {
        transform: `translate3d(${rect.left.toFixed(1)}px, ${rect.top.toFixed(1)}px, 0)`,
        width: `${rect.width.toFixed(1)}px`,
        height: `${rect.height.toFixed(1)}px`,
        opacity: 1,
        transition: animate && motion !== "reduced" ? PILL_TRANSITION : "none",
        willChange: motion !== "reduced" ? "transform, width, height" : undefined,
      }
    : {
        opacity: 0,
        pointerEvents: "none",
      };

  return { style, ready, pillRef };
}

/**
 * Tracks pointer coordinates into `--qm-mx` and `--qm-my` CSS custom properties
 * (in px relative to element top-left) throttled to RAF.
 * Active only on fine-pointer desktop devices when motion quality is `"full"`.
 */
export function usePointerGlow(ref: RefObject<HTMLElement | null>, enabled = true): void {
  const motion = useEffectiveMotion();

  useEffect(() => {
    if (!enabled || motion !== "full") return;
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    if (!window.matchMedia(FINE_POINTER_QUERY).matches) return;

    const el = ref.current;
    if (!el) return;

    let rafId: number | null = null;
    let clientX = 0;
    let clientY = 0;

    const flush = () => {
      rafId = null;
      const rect = el.getBoundingClientRect();
      el.style.setProperty("--qm-mx", `${(clientX - rect.left).toFixed(1)}px`);
      el.style.setProperty("--qm-my", `${(clientY - rect.top).toFixed(1)}px`);
    };

    const onPointerMove = (e: PointerEvent) => {
      if (e.pointerType === "touch") return;
      clientX = e.clientX;
      clientY = e.clientY;
      if (rafId === null) {
        rafId = window.requestAnimationFrame(flush);
      }
    };

    el.addEventListener("pointermove", onPointerMove, { passive: true });
    return () => {
      el.removeEventListener("pointermove", onPointerMove);
      if (rafId !== null) {
        window.cancelAnimationFrame(rafId);
      }
      el.style.removeProperty("--qm-mx");
      el.style.removeProperty("--qm-my");
    };
  }, [ref, enabled, motion]);
}
