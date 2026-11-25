import React, { useEffect, useRef } from "react";
import { useEffectiveMotion } from "../lib/motion";
import { cn } from "../lib/utils";

export interface HudOscilloscopeProps {
  values: number[];
  color: string;
  height?: number;
  className?: string;
  label?: string;
}

interface Rgb {
  r: number;
  g: number;
  b: number;
}

const FALLBACK_RGB: Rgb = { r: 34, g: 211, b: 238 };

function resolveCssColor(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "#22d3ee";
  if (typeof window === "undefined" || typeof document === "undefined") return trimmed;
  const varMatch = /^var\(\s*(--[^,\s)]+)(?:\s*,\s*([^)]+))?\s*\)$/.exec(trimmed);
  if (varMatch) {
    const resolved = window
      .getComputedStyle(document.documentElement)
      .getPropertyValue(varMatch[1])
      .trim();
    if (resolved) return resolved;
    if (varMatch[2]) return varMatch[2].trim();
  }
  return trimmed;
}

function parseRgb(colorStr: string): Rgb {
  const s = colorStr.trim();
  if (s.startsWith("#")) {
    const hex = s.slice(1);
    if (hex.length === 3 || hex.length === 4) {
      const r = parseInt(hex[0] + hex[0], 16);
      const g = parseInt(hex[1] + hex[1], 16);
      const b = parseInt(hex[2] + hex[2], 16);
      if (Number.isFinite(r) && Number.isFinite(g) && Number.isFinite(b)) return { r, g, b };
    } else if (hex.length === 6 || hex.length === 8) {
      const r = parseInt(hex.slice(0, 2), 16);
      const g = parseInt(hex.slice(2, 4), 16);
      const b = parseInt(hex.slice(4, 6), 16);
      if (Number.isFinite(r) && Number.isFinite(g) && Number.isFinite(b)) return { r, g, b };
    }
  }
  const rgbMatch = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(s);
  if (rgbMatch) {
    return {
      r: Math.max(0, Math.min(255, Math.round(Number(rgbMatch[1])))),
      g: Math.max(0, Math.min(255, Math.round(Number(rgbMatch[2])))),
      b: Math.max(0, Math.min(255, Math.round(Number(rgbMatch[3])))),
    };
  }
  return FALLBACK_RGB;
}

function rgba(c: Rgb, a: number): string {
  return `rgba(${c.r}, ${c.g}, ${c.b}, ${a})`;
}

/**
 * Computes Fritsch-Carlson monotone cubic tangents so throughput waveforms
 * stay silky smooth without dipping below zero or overshooting bursts.
 */
function traceMonotoneCurve(
  ctx: CanvasRenderingContext2D,
  xs: number[],
  ys: number[],
): void {
  const n = xs.length;
  if (n === 0) return;
  ctx.moveTo(xs[0], ys[0]);
  if (n === 1) return;
  if (n === 2) {
    ctx.lineTo(xs[1], ys[1]);
    return;
  }

  const dx = new Float64Array(n - 1);
  const slopes = new Float64Array(n - 1);
  for (let i = 0; i < n - 1; i++) {
    const d = xs[i + 1] - xs[i] || 1;
    dx[i] = d;
    slopes[i] = (ys[i + 1] - ys[i]) / d;
  }

  const m = new Float64Array(n);
  m[0] = slopes[0];
  m[n - 1] = slopes[n - 2];
  for (let i = 1; i < n - 1; i++) {
    m[i] = slopes[i - 1] * slopes[i] <= 0 ? 0 : (slopes[i - 1] + slopes[i]) * 0.5;
  }

  for (let i = 0; i < n - 1; i++) {
    if (Math.abs(slopes[i]) < 1e-6) {
      m[i] = 0;
      m[i + 1] = 0;
    } else {
      const a = m[i] / slopes[i];
      const b = m[i + 1] / slopes[i];
      const s = a * a + b * b;
      if (s > 9) {
        const tau = 3 / Math.sqrt(s);
        m[i] = tau * a * slopes[i];
        m[i + 1] = tau * b * slopes[i];
      }
    }
  }

  for (let i = 0; i < n - 1; i++) {
    const h = dx[i] / 3;
    ctx.bezierCurveTo(
      xs[i] + h,
      ys[i] + m[i] * h,
      xs[i + 1] - h,
      ys[i + 1] - m[i + 1] * h,
      xs[i + 1],
      ys[i + 1],
    );
  }
}

export const HudOscilloscope = React.memo(function HudOscilloscope({
  values,
  color,
  height = 46,
  className,
  label,
}: HudOscilloscopeProps) {
  const motion = useEffectiveMotion();
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const stateRef = useRef<{
    target: number[];
    display: number[];
    targetMax: number;
    displayMax: number;
    width: number;
    height: number;
    dpr: number;
    strokeRgb: Rgb;
    gridColor: string;
    motion: "full" | "balanced" | "reduced";
    rafId: number | null;
    lastFrameTime: number;
    lastDrawTime: number;
  }>({
    target: [],
    display: [],
    targetMax: 1,
    displayMax: 1,
    width: 0,
    height,
    dpr: 1,
    strokeRgb: FALLBACK_RGB,
    gridColor: "rgba(148, 198, 255, 0.14)",
    motion,
    rafId: null,
    lastFrameTime: 0,
    lastDrawTime: 0,
  });

  const drawRef = useRef<(now: number) => void>(() => {});
  const startLoopRef = useRef<() => void>(() => {});

  // Keep refs updated for motion & height
  stateRef.current.motion = motion;
  stateRef.current.height = height;

  // Core setup: ResizeObserver, MutationObserver (skin/dark), visibilitychange, and draw/RAF loop
  useEffect(() => {
    const wrap = wrapRef.current;
    const canvas = canvasRef.current;
    if (!wrap || !canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const s = stateRef.current;

    const refreshColors = () => {
      const resolvedStroke = resolveCssColor(color);
      s.strokeRgb = parseRgb(resolvedStroke);
      const lineCss = resolveCssColor("var(--qm-line)");
      const lineRgb = parseRgb(lineCss);
      s.gridColor = rgba(lineRgb, 0.35);
    };

    const resizeCanvas = () => {
      const rect = wrap.getBoundingClientRect();
      const w = Math.max(0, Math.round(rect.width));
      const h = Math.max(1, Math.round(rect.height || s.height));
      const dpr = Math.min(3, typeof window !== "undefined" ? window.devicePixelRatio || 1 : 1);
      s.width = w;
      s.height = h;
      s.dpr = dpr;
      if (w > 0 && h > 0) {
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(h * dpr);
      }
    };

    const draw = (now: number) => {
      const { width: w, height: h, dpr, display, displayMax, strokeRgb, gridColor } = s;
      if (w <= 0 || h <= 0) return;

      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const padT = 6;
      const padB = 4;
      const padR = 7;
      const plotW = Math.max(1, w - padR);
      const plotH = Math.max(1, h - padT - padB);

      // Subtle 2-hairline horizontal grid
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1;
      ctx.beginPath();
      const y1 = Math.round(padT + plotH * 0.33) + 0.5;
      const y2 = Math.round(padT + plotH * 0.67) + 0.5;
      ctx.moveTo(0, y1);
      ctx.lineTo(w, y1);
      ctx.moveTo(0, y2);
      ctx.lineTo(w, y2);
      ctx.stroke();

      const n = display.length;
      if (n < 2) {
        ctx.restore();
        return;
      }

      const maxScale = Math.max(1e-4, displayMax);
      const stepX = plotW / (n - 1);
      const xs: number[] = new Array(n);
      const ys: number[] = new Array(n);
      for (let i = 0; i < n; i++) {
        xs[i] = i * stepX;
        const norm = Math.max(0, Math.min(1, display[i] / maxScale));
        ys[i] = padT + (1 - norm) * plotH;
      }

      // Vertical gradient wash beneath the waveform
      const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH + padB);
      grad.addColorStop(0, rgba(strokeRgb, 0.28));
      grad.addColorStop(0.75, rgba(strokeRgb, 0.06));
      grad.addColorStop(1, rgba(strokeRgb, 0));

      ctx.beginPath();
      traceMonotoneCurve(ctx, xs, ys);
      ctx.lineTo(xs[n - 1], h);
      ctx.lineTo(xs[0], h);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // Luminous waveform stroke
      ctx.save();
      ctx.beginPath();
      traceMonotoneCurve(ctx, xs, ys);
      ctx.strokeStyle = rgba(strokeRgb, 0.96);
      ctx.lineWidth = 2;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      if (s.motion === "full") {
        ctx.shadowColor = rgba(strokeRgb, 0.65);
        ctx.shadowBlur = 8;
      }
      ctx.stroke();
      ctx.restore();

      // Leading-edge live beam dot at rightmost sample
      const tipX = xs[n - 1];
      const tipY = ys[n - 1];
      const breath = s.motion === "full" ? 0.5 + 0.5 * Math.sin(now * 0.0032) : 0.35;
      const haloR = 4.8 + breath * 2.4;
      const haloAlpha = s.motion === "full" ? 0.34 - breath * 0.16 : 0.22;

      ctx.beginPath();
      ctx.arc(tipX, tipY, haloR, 0, Math.PI * 2);
      ctx.fillStyle = rgba(strokeRgb, haloAlpha);
      ctx.fill();

      ctx.save();
      if (s.motion === "full") {
        ctx.shadowColor = rgba(strokeRgb, 0.85);
        ctx.shadowBlur = 7;
      }
      ctx.beginPath();
      ctx.arc(tipX, tipY, 2.75, 0, Math.PI * 2);
      ctx.fillStyle = rgba(strokeRgb, 1);
      ctx.fill();
      ctx.restore();

      ctx.beginPath();
      ctx.arc(tipX, tipY, 1.1, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(255, 255, 255, 0.9)";
      ctx.fill();

      ctx.restore();
    };

    const cancelLoop = () => {
      if (s.rafId !== null && typeof window !== "undefined") {
        window.cancelAnimationFrame(s.rafId);
        s.rafId = null;
      }
      s.lastFrameTime = 0;
    };

    const tick = (now: number) => {
      if (typeof document !== "undefined" && document.hidden) {
        cancelLoop();
        return;
      }

      // Throttle to ~30 fps in balanced mode
      if (s.motion === "balanced" && s.lastDrawTime > 0 && now - s.lastDrawTime < 32) {
        s.rafId = window.requestAnimationFrame(tick);
        return;
      }

      const dt = s.lastFrameTime > 0 ? Math.min(0.05, Math.max(0.001, (now - s.lastFrameTime) / 1000)) : 1 / 60;
      s.lastFrameTime = now;
      s.lastDrawTime = now;

      const valAlpha = 1 - Math.exp(-10 * dt);
      const scaleAlpha = 1 - Math.exp(-6 * dt);
      const eps = Math.max(1e-4, s.targetMax * 0.0015);
      let settled = true;

      for (let i = 0; i < s.target.length; i++) {
        const diff = s.target[i] - s.display[i];
        if (Math.abs(diff) > eps) {
          s.display[i] += diff * valAlpha;
          settled = false;
        } else {
          s.display[i] = s.target[i];
        }
      }

      const maxDiff = s.targetMax - s.displayMax;
      if (Math.abs(maxDiff) > eps) {
        s.displayMax += maxDiff * scaleAlpha;
        settled = false;
      } else {
        s.displayMax = s.targetMax;
      }

      draw(now);

      // Keep RAF alive while converging, or for the gentle leading-edge halo breath in "full" mode
      if (!settled || (s.motion === "full" && s.display.length >= 2)) {
        s.rafId = window.requestAnimationFrame(tick);
      } else {
        s.rafId = null;
        s.lastFrameTime = 0;
      }
    };

    const startLoop = () => {
      if (typeof document !== "undefined" && document.hidden) {
        cancelLoop();
        return;
      }
      if (s.motion === "reduced") {
        cancelLoop();
        s.display = s.target.slice();
        s.displayMax = s.targetMax;
        draw(typeof performance !== "undefined" ? performance.now() : 0);
        return;
      }
      if (s.rafId === null && typeof window !== "undefined") {
        s.lastFrameTime = 0;
        s.rafId = window.requestAnimationFrame(tick);
      }
    };

    drawRef.current = draw;
    startLoopRef.current = startLoop;

    refreshColors();
    resizeCanvas();
    startLoop();

    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(() => {
        resizeCanvas();
        draw(typeof performance !== "undefined" ? performance.now() : 0);
      });
      ro.observe(wrap);
    }

    let mo: MutationObserver | null = null;
    if (typeof MutationObserver !== "undefined" && typeof document !== "undefined") {
      mo = new MutationObserver(() => {
        refreshColors();
        draw(typeof performance !== "undefined" ? performance.now() : 0);
      });
      mo.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ["data-skin", "class"],
      });
    }

    const onVisibilityChange = () => {
      if (document.hidden) {
        cancelLoop();
      } else {
        s.display = s.target.slice();
        s.displayMax = s.targetMax;
        draw(typeof performance !== "undefined" ? performance.now() : 0);
        startLoop();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      cancelLoop();
      ro?.disconnect();
      mo?.disconnect();
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [color, height, motion]);

  // Feed incoming 1 Hz data samples into the interpolation target buffer
  useEffect(() => {
    const s = stateRef.current;
    const clean = values.map((v) => (Number.isFinite(v) && v >= 0 ? v : 0));
    let peak = 0;
    for (let i = 0; i < clean.length; i++) {
      if (clean[i] > peak) peak = clean[i];
    }
    const nextMax = Math.max(1e-3, peak * 1.12);

    s.target = clean;
    s.targetMax = nextMax;

    if (s.motion === "reduced" || s.display.length === 0) {
      s.display = clean.slice();
      s.displayMax = nextMax;
    } else if (clean.length === s.display.length + 1) {
      s.display = [...s.display, s.display[s.display.length - 1] ?? clean[clean.length - 1]];
    } else if (clean.length !== s.display.length) {
      // Smoothly resample previous display buffer onto new length
      const prev = s.display;
      const nextDisplay = new Array<number>(clean.length);
      for (let i = 0; i < clean.length; i++) {
        const idx = clean.length <= 1 ? 0 : (i / (clean.length - 1)) * (prev.length - 1);
        const lo = Math.floor(idx);
        const hi = Math.min(prev.length - 1, lo + 1);
        const f = idx - lo;
        nextDisplay[i] = prev[lo] * (1 - f) + prev[hi] * f;
      }
      s.display = nextDisplay;
    }

    startLoopRef.current();
  }, [values]);

  return (
    <div ref={wrapRef} className={cn("relative w-full overflow-hidden", className)} style={{ height }}>
      <canvas
        ref={canvasRef}
        className="block h-full w-full"
        role="img"
        aria-label={label ?? "Live telemetry oscilloscope"}
      />
    </div>
  );
});
