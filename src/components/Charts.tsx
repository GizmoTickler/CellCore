import React, { useId, useMemo, useRef, useState } from "react";

interface PointCoord {
  x: number;
  y: number;
}

function buildMonotonePath(pts: PointCoord[]): string {
  if (pts.length === 0) return "";
  if (pts.length === 1) return `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;
  if (pts.length === 2) {
    return `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)} L ${pts[1].x.toFixed(2)} ${pts[1].y.toFixed(2)}`;
  }

  const n = pts.length;
  const dx: number[] = [];
  const dy: number[] = [];
  const slopes: number[] = [];

  for (let i = 0; i < n - 1; i++) {
    const ddx = pts[i + 1].x - pts[i].x || 1;
    const ddy = pts[i + 1].y - pts[i].y;
    dx.push(ddx);
    dy.push(ddy);
    slopes.push(ddy / ddx);
  }

  const tangents: number[] = [slopes[0]];
  for (let i = 1; i < n - 1; i++) {
    if (slopes[i - 1] * slopes[i] <= 0) {
      tangents.push(0);
    } else {
      tangents.push((slopes[i - 1] + slopes[i]) / 2);
    }
  }
  tangents.push(slopes[n - 2]);

  for (let i = 0; i < n - 1; i++) {
    if (Math.abs(slopes[i]) < 1e-6) {
      tangents[i] = 0;
      tangents[i + 1] = 0;
    } else {
      const a = tangents[i] / slopes[i];
      const b = tangents[i + 1] / slopes[i];
      const s = a * a + b * b;
      if (s > 9) {
        const tau = 3 / Math.sqrt(s);
        tangents[i] = tau * a * slopes[i];
        tangents[i + 1] = tau * b * slopes[i];
      }
    }
  }

  let d = `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;
  for (let i = 0; i < n - 1; i++) {
    const h = dx[i] / 3;
    const cp1x = pts[i].x + h;
    const cp1y = pts[i].y + tangents[i] * h;
    const cp2x = pts[i + 1].x - h;
    const cp2y = pts[i + 1].y - tangents[i + 1] * h;
    d += ` C ${cp1x.toFixed(2)} ${cp1y.toFixed(2)}, ${cp2x.toFixed(2)} ${cp2y.toFixed(2)}, ${pts[i + 1].x.toFixed(2)} ${pts[i + 1].y.toFixed(2)}`;
  }
  return d;
}

function formatTickValue(v: number, span: number, unit = ""): string {
  let numStr: string;
  if (Math.abs(v) < 0.005) numStr = "0";
  else if (span <= 0.5) numStr = v.toFixed(2);
  else if (span <= 4) numStr = v.toFixed(1);
  else numStr = String(Math.round(v));
  return unit ? `${numStr} ${unit}` : numStr;
}

export interface SeriesConfig {
  label: string;
  values: number[];
  stroke: string;
  fillStart: string;
  unit?: string;
}

export const InteractiveAreaChart = React.memo(function InteractiveAreaChart({
  series,
  labels,
  height = 175,
  minOverride,
  maxOverride,
  showPeakBadge = true,
  emptyLabel = "Waiting for telemetry samples...",
}: {
  series: SeriesConfig[];
  labels?: string[];
  height?: number;
  minOverride?: number;
  maxOverride?: number;
  showPeakBadge?: boolean;
  emptyLabel?: string;
}) {
  const uid = useId().replace(/:/g, "");
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const count = useMemo(
    () => Math.max(0, ...series.map((s) => s.values.length)),
    [series]
  );

  const width = 560;
  const padL = 44;
  const padR = 14;
  const padT = 24;
  const padB = 22;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  const { minVal, maxVal, ticks } = useMemo(() => {
    const allVals = series.flatMap((s) => s.values.filter((v) => Number.isFinite(v)));
    if (allVals.length === 0) {
      return { minVal: 0, maxVal: 1, ticks: [0, 0.5, 1] };
    }
    let lo = minOverride ?? Math.min(...allVals);
    let hi = maxOverride ?? Math.max(...allVals);
    if (Math.abs(hi - lo) < 1e-4) {
      const pad = Math.max(0.2, Math.abs(lo) * 0.1);
      lo = lo - pad;
      hi = hi + pad;
    } else {
      const margin = (hi - lo) * 0.14;
      if (minOverride == null) lo = lo >= 0 ? Math.max(0, lo - margin) : lo - margin;
      if (maxOverride == null) hi = hi + margin;
    }
    const mid = (lo + hi) / 2;
    return { minVal: lo, maxVal: hi, ticks: [hi, mid, lo] };
  }, [series, minOverride, maxOverride]);

  const span = Math.max(0.0001, maxVal - minVal);

  const computedSeries = useMemo(() => {
    return series.map((s) => {
      const len = s.values.length;
      const coords: PointCoord[] = s.values.map((val, i) => {
        const x = len <= 1 ? padL + plotW : padL + (i / (len - 1)) * plotW;
        const clamped = Math.max(minVal, Math.min(maxVal, val));
        const y = padT + (1 - (clamped - minVal) / span) * plotH;
        return { x, y };
      });
      const linePath = buildMonotonePath(coords);
      const areaPath =
        coords.length >= 2
          ? `${linePath} L ${coords[coords.length - 1].x.toFixed(2)} ${(padT + plotH).toFixed(2)} L ${coords[0].x.toFixed(2)} ${(padT + plotH).toFixed(2)} Z`
          : "";
      return { ...s, coords, linePath, areaPath };
    });
  }, [series, minVal, maxVal, span, plotW, plotH]);

  const peakPoint = useMemo(() => {
    const primary = computedSeries[0];
    if (!showPeakBadge || !primary || primary.values.length < 3) return null;
    let bestIdx = 0;
    let bestVal = -Infinity;
    for (let i = 0; i < primary.values.length; i++) {
      if (primary.values[i] > bestVal) {
        bestVal = primary.values[i];
        bestIdx = i;
      }
    }
    const pt = primary.coords[bestIdx];
    if (!pt) return null;
    const text = formatTickValue(bestVal, span, primary.unit ?? "");
    return { x: pt.x, y: pt.y, text };
  }, [computedSeries, showPeakBadge, span]);

  function handlePointerMove(e: React.PointerEvent<SVGSVGElement>) {
    if (count === 0) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const relX = ((e.clientX - rect.left) / rect.width) * width;
    const clampedX = Math.max(padL, Math.min(padL + plotW, relX));
    const idx = count <= 1 ? 0 : Math.round(((clampedX - padL) / plotW) * (count - 1));
    setHoverIdx(Math.max(0, Math.min(count - 1, idx)));
  }

  if (count === 0) {
    return (
      <div
        className="flex items-center justify-center rounded-xl border border-dashed border-line text-xs text-muted"
        style={{ height }}
      >
        {emptyLabel}
      </div>
    );
  }

  const activeIdx = hoverIdx != null && hoverIdx < count ? hoverIdx : null;
  const activeX =
    activeIdx != null
      ? count <= 1
        ? padL + plotW
        : padL + (activeIdx / (count - 1)) * plotW
      : null;

  const unit = series[0]?.unit ?? "";

  return (
    <div ref={containerRef} className="relative select-none">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full overflow-visible touch-pan-y"
        style={{ height }}
        onPointerMove={handlePointerMove}
        onPointerLeave={() => setHoverIdx(null)}
      >
        <defs>
          {computedSeries.map((s, idx) => (
            <linearGradient key={idx} id={`qm-area-${uid}-${idx}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" style={{ stopColor: s.fillStart, stopOpacity: 0.22 }} />
              <stop offset="100%" style={{ stopColor: s.fillStart, stopOpacity: 0.01 }} />
            </linearGradient>
          ))}
        </defs>

        {/* Horizontal grid lines + Y ticks */}
        {ticks.map((t, idx) => {
          const y = padT + (1 - (t - minVal) / span) * plotH;
          return (
            <g key={idx}>
              <line
                x1={padL}
                y1={y}
                x2={padL + plotW}
                y2={y}
                stroke="currentColor"
                className="text-line"
              />
              <text
                x={padL - 8}
                y={y + 3}
                textAnchor="end"
                className="fill-muted text-[9.5px] qm-tabular"
              >
                {formatTickValue(t, span, "")}
              </text>
            </g>
          );
        })}

        {/* Area fills */}
        {computedSeries.map((s, idx) =>
          s.areaPath ? (
            <path key={`a-${idx}`} d={s.areaPath} fill={`url(#qm-area-${uid}-${idx})`} />
          ) : null
        )}

        {/* Spline paths + live endpoint */}
        {computedSeries.map((s, idx) => {
          const last = s.coords[s.coords.length - 1];
          return (
            <g key={`l-${idx}`}>
              {s.linePath && (
                <path
                  d={s.linePath}
                  fill="none"
                  style={{ stroke: s.stroke }}
                  strokeWidth="2.1"
                  strokeLinecap="round"
                />
              )}
              {last && activeIdx == null && (
                <g>
                  <circle cx={last.x} cy={last.y} r="5" style={{ fill: s.stroke }} opacity="0.2" />
                  <circle cx={last.x} cy={last.y} r="2.75" style={{ fill: s.stroke }} />
                </g>
              )}
            </g>
          );
        })}

        {/* Editorial Plum Peak Callout Badge */}
        {peakPoint && activeIdx == null && (
          <g>
            {(() => {
              const pillW = Math.max(46, peakPoint.text.length * 6.2 + 14);
              const px = Math.max(padL + pillW / 2, Math.min(padL + plotW - pillW / 2, peakPoint.x));
              const tipX = Math.max(px - pillW / 2 + 6, Math.min(px + pillW / 2 - 6, peakPoint.x));
              const py = Math.max(16, peakPoint.y - 12);
              return (
                <>
                  <rect
                    x={px - pillW / 2}
                    y={py - 14}
                    width={pillW}
                    height={16}
                    rx={6}
                    style={{ fill: "var(--qm-ink)" }}
                  />
                  <polygon
                    points={`${tipX - 4},${py + 2} ${tipX + 4},${py + 2} ${tipX},${py + 6}`}
                    style={{ fill: "var(--qm-ink)" }}
                  />
                  <text
                    x={px}
                    y={py - 3.5}
                    textAnchor="middle"
                    style={{ fill: "var(--qm-paper)" }}
                    className="text-[9px] font-bold qm-tabular"
                  >
                    {peakPoint.text}
                  </text>
                </>
              );
            })()}
          </g>
        )}

        {/* X axis edge labels */}
        {labels && labels.length > 0 && (
          <g>
            <text
              x={padL}
              y={height - 4}
              textAnchor="start"
              className="fill-muted text-[9.5px] qm-tabular"
            >
              {labels[0]}
            </text>
            {labels.length > 2 && (
              <text
                x={padL + plotW / 2}
                y={height - 4}
                textAnchor="middle"
                className="fill-muted text-[9.5px] qm-tabular"
              >
                {labels[Math.floor(labels.length / 2)]}
              </text>
            )}
            <text
              x={padL + plotW}
              y={height - 4}
              textAnchor="end"
              className="fill-muted text-[9.5px] qm-tabular"
            >
              {labels[labels.length - 1]}
            </text>
          </g>
        )}

        {/* Hover crosshair + active dots */}
        {activeIdx != null && activeX != null && (
          <g>
            <line
              x1={activeX}
              y1={padT}
              x2={activeX}
              y2={padT + plotH}
              style={{ stroke: "var(--qm-muted)" }}
              strokeDasharray="3 3"
              opacity="0.55"
            />
            {computedSeries.map((s, idx) => {
              const pt = s.coords[activeIdx];
              if (!pt) return null;
              return (
                <circle
                  key={`h-${idx}`}
                  cx={pt.x}
                  cy={pt.y}
                  r="4"
                  style={{ fill: s.stroke, stroke: "var(--qm-surface)" }}
                  strokeWidth="1.5"
                />
              );
            })}
          </g>
        )}
      </svg>

      {/* Bottom Centered Dot Legend */}
      <div className="mt-1 flex items-center justify-center gap-5 text-xs text-ink-2">
        {series.map((s) => (
          <div key={s.label} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-3.5 rounded-full" style={{ backgroundColor: s.stroke }} />
            <span className="font-medium">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Floating Hover Callout Pill */}
      {activeIdx != null && activeX != null && (
        <div
          data-testid="chart-hover-tooltip"
          className="pointer-events-none absolute top-1 z-20 rounded-lg border border-line bg-ink text-paper px-2.5 py-1.5 text-[11px] shadow-md"
          style={{
            left: `${Math.max(10, Math.min(72, (activeX / width) * 100))}%`,
          }}
        >
          {labels?.[activeIdx] && (
            <div className="text-[10px] opacity-70 mb-0.5 qm-tabular">
              {labels[activeIdx]}
            </div>
          )}
          <div className="space-y-0.5">
            {series.map((s, i) => {
              const val = s.values[activeIdx];
              if (val == null) return null;
              return (
                <div key={i} className="flex items-center gap-2 qm-tabular">
                  <span
                    className="h-2 w-2 rounded-full shrink-0"
                    style={{ backgroundColor: s.stroke }}
                  />
                  <span className="opacity-80">{s.label}:</span>
                  <span className="font-semibold">
                    {formatTickValue(val, span, s.unit ?? unit)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
});

export function SmoothAreaChart({
  values,
  labels,
  label = "Value",
  stroke = "var(--qm-ember)",
  unit = "",
  height = 175,
  minOverride,
  maxOverride,
  emptyLabel,
}: {
  values: number[];
  labels?: string[];
  label?: string;
  stroke?: string;
  unit?: string;
  height?: number;
  minOverride?: number;
  maxOverride?: number;
  emptyLabel?: string;
}) {
  return (
    <InteractiveAreaChart
      series={[{ label, values, stroke, fillStart: stroke, unit }]}
      labels={labels}
      height={height}
      minOverride={minOverride}
      maxOverride={maxOverride}
      emptyLabel={emptyLabel}
    />
  );
}

export function DualAreaChart({
  primaryValues,
  secondaryValues,
  labels,
  primaryLabel = "Download",
  secondaryLabel = "Upload",
  primaryColor = "var(--qm-jade)",
  secondaryColor = "var(--qm-berry)",
  unit = "Mbps",
  height = 175,
}: {
  primaryValues: number[];
  secondaryValues: number[];
  labels?: string[];
  primaryLabel?: string;
  secondaryLabel?: string;
  primaryColor?: string;
  secondaryColor?: string;
  unit?: string;
  height?: number;
}) {
  return (
    <InteractiveAreaChart
      series={[
        { label: primaryLabel, values: primaryValues, stroke: primaryColor, fillStart: primaryColor, unit },
        { label: secondaryLabel, values: secondaryValues, stroke: secondaryColor, fillStart: secondaryColor, unit },
      ]}
      labels={labels}
      height={height}
      minOverride={0}
    />
  );
}

const PLUM_PALETTE = ["var(--qm-ember)", "var(--qm-berry)", "var(--qm-saffron)", "var(--qm-jade)", "var(--qm-muted)"];

export interface DonutSlice {
  label: string;
  value: number;
  displayValue?: string;
  color?: string;
}

export function DonutInsightsChart({
  slices,
  centerTop,
  centerSub,
}: {
  slices: DonutSlice[];
  centerTop?: string;
  centerSub?: string;
}) {
  const valid = slices.filter((s) => s.value > 0);
  const total = valid.reduce((acc, s) => acc + s.value, 0);

  if (valid.length === 0 || total <= 0) {
    return (
      <div className="py-6 text-center text-xs text-muted">
        Collecting distribution telemetry…
      </div>
    );
  }

  const size = 132;
  const cx = size / 2;
  const cy = size / 2;
  const r = 44;
  const circ = 2 * Math.PI * r;

  let offset = 0;
  const segments = valid.map((s, idx) => {
    const pct = s.value / total;
    const rawLen = pct * circ;
    const gap = valid.length > 1 ? Math.min(2.5, rawLen * 0.25) : 0;
    const dash = Math.max(1, rawLen - gap);
    const seg = {
      ...s,
      pctRounded: Math.round(pct * 100),
      color: s.color ?? PLUM_PALETTE[idx % PLUM_PALETTE.length],
      dashArray: `${dash} ${circ - dash}`,
      dashOffset: -offset,
    };
    offset += rawLen;
    return seg;
  });

  return (
    <div className="flex flex-col sm:flex-row items-center gap-5">
      <div className="relative h-[132px] w-[132px] shrink-0">
        <svg viewBox={`0 0 ${size} ${size}`} className="h-full w-full -rotate-90">
          {segments.map((seg, i) => (
            <circle
              key={i}
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              style={{ stroke: seg.color }}
              strokeWidth="22"
              strokeDasharray={seg.dashArray}
              strokeDashoffset={seg.dashOffset}
            />
          ))}
        </svg>
        {(centerTop || centerSub) && (
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center leading-tight">
            {centerTop && (
              <span className="text-sm font-bold text-ink qm-tabular">
                {centerTop}
              </span>
            )}
            {centerSub && (
              <span className="text-[10px] text-muted">{centerSub}</span>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 w-full space-y-2">
        {segments.map((seg, idx) => (
          <div key={idx} className="flex items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2 min-w-0">
              <span
                className="h-2.5 w-2.5 rounded-full shrink-0"
                style={{ backgroundColor: seg.color }}
              />
              <span className="text-ink-2 truncate">{seg.label}</span>
            </div>
            <span className="font-bold text-ink qm-tabular shrink-0">
              {seg.displayValue ?? `${seg.pctRounded}%`}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
