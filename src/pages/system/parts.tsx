import React from "react";
import { cn } from "../../lib/utils";

/** Form label + control + optional hint, with consistent rhythm. */
export function Field({
  label,
  htmlFor,
  hint,
  aside,
  children,
  className,
}: {
  label: string;
  htmlFor?: string;
  hint?: React.ReactNode;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <label htmlFor={htmlFor} className="text-[12.5px] font-semibold text-ink-2">
          {label}
        </label>
        {aside}
      </div>
      {children}
      {hint && <p className="mt-1.5 text-[11.5px] text-muted leading-snug">{hint}</p>}
    </div>
  );
}

/** Small tone dot + text, used for inline verdicts. */
export function Verdict({
  tone,
  children,
  className,
}: {
  tone: "jade" | "saffron" | "crimson" | "ember" | "muted";
  children: React.ReactNode;
  className?: string;
}) {
  const dot = { jade: "bg-jade", saffron: "bg-saffron", crimson: "bg-crimson", ember: "bg-ember", muted: "bg-muted" }[tone];
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span className={cn("h-2 w-2 shrink-0 rounded-full", dot)} />
      {children}
    </span>
  );
}

/* ───────────────────────── Heat scale ───────────────────────── */

/** Scale shown on the thermal rail (°C). The SDX75 starts throttling in the 90s. */
export const HEAT_MIN = 20;
export const HEAT_MAX = 95;
export const HEAT_WARM = 65;
export const HEAT_HOT = 80;

const clamp01 = (n: number) => Math.max(0, Math.min(1, n));

export function heatPct(celsius: number): number {
  return clamp01((celsius - HEAT_MIN) / (HEAT_MAX - HEAT_MIN)) * 100;
}

/** cool (jade) → saffron at 60 °C → crimson at 85 °C, mixed from theme tokens. */
export function heatColor(celsius: number): string {
  if (celsius <= 60) {
    const p = clamp01((celsius - 30) / 30) * 100;
    return `color-mix(in oklab, var(--qm-saffron) ${p.toFixed(0)}%, var(--qm-jade))`;
  }
  const p = clamp01((celsius - 60) / 25) * 100;
  return `color-mix(in oklab, var(--qm-crimson) ${p.toFixed(0)}%, var(--qm-saffron))`;
}

export const HEAT_GRADIENT =
  "linear-gradient(90deg, var(--qm-jade) 0%, var(--qm-jade) 13%, var(--qm-saffron) 53%, var(--qm-crimson) 87%, var(--qm-crimson) 100%)";

export function heatVerdict(celsius: number | null): {
  label: string;
  note: string;
  tone: "jade" | "saffron" | "crimson" | "muted";
  ink: string;
} {
  if (celsius == null) return { label: "No sensors", note: "Waiting for thermal data from the modem.", tone: "muted", ink: "text-muted" };
  if (celsius >= HEAT_HOT)
    return { label: "Running hot", note: "Close to thermal throttling. Check airflow and enclosure.", tone: "crimson", ink: "text-crimson-ink" };
  if (celsius >= HEAT_WARM)
    return { label: "Running warm", note: "Within limits, but above the comfortable range.", tone: "saffron", ink: "text-saffron-ink" };
  return { label: "Running cool", note: "Every die is well below throttling.", tone: "jade", ink: "text-jade-ink" };
}

export function heatInk(celsius: number): string {
  return celsius >= HEAT_HOT ? "text-crimson-ink" : celsius >= HEAT_WARM ? "text-saffron-ink" : "text-jade-ink";
}
