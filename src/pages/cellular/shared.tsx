import React from "react";
import { Button, Modal } from "../../components/ui";
import { cn } from "../../lib/utils";

export type Tone = "jade" | "saffron" | "crimson" | "ember" | "muted";

/** RSRP → semantic tone. Same thresholds as `signalQuality`, without SINR. */
export function rsrpTone(v: number | null | undefined): Tone {
  if (v == null) return "muted";
  if (v >= -98) return "jade";
  if (v >= -108) return "saffron";
  return "crimson";
}

export function rsrpWord(v: number | null | undefined): string {
  if (v == null) return "No reading";
  if (v >= -85) return "Excellent";
  if (v >= -98) return "Strong";
  if (v >= -108) return "Fair";
  return "Weak";
}

export const TONE_BG: Record<Tone, string> = {
  jade: "bg-jade",
  saffron: "bg-saffron",
  crimson: "bg-crimson",
  ember: "bg-ember",
  muted: "bg-line-strong",
};

export const TONE_TEXT: Record<Tone, string> = {
  jade: "text-jade-ink",
  saffron: "text-saffron-ink",
  crimson: "text-crimson-ink",
  ember: "text-ember-ink",
  muted: "text-muted",
};

export const TONE_SOFT: Record<Tone, string> = {
  jade: "bg-jade-soft",
  saffron: "bg-saffron-soft",
  crimson: "bg-crimson-soft",
  ember: "bg-ember-soft",
  muted: "bg-sunk",
};

/** RSRP mapped to 0–100 on a −130…−70 dBm scale. */
export function rsrpPct(v: number | null | undefined): number {
  if (v == null) return 0;
  return Math.max(3, Math.min(100, ((v + 130) / 60) * 100));
}

/** A compact horizontal signal bar with an optional reference tick. */
export function SignalBar({
  value,
  reference,
  className,
}: {
  value: number | null | undefined;
  reference?: number | null;
  className?: string;
}) {
  const tone = rsrpTone(value);
  return (
    <div className={cn("relative h-2 rounded-full bg-line/80 overflow-hidden", className)}>
      <div
        className={cn("h-full rounded-full transition-[width] duration-500", TONE_BG[tone])}
        style={{ width: `${rsrpPct(value)}%` }}
      />
      {reference != null && (
        <div
          className="absolute inset-y-0 w-0.5 bg-ink/70"
          style={{ left: `calc(${rsrpPct(reference)}% - 1px)` }}
          title={`Your cell: ${reference} dBm`}
        />
      )}
    </div>
  );
}

/** Label with an optional technical term rendered as quiet secondary text. */
export function Field({
  label,
  term,
  htmlFor,
  children,
  className,
}: {
  label: string;
  term?: string;
  htmlFor?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <label htmlFor={htmlFor} className="mb-1.5 flex items-baseline gap-1.5 text-[12.5px] font-semibold text-ink-2">
        {label}
        {term && <span className="font-mono text-[11px] font-medium text-muted">{term}</span>}
      </label>
      {children}
    </div>
  );
}

/** Radio-style choice tile: plain label first, technical term second. */
export function ChoiceTile({
  selected,
  onClick,
  label,
  term,
  hint,
  icon,
}: {
  selected: boolean;
  onClick: () => void;
  label: string;
  term?: string;
  hint?: string;
  icon?: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={onClick}
      className={cn(
        "group relative flex min-h-[4.25rem] w-full items-start gap-3 rounded-2xl border px-3.5 py-3 text-left transition cursor-pointer",
        selected
          ? "border-ember bg-ember-soft shadow-[0_8px_20px_-14px_var(--qm-ember)]"
          : "border-line bg-raised hover:border-line-strong"
      )}
    >
      <span
        className={cn(
          "mt-0.5 flex h-[1.1rem] w-[1.1rem] shrink-0 items-center justify-center rounded-full border-2 transition",
          selected ? "border-ember" : "border-line-strong"
        )}
      >
        <span className={cn("h-2 w-2 rounded-full transition", selected ? "bg-ember" : "bg-transparent")} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5 text-[13.5px] font-semibold text-ink">
          {icon}
          {label}
        </span>
        {(hint || term) && (
          <span className="mt-0.5 block text-[12px] leading-snug text-muted">
            {hint}
            {hint && term && " · "}
            {term && <span className="font-mono text-[11px]">{term}</span>}
          </span>
        )}
      </span>
    </button>
  );
}

/** Confirmation dialog for actions that drop the link or remove data. */
export function ConfirmModal({
  open,
  title,
  body,
  confirmLabel,
  tone = "danger",
  busy,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  tone?: "danger" | "primary";
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal open={open} onClose={onClose} title={title}>
      <div className="space-y-5">
        <div className="leading-relaxed">{body}</div>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={tone} onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function EmptyState({ icon, title, children }: { icon: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-line-strong px-6 py-10 text-center">
      <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-ember-soft text-ember-ink">{icon}</div>
      <div className="qm-display text-[1.05rem] font-semibold text-ink">{title}</div>
      {children && <div className="max-w-sm text-[13px] text-muted">{children}</div>}
    </div>
  );
}

/** Small key/value pair used in summary strips. */
export function Fact({ label, value, unit, tone }: { label: string; value: React.ReactNode; unit?: string; tone?: Tone }) {
  return (
    <div className="min-w-0">
      <div className="text-[11.5px] font-semibold text-muted">{label}</div>
      <div className={cn("mt-0.5 flex items-baseline gap-1 qm-display text-[1.35rem] font-semibold leading-tight qm-tabular", tone ? TONE_TEXT[tone] : "text-ink")}>
        <span className="truncate">{value}</span>
        {unit && <span className="font-sans text-[11.5px] font-semibold text-muted">{unit}</span>}
      </div>
    </div>
  );
}
