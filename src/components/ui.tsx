import React, { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, Copy, X } from "lucide-react";
import { cn, copyToClipboard } from "../lib/utils";
import { sectionFor, subFor } from "../lib/nav";
import { hrefFor, type Section } from "../stores/route-store";
import { useToastStore } from "../stores/toast-store";

export const APP_VERSION = typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "1.0.0";

/* ───────────────────────── Brand ───────────────────────── */

export function BrandMark({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "relative flex h-9 w-9 shrink-0 items-center justify-center rounded-[0.8rem] qm-sun text-on-ember shadow-[0_8px_20px_-8px_var(--qm-ember)]",
        className
      )}
    >
      <svg viewBox="0 0 24 24" className="h-[1.35rem] w-[1.35rem]" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round">
        {/* Outer cellular hexagon */}
        <polygon points="12,2.2 20.5,7.1 20.5,16.9 12,21.8 3.5,16.9 3.5,7.1" strokeWidth="1.9" />
        {/* 3-sector RF spokes */}
        <path d="M12 12V3.2M12 12l7.6 4.4M12 12l-7.6 4.4" strokeWidth="1.25" opacity=".45" />
        {/* Concentric 3-sector RF wave arcs */}
        <path d="M8.8 9.2a4.6 4.6 0 0 1 6.4 0" strokeWidth="1.75" opacity=".9" />
        <path d="M16.4 10.6a4.6 4.6 0 0 1-2.8 5.6" strokeWidth="1.75" opacity=".9" />
        <path d="M10.4 16.2a4.6 4.6 0 0 1-2.8-5.6" strokeWidth="1.75" opacity=".9" />
        {/* Solid RF core + vertex nodes */}
        <circle cx="12" cy="12" r="2.3" fill="currentColor" stroke="none" />
        <circle cx="12" cy="2.4" r="1.25" fill="currentColor" stroke="none" />
        <circle cx="20.3" cy="16.8" r="1.25" fill="currentColor" stroke="none" />
        <circle cx="3.7" cy="16.8" r="1.25" fill="currentColor" stroke="none" />
      </svg>
    </div>
  );
}

export function BrandLogo({ compact = false, subtitle }: { compact?: boolean; subtitle?: string }) {
  return (
    <div className="flex items-center gap-2.5 select-none min-w-0">
      <BrandMark />
      {!compact && (
        <div className="leading-tight min-w-0">
          <div className="flex items-baseline gap-1.5">
            <span className="qm-display text-[1.05rem] font-semibold text-ink">CellCore</span>
            <span className="text-[10px] font-bold text-ember-ink qm-tabular">{APP_VERSION}</span>
          </div>
          {subtitle && <div className="text-[11px] text-muted truncate max-w-[200px]">{subtitle}</div>}
        </div>
      )}
    </div>
  );
}

/* ───────────────────────── Layout ───────────────────────── */

export function Card({ children, className, ...rest }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("qm-card p-[var(--qm-pad)] transition-colors", className)} {...rest}>
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  icon,
  action,
  className,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-3 mb-4", className)}>
      <div className="flex items-start gap-3 min-w-0">
        {icon && (
          <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-ember-soft text-ember-ink">
            {icon}
          </div>
        )}
        <div className="min-w-0">
          <h3 className="qm-display text-[1.12rem] font-semibold leading-snug text-ink">{title}</h3>
          {subtitle && <p className="text-[12.5px] text-muted mt-0.5 leading-snug">{subtitle}</p>}
        </div>
      </div>
      {action && <div className="shrink-0 flex flex-wrap items-center gap-1.5">{action}</div>}
    </div>
  );
}

/**
 * Page header: section eyebrow, large title for the active sub-view, hint, actions.
 * On small screens it also renders the sub-view switcher (the rail is hidden there).
 */
export function PageHeader({
  section,
  sub,
  onSubChange,
  title,
  hint,
  actions,
}: {
  section: Section;
  sub?: string | null;
  onSubChange?: (id: string) => void;
  title?: React.ReactNode;
  hint?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  const sec = sectionFor(section);
  const active = sec.subs.length ? subFor(section, sub ?? null) : null;
  return (
    <header className="qm-rise space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="qm-eyebrow flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full qm-sun" />
            {sec.label}
          </div>
          <h1 className="qm-display mt-1.5 text-[2rem] sm:text-[2.4rem] font-semibold leading-[1.05] text-ink">
            {title ?? active?.label ?? sec.label}
          </h1>
          <p className="mt-1.5 text-[13.5px] text-ink-2/80 max-w-xl">{hint ?? active?.hint ?? sec.hint}</p>
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {sec.subs.length > 0 && (
        <nav className="qm-subchips -mx-4 px-4 overflow-x-auto" aria-label={`${sec.label} sections`}>
          <div className="flex gap-1.5 w-max">
            {sec.subs.map((s) => {
              const on = s.id === active?.id;
              return (
                <a
                  key={s.id}
                  href={hrefFor(section, s.id)}
                  onClick={(e) => {
                    if (onSubChange) {
                      e.preventDefault();
                      onSubChange(s.id);
                    }
                  }}
                  className={cn(
                    "rounded-full border px-3.5 py-1.5 text-[12.5px] font-semibold whitespace-nowrap transition",
                    on
                      ? "border-transparent bg-ink text-paper"
                      : "border-line bg-surface text-ink-2 hover:border-line-strong"
                  )}
                >
                  {s.label}
                </a>
              );
            })}
          </div>
        </nav>
      )}
    </header>
  );
}

/* ───────────────────────── Atoms ───────────────────────── */

export type BadgeVariant = "neutral" | "success" | "sage" | "info" | "plum" | "warning" | "danger";

const BADGE: Record<BadgeVariant, string> = {
  neutral: "bg-sunk text-ink-2 border-line",
  success: "bg-jade-soft text-jade-ink border-transparent",
  sage: "bg-ember-soft text-ember-ink border-transparent",
  info: "bg-ember-soft text-ember-ink border-transparent",
  plum: "bg-berry-soft text-berry-ink border-transparent",
  warning: "bg-saffron-soft text-saffron-ink border-transparent",
  danger: "bg-crimson-soft text-crimson-ink border-transparent",
};

export function Badge({
  children,
  variant = "neutral",
  className,
  dot = false,
}: {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
  dot?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11.5px] font-semibold leading-[1.15rem] whitespace-nowrap qm-tabular",
        BADGE[variant],
        className
      )}
    >
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

export function LiveDot({ tone = "jade", className }: { tone?: "jade" | "ember" | "saffron" | "crimson" | "muted"; className?: string }) {
  const map = {
    jade: "text-jade bg-jade",
    ember: "text-ember bg-ember",
    saffron: "text-saffron bg-saffron",
    crimson: "text-crimson bg-crimson",
    muted: "text-muted bg-muted",
  } as const;
  return <span className={cn("inline-block h-2 w-2 rounded-full qm-live-dot", map[tone], className)} />;
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded-md border border-line-strong bg-raised px-1 text-[10.5px] font-semibold text-ink-2">
      {children}
    </kbd>
  );
}

type ButtonVariant = "primary" | "tier1" | "tier2" | "tier3" | "secondary" | "ghost" | "danger" | "success";
type ButtonSize = "sm" | "md" | "lg";

const BTN: Record<ButtonVariant, string> = {
  primary:
    "bg-ember text-on-ember border border-transparent shadow-[0_6px_16px_-8px_var(--qm-ember)] hover:brightness-[1.06] active:brightness-95",
  tier1:
    "qm-sun-ink text-on-ember border border-transparent shadow-[0_10px_24px_-10px_var(--qm-ember)] hover:brightness-[1.05] active:brightness-95",
  tier2: "bg-ink text-paper border border-transparent hover:opacity-90",
  tier3: "bg-ember-soft text-ember-ink border border-transparent hover:brightness-[0.97]",
  secondary: "bg-raised text-ink border border-line hover:border-line-strong hover:bg-sunk",
  ghost: "bg-transparent text-ink-2 border border-transparent hover:bg-sunk hover:text-ink",
  danger: "bg-crimson text-on-crimson border border-transparent hover:brightness-[1.06]",
  success: "bg-jade text-on-jade border border-transparent hover:brightness-[1.06]",
};

const BTN_SIZE: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-[12.5px] rounded-full",
  md: "h-9 px-4 text-[13px] rounded-full",
  lg: "h-11 px-5 text-[14px] rounded-2xl",
};

export function Button({
  children,
  variant = "secondary",
  size = "md",
  className,
  type = "button",
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: ButtonSize }) {
  return (
    <button
      type={type}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 font-semibold transition-all cursor-pointer select-none disabled:opacity-45 disabled:cursor-not-allowed whitespace-nowrap active:translate-y-px",
        BTN[variant],
        BTN_SIZE[size],
        className
      )}
      {...rest}
    >
      {children}
    </button>
  );
}

export function StatTile({
  label,
  value,
  sub,
  icon,
  tone = "neutral",
  rightAction,
  className,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon?: React.ReactNode;
  tone?: "neutral" | "cyan" | "emerald" | "amber" | "rose";
  rightAction?: React.ReactNode;
  className?: string;
}) {
  const toneClass: Record<string, string> = {
    neutral: "text-ink",
    cyan: "text-ember-ink",
    emerald: "text-jade-ink",
    amber: "text-saffron-ink",
    rose: "text-crimson-ink",
  };
  const longText = typeof value === "string" && value.length > 14;
  return (
    <div className={cn("qm-subcard p-4 flex flex-col justify-between min-w-0", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[12px] font-semibold text-muted truncate">
          {icon && <span className="shrink-0">{icon}</span>}
          <span className="truncate">{label}</span>
        </span>
        {rightAction}
      </div>
      <div
        className={cn(
          "mt-2 qm-display font-semibold truncate leading-none",
          longText ? "text-[1.05rem]" : "text-[1.75rem]",
          toneClass[tone]
        )}
      >
        {value}
      </div>
      {sub && <div className="mt-1.5 text-[11.5px] text-muted truncate">{sub}</div>}
    </div>
  );
}

/** Horizontal meter with tone thresholds. */
export function Meter({
  pct,
  tone = "ember",
  className,
  thin = false,
}: {
  pct: number;
  tone?: "ember" | "sun" | "jade" | "saffron" | "crimson" | "berry" | "muted";
  className?: string;
  thin?: boolean;
}) {
  const fill = {
    ember: "bg-ember",
    sun: "qm-sun",
    jade: "bg-jade",
    saffron: "bg-saffron",
    crimson: "bg-crimson",
    berry: "bg-berry",
    muted: "bg-line-strong",
  }[tone];
  return (
    <div className={cn("rounded-full bg-line/80 overflow-hidden", thin ? "h-1.5" : "h-2.5", className)}>
      <div
        className={cn("h-full rounded-full transition-[width] duration-500 ease-out", fill)}
        style={{ width: `${Math.max(0, Math.min(100, pct))}%` }}
      />
    </div>
  );
}

export function Input({ className, ...rest }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "w-full h-10 rounded-xl border border-line bg-raised px-3.5 text-[13px] text-ink placeholder:text-muted/80 focus:outline-none focus:ring-4 focus:ring-ember/15 focus:border-ember transition",
        className
      )}
      {...rest}
    />
  );
}

export function Select({ className, children, ...rest }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "w-full h-10 rounded-xl border border-line bg-raised px-3 text-[13px] text-ink focus:outline-none focus:ring-4 focus:ring-ember/15 focus:border-ember transition cursor-pointer",
        className
      )}
      {...rest}
    >
      {children}
    </select>
  );
}

export function SegmentedTabs<T extends string>({
  options,
  value,
  onChange,
  className,
}: {
  options: Array<{ id: T; label: string; icon?: React.ReactNode; badge?: string | number }>;
  value: T;
  onChange: (id: T) => void;
  className?: string;
}) {
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  return (
    <div
      role="tablist"
      className={cn("inline-flex flex-wrap items-center gap-0.5 rounded-full border border-line bg-sunk p-1 max-w-full", className)}
    >
      {options.map((opt, idx) => {
        const active = opt.id === value;
        return (
          <button
            key={opt.id}
            ref={(el) => {
              tabRefs.current[idx] = el;
            }}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(opt.id)}
            onKeyDown={(e) => {
              let nextIdx = -1;
              if (e.key === "ArrowRight") nextIdx = (idx + 1) % options.length;
              else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + options.length) % options.length;
              else if (e.key === "Home") nextIdx = 0;
              else if (e.key === "End") nextIdx = options.length - 1;
              if (nextIdx >= 0) {
                e.preventDefault();
                onChange(options[nextIdx].id);
                tabRefs.current[nextIdx]?.focus();
              }
            }}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12.5px] font-semibold transition-all cursor-pointer whitespace-nowrap",
              active ? "bg-raised text-ink shadow-[0_2px_8px_-3px_rgba(0,0,0,0.3)]" : "text-muted hover:text-ink"
            )}
          >
            {opt.icon}
            <span>{opt.label}</span>
            {opt.badge !== undefined && opt.badge !== "" && (
              <span
                className={cn(
                  "rounded-full px-1.5 text-[10px] qm-tabular",
                  active ? "bg-ember-soft text-ember-ink" : "bg-sunk text-ink-2"
                )}
              >
                {opt.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function Switch({
  checked,
  onChange,
  disabled = false,
  label,
  description,
  ariaLabel,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label?: string;
  description?: string;
  ariaLabel?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      {(label || description) && (
        <div className="min-w-0">
          {label && <div className="text-[13px] font-semibold text-ink">{label}</div>}
          {description && <div className="text-[12px] text-muted mt-0.5">{description}</div>}
        </div>
      )}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabel ?? label}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        className={cn(
          "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed",
          checked ? "bg-ember" : "bg-line-strong"
        )}
      >
        <span
          className={cn(
            "inline-block h-[1.1rem] w-[1.1rem] rounded-full bg-white shadow transition-transform",
            checked ? "translate-x-[1.4rem]" : "translate-x-[0.2rem]"
          )}
        />
      </button>
    </div>
  );
}

export function CopyButton({ value, label, className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  async function handleCopy() {
    if (!value) return;
    if (await copyToClipboard(value)) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    }
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? "Copied" : `Copy ${label ?? "value"}`}
      aria-label={copied ? "Copied" : `Copy ${label ?? "value"}`}
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[11px] font-semibold text-muted hover:text-ember-ink hover:bg-ember-soft transition cursor-pointer shrink-0",
        className
      )}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-jade-ink" /> : <Copy className="h-3.5 w-3.5" />}
      {label && <span>{copied ? "Copied" : label}</span>}
    </button>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-2xl bg-line/70", className)} />;
}

/* ───────────────────────── Signal ───────────────────────── */

export type SignalQuality = { label: string; tone: "jade" | "ember" | "saffron" | "crimson" | "muted"; badge: BadgeVariant };

export function signalQuality(rsrp: number | null | undefined, sinr?: number | null): SignalQuality {
  if (rsrp == null) return { label: "No signal", tone: "muted", badge: "neutral" };
  if (rsrp >= -85 && (sinr == null || sinr >= 15)) return { label: "Excellent", tone: "jade", badge: "success" };
  if (rsrp >= -98 && (sinr == null || sinr >= 8)) return { label: "Strong", tone: "jade", badge: "success" };
  if (rsrp >= -108) return { label: "Fair", tone: "saffron", badge: "warning" };
  return { label: "Weak", tone: "crimson", badge: "danger" };
}

/**
 * The hero dial: a 260° arc filled with the sunset gradient, tick marks every 5 dB,
 * and the value set in the display face. Used on Now and the login preview.
 */
export function SignalDial({
  value,
  min = -125,
  max = -70,
  unit = "dBm",
  caption,
  size = 220,
  onDark = false,
}: {
  value: number | null;
  min?: number;
  max?: number;
  unit?: string;
  caption?: React.ReactNode;
  size?: number;
  onDark?: boolean;
}) {
  const gid = useId().replace(/:/g, "");
  const shown = value;
  const sweep = 260;
  const start = 90 + (360 - sweep) / 2; // degrees, SVG 0° = east, clockwise
  const r = 84;
  const c = 100;
  const frac = shown == null ? 0 : Math.max(0.02, Math.min(1, (shown - min) / (max - min)));
  const polar = (deg: number, rad: number) => {
    const a = (deg * Math.PI) / 180;
    return [c + rad * Math.cos(a), c + rad * Math.sin(a)] as const;
  };
  const arc = (from: number, to: number, rad: number) => {
    const [x1, y1] = polar(from, rad);
    const [x2, y2] = polar(to, rad);
    const large = to - from > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${rad} ${rad} 0 ${large} 1 ${x2} ${y2}`;
  };
  const end = start + sweep * frac;
  const [kx, ky] = polar(end, r);
  const ticks = [];
  for (let v = min; v <= max; v += 5) {
    const deg = start + ((v - min) / (max - min)) * sweep;
    const major = v % 10 === 0;
    const [x1, y1] = polar(deg, r - 15);
    const [x2, y2] = polar(deg, r - (major ? 22 : 19));
    ticks.push(
      <line
        key={v}
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        strokeWidth={major ? 1.6 : 1}
        className={onDark ? "stroke-on-ember/35" : "stroke-line-strong"}
        strokeLinecap="round"
      />
    );
  }
  return (
    <div className="relative" style={{ width: size, height: size * 0.86 }}>
      <svg viewBox="0 0 200 172" className="w-full h-full overflow-visible">
        <defs>
          <linearGradient id={`dial-${gid}`} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" style={{ stopColor: "var(--qm-dial-a)" }} />
            <stop offset="55%" style={{ stopColor: "var(--qm-dial-b)" }} />
            <stop offset="100%" style={{ stopColor: "var(--qm-dial-c)" }} />
          </linearGradient>
          <filter id={`glow-${gid}`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" />
          </filter>
        </defs>
        <path
          d={arc(start, start + sweep, r)}
          fill="none"
          strokeWidth="13"
          strokeLinecap="round"
          className={onDark ? "stroke-on-ember/15" : "stroke-line"}
        />
        {ticks}
        {shown != null && (
          <>
            <path d={arc(start, end, r)} fill="none" stroke={`url(#dial-${gid})`} strokeWidth="13" strokeLinecap="round" opacity=".55" filter={`url(#glow-${gid})`} />
            <path
              d={arc(start, end, r)}
              fill="none"
              stroke={`url(#dial-${gid})`}
              strokeWidth="13"
              strokeLinecap="round"
              style={{ transition: "d 600ms cubic-bezier(.2,.7,.2,1)" }}
            />
            <circle cx={kx} cy={ky} r="8.5" fill="#fff" style={{ stroke: "var(--qm-dial-b)" }} strokeWidth="3" />
          </>
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-1 text-center pointer-events-none">
        <div className={cn("qm-display font-semibold leading-none", onDark ? "text-on-ember" : "text-ink")} style={{ fontSize: size * 0.24 }}>
          {shown ?? "––"}
        </div>
        <div className={cn("mt-1 text-[12px] font-semibold tracking-wide", onDark ? "text-on-ember" : "text-muted")}>{unit}</div>
        {caption && <div className="mt-2">{caption}</div>}
      </div>
    </div>
  );
}

/** Back-compat compact gauge used by older pages. */
export function SignalGauge({ rsrp, sinr, rat }: { rsrp: number | null; sinr: number | null; rat?: string }) {
  const q = signalQuality(rsrp, sinr);
  return (
    <div className="flex flex-col items-center">
      <SignalDial value={rsrp} size={150} unit={rat ? `dBm · ${rat}` : "dBm"} />
      <Badge variant={q.badge} className="-mt-3" dot>
        {q.label}
      </Badge>
    </div>
  );
}

/* ───────────────────────── Overlays ───────────────────────── */

const modalStack: string[] = [];

export function Modal({
  open,
  onClose,
  title,
  zIndexClass = "z-[60]",
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  zIndexClass?: string;
  children: React.ReactNode;
}) {
  const modalId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    modalStack.push(modalId);
    const prevActive = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const prevOverflow = document.body.style.overflow;
    if (modalStack.length === 1) {
      document.body.style.overflow = "hidden";
    }

    const focusTimer = window.requestAnimationFrame(() => {
      const container = dialogRef.current;
      if (!container) return;
      if (container.contains(document.activeElement)) return;
      const focusable = container.querySelector<HTMLElement>(
        'input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      (focusable ?? container).focus();
    });

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && modalStack[modalStack.length - 1] === modalId) {
        e.stopPropagation();
        onCloseRef.current();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.cancelAnimationFrame(focusTimer);
      window.removeEventListener("keydown", onKey);
      const idx = modalStack.lastIndexOf(modalId);
      if (idx >= 0) modalStack.splice(idx, 1);
      if (modalStack.length === 0) {
        document.body.style.overflow = prevOverflow;
      }
      if (prevActive && prevActive.isConnected) {
        prevActive.focus();
      }
    };
  }, [open, modalId]);

  if (!open) return null;
  const dialog = (
    <div
      className={cn("fixed inset-0 flex items-end sm:items-center justify-center bg-stone-950/45 p-3 sm:p-4 backdrop-blur-sm", zIndexClass)}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="qm-card qm-dialog qm-rise w-full max-w-md max-h-[90vh] overflow-y-auto p-6 shadow-[var(--qm-shadow-pop)] focus:outline-none"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-2">
          <h4 className="qm-display text-[1.25rem] font-semibold text-ink">{title}</h4>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-full p-1.5 text-muted hover:text-ink hover:bg-sunk cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-3 text-[13.5px] text-ink-2">{children}</div>
      </div>
    </div>
  );
  return typeof document !== "undefined" ? createPortal(dialog, document.body) : dialog;
}

export function ToastViewport() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);
  const pause = useToastStore((s) => s.pause);
  const resume = useToastStore((s) => s.resume);
  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-20 lg:bottom-5 right-0 lg:right-5 z-[70] flex flex-col gap-2 max-w-sm w-full pointer-events-none px-4 lg:px-0">
      {toasts.map((t) => (
        <div
          key={t.id}
          role="status"
          onMouseEnter={() => pause(t.id)}
          onMouseLeave={() => resume(t.id)}
          className="pointer-events-auto qm-card qm-rise pl-4 pr-2.5 py-3 flex items-start justify-between gap-3 text-[13px] shadow-[var(--qm-shadow-pop)]"
        >
          <span
            className={cn(
              "mt-1.5 h-2 w-2 shrink-0 rounded-full",
              t.tone === "success" ? "bg-jade" : t.tone === "error" ? "bg-crimson" : "bg-ember"
            )}
          />
          <div className="min-w-0 flex-1">
            <div className="font-semibold text-ink">{t.title}</div>
            {t.description && <div className="text-[12px] text-muted mt-0.5">{t.description}</div>}
          </div>
          <button
            type="button"
            onClick={() => dismiss(t.id)}
            aria-label="Dismiss notification"
            className="rounded-full p-1 text-muted hover:text-ink hover:bg-sunk cursor-pointer shrink-0"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

/* ───────────────────────── Sparkline ───────────────────────── */

/** Tiny inline trend line. `color` is any CSS color, typically a token var like `var(--qm-jade)`. */
export function Sparkline({
  values,
  color = "var(--qm-ember)",
  height = 40,
  className,
  fill = true,
}: {
  values: Array<number | null | undefined>;
  color?: string;
  height?: number;
  className?: string;
  fill?: boolean;
}) {
  const gid = useId().replace(/:/g, "");
  const pts = values.map((v) => (v == null || !Number.isFinite(v) ? null : v));
  const nums = pts.filter((v): v is number => v != null);
  if (nums.length < 2) {
    return <div className={cn("rounded-lg bg-line/40", className)} style={{ height }} />;
  }
  const w = 200;
  const min = Math.min(...nums);
  const max = Math.max(...nums);
  const span = max - min || 1;
  const step = w / Math.max(1, pts.length - 1);
  let d = "";
  let first: [number, number] | null = null;
  let last: [number, number] | null = null;
  pts.forEach((v, i) => {
    if (v == null) return;
    const x = i * step;
    const y = height - 3 - ((v - min) / span) * (height - 6);
    d += `${d ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)} `;
    if (!first) first = [x, y];
    last = [x, y];
  });
  const f = first as [number, number] | null;
  const l = last as [number, number] | null;
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className={cn("w-full overflow-visible", className)} style={{ height }}>
      <defs>
        <linearGradient id={`spk-${gid}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" style={{ stopColor: color, stopOpacity: 0.28 }} />
          <stop offset="100%" style={{ stopColor: color, stopOpacity: 0 }} />
        </linearGradient>
      </defs>
      {fill && f && l && <path d={`${d} L${l[0]} ${height} L${f[0]} ${height} Z`} fill={`url(#spk-${gid})`} />}
      <path d={d} fill="none" style={{ stroke: color }} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
