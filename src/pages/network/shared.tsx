import type React from "react";
import { HardDrive, Zap } from "lucide-react";
import { cn } from "../../lib/utils";
import type { MpdnRule } from "../../types/cellcore";

export interface ArpMacEntry {
  hostname: string;
  ip: string;
  mac: string;
}

export interface NetworkLanResponse {
  lanIp?: {
    gatewayIp: string;
    poolStart: string;
    poolEnd: string;
    netmask: string;
  } | null;
  mpdnRules?: MpdnRule[];
  dhcpDnsRaw?: string;
  usbnetRaw?: string;
  arpClients?: ArpMacEntry[];
  ethLink?: {
    currentLimit: string;
    actualSpeed: string;
  };
  ttl?: {
    enabled: boolean;
    ttl: number;
    hl: number;
  };
  mtu?: {
    enabled: boolean;
    value: number;
  };
  dns?: {
    uciOption: string;
    custom?: string[] | null;
  };
  tailscale?: {
    installed: boolean;
    running: boolean;
    authenticated: boolean;
    loginUrl?: string | null;
    selfIp?: string | null;
    peers?: Array<{ hostName: string; ip: string; online: boolean; os: string }>;
  };
}

/** Busy tag of the in-flight mutation (null when idle) and the POST /api/v1/network/lan runner. */
export interface NetMutator {
  busy: string | null;
  mutate: (actionTag: string, payload: Record<string, unknown>, okMsg: string) => Promise<boolean>;
}

/** Dotted part of a netmask; the daemon may append an inferred " (/22)". */
export function netmaskDotted(mask: string | undefined): string {
  return (mask ?? "").trim().split(/\s+/)[0] ?? "";
}

export function netmaskBits(mask: string | undefined): number | null {
  if (!mask) return null;
  const octets = netmaskDotted(mask).split(".").map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return octets.reduce((sum, n) => sum + ((n >>> 0).toString(2).match(/1/g)?.length ?? 0), 0);
}

/** "/22 · 1,022 addresses" style summary for a dotted netmask. */
export function netmaskSummary(mask: string | undefined): string {
  const bits = netmaskBits(mask);
  if (bits == null) return mask || "--";
  const hosts = bits >= 31 ? 2 ** (32 - bits) : 2 ** (32 - bits) - 2;
  return `/${bits} · ${hosts.toLocaleString()} addresses`;
}

/** Split "16.64 GiB" into number and unit so the unit can sit smaller beside the value. */
export function splitUnit(s: string): [string, string] {
  const i = s.lastIndexOf(" ");
  return i > 0 ? [s.slice(0, i), s.slice(i + 1)] : [s, ""];
}

export function BigValue({
  value,
  unit,
  className,
  unitClassName,
}: {
  value: React.ReactNode;
  unit?: React.ReactNode;
  className?: string;
  unitClassName?: string;
}) {
  return (
    <div className={cn("qm-display font-semibold leading-none text-ink qm-tabular", className)}>
      {value}
      {unit && <span className={cn("ml-1.5 text-[0.42em] font-semibold text-muted align-baseline", unitClassName)}>{unit}</span>}
    </div>
  );
}

/**
 * Small footer that says what Apply does and whether the setting survives a reboot.
 * Every settings card ends with one so the consequence is never a guess.
 */
export function ApplyNote({ effect, persist }: { effect: React.ReactNode; persist: React.ReactNode }) {
  return (
    <div className="grid gap-2 sm:grid-cols-2 break-words border-t border-line pt-3.5 text-[12px] leading-snug text-ink-2">
      {/* overflow-wrap:anywhere also lowers the min-content width, so a long path (e.g. /etc/cellcore/...)
          wraps instead of widening the grid track past the card at 1024 px. */}
      <div className="flex min-w-0 items-start gap-2">
        <Zap className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ember-ink" />
        <span className="min-w-0 [overflow-wrap:anywhere]">{effect}</span>
      </div>
      <div className="flex min-w-0 items-start gap-2">
        <HardDrive className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
        <span className="min-w-0 [overflow-wrap:anywhere]">{persist}</span>
      </div>
    </div>
  );
}

/** Field label with plain-language name first and the technical term as secondary text. */
export function FieldLabel({ children, term, htmlFor }: { children: React.ReactNode; term?: string; htmlFor?: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-1.5 flex items-baseline justify-between gap-2 text-[12.5px] font-semibold text-ink-2">
      <span>{children}</span>
      {term && <span className="font-mono text-[11px] font-medium text-muted">{term}</span>}
    </label>
  );
}

/** Fill-the-inputs shortcut chip (never applies anything by itself). */
export function PresetChip({
  active,
  onClick,
  children,
}: {
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex h-8 items-center rounded-full border px-3 text-[12px] font-semibold transition cursor-pointer whitespace-nowrap",
        active
          ? "border-ember/50 bg-ember-soft text-ember-ink"
          : "border-line bg-raised text-ink-2 hover:border-line-strong hover:text-ink"
      )}
    >
      {children}
    </button>
  );
}
