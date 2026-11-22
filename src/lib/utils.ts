import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number | null | undefined, decimals = 2): string {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1) return "0 B";
  const k = 1024;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
  return `${(bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : decimals)} ${units[i]}`;
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below for non-secure or restricted contexts
  }
  try {
    const el = document.createElement("textarea");
    el.value = text;
    el.setAttribute("readonly", "");
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

export function formatBitrate(bitsPerSec: number | null | undefined): string {
  if (bitsPerSec == null || !Number.isFinite(bitsPerSec) || bitsPerSec < 0) return "0.00 Mbps";
  if (bitsPerSec >= 1_000_000_000) return `${(bitsPerSec / 1_000_000_000).toFixed(2)} Gbps`;
  if (bitsPerSec >= 1_000_000) return `${(bitsPerSec / 1_000_000).toFixed(2)} Mbps`;
  if (bitsPerSec >= 1_000) return `${(bitsPerSec / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bitsPerSec)} bps`;
}

export function maskSecretId(value: string | null | undefined, keepTail = 4): string {
  if (!value) return "—";
  const clean = value.trim();
  if (clean.length <= keepTail) return "•".repeat(clean.length);
  return `${"•".repeat(Math.min(clean.length - keepTail, 11))}${clean.slice(-keepTail)}`;
}

export function signalColorClass(kind: "rsrp" | "rsrq" | "sinr", value: number | null): string {
  if (value == null) return "text-muted";
  if (kind === "rsrp") {
    if (value >= -100) return "text-jade-ink";
    if (value >= -112) return "text-saffron-ink";
    return "text-crimson-ink";
  }
  if (kind === "rsrq") {
    if (value >= -15) return "text-jade-ink";
    if (value >= -20) return "text-saffron-ink";
    return "text-crimson-ink";
  }
  if (value >= 5) return "text-jade-ink";
  if (value >= 0) return "text-saffron-ink";
  return "text-crimson-ink";
}

export function signalPercent(kind: "rsrp" | "rsrq" | "sinr", value: number | null): number {
  if (value == null) return 0;
  if (kind === "rsrp") return Math.max(4, Math.min(100, ((value + 130) / 60) * 100));
  if (kind === "rsrq") return Math.max(4, Math.min(100, ((value + 25) / 22) * 100));
  return Math.max(4, Math.min(100, ((value + 5) / 35) * 100));
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return "0s";
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rem = s % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${rem}s`;
  if (m > 0) return `${m}m ${rem}s`;
  return `${rem}s`;
}
