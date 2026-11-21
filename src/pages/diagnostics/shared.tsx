import type React from "react";
import { create } from "zustand";

/** Each sub-view renders the page header itself so it can supply its own actions. */
export type HeaderFn = (actions?: React.ReactNode) => React.ReactNode;

export type Tone = "jade" | "saffron" | "crimson" | "ember" | "berry" | "muted";

export const TONE_INK: Record<Tone, string> = {
  jade: "text-jade-ink",
  saffron: "text-saffron-ink",
  crimson: "text-crimson-ink",
  ember: "text-ember-ink",
  berry: "text-berry-ink",
  muted: "text-muted",
};

export const TONE_SOFT: Record<Tone, string> = {
  jade: "bg-jade-soft",
  saffron: "bg-saffron-soft",
  crimson: "bg-crimson-soft",
  ember: "bg-ember-soft",
  berry: "bg-berry-soft",
  muted: "bg-sunk",
};

export const TONE_FILL: Record<Tone, string> = {
  jade: "bg-jade",
  saffron: "bg-saffron",
  crimson: "bg-crimson",
  ember: "bg-ember",
  berry: "bg-berry",
  muted: "bg-line-strong",
};

export function errMsg(e: unknown, fallback: string): string {
  return e instanceof Error ? e.message : fallback;
}

/** Bufferbloat grade → status tone and a plain-language verdict. */
export function gradeMeta(grade: string | null | undefined): { tone: Tone; verdict: string; detail: string } {
  const g = (grade ?? "").trim().toUpperCase();
  if (!g || g === "--") return { tone: "muted", verdict: "No grade yet", detail: "Run a test to measure latency under load." };
  if (g.startsWith("A")) return { tone: "jade", verdict: "Barely any lag under load", detail: "Calls and games stay smooth while the link is busy." };
  if (g === "B") return { tone: "saffron", verdict: "Mild lag under load", detail: "Busy transfers add a little delay to calls and games." };
  if (g === "C") return { tone: "saffron", verdict: "Noticeable lag under load", detail: "Downloads will make calls and games feel sluggish." };
  return { tone: "crimson", verdict: "Severe lag under load", detail: "Latency balloons while the link is busy: calls stutter, games rubber-band." };
}

/** Big-number formatting for throughput: drop decimals once the number is large. */
export function fmtMbps(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v) || v === 0) return "--";
  if (v >= 100) return String(Math.round(v));
  return v.toFixed(1);
}

export function median(vals: number[]): number | null {
  const v = vals.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (v.length === 0) return null;
  const mid = Math.floor(v.length / 2);
  return v.length % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2;
}

/* ───────── Session state that must survive sub-view remounts (AppShell re-keys on route) ───────── */

export interface AtEntry {
  id: number;
  cmd: string;
  resp: string;
  ok: boolean;
  latencyMs: number;
  ts: string;
}

export interface SentSms {
  id: number;
  phone: string;
  message: string;
  ts: string;
}

interface DiagSession {
  /** Newest first, capped at 15 entries (same as the previous console). */
  atLog: AtEntry[];
  /** Command recall for ↑/↓, newest first, unique. */
  atRecall: string[];
  atDraft: string;
  sentSms: SentSms[];
  addAt: (e: Omit<AtEntry, "id">) => void;
  clearAt: () => void;
  setAtDraft: (v: string) => void;
  addSent: (s: Omit<SentSms, "id">) => void;
}

let seq = 0;

export const useDiagSession = create<DiagSession>((set) => ({
  atLog: [],
  atRecall: [],
  atDraft: "AT+QGMR",
  sentSms: [],
  addAt: (e) =>
    set((s) => ({
      atLog: [{ ...e, id: ++seq }, ...s.atLog.slice(0, 14)],
      atRecall: [e.cmd, ...s.atRecall.filter((c) => c !== e.cmd)].slice(0, 50),
    })),
  clearAt: () => set({ atLog: [] }),
  setAtDraft: (v) => set({ atDraft: v }),
  addSent: (m) => set((s) => ({ sentSms: [...s.sentSms, { ...m, id: ++seq }].slice(-50) })),
}));
