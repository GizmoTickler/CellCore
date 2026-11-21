import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bookmark,
  CheckCircle2,
  Copy,
  Radio,
  RotateCcw,
  Sun,
  Trash2,
  Volume2,
  VolumeX,
  Zap,
} from "lucide-react";
import { Badge, Button, Card, Input, LiveDot } from "../../components/ui";
import { TowerFinderCard } from "../../components/TowerFinderCard";
import { cn } from "../../lib/utils";
import type { AntennaAlignState } from "../../types/cellcore";
import { TONE_BG, TONE_TEXT, rsrpPct, rsrpTone, rsrpWord } from "./shared";

type Vec = (number | null)[];
type AudioMode = "off" | "pitch" | "geiger";

interface AlignBookmark {
  id: string;
  label: string;
  meanRsrp: number | null;
  peakMeanRsrp: number | null;
  meanSinr: number | null;
  spread: number | null;
  pci: number | null;
  band: string;
  beam: number | null;
  ts: string;
}

const BOOKMARKS_KEY = "qm.align.bookmarks.v1";

const CHAINS = [
  { id: "RX0", name: "Main (PRX)", tx: "TX0" },
  { id: "RX1", name: "Diversity (DRX)", tx: null },
  { id: "RX2", name: "MIMO 3", tx: "TX1" },
  { id: "RX3", name: "MIMO 4", tx: null },
];

const HISTORY = 90; // ~36 s at 400 ms

function loadBookmarks(): AlignBookmark[] {
  try {
    const raw = window.localStorage.getItem(BOOKMARKS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as AlignBookmark[]).slice(0, 25) : [];
  } catch {
    return [];
  }
}

function saveBookmarks(list: AlignBookmark[]) {
  try {
    window.localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(list.slice(0, 25)));
  } catch {
    // ignore storage errors
  }
}

/** Half-ring "aim score" gauge with a best-seen tick. */
function AimGauge({ score, best }: { score: number; best: number }) {
  const gid = useId().replace(/:/g, "");
  const r = 80;
  const cx = 100;
  const cy = 96;
  const pt = (frac: number, rad = r) => {
    const a = Math.PI * (1 - frac);
    return [cx + rad * Math.cos(a), cy - rad * Math.sin(a)] as const;
  };
  const arc = (from: number, to: number) => {
    const [x1, y1] = pt(from);
    const [x2, y2] = pt(to);
    return `M ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2} ${y2}`;
  };
  const f = Math.max(0.005, Math.min(1, score / 100));
  const [kx, ky] = pt(f);
  const [b1x, b1y] = pt(best / 100, r - 14);
  const [b2x, b2y] = pt(best / 100, r + 14);
  const ticks = Array.from({ length: 11 }, (_, i) => {
    const [x1, y1] = pt(i / 10, r - 16);
    const [x2, y2] = pt(i / 10, r - (i % 5 === 0 ? 24 : 20));
    return (
      <line
        key={i}
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        strokeWidth={i % 5 === 0 ? 1.6 : 1}
        strokeLinecap="round"
        className="stroke-line-strong"
      />
    );
  });
  return (
    <svg viewBox="0 0 200 112" className="w-full max-w-[300px] overflow-visible" aria-hidden>
      <defs>
        <linearGradient id={`aim-${gid}`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" style={{ stopColor: "var(--qm-berry)" }} />
          <stop offset="50%" style={{ stopColor: "var(--qm-ember)" }} />
          <stop offset="100%" style={{ stopColor: "var(--qm-saffron)" }} />
        </linearGradient>
        <filter id={`aimglow-${gid}`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="4" />
        </filter>
      </defs>
      <path d={arc(0, 1)} fill="none" strokeWidth="14" strokeLinecap="round" className="stroke-line" />
      {ticks}
      <path d={arc(0, f)} fill="none" stroke={`url(#aim-${gid})`} strokeWidth="14" strokeLinecap="round" opacity=".5" filter={`url(#aimglow-${gid})`} />
      <path d={arc(0, f)} fill="none" stroke={`url(#aim-${gid})`} strokeWidth="14" strokeLinecap="round" />
      {best > 0 && (
        <line x1={b1x} y1={b1y} x2={b2x} y2={b2y} strokeWidth="2.5" strokeLinecap="round" style={{ stroke: "var(--qm-ink)" }}>
          <title>Best this session: {best}</title>
        </line>
      )}
      <circle cx={kx} cy={ky} r="8" style={{ fill: "var(--qm-raised)", stroke: "var(--qm-ember)" }} strokeWidth="3" />
    </svg>
  );
}

/** Rolling trace of mean RSRP with the peak-hold line. */
function Trace({ points, peak }: { points: number[]; peak: number | null }) {
  const gid = useId().replace(/:/g, "");
  const W = 600;
  const H = 150;
  if (points.length < 2) {
    return (
      <div className="flex h-[150px] items-center justify-center rounded-2xl border border-dashed border-line-strong text-[12.5px] text-muted">
        Waiting for live 400 ms samples…
      </div>
    );
  }
  const all = peak != null ? [...points, peak] : points;
  const lo = Math.floor(Math.min(...all) - 2);
  const hi = Math.ceil(Math.max(...all) + 2);
  const y = (v: number) => H - ((v - lo) / (hi - lo || 1)) * H;
  const span = Math.min(HISTORY, Math.max(points.length, 24));
  const x = (i: number) => (i / (span - 1)) * W;
  const off = span - points.length;
  const line = points.map((v, i) => `${i === 0 ? "M" : "L"} ${x(i + off).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L ${x(span - 1)} ${H} L ${x(off)} ${H} Z`;
  const last = points[points.length - 1];
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-[150px] w-full overflow-visible">
        <defs>
          <linearGradient id={`tr-${gid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" style={{ stopColor: "var(--qm-ember)", stopOpacity: 0.32 }} />
            <stop offset="100%" style={{ stopColor: "var(--qm-ember)", stopOpacity: 0 }} />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((g) => (
          <line key={g} x1="0" x2={W} y1={H * g} y2={H * g} className="stroke-line" strokeDasharray="2 6" vectorEffect="non-scaling-stroke" />
        ))}
        {peak != null && (
          <line x1="0" x2={W} y1={y(peak)} y2={y(peak)} strokeWidth="1.5" strokeDasharray="6 5" vectorEffect="non-scaling-stroke" style={{ stroke: "var(--qm-berry)" }} />
        )}
        <path d={area} fill={`url(#tr-${gid})`} />
        <path d={line} fill="none" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" style={{ stroke: "var(--qm-ember)" }} />
      </svg>
      <span
        className="pointer-events-none absolute right-0 h-3 w-3 -translate-y-1/2 translate-x-1/2 rounded-full border-2 border-raised bg-ember shadow"
        style={{ top: `${(y(last) / H) * 100}%` }}
      />
      <div className="pointer-events-none absolute inset-y-0 left-1 flex flex-col justify-between py-0.5 text-[10.5px] font-semibold text-muted qm-tabular">
        <span>{hi}</span>
        <span>{lo}</span>
      </div>
      {peak != null && (
        <span
          className="pointer-events-none absolute right-2 -translate-y-full rounded-full bg-berry-soft px-1.5 text-[10.5px] font-bold text-berry-ink qm-tabular"
          style={{ top: `${(y(peak) / H) * 100}%` }}
        >
          peak {peak}
        </span>
      )}
    </div>
  );
}

/** Vertical level meter for one receive chain. */
function ChainMeter({
  id,
  name,
  tx,
  rsrp,
  peak,
  sinr,
  peakSinr,
  rsrq,
}: {
  id: string;
  name: string;
  tx: string | null;
  rsrp: number | null;
  peak: number | null;
  sinr: number | null;
  peakSinr: number | null;
  rsrq: number | null;
}) {
  const tone = rsrpTone(rsrp);
  const gap = rsrp != null && peak != null ? Math.round((rsrp - peak) * 10) / 10 : null;
  const atPeak = gap != null && gap >= -1;
  return (
    <div className="qm-subcard flex flex-col p-3.5 sm:p-4 min-w-0">
      <div className="flex items-center justify-between gap-1">
        <span className="flex items-center gap-1.5">
          <span className="font-mono text-[12px] font-bold text-ink">{id}</span>
          {tx && <span className="rounded bg-ember-soft px-1.5 py-0.5 text-[9.5px] font-bold text-ember-ink">{tx}</span>}
        </span>
        <span className="truncate text-[11px] text-muted">{name}</span>
      </div>
      <div className="mt-3 flex items-end gap-3">
        <div className="relative h-36 sm:h-44 w-5 sm:w-6 shrink-0 overflow-hidden rounded-full bg-line/80">
          <div
            className={cn("absolute inset-x-0 bottom-0 rounded-full transition-[height] duration-300 ease-out", TONE_BG[tone])}
            style={{ height: `${rsrpPct(rsrp)}%` }}
          />
          {peak != null && (
            <div
              className="absolute inset-x-0 h-[3px] bg-berry transition-[bottom] duration-300"
              style={{ bottom: `calc(${rsrpPct(peak)}% - 1.5px)` }}
              title={`Peak ${peak} dBm`}
            />
          )}
        </div>
        <div className="min-w-0 pb-0.5">
          <div className={cn("qm-display text-[1.65rem] sm:text-[2rem] font-semibold leading-none qm-tabular", rsrp == null ? "text-muted" : "text-ink")}>
            {rsrp ?? "—"}
          </div>
          <div className="mt-1 text-[11px] font-semibold text-muted">dBm RSRP</div>
          <div className={cn("mt-2 text-[12px] font-semibold", TONE_TEXT[tone])}>{rsrpWord(rsrp)}</div>
        </div>
      </div>
      <div className="mt-3 space-y-1 border-t border-line pt-2.5 text-[11.5px] qm-tabular">
        <div className="flex justify-between gap-2">
          <span className="text-muted">vs peak</span>
          <span className={cn("font-semibold", gap == null ? "text-muted" : atPeak ? "text-jade-ink" : "text-berry-ink")}>
            {gap == null ? "—" : atPeak ? "at peak" : `${gap} dB`}
          </span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-muted">SINR</span>
          <span className="font-semibold text-ink-2">
            {sinr ?? "—"}
            <span className="text-muted font-normal"> / {peakSinr ?? "—"}</span>
          </span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-muted">RSRQ</span>
          <span className="font-semibold text-ink-2">{rsrq ?? "—"}</span>
        </div>
      </div>
    </div>
  );
}

function skewTone(db: number | null | undefined): "success" | "warning" | "danger" | "neutral" {
  if (db == null) return "neutral";
  if (db <= 3) return "success";
  if (db <= 6) return "warning";
  return "danger";
}

export function AlignView({
  active,
  samples,
  rsrp,
  sinr,
  rsrq,
  peakRsrp,
  peakSinr,
  summary,
  align,
  resetSeq,
  keepAwake,
  onToggleKeepAwake,
  busy,
  onResetPeaks,
}: {
  active: boolean;
  samples: number;
  rsrp: Vec;
  sinr: Vec;
  rsrq: Vec;
  peakRsrp: Vec;
  peakSinr: Vec;
  summary: { meanCur: number | null; meanPeak: number | null; meanSinr: number | null; peakMeanSinr?: number | null; score: number };
  align?: AntennaAlignState | null;
  resetSeq: number;
  keepAwake: boolean;
  onToggleKeepAwake: (next: boolean) => void;
  busy: string | null;
  onResetPeaks: () => void;
}) {
  const [trace, setTrace] = useState<number[]>([]);
  const [best, setBest] = useState(0);
  const [audioMode, setAudioMode] = useState<AudioMode>("off");
  const [wakeEnabled, setWakeEnabled] = useState(false);
  const [wakeActive, setWakeActive] = useState(false);
  const [haptics, setHaptics] = useState(true);
  const [bookmarkLabel, setBookmarkLabel] = useState("");
  const [bookmarks, setBookmarks] = useState<AlignBookmark[]>(loadBookmarks);
  const [copiedBookmarks, setCopiedBookmarks] = useState(false);
  const [handover, setHandover] = useState<{ from: string; to: string } | null>(null);

  const audioCtxRef = useRef<AudioContext | null>(null);
  const oscRef = useRef<OscillatorNode | null>(null);
  const gainRef = useRef<GainNode | null>(null);
  const wakeLockRef = useRef<{ release: () => Promise<void> } | null>(null);
  const lastSampleKeyRef = useRef<string>("");
  const prevPeakMeanRef = useRef<number | null>(null);
  const baseCellRef = useRef<{ pci: number | null; band: string } | null>(null);
  const summaryRef = useRef(summary);
  summaryRef.current = summary;

  const stopAudioNodes = useCallback(() => {
    try {
      oscRef.current?.stop();
      oscRef.current?.disconnect();
    } catch {
      // ignore
    }
    oscRef.current = null;
    try {
      gainRef.current?.disconnect();
    } catch {
      // ignore
    }
    gainRef.current = null;
  }, []);

  const ensureAudioCtx = useCallback((): AudioContext | null => {
    const Ctor = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return null;
    if (!audioCtxRef.current || audioCtxRef.current.state === "closed") {
      audioCtxRef.current = new Ctor();
    }
    if (audioCtxRef.current.state === "suspended") {
      void audioCtxRef.current.resume().catch(() => {});
    }
    return audioCtxRef.current;
  }, []);

  const playChime = useCallback(
    (kind: "peak" | "handover") => {
      if (audioMode === "off") return;
      const ctx = ensureAudioCtx();
      if (!ctx) return;
      const now = ctx.currentTime;
      const freqs = kind === "peak" ? [880, 1175, 1397] : [620, 415];
      freqs.forEach((f, idx) => {
        const osc = ctx.createOscillator();
        const g = ctx.createGain();
        osc.type = kind === "peak" ? "sine" : "triangle";
        osc.frequency.setValueAtTime(f, now + idx * 0.08);
        g.gain.setValueAtTime(0.06, now + idx * 0.08);
        g.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.08 + 0.11);
        osc.connect(g);
        g.connect(ctx.destination);
        osc.start(now + idx * 0.08);
        osc.stop(now + idx * 0.08 + 0.12);
      });
    },
    [audioMode, ensureAudioCtx]
  );

  // Manage pitch & geiger audio generators
  useEffect(() => {
    stopAudioNodes();
    if (audioMode === "off") return;
    const ctx = ensureAudioCtx();
    if (!ctx) return;

    if (audioMode === "pitch") {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      const val = summaryRef.current.meanCur ?? -110;
      const freq = 220 + Math.max(0, Math.min(1, (val + 125) / 60)) * 760;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.035, ctx.currentTime);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      oscRef.current = osc;
      gainRef.current = gain;
      return () => stopAudioNodes();
    }

    // Geiger click mode: click interval shrinks as aim score improves
    let timer = 0;
    const schedule = () => {
      const sc = summaryRef.current.score;
      const periodMs = Math.max(95, Math.round(640 - (sc / 100) * 530));
      const c = audioCtxRef.current;
      if (c && c.state === "running") {
        const now = c.currentTime;
        const osc = c.createOscillator();
        const g = c.createGain();
        osc.type = "square";
        osc.frequency.setValueAtTime(520 + sc * 6, now);
        g.gain.setValueAtTime(0.045, now);
        g.gain.exponentialRampToValueAtTime(0.001, now + 0.022);
        osc.connect(g);
        g.connect(c.destination);
        osc.start(now);
        osc.stop(now + 0.025);
      }
      timer = window.setTimeout(schedule, periodMs);
    };
    schedule();
    return () => {
      window.clearTimeout(timer);
      stopAudioNodes();
    };
  }, [audioMode, ensureAudioCtx, stopAudioNodes]);

  // Smoothly update Pitch oscillator frequency on new signal samples
  useEffect(() => {
    if (audioMode !== "pitch" || !oscRef.current || !audioCtxRef.current) return;
    if (summary.meanCur == null) return;
    const freq = 220 + Math.max(0, Math.min(1, (summary.meanCur + 125) / 60)) * 760;
    oscRef.current.frequency.setTargetAtTime(freq, audioCtxRef.current.currentTime, 0.08);
  }, [audioMode, summary.meanCur]);

  useEffect(() => {
    return () => {
      stopAudioNodes();
      void audioCtxRef.current?.close().catch(() => {});
    };
  }, [stopAudioNodes]);

  // Screen Wake Lock while aiming on mobile roof
  useEffect(() => {
    if (!wakeEnabled) {
      setWakeActive(false);
      void wakeLockRef.current?.release().catch(() => {});
      wakeLockRef.current = null;
      return;
    }
    let alive = true;
    const nav = navigator as Navigator & { wakeLock?: { request: (t: "screen") => Promise<{ release: () => Promise<void> }> } };
    const req = async () => {
      try {
        if (!nav.wakeLock) return;
        const lock = await nav.wakeLock.request("screen");
        if (!alive) {
          void lock.release().catch(() => {});
          return;
        }
        wakeLockRef.current = lock;
        setWakeActive(true);
      } catch {
        if (alive) setWakeActive(false);
      }
    };
    void req();
    const onVis = () => {
      if (document.visibilityState === "visible" && wakeEnabled) void req();
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      alive = false;
      document.removeEventListener("visibilitychange", onVis);
      setWakeActive(false);
      void wakeLockRef.current?.release().catch(() => {});
      wakeLockRef.current = null;
    };
  }, [wakeEnabled]);

  // Reset trace, peaks baseline, and cell handover reference when Reset Peaks clicked
  useEffect(() => {
    if (resetSeq === 0) return;
    setTrace([]);
    setBest(0);
    setHandover(null);
    prevPeakMeanRef.current = null;
    baseCellRef.current =
      align?.servingPci != null || align?.servingBand
        ? { pci: align?.servingPci ?? null, band: align?.servingBand ?? "" }
        : null;
  }, [resetSeq]); // eslint-disable-line react-hooks/exhaustive-deps

  // WebSocket-driven trace updates + peak/handover detectors
  useEffect(() => {
    if (summary.meanCur == null) return;
    const sampleKey = `${align?.updatedAtMs ?? 0}:${align?.samples ?? samples}:${summary.meanCur}`;
    if (sampleKey === lastSampleKeyRef.current) return;
    lastSampleKeyRef.current = sampleKey;

    setTrace((t) => [...t.slice(-(HISTORY - 1)), summary.meanCur!]);
    setBest((b) => Math.max(b, summary.score));

    if (summary.meanPeak != null && prevPeakMeanRef.current != null && summary.meanPeak > prevPeakMeanRef.current) {
      playChime("peak");
      if (haptics && typeof navigator.vibrate === "function") {
        navigator.vibrate(25);
      }
    }
    prevPeakMeanRef.current = summary.meanPeak;

    const curPci = align?.servingPci ?? null;
    const curBand = align?.servingBand ?? "";
    if (curPci != null || curBand) {
      if (!baseCellRef.current) {
        baseCellRef.current = { pci: curPci, band: curBand };
      } else if (baseCellRef.current.pci !== curPci || baseCellRef.current.band !== curBand) {
        setHandover({
          from: `${baseCellRef.current.band || "?"} PCI ${baseCellRef.current.pci ?? "?"}`,
          to: `${curBand || "?"} PCI ${curPci ?? "?"}`,
        });
        playChime("handover");
      }
    }
  }, [align?.updatedAtMs, align?.samples, align?.servingPci, align?.servingBand, samples, summary.meanCur, summary.meanPeak, summary.score, playChime, haptics]);

  const cycleAudioMode = () => {
    const next: AudioMode = audioMode === "off" ? "pitch" : audioMode === "pitch" ? "geiger" : "off";
    if (next !== "off") ensureAudioCtx();
    setAudioMode(next);
  };

  const addBookmark = () => {
    const label = bookmarkLabel.trim() || `${bookmarks.length + 1} · Spot`;
    const entry: AlignBookmark = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      label,
      meanRsrp: summary.meanCur,
      peakMeanRsrp: summary.meanPeak,
      meanSinr: summary.meanSinr,
      spread: align?.rsrpSpread ?? null,
      pci: align?.servingPci ?? null,
      band: align?.servingBand ?? "",
      beam: align?.ssbBeamId ?? null,
      ts: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    };
    const next = [entry, ...bookmarks].slice(0, 25);
    setBookmarks(next);
    saveBookmarks(next);
    setBookmarkLabel("");
  };

  const removeBookmark = (id: string) => {
    const next = bookmarks.filter((b) => b.id !== id);
    setBookmarks(next);
    saveBookmarks(next);
  };

  const clearBookmarks = () => {
    setBookmarks([]);
    saveBookmarks([]);
  };

  const copyBookmarksTable = () => {
    const header = "Label\tRSRP\tPeak\tSINR\tSpread\tCell\tBeam\tTime";
    const rows = bookmarks.map(
      (b) =>
        `${b.label}\t${b.meanRsrp ?? "—"}\t${b.peakMeanRsrp ?? "—"}\t${b.meanSinr ?? "—"}\t${b.spread ?? "—"}\t${b.band || "?"} PCI ${b.pci ?? "?"}\t${b.beam ?? "—"}\t${b.ts}`
    );
    void navigator.clipboard?.writeText([header, ...rows].join("\n")).then(() => {
      setCopiedBookmarks(true);
      window.setTimeout(() => setCopiedBookmarks(false), 1800);
    });
  };

  const bestBookmarkId = useMemo(() => {
    let bestId: string | null = null;
    let bestVal = -Infinity;
    for (const b of bookmarks) {
      if (b.meanRsrp != null && b.meanRsrp > bestVal) {
        bestVal = b.meanRsrp;
        bestId = b.id;
      }
    }
    return bestId;
  }, [bookmarks]);

  const prev = trace.length > 6 ? trace.slice(-7, -2).reduce((a, b) => a + b, 0) / 5 : null;
  const delta = prev != null && summary.meanCur != null ? summary.meanCur - prev : 0;
  const trend = delta > 0.6 ? "up" : delta < -0.6 ? "down" : "flat";
  const scoreTone = summary.score >= 70 ? "jade" : summary.score >= 45 ? "saffron" : summary.meanCur == null ? "muted" : "crimson";
  const peakGap = summary.meanCur != null && summary.meanPeak != null ? Math.round((summary.meanCur - summary.meanPeak) * 10) / 10 : null;

  return (
    <div className="space-y-4 sm:space-y-5">
      {/* Compact Roof HUD: above-the-fold at 375 px with >= 48 px touch controls */}
      <Card className="p-3.5 sm:p-4">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 qm-tabular">
          <div className="qm-subcard p-2.5">
            <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted">Live Mean</div>
            <div className={cn("qm-display text-[1.4rem] leading-tight font-semibold", TONE_TEXT[rsrpTone(summary.meanCur)])}>
              {summary.meanCur ?? "—"} <span className="text-[11px] font-sans text-muted">dBm</span>
            </div>
          </div>
          <div className="qm-subcard p-2.5">
            <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted">Peak Mean</div>
            <div className="qm-display text-[1.4rem] leading-tight font-semibold text-berry-ink">
              {summary.meanPeak ?? "—"} <span className="text-[11px] font-sans text-muted">dBm</span>
            </div>
          </div>
          <div className="qm-subcard p-2.5">
            <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted">SINR (Peak)</div>
            <div className="qm-display text-[1.4rem] leading-tight font-semibold text-ink">
              {summary.meanSinr ?? "—"}
              <span className="text-[11px] font-sans text-muted">
                {summary.peakMeanSinr != null ? ` (${summary.peakMeanSinr})` : " dB"}
              </span>
            </div>
          </div>
          <div className="qm-subcard p-2.5">
            <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted">Aim · Spread</div>
            <div className={cn("qm-display text-[1.4rem] leading-tight font-semibold", TONE_TEXT[scoreTone])}>
              {summary.meanCur == null ? "—" : summary.score}
              <span className="text-[11px] font-sans text-muted">
                {align?.rsrpSpread != null ? ` · Δ${align.rsrpSpread}dB` : " /100"}
              </span>
            </div>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 sm:flex sm:flex-wrap gap-2">
          <Button
            variant="secondary"
            className="min-h-12 px-3.5 text-[12.5px] font-semibold"
            onClick={onResetPeaks}
            disabled={busy === "align-reset"}
          >
            <RotateCcw className="h-4 w-4" />
            Reset peaks
          </Button>
          <Button
            variant={keepAwake ? "primary" : "secondary"}
            className="min-h-12 px-3.5 text-[12.5px] font-semibold"
            onClick={() => onToggleKeepAwake(!keepAwake)}
            disabled={busy === "align-awake"}
            title="Periodic 64 KiB keep-alive download burst (~35 KB/s) keeps all 4 NR5G RX chains awake continuously"
          >
            <Zap className="h-4 w-4" />
            {keepAwake ? "4×4 RX Awake: ON" : "Keep 4×4 RX Awake"}
          </Button>
          <Button
            variant={audioMode !== "off" ? "primary" : "secondary"}
            className="min-h-12 px-3.5 text-[12.5px] font-semibold"
            onClick={cycleAudioMode}
          >
            {audioMode === "off" ? <VolumeX className="h-4 w-4" /> : <Volume2 className="h-4 w-4" />}
            Audio: {audioMode === "off" ? "Off" : audioMode === "pitch" ? "Pitch" : "Geiger"}
          </Button>
          <Button
            variant={wakeEnabled ? "primary" : "secondary"}
            className="min-h-12 px-3.5 text-[12.5px] font-semibold"
            onClick={() => setWakeEnabled((v) => !v)}
          >
            <Sun className="h-4 w-4" />
            {wakeEnabled ? (wakeActive ? "Screen Awake" : "Wake Lock…") : "Wake Lock"}
          </Button>
          <Button
            variant={haptics ? "secondary" : "ghost"}
            className="min-h-12 px-3 text-[12px]"
            onClick={() => setHaptics((v) => !v)}
            title="Vibrate when a new mean peak is reached"
          >
            Haptics: {haptics ? "On" : "Off"}
          </Button>
        </div>
      </Card>

      {handover && (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-saffron/45 bg-saffron-soft p-3.5 text-[12.5px] text-saffron-ink">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <div className="font-bold">Cell / Band handover detected</div>
              <div>
                Switched from <span className="font-mono">{handover.from}</span> to <span className="font-mono">{handover.to}</span>. Peak holds from the old cell may not apply to this sector.
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                baseCellRef.current = { pci: align?.servingPci ?? null, band: align?.servingBand ?? "" };
                setHandover(null);
                onResetPeaks();
              }}
            >
              Accept &amp; reset peaks
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setHandover(null)}>
              Dismiss
            </Button>
          </div>
        </div>
      )}

      {/* Visual Tower Finder, Polar Compass & 360° Signal Sweep */}
      <TowerFinderCard meanRsrp={summary.meanCur} meanSinr={summary.meanSinr} haptics={haptics} />

      {/* Main Gauge + WS-driven Trace */}
      <Card className="qm-grain overflow-hidden p-0 sm:p-0">
        <div className="relative z-[1] grid lg:grid-cols-12">
          <div className="lg:col-span-4 flex flex-col items-center justify-center border-b lg:border-b-0 lg:border-r border-line px-5 py-6">
            <div className="flex items-center gap-2 self-stretch justify-between">
              <span className="flex items-center gap-2 text-[12px] font-semibold text-ink-2">
                <LiveDot tone={active ? "jade" : "saffron"} />
                {active ? "Live · 400 ms WS" : "Starting fast sampling…"}
              </span>
              <span className="text-[11px] text-muted qm-tabular">
                {align?.activeChains ?? rsrp.filter((v) => v != null).length}/4 RX · #{samples}
              </span>
            </div>
            <div className="relative mt-3 w-full flex justify-center">
              <AimGauge score={summary.score} best={best} />
              <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
                <div className={cn("qm-display text-[3.4rem] font-semibold leading-none qm-tabular", TONE_TEXT[scoreTone])}>
                  {summary.meanCur == null ? "—" : summary.score}
                </div>
              </div>
            </div>
            <div className="mt-1.5 text-[12px] font-semibold text-muted">Aim score / 100</div>
            <div
              className={cn(
                "mt-3 inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12.5px] font-bold",
                trend === "up" ? "bg-jade-soft text-jade-ink" : trend === "down" ? "bg-crimson-soft text-crimson-ink" : "bg-sunk text-ink-2"
              )}
            >
              {trend === "up" ? <ArrowUpRight className="h-4 w-4" /> : trend === "down" ? <ArrowDownRight className="h-4 w-4" /> : <ArrowRight className="h-4 w-4" />}
              {trend === "up" ? "Getting better" : trend === "down" ? "Getting worse" : "Holding steady"}
            </div>
            {best > 0 && <div className="mt-2 text-[11.5px] text-muted qm-tabular">Best score this spot: {best}</div>}
          </div>

          <div className="lg:col-span-8 min-w-0 p-5 sm:p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="qm-display text-[1.12rem] font-semibold text-ink">Signal while you turn</h3>
                <p className="text-[12.5px] text-muted">WebSocket-synchronized 4-chain average · last ~36 s</p>
              </div>
              {peakGap != null && (
                <Badge variant={peakGap >= -1 ? "success" : "warning"}>
                  {peakGap >= -1 ? "At spot peak" : `${peakGap} dB from peak`}
                </Badge>
              )}
            </div>
            <div className="mt-4">
              <Trace points={trace} peak={summary.meanPeak} />
            </div>
            {/* Live RF Link & PHY Strip */}
            <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-[11.5px] qm-tabular">
              <div className="qm-subcard p-2">
                <div className="text-[10px] font-semibold uppercase text-muted">Serving Cell</div>
                <div className="mt-0.5 font-bold text-ink truncate">
                  {align?.servingBand || "—"} · PCI {align?.servingPci ?? "—"}
                </div>
                <div className="text-[10.5px] text-muted truncate">
                  {align?.servingRat || "—"} · {align?.rrcState || "—"}
                </div>
              </div>
              <div className="qm-subcard p-2">
                <div className="text-[10px] font-semibold uppercase text-muted">CA &amp; TA</div>
                <div className="mt-0.5 font-bold text-ink">
                  {align?.caCount ?? 0} CC · {align?.caTotalMhz ?? 0}M
                </div>
                <div className="text-[10.5px] text-muted">
                  TA {align?.taMeters != null ? `${align.taMeters} m` : "—"}
                </div>
              </div>
              {align?.ssbBeamId != null && (
                <div className="qm-subcard p-2">
                  <div className="text-[10px] font-semibold uppercase text-muted">SSB Beam</div>
                  <div className="mt-0.5 font-mono font-bold text-ink">{align.ssbBeamId}</div>
                  <div className="text-[10px] text-muted">SSB index</div>
                </div>
              )}
              {align?.nr5gPathlossDb != null && (
                <div className="qm-subcard p-2">
                  <div className="text-[10px] font-semibold uppercase text-muted">NR Pathloss</div>
                  <div className="mt-0.5 font-bold text-ink">{align.nr5gPathlossDb} dB</div>
                  <div className="text-[10px] text-muted">RF attenuation</div>
                </div>
              )}
              {(align?.nr5gMcs != null || align?.nr5gRi != null || align?.nr5gCqi != null) && (
                <div className="qm-subcard p-2">
                  <div className="text-[10px] font-semibold uppercase text-muted">NR CSI</div>
                  <div className="mt-0.5 font-mono font-bold text-ink">
                    {align?.nr5gMcs ?? "—"} / {align?.nr5gRi ?? "—"} / {align?.nr5gCqi ?? "—"}
                  </div>
                  <div className="text-[10px] text-muted">MCS / RI / CQI</div>
                </div>
              )}
              {align?.nr5gTxPwr && (
                <div className="qm-subcard p-2">
                  <div className="text-[10px] font-semibold uppercase text-muted">NR TX Power</div>
                  <div className="mt-0.5 font-mono font-bold text-ink truncate">{align.nr5gTxPwr}</div>
                  <div className="text-[10px] text-muted">dBm</div>
                </div>
              )}
            </div>
            {align?.mimoLayers && align.mimoLayers.length > 0 && (
              <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                <span className="font-semibold text-muted mr-1">Per-CC MIMO:</span>
                {align.mimoLayers.map((layer, idx) => (
                  <Badge key={`${layer.arfcn}-${idx}`} variant={layer.dlLayers >= 4 ? "success" : "info"}>
                    {layer.band || layer.arfcn} · {layer.dlLayers}×{layer.ulLayers}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* 4×4 MIMO Balance & Cross-Pol Skew Meter */}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div>
            <h3 className="qm-display text-[1.08rem] font-semibold text-ink">4×4 MIMO Balance &amp; Cross-Pol Skew</h3>
            <p className="text-[12px] text-muted">Keep all 4 chains within 3 dB for maximum rank-4 spatial throughput</p>
          </div>
          <Badge variant={skewTone(align?.rsrpSpread)}>
            Spread {align?.rsrpSpread != null ? `${align.rsrpSpread} dB` : "—"}
          </Badge>
        </div>
        <div className="grid gap-3 sm:grid-cols-3 text-[12.5px] qm-tabular">
          <div className="qm-subcard p-3 flex items-center justify-between">
            <div>
              <div className="text-muted text-[11px] font-semibold">4-Chain Spread (max − min)</div>
              <div className="font-bold text-ink mt-0.5">{align?.rsrpSpread != null ? `${align.rsrpSpread} dB` : "—"}</div>
            </div>
            <Badge variant={skewTone(align?.rsrpSpread)}>
              {align?.rsrpSpread == null ? "—" : align.rsrpSpread <= 3 ? "Balanced" : align.rsrpSpread <= 6 ? "Fair" : "Skewed"}
            </Badge>
          </div>
          <div className="qm-subcard p-3 space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-muted text-[11px] font-semibold">Cross-Pol Pair 0/1 (RX0 vs RX1)</div>
                <div className="font-bold text-ink mt-0.5">{align?.pair01Skew != null ? `${align.pair01Skew} dB` : "—"}</div>
              </div>
              <Badge variant={skewTone(align?.pair01Skew)}>
                {align?.pair01Skew == null ? "—" : align.pair01Skew <= 4 ? "Balanced" : "Skewed"}
              </Badge>
            </div>
            {rsrp[0] != null && rsrp[1] != null && (
              <div>
                <div className="relative h-2.5 rounded-full bg-line overflow-hidden">
                  <div className="absolute inset-y-0 left-1/2 w-[2px] -translate-x-1/2 bg-ink/40" />
                  <div
                    className={cn(
                      "absolute top-1/2 h-3.5 w-3.5 -translate-y-1/2 -translate-x-1/2 rounded-full border-2 border-raised transition-[left] duration-300",
                      Math.abs(rsrp[0] - rsrp[1]) <= 4 ? "bg-jade" : Math.abs(rsrp[0] - rsrp[1]) <= 7 ? "bg-saffron" : "bg-crimson"
                    )}
                    style={{ left: `${Math.max(8, Math.min(92, 50 + ((rsrp[1] - rsrp[0]) / 12) * 42))}%` }}
                  />
                </div>
                <div className="mt-1 flex justify-between text-[10px] text-muted font-mono">
                  <span>RX0 {rsrp[0]}</span>
                  <span>±45°</span>
                  <span>RX1 {rsrp[1]}</span>
                </div>
              </div>
            )}
          </div>
          <div className="qm-subcard p-3 space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-muted text-[11px] font-semibold">Cross-Pol Pair 2/3 (RX2 vs RX3)</div>
                <div className="font-bold text-ink mt-0.5">{align?.pair23Skew != null ? `${align.pair23Skew} dB` : "—"}</div>
              </div>
              <Badge variant={skewTone(align?.pair23Skew)}>
                {align?.pair23Skew == null ? "—" : align.pair23Skew <= 4 ? "Balanced" : "Skewed"}
              </Badge>
            </div>
            {rsrp[2] != null && rsrp[3] != null && (
              <div>
                <div className="relative h-2.5 rounded-full bg-line overflow-hidden">
                  <div className="absolute inset-y-0 left-1/2 w-[2px] -translate-x-1/2 bg-ink/40" />
                  <div
                    className={cn(
                      "absolute top-1/2 h-3.5 w-3.5 -translate-y-1/2 -translate-x-1/2 rounded-full border-2 border-raised transition-[left] duration-300",
                      Math.abs(rsrp[2] - rsrp[3]) <= 4 ? "bg-jade" : Math.abs(rsrp[2] - rsrp[3]) <= 7 ? "bg-saffron" : "bg-crimson"
                    )}
                    style={{ left: `${Math.max(8, Math.min(92, 50 + ((rsrp[3] - rsrp[2]) / 12) * 42))}%` }}
                  />
                </div>
                <div className="mt-1 flex justify-between text-[10px] text-muted font-mono">
                  <span>RX2 {rsrp[2]}</span>
                  <span>±45°</span>
                  <span>RX3 {rsrp[3]}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* Per-antenna ChainMeters */}
      <div>
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="qm-display text-[1.12rem] font-semibold text-ink">Each antenna</h3>
          <span className="flex items-center gap-3 text-[11.5px] text-muted">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-3 rounded-full bg-jade" />
              now
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-[3px] w-3 bg-berry" />
              peak hold
            </span>
          </span>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          {CHAINS.map((c, i) => (
            <ChainMeter
              key={c.id}
              id={c.id}
              name={c.name}
              tx={c.tx}
              rsrp={rsrp[i] ?? null}
              peak={peakRsrp[i] ?? null}
              sinr={sinr[i] ?? null}
              peakSinr={peakSinr[i] ?? null}
              rsrq={rsrq[i] ?? null}
            />
          ))}
        </div>
      </div>

      {/* Compass / Azimuth Position Bookmarks */}
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
          <div>
            <h3 className="qm-display text-[1.08rem] font-semibold text-ink flex items-center gap-2">
              <Radio className="h-4 w-4 text-ember-ink" /> Azimuth / Mount Bookmarks
            </h3>
            <p className="text-[12px] text-muted">Log bearings or mounting locations locally in this browser to compare spots objectively</p>
          </div>
          {bookmarks.length > 0 && (
            <div className="flex items-center gap-2">
              <Button size="sm" variant="secondary" onClick={copyBookmarksTable}>
                {copiedBookmarks ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                {copiedBookmarks ? "Copied" : "Copy table"}
              </Button>
              <Button size="sm" variant="ghost" onClick={clearBookmarks}>
                Clear all
              </Button>
            </div>
          )}
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <Input
            value={bookmarkLabel}
            onChange={(e) => setBookmarkLabel(e.target.value)}
            placeholder="e.g. 245° SW gable peak"
            className="min-h-12"
            onKeyDown={(e) => {
              if (e.key === "Enter") addBookmark();
            }}
          />
          <Button variant="primary" className="min-h-12 px-4 shrink-0 font-semibold" onClick={addBookmark} disabled={summary.meanCur == null}>
            <Bookmark className="h-4 w-4" />
            Save position
          </Button>
        </div>
        {bookmarks.length > 0 && (
          <div className="mt-4 overflow-x-auto -mx-1">
            <table className="w-full min-w-[540px] text-[12.5px] qm-tabular">
              <thead>
                <tr className="text-left text-[11px] font-bold uppercase tracking-wider text-muted border-b border-line">
                  <th className="px-2 pb-2">Position</th>
                  <th className="px-2 pb-2 text-right">RSRP</th>
                  <th className="px-2 pb-2 text-right">SINR</th>
                  <th className="px-2 pb-2 text-right">Spread</th>
                  <th className="px-2 pb-2">Cell / Beam</th>
                  <th className="px-2 pb-2 text-right">Time</th>
                  <th className="px-2 pb-2 text-right" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {bookmarks.map((b) => (
                  <tr key={b.id} className={b.id === bestBookmarkId ? "bg-jade-soft/30" : undefined}>
                    <td className="px-2 py-2 font-semibold text-ink">
                      <span className="flex items-center gap-1.5">
                        {b.label}
                        {b.id === bestBookmarkId && <Badge variant="success">Best</Badge>}
                      </span>
                    </td>
                    <td className="px-2 py-2 text-right font-bold text-ink">{b.meanRsrp ?? "—"}</td>
                    <td className="px-2 py-2 text-right text-ink-2">{b.meanSinr ?? "—"}</td>
                    <td className="px-2 py-2 text-right text-ink-2">{b.spread != null ? `${b.spread} dB` : "—"}</td>
                    <td className="px-2 py-2 font-mono text-[11.5px] text-ink-2">
                      {b.band || "?"} PCI {b.pci ?? "?"} {b.beam != null ? `· B${b.beam}` : ""}
                    </td>
                    <td className="px-2 py-2 text-right text-muted">{b.ts}</td>
                    <td className="px-2 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => removeBookmark(b.id)}
                        className="p-1.5 text-muted hover:text-crimson-ink cursor-pointer"
                        aria-label={`Delete bookmark ${b.label}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
