import { Suspense, lazy, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Bookmark,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Compass,
  Copy,
  Crosshair,
  Play,
  Radio,
  RotateCcw,
  Sparkles,
  Sun,
  Trash2,
  Volume2,
  VolumeX,
  Zap,
} from "lucide-react";
import { Badge, Button, Card, Input, LiveDot, Skeleton } from "../../components/ui";
import { playHudLock, triggerHaptic } from "../../lib/hud-fx";
import { RollingNumber } from "../../lib/motion";
import { cn, copyToClipboard } from "../../lib/utils";
import type { AntennaAlignState } from "../../types/cellcore";
import { TONE_BG, TONE_TEXT, rsrpPct, rsrpTone, rsrpWord } from "./shared";

const TowerFinderCard = lazy(() =>
  import("../../components/TowerFinderCard").then((m) => ({ default: m.TowerFinderCard }))
);

type Vec = (number | null)[];
type AudioMode = "off" | "voice" | "tone" | "geiger";
type FocusTarget = "all" | 0 | 1 | 2 | 3;

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
const AUDIO_VOL_KEY = "qm.align.volume.v1";

const CHAINS = [
  { idx: 0 as const, id: "RX0", name: "Main (PRX)", role: "PRX · TX0", tx: "TX0" },
  { idx: 1 as const, id: "RX1", name: "Diversity (DRX)", role: "DRX", tx: null },
  { idx: 2 as const, id: "RX2", name: "MIMO 3", role: "MIMO · TX1", tx: "TX1" },
  { idx: 3 as const, id: "RX3", name: "MIMO 4", role: "MIMO", tx: null },
] as const;

const JACK_SLOTS = [
  { slot: 0, title: "Jack 1 · Far Left" },
  { slot: 1, title: "Jack 2 · Ctr Left" },
  { slot: 2, title: "Jack 3 · Ctr Right" },
  { slot: 3, title: "Jack 4 · Far Right" },
] as const;

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

function loadSavedVolume(): number {
  try {
    const v = Number(window.localStorage.getItem(AUDIO_VOL_KEY));
    if (Number.isFinite(v) && v >= 0.2 && v <= 1) return v;
  } catch {
    // ignore
  }
  return 0.75;
}

function computeAimScore(rsrpVal: number | null, sinrVal: number | null): number {
  if (rsrpVal == null) return 0;
  return Math.max(0, Math.min(100, Math.round(((rsrpVal + 125) / 55) * 70 + ((sinrVal ?? 5) + 5) * 1.2)));
}

/** Sort rank so physical left-to-right jack labels display in natural bulkhead order. */
function labelSortRank(label: string, fallbackIdx: number): number {
  const s = label.toLowerCase();
  if (s.includes("jack 1") || s.includes("j1") || s.includes("far left") || s.includes("port 1")) return 0;
  if (s.includes("jack 2") || s.includes("j2") || s.includes("ctr left") || s.includes("center left") || s.includes("port 2")) return 1;
  if (s.includes("jack 3") || s.includes("j3") || s.includes("ctr right") || s.includes("center right") || s.includes("port 3")) return 2;
  if (s.includes("jack 4") || s.includes("j4") || s.includes("far right") || s.includes("port 4")) return 3;
  return 10 + fallbackIdx;
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
    <svg viewBox="0 0 200 112" className="w-full max-w-[260px] overflow-visible" aria-hidden>
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

/** Rolling trace of RSRP (selected chain or 4-chain mean) with peak-hold line. */
function Trace({ points, peak }: { points: number[]; peak: number | null }) {
  const gid = useId().replace(/:/g, "");
  const W = 600;
  const H = 156;
  if (points.length < 2) {
    return (
      <div className="flex h-[156px] items-center justify-center rounded-2xl border border-dashed border-line-strong text-[12.5px] text-muted">
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
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-[156px] w-full overflow-visible">
        <defs>
          <linearGradient id={`tr-${gid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" style={{ stopColor: "var(--qm-ember)", stopOpacity: 0.34 }} />
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
        <path d={line} fill="none" strokeWidth="2.75" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" style={{ stroke: "var(--qm-ember)" }} />
      </svg>
      <span
        className="pointer-events-none absolute right-0 h-3.5 w-3.5 -translate-y-1/2 translate-x-1/2 rounded-full border-2 border-raised bg-ember shadow"
        style={{ top: `${(y(last) / H) * 100}%` }}
      />
      <div className="pointer-events-none absolute inset-y-0 left-1 flex flex-col justify-between py-0.5 text-[11px] font-semibold text-muted qm-tabular">
        <span>{hi} dBm</span>
        <span>{lo} dBm</span>
      </div>
      {peak != null && (
        <span
          className="pointer-events-none absolute right-2 -translate-y-full rounded-full bg-berry-soft px-2 py-0.5 text-[10.5px] font-bold text-berry-ink qm-tabular"
          style={{ top: `${(y(peak) / H) * 100}%` }}
        >
          peak {peak}
        </span>
      )}
    </div>
  );
}

/** Clickable vertical level meter for one receive chain (click to solo/focus!). */
function ChainMeter({
  id,
  name,
  jackLabel,
  tx,
  rsrp,
  peak,
  sinr,
  peakSinr,
  rsrq,
  focused,
  dimmed,
  onSelect,
}: {
  id: string;
  name: string;
  jackLabel: string;
  tx: string | null;
  rsrp: number | null;
  peak: number | null;
  sinr: number | null;
  peakSinr: number | null;
  rsrq: number | null;
  focused: boolean;
  dimmed: boolean;
  onSelect: () => void;
}) {
  const tone = rsrpTone(rsrp);
  const gap = rsrp != null && peak != null ? Math.round((rsrp - peak) * 10) / 10 : null;
  const atPeak = gap != null && gap >= -1;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={focused}
      className={cn(
        "qm-subcard qm-hud-card qm-spring-press flex flex-col p-3.5 sm:p-4 min-w-0 text-left transition-all cursor-pointer",
        focused
          ? "qm-reticle ring-2 ring-ember bg-raised shadow-[var(--qm-shadow)]"
          : "hover:border-line-strong",
        dimmed && "opacity-65 hover:opacity-100"
      )}
    >
      <div className="flex items-center justify-between gap-1 w-full">
        <span className="flex items-center gap-1.5 min-w-0">
          <span className="font-mono text-[12.5px] font-bold text-ink">{id}</span>
          {tx && <span className="rounded bg-ember-soft px-1.5 py-0.5 text-[9.5px] font-bold text-ember-ink">{tx}</span>}
          {focused && <span className="rounded bg-jade-soft px-1.5 py-0.5 text-[9.5px] font-bold text-jade-ink">SOLO</span>}
        </span>
        <span className="truncate text-[11px] font-semibold text-ember-ink">
          {jackLabel || <span className="font-normal text-muted">{name}</span>}
        </span>
      </div>
      <div className="mt-3 flex items-end gap-3 w-full">
        <div className="relative h-32 sm:h-40 w-5 sm:w-6 shrink-0 overflow-hidden rounded-full bg-line/80">
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
          <div className={cn("qm-display text-[1.75rem] sm:text-[2.15rem] font-semibold leading-none qm-tabular", rsrp == null ? "text-muted" : "text-ink")}>
            {rsrp ?? "—"}
          </div>
          <div className="mt-1 text-[11px] font-semibold text-muted">dBm RSRP</div>
          <div className={cn("mt-2 text-[12px] font-semibold", TONE_TEXT[tone])}>{rsrpWord(rsrp)}</div>
        </div>
      </div>
      <div className="mt-3 space-y-1 border-t border-line pt-2.5 text-[11.5px] qm-tabular w-full">
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
    </button>
  );
}

function skewTone(db: number | null | undefined): "success" | "warning" | "danger" | "neutral" {
  if (db == null) return "neutral";
  if (db <= 3) return "success";
  if (db <= 6) return "warning";
  return "danger";
}

function speakText(text: string, volume: number) {
  try {
    if (typeof window === "undefined" || !("speechSynthesis" in window)) return;
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(text);
    u.rate = 1.15;
    u.pitch = 1.0;
    u.volume = Math.max(0.2, Math.min(1, volume));
    window.speechSynthesis.speak(u);
  } catch {
    // ignore speech synthesis errors
  }
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
  onResetChainPeak,
  antennaLabels,
  onSaveAntennaLabels,
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
  onResetChainPeak?: (chainIdx: number) => void;
  antennaLabels?: string[];
  onSaveAntennaLabels?: (labels: [string, string, string, string]) => void;
}) {
  const [focus, setFocus] = useState<FocusTarget>("all");
  const [meanTrace, setMeanTrace] = useState<number[]>([]);
  const [chainTraces, setChainTraces] = useState<[number[], number[], number[], number[]]>([[], [], [], []]);
  const [bestMeanScore, setBestMeanScore] = useState(0);
  const [bestChainScores, setBestChainScores] = useState<[number, number, number, number]>([0, 0, 0, 0]);

  const [audioMode, setAudioMode] = useState<AudioMode>("off");
  const [volume, setVolume] = useState<number>(loadSavedVolume);
  const [wakeEnabled, setWakeEnabled] = useState(false);
  const [wakeActive, setWakeActive] = useState(false);
  const wakeSupported =
    typeof navigator !== "undefined" &&
    "wakeLock" in navigator &&
    (typeof window === "undefined" || window.isSecureContext);
  const [haptics, setHaptics] = useState(true);
  const [showOutdoorTools, setShowOutdoorTools] = useState(false);

  // Port identification & label editor state
  const [mapperOpen, setMapperOpen] = useState(false);
  const [draftLabels, setDraftLabels] = useState<[string, string, string, string]>(["", "", "", ""]);
  const [detectStep, setDetectStep] = useState<number | null>(null); // 0..3 jack slot
  const [detectAssigned, setDetectAssigned] = useState<(number | null)[]>([null, null, null, null]); // slot -> chainIdx
  const [detectBaseline, setDetectBaseline] = useState<(number | null)[]>([null, null, null, null]);
  const [detectLastMsg, setDetectLastMsg] = useState<string>("");
  const detectHitStreakRef = useRef<{ chain: number; count: number }>({ chain: -1, count: 0 });

  const [bookmarkLabel, setBookmarkLabel] = useState("");
  const [bookmarks, setBookmarks] = useState<AlignBookmark[]>(loadBookmarks);
  const [copiedBookmarks, setCopiedBookmarks] = useState(false);
  const [handover, setHandover] = useState<{ from: string; to: string } | null>(null);
  const [justHitPeak, setJustHitPeak] = useState(false);
  const [lockPulseSeq, setLockPulseSeq] = useState(0);
  const peakPulseTimerRef = useRef<number | null>(null);

  const audioCtxRef = useRef<AudioContext | null>(null);
  const masterBusRef = useRef<DynamicsCompressorNode | null>(null);
  const oscMainRef = useRef<OscillatorNode | null>(null);
  const oscHarmRef = useRef<OscillatorNode | null>(null);
  const toneGainRef = useRef<GainNode | null>(null);
  const wakeLockRef = useRef<{ release: () => Promise<void> } | null>(null);
  const lastSampleKeyRef = useRef<string>("");
  const prevFocusPeakRef = useRef<number | null>(null);
  const baseCellRef = useRef<{ pci: number | null; band: string } | null>(null);
  const lastObservedCellRef = useRef<{ pci: number | null; band: string } | null>(null);

  // Voice synthesis throttling refs
  const lastSpokenAtRef = useRef<number>(0);
  const lastSpokenValRef = useRef<number | null>(null);

  const normLabels: [string, string, string, string] = useMemo(
    () => [
      antennaLabels?.[0]?.trim() ?? "",
      antennaLabels?.[1]?.trim() ?? "",
      antennaLabels?.[2]?.trim() ?? "",
      antennaLabels?.[3]?.trim() ?? "",
    ],
    [antennaLabels]
  );

  useEffect(() => {
    if (!mapperOpen) {
      setDraftLabels(normLabels);
    }
  }, [normLabels, mapperOpen]);

  // Display order of CHAINS: follow physical jack order when labels specify Jack 1..4 / Far Left..Far Right
  const orderedChains = useMemo(() => {
    const hasCustomOrder = normLabels.some((l) => l.length > 0);
    if (!hasCustomOrder) return [...CHAINS];
    return [...CHAINS].sort(
      (a, b) => labelSortRank(normLabels[a.idx], a.idx) - labelSortRank(normLabels[b.idx], b.idx)
    );
  }, [normLabels]);

  // Resolved active signal metrics for current FocusTarget ("all" vs solo chain 0..3)
  const focusCur = focus === "all" ? summary.meanCur : (rsrp[focus] ?? null);
  const focusPeak = focus === "all" ? summary.meanPeak : (peakRsrp[focus] ?? null);
  const focusSinr = focus === "all" ? summary.meanSinr : (sinr[focus] ?? null);
  const focusPeakSinr = focus === "all" ? (summary.peakMeanSinr ?? null) : (peakSinr[focus] ?? null);
  const focusScore = focus === "all" ? summary.score : computeAimScore(focusCur, focusSinr);
  const focusBest = focus === "all" ? bestMeanScore : bestChainScores[focus];
  const focusTrace = focus === "all" ? meanTrace : chainTraces[focus];
  const focusTitle =
    focus === "all"
      ? "All 4 Antennas (Average)"
      : `${CHAINS[focus].id} · ${normLabels[focus] || CHAINS[focus].role}`;

  const liveFocusRef = useRef({
    focus,
    cur: focusCur,
    peak: focusPeak,
    sinr: focusSinr,
    score: focusScore,
    spread: align?.rsrpSpread ?? null,
    label: focus === "all" ? "All 4" : CHAINS[focus].id,
    volume,
  });
  liveFocusRef.current = {
    focus,
    cur: focusCur,
    peak: focusPeak,
    sinr: focusSinr,
    score: focusScore,
    spread: align?.rsrpSpread ?? null,
    label: focus === "all" ? "All 4" : CHAINS[focus].id,
    volume,
  };

  // Auto-enable 4x4 RX keep-awake only when user explicitly enters RX2/RX3 (never fights clicking OFF)
  const selectFocus = useCallback(
    (next: FocusTarget) => {
      setFocus(next);
      if ((next === 2 || next === 3) && !keepAwake) {
        onToggleKeepAwake(true);
      }
    },
    [keepAwake, onToggleKeepAwake]
  );

  const stopToneNodes = useCallback(() => {
    for (const ref of [oscMainRef, oscHarmRef]) {
      try {
        ref.current?.stop();
        ref.current?.disconnect();
      } catch {
        // ignore
      }
      ref.current = null;
    }
    try {
      toneGainRef.current?.disconnect();
    } catch {
      // ignore
    }
    toneGainRef.current = null;
  }, []);

  /** Create/unlock AudioContext + master compressor inside a user gesture so laptop speakers always wake. */
  const ensureAudioGraph = useCallback((): { ctx: AudioContext; bus: AudioNode } | null => {
    const Ctor =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return null;
    if (!audioCtxRef.current || audioCtxRef.current.state === "closed") {
      const ctx = new Ctor();
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.setValueAtTime(-14, ctx.currentTime);
      comp.knee.setValueAtTime(12, ctx.currentTime);
      comp.ratio.setValueAtTime(4, ctx.currentTime);
      comp.attack.setValueAtTime(0.003, ctx.currentTime);
      comp.release.setValueAtTime(0.15, ctx.currentTime);
      comp.connect(ctx.destination);
      audioCtxRef.current = ctx;
      masterBusRef.current = comp;
    }
    const ctx = audioCtxRef.current;
    const bus = masterBusRef.current ?? ctx.destination;
    if (ctx.state === "suspended") {
      void ctx.resume().catch(() => {});
    }
    return { ctx, bus };
  }, []);

  /** Audible confirmation/peak chime routed through master compressor (waits for ctx.resume if needed). */
  const playChime = useCallback(
    (kind: "confirm" | "peak" | "handover", force = false) => {
      if (!force && audioMode === "off") return;
      const graph = ensureAudioGraph();
      if (!graph) return;
      const { ctx, bus } = graph;
      const fire = () => {
        const now = ctx.currentTime + 0.01;
        const notes =
          kind === "peak"
            ? [659.25, 880, 1174.66]
            : kind === "confirm"
              ? [587.33, 880]
              : [622.25, 415.3];
        const peakGain = 0.28 * liveFocusRef.current.volume;
        notes.forEach((f, idx) => {
          const t0 = now + idx * 0.085;
          const osc = ctx.createOscillator();
          const g = ctx.createGain();
          osc.type = kind === "handover" ? "sawtooth" : "triangle";
          osc.frequency.setValueAtTime(f, t0);
          g.gain.setValueAtTime(0.001, t0);
          g.gain.linearRampToValueAtTime(peakGain, t0 + 0.012);
          g.gain.exponentialRampToValueAtTime(0.001, t0 + 0.14);
          osc.connect(g);
          g.connect(bus);
          osc.start(t0);
          osc.stop(t0 + 0.15);
        });
      };
      if (ctx.state === "suspended") {
        void ctx.resume().then(fire).catch(() => {});
      } else {
        fire();
      }
    },
    [audioMode, ensureAudioGraph]
  );

  /** Map RSRP around a tight 20 dB window anchored near peak so every 1 dB move gives an obvious pitch step. */
  const computePitchHz = useCallback((cur: number | null, peak: number | null): number => {
    const v = cur ?? -105;
    const anchorHi = peak != null ? peak + 2 : -82;
    const anchorLo = anchorHi - 22;
    const norm = Math.max(0, Math.min(1, (v - anchorLo) / (anchorHi - anchorLo)));
    // Exponential musical pitch from 310 Hz to 1420 Hz (audible on small laptop speakers)
    return 310 * Math.pow(1420 / 310, norm);
  }, []);

  // Manage Tone & Geiger audio generators
  useEffect(() => {
    stopToneNodes();
    if (audioMode !== "tone" && audioMode !== "geiger") {
      if (audioMode === "off" && typeof window !== "undefined" && "speechSynthesis" in window) {
        try {
          window.speechSynthesis.cancel();
        } catch {
          // ignore
        }
      }
      return;
    }
    const graph = ensureAudioGraph();
    if (!graph) return;
    const { ctx, bus } = graph;

    if (audioMode === "tone") {
      const startTone = () => {
        if (oscMainRef.current) return;
        const osc1 = ctx.createOscillator();
        const osc2 = ctx.createOscillator();
        const harmGain = ctx.createGain();
        const mainGain = ctx.createGain();
        osc1.type = "triangle";
        osc2.type = "sine";
        const hz = computePitchHz(liveFocusRef.current.cur, liveFocusRef.current.peak);
        osc1.frequency.setValueAtTime(hz, ctx.currentTime);
        osc2.frequency.setValueAtTime(hz * 2, ctx.currentTime);
        harmGain.gain.setValueAtTime(0.35, ctx.currentTime);
        mainGain.gain.setValueAtTime(0.2 * liveFocusRef.current.volume, ctx.currentTime);

        osc1.connect(mainGain);
        osc2.connect(harmGain);
        harmGain.connect(mainGain);
        mainGain.connect(bus);
        osc1.start();
        osc2.start();
        oscMainRef.current = osc1;
        oscHarmRef.current = osc2;
        toneGainRef.current = mainGain;
      };
      if (ctx.state === "suspended") {
        void ctx.resume().then(startTone).catch(() => {});
      } else {
        startTone();
      }
      return () => stopToneNodes();
    }

    // Geiger mode: crisp dual-oscillator percussive ticks whose tempo tracks proximity to peak + score
    let timer = 0;
    const schedule = () => {
      const { cur, peak, score, volume: vol } = liveFocusRef.current;
      const gapFromPeak = cur != null && peak != null ? Math.max(0, peak - cur) : 8;
      // Fast 95 ms chatter at peak, slowing to ~580 ms when >10 dB below peak
      const closeness = Math.max(0, Math.min(1, 1 - gapFromPeak / 12)) * 0.65 + (score / 100) * 0.35;
      const periodMs = Math.max(90, Math.round(600 - closeness * 505));

      const emitTick = () => {
        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const g = ctx.createGain();
        osc.type = "triangle";
        const f0 = 660 + Math.round(closeness * 920);
        osc.frequency.setValueAtTime(f0 * 1.25, now);
        osc.frequency.exponentialRampToValueAtTime(f0, now + 0.04);
        g.gain.setValueAtTime(0.001, now);
        g.gain.linearRampToValueAtTime(0.32 * vol, now + 0.005);
        g.gain.exponentialRampToValueAtTime(0.001, now + 0.048);
        osc.connect(g);
        g.connect(bus);
        osc.start(now);
        osc.stop(now + 0.052);
      };

      if (ctx.state === "suspended") {
        void ctx.resume().then(emitTick).catch(() => {});
      } else if (ctx.state === "running") {
        emitTick();
      }
      timer = window.setTimeout(schedule, periodMs);
    };
    schedule();
    return () => {
      window.clearTimeout(timer);
      stopToneNodes();
    };
  }, [audioMode, computePitchHz, ensureAudioGraph, stopToneNodes]);

  // Smoothly update Tone frequency & volume whenever signal or focus changes
  useEffect(() => {
    if (audioMode !== "tone" || !oscMainRef.current || !audioCtxRef.current) return;
    const now = audioCtxRef.current.currentTime;
    const hz = computePitchHz(focusCur, focusPeak);
    oscMainRef.current.frequency.setTargetAtTime(hz, now, 0.06);
    oscHarmRef.current?.frequency.setTargetAtTime(hz * 2, now, 0.06);
    toneGainRef.current?.gain.setTargetAtTime(0.2 * volume, now, 0.05);
  }, [audioMode, computePitchHz, focusCur, focusPeak, volume]);

  useEffect(() => {
    return () => {
      if (peakPulseTimerRef.current != null) {
        window.clearTimeout(peakPulseTimerRef.current);
        peakPulseTimerRef.current = null;
      }
      stopToneNodes();
      if (typeof window !== "undefined" && "speechSynthesis" in window) {
        try {
          window.speechSynthesis.cancel();
        } catch {
          // ignore
        }
      }
      void audioCtxRef.current?.close().catch(() => {});
    };
  }, [stopToneNodes]);

  // Screen Wake Lock while aiming
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

  // Reset all traces & peaks when Reset All Peaks clicked
  useEffect(() => {
    if (resetSeq === 0) return;
    setMeanTrace([]);
    setChainTraces([[], [], [], []]);
    setBestMeanScore(0);
    setBestChainScores([0, 0, 0, 0]);
    setHandover(null);
    setJustHitPeak(false);
    prevFocusPeakRef.current = null;
    lastSpokenValRef.current = null;
    baseCellRef.current =
      align?.servingPci != null || align?.servingBand
        ? { pci: align?.servingPci ?? null, band: align?.servingBand ?? "" }
        : null;
    lastObservedCellRef.current = baseCellRef.current;
  }, [resetSeq]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reset peak tracker when user switches between antennas
  useEffect(() => {
    prevFocusPeakRef.current = focusPeak;
    lastSpokenValRef.current = null;
    setJustHitPeak(false);
  }, [focus]); // eslint-disable-line react-hooks/exhaustive-deps

  // WebSocket-driven trace updates, Voice readout, Peak chime & Port Auto-Detect
  useEffect(() => {
    const sampleKey = `${align?.updatedAtMs ?? 0}:${align?.samples ?? samples}:${rsrp.join(",")}`;
    if (sampleKey === lastSampleKeyRef.current) return;
    lastSampleKeyRef.current = sampleKey;

    if (summary.meanCur != null) {
      setMeanTrace((t) => [...t.slice(-(HISTORY - 1)), summary.meanCur!]);
      setBestMeanScore((b) => Math.max(b, summary.score));
    }
    setChainTraces((prev) => [
      rsrp[0] != null ? [...prev[0].slice(-(HISTORY - 1)), rsrp[0]] : prev[0],
      rsrp[1] != null ? [...prev[1].slice(-(HISTORY - 1)), rsrp[1]] : prev[1],
      rsrp[2] != null ? [...prev[2].slice(-(HISTORY - 1)), rsrp[2]] : prev[2],
      rsrp[3] != null ? [...prev[3].slice(-(HISTORY - 1)), rsrp[3]] : prev[3],
    ]);
    setBestChainScores((prev) => [
      Math.max(prev[0], computeAimScore(rsrp[0] ?? null, sinr[0] ?? null)),
      Math.max(prev[1], computeAimScore(rsrp[1] ?? null, sinr[1] ?? null)),
      Math.max(prev[2], computeAimScore(rsrp[2] ?? null, sinr[2] ?? null)),
      Math.max(prev[3], computeAimScore(rsrp[3] ?? null, sinr[3] ?? null)),
    ]);

    // Peak detector for currently focused target
    const isNewPeak =
      focusPeak != null && prevFocusPeakRef.current != null && focusPeak > prevFocusPeakRef.current;
    if (isNewPeak) {
      setJustHitPeak(true);
      setLockPulseSeq((n) => n + 1);
      if (peakPulseTimerRef.current != null) {
        window.clearTimeout(peakPulseTimerRef.current);
      }
      peakPulseTimerRef.current = window.setTimeout(() => {
        setJustHitPeak(false);
        peakPulseTimerRef.current = null;
      }, 2400);

      if (audioMode === "voice") {
        speakText(`Minus ${Math.abs(Math.round(focusPeak))}, new peak`, volume);
        lastSpokenAtRef.current = Date.now();
        lastSpokenValRef.current = Math.round(focusPeak);
        if (haptics && typeof navigator.vibrate === "function") {
          navigator.vibrate(30);
        }
      } else if (audioMode === "tone" || audioMode === "geiger") {
        playChime("peak");
        if (haptics && typeof navigator.vibrate === "function") {
          navigator.vibrate(30);
        }
      } else {
        // AlignView's own audio is OFF — softly cue HUD lock SFX/haptic if user opted into hudSfx
        playHudLock();
        if (haptics) triggerHaptic(10);
      }
    }
    prevFocusPeakRef.current = focusPeak;

    // Hands-free Voice readout every ~2.3s on >=1 dB move, or ~5.5s steady keepalive
    if (audioMode === "voice" && !isNewPeak && focusCur != null && detectStep == null) {
      const nowMs = Date.now();
      const rounded = Math.round(focusCur);
      const prevVal = lastSpokenValRef.current;
      const diff = prevVal != null ? rounded - prevVal : 99;
      const elapsed = nowMs - lastSpokenAtRef.current;
      if ((Math.abs(diff) >= 1 && elapsed >= 2200) || elapsed >= 5500) {
        let phrase = `Minus ${Math.abs(rounded)}`;
        if (prevVal != null && diff >= 1) phrase += `, up ${diff}`;
        else if (prevVal != null && diff <= -1) phrase += `, down ${Math.abs(diff)}`;
        else if (focusPeak != null && rounded >= Math.round(focusPeak) - 1) phrase += `, at peak`;
        speakText(phrase, volume);
        lastSpokenAtRef.current = nowMs;
        lastSpokenValRef.current = rounded;
      }
    }

    // Guided Port Auto-Detect: watch for an unassigned chain moving >= 4.5 dB relative to others
    if (detectStep != null && detectStep >= 0 && detectStep < 4) {
      if (detectBaseline.every((b) => b == null) && rsrp.some((v) => v != null)) {
        setDetectBaseline([rsrp[0] ?? null, rsrp[1] ?? null, rsrp[2] ?? null, rsrp[3] ?? null]);
      } else {
        const usedChains = new Set(detectAssigned.filter((x): x is number => x != null));
        const diffs: Array<{ ch: number; delta: number }> = [];
        for (let ch = 0; ch < 4; ch++) {
          if (usedChains.has(ch)) continue;
          const base = detectBaseline[ch];
          const cur = rsrp[ch];
          if (base != null && cur != null) {
            diffs.push({ ch, delta: Math.abs(cur - base) });
          } else if (base != null && cur == null) {
            // Antenna completely unscrewed (dropped to None)
            diffs.push({ ch, delta: 25 });
          } else if (base == null && cur != null) {
            // Antenna screwed onto previously empty jack
            diffs.push({ ch, delta: 25 });
          }
        }
        if (diffs.length > 0) {
          diffs.sort((a, b) => b.delta - a.delta);
          const top = diffs[0];
          const runnerUp = diffs[1]?.delta ?? 0;
          if (top.delta >= 4.5 && top.delta - runnerUp >= 3.0) {
            if (detectHitStreakRef.current.chain === top.ch) {
              detectHitStreakRef.current.count += 1;
            } else {
              detectHitStreakRef.current = { chain: top.ch, count: 1 };
            }
            if (detectHitStreakRef.current.count >= 2) {
              const slotTitle = JACK_SLOTS[detectStep].title;
              const nextAssigned = [...detectAssigned];
              nextAssigned[detectStep] = top.ch;
              const nextLabels: [string, string, string, string] = [...draftLabels] as [string, string, string, string];
              nextLabels[top.ch] = slotTitle;

              // If 3 jacks are assigned, the 4th remaining jack maps deterministically to the last chain!
              const assignedCount = nextAssigned.filter((x) => x != null).length;
              if (assignedCount === 3) {
                const lastSlot = nextAssigned.findIndex((x) => x == null);
                const allUsed = new Set(nextAssigned.filter((x): x is number => x != null));
                const lastCh = [0, 1, 2, 3].find((c) => !allUsed.has(c)) ?? null;
                if (lastSlot >= 0 && lastCh != null) {
                  nextAssigned[lastSlot] = lastCh;
                  nextLabels[lastCh] = JACK_SLOTS[lastSlot].title;
                }
                setDetectAssigned(nextAssigned);
                setDraftLabels(nextLabels);
                setDetectStep(null);
                setDetectLastMsg(`Mapped all 4 jacks! (${slotTitle} → RX${top.ch}, auto-completed remaining port)`);
                playChime("peak", true);
                speakText(`${slotTitle} is R X ${top.ch}. All four ports mapped!`, volume);
                onSaveAntennaLabels?.(nextLabels);
              } else {
                const nextStep = detectStep + 1;
                setDetectAssigned(nextAssigned);
                setDraftLabels(nextLabels);
                setDetectStep(nextStep);
                setDetectBaseline([rsrp[0] ?? null, rsrp[1] ?? null, rsrp[2] ?? null, rsrp[3] ?? null]);
                detectHitStreakRef.current = { chain: -1, count: 0 };
                setDetectLastMsg(`Detected ${slotTitle} → RX${top.ch}! Now touch/loosen ${JACK_SLOTS[nextStep].title}…`);
                playChime("confirm", true);
                speakText(`R X ${top.ch}. Next, touch ${JACK_SLOTS[nextStep].title}`, volume);
              }
            }
          }
        }
      }
    }

    // Serving cell handover check: chime only on cell transitions, never every 400 ms
    const curPci = align?.servingPci ?? null;
    const curBand = align?.servingBand ?? "";
    if (curPci != null || curBand) {
      if (!baseCellRef.current) {
        baseCellRef.current = { pci: curPci, band: curBand };
        lastObservedCellRef.current = { pci: curPci, band: curBand };
      } else {
        const prevObs = lastObservedCellRef.current;
        const transitioned = !prevObs || prevObs.pci !== curPci || prevObs.band !== curBand;
        lastObservedCellRef.current = { pci: curPci, band: curBand };
        if (transitioned && (baseCellRef.current.pci !== curPci || baseCellRef.current.band !== curBand)) {
          setHandover({
            from: `${baseCellRef.current.band || "?"} PCI ${baseCellRef.current.pci ?? "?"}`,
            to: `${curBand || "?"} PCI ${curPci ?? "?"}`,
          });
          playChime("handover");
        }
      }
    }
  }, [
    align?.updatedAtMs,
    align?.samples,
    align?.servingPci,
    align?.servingBand,
    samples,
    rsrp,
    sinr,
    summary.meanCur,
    summary.score,
    focusCur,
    focusPeak,
    audioMode,
    volume,
    playChime,
    haptics,
    detectStep,
    detectBaseline,
    detectAssigned,
    draftLabels,
    onSaveAntennaLabels,
  ]);

  const selectAudioMode = useCallback(
    (next: AudioMode) => {
      setAudioMode(next);
      if (next === "off") {
        if (typeof window !== "undefined" && "speechSynthesis" in window) {
          try {
            window.speechSynthesis.cancel();
          } catch {
            // ignore
          }
        }
        return;
      }
      ensureAudioGraph();
      if (next === "voice") {
        const curTxt = focusCur != null ? `minus ${Math.abs(Math.round(focusCur))}` : "waiting for signal";
        speakText(`Voice readout on. ${focus === "all" ? "All four" : CHAINS[focus].id}, ${curTxt}`, volume);
        lastSpokenAtRef.current = Date.now();
      } else {
        playChime("confirm", true);
      }
    },
    [ensureAudioGraph, focus, focusCur, playChime, volume]
  );

  const cycleVolume = () => {
    const next = volume < 0.5 ? 0.75 : volume < 0.9 ? 1.0 : 0.4;
    setVolume(next);
    try {
      window.localStorage.setItem(AUDIO_VOL_KEY, String(next));
    } catch {
      // ignore
    }
    if (audioMode === "voice") {
      speakText(`Volume ${Math.round(next * 100)} percent`, next);
    } else {
      playChime("confirm", true);
    }
  };

  const stepFocus = useCallback(
    (dir: 1 | -1) => {
      const seq: FocusTarget[] = ["all", ...orderedChains.map((c) => c.idx)];
      const curPos = seq.indexOf(focus);
      const nextPos = (curPos + dir + seq.length) % seq.length;
      const nextTarget = seq[nextPos];
      selectFocus(nextTarget);
      if (audioMode === "voice") {
        const name = nextTarget === "all" ? "All four antennas" : `${CHAINS[nextTarget].id} ${normLabels[nextTarget]}`;
        speakText(name, volume);
      }
    },
    [audioMode, focus, normLabels, orderedChains, selectFocus, volume]
  );

  const handleResetActivePeak = useCallback(() => {
    if (focus === "all" || !onResetChainPeak) {
      onResetPeaks();
    } else {
      onResetChainPeak(focus);
      setChainTraces((prev) => {
        const next: [number[], number[], number[], number[]] = [...prev] as [number[], number[], number[], number[]];
        next[focus] = rsrp[focus] != null ? [rsrp[focus]!] : [];
        return next;
      });
      setBestChainScores((prev) => {
        const next: [number, number, number, number] = [...prev] as [number, number, number, number];
        next[focus] = computeAimScore(rsrp[focus] ?? null, sinr[focus] ?? null);
        return next;
      });
      prevFocusPeakRef.current = rsrp[focus] ?? null;
    }
  }, [focus, onResetChainPeak, onResetPeaks, rsrp, sinr]);

  // Laptop keyboard shortcuts (0 = All, 1-4 = ordered antennas, N = Next, R = Reset Peak, M = Audio)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (document.querySelector('[role="dialog"]')) return;
      const tag = (e.target as HTMLElement | null)?.tagName?.toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "0") {
        selectFocus("all");
      } else if (e.key >= "1" && e.key <= "4") {
        const ch = orderedChains[Number(e.key) - 1];
        if (ch) selectFocus(ch.idx);
      } else if (e.key === "n" || e.key === "N") {
        stepFocus(1);
      } else if (e.key === "r" || e.key === "R") {
        handleResetActivePeak();
      } else if (e.key === "m" || e.key === "M") {
        const order: AudioMode[] = ["off", "voice", "tone", "geiger"];
        selectAudioMode(order[(order.indexOf(audioMode) + 1) % order.length]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [audioMode, handleResetActivePeak, orderedChains, selectAudioMode, selectFocus, stepFocus]);

  const startAutoDetect = () => {
    ensureAudioGraph();
    if (!keepAwake) onToggleKeepAwake(true);
    setMapperOpen(true);
    setDetectAssigned([null, null, null, null]);
    setDetectBaseline([rsrp[0] ?? null, rsrp[1] ?? null, rsrp[2] ?? null, rsrp[3] ?? null]);
    detectHitStreakRef.current = { chain: -1, count: 0 };
    setDetectStep(0);
    setDetectLastMsg(`Step 1 of 4: Cover with your hand or loosen ${JACK_SLOTS[0].title}…`);
    playChime("confirm", true);
    speakText(`Touch or loosen ${JACK_SLOTS[0].title}`, volume);
  };

  const applyPresetLabels = (preset: [string, string, string, string]) => {
    setDraftLabels(preset);
    setDetectStep(null);
    setDetectLastMsg("Applied preset jack labels.");
    onSaveAntennaLabels?.(preset);
  };

  const addBookmark = () => {
    const defaultName =
      focus === "all"
        ? `${bookmarks.length + 1} · All 4`
        : `${bookmarks.length + 1} · ${CHAINS[focus].id}`;
    const label = bookmarkLabel.trim() || defaultName;
    const entry: AlignBookmark = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      label,
      meanRsrp: focusCur,
      peakMeanRsrp: focusPeak,
      meanSinr: focusSinr,
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
    void copyToClipboard([header, ...rows].join("\n")).then((ok) => {
      if (!ok) return;
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

  const prevWindow = focusTrace.length > 6 ? focusTrace.slice(-7, -2).reduce((a, b) => a + b, 0) / 5 : null;
  const delta = prevWindow != null && focusCur != null ? Math.round((focusCur - prevWindow) * 10) / 10 : 0;
  const trend = delta > 0.6 ? "up" : delta < -0.6 ? "down" : "flat";
  const scoreTone = focusScore >= 70 ? "jade" : focusScore >= 45 ? "saffron" : focusCur == null ? "muted" : "crimson";
  const peakGap = focusCur != null && focusPeak != null ? Math.round((focusCur - focusPeak) * 10) / 10 : null;
  const isPeakLocked = peakGap != null && peakGap >= -1;
  const showNewPeakPill = justHitPeak || (peakGap != null && peakGap >= 0 && focusPeak != null && samples > 1);
  const heroDecimals = focus === "all" ? 1 : 0;

  return (
    <div className="space-y-4 sm:space-y-5">
      {/* 1. Target Antenna Selector + Hands-Free Audio Controls */}
      <Card className="p-3.5 sm:p-4 space-y-3.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[11px] font-bold uppercase tracking-wider text-muted">
              1. Select What You Are Adjusting
            </div>
            <p className="text-[12px] text-muted">
              Solo a single antenna to get full 1:1 dB sensitivity &amp; audio feedback without the other 3 averaging it out
            </p>
          </div>
          <Button
            size="sm"
            variant={mapperOpen ? "primary" : "secondary"}
            onClick={() => {
              setMapperOpen((v) => !v);
              if (mapperOpen) setDetectStep(null);
            }}
          >
            <Crosshair className="h-3.5 w-3.5" />
            {normLabels.some((l) => l) ? "Edit Jack Map" : "Identify Jacks"}
          </Button>
        </div>

        {/* Tactile Target Pills: All 4 + Each Antenna */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 qm-tabular">
          <button
            type="button"
            onClick={() => selectFocus("all")}
            className={cn(
              "flex flex-col justify-between rounded-2xl border p-3 text-left transition-all cursor-pointer min-h-[68px]",
              focus === "all"
                ? "border-ember bg-ember-soft/45 ring-2 ring-ember"
                : "border-line bg-sunk/70 hover:border-line-strong"
            )}
          >
            <div className="flex items-center justify-between gap-1">
              <span className="text-[12px] font-bold text-ink">All 4</span>
              <span className="text-[10px] font-semibold text-muted">Panel</span>
            </div>
            <div className="mt-1 flex items-baseline justify-between gap-1">
              <span className={cn("qm-display text-[1.25rem] font-semibold leading-none", TONE_TEXT[rsrpTone(summary.meanCur)])}>
                {summary.meanCur ?? "—"}
              </span>
              <span className="text-[10.5px] text-muted">
                {align?.rsrpSpread != null ? `Δ${align.rsrpSpread}dB` : "dBm"}
              </span>
            </div>
          </button>

          {orderedChains.map((c, posIdx) => {
            const val = rsrp[c.idx] ?? null;
            const isSel = focus === c.idx;
            const jLabel = normLabels[c.idx];
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => selectFocus(isSel ? "all" : c.idx)}
                title={`Shortcut key: ${posIdx + 1}`}
                className={cn(
                  "flex flex-col justify-between rounded-2xl border p-3 text-left transition-all cursor-pointer min-h-[68px]",
                  isSel
                    ? "border-ember bg-ember-soft/45 ring-2 ring-ember"
                    : "border-line bg-sunk/70 hover:border-line-strong"
                )}
              >
                <div className="flex items-center justify-between gap-1 min-w-0">
                  <span className="font-mono text-[12px] font-bold text-ink">{c.id}</span>
                  {c.tx ? (
                    <span className="rounded bg-ember-soft px-1.5 py-0.5 text-[9.5px] font-bold text-ember-ink">{c.tx}</span>
                  ) : (
                    <span className="text-[10px] text-muted">{c.role}</span>
                  )}
                </div>
                {jLabel && (
                  <div className="truncate text-[11px] font-semibold text-ember-ink mt-0.5">{jLabel}</div>
                )}
                <div className="mt-1 flex items-baseline justify-between gap-1">
                  <span className={cn("qm-display text-[1.25rem] font-semibold leading-none", TONE_TEXT[rsrpTone(val)])}>
                    {val ?? "—"}
                  </span>
                  <span className="text-[10.5px] text-muted">
                    {sinr[c.idx] != null ? `${sinr[c.idx]}dB` : "idle"}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Audio Mode Bar + Volume + Test + Keep-Awake + Reset */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-line">
          <div className="inline-flex rounded-xl border border-line bg-sunk p-1 gap-1" role="group" aria-label="Audio feedback mode">
            {(
              [
                { id: "off", label: "Mute" },
                { id: "voice", label: "Voice" },
                { id: "tone", label: "Tone" },
                { id: "geiger", label: "Geiger" },
              ] as const
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => selectAudioMode(m.id)}
                className={cn(
                  "rounded-lg px-2.5 py-1.5 text-[12px] font-semibold transition-colors cursor-pointer flex items-center gap-1.5",
                  audioMode === m.id
                    ? "bg-ember text-on-ember shadow-sm"
                    : "text-ink-2 hover:text-ink"
                )}
              >
                {m.id === "off" ? <VolumeX className="h-3.5 w-3.5" /> : m.id === "voice" ? <Volume2 className="h-3.5 w-3.5" /> : null}
                {m.label}
              </button>
            ))}
          </div>

          <Button
            size="sm"
            variant="secondary"
            onClick={cycleVolume}
            title="Cycle audio loudness (40% / 75% / 100%)"
          >
            Vol {Math.round(volume * 100)}%
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              if (audioMode === "voice") {
                speakText(
                  `${focus === "all" ? "All four" : CHAINS[focus].id}, ${focusCur != null ? `minus ${Math.abs(Math.round(focusCur))} d B m` : "ready"}`,
                  volume
                );
              } else {
                playChime("confirm", true);
              }
            }}
            title="Play an audible test sound to verify laptop speakers"
          >
            <Play className="h-3.5 w-3.5" />
            Test sound
          </Button>

          <div className="sm:ml-auto flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={handleResetActivePeak}
              disabled={busy === "align-reset"}
            >
              <RotateCcw className="h-3.5 w-3.5" />
              {focus === "all" ? "Reset all peaks" : `Reset ${CHAINS[focus].id} peak`}
            </Button>
            <Button
              size="sm"
              variant={keepAwake ? "primary" : "secondary"}
              onClick={() => onToggleKeepAwake(!keepAwake)}
              disabled={busy === "align-awake"}
              title="1 Hz 32 KiB cellular keep-alive burst keeps secondary RX2/RX3 chains awake continuously"
            >
              <Zap className="h-3.5 w-3.5" />
              {keepAwake ? "4×4 Awake: ON" : "4×4 Awake: OFF"}
            </Button>
            <Button
              size="sm"
              variant={wakeEnabled ? "primary" : "ghost"}
              disabled={!wakeSupported}
              onClick={() => wakeSupported && setWakeEnabled((v) => !v)}
              title={wakeSupported ? "Keep screen from dimming while aiming" : "Screen Wake Lock requires HTTPS"}
            >
              <Sun className="h-3.5 w-3.5" />
              {!wakeSupported
                ? "HTTPS required"
                : wakeEnabled
                  ? wakeActive
                    ? "Screen Awake"
                    : "Wake…"
                  : "Wake Lock"}
            </Button>
          </div>
        </div>
      </Card>

      {/* Guided Port Identifier & Jack Label Editor Drawer */}
      {mapperOpen && (
        <Card className="border-ember/50 bg-raised p-4 space-y-3.5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="qm-display text-[1.05rem] font-semibold text-ink flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-ember-ink" /> Identify Which Physical Jack Maps to RX0–RX3
              </h3>
              <p className="text-[12px] text-muted mt-0.5">
                Auto-detect ports hands-free by touching/loosening one antenna at a time, or apply a 1-click hardware preset. Saved to the modem.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {detectStep == null ? (
                <Button size="sm" variant="primary" onClick={startAutoDetect}>
                  <Crosshair className="h-3.5 w-3.5" />
                  Start Guided Auto-Detect
                </Button>
              ) : (
                <Button size="sm" variant="secondary" onClick={() => setDetectStep(null)}>
                  Stop Auto-Detect
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => { setMapperOpen(false); setDetectStep(null); }}>
                Close
              </Button>
            </div>
          </div>

          {detectStep != null && (
            <div className="rounded-2xl border border-ember/45 bg-ember-soft/30 p-3.5 flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-[12px] font-bold uppercase tracking-wide text-ember-ink">
                  Auto-Detecting · Step {detectStep + 1} of 4 ({JACK_SLOTS[detectStep].title})
                </div>
                <div className="text-[13.5px] font-semibold text-ink mt-0.5">
                  Wrap your hand tightly around (or unscrew) <span className="underline">{JACK_SLOTS[detectStep].title}</span> until it shifts ≥5 dB…
                </div>
                {detectLastMsg && <div className="text-[12px] text-muted mt-1">{detectLastMsg}</div>}
              </div>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setDetectBaseline([rsrp[0] ?? null, rsrp[1] ?? null, rsrp[2] ?? null, rsrp[3] ?? null])}
              >
                Re-snapshot baseline
              </Button>
            </div>
          )}

          {detectStep == null && detectLastMsg && (
            <div className="text-[12px] font-semibold text-jade-ink">{detectLastMsg}</div>
          )}

          {/* Quick Hardware Presets */}
          <div className="flex flex-wrap items-center gap-2 text-[12px]">
            <span className="font-semibold text-muted">1-Click Presets:</span>
            <Button
              size="sm"
              variant="secondary"
              onClick={() =>
                applyPresetLabels([
                  "Jack 1 · Far Left",
                  "Jack 4 · Far Right",
                  "Jack 2 · Ctr Left",
                  "Jack 3 · Ctr Right",
                ])
              }
              title="Verified Quectel RM551E-GL MHF4 0·1·2·3 sequential bulkhead order (ANT0=RX0, ANT1=RX2, ANT2=RX3, ANT3=RX1)"
            >
              RM551E-GL Sequential (J1=RX0, J2=RX2, J3=RX3, J4=RX1)
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() =>
                applyPresetLabels([
                  "Jack 1 · Far Left",
                  "Jack 2 · Ctr Left",
                  "Jack 3 · Ctr Right",
                  "Jack 4 · Far Right",
                ])
              }
            >
              1:1 Sequential (RX0·RX1·RX2·RX3)
            </Button>
            <Button size="sm" variant="ghost" onClick={() => applyPresetLabels(["", "", "", ""])}>
              Clear labels
            </Button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
            {CHAINS.map((c) => (
              <div key={c.id} className="space-y-1">
                <label className="flex items-center justify-between text-[11.5px] font-semibold text-ink-2">
                  <span>
                    {c.id} <span className="text-muted font-normal">({c.role})</span>
                  </span>
                  <span className="font-mono text-muted">{rsrp[c.idx] ?? "—"} dBm</span>
                </label>
                <Input
                  value={draftLabels[c.idx]}
                  placeholder="e.g. Jack 1 · Far Left"
                  onChange={(e) => {
                    const next: [string, string, string, string] = [...draftLabels] as [string, string, string, string];
                    next[c.idx] = e.target.value;
                    setDraftLabels(next);
                  }}
                />
              </div>
            ))}
          </div>

          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="primary"
              disabled={busy === "align-labels"}
              onClick={() => {
                onSaveAntennaLabels?.(draftLabels);
                setMapperOpen(false);
              }}
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              Save labels to modem
            </Button>
          </div>
        </Card>
      )}

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
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                baseCellRef.current = { pci: align?.servingPci ?? null, band: align?.servingBand ?? "" };
                lastObservedCellRef.current = baseCellRef.current;
                setHandover(null);
              }}
            >
              Dismiss
            </Button>
          </div>
        </div>
      )}

      {/* 2. Across-the-Room Live Hero Readout + Gauge + 36s Trace */}
      <Card className="qm-hud-card qm-reticle overflow-hidden p-0 sm:p-0">
        <div className="qm-grain relative z-[1] grid lg:grid-cols-12">
          <div className="lg:col-span-5 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-line px-5 py-5 sm:p-6">
            <div className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-2 text-[12px] font-semibold text-ink-2">
                <LiveDot tone={active ? "jade" : "saffron"} />
                {active ? "Live · 400 ms" : "Starting fast sampling…"}
              </span>
              <div className="flex items-center gap-1.5">
                <Button size="sm" variant="ghost" onClick={() => stepFocus(-1)} title="Previous antenna">
                  <ArrowLeft className="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="secondary" onClick={() => stepFocus(1)} title="Next antenna (Shortcut: N)">
                  Next <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>

            {/* Big Across-the-Room Readout with Target-Lock Reticle */}
            <div className="my-4 flex flex-col items-center text-center qm-tabular">
              <div className="inline-flex items-center gap-2 rounded-full bg-sunk px-3 py-1 text-[12px] font-bold text-ink">
                {focus === "all" ? "AIMING ALL 4" : `SOLOING ${focusTitle.toUpperCase()}`}
              </div>

              <div
                className={cn(
                  "relative mt-3 flex items-center justify-center rounded-2xl px-8 py-4 sm:px-10 sm:py-5 transition-all duration-300",
                  isPeakLocked &&
                    "bg-jade-soft/20 shadow-[0_0_32px_-12px_var(--qm-jade)]"
                )}
              >
                {/* Target-Lock SVG corner brackets + inner crosshair ring */}
                <svg
                  viewBox="0 0 240 120"
                  preserveAspectRatio="none"
                  className="pointer-events-none absolute inset-0 h-full w-full overflow-visible"
                  aria-hidden
                >
                  {/* Inner crosshair ring & lock pulse */}
                  <g
                    className="transition-transform duration-300 ease-out"
                    style={{
                      transformOrigin: "120px 60px",
                      transform: isPeakLocked ? "scale(0.92)" : "scale(1)",
                    }}
                  >
                    <circle
                      cx="120"
                      cy="60"
                      r="50"
                      fill="none"
                      stroke={isPeakLocked ? "var(--qm-jade)" : "var(--qm-line-strong)"}
                      strokeWidth={isPeakLocked ? "1.25" : "0.9"}
                      strokeDasharray="3 5"
                      opacity={isPeakLocked ? "0.6" : "0.32"}
                    />
                    {/* 4 cardinal crosshair ticks */}
                    <line x1="120" y1="3" x2="120" y2="12" stroke={isPeakLocked ? "var(--qm-jade)" : "var(--qm-line-strong)"} strokeWidth="1.2" opacity={isPeakLocked ? "0.8" : "0.38"} />
                    <line x1="120" y1="108" x2="120" y2="117" stroke={isPeakLocked ? "var(--qm-jade)" : "var(--qm-line-strong)"} strokeWidth="1.2" opacity={isPeakLocked ? "0.8" : "0.38"} />
                    <line x1="56" y1="60" x2="66" y2="60" stroke={isPeakLocked ? "var(--qm-jade)" : "var(--qm-line-strong)"} strokeWidth="1.2" opacity={isPeakLocked ? "0.8" : "0.38"} />
                    <line x1="174" y1="60" x2="184" y2="60" stroke={isPeakLocked ? "var(--qm-jade)" : "var(--qm-line-strong)"} strokeWidth="1.2" opacity={isPeakLocked ? "0.8" : "0.38"} />
                  </g>

                  {/* Emerald lock radar ripple when within 1.0 dB of peak or setting a new peak */}
                  {isPeakLocked && (
                    <circle
                      key={`lock-ring-${lockPulseSeq}`}
                      cx="120"
                      cy="60"
                      r="52"
                      fill="none"
                      stroke="var(--qm-jade)"
                      strokeWidth={justHitPeak ? "2" : "1.3"}
                      className="qm-radar-ring"
                    />
                  )}

                  {/* 4 dynamic corner targeting brackets that tighten inward on peak lock */}
                  <g
                    fill="none"
                    stroke={isPeakLocked ? "var(--qm-jade-ink)" : "var(--qm-ember-ink)"}
                    strokeWidth={isPeakLocked ? "2.4" : "1.6"}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    opacity={isPeakLocked ? "0.95" : "0.42"}
                  >
                    <path
                      d="M 6 24 L 6 6 L 26 6"
                      className="transition-transform duration-300 ease-out"
                      style={{ transform: isPeakLocked ? "translate(6px, 4px)" : "translate(0px, 0px)" }}
                    />
                    <path
                      d="M 214 6 L 234 6 L 234 24"
                      className="transition-transform duration-300 ease-out"
                      style={{ transform: isPeakLocked ? "translate(-6px, 4px)" : "translate(0px, 0px)" }}
                    />
                    <path
                      d="M 6 96 L 6 114 L 26 114"
                      className="transition-transform duration-300 ease-out"
                      style={{ transform: isPeakLocked ? "translate(6px, -4px)" : "translate(0px, 0px)" }}
                    />
                    <path
                      d="M 214 114 L 234 114 L 234 96"
                      className="transition-transform duration-300 ease-out"
                      style={{ transform: isPeakLocked ? "translate(-6px, -4px)" : "translate(0px, 0px)" }}
                    />
                  </g>
                </svg>

                <div className="relative z-[1] flex items-baseline justify-center gap-2">
                  <span className={cn("qm-display text-[4.1rem] sm:text-[5rem] font-bold leading-none tracking-tight", TONE_TEXT[rsrpTone(focusCur)])}>
                    <RollingNumber
                      value={focusCur}
                      decimals={heroDecimals}
                      fallback="—"
                      stiffness={210}
                      damping={28}
                    />
                  </span>
                  <span className="text-[15px] font-bold text-muted">dBm</span>
                </div>
              </div>

              <div className="mt-2.5 flex flex-wrap items-center justify-center gap-2 text-[13px]">
                <span className="rounded-lg bg-sunk px-2.5 py-1 font-semibold text-ink">
                  Peak <strong className="text-berry-ink">{focusPeak ?? "—"}</strong> dBm
                </span>
                {peakGap != null && (
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11.5px] font-bold qm-tabular transition-colors",
                      showNewPeakPill
                        ? "border-jade/50 bg-jade-soft text-jade-ink shadow-[0_0_16px_-4px_var(--qm-jade)]"
                        : isPeakLocked
                          ? "border-jade/40 bg-jade-soft/85 text-jade-ink"
                          : peakGap >= -4
                            ? "border-saffron/35 bg-saffron-soft/80 text-saffron-ink"
                            : "border-line bg-sunk text-muted"
                    )}
                  >
                    {showNewPeakPill
                      ? "NEW PEAK ▲"
                      : isPeakLocked
                        ? "AT PEAK ▲"
                        : `−${Math.abs(peakGap).toFixed(1)} dB from peak`}
                  </span>
                )}
                <span className="rounded-lg bg-sunk px-2.5 py-1 font-semibold text-ink">
                  SINR <strong>{focusSinr ?? "—"}</strong>
                  {focusPeakSinr != null ? <span className="text-muted"> / {focusPeakSinr}</span> : null} dB
                </span>
              </div>

              <div
                className={cn(
                  "mt-3 inline-flex items-center gap-1.5 rounded-full px-3.5 py-1 text-[13px] font-bold",
                  trend === "up"
                    ? "bg-jade-soft text-jade-ink"
                    : trend === "down"
                      ? "bg-crimson-soft text-crimson-ink"
                      : "bg-sunk text-ink-2"
                )}
              >
                {trend === "up" ? (
                  <ArrowUpRight className="h-4 w-4" />
                ) : trend === "down" ? (
                  <ArrowDownRight className="h-4 w-4" />
                ) : (
                  <ArrowRight className="h-4 w-4" />
                )}
                {trend === "up"
                  ? `Getting stronger (+${Math.abs(delta)} dB)`
                  : trend === "down"
                    ? `Dropping (${delta} dB)`
                    : "Holding steady"}
              </div>
            </div>

            <div className="flex flex-col items-center pt-1 border-t border-line/70">
              <div className="relative mt-2 w-full flex justify-center">
                <AimGauge score={focusScore} best={focusBest} />
                <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
                  <div className={cn("qm-display text-[2.2rem] font-semibold leading-none qm-tabular", TONE_TEXT[scoreTone])}>
                    {focusCur == null ? "—" : focusScore}
                  </div>
                </div>
              </div>
              <div className="mt-1 text-[11.5px] font-semibold text-muted qm-tabular">
                Score / 100 {focusBest > 0 ? `· Best ${focusBest}` : ""} · {align?.activeChains ?? rsrp.filter((v) => v != null).length}/4 RX awake
              </div>
            </div>
          </div>

          <div className="lg:col-span-7 min-w-0 p-5 sm:p-6 flex flex-col justify-between">
            <div>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 className="qm-display text-[1.12rem] font-semibold text-ink">
                    {focus === "all" ? "4-Antenna Average Trace" : `${focusTitle} Live Trace`}
                  </h3>
                  <p className="text-[12.5px] text-muted">
                    400 ms real-time history (~36 s) · keys <span className="font-mono">0–4</span> switch target, <span className="font-mono">R</span> resets peak, <span className="font-mono">M</span> cycles audio
                  </p>
                </div>
              </div>
              <div className="mt-4">
                <Trace points={focusTrace} peak={focusPeak} />
              </div>
            </div>

            {/* Live RF Link & PHY Strip */}
            <div>
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
        </div>
      </Card>

      {/* 3. Clickable Per-Antenna Cards (ordered left-to-right when mapped) */}
      <div>
        <div className="mb-2.5 flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="qm-display text-[1.12rem] font-semibold text-ink">
            Each Antenna <span className="text-[12px] font-sans font-normal text-muted ml-1">(click any card to solo)</span>
          </h3>
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
          {orderedChains.map((c) => (
            <ChainMeter
              key={c.id}
              id={c.id}
              name={c.name}
              jackLabel={normLabels[c.idx]}
              tx={c.tx}
              rsrp={rsrp[c.idx] ?? null}
              peak={peakRsrp[c.idx] ?? null}
              sinr={sinr[c.idx] ?? null}
              peakSinr={peakSinr[c.idx] ?? null}
              rsrq={rsrq[c.idx] ?? null}
              focused={focus === c.idx}
              dimmed={focus !== "all" && focus !== c.idx}
              onSelect={() => selectFocus(focus === c.idx ? "all" : c.idx)}
            />
          ))}
        </div>
      </div>

      {/* 4. 4×4 MIMO Balance & Cross-Pol Skew Meter */}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div>
            <h3 className="qm-display text-[1.08rem] font-semibold text-ink">4×4 MIMO Balance &amp; Cross-Pol Skew</h3>
            <p className="text-[12px] text-muted">Keep all 4 chains within ~3–6 dB for rank-4 spatial multiplexing</p>
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
                <div className="text-muted text-[11px] font-semibold">Primary Pair (RX0 vs RX1)</div>
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
                <div className="text-muted text-[11px] font-semibold">MIMO Pair (RX2 vs RX3)</div>
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

      {/* 5. Collapsible Outdoor Panel Tools (Tower Finder Map, Compass & Position Bookmarks) */}
      <Card className="p-3.5 sm:p-4">
        <button
          type="button"
          onClick={() => setShowOutdoorTools((v) => !v)}
          className="flex w-full items-center justify-between gap-3 text-left cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <Compass className="h-4 w-4 text-ember-ink shrink-0" />
            <div>
              <div className="qm-display text-[1.02rem] font-semibold text-ink">
                Outdoor Panel Compass, Tower Map &amp; Position Bookmarks
              </div>
              <div className="text-[12px] text-muted">
                360° directional roof sweep, OpenCelliD tower bearing &amp; saved comparison log ({bookmarks.length} saved)
              </div>
            </div>
          </div>
          {showOutdoorTools ? <ChevronUp className="h-4 w-4 text-muted" /> : <ChevronDown className="h-4 w-4 text-muted" />}
        </button>
      </Card>

      {showOutdoorTools && (
        <>
          <Suspense fallback={<Skeleton className="h-64" />}>
            <TowerFinderCard meanRsrp={summary.meanCur} meanSinr={summary.meanSinr} haptics={haptics} />
          </Suspense>

          <Card>
            <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
              <div>
                <h3 className="qm-display text-[1.08rem] font-semibold text-ink flex items-center gap-2">
                  <Radio className="h-4 w-4 text-ember-ink" /> Azimuth / Mount Bookmarks
                </h3>
                <p className="text-[12px] text-muted">Log bearings or antenna configurations locally to compare objectively</p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant={haptics ? "secondary" : "ghost"}
                  onClick={() => setHaptics((v) => !v)}
                >
                  Haptics: {haptics ? "On" : "Off"}
                </Button>
                {bookmarks.length > 0 && (
                  <>
                    <Button size="sm" variant="secondary" onClick={copyBookmarksTable}>
                      {copiedBookmarks ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                      {copiedBookmarks ? "Copied" : "Copy table"}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={clearBookmarks}>
                      Clear all
                    </Button>
                  </>
                )}
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                value={bookmarkLabel}
                onChange={(e) => setBookmarkLabel(e.target.value)}
                placeholder="e.g. 2x Cradlepoint TX + 2x Smooth Black RX"
                className="min-h-11"
                onKeyDown={(e) => {
                  if (e.key === "Enter") addBookmark();
                }}
              />
              <Button variant="primary" className="min-h-11 px-4 shrink-0 font-semibold" onClick={addBookmark} disabled={focusCur == null}>
                <Bookmark className="h-4 w-4" />
                Save snapshot
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
        </>
      )}
    </div>
  );
}
