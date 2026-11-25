import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, History, Minus, Play, Radio, Square, Trash2 } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { playHudSuccess } from "../../lib/hud-fx";
import { RollingNumber, useSpringRef } from "../../lib/motion";
import { cn } from "../../lib/utils";
import { useWsStore } from "../../stores/ws-store";
import { useToastStore } from "../../stores/toast-store";
import type { SpeedtestLiveState, SpeedtestRun } from "../../types/cellcore";
import { Badge, Button, Card, CardHeader, LiveDot, Meter, Modal } from "../../components/ui";
import { DualAreaChart, SmoothAreaChart } from "../../components/Charts";
import { TONE_INK, TONE_SOFT, errMsg, fmtMbps, gradeMeta, median, type HeaderFn } from "./shared";

const STEPS = [
  { id: "ping", label: "Ping" },
  { id: "download", label: "Download" },
  { id: "upload", label: "Upload" },
  { id: "complete", label: "Done" },
] as const;

const REACTOR_TICKS = [
  { mbps: 0, label: "0" },
  { mbps: 10, label: "10" },
  { mbps: 50, label: "50" },
  { mbps: 150, label: "150" },
  { mbps: 400, label: "400" },
  { mbps: 800, label: "800" },
  { mbps: 1500, label: "1.5G" },
] as const;

const REACTOR_CX = 110;
const REACTOR_CY = 108;
const REACTOR_R = 84;
const REACTOR_START = 140; // degrees (SVG 0° = east, clockwise)
const REACTOR_SWEEP = 260;
const REACTOR_ARC_LEN = (REACTOR_SWEEP / 360) * 2 * Math.PI * REACTOR_R;

function mbpsToReactorNorm(mbps: number | null | undefined): number {
  if (mbps == null || !Number.isFinite(mbps) || mbps <= 0) return 0;
  return Math.max(0, Math.min(1, Math.pow(mbps / 1500, 0.45)));
}

function reactorPolar(deg: number, rad: number): readonly [number, number] {
  const a = (deg * Math.PI) / 180;
  return [REACTOR_CX + rad * Math.cos(a), REACTOR_CY + rad * Math.sin(a)] as const;
}

function describeReactorArc(startDeg: number, endDeg: number, rad: number): string {
  const [x1, y1] = reactorPolar(startDeg, rad);
  const [x2, y2] = reactorPolar(endDeg, rad);
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${rad} ${rad} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

const REACTOR_TRACK_PATH = describeReactorArc(REACTOR_START, REACTOR_START + REACTOR_SWEEP, REACTOR_R);
const REACTOR_INNER_ARC = describeReactorArc(REACTOR_START, REACTOR_START + REACTOR_SWEEP, REACTOR_R - 14);

const SpeedtestReactorGauge = React.memo(function SpeedtestReactorGauge({
  phase,
  running,
  mbps,
  pingMs,
  grade,
  gradeKey,
}: {
  phase: SpeedtestLiveState["phase"];
  running: boolean;
  mbps: number | null;
  pingMs: number | null;
  grade: string;
  gradeKey: string;
}) {
  const gid = useId().replace(/:/g, "");
  const arcRef = useRef<SVGPathElement | null>(null);
  const arcGlowRef = useRef<SVGPathElement | null>(null);
  const needleRef = useRef<SVGLineElement | null>(null);
  const tipRef = useRef<SVGCircleElement | null>(null);
  const tipHaloRef = useRef<SVGCircleElement | null>(null);

  const isPing = running && (phase === "ping" || phase === "starting");
  const isDownload = running && phase === "download";
  const isUpload = running && phase === "upload";
  const isSettled = !running;

  const targetNorm = isPing ? 0 : mbpsToReactorNorm(mbps);
  const initialNormRef = useRef(targetNorm);
  const currentNormRef = useRef(targetNorm);

  const applyFrame = (norm: number) => {
    const clamped = Math.max(0, Math.min(1, norm));
    currentNormRef.current = clamped;
    const offset = (REACTOR_ARC_LEN * (1 - clamped)).toFixed(2);
    const activeOpacity = clamped <= 0.003 ? "0" : "1";
    const glowOpacity = clamped <= 0.003 ? "0" : isSettled ? "0.34" : "0.62";

    if (arcRef.current) {
      arcRef.current.setAttribute("stroke-dashoffset", offset);
      arcRef.current.setAttribute("opacity", activeOpacity);
    }
    if (arcGlowRef.current) {
      arcGlowRef.current.setAttribute("stroke-dashoffset", offset);
      arcGlowRef.current.setAttribute("opacity", glowOpacity);
    }

    const deg = REACTOR_START + REACTOR_SWEEP * clamped;
    const [nx1, ny1] = reactorPolar(deg, 50);
    const [nx2, ny2] = reactorPolar(deg, REACTOR_R - 2);
    const [tx, ty] = reactorPolar(deg, REACTOR_R);

    if (needleRef.current) {
      needleRef.current.setAttribute("x1", nx1.toFixed(2));
      needleRef.current.setAttribute("y1", ny1.toFixed(2));
      needleRef.current.setAttribute("x2", nx2.toFixed(2));
      needleRef.current.setAttribute("y2", ny2.toFixed(2));
      needleRef.current.setAttribute("opacity", activeOpacity);
    }
    if (tipRef.current) {
      tipRef.current.setAttribute("cx", tx.toFixed(2));
      tipRef.current.setAttribute("cy", ty.toFixed(2));
      tipRef.current.setAttribute("opacity", activeOpacity);
    }
    if (tipHaloRef.current) {
      tipHaloRef.current.setAttribute("cx", tx.toFixed(2));
      tipHaloRef.current.setAttribute("cy", ty.toFixed(2));
      tipHaloRef.current.setAttribute("opacity", clamped <= 0.003 ? "0" : isSettled ? "0.28" : "0.55");
    }
  };

  useSpringRef(targetNorm, applyFrame, {
    stiffness: running ? 190 : 120,
    damping: running ? 24 : 22,
    precision: 0.0005,
    initial: initialNormRef.current,
  });

  // Sync glow opacity on running/settled transitions without interrupting spring interpolation
  useEffect(() => {
    applyFrame(currentNormRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSettled, isPing]);

  const initDeg = REACTOR_START + REACTOR_SWEEP * initialNormRef.current;
  const [initNx1, initNy1] = reactorPolar(initDeg, 50);
  const [initNx2, initNy2] = reactorPolar(initDeg, REACTOR_R - 2);
  const [initTx, initTy] = reactorPolar(initDeg, REACTOR_R);
  const initOffset = REACTOR_ARC_LEN * (1 - initialNormRef.current);
  const initVis = initialNormRef.current <= 0.003 ? 0 : 1;

  const gradId = isDownload
    ? `reactor-dl-${gid}`
    : isUpload
      ? `reactor-ul-${gid}`
      : `reactor-idle-${gid}`;
  const accentColor = isDownload
    ? "#22d3ee"
    : isUpload
      ? "#c084fc"
      : "var(--qm-ember)";
  const gm = gradeMeta(grade);

  const liveSpeedVal = mbps != null && Number.isFinite(mbps) && mbps > 0 ? mbps : null;
  const speedDecimals = liveSpeedVal != null && liveSpeedVal >= 100 ? 0 : 1;
  const livePingVal = pingMs != null && Number.isFinite(pingMs) && pingMs > 0 ? pingMs : null;

  const phaseEyebrow = isPing
    ? phase === "starting"
      ? "CONNECTING"
      : "PING"
    : isDownload
      ? "DOWNLOAD"
      : isUpload
        ? "UPLOAD"
        : phase === "stopped"
          ? "ABORTED"
          : phase === "error"
            ? "FAILED"
            : "REACTOR";

  return (
    <div className="relative mx-auto flex w-[210px] shrink-0 flex-col items-center select-none">
      <svg viewBox="0 0 220 202" className="w-[210px] h-auto overflow-visible" aria-hidden>
        <defs>
          <linearGradient id={`reactor-dl-${gid}`} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="55%" stopColor="#22d3ee" />
            <stop offset="100%" stopColor="#67e8f9" />
          </linearGradient>
          <linearGradient id={`reactor-ul-${gid}`} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor="#8b5cf6" />
            <stop offset="58%" stopColor="#c084fc" />
            <stop offset="100%" stopColor="#f59e0b" />
          </linearGradient>
          <linearGradient id={`reactor-idle-${gid}`} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" style={{ stopColor: "var(--qm-dial-a)" }} />
            <stop offset="55%" style={{ stopColor: "var(--qm-dial-b)" }} />
            <stop offset="100%" style={{ stopColor: "var(--qm-dial-c)" }} />
          </linearGradient>
          <radialGradient id={`reactor-core-${gid}`} cx="50%" cy="35%" r="65%">
            <stop offset="0%" style={{ stopColor: "var(--qm-raised)", stopOpacity: 0.9 }} />
            <stop offset="100%" style={{ stopColor: "var(--qm-sunk)", stopOpacity: 0.55 }} />
          </radialGradient>
          <filter id={`reactor-glow-${gid}`} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="5" />
          </filter>
        </defs>

        {/* Glass core housing */}
        <circle
          cx={REACTOR_CX}
          cy={REACTOR_CY}
          r="56"
          fill={`url(#reactor-core-${gid})`}
          className="stroke-line"
          strokeWidth="1"
        />
        <circle
          cx={REACTOR_CX}
          cy={REACTOR_CY}
          r="50"
          fill="none"
          className="stroke-line-strong/40"
          strokeWidth="0.75"
          strokeDasharray="2 5"
        />

        {/* Ping / Starting radar ripples */}
        {isPing && (
          <g>
            <circle
              cx={REACTOR_CX}
              cy={REACTOR_CY}
              r="52"
              fill="none"
              stroke="var(--qm-ember)"
              strokeWidth="1.5"
              className="qm-radar-ring"
            />
            <circle
              cx={REACTOR_CX}
              cy={REACTOR_CY}
              r="52"
              fill="none"
              stroke="var(--qm-jade)"
              strokeWidth="1.25"
              className="qm-radar-ring"
              style={{ animationDelay: "630ms" }}
            />
            <circle
              cx={REACTOR_CX}
              cy={REACTOR_CY}
              r="52"
              fill="none"
              stroke="var(--qm-ember-ink)"
              strokeWidth="1"
              className="qm-radar-ring"
              style={{ animationDelay: "1260ms" }}
            />
          </g>
        )}

        {/* Ambient track + inner guide */}
        <path
          d={REACTOR_TRACK_PATH}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          className="stroke-line/80"
        />
        <path
          d={REACTOR_INNER_ARC}
          fill="none"
          strokeWidth="1"
          className="stroke-line-strong/50"
          strokeDasharray="1.5 6"
        />

        {/* Non-linear perceptual ticks */}
        {REACTOR_TICKS.map((t) => {
          const deg = REACTOR_START + mbpsToReactorNorm(t.mbps) * REACTOR_SWEEP;
          const [x1, y1] = reactorPolar(deg, REACTOR_R - 11);
          const [x2, y2] = reactorPolar(deg, REACTOR_R - 17);
          const [lx, ly] = reactorPolar(deg, REACTOR_R + 13);
          return (
            <g key={t.mbps}>
              <line
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                strokeWidth="1.4"
                strokeLinecap="round"
                className="stroke-line-strong"
              />
              <text
                x={lx}
                y={ly}
                textAnchor="middle"
                dominantBaseline="central"
                className="fill-muted font-mono text-[8.5px] font-semibold"
              >
                {t.label}
              </text>
            </g>
          );
        })}

        {/* Plasma glow arc (mutated at 60/120fps via useSpringRef) */}
        <path
          ref={arcGlowRef}
          d={REACTOR_TRACK_PATH}
          fill="none"
          stroke={`url(#${gradId})`}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={REACTOR_ARC_LEN}
          strokeDashoffset={initOffset}
          opacity={initVis ? (isSettled ? 0.34 : 0.62) : 0}
          filter={`url(#reactor-glow-${gid})`}
        />
        <path
          ref={arcRef}
          d={REACTOR_TRACK_PATH}
          fill="none"
          stroke={`url(#${gradId})`}
          strokeWidth="9.5"
          strokeLinecap="round"
          strokeDasharray={REACTOR_ARC_LEN}
          strokeDashoffset={initOffset}
          opacity={initVis}
        />

        {/* Glowing needle & tip orb (mutated directly via refs) */}
        <line
          ref={needleRef}
          x1={initNx1}
          y1={initNy1}
          x2={initNx2}
          y2={initNy2}
          stroke={accentColor}
          strokeWidth="2.4"
          strokeLinecap="round"
          opacity={initVis}
        />
        <circle
          ref={tipHaloRef}
          cx={initTx}
          cy={initTy}
          r="9"
          fill={accentColor}
          opacity={initVis ? (isSettled ? 0.28 : 0.55) : 0}
          filter={`url(#reactor-glow-${gid})`}
        />
        <circle
          ref={tipRef}
          cx={initTx}
          cy={initTy}
          r="4.2"
          fill="#ffffff"
          stroke={accentColor}
          strokeWidth="2.2"
          opacity={initVis}
        />
      </svg>

      {/* Center glass readout */}
      <div className="pointer-events-none absolute inset-x-0 top-[46px] flex flex-col items-center text-center">
        <span
          className={cn(
            "text-[9.5px] font-bold tracking-[0.16em] uppercase",
            isDownload ? "text-jade-ink" : isUpload ? "text-berry-ink" : isPing ? "text-ember-ink" : "text-muted"
          )}
        >
          {phaseEyebrow}
        </span>
        {isPing ? (
          <>
            <div className="mt-1 qm-display text-[2rem] font-semibold leading-none text-ink qm-tabular">
              <RollingNumber value={livePingVal} decimals={1} fallback="…" stiffness={200} damping={26} />
            </div>
            <span className="mt-0.5 text-[10.5px] font-semibold text-muted">ms ping</span>
          </>
        ) : (
          <>
            <div className="mt-1 qm-display text-[2.05rem] font-semibold leading-none text-ink qm-tabular">
              <RollingNumber
                value={liveSpeedVal}
                decimals={speedDecimals}
                fallback={running ? "0.0" : "--"}
                stiffness={running ? 190 : 140}
                damping={26}
              />
            </div>
            <span className="mt-0.5 text-[10.5px] font-semibold text-muted">Mbps</span>
          </>
        )}
      </div>

      {/* Bottom reactor slot: Bufferbloat Grade badge with spring-pop animation when settled */}
      <div className="relative -mt-4 flex min-h-[26px] items-center justify-center">
        {isSettled && grade && grade !== "--" ? (
          <span
            key={gradeKey}
            className={cn(
              "qm-grade-slam inline-flex items-center gap-1.5 rounded-full border border-line/80 px-2.5 py-0.5 text-[11px] font-bold shadow-sm",
              TONE_SOFT[gm.tone],
              TONE_INK[gm.tone]
            )}
          >
            <span className="text-[9.5px] uppercase tracking-wider opacity-80">Grade</span>
            <span className="qm-display text-[13px] leading-none">{grade}</span>
          </span>
        ) : running ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-sunk/80 px-2.5 py-0.5 text-[10.5px] font-semibold text-ink-2">
            <span className={cn("h-1.5 w-1.5 rounded-full qm-live-dot", isUpload ? "bg-berry" : "bg-jade")} />
            {isPing ? "Probing latency" : isDownload ? "8-stream DL" : "8-stream UL"}
          </span>
        ) : (
          <span className="text-[10.5px] font-medium text-muted">Ready · 0–1.5G+</span>
        )}
      </div>
    </div>
  );
});

function GradeChip({ grade, className }: { grade: string; className?: string }) {
  const m = gradeMeta(grade);
  return (
    <span
      className={cn(
        "inline-flex h-7 min-w-7 items-center justify-center rounded-lg px-1.5 qm-display text-[15px] font-semibold",
        TONE_SOFT[m.tone],
        TONE_INK[m.tone],
        className
      )}
    >
      {grade || "--"}
    </span>
  );
}

function Numeral({ label, dot, value }: { label: string; dot: string; value: number | null | undefined }) {
  const numeric = value != null && Number.isFinite(value) && value > 0 ? value : null;
  const decimals = numeric != null && numeric >= 100 ? 0 : 1;
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-2 text-[12.5px] font-semibold text-muted">
        <span className={cn("h-2 w-2 rounded-full", dot)} />
        {label}
      </div>
      <div className="mt-1 flex items-baseline gap-2 min-w-0">
        <span className="qm-display qm-tabular font-semibold leading-[0.9] text-ink text-[2.65rem] sm:text-[3.5rem] xl:text-[4.25rem]">
          <RollingNumber value={numeric} decimals={decimals} fallback="--" stiffness={190} damping={26} />
        </span>
        <span className="text-[13px] sm:text-[15px] font-semibold text-muted">Mbps</span>
      </div>
    </div>
  );
}

function Delta({ latest, base }: { latest: number; base: number | null }) {
  if (base == null || base === 0) return null;
  const pct = Math.round(((latest - base) / base) * 100);
  const flat = Math.abs(pct) < 5;
  const Icon = flat ? Minus : pct > 0 ? ArrowUp : ArrowDown;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 text-[11.5px] font-semibold qm-tabular",
        flat ? "text-muted" : pct > 0 ? "text-jade-ink" : "text-crimson-ink"
      )}
      title="Latest run compared with the median of saved runs"
    >
      <Icon className="h-3 w-3" />
      {flat ? "steady" : `${Math.abs(pct)}%`}
    </span>
  );
}

interface SpeedtestRfSnapshotCompat {
  rat?: string | null;
  band?: string | null;
  pci?: number | null;
  caCount?: number | null;
  caBandwidthMhz?: number | null;
  rsrp?: number | null;
  sinr?: number | null;
}

function getRunRf(run: Partial<SpeedtestRun> | null | undefined): SpeedtestRfSnapshotCompat | null {
  if (!run || typeof run !== "object") return null;
  const rf = (run as Partial<SpeedtestRun> & { rf?: SpeedtestRfSnapshotCompat | null }).rf;
  if (!rf || typeof rf !== "object") return null;
  if (!rf.band && !rf.rat && rf.pci == null && rf.rsrp == null && rf.sinr == null && rf.caBandwidthMhz == null) {
    return null;
  }
  return rf;
}

function RfSnapshotPill({ rf, compact = false }: { rf: SpeedtestRfSnapshotCompat; compact?: boolean }) {
  const bandPart = rf.band || rf.rat || "RF";
  const bwPart = rf.caBandwidthMhz != null && Number.isFinite(rf.caBandwidthMhz) ? `${Math.round(rf.caBandwidthMhz)} MHz` : null;
  const caPart = rf.caCount != null && rf.caCount > 1 ? `${rf.caCount}CA` : null;
  const pciPart = rf.pci != null ? `PCI ${rf.pci}` : null;
  const sigPart =
    rf.rsrp != null || rf.sinr != null
      ? `${rf.rsrp != null ? rf.rsrp : "--"} dBm / ${rf.sinr != null ? rf.sinr : "--"} dB`
      : null;

  return (
    <span
      className={cn(
        "inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5 rounded-lg border border-line bg-sunk/70 px-2 py-0.5 font-mono qm-tabular text-ink-2",
        compact ? "text-[10.5px] leading-snug" : "text-[11.5px] leading-snug"
      )}
      title="Captured radio conditions during this speedtest run"
    >
      <Radio className="h-3 w-3 shrink-0 text-ember-ink" />
      <span className="font-semibold text-ink">
        {bandPart}
        {bwPart ? ` · ${bwPart}` : ""}
        {caPart ? ` (${caPart})` : ""}
      </span>
      {pciPart && <span className="text-muted">· {pciPart}</span>}
      {sigPart && <span className="text-ink-2">· {sigPart}</span>}
    </span>
  );
}

const LiveRadioStrip = React.memo(function LiveRadioStrip() {
  const modem = useWsStore((s) => s.modem);
  if (!modem || modem.carriers.length === 0) return null;

  const totalMhz = Math.round(modem.carriers.reduce((acc, c) => acc + (c.bandwidthMhz ?? 0), 0));

  return (
    <div className="rounded-2xl border border-line bg-sunk/50 px-3.5 py-2.5 space-y-1.5">
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11.5px] font-semibold text-muted">
        <span className="inline-flex items-center gap-1.5">
          <Radio className="h-3.5 w-3.5 text-ember-ink" />
          Live Radio · {modem.carriers.length}CA · {totalMhz} MHz
        </span>
        {modem.serving?.sinr != null && (
          <span className="font-mono qm-tabular text-ink-2">
            {modem.serving.rat} · SINR {modem.serving.sinr} dB
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {modem.carriers.map((c, idx) => {
          const isPcc = c.role === "PCC";
          const sccActive = !isPcc && c.pcellState === 2;
          const sccDormant = !isPcc && c.pcellState === 1;
          return (
            <Badge
              key={`${c.role}-${c.arfcn}-${idx}`}
              variant={isPcc ? "info" : sccActive ? "success" : "neutral"}
            >
              {c.role} {c.band}
              {c.bandwidthMhz ? ` ${c.bandwidthMhz}MHz` : ""}
              {c.dlMimoLayers ? ` ${c.dlMimoLayers}×${c.ulMimoLayers || 0}` : ""}
              {sccActive ? " · Active" : sccDormant ? " · Dormant" : ""}
            </Badge>
          );
        })}
      </div>
    </div>
  );
});

export function SpeedtestView({ header }: { header: HeaderFn }) {
  const push = useToastStore((s) => s.push);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const speedtest = useWsStore((s) => s.speedtest);
  const speedtestHistory = useWsStore((s) => s.speedtestHistory);
  const refreshSpeedtestHistory = useWsStore((s) => s.refreshSpeedtestHistory);
  const resetSpeedtest = useWsStore((s) => s.resetSpeedtest);

  useEffect(() => {
    void refreshSpeedtestHistory();
  }, [refreshSpeedtestHistory]);

  // Play HUD success triad once when a live run transitions from running -> complete
  const wasRunningRef = useRef(false);
  useEffect(() => {
    if (speedtest.running) {
      wasRunningRef.current = true;
    } else if (wasRunningRef.current && speedtest.phase === "complete") {
      wasRunningRef.current = false;
      playHudSuccess();
    } else if (!speedtest.running && speedtest.phase !== "complete") {
      wasRunningRef.current = false;
    }
  }, [speedtest.running, speedtest.phase]);

  async function startSpeedtestRun() {
    setBusy("speedtest");
    try {
      await disruptiveFetch("speedtest", "/api/v1/speedtest/start", {
        method: "POST",
        body: "{}",
      });
      resetSpeedtest();
    } catch (e) {
      if (!isCancelled(e)) push("Couldn't start the speedtest", "error", errMsg(e, "Failed to start speedtest"));
    } finally {
      setBusy(null);
    }
  }

  async function stopSpeedtestRun() {
    setBusy("speedtest-stop");
    try {
      await apiFetch("/api/v1/speedtest/stop", { method: "POST", body: "{}" });
    } catch (e) {
      push("Couldn't stop the speedtest", "error", errMsg(e, "Failed to stop speedtest"));
    } finally {
      setBusy(null);
    }
  }

  async function clearSpeedtestHistory() {
    setBusy("speedtest-clear");
    try {
      await apiFetch("/api/v1/speedtest/history", { method: "DELETE" });
      await refreshSpeedtestHistory();
      push("Speedtest history cleared", "success");
    } catch (e) {
      push("Couldn't clear history", "error", errMsg(e, "Failed clearing history"));
    } finally {
      setBusy(null);
      setConfirmClear(false);
    }
  }

  const liveSamples = speedtest.samples ?? [];
  const isLive = speedtest.phase !== "idle";
  const activeRunDisplay: Partial<SpeedtestRun> | null = isLive
    ? {
        downloadMbps: speedtest.downloadMbps ?? 0,
        uploadMbps: speedtest.uploadMbps ?? 0,
        pingMs: speedtest.pingMs ?? 0,
        jitterMs: speedtest.jitterMs ?? 0,
        dlLatencyIqm: speedtest.dlLatencyIqm,
        ulLatencyIqm: speedtest.ulLatencyIqm,
        bufferbloatGrade: speedtest.bufferbloatGrade ?? "--",
        serverName: speedtest.serverName,
        serverLocation: speedtest.serverLocation,
        isp: speedtest.isp,
        packetLoss: speedtest.packetLoss,
      }
    : speedtestHistory[0] ?? null;

  const grade = activeRunDisplay?.bufferbloatGrade || "--";
  const gm = gradeMeta(speedtest.running && !speedtest.bufferbloatGrade ? "--" : grade);
  const idlePing = activeRunDisplay?.pingMs || null;
  const loadedDl = activeRunDisplay?.dlLatencyIqm ?? null;
  const loadedUl = activeRunDisplay?.ulLatencyIqm ?? null;
  const worstLoaded = Math.max(loadedDl ?? 0, loadedUl ?? 0) || null;
  const addedLag = idlePing && worstLoaded ? Math.max(0, Math.round(worstLoaded - idlePing)) : null;

  const stepIdx = STEPS.findIndex((s) => s.id === speedtest.phase);

  const statusLine = speedtest.running
    ? `Testing ${speedtest.phase === "starting" ? "· connecting to Cloudflare" : `· ${speedtest.phase}`}`
    : speedtest.phase === "complete"
      ? "Run complete"
      : speedtest.phase === "stopped"
        ? "Run aborted"
        : speedtest.phase === "error"
          ? "Run failed"
          : speedtestHistory[0]
            ? `Last run · ${speedtestHistory[0].timestamp}`
            : "Ready when you are";

  // History, oldest → newest for the trend chart.
  const chrono = useMemo(() => [...speedtestHistory].reverse(), [speedtestHistory]);
  const medDl = median(speedtestHistory.map((r) => r.downloadMbps));
  const medUl = median(speedtestHistory.map((r) => r.uploadMbps));
  const maxDl = Math.max(1, ...speedtestHistory.map((r) => r.downloadMbps || 0));
  const maxUl = Math.max(1, ...speedtestHistory.map((r) => r.uploadMbps || 0));
  const latest = speedtestHistory[0];
  const gradeCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of speedtestHistory) m.set(r.bufferbloatGrade || "--", (m.get(r.bufferbloatGrade || "--") ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [speedtestHistory]);

  const latestPhaseSampleMbps = useMemo(() => {
    for (let i = liveSamples.length - 1; i >= 0; i--) {
      const s = liveSamples[i];
      if (s.phase === speedtest.phase && Number.isFinite(s.mbps)) return s.mbps;
    }
    return null;
  }, [liveSamples, speedtest.phase]);

  const reactorMbps = speedtest.running
    ? speedtest.phase === "download"
      ? (speedtest.downloadMbps && speedtest.downloadMbps > 0 ? speedtest.downloadMbps : latestPhaseSampleMbps)
      : speedtest.phase === "upload"
        ? (speedtest.uploadMbps && speedtest.uploadMbps > 0 ? speedtest.uploadMbps : latestPhaseSampleMbps)
        : 0
    : activeRunDisplay?.downloadMbps ?? null;

  const gradeKey = String(activeRunDisplay?.id ?? speedtest.phase);

  return (
    <>
      {header()}

      {/* ── Hero: run + warp-core reactor + headline numbers + bufferbloat verdict ── */}
      <Card className="qm-hud-card qm-reticle overflow-hidden p-0 sm:p-0">
        <div className="qm-grain relative z-[1] grid lg:grid-cols-12">
          <div className="lg:col-span-8 p-5 sm:p-7 space-y-6 min-w-0">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-[12.5px] font-semibold text-ink-2">
                {speedtest.running ? <LiveDot tone="ember" /> : <span className="h-2 w-2 rounded-full bg-line-strong" />}
                <span className="qm-tabular">{statusLine}</span>
              </div>
              {(activeRunDisplay?.serverName || activeRunDisplay?.isp) && (
                <div className="text-[12px] text-muted truncate max-w-full">
                  {activeRunDisplay?.serverName}
                  {activeRunDisplay?.serverLocation ? ` · ${activeRunDisplay.serverLocation}` : ""}
                </div>
              )}
            </div>

            <div className="flex flex-col md:flex-row md:items-center gap-6">
              <SpeedtestReactorGauge
                phase={speedtest.phase}
                running={speedtest.running}
                mbps={reactorMbps}
                pingMs={activeRunDisplay?.pingMs ?? null}
                grade={speedtest.running && !speedtest.bufferbloatGrade ? "--" : grade}
                gradeKey={gradeKey}
              />

              <div className="min-w-0 flex-1 space-y-4">
                <div className="grid grid-cols-2 gap-4 sm:gap-6">
                  <Numeral label="Download" dot="bg-ember" value={activeRunDisplay?.downloadMbps} />
                  <Numeral label="Upload" dot="bg-berry" value={activeRunDisplay?.uploadMbps} />
                </div>

                <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[13px] text-ink-2 qm-tabular">
                  <span>
                    <span className="text-muted">Idle ping </span>
                    <b className="text-ink">{activeRunDisplay?.pingMs ? `${activeRunDisplay.pingMs} ms` : "--"}</b>
                  </span>
                  <span>
                    <span className="text-muted">Jitter </span>
                    <b className="text-ink">{activeRunDisplay?.jitterMs ? `${activeRunDisplay.jitterMs} ms` : "--"}</b>
                  </span>
                  {activeRunDisplay?.packetLoss != null && (
                    <span>
                      <span className="text-muted">Loss </span>
                      <b className="text-ink">{activeRunDisplay.packetLoss}%</b>
                    </span>
                  )}
                  {activeRunDisplay?.isp && (
                    <span>
                      <span className="text-muted">ISP </span>
                      <b className="text-ink">{activeRunDisplay.isp}</b>
                    </span>
                  )}
                </div>

                {(() => {
                  const latestRf = !isLive ? getRunRf(activeRunDisplay) : null;
                  return latestRf ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <RfSnapshotPill rf={latestRf} />
                    </div>
                  ) : null;
                })()}
              </div>
            </div>

            {/* Phase stepper */}
            <div className="space-y-2.5">
              <ol className="grid grid-cols-4 gap-1.5">
                {STEPS.map((s, i) => {
                  const done = stepIdx > i || speedtest.phase === "complete";
                  const active = speedtest.running && stepIdx === i;
                  return (
                    <li
                      key={s.id}
                      className={cn(
                        "flex items-center justify-center gap-1.5 rounded-full px-2 py-1.5 text-[12px] font-semibold transition-colors",
                        active ? "bg-ink text-paper" : done ? "bg-ember-soft text-ember-ink" : "bg-sunk text-muted"
                      )}
                    >
                      {active && <span className="h-1.5 w-1.5 rounded-full bg-current qm-live-dot" />}
                      {s.label}
                    </li>
                  );
                })}
              </ol>
              <Meter pct={speedtest.progress} tone="sun" className={speedtest.running ? "qm-energy-shimmer" : undefined} />
            </div>

            {speedtest.error && (
              <div className="rounded-2xl bg-crimson-soft px-4 py-3 text-[13px] text-crimson-ink">{speedtest.error}</div>
            )}

            {/* Live Carrier Aggregation & SCC activation strip (1s refresh during test) */}
            <LiveRadioStrip />

            {/* Controls */}
            <div className="flex flex-col sm:flex-row gap-2.5">
              <div className="flex min-h-12 flex-1 items-center rounded-2xl border border-line bg-sunk/60 px-4 py-2.5 text-[12.5px] leading-snug font-medium text-ink-2 min-w-0">
                <span className="min-w-0 break-words">
                  Native Rust · Cloudflare Anycast · 8-stream HTTP + loaded bufferbloat
                </span>
              </div>
              {speedtest.running ? (
                  <Button
                    variant="danger"
                    size="lg"
                    className="h-12 sm:min-w-[220px] qm-spring-press"
                    onClick={stopSpeedtestRun}
                    disabled={busy === "speedtest-stop"}
                  >
                    <Square className="h-4 w-4" />
                    Abort · {speedtest.progress}%
                  </Button>
                ) : (
                  <Button
                    variant="tier1"
                    size="lg"
                    className="h-12 sm:min-w-[220px] text-[15px] qm-spring-press"
                    onClick={startSpeedtestRun}
                    disabled={busy === "speedtest"}
                  >
                    <Play className="h-4 w-4 fill-current" />
                    Run speedtest
                  </Button>
                )}
            </div>
            <p className="-mt-3 text-[11.5px] text-muted">Each run saturates the link for several seconds and counts against your data plan.</p>
          </div>

          {/* Grade */}
          <div className="lg:col-span-4 border-t lg:border-t-0 lg:border-l border-line bg-sunk/70 p-6 sm:p-7 flex flex-col items-center justify-center text-center gap-4">
            <div className="qm-eyebrow">Bufferbloat grade</div>
            <div
              key={`${gradeKey}-${grade}`}
              className={cn(
                "flex h-36 w-36 sm:h-40 sm:w-40 items-center justify-center rounded-full ring-[10px]",
                !speedtest.running && grade !== "--" && "qm-grade-slam",
                TONE_SOFT[gm.tone],
                gm.tone === "jade" ? "ring-jade/15" : gm.tone === "saffron" ? "ring-saffron/15" : gm.tone === "crimson" ? "ring-crimson/15" : "ring-line/60"
              )}
            >
              <span className={cn("qm-display font-semibold leading-none text-[5.2rem] sm:text-[6rem]", TONE_INK[gm.tone])}>
                {speedtest.running && !speedtest.bufferbloatGrade ? "…" : grade}
              </span>
            </div>
            <div className="space-y-1 max-w-[260px]">
              <div className="qm-display text-[1.15rem] font-semibold text-ink">{gm.verdict}</div>
              <p className="text-[12.5px] text-muted leading-snug">{gm.detail}</p>
            </div>
            <div className="grid w-full max-w-[280px] grid-cols-2 gap-2 qm-tabular">
              <div className="rounded-xl bg-surface border border-line px-3 py-2">
                <div className="text-[11px] text-muted">Loaded ↓</div>
                <div className="text-[14px] font-semibold text-ink">{loadedDl != null ? `${loadedDl} ms` : "--"}</div>
              </div>
              <div className="rounded-xl bg-surface border border-line px-3 py-2">
                <div className="text-[11px] text-muted">Loaded ↑</div>
                <div className="text-[14px] font-semibold text-ink">{loadedUl != null ? `${loadedUl} ms` : "--"}</div>
              </div>
            </div>
            {addedLag != null && (
              <div className="text-[12px] text-ink-2">
                Load adds up to <b className={TONE_INK[gm.tone]}>+{addedLag} ms</b> over idle ping
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* ── Live trace + trend ── */}
      <div className="grid gap-5 lg:grid-cols-12 items-start">
        <Card className="lg:col-span-7 min-w-0">
          <CardHeader
            title="Live throughput"
            subtitle="Mbps streamed from the modem through each phase"
            action={
              speedtest.running ? (
                <Badge variant="info" dot>
                  {speedtest.phase} · {speedtest.progress}%
                </Badge>
              ) : liveSamples.length > 0 ? (
                <Badge>{liveSamples.length} samples</Badge>
              ) : undefined
            }
          />
          <SmoothAreaChart
            values={liveSamples.map((s) => s.mbps)}
            labels={liveSamples.map((s) => s.phase.slice(0, 2).toUpperCase())}
            label="Throughput"
            unit="Mbps"
            stroke="var(--qm-ember)"
            minOverride={0}
            height={liveSamples.length ? 230 : 150}
            emptyLabel="The trace draws here while a test runs."
          />
        </Card>

        <Card className="lg:col-span-5 min-w-0">
          <CardHeader title="Trend" subtitle={`Across ${speedtestHistory.length} saved run${speedtestHistory.length === 1 ? "" : "s"}`} />
          {speedtestHistory.length === 0 ? (
            <div className="qm-subcard p-6 text-center text-[13px] text-muted">Trends appear after your first run.</div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-2">
                <div className="qm-subcard p-3 min-w-0">
                  <div className="text-[11px] font-semibold text-muted">Typical down</div>
                  <div className="qm-display text-[1.45rem] font-semibold text-ink qm-tabular leading-tight">{fmtMbps(medDl)}</div>
                  {latest && <Delta latest={latest.downloadMbps} base={medDl} />}
                </div>
                <div className="qm-subcard p-3 min-w-0">
                  <div className="text-[11px] font-semibold text-muted">Typical up</div>
                  <div className="qm-display text-[1.45rem] font-semibold text-ink qm-tabular leading-tight">{fmtMbps(medUl)}</div>
                  {latest && <Delta latest={latest.uploadMbps} base={medUl} />}
                </div>
                <div className="qm-subcard p-3 min-w-0">
                  <div className="text-[11px] font-semibold text-muted">Grades</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {gradeCounts.slice(0, 3).map(([g, n]) => (
                      <span key={g} className="inline-flex items-center gap-1 text-[11.5px] text-muted qm-tabular">
                        <GradeChip grade={g} className="h-6 min-w-6 text-[13px]" />×{n}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              {chrono.length >= 2 ? (
                <DualAreaChart
                  primaryValues={chrono.map((r) => r.downloadMbps)}
                  secondaryValues={chrono.map((r) => r.uploadMbps)}
                  labels={chrono.map((r) => r.timestamp.slice(5, 16))}
                  primaryColor="var(--qm-ember)"
                  secondaryColor="var(--qm-berry)"
                  height={160}
                />
              ) : (
                <p className="text-[12.5px] text-muted">Run one more test to draw a trend line.</p>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* ── History ── */}
      <Card className="min-w-0">
        <CardHeader
          title="Run history"
          subtitle={`${speedtestHistory.length} of 50 saved on the gateway · newest first`}
          icon={<History className="h-4 w-4" />}
          action={
            speedtestHistory.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setConfirmClear(true)} disabled={busy === "speedtest-clear"}>
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </Button>
            )
          }
        />
        <div className="w-full max-w-full overflow-x-auto rounded-2xl border border-line max-h-[420px] overflow-y-auto">
          <table className="w-full min-w-[820px] text-left text-[12.5px] qm-tabular">
            <thead className="sticky top-0 z-[1] bg-sunk text-[11.5px] font-semibold text-muted">
              <tr>
                <th className="py-2.5 px-3">When</th>
                <th className="py-2.5 px-3 text-right">Download</th>
                <th className="py-2.5 px-3 text-right">Upload</th>
                <th className="py-2.5 px-3 text-right">Ping</th>
                <th className="py-2.5 px-3 text-right">Loaded ↓ / ↑</th>
                <th className="py-2.5 px-3 text-center">Grade</th>
                <th className="py-2.5 px-3">Radio</th>
                <th className="py-2.5 px-3">Server</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line bg-surface">
              {speedtestHistory.map((run) => {
                const [d, t] = run.timestamp.split(" ");
                const rf = getRunRf(run);
                return (
                  <tr key={run.id} className="hover:bg-sunk/60">
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="font-semibold text-ink">{t ?? run.timestamp}</div>
                      <div className="text-[11px] text-muted">{d}</div>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="font-semibold text-ink">{run.downloadMbps} <span className="text-muted font-normal text-[11px]">Mbps</span></div>
                      <Meter pct={(run.downloadMbps / maxDl) * 100} tone="ember" thin className="mt-1 ml-auto w-24" />
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="font-semibold text-ink">{run.uploadMbps} <span className="text-muted font-normal text-[11px]">Mbps</span></div>
                      <Meter pct={(run.uploadMbps / maxUl) * 100} tone="berry" thin className="mt-1 ml-auto w-24" />
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap text-ink-2">{run.pingMs} ms</td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap text-ink-2">
                      {run.dlLatencyIqm ?? "--"} / {run.ulLatencyIqm ?? "--"} ms
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <GradeChip grade={run.bufferbloatGrade} />
                    </td>
                    <td className="py-2.5 px-3">
                      {rf ? <RfSnapshotPill rf={rf} compact /> : <span className="text-muted">--</span>}
                    </td>
                    <td className="py-2.5 px-3 max-w-[200px]">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="truncate text-ink-2">{run.serverName || "--"}</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {speedtestHistory.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[13px] text-muted">
                    No saved runs yet. Results land here automatically.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal open={confirmClear} onClose={() => setConfirmClear(false)} title="Clear run history?">
        <p>This deletes all {speedtestHistory.length} saved speedtest results from the gateway. It can't be undone.</p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirmClear(false)}>
            Keep history
          </Button>
          <Button variant="danger" onClick={clearSpeedtestHistory} disabled={busy === "speedtest-clear"}>
            <Trash2 className="h-3.5 w-3.5" />
            Clear history
          </Button>
        </div>
      </Modal>
    </>
  );
}
