import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, History, Minus, Play, Radio, Square, Trash2 } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { cn } from "../../lib/utils";
import { useWsStore } from "../../stores/ws-store";
import { useToastStore } from "../../stores/toast-store";
import type { SpeedtestRun } from "../../types/cellcore";
import { Badge, Button, Card, CardHeader, LiveDot, Meter, Modal } from "../../components/ui";
import { DualAreaChart, SmoothAreaChart } from "../../components/Charts";
import { TONE_INK, TONE_SOFT, errMsg, fmtMbps, gradeMeta, median, type HeaderFn } from "./shared";

const STEPS = [
  { id: "ping", label: "Ping" },
  { id: "download", label: "Download" },
  { id: "upload", label: "Upload" },
  { id: "complete", label: "Done" },
] as const;

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

function Numeral({ label, dot, value }: { label: string; dot: string; value: string }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-2 text-[12.5px] font-semibold text-muted">
        <span className={cn("h-2 w-2 rounded-full", dot)} />
        {label}
      </div>
      <div className="mt-1 flex items-baseline gap-2 min-w-0">
        <span className="qm-display qm-tabular font-semibold leading-[0.9] text-ink text-[3.1rem] sm:text-[4.4rem] lg:text-[5rem]">
          {value}
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

export function SpeedtestView({ header }: { header: HeaderFn }) {
  const push = useToastStore((s) => s.push);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const speedtest = useWsStore((s) => s.speedtest);
  const speedtestHistory = useWsStore((s) => s.speedtestHistory);
  const modem = useWsStore((s) => s.modem);
  const refreshSpeedtestHistory = useWsStore((s) => s.refreshSpeedtestHistory);
  const resetSpeedtest = useWsStore((s) => s.resetSpeedtest);

  useEffect(() => {
    void refreshSpeedtestHistory();
  }, [refreshSpeedtestHistory]);

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

  return (
    <>
      {header()}

      {/* ── Hero: run + headline numbers + bufferbloat verdict ── */}
      <Card className="qm-grain overflow-hidden p-0 sm:p-0">
        <div className="relative z-[1] grid lg:grid-cols-12">
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

            <div className="grid grid-cols-2 gap-4 sm:gap-8">
              <Numeral label="Download" dot="bg-ember" value={fmtMbps(activeRunDisplay?.downloadMbps)} />
              <Numeral label="Upload" dot="bg-berry" value={fmtMbps(activeRunDisplay?.uploadMbps)} />
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-2 text-[13px] text-ink-2 qm-tabular">
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
              <Meter pct={speedtest.progress} tone="sun" />
            </div>

            {speedtest.error && (
              <div className="rounded-2xl bg-crimson-soft px-4 py-3 text-[13px] text-crimson-ink">{speedtest.error}</div>
            )}

            {/* Live Carrier Aggregation & SCC activation strip (1s refresh during test) */}
            {modem && modem.carriers.length > 0 && (
              <div className="rounded-2xl border border-line bg-sunk/50 px-3.5 py-2.5 space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11.5px] font-semibold text-muted">
                  <span className="inline-flex items-center gap-1.5">
                    <Radio className="h-3.5 w-3.5 text-ember-ink" />
                    Live Radio · {modem.carriers.length}CA ·{" "}
                    {Math.round(
                      modem.carriers.reduce((acc, c) => acc + (c.bandwidthMhz ?? 0), 0)
                    )}{" "}
                    MHz
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
            )}

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
                    className="h-12 sm:min-w-[220px]"
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
                    className="h-12 sm:min-w-[220px] text-[15px]"
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
              className={cn(
                "flex h-36 w-36 sm:h-40 sm:w-40 items-center justify-center rounded-full ring-[10px]",
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
          <table className="w-full min-w-[720px] text-left text-[12.5px] qm-tabular">
            <thead className="sticky top-0 z-[1] bg-sunk text-[11.5px] font-semibold text-muted">
              <tr>
                <th className="py-2.5 px-3">When</th>
                <th className="py-2.5 px-3 text-right">Download</th>
                <th className="py-2.5 px-3 text-right">Upload</th>
                <th className="py-2.5 px-3 text-right">Ping</th>
                <th className="py-2.5 px-3 text-right">Loaded ↓ / ↑</th>
                <th className="py-2.5 px-3 text-center">Grade</th>
                <th className="py-2.5 px-3">Server</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line bg-surface">
              {speedtestHistory.map((run) => {
                const [d, t] = run.timestamp.split(" ");
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
                  <td colSpan={7} className="py-8 text-center text-[13px] text-muted">
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
