import { useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronRight,
  Clock,
  Crosshair,
  Globe,
  HardDrive,
  MapPin,
  Play,
  RefreshCw,
  Square,
  Timer,
  Zap,
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { disruptiveFetch, isCancelled } from "../lib/disruptive";
import { formatDistanceValue, getBandMetadata } from "../lib/parsers";
import { cn, formatBitrate, formatBytes, signalPercent } from "../lib/utils";
import { hrefFor } from "../stores/route-store";
import { useToastStore } from "../stores/toast-store";
import { useLiveness, useWsStore } from "../stores/ws-store";
import { Badge, Button, CopyButton, LiveDot, Meter, SignalDial, Skeleton, Sparkline, signalQuality } from "../components/ui";
import { InteractiveAreaChart } from "../components/Charts";
import { EventRow, FailoverBadge } from "../components/obs";
import { useObsStore } from "../stores/obs-store";

function splitRate(bps: number): { value: string; unit: string } {
  const [v, u] = formatBitrate(bps).split(" ");
  return { value: v, unit: u ?? "" };
}

function Panel({ className, children }: { className?: string; children: React.ReactNode }) {
  return <section className={cn("qm-card p-[var(--qm-pad)] min-w-0", className)}>{children}</section>;
}

function PanelTitle({ title, hint, action }: { title: string; hint?: string; action?: React.ReactNode }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="qm-display text-[1.15rem] leading-tight text-ink">{title}</h2>
        {hint && <p className="mt-0.5 text-[12.5px] text-muted">{hint}</p>}
      </div>
      {action}
    </div>
  );
}

function KV({ label, value, copy, mono = false }: { label: string; value?: string | null; copy?: string | null; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2.5 border-b border-line last:border-0">
      <span className="text-[12.5px] text-muted shrink-0">{label}</span>
      <span className="flex items-center gap-1 min-w-0">
        <span className={cn("truncate text-[13px] font-semibold text-ink qm-tabular", mono && "font-mono text-[12px]")} title={value ?? undefined}>
          {value || "—"}
        </span>
        {copy && <CopyButton value={copy} />}
      </span>
    </div>
  );
}

// Text sits on every segment: solid fills carry on-ember, soft tints carry matching ink (6CC-ready).
const SEGMENT_TONES = [
  "qm-sun-ink text-on-ember",
  "bg-ember text-on-ember",
  "bg-ember/40 text-ink",
  "bg-jade-soft text-jade-ink",
  "bg-plum-soft text-plum-ink",
  "bg-saffron-soft text-saffron-ink",
];

export function OverviewPage() {
  const [speedBusy, setSpeedBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [sigMetric, setSigMetric] = useState<"rsrp" | "sinr" | "rsrq">("rsrp");
  const toast = useToastStore((s) => s.push);

  const modem = useWsStore((s) => s.modem);
  const signalHistory = useWsStore((s) => s.signalHistory);
  const rsrqHistory = useWsStore((s) => s.rsrqHistory);
  const traffic = useWsStore((s) => s.traffic);
  const dataUsage = useWsStore((s) => s.dataUsage);
  const internals = useWsStore((s) => s.internals);
  const settings = useWsStore((s) => s.settings);
  const ping = useWsStore((s) => s.ping);
  const pingHistory = useWsStore((s) => s.pingHistory);
  const memory = useWsStore((s) => s.memory);
  const sessionUptime = useWsStore((s) => s.sessionUptime);
  const deviceUptime = useWsStore((s) => s.deviceUptime);
  const speedtest = useWsStore((s) => s.speedtest);
  const speedtestHistory = useWsStore((s) => s.speedtestHistory);
  const hydrated = useWsStore((s) => s.hydrated);
  const hydrateBootstrap = useWsStore((s) => s.hydrateBootstrap);
  const resetSpeedtest = useWsStore((s) => s.resetSpeedtest);
  const wsStatus = useWsStore((s) => s.status);
  const liveness = useLiveness();
  const recentEvents = useObsStore((s) => s.recent);
  const failover = useObsStore((s) => s.failover);

  const serving = modem?.serving ?? null;
  const carriers = useMemo(() => modem?.carriers ?? [], [modem]);
  const mimo = modem?.mimo ?? { rsrp: [null, null, null, null], rsrq: [null, null, null, null], sinr: [null, null, null, null], rat: "NR5G" };
  const bearer = modem?.bearers?.[0] ?? null;
  const isClat = Boolean(bearer?.ipv4?.startsWith("192.0.0."));
  const isConnected = bearer?.status === "CONNECTED" || (modem?.identity?.cfun === 1 && carriers.length > 0);
  const totalBw = useMemo(() => carriers.reduce((sum, c) => sum + (c.bandwidthMhz ?? 0), 0), [carriers]);
  const quality = signalQuality(serving?.rsrp ?? null, serving?.sinr ?? null);
  const pcc = carriers.find((c) => c.role === "PCC") ?? null;
  const operator = modem?.operator || "Searching";
  const ratLabel = serving?.rat?.includes("NR") ? "5G" : serving?.rat?.includes("LTE") ? "LTE" : serving?.rat || "Cellular";
  const ratMode = serving?.rat ?? "";

  const distUnit: "mi" | "km" = settings?.measurementUnit === "km" ? "km" : "mi";
  const towerDist = formatDistanceValue(modem?.timeAdvance?.activeMeters ?? null, distUnit);

  const rxSeries = useMemo(() => traffic.history.map((p) => p.rxBps), [traffic.history]);
  const txSeries = useMemo(() => traffic.history.map((p) => p.txBps), [traffic.history]);
  const pingSeries = useMemo(() => pingHistory.slice(-60).map((p) => p.latency), [pingHistory]);

  const usage = useMemo(() => {
    if (dataUsage?.usageSummary) {
      const u = dataUsage.usageSummary;
      return { today: u.todayRx + u.todayTx, month: u.monthRx + u.monthTx, todayRx: u.todayRx, todayTx: u.todayTx };
    }
    const d = dataUsage?.daily?.[dataUsage.daily.length - 1];
    const m = dataUsage?.monthly?.[dataUsage.monthly.length - 1];
    return {
      today: d ? d.rxBytes + d.txBytes : traffic.rxTotalBytes + traffic.txTotalBytes,
      month: m ? m.rxBytes + m.txBytes : 0,
      todayRx: d?.rxBytes ?? traffic.rxTotalBytes,
      todayTx: d?.txBytes ?? traffic.txTotalBytes,
    };
  }, [dataUsage, traffic.rxTotalBytes, traffic.txTotalBytes]);

  const memPct = memory ? Math.round(memory.percent) : 0;
  const lastRun = speedtestHistory[0] ?? null;
  const running = speedtest.running;
  const rx = splitRate(traffic.rxBps);
  const tx = splitRate(traffic.txBps);

  const verdict = !serving
    ? wsStatus === "connected"
      ? "Looking for a cell…"
      : "Connecting to the gateway…"
    : `${quality.label} ${ratLabel} on ${operator}`;

  async function refresh() {
    setRefreshing(true);
    try {
      await apiFetch("/api/v1/modem/refresh", { method: "POST", body: "{}" });
      await hydrateBootstrap();
    } catch (e) {
      toast("Refresh failed", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setRefreshing(false);
    }
  }

  async function startSpeedtest() {
    setSpeedBusy(true);
    resetSpeedtest();
    try {
      await disruptiveFetch("speedtest", "/api/v1/speedtest/start", { method: "POST", body: JSON.stringify({}) });
    } catch (e) {
      if (!isCancelled(e)) toast("Speedtest failed to start", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setSpeedBusy(false);
    }
  }

  async function stopSpeedtest() {
    setSpeedBusy(true);
    try {
      await apiFetch("/api/v1/speedtest/stop", { method: "POST", body: JSON.stringify({}) });
    } finally {
      setSpeedBusy(false);
    }
  }

  if (!hydrated && !serving) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-[340px]" />
        <div className="grid gap-5 lg:grid-cols-12">
          <Skeleton className="h-56 lg:col-span-8" />
          <Skeleton className="h-56 lg:col-span-4" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── Hero: verdict + dial + live flow ─────────────────────────── */}
      <section className="qm-card qm-grain relative overflow-hidden p-0">
        <div aria-hidden className="pointer-events-none absolute -top-40 -right-24 h-[420px] w-[420px] rounded-full qm-sun opacity-[0.13] blur-3xl" />
        <div className="relative grid lg:grid-cols-12">
          <div className="lg:col-span-5 flex flex-col items-center justify-center gap-3 px-6 pt-8 pb-4 lg:py-10 lg:border-r border-line">
            <SignalDial
              value={serving?.rsrp ?? null}
              size={236}
              unit="dBm RSRP"
              caption={
                <Badge variant={quality.badge} dot>
                  {quality.label}
                </Badge>
              }
            />
            <div className="grid w-full max-w-[300px] grid-cols-3 gap-2 text-center qm-tabular">
              {[
                { k: "SINR", v: serving?.sinr, u: "dB", pct: signalPercent("sinr", serving?.sinr ?? null) },
                { k: "RSRQ", v: serving?.rsrq, u: "dB", pct: signalPercent("rsrq", serving?.rsrq ?? null) },
                { k: "Tower", v: towerDist, u: "", pct: null },
              ].map((m) => (
                <div key={m.k} className="rounded-2xl bg-sunk px-2 py-2.5">
                  <div className="qm-eyebrow">{m.k}</div>
                  <div className="mt-1 text-[15px] font-bold text-ink">
                    {m.v ?? "—"}
                    {m.u && m.v != null && <span className="ml-0.5 text-[11px] font-semibold text-muted">{m.u}</span>}
                  </div>
                  {m.pct != null && <Meter pct={m.pct} thin className="mt-1.5" tone="sun" />}
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-7 flex flex-col gap-6 px-6 pb-7 pt-4 lg:p-10">
            <div>
              <div className="qm-eyebrow flex flex-wrap items-center gap-2">
                <LiveDot tone={!liveness.live ? liveness.tone : isConnected ? "jade" : "saffron"} />
                <span role={liveness.live ? undefined : "status"}>{liveness.label}</span> · {traffic.primaryIface}
                <FailoverBadge />
              </div>
              <h1 className="qm-display mt-2 text-[2.1rem] sm:text-[2.75rem] leading-[1.02] text-ink">{verdict}</h1>
              <p className="mt-2.5 text-[14px] text-ink-2 leading-relaxed max-w-xl">
                {serving ? (
                  <>
                    {ratMode} anchored on <strong className="text-ink">{pcc?.band ?? serving.band}</strong>
                    {carriers.length > 1 && (
                      <>
                        {" "}
                        with <strong className="text-ink">{carriers.length} carriers</strong> aggregating{" "}
                        <strong className="qm-sun-text">{totalBw} MHz</strong>
                      </>
                    )}
                    . Cell {serving.cellId} · PCI {serving.pci ?? "—"} · {serving.mcc}-{serving.mnc}
                  </>
                ) : (
                  "Radio telemetry will appear as soon as the modem reports a serving cell."
                )}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Download", icon: <ArrowDown className="h-3.5 w-3.5" />, rate: rx, series: rxSeries, color: "var(--qm-jade)", tone: "text-jade-ink" },
                { label: "Upload", icon: <ArrowUp className="h-3.5 w-3.5" />, rate: tx, series: txSeries, color: "var(--qm-berry)", tone: "text-berry-ink" },
              ].map((f) => (
                <div key={f.label} className="rounded-2xl border border-line bg-raised/60 p-4 min-w-0">
                  <div className={cn("flex items-center gap-1.5 text-[12px] font-bold", f.tone)}>
                    {f.icon}
                    {f.label}
                  </div>
                  <div className="mt-1 flex items-baseline gap-1.5 qm-tabular">
                    <span className="qm-display text-[1.9rem] leading-none text-ink">{f.rate.value}</span>
                    <span className="text-[12px] font-semibold text-muted">{f.rate.unit}</span>
                  </div>
                  <Sparkline values={f.series} color={f.color} height={34} className="mt-2" />
                </div>
              ))}
            </div>

            {running || speedtest.phase !== "idle" ? (
              <div className="rounded-2xl border border-line bg-sunk p-4 space-y-3">
                <div className="flex items-center justify-between gap-2 text-[13px]">
                  <span className="font-bold capitalize text-ink flex items-center gap-2">
                    <Zap className="h-4 w-4 text-ember-ink" />
                    Speedtest · {speedtest.phase}
                  </span>
                  <span className="font-bold qm-tabular text-ink">{speedtest.progress}%</span>
                </div>
                <Meter pct={speedtest.progress} tone="sun" />
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[13px] qm-tabular">
                  <span className="text-jade-ink font-bold">↓ {speedtest.downloadMbps ?? "—"} Mbps</span>
                  <span className="text-berry-ink font-bold">↑ {speedtest.uploadMbps ?? "—"} Mbps</span>
                  {speedtest.bufferbloatGrade && <Badge variant={speedtest.bufferbloatGrade.startsWith("A") ? "success" : "warning"}>Bloat {speedtest.bufferbloatGrade}</Badge>}
                  {running ? (
                    <Button variant="secondary" size="sm" className="ml-auto" onClick={stopSpeedtest} disabled={speedBusy}>
                      <Square className="h-3.5 w-3.5" /> Stop
                    </Button>
                  ) : (
                    <a href={hrefFor("/diagnostics", "speedtest")} className="ml-auto text-[12.5px] font-bold text-ember-ink hover:underline">
                      Details →
                    </a>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="tier1" size="lg" onClick={startSpeedtest} disabled={speedBusy}>
                  <Play className="h-4 w-4" /> Run speedtest
                </Button>
                <Button variant="secondary" size="lg" onClick={() => (window.location.hash = hrefFor("/cellular", "lock"))}>
                  <Crosshair className="h-4 w-4" /> Lock this cell
                </Button>
                <Button variant="ghost" size="lg" onClick={refresh} disabled={refreshing} aria-label="Refresh radio telemetry" title="Refresh radio telemetry">
                  <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
                </Button>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ── Spectrum ribbon + antennas ───────────────────────────────── */}
      <div className="grid gap-5 lg:grid-cols-12">
        <Panel className="lg:col-span-8">
          <PanelTitle
            title="Spectrum"
            hint={carriers.length ? `${carriers.length} component carriers · ${totalBw} MHz downlink` : "Single carrier"}
            action={
              <a href={hrefFor("/cellular", "bands")} className="inline-flex items-center gap-1 text-[12.5px] font-bold text-ember-ink hover:underline">
                Bands <ChevronRight className="h-3.5 w-3.5" />
              </a>
            }
          />
          {carriers.length > 0 ? (
            <>
              <div className="flex flex-wrap sm:flex-nowrap min-h-16 w-full gap-1 overflow-hidden rounded-2xl" role="img" aria-label="Carrier aggregation by bandwidth">
                {carriers.map((c, i) => {
                  const bw = c.bandwidthMhz ?? 5;
                  return (
                    <div
                      key={`${c.arfcn}-${i}`}
                      className={cn("flex min-w-[68px] sm:min-w-[52px] flex-col justify-center overflow-hidden px-3 py-2 whitespace-nowrap transition-all", SEGMENT_TONES[Math.min(i, SEGMENT_TONES.length - 1)])}
                      style={{ flexGrow: bw, flexBasis: "68px" }}
                      title={`${c.role} ${c.band} · ${bw} MHz${c.dlMimoLayers ? ` · ${c.dlMimoLayers}×${c.ulMimoLayers ?? 1} MIMO` : ""}`}
                    >
                      <span className="text-[14px] font-extrabold leading-none">{c.band}</span>
                      <span className="mt-1 text-[11px] font-semibold qm-tabular">
                        {c.bandwidthMhz ?? "—"}M{c.dlMimoLayers ? ` · ${c.dlMimoLayers}×${c.ulMimoLayers ?? 1}` : ""}
                      </span>
                    </div>
                  );
                })}
              </div>
              <div className="mt-4 overflow-x-auto -mx-1">
                <table className="w-full min-w-[580px] text-[13px] qm-tabular">
                  <thead>
                    <tr className="text-left text-[11px] font-bold uppercase tracking-wider text-muted">
                      <th className="px-1 pb-2">Carrier</th>
                      <th className="px-1 pb-2">State</th>
                      <th className="px-1 pb-2">Spectrum</th>
                      <th className="px-1 pb-2 text-right">ARFCN</th>
                      <th className="px-1 pb-2 text-right">PCI</th>
                      <th className="px-1 pb-2 text-right">MIMO</th>
                      <th className="px-1 pb-2 text-right">RSRP / SINR</th>
                      <th className="px-1 pb-2 text-right">Width</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {carriers.map((c, i) => {
                      const meta = getBandMetadata(c.band);
                      const stateBadge = c.role === "PCC" ? "PCC" : c.pcellState === 2 ? "Active" : c.pcellState === 1 ? "Config" : c.pcellState === 0 ? "Deact" : "SCC";
                      return (
                        <tr key={`${c.arfcn}-row-${i}`}>
                          <td className="px-1 py-2.5">
                            <span className="flex items-center gap-2">
                              <span className={cn("h-2.5 w-2.5 rounded-full", SEGMENT_TONES[Math.min(i, SEGMENT_TONES.length - 1)].split(" ")[0])} />
                              <span className="font-bold text-ink">{c.band}</span>
                              {c.role === "PCC" ? (
                                <Badge variant="sage">Anchor</Badge>
                              ) : c.ulConfigured ? (
                                <Badge variant="plum">UL CA</Badge>
                              ) : null}
                            </span>
                          </td>
                          <td className="px-1 py-2.5">
                            <Badge variant={c.role === "PCC" || c.pcellState === 2 ? "success" : "neutral"}>{stateBadge}</Badge>
                          </td>
                          <td className="px-1 py-2.5 text-ink-2">
                            {meta.spectrum} · {meta.duplex}
                          </td>
                          <td className="px-1 py-2.5 text-right font-mono text-[12px] text-ink-2">{c.arfcn}</td>
                          <td className="px-1 py-2.5 text-right text-ink-2">{c.pci ?? "—"}</td>
                          <td className="px-1 py-2.5 text-right text-ink-2">{c.dlMimoLayers != null ? `${c.dlMimoLayers}×${c.ulMimoLayers ?? 1}` : "—"}</td>
                          <td className="px-1 py-2.5 text-right text-ink-2">
                            {c.rsrp != null || c.sinr != null ? `${c.rsrp ?? "—"} / ${c.sinr ?? "—"}` : "—"}
                          </td>
                          <td className="px-1 py-2.5 text-right font-bold text-ink">
                            {c.bandwidthMhz ?? "—"}
                            {c.ulBandwidthMhz != null && c.ulBandwidthMhz !== c.bandwidthMhz ? ` / ↑${c.ulBandwidthMhz}` : ""} MHz
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="rounded-2xl bg-sunk px-4 py-8 text-center text-[13px] text-muted">
              {serving ? `Single carrier on ${serving.band}${serving.dlBandwidthMhz ? ` · ${serving.dlBandwidthMhz} MHz` : ""}` : "Waiting for carrier report…"}
            </div>
          )}
        </Panel>

        <Panel className="lg:col-span-4">
          <PanelTitle
            title="Antennas"
            hint={`4×4 MIMO · ${mimo.rat || "NR5G"}`}
            action={
              <a href={hrefFor("/cellular", "align")} className="inline-flex items-center gap-1 text-[12.5px] font-bold text-ember-ink hover:underline">
                Aim <ChevronRight className="h-3.5 w-3.5" />
              </a>
            }
          />
          <div className="space-y-4">
            {[0, 1, 2, 3].map((i) => {
              const role = (["PRX · TX0", "DRX", "MIMO · TX1", "MIMO"] as const)[i];
              const rsrp = mimo.rsrp[i];
              const q = signalQuality(rsrp, mimo.sinr[i]);
              const active = rsrp != null;
              return (
                <div key={i}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="flex flex-wrap items-center gap-1.5 text-[13px] font-bold text-ink">
                      <span>RX{i}</span>
                      <span className="rounded-md border border-line bg-sunk px-1.5 py-0.5 font-mono text-[10.5px] font-semibold tracking-tight text-ink-2">
                        {role}
                      </span>
                      <span className="ml-0.5 text-[12px] font-medium text-muted">{active ? `SINR ${mimo.sinr[i] ?? "—"} dB` : "idle"}</span>
                    </span>
                    <span className={cn("text-[14px] font-bold qm-tabular shrink-0", active ? "text-ink" : "text-muted")}>{active ? `${rsrp} dBm` : "—"}</span>
                  </div>
                  <Meter
                    className="mt-1.5"
                    pct={active ? signalPercent("rsrp", rsrp) : 0}
                    tone={!active ? "muted" : q.tone === "jade" ? "jade" : q.tone === "saffron" ? "saffron" : "crimson"}
                  />
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      {/* ── Pulse strip ──────────────────────────────────────────────── */}
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
        <Panel className="flex flex-col">
          <div className="flex items-center justify-between">
            <span className="qm-eyebrow flex items-center gap-1.5">
              <Timer className="h-3.5 w-3.5" /> Latency
            </span>
            <span className="text-[11.5px] text-muted">{ping?.host ?? "8.8.8.8"}</span>
          </div>
          <div className="mt-2 flex items-baseline gap-1 qm-tabular">
            <span className="qm-display text-[2rem] leading-none text-ink">{ping?.latency ?? "—"}</span>
            <span className="text-[12px] font-semibold text-muted">ms</span>
          </div>
          <Sparkline values={pingSeries} color="var(--qm-ember)" height={38} className="mt-auto pt-3" />
        </Panel>

        <Panel>
          <span className="qm-eyebrow flex items-center gap-1.5">
            <HardDrive className="h-3.5 w-3.5" /> Data today
          </span>
          <div className="mt-2 qm-display text-[2rem] leading-none text-ink qm-tabular">{formatBytes(usage.today, 1)}</div>
          <div className="mt-3 flex h-2 overflow-hidden rounded-full bg-line">
            <div className="bg-jade" style={{ flexGrow: usage.todayRx || 1 }} />
            <div className="bg-berry" style={{ flexGrow: usage.todayTx || 0 }} />
          </div>
          <div className="mt-2 text-[12px] text-muted qm-tabular">
            Month {usage.month > 0 ? formatBytes(usage.month, 1) : "—"} ·{" "}
            <a href={hrefFor("/network", "usage")} className="font-bold text-ember-ink hover:underline">
              History
            </a>
          </div>
        </Panel>

        <Panel>
          <span className="qm-eyebrow flex items-center gap-1.5">
            <Zap className="h-3.5 w-3.5" /> Last speedtest
          </span>
          {lastRun ? (
            <>
              <div className="mt-2 flex items-baseline gap-3 qm-tabular">
                <span className="qm-display text-[2rem] leading-none text-ink">{Math.round(lastRun.downloadMbps)}</span>
                <span className="text-[12px] font-semibold text-muted">↓ Mbps</span>
                <span className="ml-auto text-[15px] font-bold text-berry-ink">↑ {Math.round(lastRun.uploadMbps)}</span>
              </div>
              <div className="mt-3 flex items-center gap-2 text-[12px] text-muted qm-tabular">
                <Badge variant={lastRun.bufferbloatGrade?.startsWith("A") ? "success" : lastRun.bufferbloatGrade?.startsWith("B") ? "sage" : "warning"}>
                  Grade {lastRun.bufferbloatGrade || "—"}
                </Badge>
                {lastRun.pingMs} ms idle
              </div>
            </>
          ) : (
            <div className="mt-3 text-[13px] text-muted">No runs yet.</div>
          )}
        </Panel>

        <Panel>
          <span className="qm-eyebrow flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5" /> Uptime
          </span>
          <div className="mt-2 qm-display text-[1.6rem] leading-none text-ink qm-tabular">
            {sessionUptime?.uptimeFormatted ?? sessionUptime?.uptime_formatted ?? "—"}
          </div>
          <div className="mt-1 text-[12px] text-muted">WAN session</div>
          <div className="mt-3 flex items-center justify-between text-[12.5px] qm-tabular">
            <span className="text-muted">Gateway</span>
            <span className="font-bold text-ink">{deviceUptime?.uptimeFormatted ?? deviceUptime?.uptime_formatted ?? "—"}</span>
          </div>
        </Panel>
      </div>

      {/* ── Recent events ────────────────────────────────────────────── */}
      <Panel>
        <PanelTitle
          title="Recent events"
          hint={
            failover?.active
              ? "Carrying failover traffic: scheduled reboots, lock schedules and LinkWatch resets wait"
              : failover?.lastEpisode
                ? `Standby · last failover ended ${new Date(failover.lastEpisode.endedAt * 1000).toLocaleString()}`
                : "Handovers, carrier changes, recoveries and failover, newest first"
          }
          action={
            <a href={hrefFor("/diagnostics", "events")} className="inline-flex items-center gap-1 whitespace-nowrap text-[12.5px] font-bold text-ember-ink hover:underline">
              All events <ChevronRight className="h-3.5 w-3.5" />
            </a>
          }
        />
        {recentEvents.length > 0 ? (
          <div className="grid gap-x-8 lg:grid-cols-2">
            {[recentEvents.slice(0, 3), recentEvents.slice(3, 6)].map((col, i) => (
              <div key={i} className="min-w-0">
                {col.map((e) => (
                  <EventRow key={e.id} event={e} />
                ))}
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-2xl bg-sunk px-4 py-6 text-center text-[13px] text-muted">No events recorded yet.</div>
        )}
      </Panel>

      {/* ── Signal history (3h) ──────────────────────────────────────── */}
      <Panel>
        <PanelTitle
          title="Signal history (3h)"
          hint="1-minute sampled link trend across all active receive chains"
          action={
            <div className="inline-flex rounded-full bg-sunk p-0.5 border border-line">
              {(["rsrp", "sinr", "rsrq"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setSigMetric(m)}
                  className={cn(
                    "cursor-pointer rounded-full px-2.5 py-1 text-[11px] font-bold uppercase transition-colors",
                    sigMetric === m ? "bg-ember text-on-ember" : "text-ink-2 hover:text-ink"
                  )}
                >
                  {m}
                </button>
              ))}
            </div>
          }
        />
        <InteractiveAreaChart
          series={[
            {
              label: sigMetric.toUpperCase(),
              values: (sigMetric === "rsrp" ? signalHistory.rsrp : sigMetric === "sinr" ? signalHistory.sinr : rsrqHistory).map((p) => p.value),
              stroke: sigMetric === "rsrp" ? "var(--qm-ember)" : sigMetric === "sinr" ? "var(--qm-jade)" : "var(--qm-saffron)",
              fillStart: sigMetric === "rsrp" ? "var(--qm-ember)" : sigMetric === "sinr" ? "var(--qm-jade)" : "var(--qm-saffron)",
              unit: sigMetric === "rsrp" ? " dBm" : " dB",
            },
          ]}
          labels={(sigMetric === "rsrp" ? signalHistory.rsrp : sigMetric === "sinr" ? signalHistory.sinr : rsrqHistory).map((p) => p.label)}
          height={175}
          emptyLabel="Waiting for 1-minute signal samples…"
        />
      </Panel>

      {/* ── Addressing + appliance ───────────────────────────────────── */}
      <div className="grid gap-5 lg:grid-cols-12">
        <Panel className="lg:col-span-7">
          <PanelTitle
            title="Addressing"
            hint={bearer ? `${bearer.apn || "APN"} · ${bearer.ipType}${isClat ? " · 464XLAT" : ""}` : "No data bearer yet"}
            action={
              <Badge variant={isConnected ? "success" : "warning"} dot>
                {isConnected ? "Connected" : "Idle"}
              </Badge>
            }
          />
          <KV label="Public IP" value={modem?.publicIp ?? null} copy={modem?.publicIp ?? null} />
          <KV label={isClat ? "CLAT IPv4" : "IPv4"} value={bearer?.ipv4 ?? null} copy={bearer?.ipv4 ?? null} mono />
          {bearer?.ipv4Gateway && <KV label="IPv4 gateway" value={bearer.ipv4Gateway} copy={bearer.ipv4Gateway} mono />}
          <KV label="IPv6" value={bearer?.ipv6 ?? null} copy={bearer?.ipv6 ?? null} mono />
          <KV label="IPv6 gateway" value={bearer?.ipv6Gateway ?? null} copy={bearer?.ipv6Gateway ?? null} mono />
          {(() => {
            const dnsList = Array.from(
              new Set([bearer?.ipv4Dns1, bearer?.ipv4Dns2, bearer?.ipv6Dns1, bearer?.ipv6Dns2].filter((x): x is string => Boolean(x)))
            );
            return <KV label="DNS" value={dnsList.join(", ") || null} copy={dnsList[0] ?? null} mono />;
          })()}
        </Panel>

        <Panel className="lg:col-span-5">
          <PanelTitle
            title="Appliance"
            hint={`${modem?.identity?.model || "RM551E-GL"} · ${traffic.lanIface} ${internals?.ethSpeed ?? ""}`}
            action={
              <a href={hrefFor("/system", "hardware")} className="inline-flex items-center gap-1 text-[12.5px] font-bold text-ember-ink hover:underline">
                System <ChevronRight className="h-3.5 w-3.5" />
              </a>
            }
          />
          <div className="space-y-4">
            <div>
              <div className="flex items-baseline justify-between text-[13px] qm-tabular">
                <span className="font-semibold text-ink">Memory</span>
                <span className="text-muted">
                  {memory ? `${Math.round(memory.used / 1048576)} / ${Math.round(memory.total / 1048576)} MiB` : "—"}
                </span>
              </div>
              <Meter className="mt-1.5" pct={memPct} tone={memPct > 85 ? "crimson" : memPct > 70 ? "saffron" : "ember"} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-2xl bg-sunk p-3.5">
                <div className="qm-eyebrow flex items-center gap-1.5">
                  <Globe className="h-3 w-3" /> LAN link
                </div>
                <div className="mt-1.5 text-[15px] font-bold text-ink qm-tabular">{internals?.ethSpeed || "—"}</div>
              </div>
              <div className="rounded-2xl bg-sunk p-3.5">
                <div className="qm-eyebrow flex items-center gap-1.5">
                  <MapPin className="h-3 w-3" /> Tower
                </div>
                <div className="mt-1.5 text-[15px] font-bold text-ink qm-tabular">{towerDist}</div>
              </div>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
