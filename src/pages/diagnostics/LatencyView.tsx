import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Zap } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { useDraft } from "../../lib/draft";
import { cn } from "../../lib/utils";
import { useWsStore } from "../../stores/ws-store";
import { useObsStore } from "../../stores/obs-store";
import { useToastStore } from "../../stores/toast-store";
import type { PingPoint } from "../../types/cellcore";
import { Badge, Button, Card, CardHeader, Input, LiveDot, SegmentedTabs, Switch } from "../../components/ui";
import { SmoothAreaChart, type ChartMarker } from "../../components/Charts";
import { eventLabel } from "../../components/obs";
import { TONE_FILL, TONE_INK, errMsg, type HeaderFn, type Tone } from "./shared";

const CHART_EVENT_TYPES = new Set([
  "handover",
  "band_change",
  "ca_change",
  "rat_change",
  "quecwatch_recovery",
  "failover_start",
  "failover_end",
]);

function toEpochMs(ts: number): number {
  return ts < 1e12 ? ts * 1000 : ts;
}

type LatWindow = "realtime" | "hourly" | "twelvehour" | "daily";

interface LatencyResp {
  window: string;
  data: PingPoint[];
  config: { enabled: boolean; host: string; interval: number; keepAlive: boolean };
}

function rttMeta(p: PingPoint | undefined): { tone: Tone; label: string } {
  if (!p) return { tone: "muted", label: "Waiting for samples" };
  if (!p.ok || !Number.isFinite(p.latency)) return { tone: "crimson", label: "No reply" };
  if (p.latency < 60) return { tone: "jade", label: "Snappy" };
  if (p.latency < 120) return { tone: "jade", label: "Good" };
  if (p.latency < 250) return { tone: "saffron", label: "Sluggish" };
  return { tone: "crimson", label: "Poor" };
}

export function LatencyView({ header }: { header: HeaderFn }) {
  const qc = useQueryClient();
  const push = useToastStore((s) => s.push);
  const [latWindow, setLatWindow] = useState<LatWindow>("realtime");
  const [busy, setBusy] = useState(false);
  const pingHistory = useWsStore((s) => s.pingHistory);
  const recentEvents = useObsStore((s) => s.recent);

  const latencyQuery = useQuery({
    queryKey: ["diag-latency", latWindow],
    queryFn: () => apiFetch<LatencyResp>(`/api/v1/diagnostics/latency?window=${latWindow}`),
    refetchInterval: latWindow !== "realtime" ? 15000 : false,
  });

  const cfg = latencyQuery.data?.config;
  // Draft: a refetch never overwrites the host being typed.
  const [pingHostInput, setPingHostInput, hostD] = useDraft(cfg?.host || null, "8.8.8.8");

  const displayedPingPoints = useMemo(() => {
    if (latWindow === "realtime") return pingHistory;
    return latencyQuery.data?.data ?? [];
  }, [latWindow, pingHistory, latencyQuery.data]);

  const latencyMarkers = useMemo<ChartMarker[]>(() => {
    if (displayedPingPoints.length < 2 || recentEvents.length === 0) return [];
    const ptMs = displayedPingPoints.map((p) => toEpochMs(p.ts));
    const minMs = ptMs[0];
    const maxMs = ptMs[ptMs.length - 1];
    const padMs = latWindow === "realtime" ? 15_000 : 60_000;
    const out: ChartMarker[] = [];
    for (const ev of recentEvents) {
      if (!CHART_EVENT_TYPES.has(ev.type)) continue;
      const evMs = toEpochMs(ev.ts);
      if (evMs < minMs - padMs || evMs > maxMs + padMs) continue;
      let bestIdx = 0;
      let bestDiff = Math.abs(ptMs[0] - evMs);
      for (let i = 1; i < ptMs.length; i++) {
        const diff = Math.abs(ptMs[i] - evMs);
        if (diff < bestDiff) {
          bestDiff = diff;
          bestIdx = i;
        }
      }
      const tone: ChartMarker["tone"] =
        ev.severity === "critical" || ev.type === "quecwatch_recovery"
          ? "danger"
          : ev.severity === "warning" || ev.type === "failover_start"
            ? "warn"
            : "info";
      out.push({
        index: bestIdx,
        label: ev.title || eventLabel(ev.type),
        tone,
      });
    }
    return out;
  }, [displayedPingPoints, recentEvents, latWindow]);

  const latencySummary = useMemo(() => {
    if (displayedPingPoints.length === 0) return { min: "--", avg: "--", max: "--", loss: "--" };
    const okVals = displayedPingPoints
      .filter((p) => p.ok && Number.isFinite(p.latency))
      .map((p) => p.latency);
    const losses = displayedPingPoints.map((p) =>
      p.ok ? Number(p.packetLoss ?? p.packet_loss ?? 0) : 100
    );
    return {
      min: okVals.length > 0 ? `${Math.round(Math.min(...okVals))}` : "--",
      avg: okVals.length > 0 ? `${Math.round(okVals.reduce((a, b) => a + b, 0) / okVals.length)}` : "--",
      max: okVals.length > 0 ? `${Math.round(Math.max(...okVals))}` : "--",
      loss: `${Math.round((losses.reduce((a, b) => a + b, 0) / losses.length) * 10) / 10}`,
    };
  }, [displayedPingPoints]);

  async function updateLatencyCfg(patch: { enabled?: boolean; host?: string; interval?: number; keepAlive?: boolean }) {
    setBusy(true);
    try {
      await apiFetch("/api/v1/diagnostics/latency", {
        method: "POST",
        body: JSON.stringify(patch),
      });
      await qc.invalidateQueries({ queryKey: ["diag-latency"] });
      if (patch.host !== undefined) hostD.reset();
      push("Latency & CA probe settings updated", "success");
    } catch (e) {
      push("Update failed", "error", errMsg(e, "Update failed"));
    } finally {
      setBusy(false);
    }
  }

  const last = pingHistory[pingHistory.length - 1];
  const now = rttMeta(last);
  const strip = pingHistory.slice(-60);
  const stripMax = Math.max(80, ...strip.filter((p) => p.ok && Number.isFinite(p.latency)).map((p) => p.latency));
  const recentLoss = strip.length ? Math.round((strip.filter((p) => !p.ok).length / strip.length) * 1000) / 10 : null;
  const probeOn = Boolean(cfg?.enabled ?? true);

  return (
    <>
      {header(
        <Badge variant={probeOn ? "success" : "neutral"} dot>
          {probeOn ? `Probing ${cfg?.host ?? "8.8.8.8"}` : "Probe paused"}
        </Badge>
      )}

      {/* ── Right now ── */}
      <Card className="qm-grain overflow-hidden p-0 sm:p-0">
        <div className="relative z-[1] grid lg:grid-cols-12">
          <div className="lg:col-span-5 p-5 sm:p-7 space-y-3 min-w-0">
            <div className="flex items-center gap-2 text-[12.5px] font-semibold text-ink-2">
              {last ? <LiveDot tone={now.tone === "muted" ? "muted" : now.tone === "jade" ? "jade" : now.tone === "saffron" ? "saffron" : "crimson"} /> : <span className="h-2 w-2 rounded-full bg-line-strong" />}
              Right now · {last?.host ?? cfg?.host ?? "8.8.8.8"}
            </div>
            <div className="flex items-baseline gap-2">
              <span className={cn("qm-display qm-tabular font-semibold leading-[0.9] text-[4.2rem] sm:text-[5.2rem]", now.tone === "crimson" ? "text-crimson-ink" : "text-ink")}>
                {last && last.ok && Number.isFinite(last.latency) ? Math.round(last.latency) : "--"}
              </span>
              <span className="text-[15px] font-semibold text-muted">ms</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={cn("qm-display text-[1.2rem] font-semibold", TONE_INK[now.tone])}>{now.label}</span>
              {recentLoss != null && (
                <span className="text-[12.5px] text-muted qm-tabular">· {recentLoss}% loss in the last {strip.length} pings</span>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1">
              <Badge variant={cfg?.keepAlive ? "info" : "neutral"}>
                <Zap className="h-3 w-3" />
                Keep-alive {cfg?.keepAlive ? "on" : "off"}
              </Badge>
              <Badge>Every {cfg?.interval ?? 5}s</Badge>
            </div>
          </div>
          <div className="lg:col-span-7 border-t lg:border-t-0 lg:border-l border-line bg-sunk/70 p-5 sm:p-7 flex flex-col justify-end min-w-0">
            <div className="flex items-center justify-between text-[11.5px] text-muted mb-2">
              <span className="font-semibold">Last {strip.length || 0} pings</span>
              <span className="flex items-center gap-3">
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-jade" />&lt;120</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-saffron" />&lt;250</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-crimson" />slow / lost</span>
              </span>
            </div>
            <div className="flex h-28 sm:h-32 items-end gap-[2px]" role="img" aria-label="Recent ping round-trip times">
              {strip.length === 0 && <div className="m-auto text-[12.5px] text-muted">Waiting for the first ping…</div>}
              {strip.map((p, i) => {
                const m = rttMeta(p);
                const h = p.ok && Number.isFinite(p.latency) ? Math.max(6, (p.latency / stripMax) * 100) : 100;
                return (
                  <div
                    key={`${p.ts}-${i}`}
                    title={p.ok ? `${Math.round(p.latency)} ms` : "lost"}
                    className={cn("flex-1 min-w-[2px] rounded-t-[3px] transition-[height]", TONE_FILL[m.tone], !p.ok && "opacity-40")}
                    style={{ height: `${h}%` }}
                  />
                );
              })}
            </div>
          </div>
        </div>
      </Card>

      {/* ── History ── */}
      <Card className="min-w-0">
        <CardHeader
          title="Round-trip history"
          subtitle={latWindow === "realtime" ? "Live stream from the modem" : "Rolled up on the gateway, refreshed every 15 s"}
          icon={<Activity className="h-4 w-4" />}
          action={
            <SegmentedTabs
              value={latWindow}
              onChange={setLatWindow}
              options={[
                { id: "realtime", label: "Live" },
                { id: "hourly", label: "1h" },
                { id: "twelvehour", label: "12h" },
                { id: "daily", label: "24h" },
              ]}
            />
          }
        />
        <div className="grid grid-cols-4 gap-2 mb-4">
          {[
            { k: "Best", v: latencySummary.min, u: "ms" },
            { k: "Average", v: latencySummary.avg, u: "ms" },
            { k: "Worst", v: latencySummary.max, u: "ms" },
            { k: "Loss", v: latencySummary.loss, u: "%" },
          ].map((s) => (
            <div key={s.k} className="qm-subcard px-3 py-2.5 min-w-0">
              <div className="text-[11px] font-semibold text-muted">{s.k}</div>
              <div className="flex items-baseline gap-1">
                <span className="qm-display qm-tabular text-[1.35rem] sm:text-[1.6rem] font-semibold text-ink leading-tight">{s.v}</span>
                {s.v !== "--" && <span className="text-[11px] text-muted">{s.u}</span>}
              </div>
            </div>
          ))}
        </div>
        <SmoothAreaChart
          values={displayedPingPoints.map((p) => p.latency)}
          labels={displayedPingPoints.map(
            (p) =>
              p.timestamp.slice(11, 16) ||
              new Date(p.ts).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit" })
          )}
          markers={latencyMarkers}
          label="RTT"
          unit="ms"
          stroke="var(--qm-ember)"
          height={230}
          minOverride={0}
          emptyLabel="No latency samples collected yet for this window."
        />
      </Card>

      {/* ── Settings ── */}
      <div className="grid gap-5 md:grid-cols-2">
        <Card className="min-w-0 space-y-4">
          <Switch
            label="Ping probe"
            description={`Measures round-trip time to ${cfg?.host ?? "8.8.8.8"} every ${cfg?.interval ?? 5}s`}
            checked={probeOn}
            onChange={(v) => updateLatencyCfg({ enabled: v })}
            disabled={busy}
          />
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void updateLatencyCfg({ host: pingHostInput });
            }}
          >
            <Input
              value={pingHostInput}
              onChange={(e) => setPingHostInput(e.target.value)}
              placeholder="8.8.8.8"
              aria-label="Ping target host"
              className="font-mono"
            />
            <Button type="submit" variant="secondary" className="h-10 shrink-0" disabled={busy}>
              Apply host
            </Button>
          </form>
        </Card>
        <Card className="min-w-0 space-y-3">
          <Switch
            label="Carrier keep-alive"
            description="A tiny ping every second so the network doesn't drop your extra 5G carriers when the link goes quiet."
            checked={Boolean(cfg?.keepAlive)}
            onChange={(v) => updateLatencyCfg({ keepAlive: v })}
            disabled={busy}
          />
          <p className="text-[11.5px] text-muted">RRC / 4CA keep-alive · 1 Hz ICMP.</p>
        </Card>
      </div>
    </>
  );
}
