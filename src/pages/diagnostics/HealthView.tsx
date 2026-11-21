import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleX, RefreshCw, ShieldCheck } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { useDraft } from "../../lib/draft";
import { cn } from "../../lib/utils";
import { useToastStore } from "../../stores/toast-store";
import { Badge, Button, Card, CardHeader, Input, LiveDot, Skeleton, Switch } from "../../components/ui";
import { TONE_INK, TONE_SOFT, errMsg, type HeaderFn, type Tone } from "./shared";

interface HealthResp {
  checks: Array<{ label: string; ok: boolean; detail: string }>;
  passed: number;
  total: number;
}

interface LinkWatchResp {
  enabled: boolean;
  config: {
    pingTarget: string;
    pingInterval: number;
    pingFailures: number;
    maxRetries: number;
    connectionRefresh: boolean;
    autoSimFailover: boolean;
    highLatencyMonitoring: boolean;
    latencyCeiling: number;
  };
  runtime: { status: string; message: string; retry: number; currentLatency: number };
}

function runtimeTone(status: string | undefined, enabled: boolean): Tone {
  if (!enabled) return "muted";
  const s = (status ?? "").toLowerCase();
  if (s === "healthy" || s === "ok" || s === "monitoring") return "jade";
  if (/fail|error|down|lost|dead/.test(s)) return "crimson";
  if (!s) return "muted";
  return "saffron";
}

export function HealthView({ header }: { header: HeaderFn }) {
  const qc = useQueryClient();
  const push = useToastStore((s) => s.push);
  const [busy, setBusy] = useState(false);

  const healthQuery = useQuery({
    queryKey: ["diag-health"],
    queryFn: () => apiFetch<HealthResp>("/api/v1/diagnostics/health"),
    refetchInterval: 15000,
  });

  const qwQuery = useQuery({
    queryKey: ["diag-quecwatch"],
    queryFn: () => apiFetch<LinkWatchResp>("/api/v1/diagnostics/quecwatch"),
    refetchInterval: 10000,
  });

  // Drafts: the 10 s runtime poll (and the first load) never overwrite what you're typing.
  const qwCfg = qwQuery.data?.config;
  const [qwTarget, setQwTarget, targetD] = useDraft(qwCfg ? qwCfg.pingTarget || "8.8.8.8" : null, "8.8.8.8");
  const [qwInterval, setQwInterval, intervalD] = useDraft(qwCfg ? String(qwCfg.pingInterval ?? 60) : null, "60");
  const [qwMaxRetries, setQwMaxRetries, retriesD] = useDraft(qwCfg ? String(qwCfg.maxRetries ?? 5) : null, "5");

  async function saveLinkWatch(enabled: boolean) {
    setBusy(true);
    try {
      const cfg = qwQuery.data?.config;
      await apiFetch("/api/v1/diagnostics/quecwatch", {
        method: "POST",
        body: JSON.stringify({
          enabled,
          pingTarget: qwTarget.trim() || "8.8.8.8",
          pingInterval: Number(qwInterval) || 60,
          pingFailures: cfg?.pingFailures ?? 3,
          maxRetries: Number(qwMaxRetries) || 5,
          connectionRefresh: cfg?.connectionRefresh ?? true,
          autoSimFailover: cfg?.autoSimFailover ?? false,
          highLatencyMonitoring: cfg?.highLatencyMonitoring ?? false,
          latencyCeiling: cfg?.latencyCeiling ?? 150,
        }),
      });
      await qc.invalidateQueries({ queryKey: ["diag-quecwatch"] });
      targetD.reset();
      intervalD.reset();
      retriesD.reset();
      push(`LinkWatch ${enabled ? "enabled" : "disabled"}`, "success");
    } catch (e) {
      push("LinkWatch update failed", "error", errMsg(e, "LinkWatch error"));
    } finally {
      setBusy(false);
    }
  }

  const h = healthQuery.data;
  const passed = h?.passed ?? 0;
  const total = h?.total ?? 4;
  const failing = (h?.checks ?? []).filter((c) => !c.ok);
  const loading = healthQuery.isLoading;
  const verdictTone: Tone = loading ? "muted" : failing.length === 0 && passed === total ? "jade" : passed === 0 ? "crimson" : "saffron";
  const headline = loading
    ? "Checking the link…"
    : verdictTone === "jade"
      ? "Everything looks healthy"
      : `${total - passed} check${total - passed === 1 ? "" : "s"} need${total - passed === 1 ? "s" : ""} attention`;

  const qw = qwQuery.data;
  const qwEnabled = Boolean(qw?.enabled);
  const rt = qw?.runtime;
  const rtTone = runtimeTone(rt?.status, qwEnabled);
  const VerdictIcon = verdictTone === "jade" || verdictTone === "muted" ? CircleCheck : CircleX;

  return (
    <>
      {header(
        <Button variant="secondary" size="sm" onClick={() => { void healthQuery.refetch(); void qwQuery.refetch(); }}>
          <RefreshCw className={cn("h-3.5 w-3.5", (healthQuery.isFetching || qwQuery.isFetching) && "animate-spin")} />
          Re-check
        </Button>
      )}

      {/* ── Verdict ── */}
      <Card className="qm-grain overflow-hidden p-0 sm:p-0">
        <div className="relative z-[1] grid lg:grid-cols-12">
          <div className="lg:col-span-7 p-5 sm:p-7 space-y-5 min-w-0">
            <div className="flex items-start gap-4">
              <div className={cn("flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl", TONE_SOFT[verdictTone], TONE_INK[verdictTone])}>
                <VerdictIcon className="h-7 w-7" />
              </div>
              <div className="min-w-0">
                <div className="qm-display text-[1.7rem] sm:text-[2.1rem] font-semibold leading-tight text-ink">{headline}</div>
                <p className="mt-1 text-[13px] text-muted qm-tabular">
                  {passed} of {total} readiness checks passing · re-checked every 15 s
                </p>
              </div>
            </div>
            {/* One segment per check */}
            <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${Math.max(1, h?.checks.length ?? total)}, minmax(0, 1fr))` }}>
              {(h?.checks ?? Array.from({ length: total }, () => null)).map((c, i) => (
                <div key={c?.label ?? i} className="min-w-0 space-y-1.5">
                  <div className={cn("h-2.5 rounded-full", c == null ? "bg-line animate-pulse" : c.ok ? "bg-jade" : "bg-crimson")} />
                  {c && <div className={cn("hidden sm:block truncate text-[11.5px] font-semibold", c.ok ? "text-ink-2" : "text-crimson-ink")} title={c.label}>{c.label}</div>}
                </div>
              ))}
            </div>
            {failing.length > 0 && (
              <ul className="space-y-1.5">
                {failing.map((c) => (
                  <li key={c.label} className="flex items-start gap-2 text-[13px]">
                    <CircleX className="mt-0.5 h-4 w-4 shrink-0 text-crimson-ink" />
                    <span>
                      <b className="text-ink">{c.label}</b> <span className="text-ink-2">— {c.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Watchdog at a glance */}
          <div className="lg:col-span-5 border-t lg:border-t-0 lg:border-l border-line bg-sunk/70 p-5 sm:p-7 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div className="qm-eyebrow">LinkWatch watchdog</div>
              <Badge variant={qwEnabled ? "success" : "neutral"} dot>
                {qwEnabled ? "Armed" : "Off"}
              </Badge>
            </div>
            <div className="flex items-center gap-2.5">
              {qwEnabled && rtTone !== "muted" ? <LiveDot tone={rtTone === "jade" ? "jade" : rtTone === "crimson" ? "crimson" : "saffron"} /> : <span className="h-2 w-2 rounded-full bg-line-strong" />}
              <span className={cn("qm-display text-[1.5rem] font-semibold capitalize leading-none", TONE_INK[rtTone === "muted" ? "muted" : rtTone])}>
                {qwQuery.isLoading ? "…" : rt?.status || (qwEnabled ? "Starting" : "Not watching")}
              </span>
            </div>
            {rt?.message && <p className="text-[12.5px] text-ink-2 leading-snug">{rt.message}</p>}
            <div className="grid grid-cols-3 gap-2 qm-tabular">
              <div className="rounded-xl bg-surface border border-line px-3 py-2 min-w-0">
                <div className="text-[11px] text-muted">Latency</div>
                <div className="text-[14px] font-semibold text-ink truncate">{rt?.currentLatency ? `${rt.currentLatency} ms` : "--"}</div>
              </div>
              <div className="rounded-xl bg-surface border border-line px-3 py-2 min-w-0">
                <div className="text-[11px] text-muted">Retries</div>
                <div className="text-[14px] font-semibold text-ink">
                  {rt?.retry ?? 0}
                  <span className="text-muted font-normal">/{qw?.config?.maxRetries ?? "--"}</span>
                </div>
              </div>
              <div className="rounded-xl bg-surface border border-line px-3 py-2 min-w-0">
                <div className="text-[11px] text-muted">Target</div>
                <div className="text-[13px] font-semibold text-ink truncate font-mono">{qw?.config?.pingTarget || "--"}</div>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-12 items-start">
        {/* ── Checks ── */}
        <Card className="lg:col-span-7 min-w-0">
          <CardHeader title="Readiness checks" subtitle="What the gateway verifies before it calls the link healthy" />
          {loading ? (
            <div className="space-y-2">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-14" />
              ))}
            </div>
          ) : (
            <ul className="divide-y divide-line rounded-2xl border border-line overflow-hidden">
              {(h?.checks ?? []).map((c) => (
                <li key={c.label} className="flex items-center gap-3 bg-surface px-4 py-3">
                  <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl", c.ok ? "bg-jade-soft text-jade-ink" : "bg-crimson-soft text-crimson-ink")}>
                    {c.ok ? <CircleCheck className="h-4.5 w-4.5" /> : <CircleX className="h-4.5 w-4.5" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13.5px] font-semibold text-ink">{c.label}</div>
                    <div className="text-[12px] text-muted break-words">{c.detail}</div>
                  </div>
                  <Badge variant={c.ok ? "success" : "danger"}>{c.ok ? "OK" : "Alert"}</Badge>
                </li>
              ))}
              {(h?.checks ?? []).length === 0 && <li className="px-4 py-6 text-center text-[13px] text-muted">No checks reported.</li>}
            </ul>
          )}
        </Card>

        {/* ── Watchdog settings ── */}
        <Card className="lg:col-span-5 min-w-0">
          <CardHeader
            title="Auto-recovery"
            subtitle="If pings keep failing, LinkWatch reconnects the modem for you"
            icon={<ShieldCheck className="h-4 w-4" />}
          />
          <div className="space-y-4">
            <Switch
              label={qwEnabled ? "Watchdog is on" : "Watchdog is off"}
              description="Turning it on or off saves the settings below"
              checked={qwEnabled}
              onChange={saveLinkWatch}
              disabled={busy}
            />
            <div className="grid grid-cols-2 gap-3">
              <label className="col-span-2 block">
                <span className="mb-1 block text-[12px] font-semibold text-ink-2">Ping target</span>
                <Input value={qwTarget} onChange={(e) => setQwTarget(e.target.value)} className="font-mono" placeholder="8.8.8.8" />
              </label>
              <label className="block">
                <span className="mb-1 block text-[12px] font-semibold text-ink-2">Every (seconds)</span>
                <Input type="number" inputMode="numeric" value={qwInterval} onChange={(e) => setQwInterval(e.target.value)} className="qm-tabular" />
              </label>
              <label className="block">
                <span className="mb-1 block text-[12px] font-semibold text-ink-2">Give up after (retries)</span>
                <Input type="number" inputMode="numeric" value={qwMaxRetries} onChange={(e) => setQwMaxRetries(e.target.value)} className="qm-tabular" />
              </label>
            </div>
            <p className="text-[12px] text-muted leading-snug">
              Pings <span className="font-mono text-ink-2">{qwTarget || "8.8.8.8"}</span> every {Number(qwInterval) || 60} s. After{" "}
              {qw?.config?.pingFailures ?? 3} misses in a row it refreshes the connection, up to {Number(qwMaxRetries) || 5} times.
            </p>
            <Button variant="primary" className="w-full" onClick={() => saveLinkWatch(true)} disabled={busy}>
              Save &amp; enable
            </Button>
          </div>
        </Card>
      </div>
    </>
  );
}
