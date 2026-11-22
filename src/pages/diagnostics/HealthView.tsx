import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Check,
  ChevronDown,
  CircleCheck,
  CircleX,
  Gauge,
  LifeBuoy,
  RefreshCw,
  ShieldCheck,
  Sliders,
} from "lucide-react";
import { apiFetch } from "../../lib/api";
import { resetAll, useDraft } from "../../lib/draft";
import { cn } from "../../lib/utils";
import { useObsStore } from "../../stores/obs-store";
import { useToastStore } from "../../stores/toast-store";
import { Badge, Button, Card, CardHeader, Input, LiveDot, Select, Skeleton, Switch } from "../../components/ui";
import { EventRow } from "../../components/obs";
import { LoadError } from "../admin/shared";
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
    preferredSimSlot?: number;
    simFailbackMins?: number;
    highLatencyMonitoring: boolean;
    latencyCeiling: number;
  };
  runtime: { status: string; message: string; retry: number; currentLatency: number };
}

const RECOVERY_EVENT_TYPES = new Set([
  "quecwatch_recovery",
  "cell_lock_bypassed",
  "modem_ssr",
  "r10_action",
]);

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
  const [busy, setBusy] = useState<string | null>(null);
  const recentEvents = useObsStore((s) => s.recent);

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
  const [qwFailures, setQwFailures, failuresD] = useDraft(qwCfg ? String(qwCfg.pingFailures ?? 3) : null, "3");
  const [qwMaxRetries, setQwMaxRetries, retriesD] = useDraft(qwCfg ? String(qwCfg.maxRetries ?? 5) : null, "5");
  const [qwConnRefresh, setQwConnRefresh, connRefreshD] = useDraft(qwCfg ? Boolean(qwCfg.connectionRefresh) : null, true);
  const [qwAutoSim, setQwAutoSim, autoSimD] = useDraft(qwCfg ? Boolean(qwCfg.autoSimFailover) : null, false);
  const [qwPrefSim, setQwPrefSim, prefSimD] = useDraft(
    qwCfg?.preferredSimSlot != null ? String(qwCfg.preferredSimSlot) : null,
    "0"
  );
  const [qwFailbackMins, setQwFailbackMins, failbackD] = useDraft(
    qwCfg?.simFailbackMins != null ? String(qwCfg.simFailbackMins) : null,
    "30"
  );
  const [qwHighLat, setQwHighLat, highLatD] = useDraft(
    qwCfg ? Boolean(qwCfg.highLatencyMonitoring) : null,
    false
  );
  const [qwLatCeiling, setQwLatCeiling, latCeilingD] = useDraft(
    qwCfg ? String(qwCfg.latencyCeiling ?? 150) : null,
    "150"
  );

  const allDrafts = [
    targetD,
    intervalD,
    failuresD,
    retriesD,
    connRefreshD,
    autoSimD,
    prefSimD,
    failbackD,
    highLatD,
    latCeilingD,
  ];

  const settingsDirty =
    qwCfg != null &&
    ((qwTarget.trim() || "8.8.8.8") !== (qwCfg.pingTarget || "8.8.8.8") ||
      (Number(qwInterval) || 60) !== (qwCfg.pingInterval ?? 60) ||
      (Number(qwFailures) || 3) !== (qwCfg.pingFailures ?? 3) ||
      (Number(qwMaxRetries) || 5) !== (qwCfg.maxRetries ?? 5) ||
      qwConnRefresh !== Boolean(qwCfg.connectionRefresh) ||
      qwAutoSim !== Boolean(qwCfg.autoSimFailover) ||
      Number(qwPrefSim) !== (qwCfg.preferredSimSlot ?? 0) ||
      (Number(qwFailbackMins) || 30) !== (qwCfg.simFailbackMins ?? 30) ||
      qwHighLat !== Boolean(qwCfg.highLatencyMonitoring) ||
      (Number(qwLatCeiling) || 150) !== (qwCfg.latencyCeiling ?? 150));

  async function saveLinkWatch(enabled: boolean, reason: "toggle" | "save") {
    setBusy(reason);
    try {
      await apiFetch("/api/v1/diagnostics/quecwatch", {
        method: "POST",
        body: JSON.stringify({
          enabled,
          pingTarget: qwTarget.trim() || "8.8.8.8",
          pingInterval: Math.max(15, Math.min(3600, Number(qwInterval) || 60)),
          pingFailures: Math.max(1, Math.min(20, Number(qwFailures) || 3)),
          maxRetries: Math.max(1, Math.min(20, Number(qwMaxRetries) || 5)),
          connectionRefresh: qwConnRefresh,
          autoSimFailover: qwAutoSim,
          preferredSimSlot: Math.max(0, Math.min(2, Number(qwPrefSim) || 0)),
          simFailbackMins: Math.max(1, Math.min(1440, Number(qwFailbackMins) || 30)),
          highLatencyMonitoring: qwHighLat,
          latencyCeiling: Math.max(20, Math.min(2000, Number(qwLatCeiling) || 150)),
        }),
      });
      await qc.invalidateQueries({ queryKey: ["diag-quecwatch"] });
      resetAll(...allDrafts);
      push(
        reason === "toggle"
          ? `LinkWatch ${enabled ? "enabled" : "disabled"}`
          : "LinkWatch settings saved",
        "success"
      );
    } catch (e) {
      push("LinkWatch update failed", "error", errMsg(e, "LinkWatch error"));
    } finally {
      setBusy(null);
    }
  }

  const recoveryEvents = useMemo(
    () => recentEvents.filter((e) => RECOVERY_EVENT_TYPES.has(e.type)).slice(0, 12),
    [recentEvents]
  );

  const h = healthQuery.data;
  const passed = h?.passed ?? 0;
  const total = h?.total ?? 4;
  const failing = (h?.checks ?? []).filter((c) => !c.ok);
  const loading = healthQuery.isLoading;
  const healthFailed = healthQuery.isError && !h;
  const verdictTone: Tone =
    loading || healthFailed
      ? "muted"
      : failing.length === 0 && passed === total
        ? "jade"
        : passed === 0
          ? "crimson"
          : "saffron";
  const headline = loading
    ? "Checking the link…"
    : healthFailed
      ? "Health checks unavailable"
      : verdictTone === "jade"
        ? "Everything looks healthy"
        : `${total - passed} check${total - passed === 1 ? "" : "s"} need${total - passed === 1 ? "s" : ""} attention`;

  const qw = qwQuery.data;
  const qwEnabled = Boolean(qw?.enabled);
  const rt = qw?.runtime;
  const rtTone = runtimeTone(rt?.status, qwEnabled);
  const VerdictIcon = verdictTone === "jade" || verdictTone === "muted" ? CircleCheck : CircleX;

  const activeStage = !qwEnabled
    ? -1
    : (rt?.retry ?? 0) === 0
      ? 0
      : Math.min(4, rt?.retry ?? 0);

  const ladderStages = [
    {
      stage: 0,
      title: "ICMP Probe",
      detail: `Every ${qwInterval || 60}s to ${qwTarget || "8.8.8.8"} · trips after ${qwFailures || 3} misses${qwHighLat ? ` or >${qwLatCeiling || 150} ms` : ""}`,
      enabled: qwEnabled,
    },
    {
      stage: 1,
      title: "Soft Bearer Reconnect",
      detail: "Native WDS bearer reconnect or ubus WAN up without resetting the RF stack",
      enabled: qwEnabled && qwConnRefresh,
    },
    {
      stage: 2,
      title: "Modem Radio Cycle",
      detail: "Verified AT+CFUN=0 → AT+CFUN=1 radio re-registration",
      enabled: qwEnabled && qwConnRefresh,
    },
    {
      stage: 3,
      title: "Cell-Lock Dead-Man Bypass",
      detail: "Temporarily lifts active PCI/ARFCN locks if pinned to a dead sector",
      enabled: qwEnabled && qwConnRefresh,
    },
    {
      stage: 4,
      title: "Dual-SIM Failover",
      detail: qwAutoSim
        ? `Switches USIM slot${Number(qwPrefSim) > 0 ? ` · auto-failback to SIM ${qwPrefSim} after ${qwFailbackMins || 30}m` : ""}`
        : "Disabled — falls back to verified CFUN radio cycle",
      enabled: qwEnabled && qwAutoSim,
    },
  ];

  return (
    <>
      {header(
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            void healthQuery.refetch();
            void qwQuery.refetch();
          }}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", (healthQuery.isFetching || qwQuery.isFetching) && "animate-spin")} />
          Re-check
        </Button>
      )}

      {/* ── Verdict ── */}
      <Card className="qm-grain overflow-hidden p-0 sm:p-0">
        <div className="relative z-[1] grid lg:grid-cols-12">
          <div className="lg:col-span-7 p-5 sm:p-7 space-y-5 min-w-0">
            {healthFailed ? (
              <LoadError
                title="Could not load readiness checks"
                error={healthQuery.error}
                onRetry={() => void healthQuery.refetch()}
              />
            ) : (
              <>
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
                      {c && (
                        <div
                          className={cn("hidden sm:block truncate text-[11.5px] font-semibold", c.ok ? "text-ink-2" : "text-crimson-ink")}
                          title={c.label}
                        >
                          {c.label}
                        </div>
                      )}
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
              </>
            )}
          </div>

          {/* Watchdog at a glance */}
          <div className="lg:col-span-5 border-t lg:border-t-0 lg:border-l border-line bg-sunk/70 p-5 sm:p-7 space-y-4">
            {qwQuery.isError && !qw ? (
              <LoadError
                title="Could not load LinkWatch status"
                error={qwQuery.error}
                onRetry={() => void qwQuery.refetch()}
              />
            ) : (
              <>
                <div className="flex items-center justify-between gap-2">
                  <div className="qm-eyebrow">LinkWatch watchdog</div>
                  <Badge variant={qwEnabled ? "success" : "neutral"} dot>
                    {qwEnabled ? "Armed" : "Off"}
                  </Badge>
                </div>
                <div className="flex items-center gap-2.5">
                  {qwEnabled && rtTone !== "muted" ? (
                    <LiveDot tone={rtTone === "jade" ? "jade" : rtTone === "crimson" ? "crimson" : "saffron"} />
                  ) : (
                    <span className="h-2 w-2 rounded-full bg-line-strong" />
                  )}
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
              </>
            )}
          </div>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-12 items-start">
        {/* ── Left Column: Readiness checks + Escalation ladder + Recovery timeline ── */}
        <div className="lg:col-span-7 min-w-0 space-y-5">
          <Card className="min-w-0">
            <CardHeader title="Readiness checks" subtitle="What the gateway verifies before it calls the link healthy" />
            {healthFailed ? (
              <LoadError
                title="Readiness checks failed to load"
                error={healthQuery.error}
                onRetry={() => void healthQuery.refetch()}
              />
            ) : loading ? (
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

          {/* Visual 5-Stage Self-Healing Escalation Ladder */}
          <Card className="min-w-0">
            <CardHeader
              title="5-Stage Escalation Ladder"
              subtitle="Progressive self-healing steps from soft bearer refresh up to Dual-SIM failover"
              icon={<Activity className="h-4 w-4" />}
              action={
                <Badge variant={activeStage === 0 ? "success" : activeStage > 0 ? "warning" : "neutral"} dot>
                  {activeStage < 0 ? "Standby (Off)" : activeStage === 0 ? "Stage 0 · Monitoring" : `Stage ${activeStage} Active`}
                </Badge>
              }
            />
            <ol className="space-y-2">
              {ladderStages.map((s) => {
                const isCurrent = activeStage === s.stage;
                const isPassed = activeStage > s.stage && s.enabled;
                return (
                  <li
                    key={s.stage}
                    className={cn(
                      "flex items-start gap-3 rounded-2xl border px-3.5 py-2.5 transition-colors",
                      isCurrent
                        ? s.stage === 0
                          ? "border-jade/50 bg-jade-soft"
                          : "border-saffron/55 bg-saffron-soft"
                        : isPassed
                          ? "border-line-strong bg-raised"
                          : "border-line bg-sunk/60",
                      !s.enabled && "opacity-55"
                    )}
                  >
                    <span
                      className={cn(
                        "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11.5px] font-bold qm-tabular",
                        isCurrent
                          ? s.stage === 0
                            ? "bg-jade text-on-jade"
                            : "bg-saffron text-black"
                          : "bg-surface border border-line text-ink-2"
                      )}
                    >
                      {s.stage}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-[13px] font-semibold text-ink">{s.title}</span>
                        <Badge variant={isCurrent ? (s.stage === 0 ? "success" : "warning") : s.enabled ? "neutral" : "neutral"}>
                          {isCurrent ? "Active" : s.enabled ? "Armed" : "Skipped"}
                        </Badge>
                      </div>
                      <p className="mt-0.5 text-[12px] text-ink-2 leading-snug">{s.detail}</p>
                    </div>
                  </li>
                );
              })}
            </ol>
          </Card>

          {/* Live Recent Recovery Timeline */}
          <Card className="min-w-0">
            <CardHeader
              title="Recent Self-Healing Timeline"
              subtitle="Live recoveries, dead-man cell-lock bypasses, modem SSRs & router IPC actions"
              icon={<LifeBuoy className="h-4 w-4" />}
              action={<Badge variant="neutral">{recoveryEvents.length} recent</Badge>}
            />
            {recoveryEvents.length > 0 ? (
              <div>
                {recoveryEvents.map((e) => (
                  <EventRow key={e.id} event={e} />
                ))}
              </div>
            ) : (
              <div className="rounded-2xl bg-sunk px-4 py-6 text-center text-[13px] text-muted">
                No self-healing recovery actions recorded recently.
              </div>
            )}
          </Card>
        </div>

        {/* ── Right Column: Self-Healing Control Center ── */}
        <Card className="lg:col-span-5 min-w-0">
          <CardHeader
            title="Auto-recovery Control Center"
            subtitle="Configure probe cadence, 5-stage escalation, Dual-SIM failback and latency ceiling"
            icon={<ShieldCheck className="h-4 w-4" />}
            action={settingsDirty ? <Badge variant="warning">Unsaved changes</Badge> : undefined}
          />
          {qwQuery.isError && !qw ? (
            <LoadError
              title="Could not load LinkWatch configuration"
              error={qwQuery.error}
              onRetry={() => void qwQuery.refetch()}
            />
          ) : (
            <div className="space-y-4">
              <div className="qm-subcard p-3.5">
                <Switch
                  label={qwEnabled ? "Watchdog is armed" : "Watchdog is off"}
                  description="Toggles monitoring immediately without losing edited fields below"
                  checked={qwEnabled}
                  onChange={(next) => void saveLinkWatch(next, "toggle")}
                  disabled={busy != null || !qw}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <label className="col-span-2 block">
                  <span className="mb-1 block text-[12px] font-semibold text-ink-2">Ping target</span>
                  <Input
                    value={qwTarget}
                    onChange={(e) => setQwTarget(e.target.value)}
                    className="font-mono"
                    placeholder="8.8.8.8"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[12px] font-semibold text-ink-2">Probe interval (s)</span>
                  <Input
                    type="number"
                    min={15}
                    max={3600}
                    inputMode="numeric"
                    value={qwInterval}
                    onChange={(e) => setQwInterval(e.target.value)}
                    className="qm-tabular"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[12px] font-semibold text-ink-2">Max retries</span>
                  <Input
                    type="number"
                    min={1}
                    max={20}
                    inputMode="numeric"
                    value={qwMaxRetries}
                    onChange={(e) => setQwMaxRetries(e.target.value)}
                    className="qm-tabular"
                  />
                </label>
              </div>

              {/* Collapsible Section 1: Escalation & Dual-SIM Failover */}
              <details className="qm-subcard p-3.5 group" open>
                <summary className="flex cursor-pointer list-none items-center justify-between gap-2 text-[12.5px] font-semibold text-ink select-none">
                  <span className="flex items-center gap-2">
                    <Sliders className="h-3.5 w-3.5 text-ember-ink" />
                    Escalation &amp; Dual-SIM Failover
                  </span>
                  <ChevronDown className="h-4 w-4 text-muted transition-transform group-open:rotate-180" />
                </summary>
                <div className="mt-3.5 space-y-3.5 border-t border-line pt-3.5">
                  <label className="block">
                    <span className="mb-1 block text-[12px] font-semibold text-ink-2">Consecutive misses before recovery</span>
                    <Input
                      type="number"
                      min={1}
                      max={20}
                      inputMode="numeric"
                      value={qwFailures}
                      onChange={(e) => setQwFailures(e.target.value)}
                      className="qm-tabular"
                    />
                  </label>
                  <Switch
                    label="Connection & radio refresh"
                    description="Allow Stages 1–3 (WDS reconnect, CFUN cycle, cell-lock bypass)"
                    checked={qwConnRefresh}
                    onChange={setQwConnRefresh}
                  />
                  <Switch
                    label="Auto Dual-SIM failover"
                    description="Switch to the secondary USIM slot if radio recovery fails (Stage 4)"
                    checked={qwAutoSim}
                    onChange={setQwAutoSim}
                  />
                  <div className={cn("grid grid-cols-2 gap-3", !qwAutoSim && "opacity-55")}>
                    <label className="block">
                      <span className="mb-1 block text-[12px] font-semibold text-ink-2">Preferred SIM slot</span>
                      <Select
                        value={qwPrefSim}
                        onChange={(e) => setQwPrefSim(e.target.value)}
                        disabled={!qwAutoSim}
                      >
                        <option value="0">None (stay active)</option>
                        <option value="1">SIM Slot 1</option>
                        <option value="2">SIM Slot 2</option>
                      </Select>
                    </label>
                    <label className="block">
                      <span className="mb-1 block text-[12px] font-semibold text-ink-2">Failback (mins)</span>
                      <Input
                        type="number"
                        min={1}
                        max={1440}
                        inputMode="numeric"
                        value={qwFailbackMins}
                        onChange={(e) => setQwFailbackMins(e.target.value)}
                        disabled={!qwAutoSim || qwPrefSim === "0"}
                        className="qm-tabular"
                      />
                    </label>
                  </div>
                </div>
              </details>

              {/* Collapsible Section 2: High-Latency Trigger */}
              <details className="qm-subcard p-3.5 group" open={qwHighLat}>
                <summary className="flex cursor-pointer list-none items-center justify-between gap-2 text-[12.5px] font-semibold text-ink select-none">
                  <span className="flex items-center gap-2">
                    <Gauge className="h-3.5 w-3.5 text-ember-ink" />
                    High-Latency Trigger
                  </span>
                  <div className="flex items-center gap-2">
                    <Badge variant={qwHighLat ? "warning" : "neutral"}>
                      {qwHighLat ? `>${qwLatCeiling || 150} ms` : "Off"}
                    </Badge>
                    <ChevronDown className="h-4 w-4 text-muted transition-transform group-open:rotate-180" />
                  </div>
                </summary>
                <div className="mt-3.5 space-y-3.5 border-t border-line pt-3.5">
                  <Switch
                    label="Trigger on high latency"
                    description="Treat pings above the ceiling as degraded probes"
                    checked={qwHighLat}
                    onChange={setQwHighLat}
                  />
                  <label className={cn("block", !qwHighLat && "opacity-55")}>
                    <span className="mb-1 block text-[12px] font-semibold text-ink-2">Latency ceiling (ms)</span>
                    <Input
                      type="number"
                      min={20}
                      max={2000}
                      inputMode="numeric"
                      value={qwLatCeiling}
                      onChange={(e) => setQwLatCeiling(e.target.value)}
                      disabled={!qwHighLat}
                      className="qm-tabular"
                    />
                  </label>
                </div>
              </details>

              <p className="text-[12px] text-muted leading-snug">
                Pings <span className="font-mono text-ink-2">{qwTarget || "8.8.8.8"}</span> every {Number(qwInterval) || 60} s. After{" "}
                {Number(qwFailures) || 3} misses in a row it escalates through up to {Number(qwMaxRetries) || 5} recovery attempts.
              </p>

              <div className="flex items-center gap-2">
                {settingsDirty && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => resetAll(...allDrafts)}
                    disabled={busy != null}
                  >
                    Discard
                  </Button>
                )}
                <Button
                  variant="primary"
                  className="flex-1"
                  onClick={() => void saveLinkWatch(qwEnabled, "save")}
                  disabled={busy != null || !settingsDirty}
                >
                  <Check className="h-4 w-4" />
                  {busy === "save" ? "Saving…" : "Save changes"}
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
