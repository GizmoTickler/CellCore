import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, BarChart3, CalendarDays, Save, Trash2 } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { useDraft } from "../../lib/draft";
import { cn, formatBytes } from "../../lib/utils";
import { useWsStore } from "../../stores/ws-store";
import { useToastStore } from "../../stores/toast-store";
import type { DataUsageState } from "../../types/cellcore";
import type { UsageCycle } from "../../types/obs";
import { Badge, Button, Card, CardHeader, Input, Meter, Modal, SegmentedTabs, Switch } from "../../components/ui";
import { ApplyNote, BigValue, FieldLabel, splitUnit } from "./shared";

type Range = "14" | "30";

const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

function parseYmd(s: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  return m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])) : null;
}
function ymd(d: Date): string {
  return d.toISOString().slice(0, 10);
}
function monthName(key: string): string {
  const m = /^(\d{4})-(\d{2})$/.exec(key);
  return m ? `${MONTHS[+m[2] - 1]} ${m[1]}` : key;
}
function shortDay(key: string): string {
  const d = parseYmd(key);
  return d ? `${MONTHS[d.getUTCMonth()].slice(0, 3)} ${d.getUTCDate()}` : key;
}

const MIB = 1024 * 1024;

/** Quota meter with the alert thresholds and the projected end-of-cycle mark. */
function CycleMeter({ cycle }: { cycle: UsageCycle }) {
  const used = cycle.usedPct ?? 0;
  const proj = cycle.projectedPct;
  const tone = used >= 95 ? "crimson" : used >= 80 ? "saffron" : "jade";
  return (
    <div className="space-y-1.5">
      <div className="relative">
        <Meter pct={used} tone={tone} />
        {cycle.thresholds.map((t) => (
          <span
            key={t}
            aria-hidden
            className={cn("absolute top-0 h-2.5 w-px", cycle.thresholdsFired.includes(t) ? "bg-ink/60" : "bg-ink/25")}
            style={{ left: `${Math.min(100, t)}%` }}
          />
        ))}
        {proj != null && proj > used && (
          <span
            aria-hidden
            title={`Projected ${proj}%`}
            className="absolute -top-1 h-[18px] w-[3px] -translate-x-1/2 rounded-full bg-ink"
            style={{ left: `${Math.min(100, proj)}%` }}
          />
        )}
      </div>
      <div className="flex justify-between gap-3 text-[12px] text-muted qm-tabular">
        <span>{formatBytes(cycle.totalBytes)} used</span>
        <span>
          {formatBytes(Math.max(0, (cycle.quotaBytes ?? 0) - cycle.totalBytes))} left of {formatBytes(cycle.quotaBytes ?? 0)}
        </span>
      </div>
    </div>
  );
}

export function UsageView({ usage, loading }: { usage: DataUsageState | null; loading: boolean }) {
  const qc = useQueryClient();
  const push = useToastStore((s) => s.push);
  const setDataUsage = useWsStore((s) => s.setDataUsage);
  const [busy, setBusy] = useState<string | null>(null);
  const [range, setRange] = useState<Range>("14");
  const [picked, setPicked] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);

  // Billing-cycle accounting is computed by the daemon (local dates, short months, projection).
  const cycleQuery = useQuery({
    queryKey: ["usage-cycle"],
    queryFn: () => apiFetch<UsageCycle>("/api/v1/network/data-usage/cycle"),
    refetchInterval: 30_000,
  });
  const cycle = cycleQuery.data ?? null;

  // Drafts: the 30 s polls and live WebSocket usage never overwrite a field being edited.
  const [floorMiBInput, setFloorMiBInput, floorD] = useDraft(
    cycle ? String(Math.round(cycle.alerts.standbyFloorBytes / MIB)) : null,
    ""
  );
  const [cycleDayInput, setCycleDayInput, cycleDayD] = useDraft(usage ? String(usage.billingCycleDay || 1) : null, "1");
  const [quotaGiBInput, setQuotaGiBInput, quotaD] = useDraft(
    usage?.quotaBytes && usage.quotaBytes > 0 ? String(Math.round(usage.quotaBytes / (1024 * 1024 * 1024))) : null,
    ""
  );

  const stats = useMemo(() => {
    const daily = usage?.daily ?? [];
    const monthly = usage?.monthly ?? [];
    const latestDay = daily[daily.length - 1];
    const latestMonth = monthly[monthly.length - 1];
    const todayRx = usage?.usageSummary?.todayRx ?? latestDay?.rxBytes ?? 0;
    const todayTx = usage?.usageSummary?.todayTx ?? latestDay?.txBytes ?? 0;
    const monthRx = usage?.usageSummary?.monthRx ?? latestMonth?.rxBytes ?? 0;
    const monthTx = usage?.usageSummary?.monthTx ?? latestMonth?.txBytes ?? 0;
    const monthTotal = monthRx + monthTx;

    // Fixed-width window of days ending at the gateway's "today", gaps rendered as empty slots.
    const byDate = new Map(daily.map((e) => [e.date, e]));
    const end = (latestDay && parseYmd(latestDay.date)) || parseYmd(ymd(new Date()))!;
    const n = Number(range);
    const days = Array.from({ length: n }, (_, i) => {
      const dt = new Date(end.getTime() - (n - 1 - i) * 86400000);
      const key = ymd(dt);
      const e = byDate.get(key);
      return { date: key, dom: dt.getUTCDate(), rx: e?.rxBytes ?? 0, tx: e?.txBytes ?? 0, has: !!e };
    });
    const withData = days.filter((x) => x.has);
    const max = Math.max(1, ...days.map((x) => x.rx + x.tx));
    const avg = withData.length ? withData.reduce((s, x) => s + x.rx + x.tx, 0) / withData.length : 0;

    return {
      todayRx,
      todayTx,
      todayTotal: todayRx + todayTx,
      monthRx,
      monthTx,
      monthTotal,
      monthLabel: latestMonth?.month ?? "Current Month",
      monthly: [...monthly].reverse(),
      days,
      max,
      avg,
    };
  }, [usage, range]);

  const sel = stats.days.find((x) => x.date === picked) ?? [...stats.days].reverse().find((x) => x.has) ?? stats.days[stats.days.length - 1];
  // Hero follows the billing cycle when the daemon reports it; calendar month otherwise.
  const heroTotal = cycle ? cycle.totalBytes : stats.monthTotal;
  const heroRx = cycle ? cycle.rxBytes : stats.monthRx;
  const heroTx = cycle ? cycle.txBytes : stats.monthTx;
  const [heroNum, heroUnit] = splitUnit(formatBytes(heroTotal));
  const rxShare = heroTotal > 0 ? (heroRx / heroTotal) * 100 : 50;
  const usedPct = cycle?.usedPct ?? null;
  const labelEvery = range === "30" ? 5 : 2;
  const cycleDayNum = Number(cycleDayInput) || 1;

  async function saveDataUsagePolicy() {
    setBusy("usage-save");
    try {
      const day = Math.min(31, Math.max(1, Number(cycleDayInput) || 1));
      const gib = quotaGiBInput.trim() ? Number(quotaGiBInput) : 0;
      const quotaBytes = Number.isFinite(gib) && gib > 0 ? Math.round(gib * 1024 * 1024 * 1024) : null;
      const res = await apiFetch<{ dataUsage?: DataUsageState }>("/api/v1/network/data-usage", {
        method: "POST",
        body: JSON.stringify({ billingCycleDay: day, quotaBytes }),
      });
      if (res.dataUsage) setDataUsage(res.dataUsage);
      const mib = floorMiBInput.trim() ? Number(floorMiBInput) : 0;
      await apiFetch("/api/v1/network/data-usage/alerts", {
        method: "POST",
        body: JSON.stringify({ standbyFloorBytes: Number.isFinite(mib) && mib > 0 ? Math.round(mib * MIB) : 0 }),
      });
      await qc.invalidateQueries({ queryKey: ["network-data-usage"] });
      await qc.invalidateQueries({ queryKey: ["usage-cycle"] });
      floorD.reset();
      cycleDayD.reset();
      quotaD.reset();
      push("Billing cycle & quota settings saved", "success");
    } catch (e) {
      push("Couldn't save usage settings", "error", e instanceof Error ? e.message : "Failed saving usage settings");
    } finally {
      setBusy(null);
    }
  }

  async function setThresholdAlerts(on: boolean) {
    setBusy("usage-alerts");
    try {
      await apiFetch("/api/v1/network/data-usage/alerts", { method: "POST", body: JSON.stringify({ thresholdsEnabled: on }) });
      await qc.invalidateQueries({ queryKey: ["usage-cycle"] });
    } catch (e) {
      push("Couldn't change quota alerts", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  async function resetDataUsage() {
    setBusy("usage-reset");
    try {
      const res = await apiFetch<{ dataUsage?: DataUsageState }>("/api/v1/network/data-usage", {
        method: "DELETE",
      });
      if (res.dataUsage) setDataUsage(res.dataUsage);
      await qc.invalidateQueries({ queryKey: ["network-data-usage"] });
      await qc.invalidateQueries({ queryKey: ["usage-cycle"] });
      push("Persistent data usage rollup cleared", "success");
    } catch (e) {
      push("Reset failed", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(null);
      setConfirmReset(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-5 lg:grid-cols-12">
        {/* Hero: this month's total, split into download / upload. */}
        <Card className="lg:col-span-8 min-w-0 relative overflow-hidden qm-grain">
          <div className="relative space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="qm-eyebrow flex items-center gap-2">
                  <CalendarDays className="h-3.5 w-3.5" />
                  {cycle ? `This cycle · ${shortDay(cycle.cycleStart)} – ${shortDay(cycle.cycleEnd)}` : `This month · ${monthName(stats.monthLabel)}`}
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="qm-display qm-sun-text text-[3.4rem] sm:text-[4.4rem] font-semibold leading-none qm-tabular">
                    {loading && !usage ? "––" : heroNum}
                  </span>
                  <span className="qm-display text-[1.4rem] font-semibold text-muted">{heroUnit}</span>
                </div>
                <div className="mt-2 text-[13px] text-ink-2">
                  {cycle
                    ? `Day ${Math.min(cycle.cycleDays, Math.floor(cycle.daysElapsed) + 1)} of ${cycle.cycleDays} · ${cycle.daysRemaining} day${cycle.daysRemaining === 1 ? "" : "s"} left · counted across reboots`
                    : "over cellular, counted across reboots"}
                </div>
              </div>
              {usedPct != null ? (
                <Badge variant={usedPct >= 95 ? "danger" : usedPct >= 80 ? "warning" : "success"}>{usedPct}% of quota</Badge>
              ) : (
                <Badge variant="neutral">No cap</Badge>
              )}
            </div>

            <div className="space-y-2.5">
              <div className="flex h-3 overflow-hidden rounded-full bg-line/80" aria-hidden>
                <div className="h-full bg-jade transition-[width] duration-500" style={{ width: `${rxShare}%` }} />
                <div className="h-full bg-berry flex-1" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-jade-soft text-jade-ink">
                    <ArrowDown className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <div className="text-[11.5px] font-semibold text-muted">Downloaded</div>
                    <div className="qm-display text-[1.15rem] font-semibold text-jade-ink qm-tabular truncate">{formatBytes(heroRx)}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-berry-soft text-berry-ink">
                    <ArrowUp className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <div className="text-[11.5px] font-semibold text-muted">Uploaded</div>
                    <div className="qm-display text-[1.15rem] font-semibold text-berry-ink qm-tabular truncate">{formatBytes(heroTx)}</div>
                  </div>
                </div>
              </div>
            </div>

            {cycle?.quotaBytes ? <CycleMeter cycle={cycle} /> : null}
          </div>
        </Card>

        {/* Today + pace */}
        <div className="lg:col-span-4 min-w-0 grid gap-5 sm:grid-cols-2 lg:grid-cols-1">
          <Card className="min-w-0">
            <div className="text-[12px] font-semibold text-muted">Today</div>
            <BytesValue bytes={stats.todayTotal} className="mt-2 text-[2.2rem]" />
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[12px] qm-tabular">
              <span className="text-jade-ink">↓ {formatBytes(stats.todayRx)}</span>
              <span className="text-berry-ink">↑ {formatBytes(stats.todayTx)}</span>
            </div>
          </Card>
          <Card className="min-w-0">
            {cycle ? (
              <>
                <div className="text-[12px] font-semibold text-muted">Projected by {shortDay(cycle.cycleEnd)}</div>
                <BytesValue bytes={cycle.projectedBytes} className="mt-2 text-[2.2rem]" />
                <div
                  className={cn(
                    "mt-2 text-[12px] qm-tabular",
                    cycle.projectedPct == null ? "text-muted" : cycle.projectedPct >= 100 ? "text-crimson-ink" : cycle.projectedPct >= 80 ? "text-saffron-ink" : "text-muted"
                  )}
                >
                  {cycle.projectedPct != null ? `${cycle.projectedPct}% of your cap at this pace` : "At this cycle's pace so far"}
                </div>
                <div className="mt-3 space-y-1 border-t border-line pt-3 text-[12px] qm-tabular">
                  {cycle.previousCycle && (
                    <div className="flex justify-between gap-2">
                      <span className="text-muted">Previous cycle</span>
                      <span className="font-semibold text-ink">{formatBytes(cycle.previousCycle.totalBytes)}</span>
                    </div>
                  )}
                  <div className="flex justify-between gap-2">
                    <span className="text-muted">Lifetime</span>
                    <span className="font-semibold text-ink">{formatBytes(cycle.lifetime.rxBytes + cycle.lifetime.txBytes)}</span>
                  </div>
                </div>
              </>
            ) : (
              <>
                <div className="text-[12px] font-semibold text-muted">Daily average · last {range} days</div>
                <BytesValue bytes={stats.avg} className="mt-2 text-[2.2rem]" />
                <div className="mt-2 text-[12px] text-muted">Days with traffic only</div>
              </>
            )}
          </Card>
        </div>
      </div>

      {/* Daily chart */}
      <Card className="space-y-4">
        <CardHeader
          title="Day by day"
          subtitle="Tap a bar for that day's split"
          icon={<BarChart3 className="h-4 w-4" />}
          action={
            <SegmentedTabs<Range>
              options={[
                { id: "14", label: "14 days" },
                { id: "30", label: "30 days" },
              ]}
              value={range}
              onChange={setRange}
            />
          }
         
        />

        <div className="flex flex-wrap items-center justify-between gap-3 qm-subcard px-4 py-3">
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-muted">{sel ? shortDay(sel.date) : "--"}</div>
            <div className="qm-display text-[1.4rem] font-semibold text-ink qm-tabular">{sel?.has ? formatBytes(sel.rx + sel.tx) : "No data"}</div>
          </div>
          {sel?.has && (
            <div className="flex gap-4 text-[12.5px] qm-tabular">
              <span className="inline-flex items-center gap-1.5 text-jade-ink">
                <span className="h-2.5 w-2.5 rounded-[3px] bg-jade" /> ↓ {formatBytes(sel.rx)}
              </span>
              <span className="inline-flex items-center gap-1.5 text-berry-ink">
                <span className="h-2.5 w-2.5 rounded-[3px] bg-berry" /> ↑ {formatBytes(sel.tx)}
              </span>
            </div>
          )}
        </div>

        {stats.days.some((x) => x.has) ? (
          <div className="flex gap-2 sm:gap-3">
            {/* y-axis */}
            <div className="relative h-52 w-12 shrink-0 text-right text-[10.5px] text-muted qm-tabular">
              {[1, 0.5, 0].map((f) => (
                <span key={f} className="absolute right-0 -translate-y-1/2" style={{ top: `${(1 - f) * 100}%` }}>
                  {f === 0 ? "0" : formatBytes(stats.max * f, f === 1 ? 1 : 0)}
                </span>
              ))}
            </div>
            <div className="min-w-0 flex-1">
              <div className="relative h-52">
                {[0, 50, 100].map((t) => (
                  <div key={t} className="absolute inset-x-0 border-t border-dashed border-line" style={{ top: `${t}%` }} />
                ))}
                <div className="absolute inset-0 flex items-end gap-[3px] sm:gap-1.5">
                  {stats.days.map((x) => {
                    const total = x.rx + x.tx;
                    const h = total > 0 ? Math.max(2, (total / stats.max) * 100) : 0;
                    const active = sel?.date === x.date;
                    return (
                      <button
                        key={x.date}
                        type="button"
                        onClick={() => setPicked(x.date)}
                        title={`${shortDay(x.date)}: ${x.has ? formatBytes(total) : "no data"}`}
                        aria-label={`${shortDay(x.date)}: ${x.has ? formatBytes(total) : "no data"}`}
                        aria-pressed={active}
                        className="group relative flex h-full min-w-0 flex-1 cursor-pointer flex-col justify-end"
                      >
                        {x.has && total > 0 ? (
                          <div
                            className={cn(
                              "flex w-full flex-col overflow-hidden rounded-t-md transition-opacity",
                              active ? "opacity-100" : "opacity-75 group-hover:opacity-100"
                            )}
                            style={{ height: `${h}%` }}
                          >
                            <div className="w-full bg-berry" style={{ height: `${(x.tx / total) * 100}%`, minHeight: x.tx > 0 ? 2 : 0 }} />
                            <div className="w-full flex-1 bg-jade" />
                          </div>
                        ) : (
                          <div className="mx-auto mb-0 h-1 w-1 rounded-full bg-line-strong" />
                        )}
                        {active && <span className="absolute -bottom-2 left-1/2 h-1 w-1 -translate-x-1/2 rounded-full bg-ink" />}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="mt-3 flex gap-[3px] sm:gap-1.5 text-[10.5px] text-muted qm-tabular">
                {stats.days.map((x, i) => (
                  <span key={x.date} className="min-w-0 flex-1 text-center">
                    {(stats.days.length - 1 - i) % labelEvery === 0 ? x.dom : ""}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="qm-subcard flex h-40 items-center justify-center p-4 text-center text-[13px] text-muted">
            Collecting initial daily cellular transfer counters…
          </div>
        )}

        <div className="flex flex-wrap gap-4 text-[12px] text-muted">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-[3px] bg-jade" /> Download
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-[3px] bg-berry" /> Upload
          </span>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Monthly history */}
        <Card className="lg:col-span-7 min-w-0">
          <CardHeader title="Month by month" subtitle="Calendar months (not billing cycles), kept for up to two years" icon={<CalendarDays className="h-4 w-4" />} />
          {stats.monthly.length > 0 ? (
            <div className="overflow-x-auto rounded-2xl border border-line">
              <table className="w-full min-w-[420px] whitespace-nowrap text-[13px]">
                <thead className="bg-sunk text-[11.5px] text-muted">
                  <tr>
                    <th className="px-4 py-2.5 text-left font-semibold">Month</th>
                    <th className="px-4 py-2.5 text-right font-semibold">Download</th>
                    <th className="px-4 py-2.5 text-right font-semibold">Upload</th>
                    <th className="px-4 py-2.5 text-right font-semibold">Total</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {stats.monthly.map((m) => (
                    <tr key={m.month} className="bg-surface">
                      <td className="px-4 py-2.5 font-semibold text-ink">{monthName(m.month)}</td>
                      <td className="px-4 py-2.5 text-right qm-tabular text-jade-ink">{formatBytes(m.rxBytes)}</td>
                      <td className="px-4 py-2.5 text-right qm-tabular text-berry-ink">{formatBytes(m.txBytes)}</td>
                      <td className="px-4 py-2.5 text-right qm-tabular font-semibold text-ink">{formatBytes(m.rxBytes + m.txBytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="qm-subcard p-4 text-[13px] text-muted">No months recorded yet.</div>
          )}
        </Card>

        {/* Plan settings */}
        <Card className="lg:col-span-5 min-w-0 space-y-4">
          <CardHeader title="Your plan" subtitle="Used for the quota meter, cycle totals and usage alerts" icon={<Save className="h-4 w-4" />} />
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel htmlFor="cycle-day" term="1–31">Renews on day</FieldLabel>
              <Input id="cycle-day" type="number" min={1} max={31} value={cycleDayInput} onChange={(e) => setCycleDayInput(e.target.value)} className="qm-tabular" />
            </div>
            <div>
              <FieldLabel htmlFor="quota" term="GiB">Cap per cycle</FieldLabel>
              <Input id="quota" type="number" min={0} value={quotaGiBInput} onChange={(e) => setQuotaGiBInput(e.target.value)} placeholder="0 = no cap" className="qm-tabular" />
            </div>
          </div>
          {cycleDayNum >= 29 && (
            <p className="text-[12px] text-muted">In shorter months the cycle renews on the last day of the month.</p>
          )}
          <div>
            <FieldLabel htmlFor="standby-floor" term="MiB / day">Standby leak alert above</FieldLabel>
            <Input
              id="standby-floor"
              type="number"
              min={0}
              value={floorMiBInput}
              onChange={(e) => setFloorMiBInput(e.target.value)}
              placeholder="0 = off"
              className="qm-tabular"
            />
            <p className="mt-1.5 text-[12px] text-muted qm-tabular">
              A backup link should be near idle. Today outside failover: {formatBytes(cycle?.standby.todayBytes ?? 0, 1)}
              {cycle?.standby.alertedToday ? " (alert raised)" : ""}.
            </p>
          </div>
          <Switch
            checked={cycle?.alerts.thresholdsEnabled ?? true}
            onChange={(v) => void setThresholdAlerts(v)}
            disabled={!cycle || busy === "usage-alerts"}
            label="Quota alerts"
            description="Raise an event at 50, 80, 95 and 100% of the cap, once per cycle"
          />
          <Button variant="primary" onClick={saveDataUsagePolicy} disabled={busy === "usage-save"}>
            Save plan
          </Button>
          <ApplyNote
            effect="Only changes how usage is measured against your plan; traffic isn't limited."
            persist="Saved with the usage log in /etc/cellcore/data_usage.json; survives reboots."
          />
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-crimson/25 bg-crimson-soft px-4 py-3">
            <div className="min-w-0 text-[12.5px]">
              <div className="font-semibold text-crimson-ink">Clear usage history</div>
              <div className="text-ink-2">Deletes every daily and monthly total.</div>
            </div>
            <Button variant="danger" size="sm" onClick={() => setConfirmReset(true)} disabled={busy === "usage-reset"}>
              <Trash2 className="h-3.5 w-3.5" />
              Reset Rollup
            </Button>
          </div>
        </Card>
      </div>

      <Modal open={confirmReset} onClose={() => setConfirmReset(false)} title="Clear all usage history?">
        <p>
          This permanently deletes every daily and monthly total stored on the gateway. Counting starts again from zero; your plan
          settings are kept. It can't be undone.
        </p>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirmReset(false)}>
            Keep history
          </Button>
          <Button variant="danger" onClick={resetDataUsage} disabled={busy === "usage-reset"}>
            <Trash2 className="h-3.5 w-3.5" />
            Clear history
          </Button>
        </div>
      </Modal>
    </div>
  );
}

function BytesValue({ bytes, className }: { bytes: number; className?: string }) {
  const [v, u] = splitUnit(formatBytes(bytes));
  return <BigValue value={v} unit={u} className={className} />;
}
