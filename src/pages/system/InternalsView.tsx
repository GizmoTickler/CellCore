import React from "react";
import { CheckCircle2, Gauge, HardDrive, Radio, RefreshCw, TriangleAlert, Usb, Wrench } from "lucide-react";
import { cn, formatBytes } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Meter, Skeleton, Switch } from "../../components/ui";
import type { SystemController } from "./useSystemController";

function loadTone(pct: number): "jade" | "saffron" | "crimson" {
  return pct >= 85 ? "crimson" : pct >= 60 ? "saffron" : "jade";
}

function ago(ts: number | undefined): string | null {
  if (!ts) return null;
  const ms = ts < 1e12 ? ts * 1000 : ts;
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(ms).toLocaleString();
}

export function InternalsView({ ctl }: { ctl: SystemController }) {
  const it = ctl.internals;
  const loading = !it && ctl.internalsQuery.isLoading;

  const ctCount = it?.conntrackCount ?? 0;
  const ctMax = it?.conntrackMax ?? 32768;
  const ctPct = ctMax > 0 ? (ctCount / ctMax) * 100 : 0;

  const flashTotal = it?.usrdataTotalBytes ?? 0;
  const flashUsed = it?.usrdataUsedBytes ?? 0;
  const flashPct = flashTotal > 0 ? (flashUsed / flashTotal) * 100 : 0;

  const aspm = it?.pcieAspm?.includes("[performance]") ? "performance" : it?.pcieAspm || "--";
  const usbBound = Boolean(it?.usbUdc && it.usbUdc !== "none");

  const report = ctl.activeReport;

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <div className="lg:col-span-7 min-w-0 space-y-5">
        <Card>
          <CardHeader
            title="Resources"
            subtitle="Connection tracking and flash, refreshed every 5 s"
            icon={<Gauge className="h-4 w-4" />}
          />
          {loading ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <Skeleton className="h-28" />
              <Skeleton className="h-28" />
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="qm-subcard p-4">
                <div className="text-[12px] font-semibold text-muted">Conntrack table</div>
                <div className="mt-2 flex items-baseline gap-1.5">
                  <span className="qm-display text-[1.9rem] font-semibold leading-none text-ink qm-tabular">
                    {ctCount.toLocaleString()}
                  </span>
                  <span className="text-[12.5px] text-muted qm-tabular">/ {ctMax.toLocaleString()} flows</span>
                </div>
                <Meter pct={ctPct} tone={loadTone(ctPct)} className="mt-3" />
                <div className="mt-2 text-[11.5px] text-muted qm-tabular">
                  {ctPct.toFixed(1)}% used · hash buckets {it?.conntrackHashsize ?? "--"}
                </div>
              </div>
              <div className="qm-subcard p-4">
                <div className="flex items-center gap-1.5 text-[12px] font-semibold text-muted">
                  <HardDrive className="h-3.5 w-3.5" /> /usrdata flash
                </div>
                {flashTotal > 0 ? (
                  <>
                    <div className="mt-2 flex items-baseline gap-1.5">
                      <span className="qm-display text-[1.9rem] font-semibold leading-none text-ink qm-tabular">
                        {formatBytes(flashUsed)}
                      </span>
                      <span className="text-[12.5px] text-muted qm-tabular">/ {formatBytes(flashTotal)}</span>
                    </div>
                    <Meter pct={flashPct} tone={loadTone(flashPct)} className="mt-3" />
                    <div className="mt-2 text-[11.5px] text-muted qm-tabular">
                      {flashPct.toFixed(0)}% used · {formatBytes(it?.usrdataAvailBytes ?? flashTotal - flashUsed)} free
                    </div>
                  </>
                ) : (
                  <div className="mt-2 qm-display text-[1.4rem] font-semibold text-ink">Flash mounted</div>
                )}
              </div>
            </div>
          )}

          <dl className="mt-5 grid gap-x-6 sm:grid-cols-2">
            <Fact label="Routing (mwan3)">
              <Badge variant={it?.mwan3Running ? "success" : "warning"} dot>
                {it?.mwan3Running ? "Active" : "Standby"}
              </Badge>
            </Fact>
            <Fact label="Ethernet PHY" mono>
              {it?.ethSpeed ?? "--"}
            </Fact>
            <Fact label="PCIe ASPM" mono>
              {aspm}
            </Fact>
            <Fact label="Autosleep" mono>
              {it?.autosleep || "--"}
            </Fact>
            <Fact label="A/B boot slot" mono>
              Slot {it?.bootSlot || "_a"}
            </Fact>
            <Fact label="USB controller" mono>
              {it?.usbController || "--"}
            </Fact>
          </dl>
        </Card>

        <Card>
          <CardHeader
            title="Controls"
            subtitle="Hardware toggles that take effect immediately"
            icon={<Radio className="h-4 w-4" />}
          />
          <div className="divide-y divide-line">
            <div className="pb-4">
              <Switch
                label="RRC / 4CA keep-alive"
                description="A 1 Hz probe that keeps the 4-carrier NR5G CA context alive during light background traffic"
                checked={Boolean(it?.keepAliveEnabled)}
                onChange={ctl.toggleKeepAlive}
                disabled={ctl.busy === "ka"}
              />
            </div>
            <div className="pt-4">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-sunk text-ink-2">
                  <Usb className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <Switch
                    label={usbBound ? "USB bench gadget bound" : "USB bench gadget unbound"}
                    description={`ConfigFS g1/UDC · ADB ${it?.usbAdbPresent ? "present (blocked)" : "excluded"}`}
                    checked={usbBound}
                    onChange={ctl.toggleUsbGadget}
                    disabled={ctl.busy === "usb"}
                  />
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <Card className="lg:col-span-5 min-w-0 self-start">
        <CardHeader
          title="Boot & policy reconciler"
          subtitle="Re-applies sysctls, ASPM, autosleep and USB policy"
          icon={<Wrench className="h-4 w-4" />}
          action={
            <Button variant="primary" size="sm" onClick={ctl.triggerReconcile} disabled={ctl.busy === "reconcile"}>
              <RefreshCw className={cn("h-3.5 w-3.5", ctl.busy === "reconcile" && "animate-spin")} />
              {ctl.busy === "reconcile" ? "Running…" : "Run now"}
            </Button>
          }
        />
        {report ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={report.warnings.length > 0 ? "warning" : "success"} dot>
                {report.warnings.length > 0 ? `${report.warnings.length} warnings` : "Clean run"}
              </Badge>
              <span className="text-[12px] text-muted">
                {report.actions.length} actions{ago(report.timestamp) ? ` · ${ago(report.timestamp)}` : ""}
              </span>
            </div>
            {report.warnings.length > 0 && (
              <ul className="space-y-1.5">
                {report.warnings.map((w, i) => (
                  <li key={i} className="flex gap-2 rounded-xl bg-saffron-soft px-3 py-2 text-[12.5px] text-saffron-ink">
                    <TriangleAlert className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                    <span className="min-w-0 break-words">{w}</span>
                  </li>
                ))}
              </ul>
            )}
            {report.actions.length > 0 ? (
              <ul className="qm-subcard divide-y divide-line/70 max-h-[420px] overflow-auto">
                {report.actions.map((a, i) => (
                  <li key={i} className="flex gap-2.5 px-3.5 py-2">
                    <CheckCircle2 className="h-3.5 w-3.5 mt-[3px] shrink-0 text-jade-ink" />
                    <span className="min-w-0 break-words font-mono text-[12px] text-ink-2 leading-relaxed">{a}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[12.5px] text-muted">Nothing needed changing.</p>
            )}
          </div>
        ) : (
          <div className="qm-subcard p-5 text-[13px] text-muted">
            No report yet this boot. Run the reconciler to re-apply policy and see what it changed.
          </div>
        )}
      </Card>
    </div>
  );
}

function Fact({ label, mono, children }: { label: string; mono?: boolean; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line py-2.5 min-w-0">
      <dt className="text-[12.5px] text-muted shrink-0">{label}</dt>
      <dd className={cn("min-w-0 truncate text-right text-[13px] text-ink", mono && "font-mono text-[12.5px]")}>{children}</dd>
    </div>
  );
}
