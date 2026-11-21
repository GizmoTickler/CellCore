import { useState } from "react";
import { Bell, CalendarClock, Eye, EyeOff, Mail, Power } from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, Skeleton, Switch } from "../../components/ui";
import type { SystemController } from "./useSystemController";
import { Field, Verdict } from "./parts";
import { FailoverCard, NotificationsCard } from "./NotificationsView";
import { LoadError } from "../admin/shared";

const WEEK = [
  { id: "monday", short: "Mon" },
  { id: "tuesday", short: "Tue" },
  { id: "wednesday", short: "Wed" },
  { id: "thursday", short: "Thu" },
  { id: "friday", short: "Fri" },
  { id: "saturday", short: "Sat" },
  { id: "sunday", short: "Sun" },
];

export function MaintenanceView({ ctl }: { ctl: SystemController }) {
  const data = ctl.maintQuery.data;
  const loading = ctl.maintQuery.isLoading;
  const enabled = Boolean(data?.scheduledReboot?.enabled);
  const days = ctl.rebDays.map((d) => d.toLowerCase());
  const dayText =
    days.length === 7 ? "every day" : WEEK.filter((d) => days.includes(d.id)).map((d) => d.short).join(", ") || "no days";
  const smtpOk = Boolean(data?.alerts?.smtpConfigured);
  const [showPw, setShowPw] = useState(false);

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      {/* Scheduled reboot */}
      <Card className="lg:col-span-5 min-w-0 self-start">
        <CardHeader
          title="Scheduled reboot"
          subtitle="A weekly restart run by cellcored's wall clock"
          icon={<Power className="h-4 w-4" />}
        />
        {ctl.maintQuery.isError && !data ? (
          <LoadError title="Could not load the reboot schedule" error={ctl.maintQuery.error} onRetry={() => void ctl.maintQuery.refetch()} />
        ) : loading ? (
          <Skeleton className="h-40" />
        ) : (
          <div className="space-y-5">
            <div className="qm-subcard p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="qm-eyebrow">{enabled ? "Next restarts" : "Status"}</div>
                  <div className="mt-1.5 flex items-baseline gap-2">
                    <span
                      className={cn(
                        "qm-display text-[2.4rem] font-semibold leading-none qm-tabular",
                        enabled ? "text-ink" : "text-muted"
                      )}
                    >
                      {enabled ? ctl.rebTime : "Off"}
                    </span>
                  </div>
                  <div className="mt-1.5 text-[12.5px] text-muted">
                    {enabled ? `Runs ${dayText}` : `Would run ${dayText} at ${ctl.rebTime}`}
                  </div>
                </div>
                <Switch
                  checked={enabled}
                  onChange={ctl.saveScheduledReboot}
                  disabled={ctl.busy === "reb"}
                />
              </div>
              <div className="mt-4 grid grid-cols-7 gap-1" aria-label={`Scheduled days: ${dayText}`}>
                {WEEK.map((d) => {
                  const on = days.includes(d.id);
                  return (
                    <div
                      key={d.id}
                      className={cn(
                        "rounded-lg py-1.5 text-center text-[11px] font-semibold",
                        on ? (enabled ? "bg-ember text-on-ember" : "bg-sunk text-ink ring-1 ring-line-strong") : "text-muted"
                      )}
                    >
                      {d.short}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="flex items-end gap-2">
              <Field label="Reboot time" htmlFor="qm-reb-time" className="flex-1">
                <Input
                  id="qm-reb-time"
                  type="time"
                  value={ctl.rebTime}
                  onChange={(e) => ctl.setRebTime(e.target.value)}
                  className="qm-tabular"
                />
              </Field>
              <Button
                variant="secondary"
                className="h-10"
                onClick={() => ctl.saveScheduledReboot(Boolean(data?.scheduledReboot?.enabled))}
                disabled={ctl.busy === "reb"}
              >
                <CalendarClock className="h-4 w-4" />
                Save time
              </Button>
            </div>
            <p className="text-[11.5px] text-muted leading-snug">
              The cellular link drops briefly while the modem restarts. While it carries failover traffic, the reboot waits until the link is quiet.
            </p>
          </div>
        )}
      </Card>

      {/* Email alerts */}
      <Card className="lg:col-span-7 min-w-0">
        <CardHeader
          title="Email account"
          subtitle="The sender and recipient used for email notifications"
          icon={<Bell className="h-4 w-4" />}
          action={
            loading ? undefined : (
              <Badge variant={smtpOk ? "success" : "neutral"} dot>
                {smtpOk ? "Configured" : "Not set up"}
              </Badge>
            )
          }
        />

        <div className="mb-5 flex items-center gap-3 rounded-2xl border border-line px-4 py-3">
          <Mail className="h-4 w-4 shrink-0 text-muted" />
          <div className="min-w-0 text-[13px]">
            {smtpOk ? (
              <Verdict tone="jade">
                <span className="text-ink-2">
                  {data?.alerts?.recipient ? (
                    <>
                      Sending to <span className="font-mono text-ink break-all">{data.alerts.recipient}</span>
                    </>
                  ) : (
                    "Sender account saved. The daemon did not report a recipient."
                  )}
                </span>
              </Verdict>
            ) : (
              <span className="text-muted">Email notifications need a sender account. Add one below.</span>
            )}
          </div>
        </div>

        <form onSubmit={ctl.saveSmtp} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Sender email" htmlFor="qm-smtp-sender" hint="A Gmail account that sends the alerts">
              <Input
                id="qm-smtp-sender"
                inputMode="email"
                autoComplete="off"
                value={ctl.smtpSender}
                onChange={(e) => ctl.setSmtpSender(e.target.value)}
                placeholder="sender@gmail.com"
              />
            </Field>
            <Field label="App password" htmlFor="qm-smtp-pw" hint="Create one under Google Account → Security">
              <div className="relative">
                <Input
                  id="qm-smtp-pw"
                  type={showPw ? "text" : "password"}
                  autoComplete="new-password"
                  value={ctl.smtpPassword}
                  onChange={(e) => ctl.setSmtpPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? "Hide app password" : "Show app password"}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-full p-1.5 text-muted hover:bg-sunk hover:text-ink cursor-pointer"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </Field>
          </div>
          <Field label="Send alerts to" htmlFor="qm-smtp-to">
            <Input
              id="qm-smtp-to"
              inputMode="email"
              value={ctl.smtpRecipient}
              onChange={(e) => ctl.setSmtpRecipient(e.target.value)}
              placeholder="alerts@example.com"
            />
          </Field>
          <div className="flex justify-end pt-1">
            <Button type="submit" variant="primary" disabled={ctl.busy === "smtp-save"}>
              {ctl.busy === "smtp-save" ? "Saving…" : "Save email account"}
            </Button>
          </div>
        </form>
      </Card>

      <NotificationsCard smtpConfigured={smtpOk} />
      <FailoverCard />
    </div>
  );
}
