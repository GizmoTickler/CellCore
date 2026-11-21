import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Clock, Server } from "lucide-react";
import { formatDuration } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, Select, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { Field, Verdict } from "../system/parts";
import { LoadError, Notice, TextArea, adminSend, errText, useAdmin } from "./shared";

interface SystemResp {
  hostname: string;
  zonename: string;
  timezone: string;
  ntp: { present: boolean; enabled: boolean; server: boolean; servers: string[] };
  time: { epoch: number; local: string; uptime: number; ntpdRunning: boolean; ntpdExitCode: number | null; stratumSeen: boolean };
}

export function SystemTimeView() {
  const q = useAdmin<SystemResp>("/system", { refetchInterval: 15000 });
  const zones = useAdmin<{ zones: string[] }>("/system/timezones", { staleTime: Infinity });
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const [hostname, setHostname] = useState("");
  const [zone, setZone] = useState("");
  const [ntpOn, setNtpOn] = useState(true);
  const [ntpServe, setNtpServe] = useState(false);
  const [servers, setServers] = useState("");
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (q.data && !dirty) {
      setHostname(q.data.hostname);
      setZone(q.data.zonename);
      setNtpOn(q.data.ntp.enabled);
      setNtpServe(q.data.ntp.server);
      setServers(q.data.ntp.servers.join("\n"));
    }
  }, [q.data, dirty]);

  if (q.isLoading) return <Skeleton className="h-80" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const touch = <T,>(f: (v: T) => void) => (v: T) => {
    setDirty(true);
    f(v);
  };

  async function save() {
    setSaving(true);
    try {
      await adminSend("POST", "/system", {
        hostname: hostname.trim(),
        zonename: zone,
        ntpEnabled: ntpOn,
        ntpServer: ntpServe,
        ntpServers: servers.split(/[\s,]+/).filter(Boolean),
      });
      toast("System settings saved", "success", "Hostname and timezone apply now; NTP restarts if it changed.");
      setDirty(false);
      await qc.invalidateQueries({ queryKey: ["admin", "/system"] });
    } catch (e) {
      toast("Could not save", "error", errText(e));
    } finally {
      setSaving(false);
    }
  }

  const ntpTone = !d.ntp.enabled ? "muted" : d.time.ntpdRunning ? "jade" : "saffron";
  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <Card className="min-w-0 lg:col-span-7">
        <CardHeader title="Identity and clock" subtitle="Stored in /etc/config/system" icon={<Server className="h-4 w-4" />} />
        <div className="space-y-4">
          <Field label="Hostname" htmlFor="adm-host" hint="Letters, digits and hyphens. Shown in logs and on the LAN.">
            <Input id="adm-host" value={hostname} onChange={(e) => touch(setHostname)(e.target.value)} autoComplete="off" />
          </Field>
          <Field label="Timezone" htmlFor="adm-tz" hint={zone ? `POSIX rule: ${zone === d.zonename ? d.timezone : "set on save"}` : undefined}>
            <Select id="adm-tz" value={zone} onChange={(e) => touch(setZone)(e.target.value)}>
              {(zones.data?.zones ?? [d.zonename]).map((z) => (
                <option key={z} value={z}>
                  {z}
                </option>
              ))}
            </Select>
          </Field>
          <Switch label="Sync time with NTP" description="Runs the busybox ntpd client" checked={ntpOn} onChange={touch(setNtpOn)} />
          <Field label="NTP servers" htmlFor="adm-ntp" hint="One per line, host names or IP addresses (up to 8).">
            <TextArea id="adm-ntp" rows={4} className="font-mono" value={servers} onChange={(e) => touch(setServers)(e.target.value)} spellCheck={false} />
          </Field>
          <Switch label="Serve time to the LAN" description="Lets LAN clients use this gateway as their NTP server" checked={ntpServe} onChange={touch(setNtpServe)} />
          <div className="flex flex-wrap justify-end gap-2 pt-1">
            {dirty && (
              <Button variant="ghost" onClick={() => setDirty(false)} disabled={saving}>
                Discard
              </Button>
            )}
            <Button variant="primary" onClick={save} disabled={!dirty || saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      </Card>

      <Card className="min-w-0 lg:col-span-5">
        <CardHeader title="Time sync" subtitle="Live from the gateway" icon={<Clock className="h-4 w-4" />} />
        <div className="space-y-4">
          <div>
            <div className="qm-display text-[1.6rem] font-semibold text-ink qm-tabular">{d.time.local || "—"}</div>
            <div className="text-[12px] text-muted">Up {formatDuration(d.time.uptime)}</div>
          </div>
          <div className="space-y-2 text-[13px]">
            <Verdict tone={ntpTone}>
              {!d.ntp.enabled
                ? "NTP sync is off"
                : d.time.ntpdRunning
                  ? "ntpd is running"
                  : `ntpd is not running${d.time.ntpdExitCode != null ? ` (exit ${d.time.ntpdExitCode})` : ""}`}
            </Verdict>
            <Verdict tone={d.time.stratumSeen ? "jade" : "muted"}>
              {d.time.stratumSeen ? "A time server has answered since boot" : "No NTP answer recorded since boot"}
            </Verdict>
          </div>
          {d.ntp.enabled && !d.time.ntpdRunning && (
            <Notice tone="warn" title="Clock is not being disciplined by NTP">
              The clock still follows the cellular network time, but ntpd exited. Check the server names, or restart sysntpd from Services.
            </Notice>
          )}
          <div className="flex flex-wrap gap-1.5">
            {d.ntp.servers.map((s) => (
              <Badge key={s} variant="neutral">
                {s}
              </Badge>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}
