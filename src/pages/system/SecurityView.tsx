import React, { useState } from "react";
import { Check, Circle, Eye, EyeOff, Lock, Ruler, ShieldCheck, Thermometer } from "lucide-react";
import { cn } from "../../lib/utils";
import { Button, Card, CardHeader, Input, SegmentedTabs, Switch } from "../../components/ui";
import type { SystemController } from "./useSystemController";
import { Field } from "./parts";
import { AcmeCertCard } from "./AcmeCertCard";
import { ApiTokensCard } from "./ApiTokensCard";
import { AuditLogCard } from "./AuditLogCard";
import { SecurityPostureCard } from "./SecurityPostureCard";

function PasswordInput({
  id,
  value,
  onChange,
  autoComplete,
  show,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete: string;
  show: boolean;
}) {
  return (
    <Input
      id={id}
      type={show ? "text" : "password"}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      autoComplete={autoComplete}
      required
    />
  );
}

function Rule({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <li className={cn("flex items-center gap-2 text-[12.5px]", ok ? "text-jade-ink" : "text-muted")}>
      {ok ? <Check className="h-3.5 w-3.5" /> : <Circle className="h-3 w-3" />}
      {children}
    </li>
  );
}

export function SecurityView({ ctl }: { ctl: SystemController }) {
  const [show, setShow] = useState(false);
  const s = ctl.settings;
  const useF = ctl.useFahrenheit;
  const km = s?.measurementUnit === "km";
  const longEnough = ctl.newPassword.length >= 8;
  const matches = ctl.newPassword.length > 0 && ctl.newPassword === ctl.confirmPassword;

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="lg:col-span-7 min-w-0">
          <CardHeader
            title="Administrator password"
            subtitle="Updates the OpenWrt root credentials in /etc/shadow"
            icon={<Lock className="h-4 w-4" />}
            action={
              <Button variant="ghost" size="sm" onClick={() => setShow((v) => !v)} aria-pressed={show}>
                {show ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                {show ? "Hide" : "Show"}
              </Button>
            }
          />
          <form onSubmit={ctl.handlePasswordChange} className="space-y-4 max-w-md">
            <Field label="Current password" htmlFor="qm-pw-old">
              <PasswordInput id="qm-pw-old" value={ctl.oldPassword} onChange={ctl.setOldPassword} autoComplete="current-password" show={show} />
            </Field>
            <div className="h-px bg-line" />
            <Field label="New password" htmlFor="qm-pw-new">
              <PasswordInput id="qm-pw-new" value={ctl.newPassword} onChange={ctl.setNewPassword} autoComplete="new-password" show={show} />
            </Field>
            <Field label="Confirm new password" htmlFor="qm-pw-confirm">
              <PasswordInput
                id="qm-pw-confirm"
                value={ctl.confirmPassword}
                onChange={ctl.setConfirmPassword}
                autoComplete="new-password"
                show={show}
              />
            </Field>
            <ul className="space-y-1">
              <Rule ok={longEnough}>At least 8 characters</Rule>
              <Rule ok={matches}>Both entries match</Rule>
            </ul>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <Button type="submit" variant="primary" disabled={ctl.busy === "pw"}>
                {ctl.busy === "pw" ? "Updating…" : "Update password"}
              </Button>
            </div>
          </form>
        </Card>

        <div className="lg:col-span-5 min-w-0 space-y-5">
          <Card>
            <CardHeader
              title="Connection security"
              subtitle="Saved to /etc/cellcore/settings.json"
              icon={<ShieldCheck className="h-4 w-4" />}
            />
            <Switch
              label="Redirect HTTP to HTTPS"
              description="Plain-HTTP requests to the console are sent to the encrypted address"
              checked={Boolean(s?.httpsRedirect ?? true)}
              onChange={(v) => ctl.updateSettings({ httpsRedirect: v })}
              disabled={ctl.busy === "settings"}
            />
          </Card>

          <Card>
            <CardHeader title="Units" subtitle="How temperatures and tower distances are shown" icon={<Ruler className="h-4 w-4" />} />
            <div className="divide-y divide-line">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4">
                <div className="flex items-center gap-2.5 min-w-0">
                  <Thermometer className="h-4 w-4 text-muted shrink-0" />
                  <div>
                    <div className="text-[13px] font-semibold text-ink">Temperature</div>
                    <div className="text-[12px] text-muted qm-tabular">e.g. {ctl.fmtTemp(45)}</div>
                  </div>
                </div>
                <SegmentedTabs
                  value={useF ? "fahrenheit" : "celsius"}
                  onChange={(u) => ctl.updateSettings({ temperatureUnit: u })}
                  options={[
                    { id: "celsius", label: "°C" },
                    { id: "fahrenheit", label: "°F" },
                  ]}
                />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-3 pt-4">
                <div className="flex items-center gap-2.5 min-w-0">
                  <Ruler className="h-4 w-4 text-muted shrink-0" />
                  <div>
                    <div className="text-[13px] font-semibold text-ink">Tower distance</div>
                    <div className="text-[12px] text-muted qm-tabular">e.g. {km ? "2.4 km" : "1.5 mi"}</div>
                  </div>
                </div>
                <SegmentedTabs
                  value={km ? "km" : "mi"}
                  onChange={(u) => ctl.updateSettings({ measurementUnit: u })}
                  options={[
                    { id: "mi", label: "Miles" },
                    { id: "km", label: "km" },
                  ]}
                />
              </div>
            </div>
          </Card>
        </div>
      </div>
      <SecurityPostureCard />
      <AcmeCertCard />
      <ApiTokensCard />
      <AuditLogCard />
    </div>
  );
}
