import { useMemo } from "react";
import { Cpu, Edit3, Eye, EyeOff, ShieldCheck, Thermometer, TriangleAlert } from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, CopyButton, Input, Modal, Switch } from "../../components/ui";
import { validateImeiLuhn, type SystemController } from "./useSystemController";
import {
  Field,
  HEAT_GRADIENT,
  HEAT_HOT,
  HEAT_MAX,
  HEAT_MIN,
  HEAT_WARM,
  heatColor,
  heatInk,
  heatPct,
  heatVerdict,
} from "./parts";

export function HardwareView({ ctl }: { ctl: SystemController }) {
  return (
    <div className="space-y-6">
      <PassportCard ctl={ctl} />
      <ThermalsCard ctl={ctl} />
      <ImeiModal ctl={ctl} />
    </div>
  );
}

/* ───────────────────────── Device passport ───────────────────────── */

function mrzLine(parts: string[], width = 44): string {
  const body = parts
    .map((p) => p.toUpperCase().replace(/[^A-Z0-9]+/g, "<"))
    .join("<<")
    .slice(0, width);
  return body.padEnd(width, "<");
}

function PassportCard({ ctl }: { ctl: SystemController }) {
  const id = ctl.modem?.identity;
  const { revealSecrets, secretsData } = ctl;
  const model = id?.model || "RM551E-GL";
  const rel = id?.rel || "Release 17";
  const imei = revealSecrets && secretsData?.imei ? secretsData.imei : id?.maskedImei || "--";
  const iccid = revealSecrets && secretsData?.iccid ? secretsData.iccid : id?.maskedIccid || "--";
  const imsi = revealSecrets && secretsData?.imsi ? secretsData.imsi : id?.maskedImsi || "--";

  const mrz = [
    mrzLine(["QM", model, "SDX75", rel]),
    mrzLine([id?.revision || "unknown firmware"]),
  ];

  return (
    <Card className="p-0 sm:p-0 overflow-hidden">
      <div className="grid lg:grid-cols-[minmax(0,300px)_minmax(0,1fr)]">
        {/* Cover */}
        <div
          className="qm-grain relative flex flex-col justify-between gap-6 p-5 sm:p-6 border-b lg:border-b-0 lg:border-r border-line"
          style={{ background: "var(--qm-sun-soft)" }}
        >
          <div className="relative z-[1]">
            <div className="qm-eyebrow">Device passport</div>
            <div className="mt-4 flex items-center gap-3.5">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl qm-sun text-on-ember shadow-[0_12px_28px_-12px_var(--qm-ember)]">
                <Cpu className="h-7 w-7" strokeWidth={1.8} />
              </div>
              <div className="min-w-0">
                <div className="qm-display text-[1.9rem] font-semibold leading-none text-ink truncate">{model}</div>
                <div className="mt-1.5 text-[12.5px] text-ink-2">
                  {id?.manufacturer ? id.manufacturer : <span className="text-muted">Manufacturer not reported</span>}
                </div>
              </div>
            </div>
          </div>
          <div className="relative z-[1] flex flex-wrap gap-1.5">
            <Badge variant="info">{rel}</Badge>
            <Badge variant="neutral">SDX75 · 5G</Badge>
            <Badge variant="neutral">SIM slot {id?.simSlot ?? 1}</Badge>
          </div>
        </div>

        {/* Identifiers */}
        <div className="p-5 sm:p-6 min-w-0">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="qm-display text-[1.12rem] font-semibold text-ink">Identifiers</h3>
              <p className="text-[12.5px] text-muted mt-0.5">
                {revealSecrets ? "Shown in full. Mask them again before sharing your screen." : "Masked by default. Revealing fetches them from the modem."}
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <Button variant="secondary" size="sm" onClick={ctl.handleToggleReveal} disabled={ctl.busy === "secrets"}>
                {revealSecrets ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                {revealSecrets ? "Mask IDs" : "Reveal IDs"}
              </Button>
              <Button variant="tier3" size="sm" onClick={ctl.openImeiModal}>
                <Edit3 className="h-3.5 w-3.5" />
                Edit IMEI
              </Button>
            </div>
          </div>

          <dl className="mt-4 divide-y divide-line border-y border-line">
            <PassportRow
              label="Firmware"
              value={id?.revision || "--"}
              copy={id?.revision || undefined}
            />
            <PassportRow
              label="IMEI"
              value={imei}
              note={id?.hasPreviousImei ? "Backup IMEI archived" : "Primary NVRAM"}
              copy={revealSecrets && secretsData?.imei ? secretsData.imei : undefined}
            />
            <PassportRow
              label="ICCID"
              value={iccid}
              note={`SIM slot ${id?.simSlot ?? 1}`}
              copy={revealSecrets && secretsData?.iccid ? secretsData.iccid : undefined}
            />
            <PassportRow
              label="IMSI"
              value={imsi}
              copy={revealSecrets && secretsData?.imsi ? secretsData.imsi : undefined}
            />
          </dl>

          <div aria-hidden className="mt-4 overflow-hidden rounded-xl bg-sunk px-3 py-2 font-mono text-[11px] leading-[1.6] tracking-[0.18em] text-muted whitespace-nowrap select-none">
            {mrz.map((l, i) => (
              <div key={i} className="overflow-hidden text-ellipsis">
                {l}
              </div>
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}

function PassportRow({
  label,
  value,
  note,
  copy,
}: {
  label: string;
  value: string;
  note?: string;
  copy?: string;
}) {
  return (
    <div className="grid grid-cols-[72px_minmax(0,1fr)_auto] sm:grid-cols-[96px_minmax(0,1fr)_auto] items-center gap-x-3 py-2.5">
      <dt className="text-[12px] font-semibold text-muted">{label}</dt>
      <dd className="min-w-0">
        <div className="font-mono text-[13px] text-ink break-all leading-snug">{value}</div>
        {note && <div className="mt-0.5 text-[11.5px] text-muted">{note}</div>}
      </dd>
      <div className="min-w-[28px] flex justify-end">{copy ? <CopyButton value={copy} /> : null}</div>
    </div>
  );
}

/* ───────────────────────── Thermals ───────────────────────── */

function ThermalsCard({ ctl }: { ctl: SystemController }) {
  const { fmtTemp, thermalGroups } = ctl;
  const all = ctl.modem?.thermals ?? [];

  const stats = useMemo(() => {
    if (all.length === 0) return null;
    let hottest = all[0];
    let coolest = all[0];
    let sum = 0;
    for (const t of all) {
      if (t.celsius > hottest.celsius) hottest = t;
      if (t.celsius < coolest.celsius) coolest = t;
      sum += t.celsius;
    }
    return { hottest, coolest, avg: Math.round((sum / all.length) * 10) / 10 };
  }, [all]);

  const verdict = heatVerdict(stats?.hottest.celsius ?? null);

  return (
    <Card>
      <CardHeader
        title="Thermals"
        subtitle={`${all.length} sensors across the SDX75 and RF dies, on one shared scale`}
        icon={<Thermometer className="h-4 w-4" />}
        action={<Badge variant={verdict.tone === "jade" ? "success" : verdict.tone === "saffron" ? "warning" : verdict.tone === "crimson" ? "danger" : "neutral"} dot>{verdict.label}</Badge>}
      />

      {stats ? (
        <div className="space-y-6">
          {/* Answer first: the hottest die */}
          <div className="grid gap-5 sm:grid-cols-[auto_minmax(0,1fr)] sm:items-end">
            <div>
              <div className="qm-eyebrow">Hottest</div>
              <div className={cn("qm-display mt-1 text-[3rem] sm:text-[3.4rem] font-semibold leading-none qm-tabular", verdict.ink)}>
                {fmtTemp(stats.hottest.celsius)}
              </div>
              <div className="mt-1.5 text-[12.5px] text-muted">
                <span className="font-mono text-ink-2">{stats.hottest.sensor}</span> · {verdict.note}
              </div>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-2 sm:justify-end text-[12.5px]">
              <div>
                <div className="text-muted">Average</div>
                <div className="qm-display text-[1.35rem] font-semibold text-ink qm-tabular">{fmtTemp(stats.avg)}</div>
              </div>
              <div>
                <div className="text-muted">Coolest</div>
                <div className="qm-display text-[1.35rem] font-semibold text-ink qm-tabular">{fmtTemp(stats.coolest.celsius)}</div>
              </div>
              <div>
                <div className="text-muted">Headroom to hot</div>
                <div className="qm-display text-[1.35rem] font-semibold text-ink qm-tabular">
                  {(() => {
                    const d = Math.max(0, HEAT_HOT - stats.hottest.celsius);
                    return ctl.useFahrenheit ? `${Math.round((d * 9) / 5)} °F` : `${Math.round(d * 10) / 10} °C`;
                  })()}
                </div>
              </div>
            </div>
          </div>

          {/* Heat rail: every sensor pinned on the cool → hot scale */}
          <HeatRail sensors={all} hottest={stats.hottest.sensor} fmtTemp={fmtTemp} />

          {/* Per-domain heat bars */}
          <div className="grid gap-4 md:grid-cols-2">
            {Object.entries(thermalGroups).map(([groupName, sensors]) => {
              if (sensors.length === 0) return null;
              const max = Math.max(...sensors.map((s) => s.celsius));
              return (
                <div key={groupName} className="qm-subcard p-4">
                  <div className="mb-3 flex items-center justify-between gap-2">
                    <div className="text-[13px] font-semibold text-ink">{groupName}</div>
                    <div className="text-[11.5px] text-muted qm-tabular">
                      {sensors.length} · peak <span className={cn("font-semibold", heatInk(max))}>{fmtTemp(max)}</span>
                    </div>
                  </div>
                  <ul className="space-y-2">
                    {sensors.map((s) => (
                      <li key={s.sensor} className="grid grid-cols-[minmax(0,92px)_minmax(0,1fr)_64px] items-center gap-3">
                        <span className="truncate font-mono text-[11.5px] text-ink-2" title={s.sensor}>
                          {s.sensor}
                        </span>
                        <span className="relative h-2 rounded-full bg-line/70 overflow-hidden">
                          <span
                            className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-500"
                            style={{ width: `${Math.max(3, heatPct(s.celsius))}%`, background: heatColor(s.celsius) }}
                          />
                        </span>
                        <span className={cn("text-right text-[13px] font-semibold qm-tabular", heatInk(s.celsius))}>
                          {fmtTemp(s.celsius)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="qm-subcard p-6 text-center text-[13px] text-muted">No thermal sensors reported yet.</div>
      )}
    </Card>
  );
}

function HeatRail({
  sensors,
  hottest,
  fmtTemp,
}: {
  sensors: Array<{ sensor: string; celsius: number }>;
  hottest: string;
  fmtTemp: (c: number) => string;
}) {
  const marks = [
    { c: HEAT_MIN, label: fmtTemp(HEAT_MIN) },
    { c: HEAT_WARM, label: `${fmtTemp(HEAT_WARM)} warm` },
    { c: HEAT_HOT, label: `${fmtTemp(HEAT_HOT)} hot` },
    { c: HEAT_MAX, label: fmtTemp(HEAT_MAX) },
  ];
  const hot = sensors.find((s) => s.sensor === hottest);
  return (
    <div className="pt-7" role="img" aria-label={`Sensor temperatures on a ${HEAT_MIN} to ${HEAT_MAX} degree scale`}>
      <div className="relative">
        {hot && (
          <div
            className="absolute -top-7 -translate-x-1/2 whitespace-nowrap rounded-full bg-ink px-2 py-0.5 text-[11px] font-semibold text-paper qm-tabular"
            style={{ left: `${heatPct(hot.celsius)}%` }}
          >
            {fmtTemp(hot.celsius)}
          </div>
        )}
        <div className="h-3 rounded-full opacity-90" style={{ background: HEAT_GRADIENT }} />
        {sensors.map((s) => (
          <span
            key={s.sensor}
            title={`${s.sensor} ${fmtTemp(s.celsius)}`}
            className={cn(
              "absolute top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-surface",
              s.sensor === hottest ? "h-[18px] w-[18px] bg-ink" : "h-3 w-3 bg-ink/70"
            )}
            style={{ left: `${heatPct(s.celsius)}%` }}
          />
        ))}
      </div>
      <div className="relative mt-2 h-4 text-[11px] text-muted qm-tabular">
        {marks.map((m, i) => (
          <span
            key={m.c}
            className={cn(
              "absolute whitespace-nowrap",
              i === 0 ? "left-0" : i === marks.length - 1 ? "right-0" : "-translate-x-1/2",
              // keep the two middle labels from colliding on phones
              i === 1 && "hidden sm:inline"
            )}
            style={i === 0 || i === marks.length - 1 ? undefined : { left: `${heatPct(m.c)}%` }}
          >
            {m.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ───────────────────────── IMEI edit (password-confirmed) ───────────────────────── */

function ImeiModal({ ctl }: { ctl: SystemController }) {
  const luhnOk = validateImeiLuhn(ctl.newImeiInput);
  return (
    <Modal open={ctl.imeiModalOpen} onClose={ctl.closeImeiModal} title="Password-Confirmed Edit IMEI">
      <form onSubmit={ctl.handleSubmitImei} className="space-y-4">
        <div className="flex gap-2.5 rounded-xl bg-saffron-soft px-3.5 py-2.5 text-[12.5px] text-saffron-ink leading-snug">
          <TriangleAlert className="h-4 w-4 shrink-0 mt-0.5" />
          <span>
            Changing NVRAM IMEI requires administrator password confirmation and automatically backs up your previous IMEI to UCI (
            <code className="font-mono">quecmanager.imei.previous</code>).
          </span>
        </div>

        <Field
          label="New 15-digit IMEI"
          htmlFor="qm-imei-new"
          aside={
            <Badge variant={luhnOk ? "success" : "danger"}>{luhnOk ? "Valid 15-digit Luhn" : "Invalid Luhn / Length"}</Badge>
          }
        >
          <div className="flex gap-2">
            <Input
              id="qm-imei-new"
              value={ctl.newImeiInput}
              onChange={(e) => ctl.setNewImeiInput(e.target.value)}
              placeholder="Enter 15-digit IMEI"
              className="font-mono tracking-wider"
              inputMode="numeric"
              maxLength={15}
              required
            />
            {ctl.secretsData?.previousImei && (
              <Button
                type="button"
                variant="secondary"
                className="h-10"
                onClick={() => ctl.setNewImeiInput(ctl.secretsData?.previousImei || "")}
              >
                Use Backup
              </Button>
            )}
          </div>
        </Field>

        <Field label="Administrator password" htmlFor="qm-imei-pw">
          <Input
            id="qm-imei-pw"
            type="password"
            value={ctl.imeiPasswordInput}
            onChange={(e) => ctl.setImeiPasswordInput(e.target.value)}
            placeholder="Confirm root password to authorize AT+EGMR"
            autoComplete="current-password"
            required
          />
        </Field>

        <div className="qm-subcard p-3.5">
          <Switch
            label="Restart radio immediately (CFUN 0 → 1)"
            description="Re-attaches the cellular session after writing NVRAM"
            checked={ctl.imeiApplyNow}
            onChange={ctl.setImeiApplyNow}
          />
        </div>

        <div className="flex flex-wrap justify-end gap-2 pt-1">
          <Button variant="secondary" onClick={ctl.closeImeiModal}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            disabled={!luhnOk || !ctl.imeiPasswordInput || ctl.busy === "imei-save"}
          >
            <ShieldCheck className="h-4 w-4" />
            {ctl.busy === "imei-save" ? "Applying..." : "Confirm & Write IMEI"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
