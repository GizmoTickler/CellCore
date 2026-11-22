import { useState } from "react";
import {
  AlertTriangle,
  CalendarClock,
  Crosshair,
  Lock,
  LockOpen,
  Radio,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Unlock,
} from "lucide-react";
import { Badge, Button, Card, CardHeader, Input, Select, Skeleton, Switch } from "../../components/ui";
import { cn } from "../../lib/utils";
import type { ServingCellInfo } from "../../types/cellcore";
import { ConfirmModal, Field, TONE_TEXT, rsrpTone } from "./shared";
import { useLockForm } from "./lock-form";

export interface LockStatus {
  lteLocked: boolean;
  nrLocked: boolean;
  ltePersist: boolean;
  nrPersist: boolean;
}

const DEADMAN_PRESETS = [
  { secs: 60, label: "1 minute (60 s)" },
  { secs: 120, label: "2 minutes (120 s)" },
  { secs: 180, label: "3 minutes (180 s)" },
  { secs: 300, label: "5 minutes (300 s)" },
  { secs: 600, label: "10 minutes (600 s)" },
  { secs: 900, label: "15 minutes (900 s)" },
];

function StatusTile({
  title,
  term,
  locked,
  persist,
  bypassed,
  raw,
  loading,
  onRelease,
  releasing,
}: {
  title: string;
  term: string;
  locked: boolean;
  persist: boolean;
  bypassed: boolean;
  raw?: string;
  loading: boolean;
  onRelease: () => void;
  releasing: boolean;
}) {
  const line = (raw ?? "")
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.startsWith("+QNWLOCK"));
  return (
    <div
      className={cn(
        "relative min-w-0 overflow-hidden rounded-2xl border p-3.5 sm:p-5",
        bypassed && locked
          ? "border-crimson/50 bg-crimson-soft"
          : locked
            ? "border-saffron/50 bg-saffron-soft"
            : "border-line bg-raised"
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-baseline gap-1.5 text-[12.5px] font-semibold text-ink-2">
            {title} <span className="font-mono text-[11px] font-medium text-muted">{term}</span>
          </div>
          {loading ? (
            <Skeleton className="mt-2 h-8 w-32" />
          ) : (
            <div
              className={cn(
                "mt-1 flex items-center gap-2 qm-display text-[1.6rem] font-semibold leading-tight",
                bypassed && locked ? "text-crimson-ink" : locked ? "text-saffron-ink" : "text-jade-ink"
              )}
            >
              {bypassed && locked ? (
                <ShieldAlert className="h-5 w-5" />
              ) : locked ? (
                <Lock className="h-5 w-5" />
              ) : (
                <LockOpen className="h-5 w-5" />
              )}
              {bypassed && locked ? "Bypassed" : locked ? "Pinned" : "Free"}
            </div>
          )}
          <div className="mt-1 hidden sm:block text-[12.5px] text-ink-2">
            {bypassed && locked
              ? "Temporarily released by Dead-Man's Switch."
              : locked
                ? "Stays on one cell, even if a better one appears."
                : "Picks the best cell on its own."}
          </div>
        </div>
        {locked && (
          <Button variant="secondary" size="sm" onClick={onRelease} disabled={releasing}>
            <Unlock className="h-3.5 w-3.5" />
            Release
          </Button>
        )}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge variant={persist ? "success" : "neutral"}>
          {persist ? "Survives reboot" : "Clears on reboot"}
        </Badge>
        {locked && line && <code className="truncate font-mono text-[11px] text-muted max-w-full">{line}</code>}
      </div>
    </div>
  );
}

export function LockView({
  loading,
  status,
  lteRaw,
  nrRaw,
  bypassed,
  deadmanEnabled,
  deadmanSecs,
  deadmanDirty,
  setDeadmanEnabled,
  setDeadmanSecs,
  onSaveDeadman,
  onRearmBypassed,
  canRearm,
  nrPersistDraft,
  setNrPersistDraft,
  ltePersistDraft,
  setLtePersistDraft,
  schedule,
  schedStart,
  schedEnd,
  schedDirty,
  setSchedStart,
  setSchedEnd,
  onSaveSchedule,
  serving,
  busy,
  onPrefill,
  onLockNr,
  onLockLte,
  onClear,
  onToggleSchedule,
}: {
  loading: boolean;
  status: LockStatus;
  lteRaw?: string;
  nrRaw?: string;
  bypassed: boolean;
  deadmanEnabled: boolean;
  deadmanSecs: number;
  deadmanDirty: boolean;
  setDeadmanEnabled: (v: boolean) => void;
  setDeadmanSecs: (v: number) => void;
  onSaveDeadman: () => void;
  onRearmBypassed: () => void;
  canRearm: boolean;
  nrPersistDraft: boolean;
  setNrPersistDraft: (v: boolean) => void;
  ltePersistDraft: boolean;
  setLtePersistDraft: (v: boolean) => void;
  schedule?: { enabled: boolean; lteLock?: string; nr5gLock?: string } | null;
  schedStart: string;
  schedEnd: string;
  schedDirty: boolean;
  setSchedStart: (v: string) => void;
  setSchedEnd: (v: string) => void;
  onSaveSchedule: () => void;
  serving: ServingCellInfo | null;
  busy: string | null;
  onPrefill: () => void;
  onLockNr: () => void;
  onLockLte: () => void;
  onClear: (rat: "lte" | "nr5g" | "all") => Promise<void>;
  onToggleSchedule: (enabled: boolean) => void;
}) {
  const f = useLockForm();
  const [confirmAll, setConfirmAll] = useState(false);
  const anyLocked = status.lteLocked || status.nrLocked;
  const servingIsNr = Boolean(serving?.rat.includes("NR5G"));

  const deadmanOptions = DEADMAN_PRESETS.some((p) => p.secs === deadmanSecs)
    ? DEADMAN_PRESETS
    : [...DEADMAN_PRESETS, { secs: deadmanSecs, label: `${deadmanSecs} seconds (custom)` }].sort(
        (a, b) => a.secs - b.secs
      );

  return (
    <div className="space-y-5">
      {/* Dead-Man's Switch bypass warning banner */}
      {bypassed && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-crimson/50 bg-crimson-soft px-4 py-3.5 text-crimson-ink"
        >
          <div className="flex items-start gap-3 min-w-0">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
            <div className="min-w-0">
              <div className="text-[14px] font-bold leading-snug">
                Cell lock temporarily bypassed by Dead-Man&apos;s Switch
              </div>
              <p className="mt-0.5 text-[12.5px] opacity-90 leading-snug">
                The pinned cell lost registration or reachability, so CellCore temporarily released the lock to restore connectivity. Re-arm your saved lock once the tower is back, or release it permanently.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {canRearm && (
              <Button
                variant="primary"
                size="sm"
                onClick={onRearmBypassed}
                disabled={busy === "rearm"}
              >
                <RotateCcw className="h-3.5 w-3.5" />
                {busy === "rearm" ? "Re-arming…" : "Re-arm Lock"}
              </Button>
            )}
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void onClear("all")}
              disabled={busy === "clear-all"}
            >
              <Unlock className="h-3.5 w-3.5" />
              Release Lock
            </Button>
          </div>
        </div>
      )}

      {/* Answer first: is anything pinned? */}
      <div className="grid grid-cols-2 gap-3 sm:gap-4">
        <StatusTile
          title="5G cell"
          term="NR5G"
          locked={status.nrLocked}
          persist={status.nrPersist}
          bypassed={bypassed}
          raw={nrRaw}
          loading={loading}
          onRelease={() => void onClear("nr5g")}
          releasing={busy === "clear-nr5g"}
        />
        <StatusTile
          title="LTE cell"
          term="LTE"
          locked={status.lteLocked}
          persist={status.ltePersist}
          bypassed={bypassed}
          raw={lteRaw}
          loading={loading}
          onRelease={() => void onClear("lte")}
          releasing={busy === "clear-lte"}
        />
      </div>

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Primary task: pin a cell */}
        <div className="lg:col-span-8 min-w-0 space-y-5">
          {/* Serving cell shortcut */}
          <Card className="qm-grain overflow-hidden">
            <div className="relative z-[1] flex flex-wrap items-center justify-between gap-4">
              <div className="flex min-w-0 items-center gap-3.5">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl qm-sun text-on-ember">
                  <Radio className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="qm-eyebrow">Connected to</div>
                  {serving ? (
                    <div className="mt-0.5 flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
                      <span className="qm-display text-[1.5rem] font-semibold text-ink leading-tight">{serving.band}</span>
                      <span className="text-[13px] text-ink-2 qm-tabular">
                        Cell <strong className="font-mono">{serving.pci ?? "—"}</strong> · channel{" "}
                        <strong className="font-mono">{serving.arfcn ?? "—"}</strong>
                        {serving.scsKhz != null && (
                          <>
                            {" "}· <strong className="font-mono">{serving.scsKhz} kHz</strong>
                          </>
                        )}
                      </span>
                      <span className={cn("text-[13px] font-semibold qm-tabular", TONE_TEXT[rsrpTone(serving.rsrp)])}>
                        {serving.rsrp ?? "—"} dBm
                      </span>
                    </div>
                  ) : (
                    <div className="mt-0.5 text-[13px] text-muted">Waiting for the serving cell…</div>
                  )}
                </div>
              </div>
              <Button variant="tier3" onClick={onPrefill} disabled={!serving}>
                <Crosshair className="h-4 w-4" />
                Use this cell
              </Button>
            </div>
          </Card>

          <div className="grid gap-5 md:grid-cols-2">
            <Card className={cn("min-w-0", servingIsNr && "ring-1 ring-ember/25")}>
              <CardHeader title="Pin a 5G cell" subtitle="Find these values on Cell Scan." />
              <div className="grid grid-cols-2 gap-3">
                <Field label="Cell ID" term="PCI" htmlFor="nr-pci">
                  <Input id="nr-pci" inputMode="numeric" value={f.nrPci} onChange={(e) => f.set({ nrPci: e.target.value })} placeholder="589" className="font-mono" />
                </Field>
                <Field label="Band" term="n#" htmlFor="nr-band">
                  <Input id="nr-band" inputMode="numeric" value={f.nrBand} onChange={(e) => f.set({ nrBand: e.target.value })} placeholder="41" className="font-mono" />
                </Field>
                <Field label="Channel" term="NR-ARFCN" htmlFor="nr-arfcn">
                  <Input id="nr-arfcn" inputMode="numeric" value={f.nrArfcn} onChange={(e) => f.set({ nrArfcn: e.target.value })} placeholder="521310" className="font-mono" />
                </Field>
                <Field label="Spacing" term="SCS kHz" htmlFor="nr-scs">
                  <Select id="nr-scs" value={f.nrScs} onChange={(e) => f.set({ nrScs: e.target.value })}>
                    <option value="15">15 kHz</option>
                    <option value="30">30 kHz</option>
                    <option value="60">60 kHz</option>
                    <option value="120">120 kHz</option>
                  </Select>
                </Field>
              </div>
              <div className="mt-3.5 rounded-xl border border-line bg-sunk px-3 py-2.5">
                <Switch
                  label="Survives reboot"
                  description="Write lock to NVRAM save_ctrl"
                  checked={nrPersistDraft}
                  onChange={setNrPersistDraft}
                />
              </div>
              <Button variant="primary" className="mt-4 w-full" onClick={onLockNr} disabled={busy === "nr-lock"}>
                <Lock className="h-3.5 w-3.5" />
                {busy === "nr-lock" ? "Pinning…" : "Lock to this 5G cell"}
              </Button>
            </Card>

            <Card className={cn("min-w-0", serving && !servingIsNr && "ring-1 ring-ember/25")}>
              <CardHeader title="Pin an LTE cell" subtitle="Find these values on Cell Scan." />
              <div className="grid grid-cols-2 gap-3">
                <Field label="Cell ID" term="PCI" htmlFor="lte-pci">
                  <Input id="lte-pci" inputMode="numeric" value={f.ltePci} onChange={(e) => f.set({ ltePci: e.target.value })} placeholder="123" className="font-mono" />
                </Field>
                <Field label="Channel" term="EARFCN" htmlFor="lte-earfcn">
                  <Input id="lte-earfcn" inputMode="numeric" value={f.lteEarfcn} onChange={(e) => f.set({ lteEarfcn: e.target.value })} placeholder="66786" className="font-mono" />
                </Field>
              </div>
              <div className="mt-3.5 rounded-xl border border-line bg-sunk px-3 py-2.5">
                <Switch
                  label="Survives reboot"
                  description="Write lock to NVRAM save_ctrl"
                  checked={ltePersistDraft}
                  onChange={setLtePersistDraft}
                />
              </div>
              <Button variant="primary" className="mt-4 w-full" onClick={onLockLte} disabled={busy === "lte-lock"}>
                <Lock className="h-3.5 w-3.5" />
                {busy === "lte-lock" ? "Pinning…" : "Lock to this LTE cell"}
              </Button>
            </Card>
          </div>
        </div>

        {/* Supporting: dead-man's switch + schedule + release */}
        <div className="lg:col-span-4 min-w-0 space-y-5">
          <Card>
            <CardHeader
              title="Dead-Man's Switch"
              subtitle="Auto-bypass a stuck cell lock if registration drops."
              icon={<ShieldAlert className="h-4 w-4" />}
              action={
                deadmanDirty ? (
                  <Badge variant="warning">Unsaved</Badge>
                ) : (
                  <Badge variant={deadmanEnabled ? "success" : "neutral"} dot>
                    {deadmanEnabled ? "Armed" : "Off"}
                  </Badge>
                )
              }
            />
            <div className="space-y-3.5">
              <Switch
                label="Auto-bypass on outage"
                description="Releases the lock temporarily if the pinned tower goes offline"
                checked={deadmanEnabled}
                onChange={setDeadmanEnabled}
                disabled={busy === "deadman"}
              />
              <Field label="Bypass after" htmlFor="deadman-secs">
                <Select
                  id="deadman-secs"
                  value={String(deadmanSecs)}
                  onChange={(e) => setDeadmanSecs(Number(e.target.value))}
                  disabled={!deadmanEnabled || busy === "deadman"}
                >
                  {deadmanOptions.map((opt) => (
                    <option key={opt.secs} value={String(opt.secs)}>
                      {opt.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                variant={deadmanDirty ? "primary" : "secondary"}
                size="sm"
                className="w-full"
                onClick={onSaveDeadman}
                disabled={busy === "deadman" || !deadmanDirty}
              >
                {busy === "deadman" ? "Saving…" : "Save dead-man settings"}
              </Button>
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Lock on a schedule"
              subtitle="Pin during these hours, roam freely outside them."
              icon={<CalendarClock className="h-4 w-4" />}
              action={schedDirty ? <Badge variant="warning">Unsaved</Badge> : undefined}
            />
            <div className="space-y-4">
              <Switch
                label={schedule?.enabled ? "Schedule is on" : "Schedule is off"}
                checked={Boolean(schedule?.enabled)}
                onChange={onToggleSchedule}
                disabled={busy === "sched"}
              />
              <div className="grid grid-cols-2 gap-3">
                <Field label="From" htmlFor="sched-start">
                  <Input id="sched-start" type="time" value={schedStart} onChange={(e) => setSchedStart(e.target.value)} className="qm-tabular" />
                </Field>
                <Field label="Until" htmlFor="sched-end">
                  <Input id="sched-end" type="time" value={schedEnd} onChange={(e) => setSchedEnd(e.target.value)} className="qm-tabular" />
                </Field>
              </div>
              <Button
                variant={schedDirty ? "primary" : "secondary"}
                size="sm"
                className="w-full"
                onClick={onSaveSchedule}
                disabled={busy === "sched" || !schedDirty}
              >
                {busy === "sched" ? "Saving…" : "Save schedule"}
              </Button>
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Start over"
              subtitle="Release every pin so the modem roams freely again."
              icon={<ShieldCheck className="h-4 w-4" />}
            />
            <Button
              variant={anyLocked ? "danger" : "secondary"}
              className="w-full"
              onClick={() => setConfirmAll(true)}
              disabled={busy === "clear-all"}
            >
              <Unlock className="h-3.5 w-3.5" />
              Release all locks
            </Button>
            {!anyLocked && <p className="mt-2 text-center text-[12px] text-muted">Nothing is pinned right now.</p>}
          </Card>
        </div>
      </div>

      <ConfirmModal
        open={confirmAll}
        title="Release all cell locks?"
        body="The modem will be free to pick any 5G or LTE cell. It may hand over to a different tower right away, which can briefly interrupt the connection."
        confirmLabel="Release all"
        busy={busy === "clear-all"}
        onClose={() => setConfirmAll(false)}
        onConfirm={async () => {
          setConfirmAll(false);
          await onClear("all");
        }}
      />
    </div>
  );
}
