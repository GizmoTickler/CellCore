import React, { useEffect, useState } from "react";
import {
  ArrowLeftRight,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Download,
  FileSearch,
  HardDrive,
  Loader2,
  Package,
  Play,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  XCircle,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, Meter, Modal, Select, Skeleton, Switch } from "../../components/ui";
import { FailoverWarning } from "../../components/obs";
import type { FirmwareAbScope } from "../../types/cellcore";
import type { SystemController } from "./useSystemController";

/** Split "4.0.0-1" into [4,0,0] + release "1" (display only; ordering is decided by the daemon). */
function splitVersion(v: string): { nums: string[]; rel: string | null } {
  const [main, rel] = v.split("-", 2);
  return { nums: main.split("."), rel: rel ?? null };
}

function changeKind(from: string, to: string): string {
  const a = splitVersion(from);
  const b = splitVersion(to);
  const names = ["Major", "Minor", "Patch"];
  for (let i = 0; i < Math.max(a.nums.length, b.nums.length); i++) {
    if (a.nums[i] !== b.nums[i]) return `${names[i] ?? "Build"} update`;
  }
  if (a.rel !== b.rel) return "Package rebuild";
  return "Update";
}

/** "just now", "5 min ago", "3 h ago", "2 d ago". */
function relativeTime(unixSecs: number | null | undefined, now: number): string {
  if (!unixSecs) return "never";
  const d = Math.max(0, Math.round(now / 1000 - unixSecs));
  if (d < 45) return "just now";
  if (d < 3600) return `${Math.round(d / 60)} min ago`;
  if (d < 86400) return `${Math.round(d / 3600)} h ago`;
  return `${Math.round(d / 86400)} d ago`;
}

/** Render a version with the segments that differ from `base` emphasised. */
function VersionDiff({ version, base, tone }: { version: string; base: string; tone: "old" | "new" }) {
  const tokens = version.split(/([.-])/);
  const baseTokens = base.split(/([.-])/);
  let diverged = false;
  return (
    <span className="font-mono">
      {tokens.map((t, i) => {
        if (!diverged && t !== baseTokens[i]) diverged = true;
        const sep = t === "." || t === "-";
        return (
          <span
            key={i}
            className={cn(
              !sep && diverged && (tone === "new" ? "text-ember-ink font-semibold" : "text-muted line-through decoration-1")
            )}
          >
            {t}
          </span>
        );
      })}
    </span>
  );
}

export function OtaView({ ctl }: { ctl: SystemController }) {
  const q = ctl.pkgInfoQuery;
  const d = q.data;
  const pkg = d?.package ?? "sdxpinn-cellcore";
  const installed = d?.installedVersion ?? null;
  const available = d?.availableVersion ?? null;
  const state = d?.state ?? (d?.updateAvailable ? "updateAvailable" : "unknown");
  const upgrade = d?.upgrade;
  const installing = ctl.otaWatch != null || upgrade?.state === "running";
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 30000);
    return () => window.clearInterval(t);
  }, []);
  const checking = ctl.busy === "ota-check";
  const checkedLabel = `checked ${relativeTime(d?.lastChecked, now)}`;
  const canInstall = state === "updateAvailable" && installed != null && available != null && !installing;

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      {/* Verdict */}
      <Card className={cn("lg:col-span-8 min-w-0 relative overflow-hidden", canInstall && "qm-grain")}>
        {canInstall && <div className="pointer-events-none absolute inset-0 opacity-100" style={{ background: "var(--qm-sun-soft)" }} />}
        <div className="relative z-[1]">
          {q.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-6 w-40" />
              <Skeleton className="h-14 w-72" />
              <Skeleton className="h-4 w-56" />
            </div>
          ) : installing ? (
            <InstallProgress
              status={upgrade?.state ?? "running"}
              from={upgrade?.from || installed || ""}
              target={upgrade?.target || ctl.otaWatch?.target || available || ""}
              message={upgrade?.message ?? null}
              log={d?.upgradeLog ?? []}
              reconnecting={q.isError}
            />
          ) : canInstall ? (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="info" dot>
                  Update available
                </Badge>
                <Badge variant="neutral">{changeKind(installed, available)}</Badge>
                <span className="text-[12px] text-muted">{checkedLabel}</span>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <span className="text-[1.5rem] sm:text-[1.9rem] leading-none text-ink-2">
                  <VersionDiff version={installed} base={available} tone="old" />
                </span>
                <ArrowRight className="h-6 w-6 shrink-0 text-ember-ink" />
                <span className="text-[1.9rem] sm:text-[2.4rem] leading-none text-ink">
                  <VersionDiff version={available} base={installed} tone="new" />
                </span>
              </div>
              <div className="rounded-2xl bg-surface/70 border border-line p-4">
                <div className="qm-eyebrow mb-2">What will change</div>
                <ul className="space-y-1.5 text-[13px] text-ink-2">
                  <li className="flex gap-2">
                    <Package className="h-4 w-4 mt-0.5 shrink-0 text-muted" />
                    <span>
                      <span className="font-mono text-ink">{pkg}</span> is replaced with {available} from the signed feed.
                    </span>
                  </li>
                  <li className="flex gap-2">
                    <RefreshCw className="h-4 w-4 mt-0.5 shrink-0 text-muted" />
                    <span>CellCore restarts during the install. This page follows along and reloads when it is back.</span>
                  </li>
                  {upgrade?.state === "failed" && (
                    <li className="flex gap-2 text-crimson-ink">
                      <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                      <span>
                        The last install of {upgrade.target} failed{upgrade.exitCode != null ? ` (opkg exit ${upgrade.exitCode})` : ""}.
                        {upgrade.message ? ` ${upgrade.message}` : ""}
                      </span>
                    </li>
                  )}
                </ul>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="tier1" size="lg" onClick={() => setConfirmOpen(true)} disabled={ctl.busy === "ota-upgrade"}>
                  <Download className="h-4 w-4" />
                  {ctl.busy === "ota-upgrade" ? "Starting…" : `Install ${available}`}
                </Button>
              </div>
            </div>
          ) : state === "unknown" ? (
            <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-saffron-soft text-saffron-ink">
                <TriangleAlert className="h-7 w-7" />
              </div>
              <div className="min-w-0">
                <div className="qm-eyebrow">Update status unknown</div>
                <div className="mt-1 text-[1.6rem] leading-none text-ink font-mono break-all">{installed ?? "Installed version unknown"}</div>
                <p className="mt-2 text-[13px] text-muted">
                  {available == null ? "The signed feed has not been read yet. Check for updates." : "The installed version could not be read."}
                </p>
                {(d?.errors ?? []).length > 0 && (
                  <ul className="mt-2 space-y-0.5 text-[12px] text-saffron-ink">
                    {d!.errors!.map((e) => (
                      <li key={e} className="break-all">
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-jade-soft text-jade-ink">
                <CheckCircle2 className="h-7 w-7" />
              </div>
              <div className="min-w-0">
                <div className="qm-eyebrow">
                  Up to date · {checkedLabel}
                </div>
                <div className="mt-1 text-[2rem] sm:text-[2.4rem] leading-none text-ink font-mono break-all">{installed}</div>
                <p className="mt-2 text-[13px] text-muted">
                  {state === "feedOlder"
                    ? `The feed offers ${available}, which is older than what is installed.`
                    : "No newer build on the signed feed."}
                </p>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Package facts */}
      <Card className="lg:col-span-4 min-w-0">
        <CardHeader title="Package" icon={<Package className="h-4 w-4" />} />
        <dl className="divide-y divide-line border-y border-line text-[13px]">
          <Row label="Name">
            <span className="font-mono text-[12.5px] break-all">{pkg}</span>
          </Row>
          <Row label="Installed">
            <span className="font-mono">{installed ?? "unknown"}</span>
          </Row>
          <Row label="On feed">
            <span className={cn("font-mono", state === "updateAvailable" && "text-ember-ink font-semibold")}>{available ?? "not read"}</span>
          </Row>
          <Row label="Last checked">
            <span>{relativeTime(d?.lastChecked, now)}</span>
          </Row>
          <Row label="Active boot slot">
            <span className="font-mono">Slot {ctl.internals?.bootSlot || "_a"}</span>
          </Row>
        </dl>
        <Button variant="secondary" className="mt-4 w-full" onClick={ctl.checkOtaFeed} disabled={checking || installing}>
          <RefreshCw className={cn("h-4 w-4", checking && "animate-spin")} />
          {checking ? "Checking feed…" : "Check for updates"}
        </Button>
        <p className={cn("mt-2 text-[11.5px] flex items-center gap-1.5", d?.signatureVerified === false ? "text-crimson-ink" : "text-muted")}>
          {d?.signatureVerified === false ? <XCircle className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
          {d?.signatureVerified === true
            ? "Feed signature verified on the last check."
            : d?.signatureVerified === false
              ? "Feed signature check failed on the last check."
              : "Packages are verified against the SDXPINN feed signature."}
        </p>
      </Card>

      <Modal open={confirmOpen} onClose={() => setConfirmOpen(false)} title={`Install ${available ?? "update"}?`}>
        <FailoverWarning action="Installing" />
        <p className="mt-3">
          This upgrades <span className="font-mono text-ink">{pkg}</span> from {installed} to {available}. CellCore restarts while
          it installs, so the console disconnects for a short time and then reloads.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirmOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              setConfirmOpen(false);
              if (available) void ctl.upgradePackage(available);
            }}
          >
            Install now
          </Button>
        </div>
      </Modal>

      {/* A/B Modem Firmware (Zero-USB) */}
      <FirmwareAbSection ctl={ctl} />
    </div>
  );
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || bytes <= 0) return "—";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KiB`;
  return `${bytes} B`;
}

function FirmwareAbSection({ ctl }: { ctl: SystemController }) {
  const q = ctl.firmwareAbQuery;
  const st = q.data;
  const job = st?.job;
  const running = Boolean(job?.running);
  const [switchModalOpen, setSwitchModalOpen] = useState(false);
  const [flashModalOpen, setFlashModalOpen] = useState(false);

  const activeSlot = st?.activeSlot ?? null;
  const inactiveSlot = st?.inactiveSlot ?? null;
  const inactiveUnbootable =
    inactiveSlot === "_a" ? st?.slotAUnbootable === true : inactiveSlot === "_b" ? st?.slotBUnbootable === true : false;
  const canSwitch = Boolean(st?.supported && inactiveSlot && !inactiveUnbootable && !running);
  const needsConfirm = Boolean(
    st?.supported &&
      (st.trialBootActive === true ||
        (st.lastState?.targetSlot && st.lastState.targetSlot === activeSlot && !st.lastState.verifiedOnBoot))
  );
  const pct = job && job.total > 0 ? Math.round((job.completed / job.total) * 100) : 0;
  const displayLog = (job?.log?.length ? job.log : st?.lastState?.log) ?? [];

  return (
    <>
      <Card className="lg:col-span-12 min-w-0">
        <CardHeader
          title="A/B Modem Firmware (Zero-USB)"
          subtitle="Flash stock Quectel SDX75 firmware to the inactive NAND slot over Ethernet with MD5/SHA-256 verification and instant slot rollback."
          icon={<Cpu className="h-4 w-4" />}
          action={
            <div className="flex flex-wrap items-center gap-2">
              {q.isLoading ? (
                <Badge variant="neutral">Probing…</Badge>
              ) : st?.supported ? (
                <Badge variant="success" dot>
                  Dual-Slot A/B ({st.abBaseCount} pairs)
                </Badge>
              ) : (
                <Badge variant="warning" dot>
                  Single-Slot Legacy
                </Badge>
              )}
              <Button variant="ghost" size="sm" onClick={() => void q.refetch()} disabled={q.isFetching}>
                <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} />
                Refresh
              </Button>
            </div>
          }
        />

        {q.isLoading ? (
          <div className="grid gap-3 sm:grid-cols-4">
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
          </div>
        ) : !st?.supported ? (
          <div className="rounded-2xl border border-line bg-sunk/60 p-4 flex items-start gap-3">
            <TriangleAlert className="h-5 w-5 text-saffron-ink shrink-0 mt-0.5" />
            <div className="text-[13px] text-ink-2 space-y-1">
              <div className="font-semibold text-ink">Dual-slot A/B NAND layout not detected on this modem</div>
              <p>{st?.unsupportedReason || "This modem appears to be running legacy single-slot firmware (e.g. R01A04). Upgrade once via USB QFirehose to R02A02+ to enable zero-USB A/B firmware flashing."}</p>
              {st?.projectRev && (
                <p className="font-mono text-[12px] text-muted">Current build: {st.projectRev}</p>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-5">
            {/* Slot Status Strip */}
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="qm-subcard p-3.5">
                <div className="text-[11.5px] font-semibold text-muted">Active / Inactive Slot</div>
                <div className="mt-1.5 flex items-center gap-2 font-mono text-[1.15rem] font-semibold text-ink">
                  <span>{activeSlot ?? "?"}</span>
                  <ArrowRight className="h-4 w-4 text-muted" />
                  <span className="text-ember-ink">{inactiveSlot ?? "?"}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  <Badge variant={st.slotAUnbootable ? "danger" : "success"}>
                    _a: {st.slotAUnbootable ? "unbootable" : "bootable"}
                  </Badge>
                  <Badge variant={st.slotBUnbootable ? "danger" : "success"}>
                    _b: {st.slotBUnbootable ? "unbootable" : "bootable"}
                  </Badge>
                </div>
              </div>

              <div className="qm-subcard p-3.5">
                <div className="text-[11.5px] font-semibold text-muted">Modem Firmware Rev</div>
                <div className="mt-1.5 font-mono text-[12.5px] font-semibold text-ink break-all">
                  {st.projectRev || "Unknown"}
                </div>
                <div className="mt-1 text-[11.5px] text-muted font-mono">
                  {st.projectName || "SDX75"} · {st.totalMtds} MTDs
                </div>
              </div>

              <div className="qm-subcard p-3.5">
                <div className="text-[11.5px] font-semibold text-muted">Trial Boot / RCI</div>
                <div className="mt-1.5 flex items-center gap-2">
                  <Badge variant={st.trialBootActive ? "warning" : "success"} dot>
                    {st.trialBootActive ? "Trial boot active" : "Confirmed stable"}
                  </Badge>
                </div>
                <div className="mt-1.5 text-[11.5px] text-muted">
                  {st.rci?.trialBootFailedAttempts != null
                    ? `Failed attempts: ${st.rci.trialBootFailedAttempts}/${st.rci.trialBootMaxAttempts ?? "?"}`
                    : st.tmpAvailMib != null
                      ? `/tmp staging free: ${st.tmpAvailMib} MiB`
                      : "Ready"}
                </div>
              </div>

              <div className="qm-subcard p-3.5 flex flex-col justify-between gap-2">
                <div className="text-[11.5px] font-semibold text-muted">Slot Actions</div>
                <div className="flex flex-wrap gap-2">
                  {needsConfirm && (
                    <Button
                      variant="success"
                      size="sm"
                      onClick={() => void ctl.confirmAbSlot()}
                      disabled={ctl.busy === "ab-confirm" || running}
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Confirm {activeSlot}
                    </Button>
                  )}
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setSwitchModalOpen(true)}
                    disabled={!canSwitch || ctl.busy === "ab-switch"}
                  >
                    <ArrowLeftRight className="h-3.5 w-3.5" />
                    Switch to {inactiveSlot ?? "other"} & Reboot
                  </Button>
                </div>
              </div>
            </div>

            {/* Flash Inactive Slot Controls */}
            <div className="rounded-2xl border border-line bg-surface/60 p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-[13.5px] font-semibold text-ink">Flash Inactive Slot ({inactiveSlot})</div>
                  <p className="text-[12px] text-muted mt-0.5">
                    Copy a stock Quectel firmware <span className="font-mono">.zip</span> onto the modem over Ethernet (e.g.{" "}
                    <span className="font-mono">scp firmware.zip root@modem:/tmp/</span>), then inspect and flash one image at a time.
                  </p>
                </div>
                {st.tmpAvailMib != null && (
                  <Badge variant={st.tmpAvailMib >= 128 ? "neutral" : "warning"}>
                    <HardDrive className="h-3 w-3" />
                    /tmp {st.tmpAvailMib} MiB free
                  </Badge>
                )}
              </div>

              <div className="grid gap-3 md:grid-cols-12">
                <div className="md:col-span-8">
                  <label className="block text-[12px] font-semibold text-ink-2 mb-1">Firmware .zip or directory path</label>
                  <Input
                    value={ctl.abPath}
                    onChange={(e) => {
                      ctl.setAbPath(e.target.value);
                      ctl.setAbInspect(null);
                    }}
                    placeholder="/tmp/RM551EGL00AAR02A02M8G.zip"
                    disabled={running}
                    className="font-mono text-[12.5px]"
                  />
                </div>
                <div className="md:col-span-4">
                  <label className="block text-[12px] font-semibold text-ink-2 mb-1">Partition scope</label>
                  <Select
                    value={ctl.abScope}
                    onChange={(e) => {
                      ctl.setAbScope(e.target.value as FirmwareAbScope);
                      ctl.setAbInspect(null);
                    }}
                    disabled={running}
                  >
                    <option value="rootfs">rootfs (boot + system — 2 partitions)</option>
                    <option value="baseband">baseband (modem + TZ + DSP — 15 partitions)</option>
                    <option value="full">full (all 22 A/B partitions, sbl last)</option>
                  </Select>
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-3 pt-1">
                <Switch
                  checked={ctl.abPreserveCellcore}
                  onChange={ctl.setAbPreserveCellcore}
                  disabled={running}
                  label="Preserve CellCore overlay"
                  description="Inject clean-room S03/S13 hooks into stock sysfs.ubi"
                />
                <Switch
                  checked={ctl.abVerifyReadback}
                  onChange={ctl.setAbVerifyReadback}
                  disabled={running}
                  label="Verify raw read-back"
                  description="SHA-256 read-back check on non-UBI partitions"
                />
                <Switch
                  checked={ctl.abActivateReboot}
                  onChange={ctl.setAbActivateReboot}
                  disabled={running}
                  label="Activate & reboot after flash"
                  description="Switch slot via abctl and reboot on full verification"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                <Button
                  variant="secondary"
                  onClick={() => void ctl.inspectAbPackage()}
                  disabled={running || ctl.busy === "ab-inspect" || !ctl.abPath.trim()}
                >
                  <FileSearch className="h-4 w-4" />
                  {ctl.busy === "ab-inspect" ? "Inspecting…" : "Inspect & Plan"}
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => void ctl.startAbFlash(true)}
                  disabled={running || ctl.busy === "ab-dryrun" || !ctl.abPath.trim()}
                >
                  <Play className="h-4 w-4" />
                  {ctl.busy === "ab-dryrun" ? "Starting…" : "Dry Run"}
                </Button>
                <Button
                  variant="tier1"
                  onClick={() => setFlashModalOpen(true)}
                  disabled={running || ctl.busy === "ab-flash" || !ctl.abPath.trim()}
                >
                  <Download className="h-4 w-4" />
                  {running ? "Flashing…" : `Flash Slot ${inactiveSlot}`}
                </Button>
              </div>
            </div>

            {/* Inspection Plan Table */}
            {ctl.abInspect && (
              <div className="rounded-2xl border border-line bg-raised/60 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-semibold text-ink">
                      Planned Inactive-Slot Writes ({ctl.abInspect.plan.partitions.length})
                    </span>
                    <Badge variant="info">
                      {ctl.abInspect.plan.activeSlot} → {ctl.abInspect.plan.targetSlot}
                    </Badge>
                    {ctl.abInspect.plan.projectName && (
                      <Badge variant="neutral">{ctl.abInspect.plan.projectName}</Badge>
                    )}
                  </div>
                  <span className="text-[11.5px] text-muted font-mono">
                    {ctl.abInspect.md5Entries} MD5 entries · {ctl.abInspect.sourceKind}
                  </span>
                </div>

                {ctl.abInspect.plan.warnings.length > 0 && (
                  <ul className="space-y-1 text-[12px] text-saffron-ink">
                    {ctl.abInspect.plan.warnings.map((w) => (
                      <li key={w} className="flex items-center gap-1.5">
                        <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                        <span>{w}</span>
                      </li>
                    ))}
                  </ul>
                )}

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[12px]">
                    <thead className="border-b border-line text-muted">
                      <tr>
                        <th className="py-1.5 pr-3">Target Partition</th>
                        <th className="py-1.5 pr-3">MTD</th>
                        <th className="py-1.5 pr-3">Format</th>
                        <th className="py-1.5 pr-3">Image / Capacity</th>
                        <th className="py-1.5 pr-3">MD5</th>
                        <th className="py-1.5">Archive Path</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/60 font-mono">
                      {ctl.abInspect.plan.partitions.map((p) => (
                        <tr key={p.targetPartition}>
                          <td className="py-1.5 pr-3 text-ink font-semibold">{p.targetPartition}</td>
                          <td className="py-1.5 pr-3 text-ink-2">mtd{p.mtdNum}</td>
                          <td className="py-1.5 pr-3">
                            <Badge variant={p.isUbi ? "info" : "neutral"}>{p.isUbi ? "UBI" : "RAW"}</Badge>
                          </td>
                          <td className="py-1.5 pr-3 text-ink-2">
                            {formatBytes(p.fileSize)} / {formatBytes(p.mtdSize)}
                          </td>
                          <td className="py-1.5 pr-3">
                            {p.expectedMd5 ? (
                              <span className="text-jade-ink">{p.expectedMd5.slice(0, 10)}…</span>
                            ) : (
                              <span className="text-saffron-ink">missing</span>
                            )}
                          </td>
                          <td className="py-1.5 text-muted break-all">{p.zipRelpath}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Live Progress / Last Flash Log */}
            {(running || displayLog.length > 0 || job?.error) && (
              <div className="space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {running ? (
                      <Badge variant="info" dot>
                        <Loader2 className="h-3 w-3 animate-spin" />
                        {job?.dryRun ? "Dry-run in progress" : "Flashing inactive slot"}
                        {job?.currentPartition ? ` · ${job.currentPartition}` : ""}
                      </Badge>
                    ) : job?.ok === false ? (
                      <Badge variant="danger" dot>
                        Failed
                      </Badge>
                    ) : st.lastState?.status ? (
                      <Badge variant="success" dot>
                        Last state: {st.lastState.status}
                      </Badge>
                    ) : null}
                    {job && job.total > 0 && (
                      <span className="text-[12px] font-mono text-muted">
                        {job.completed}/{job.total} ({pct}%)
                      </span>
                    )}
                  </div>
                  {st.lastState?.message && !running && (
                    <span className="text-[12px] text-ink-2">{st.lastState.message}</span>
                  )}
                </div>
                {running && <Meter pct={pct} tone="ember" />}
                {job?.error && <p className="text-[12.5px] text-crimson-ink">{job.error}</p>}
                {displayLog.length > 0 && (
                  <pre className="qm-subcard max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-xl bg-sunk p-3 font-mono text-[11.5px] text-ink-2">
                    {displayLog.join("\n")}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Switch Slot Confirmation Modal */}
      <Modal
        open={switchModalOpen}
        onClose={() => setSwitchModalOpen(false)}
        title={`Switch to Slot ${inactiveSlot ?? ""} & Reboot?`}
      >
        <FailoverWarning action="Switching boot slots" />
        <p className="mt-3 text-[13px] text-ink-2">
          This sets the next boot slot from <span className="font-mono text-ink">{activeSlot}</span> to{" "}
          <span className="font-mono text-ink">{inactiveSlot}</span> via <span className="font-mono">abctl --set_active</span> and
          reboots the modem. Slot <span className="font-mono text-ink">{activeSlot}</span> remains untouched for instant rollback if
          SBL trial boot fails.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setSwitchModalOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={() => {
              setSwitchModalOpen(false);
              if (inactiveSlot) void ctl.switchAbSlot(inactiveSlot, true);
            }}
          >
            Switch to {inactiveSlot} & Reboot
          </Button>
        </div>
      </Modal>

      {/* Flash Confirmation Modal */}
      <Modal
        open={flashModalOpen}
        onClose={() => setFlashModalOpen(false)}
        title={`Flash Inactive Slot ${inactiveSlot ?? ""}?`}
      >
        {ctl.abActivateReboot && <FailoverWarning action="Flashing & rebooting" />}
        <div className="mt-3 space-y-2 text-[13px] text-ink-2">
          <p>
            Target slot: <span className="font-mono text-ink font-semibold">{inactiveSlot}</span> (active slot{" "}
            <span className="font-mono text-ink">{activeSlot}</span> and non-A/B partitions like{" "}
            <span className="font-mono">efs2</span> / <span className="font-mono">usrdata</span> are never modified).
          </p>
          <p>
            Scope: <span className="font-mono text-ink">{ctl.abScope}</span>
            {ctl.abInspect ? ` (${ctl.abInspect.plan.partitions.length} partitions)` : ""} · Source:{" "}
            <span className="font-mono text-ink break-all">{ctl.abPath.trim()}</span>
          </p>
          <p>
            {ctl.abActivateReboot
              ? "After all images pass verification, the inactive slot will be activated and the modem will reboot."
              : "The active slot will stay running with zero downtime. You can switch slots afterwards when ready."}
          </p>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setFlashModalOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              setFlashModalOpen(false);
              void ctl.startAbFlash(false);
            }}
          >
            {ctl.abActivateReboot ? `Flash & Reboot into ${inactiveSlot}` : `Flash Slot ${inactiveSlot}`}
          </Button>
        </div>
      </Modal>
    </>
  );
}

function InstallProgress({
  status,
  from,
  target,
  message,
  log,
  reconnecting,
}: {
  status: string;
  from: string;
  target: string;
  message: string | null;
  log: string[];
  reconnecting: boolean;
}) {
  const failed = status === "failed";
  const done = status === "succeeded";
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {failed ? (
          <Badge variant="danger" dot>
            Install failed
          </Badge>
        ) : done ? (
          <Badge variant="success" dot>
            Installed, reloading
          </Badge>
        ) : (
          <Badge variant="info" dot>
            Installing
          </Badge>
        )}
        {reconnecting && !failed && <span className="text-[12px] text-muted">Waiting for CellCore to come back…</span>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[1.5rem] sm:text-[1.9rem] leading-none">
        <span className="font-mono text-ink-2">{from}</span>
        <ArrowRight className="h-6 w-6 shrink-0 text-ember-ink" />
        <span className="font-mono text-ink">{target}</span>
        {!failed && !done && <Loader2 className="h-5 w-5 animate-spin text-muted" />}
      </div>
      {message && <p className="text-[13px] text-crimson-ink">{message}</p>}
      <pre className="qm-subcard max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-xl bg-sunk p-3 font-mono text-[11.5px] text-ink-2">
        {log.length ? log.join("\n") : "Starting installer…"}
      </pre>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <dt className="text-muted shrink-0">{label}</dt>
      <dd className="min-w-0 text-right text-ink">{children}</dd>
    </div>
  );
}
