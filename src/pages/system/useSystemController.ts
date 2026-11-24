import React, { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  apiFetch,
  confirmFirmwareAbSlot,
  getFirmwareAbStaged,
  getFirmwareAbStatus,
  inspectFirmwareAb,
  uploadFirmwareAbZip,
} from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { useWsStore } from "../../stores/ws-store";
import { useToastStore } from "../../stores/toast-store";
import { useDraft } from "../../lib/draft";

const DEFAULT_REB_DAYS = ["sunday"];
import type {
  FirmwareAbInspectReport,
  FirmwareAbScope,
  FirmwareAbSlot,
  FirmwareAbStatus,
  ReconcileReport,
  StagedFirmwareFile,
  SystemInternals,
} from "../../types/cellcore";

export const SYS_TABS = ["hardware", "internals", "logs", "alerts", "ota", "backup", "security"] as const;
export type SysTab = (typeof SYS_TABS)[number];

export type ThermalSubsystem = "CPU Cluster" | "Baseband & DSP" | "RF Transceiver" | "PHY & Chassis";

export function classifyThermalSubsystem(sensor: string): ThermalSubsystem {
  const s = sensor.toLowerCase();
  if (s.includes("cpu") || s.includes("apss") || s.includes("nspss")) return "CPU Cluster";
  if (s.includes("mdm") || s.includes("modem") || s.includes("ddr")) return "Baseband & DSP";
  if (s.includes("rf") || s.includes("pa") || s.includes("qtm") || s.includes("sdr") || s.includes("fbrx")) return "RF Transceiver";
  return "PHY & Chassis";
}

export function validateImeiLuhn(raw: string): boolean {
  const digits = raw.trim();
  if (!/^\d{15}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let d = digits.charCodeAt(i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

export interface SecretsData {
  imei: string;
  iccid: string;
  imsi: string;
  previousImei?: string | null;
}

export type OtaState = "upToDate" | "updateAvailable" | "feedOlder" | "unknown";

export interface OtaUpgradeStatus {
  state: "idle" | "running" | "succeeded" | "failed";
  target?: string;
  from?: string;
  startedAt?: number;
  finishedAt?: number | null;
  exitCode?: number | null;
  installedAfter?: string | null;
  message?: string | null;
}

export interface PkgInfo {
  package?: string;
  installedVersion?: string | null;
  availableVersion?: string | null;
  updateAvailable?: boolean;
  state?: OtaState;
  /** Unix seconds: mtime of the signed feed's package list. */
  lastChecked?: number | null;
  signatureVerified?: boolean | null;
  daemonVersion?: string;
  errors?: string[];
  upgrade?: OtaUpgradeStatus;
  upgradeLog?: string[];
}

export interface MaintenanceInfo {
  scheduledReboot?: { enabled: boolean; time: string; days: string[] };
  alerts?: { smtpConfigured: boolean; recipient: string };
}

export interface AbUploadProgress {
  pct: number;
  loaded: number;
  total: number;
  speedBps: number;
}

export interface AbRebootWatch {
  fromSlot: FirmwareAbSlot;
  targetSlot: FirmwareAbSlot;
  startedAt: number;
  seenDown: boolean;
  arrived: boolean;
}

interface AbInspectKey {
  path: string;
  scope: FirmwareAbScope;
  allowProjectMismatch: boolean;
  allowNoManifest: boolean;
}

/**
 * All System page state, queries and mutations. The handlers are carried over
 * unchanged from the pre-redesign page (same endpoints, same payloads); only the
 * feedback channel moved from an inline banner to the global toast store.
 * State lives here (not in each view) so it survives switching sub-views.
 */
export function useSystemController(tab: SysTab) {
  const qc = useQueryClient();
  const pushToast = useToastStore((s) => s.push);
  const [revealSecrets, setRevealSecrets] = useState(false);
  const [secretsData, setSecretsData] = useState<SecretsData | null>(null);
  const [imeiModalOpen, setImeiModalOpen] = useState(false);
  const [newImeiInput, setNewImeiInput] = useState("");
  const [imeiPasswordInput, setImeiPasswordInput] = useState("");
  const [imeiApplyNow, setImeiApplyNow] = useState(true);

  const [busy, setBusy] = useState<string | null>(null);

  const [logSource, setLogSource] = useState<"quecmanager" | "system">("system");
  const [logLines, setLogLines] = useState("100");
  const [logSearch, setLogSearch] = useState("");
  const [debouncedLogSearch, setDebouncedLogSearch] = useState("");
  const [logAutoRefresh, setLogAutoRefresh] = useState(false);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedLogSearch(logSearch), 300);
    return () => window.clearTimeout(t);
  }, [logSearch]);


  const [smtpSender, setSmtpSender] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");

  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [reconcileOutput, setReconcileOutput] = useState<ReconcileReport | null>(null);

  // A/B Zero-USB Modem Firmware state
  const [abPath, setAbPath] = useState("");
  const [abScope, setAbScope] = useState<FirmwareAbScope>("rootfs");
  const [abPreserveCellcore, setAbPreserveCellcore] = useState(true);
  const [abVerifyReadback, setAbVerifyReadback] = useState(true);
  const [abActivateReboot, setAbActivateReboot] = useState(false);
  const [abAllowProjectMismatch, setAbAllowProjectMismatch] = useState(false);
  const [abAllowNoManifest, setAbAllowNoManifest] = useState(false);
  const [abInspect, setAbInspect] = useState<FirmwareAbInspectReport | null>(null);
  const [abInspectKey, setAbInspectKey] = useState<AbInspectKey | null>(null);
  const [abPolling, setAbPolling] = useState(false);
  const [abUploading, setAbUploading] = useState(false);
  const [abUploadProgress, setAbUploadProgress] = useState<AbUploadProgress | null>(null);
  const [abRebootWatch, setAbRebootWatch] = useState<AbRebootWatch | null>(null);
  const [abPendingFlashReboot, setAbPendingFlashReboot] = useState<{
    fromSlot: FirmwareAbSlot;
    targetSlot: FirmwareAbSlot;
  } | null>(null);

  const settings = useWsStore((s) => s.settings);
  const internalsStore = useWsStore((s) => s.internals);
  const setInternals = useWsStore((s) => s.setInternals);
  const setSettings = useWsStore((s) => s.setSettings);
  const hydrateBootstrap = useWsStore((s) => s.hydrateBootstrap);

  function notify(kind: "ok" | "err", msg: string) {
    pushToast(msg, kind === "ok" ? "success" : "error");
  }

  const internalsQuery = useQuery({
    queryKey: ["sys-internals"],
    queryFn: () => apiFetch<SystemInternals>("/api/v1/system/internals"),
    enabled: tab === "internals",
    refetchInterval: tab === "internals" ? 5000 : false,
  });

  /** Set while an install we started is in flight; drives polling and the auto-reload. */
  const [otaWatch, setOtaWatch] = useState<{ target: string } | null>(null);

  const pkgInfoQuery = useQuery({
    queryKey: ["pkg-info"],
    queryFn: () => apiFetch<PkgInfo>("/api/v1/system/ota"),
    enabled: tab === "ota" || otaWatch != null,
    // While installing, the daemon restarts underneath us: keep polling through the gap.
    refetchInterval: (query) =>
      otaWatch != null || query.state.data?.upgrade?.state === "running" ? 2000 : false,
    retry: otaWatch != null ? true : 3,
    retryDelay: 2000,
  });

  useEffect(() => {
    const d = pkgInfoQuery.data;
    if (!otaWatch || !d?.upgrade) return;
    const done = d.upgrade.state === "succeeded" && d.installedVersion === otaWatch.target;
    // The installer writes "succeeded" only after opkg (and the postinst daemon restart) finished.
    if (done) {
      setOtaWatch(null);
      pushToast(`CellCore ${otaWatch.target} installed, reloading`, "success");
      window.setTimeout(() => window.location.reload(), 1200);
    } else if (d.upgrade.state === "failed" && d.upgrade.target === otaWatch.target) {
      setOtaWatch(null);
      pushToast("Upgrade failed", "error", d.upgrade.message ?? "See the installer log below.");
    }
  }, [pkgInfoQuery.data, otaWatch, pushToast]);

  const abRebootInFlight = abRebootWatch != null && !abRebootWatch.arrived;

  const firmwareAbQuery = useQuery<FirmwareAbStatus>({
    queryKey: ["firmware-ab"],
    queryFn: getFirmwareAbStatus,
    enabled: tab === "ota" || abPolling || abRebootInFlight || abPendingFlashReboot != null,
    refetchInterval: (query) =>
      abRebootInFlight
        ? 2500
        : abPolling || abPendingFlashReboot != null || query.state.data?.job?.running
          ? 2000
          : false,
    retry: abRebootInFlight || abPendingFlashReboot != null ? true : 1,
    retryDelay: 2000,
  });

  const abStagedQuery = useQuery<{ files: StagedFirmwareFile[] }>({
    queryKey: ["firmware-ab-staged"],
    queryFn: getFirmwareAbStaged,
    enabled: tab === "ota" && !abRebootInFlight,
    staleTime: 15_000,
  });

  // Auto-resume polling if an A/B flash job was already running on page open (e.g. started via CLI).
  useEffect(() => {
    if (firmwareAbQuery.data?.job?.running && !abPolling) {
      setAbPolling(true);
    }
  }, [firmwareAbQuery.data?.job?.running, abPolling]);

  useEffect(() => {
    const j = firmwareAbQuery.data?.job;
    if (!abPolling || !j) return;
    if (!j.running && j.finishedAt != null) {
      setAbPolling(false);
      if (j.ok === true) {
        if (abPendingFlashReboot) {
          const pending = abPendingFlashReboot;
          setAbPendingFlashReboot(null);
          const alreadyArrived = firmwareAbQuery.data?.activeSlot === pending.targetSlot;
          setAbRebootWatch({
            fromSlot: pending.fromSlot,
            targetSlot: pending.targetSlot,
            startedAt: Date.now(),
            seenDown: alreadyArrived,
            arrived: alreadyArrived,
          });
          if (alreadyArrived) {
            void hydrateBootstrap();
            void qc.invalidateQueries({ queryKey: ["sys-internals"] });
            void qc.invalidateQueries({ queryKey: ["firmware-ab-staged"] });
            pushToast(`Modem booted cleanly on Slot ${pending.targetSlot}!`, "success");
          } else {
            notify("ok", `A/B flash complete — rebooting into Slot ${pending.targetSlot}…`);
          }
        } else {
          notify("ok", j.dryRun ? "A/B firmware dry-run passed cleanly" : "A/B firmware flash completed cleanly");
        }
      } else if (j.ok === false) {
        setAbPendingFlashReboot(null);
        notify("err", j.error || "A/B firmware flash failed");
      }
    }
  }, [firmwareAbQuery.data, abPolling, abPendingFlashReboot, hydrateBootstrap, qc, pushToast]);

  // If a flash+reboot job dropped offline before we observed job.ok===true, hand off to abRebootWatch.
  useEffect(() => {
    if (!abPendingFlashReboot) return;
    const active = firmwareAbQuery.data?.activeSlot;
    if (active && active === abPendingFlashReboot.targetSlot) {
      const pending = abPendingFlashReboot;
      setAbPendingFlashReboot(null);
      setAbPolling(false);
      setAbRebootWatch({
        fromSlot: pending.fromSlot,
        targetSlot: pending.targetSlot,
        startedAt: Date.now(),
        seenDown: true,
        arrived: true,
      });
      void hydrateBootstrap();
      void qc.invalidateQueries({ queryKey: ["sys-internals"] });
      void qc.invalidateQueries({ queryKey: ["firmware-ab-staged"] });
      pushToast(`Modem booted cleanly on Slot ${pending.targetSlot}!`, "success");
    } else if (firmwareAbQuery.failureCount > 0 || firmwareAbQuery.isError) {
      const pending = abPendingFlashReboot;
      setAbPendingFlashReboot(null);
      setAbPolling(false);
      setAbRebootWatch({
        fromSlot: pending.fromSlot,
        targetSlot: pending.targetSlot,
        startedAt: Date.now(),
        seenDown: true,
        arrived: false,
      });
    }
  }, [
    abPendingFlashReboot,
    firmwareAbQuery.data?.activeSlot,
    firmwareAbQuery.failureCount,
    firmwareAbQuery.isError,
    hydrateBootstrap,
    qc,
    pushToast,
  ]);

  useEffect(() => {
    if (!abRebootWatch || abRebootWatch.arrived) return;
    if ((firmwareAbQuery.failureCount > 0 || firmwareAbQuery.isError) && !abRebootWatch.seenDown) {
      setAbRebootWatch((prev) => (prev && !prev.arrived ? { ...prev, seenDown: true } : prev));
    }
  }, [abRebootWatch, firmwareAbQuery.failureCount, firmwareAbQuery.isError]);

  useEffect(() => {
    if (!abRebootWatch || abRebootWatch.arrived) return;
    const active = firmwareAbQuery.data?.activeSlot;
    if (active && active === abRebootWatch.targetSlot) {
      setAbRebootWatch((prev) => (prev ? { ...prev, arrived: true } : prev));
      setAbPolling(false);
      void hydrateBootstrap();
      void qc.invalidateQueries({ queryKey: ["sys-internals"] });
      void qc.invalidateQueries({ queryKey: ["firmware-ab-staged"] });
      pushToast(`Modem booted cleanly on Slot ${abRebootWatch.targetSlot}!`, "success");
    }
  }, [abRebootWatch, firmwareAbQuery.data?.activeSlot, hydrateBootstrap, qc, pushToast]);

  const maintQuery = useQuery({
    queryKey: ["sys-maintenance"],
    queryFn: () => apiFetch<MaintenanceInfo>("/api/v1/system/maintenance"),
    enabled: tab === "alerts",
  });

  const logsQuery = useQuery({
    queryKey: ["sys-logs", logSource, logLines, debouncedLogSearch],
    queryFn: () =>
      apiFetch<{ logs?: string[]; source?: string }>(
        `/api/v1/system/logs?source=${logSource}&lines=${encodeURIComponent(logLines)}&search=${encodeURIComponent(debouncedLogSearch)}`
      ),
    enabled: tab === "logs",
    refetchInterval: tab === "logs" && logAutoRefresh ? 5000 : false,
  });

  // Drafts: a refetch never overwrites a schedule or recipient being edited.
  const sr = maintQuery.data?.scheduledReboot;
  const [rebTime, setRebTime, rebTimeD] = useDraft(sr?.time || null, "04:00");
  const [rebDays, setRebDays, rebDaysD] = useDraft<string[]>(
    Array.isArray(sr?.days) && sr.days.length > 0 ? sr.days : null,
    DEFAULT_REB_DAYS
  );
  const rebDirty = rebTimeD.dirty || rebDaysD.dirty;
  const [smtpRecipient, setSmtpRecipient, recipientD] = useDraft(maintQuery.data?.alerts?.recipient || null, "");

  async function loadSecrets(revealAfter = true) {
    setBusy("secrets");
    try {
      const s = await apiFetch<SecretsData>("/api/v1/modem/secrets");
      setSecretsData(s);
      if (revealAfter) setRevealSecrets(true);
      return s;
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Failed loading identifiers");
      return null;
    } finally {
      setBusy(null);
    }
  }

  async function handleToggleReveal() {
    if (revealSecrets) {
      setRevealSecrets(false);
      return;
    }
    await loadSecrets(true);
  }

  async function openImeiModal() {
    setImeiPasswordInput("");
    setImeiModalOpen(true);
    const s = await loadSecrets(false);
    if (s?.imei) setNewImeiInput(s.imei);
  }

  function closeImeiModal() {
    setImeiModalOpen(false);
    setImeiPasswordInput("");
  }

  async function handleSubmitImei(e: React.FormEvent) {
    e.preventDefault();
    const clean = newImeiInput.trim();
    if (!validateImeiLuhn(clean)) {
      notify("err", "IMEI must be a valid 15-digit Luhn checksum number");
      return;
    }
    if (!imeiPasswordInput) {
      notify("err", "Administrator password confirmation is required");
      return;
    }
    setBusy("imei-save");
    try {
      const payload = JSON.stringify({
        imei: clean,
        password: imeiPasswordInput,
        applyNow: imeiApplyNow,
      });
      const res = imeiApplyNow
        ? await disruptiveFetch<{ message?: string }>(
            "IMEI update & radio restart",
            "/api/v1/modem/imei",
            { method: "POST", body: payload },
            { confirmed: true }
          )
        : await apiFetch<{ message?: string }>("/api/v1/modem/imei", {
            method: "POST",
            body: payload,
          });
      setImeiPasswordInput("");
      setImeiModalOpen(false);
      await hydrateBootstrap();
      notify("ok", res.message || "Modem IMEI updated");
    } catch (err) {
      if (!isCancelled(err)) notify("err", err instanceof Error ? err.message : "IMEI update failed");
    } finally {
      setBusy(null);
    }
  }

  async function toggleUsbGadget(enabled: boolean) {
    setBusy("usb");
    try {
      const res = await apiFetch<{ usbUdc?: string }>("/api/v1/system/usb-gadget", {
        method: "POST",
        body: JSON.stringify({ enabled }),
      });
      if (internalsStore) {
        setInternals({ ...internalsStore, usbUdc: res.usbUdc ?? (enabled ? "bound" : "unbound") });
      }
      await qc.invalidateQueries({ queryKey: ["sys-internals"] });
      notify("ok", `USB bench gadget ${enabled ? "bound" : "unbound"}`);
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "USB gadget toggle failed");
    } finally {
      setBusy(null);
    }
  }

  async function toggleKeepAlive(enabled: boolean) {
    setBusy("ka");
    try {
      await apiFetch("/api/v1/diagnostics/latency", {
        method: "POST",
        body: JSON.stringify({ keepAlive: enabled }),
      });
      if (internalsStore) setInternals({ ...internalsStore, keepAliveEnabled: enabled });
      await qc.invalidateQueries({ queryKey: ["sys-internals"] });
      notify("ok", `RRC / 4CA Keep-Alive ${enabled ? "enabled" : "disabled"}`);
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Keep-alive toggle failed");
    } finally {
      setBusy(null);
    }
  }

  async function triggerReconcile() {
    setBusy("reconcile");
    try {
      const res = await apiFetch<{ report?: ReconcileReport }>("/api/v1/system/reconcile", {
        method: "POST",
        body: "{}",
      });
      if (res.report) setReconcileOutput(res.report);
      await qc.invalidateQueries({ queryKey: ["sys-internals"] });
      notify("ok", "Boot & policy reconciler completed");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Reconcile failed");
    } finally {
      setBusy(null);
    }
  }

  async function updateSettings(patch: Partial<{
    temperatureUnit: "celsius" | "fahrenheit";
    measurementUnit: "mi" | "km";
    httpsRedirect: boolean;
  }>) {
    setBusy("settings");
    try {
      const res = await apiFetch<{ settings?: typeof settings }>("/api/v1/system/settings", {
        method: "POST",
        body: JSON.stringify(patch),
      });
      if (res.settings) setSettings(res.settings);
      notify("ok", "Preferences updated");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Update failed");
    } finally {
      setBusy(null);
    }
  }

  async function saveScheduledReboot(enabled: boolean) {
    setBusy("reb");
    try {
      await apiFetch("/api/v1/system/maintenance", {
        method: "POST",
        body: JSON.stringify({
          scheduledRebootEnabled: enabled,
          scheduledRebootTime: rebTime,
          scheduledRebootDays: rebDays,
        }),
      });
      await qc.invalidateQueries({ queryKey: ["sys-maintenance"] });
      rebTimeD.reset();
      rebDaysD.reset();
      notify("ok", `Scheduled reboot ${enabled ? "enabled" : "disabled"}`);
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Failed saving schedule");
    } finally {
      setBusy(null);
    }
  }

  async function saveSmtp(e: React.FormEvent) {
    e.preventDefault();
    setBusy("smtp-save");
    try {
      await apiFetch("/api/v1/system/maintenance", {
        method: "POST",
        body: JSON.stringify({
          smtpSender,
          smtpPassword,
          smtpRecipient,
        }),
      });
      setSmtpPassword("");
      await qc.invalidateQueries({ queryKey: ["sys-maintenance"] });
      recipientD.reset();
      notify("ok", "SMTP credentials saved cleanly");
    } catch (err) {
      notify("err", err instanceof Error ? err.message : "SMTP error");
    } finally {
      setBusy(null);
    }
  }

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      notify("err", "Passwords do not match");
      return;
    }
    if (newPassword.length < 8) {
      notify("err", "New password must be at least 8 characters");
      return;
    }
    setBusy("pw");
    try {
      const res = await apiFetch<{ status?: string; revokedTokens?: number }>("/api/v1/system/password", {
        method: "POST",
        body: JSON.stringify({ currentPassword: oldPassword, newPassword }),
      });
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
      await qc.invalidateQueries({ queryKey: ["security", "tokens"] });
      const revoked = typeof res.revokedTokens === "number" ? res.revokedTokens : 0;
      if (revoked > 0) {
        pushToast(
          "OpenWrt root password updated cleanly",
          "success",
          `Revoked ${revoked} API token${revoked === 1 ? "" : "s"}.`
        );
      } else {
        notify("ok", "OpenWrt root password updated cleanly");
      }
    } catch (err) {
      notify("err", err instanceof Error ? err.message : "Password update failed");
    } finally {
      setBusy(null);
    }
  }

  /** Refreshes only the signed CellCore feed, then re-reads the package info. */
  async function checkOtaFeed() {
    setBusy("ota-check");
    try {
      const info = await apiFetch<PkgInfo>("/api/v1/system/ota", {
        method: "POST",
        body: JSON.stringify({ action: "check" }),
      });
      if (info && info.state) qc.setQueryData(["pkg-info"], info);
      await qc.invalidateQueries({ queryKey: ["pkg-info"] });
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Feed check failed");
      await qc.invalidateQueries({ queryKey: ["pkg-info"] });
    } finally {
      setBusy(null);
    }
  }

  /** Starts the detached installer for exactly `version`; the daemon refuses downgrades. */
  async function upgradePackage(version: string) {
    setBusy("ota-upgrade");
    try {
      // OtaView's confirm dialog shows the failover warning.
      await disruptiveFetch(
        "OTA upgrade",
        "/api/v1/system/ota",
        { method: "POST", body: JSON.stringify({ action: "upgrade", version }) },
        { confirmed: true }
      );
      setOtaWatch({ target: version });
      notify("ok", `Installing ${version}`);
      await qc.invalidateQueries({ queryKey: ["pkg-info"] });
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Upgrade failed");
    } finally {
      setBusy(null);
    }
  }

  async function inspectAbPackage(overridePath?: string) {
    const trimmed = (overridePath ?? abPath).trim();
    if (!trimmed) {
      notify("err", "Enter the path to a firmware .zip or unpacked directory on the modem");
      return;
    }
    setBusy("ab-inspect");
    try {
      const report = await inspectFirmwareAb({
        path: trimmed,
        scope: abScope,
        allowProjectMismatch: abAllowProjectMismatch,
        allowNoManifest: abAllowNoManifest,
      });
      setAbInspect(report);
      setAbInspectKey({
        path: trimmed,
        scope: abScope,
        allowProjectMismatch: abAllowProjectMismatch,
        allowNoManifest: abAllowNoManifest,
      });
      notify("ok", `Planned ${report.plan.partitions.length} inactive-slot partitions (${report.plan.targetSlot})`);
    } catch (e) {
      setAbInspect(null);
      setAbInspectKey(null);
      notify("err", e instanceof Error ? e.message : "Package inspection failed");
    } finally {
      setBusy(null);
    }
  }

  async function uploadFirmwareAb(file: File) {
    if (!file.name.toLowerCase().endsWith(".zip")) {
      notify("err", "Please select a stock Quectel firmware .zip archive");
      return;
    }
    if (file.size <= 0) {
      notify("err", "Selected firmware archive is empty");
      return;
    }
    setAbUploading(true);
    setAbUploadProgress({ pct: 0, loaded: 0, total: file.size, speedBps: 0 });
    const startedAt = performance.now();
    let lastTs = startedAt;
    let lastLoaded = 0;
    let smoothedBps = 0;

    try {
      const res = await uploadFirmwareAbZip(file, (pct, loaded, total) => {
        const now = performance.now();
        const dt = (now - lastTs) / 1000;
        if (dt >= 0.2) {
          const instBps = (loaded - lastLoaded) / dt;
          smoothedBps = smoothedBps > 0 ? smoothedBps * 0.65 + instBps * 0.35 : instBps;
          lastTs = now;
          lastLoaded = loaded;
        } else if (smoothedBps === 0 && now > startedAt) {
          smoothedBps = loaded / ((now - startedAt) / 1000);
        }
        setAbUploadProgress({
          pct,
          loaded,
          total,
          speedBps: Math.max(0, Math.round(smoothedBps)),
        });
      });
      setAbPath(res.path);
      setAbInspect(null);
      setAbInspectKey(null);
      notify("ok", `Uploaded ${file.name} to ${res.path}`);
      await qc.invalidateQueries({ queryKey: ["firmware-ab-staged"] });
      await inspectAbPackage(res.path);
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Firmware upload failed");
    } finally {
      setAbUploading(false);
      setAbUploadProgress(null);
    }
  }

  async function startAbFlash(dryRun: boolean) {
    const trimmed = abPath.trim();
    if (!trimmed) {
      notify("err", "Enter a firmware package path first");
      return;
    }
    setBusy(dryRun ? "ab-dryrun" : "ab-flash");
    try {
      const willReboot = !dryRun && abActivateReboot;
      const payload = {
        path: trimmed,
        scope: abScope,
        dryRun,
        preserveCellcore: abPreserveCellcore,
        verifyReadback: abVerifyReadback,
        activateSlot: willReboot,
        reboot: willReboot,
        allowProjectMismatch: abAllowProjectMismatch,
        allowNoManifest: abAllowNoManifest,
      };
      const res = willReboot
        ? await disruptiveFetch<{ targetSlot?: string }>(
            "A/B firmware flash & reboot",
            "/api/v1/system/firmware-ab/flash",
            { method: "POST", body: JSON.stringify(payload) },
            { confirmed: true }
          )
        : await apiFetch<{ targetSlot?: string }>("/api/v1/system/firmware-ab/flash", {
            method: "POST",
            body: JSON.stringify(payload),
          });
      if (willReboot) {
        const fromSlot: FirmwareAbSlot = firmwareAbQuery.data?.activeSlot ?? "_a";
        const targetSlot: FirmwareAbSlot =
          res.targetSlot === "_a" || res.targetSlot === "_b"
            ? res.targetSlot
            : firmwareAbQuery.data?.inactiveSlot ?? (fromSlot === "_a" ? "_b" : "_a");
        setAbPendingFlashReboot({ fromSlot, targetSlot });
        setAbRebootWatch(null);
      } else {
        setAbPendingFlashReboot(null);
      }
      setAbPolling(true);
      await qc.invalidateQueries({ queryKey: ["firmware-ab"] });
      notify("ok", dryRun ? "Started A/B firmware dry-run" : "Started inactive-slot A/B firmware flash");
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed starting A/B flash");
    } finally {
      setBusy(null);
    }
  }

  async function switchAbSlot(slot: FirmwareAbSlot, reboot: boolean, force?: boolean) {
    setBusy("ab-switch");
    const fromSlot: FirmwareAbSlot = firmwareAbQuery.data?.activeSlot ?? (slot === "_a" ? "_b" : "_a");
    try {
      const body = force ? { slot, reboot, force: true } : { slot, reboot };
      await disruptiveFetch(
        `Switch boot slot to ${slot}`,
        "/api/v1/system/firmware-ab/switch",
        { method: "POST", body: JSON.stringify(body) },
        { confirmed: true }
      );
      if (reboot) {
        setAbPendingFlashReboot(null);
        setAbRebootWatch({
          fromSlot,
          targetSlot: slot,
          startedAt: Date.now(),
          seenDown: false,
          arrived: false,
        });
      }
      await qc.invalidateQueries({ queryKey: ["firmware-ab"] });
      notify("ok", reboot ? `Switching to slot ${slot} and rebooting…` : `Next boot slot set to ${slot}`);
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Slot switch failed");
    } finally {
      setBusy(null);
    }
  }

  async function confirmAbSlot() {
    setBusy("ab-confirm");
    try {
      await confirmFirmwareAbSlot();
      await qc.invalidateQueries({ queryKey: ["firmware-ab"] });
      notify("ok", "Current boot slot confirmed as successful");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Slot confirmation failed");
    } finally {
      setBusy(null);
    }
  }

  const abInspectCurrent = Boolean(
    abInspect &&
      abInspectKey &&
      abInspectKey.path === abPath.trim() &&
      abInspectKey.scope === abScope &&
      abInspectKey.allowProjectMismatch === abAllowProjectMismatch &&
      abInspectKey.allowNoManifest === abAllowNoManifest
  );

  const useFahrenheit = settings?.temperatureUnit === "fahrenheit";
  const fmtTemp = (c: number) => (useFahrenheit ? `${Math.round(((c * 9) / 5 + 32) * 10) / 10} °F` : `${c} °C`);

  const internals = internalsQuery.data ?? internalsStore;
  const activeReport = reconcileOutput ?? internals?.lastReconcile ?? null;

  return {
    tab,
    settings,
    busy,
    // identity
    revealSecrets,
    secretsData,
    handleToggleReveal,
    imeiModalOpen,
    openImeiModal,
    closeImeiModal,
    newImeiInput,
    setNewImeiInput,
    imeiPasswordInput,
    setImeiPasswordInput,
    imeiApplyNow,
    setImeiApplyNow,
    handleSubmitImei,
    // thermals
    useFahrenheit,
    fmtTemp,
    // internals
    internals,
    internalsQuery,
    activeReport,
    toggleUsbGadget,
    toggleKeepAlive,
    triggerReconcile,
    // logs
    logsQuery,
    logSource,
    setLogSource,
    logLines,
    setLogLines,
    logSearch,
    setLogSearch,
    logAutoRefresh,
    setLogAutoRefresh,
    // maintenance
    maintQuery,
    rebTime,
    setRebTime,
    rebDays,
    setRebDays,
    rebDirty,
    saveScheduledReboot,
    smtpSender,
    setSmtpSender,
    smtpPassword,
    setSmtpPassword,
    smtpRecipient,
    setSmtpRecipient,
    saveSmtp,
    // ota
    pkgInfoQuery,
    checkOtaFeed,
    otaWatch,
    upgradePackage,
    // firmware a/b
    firmwareAbQuery,
    abStagedQuery,
    abPath,
    setAbPath,
    abScope,
    setAbScope,
    abPreserveCellcore,
    setAbPreserveCellcore,
    abVerifyReadback,
    setAbVerifyReadback,
    abActivateReboot,
    setAbActivateReboot,
    abAllowProjectMismatch,
    setAbAllowProjectMismatch,
    abAllowNoManifest,
    setAbAllowNoManifest,
    abInspect,
    setAbInspect,
    abInspectCurrent,
    abUploading,
    abUploadProgress,
    uploadFirmwareAb,
    abRebootWatch,
    setAbRebootWatch,
    inspectAbPackage,
    startAbFlash,
    switchAbSlot,
    confirmAbSlot,
    // security
    oldPassword,
    setOldPassword,
    newPassword,
    setNewPassword,
    confirmPassword,
    setConfirmPassword,
    handlePasswordChange,
    updateSettings,
  };
}

export type SystemController = ReturnType<typeof useSystemController>;
