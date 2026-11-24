import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Check, CheckCircle2, Copy, FileDown, Gauge, Loader2, Lock, LogOut, Moon, MoreVertical, Palette, Power, RefreshCw, Search, ShieldAlert, Sun, Terminal, X } from "lucide-react";
import { apiFetch, confirmFirmwareAbSlot, getFirmwareAbStatus } from "../lib/api";
import { disruptiveFetch, isCancelled } from "../lib/disruptive";
import { NAV, sectionFor } from "../lib/nav";
import { cn, copyToClipboard, formatBitrate, formatBytes, formatDuration } from "../lib/utils";
import { useAuthStore } from "../stores/auth-store";
import { hrefFor, useRouteStore, type Section } from "../stores/route-store";
import { LAYOUTS, resolveLayout, SKINS, skinMeta, useThemeStore } from "../stores/theme-store";
import { useToastStore } from "../stores/toast-store";
import { useLiveness, useWsStore } from "../stores/ws-store";
import type { AppRoute, FirmwareAbStatus, OverviewPulse } from "../types/cellcore";
import { CommandPalette, type PaletteAction } from "./CommandPalette";
import { NavIcon } from "./NavIcon";
import { BrandLogo, BrandMark, Button, Kbd, LiveDot, Modal, signalQuality } from "./ui";
import { FailoverBadge, FailoverConfirmHost, FailoverWarning, useFailoverActive } from "./obs";
import { useObsStore } from "../stores/obs-store";

export type NavRoute = AppRoute;

/* ───────────────────────── Live link bits ───────────────────────── */

function SignalBars({ rsrp, className }: { rsrp: number | null | undefined; className?: string }) {
  const level = rsrp == null ? 0 : rsrp >= -85 ? 4 : rsrp >= -95 ? 3 : rsrp >= -105 ? 2 : 1;
  return (
    <span className={cn("inline-flex items-end gap-[2px] h-3.5", className)} aria-label={`Signal ${level} of 4`}>
      {[1, 2, 3, 4].map((b) => (
        <span key={b} className={cn("w-[3px] rounded-full", b <= level ? "qm-sun" : "bg-line-strong")} style={{ height: `${25 + b * 18.75}%` }} />
      ))}
    </span>
  );
}

function useLink() {
  const modem = useWsStore((s) => s.modem);
  const traffic = useWsStore((s) => s.traffic);
  const liveness = useLiveness();
  // Stale or disconnected: say so instead of showing old numbers as live.
  const wsStatus = liveness.label;
  const serving = modem?.serving ?? null;
  const carriers = modem?.carriers ?? [];
  const q = signalQuality(serving?.rsrp ?? null, serving?.sinr ?? null);
  const live = liveness.live;
  const dot: "jade" | "saffron" | "crimson" | "muted" = !live ? liveness.tone : q.tone === "muted" ? "muted" : q.tone === "ember" ? "jade" : q.tone;
  return { modem, traffic, wsStatus, serving, carriers, q, live, dot };
}

/** Full capsule for the sidebar. */
function LinkCapsule() {
  const { modem, traffic, wsStatus, serving, carriers, live, dot } = useLink();
  const attached = Boolean(serving && serving.rat && serving.rat !== "UNKNOWN" && serving.band && serving.band !== "-");
  return (
    <div className="rounded-2xl border border-line bg-surface p-3.5 qm-tabular">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <LiveDot tone={dot} />
          <span className="text-[13px] font-bold text-ink truncate">{modem?.operator || "Searching…"}</span>
        </div>
        <SignalBars rsrp={serving?.rsrp} />
      </div>
      <div className="mt-1 text-[11.5px] text-muted truncate">
        {!live ? (
          <span role="status" className="font-semibold text-saffron-ink">{wsStatus}</span>
        ) : attached ? (
          `${serving!.rat ?? "NR5G"} · ${serving!.band} · ${carriers.length || 1}CA`
        ) : (
          "Searching for signal…"
        )}
      </div>
      <FailoverBadge compact className="mt-2" />
      <div className="mt-3 grid grid-cols-2 gap-2">
        <div className="rounded-xl bg-jade-soft px-2.5 py-1.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-jade-ink">Down</div>
          <div className="text-[13px] font-bold text-jade-ink">{formatBitrate(traffic.rxBps)}</div>
        </div>
        <div className="rounded-xl bg-berry-soft px-2.5 py-1.5">
          <div className="text-[10px] font-bold uppercase tracking-wider text-berry-ink">Up</div>
          <div className="text-[13px] font-bold text-berry-ink">{formatBitrate(traffic.txBps)}</div>
        </div>
      </div>
    </div>
  );
}

/** Pill for top bars and phones. */
function LinkPill({ className }: { className?: string }) {
  const { traffic, serving, dot, live, wsStatus } = useLink();
  const failover = useFailoverActive();
  return (
    <a
      href="#/"
      title={failover ? "Carrying failover traffic" : undefined}
      className={cn("flex items-center gap-2 whitespace-nowrap rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] font-semibold text-ink qm-tabular", failover && "border-saffron/60", className)}
    >
      {failover && <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-saffron-ink" aria-label="Carrying failover traffic" />}
      <LiveDot tone={dot} className="hidden sm:inline-block" />
      {/* Phones: the failover shield takes the signal bars' place to keep the header on one line. */}
      <SignalBars rsrp={serving?.rsrp} className={failover ? "hidden sm:inline-flex" : undefined} />
      {!live && <span className="text-saffron-ink" title={wsStatus}>{wsStatus.split(" ·")[0]}</span>}
      <span className="hidden min-[400px]:inline">{serving?.band ?? "--"}</span>
      <span className="text-jade-ink">↓{formatBitrate(traffic.rxBps)}</span>
      <span className="hidden xl:inline text-berry-ink">↑{formatBitrate(traffic.txBps)}</span>
    </a>
  );
}

/** Status line for the dock layout: a terminal-style readout across the top. */
function StatusLine({ onSearch }: { onSearch: () => void }) {
  const { modem, traffic, wsStatus, serving, carriers, dot, live } = useLink();
  const failover = useFailoverActive();
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(t);
  }, []);
  const attached = Boolean(serving && serving.rat && serving.rat !== "UNKNOWN" && serving.band && serving.band !== "-");
  const cells = [
    modem?.operator || "searching",
    !live ? wsStatus.toUpperCase() : attached ? `${serving!.rat ?? "NR5G"} ${serving!.band}` : "searching",
    attached ? `${carriers.length || 1}CA` : null,
    serving?.rsrp != null ? `RSRP ${serving.rsrp}` : null,
    serving?.sinr != null ? `SINR ${serving.sinr}` : null,
  ].filter(Boolean);
  return (
    <div className="sticky top-0 z-20 hidden lg:flex items-center gap-4 border-b border-line bg-paper/85 backdrop-blur-md px-8 h-10 text-[12px] font-mono qm-tabular">
      <LiveDot tone={dot} />
      <div className="flex items-center gap-3 text-ink-2 min-w-0 truncate">
        {cells.map((c, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span className="text-line-strong">/</span>}
            <span className={i === 0 ? "font-bold text-ink" : undefined}>{c}</span>
          </React.Fragment>
        ))}
      </div>
      <div className="ml-auto flex items-center gap-4">
        {failover && <span className="font-bold text-saffron-ink">FAILOVER</span>}
        <span className="text-jade-ink">↓ {formatBitrate(traffic.rxBps)}</span>
        <span className="text-berry-ink">↑ {formatBitrate(traffic.txBps)}</span>
        <button type="button" onClick={onSearch} className="flex items-center gap-1.5 text-muted hover:text-ink cursor-pointer">
          <Search className="h-3.5 w-3.5" /> <Kbd>⌘K</Kbd>
        </button>
        <span className="text-muted">{now.toLocaleTimeString([], { hour12: false })}</span>
      </div>
    </div>
  );
}

/* ───────────────────────── Appearance ───────────────────────── */

function Swatch({ bg, className }: { bg: string; className?: string }) {
  return <span className={cn("block rounded-lg ring-1 ring-black/10", className)} style={{ background: bg }} />;
}

function AppearanceButton({ onClick, compact = false }: { onClick: () => void; compact?: boolean }) {
  const skin = useThemeStore((s) => s.skin);
  const meta = skinMeta(skin);
  if (compact) {
    return (
      <Button variant="ghost" size="sm" className="px-2" onClick={onClick} aria-label="Appearance" title={`Appearance: ${meta.label}`}>
        <Swatch bg={meta.swatch} className="h-4 w-4 rounded-md" />
      </Button>
    );
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center gap-2.5 rounded-xl border border-line bg-surface/60 px-2.5 py-2 text-left hover:border-line-strong transition cursor-pointer"
    >
      <Swatch bg={meta.swatch} className="h-7 w-7" />
      <span className="min-w-0 flex-1">
        <span className="block text-[12.5px] font-bold text-ink truncate">{meta.label}</span>
        <span className="block text-[11px] text-muted">Appearance</span>
      </span>
      <Palette className="h-4 w-4 text-muted" />
    </button>
  );
}

function AppearanceDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return <AppearanceDialogInner onClose={onClose} />;
}

function AppearanceDialogInner({ onClose }: { onClose: () => void }) {
  const { skin, setSkin, theme, setTheme, layoutPref, setLayoutPref } = useThemeStore();
  const meta = skinMeta(skin);
  return (
    <Modal open onClose={onClose} title="Appearance">
      <div className="space-y-5">
        <div>
          <div className="qm-eyebrow mb-2">Theme ({SKINS.length})</div>
          <div className="grid max-h-[44vh] grid-cols-2 gap-2 overflow-y-auto pr-1">
            {SKINS.map((sk) => {
              const on = sk.id === skin;
              return (
                <button
                  key={sk.id}
                  type="button"
                  onClick={() => setSkin(sk.id)}
                  aria-pressed={on}
                  className={cn(
                    "flex items-center gap-2.5 rounded-xl border p-2 text-left transition cursor-pointer",
                    on ? "border-ember bg-ember-soft" : "border-line hover:border-line-strong"
                  )}
                >
                  <Swatch bg={sk.swatch} className="h-9 w-9 shrink-0" />
                  <span className="min-w-0">
                    <span className={cn("block text-[13px] font-bold truncate", on ? "text-ember-ink" : "text-ink")}>{sk.label}</span>
                    <span className="block text-[11px] text-muted truncate">{sk.hint}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <div className="qm-eyebrow mb-2">Mode</div>
            <div className="grid grid-cols-2 gap-1.5">
              {(["light", "dark"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  disabled={meta.darkOnly}
                  onClick={() => setTheme(m)}
                  className={cn(
                    "flex items-center justify-center gap-1.5 rounded-xl border py-2 text-[12.5px] font-bold capitalize transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed",
                    theme === m && !meta.darkOnly ? "border-ember bg-ember-soft text-ember-ink" : "border-line text-ink-2"
                  )}
                >
                  {m === "light" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
                  {m}
                </button>
              ))}
            </div>
            {meta.darkOnly && <p className="mt-1.5 text-[11.5px] text-muted">{meta.label} has one look.</p>}
          </div>
          <div>
            <div className="qm-eyebrow mb-2">Layout</div>
            <div className="space-y-1">
              {LAYOUTS.map((l) => {
                const on = l.id === layoutPref;
                return (
                  <button
                    key={l.id}
                    type="button"
                    onClick={() => setLayoutPref(l.id)}
                    className={cn(
                      "flex w-full items-center justify-between rounded-lg px-2.5 py-1.5 text-[12.5px] font-semibold transition cursor-pointer",
                      on ? "bg-ember-soft text-ember-ink" : "text-ink-2 hover:bg-sunk"
                    )}
                  >
                    <span>
                      {l.label}
                      {l.id === "auto" && <span className="ml-1 font-normal text-muted">({LAYOUTS.find((x) => x.id === meta.layout)?.label})</span>}
                    </span>
                    {on && <Check className="h-3.5 w-3.5" />}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </Modal>
  );
}

/* ───────────────────────── Global Actionable Status Banners ───────────────────────── */

const GlobalStatusBanners = React.memo(function GlobalStatusBanners() {
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const failover = useObsStore((s) => s.failover);
  const rxBps = useWsStore((s) => s.traffic.rxBps);
  const txBps = useWsStore((s) => s.traffic.txBps);
  const modemBypassed = useWsStore((s) =>
    Boolean((s.modem as (typeof s.modem & { cellLockBypassed?: boolean }) | null)?.cellLockBypassed)
  );
  const [confirmingSlot, setConfirmingSlot] = useState(false);
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));

  const abQuery = useQuery<FirmwareAbStatus>({
    queryKey: ["firmware-ab"],
    queryFn: getFirmwareAbStatus,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: false,
  });

  const pulseQuery = useQuery<OverviewPulse>({
    queryKey: ["overview-pulse"],
    queryFn: () => apiFetch<OverviewPulse>("/api/v1/overview/pulse"),
    staleTime: 25_000,
    refetchInterval: 30_000,
    retry: false,
  });

  const failoverActive = Boolean(failover?.active);
  useEffect(() => {
    if (!failoverActive) return;
    setNowSec(Math.floor(Date.now() / 1000));
    const t = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 5_000);
    return () => window.clearInterval(t);
  }, [failoverActive]);

  const trialBootActive = abQuery.data?.trialBootActive === true;
  const activeSlotLabel = abQuery.data?.activeSlot
    ? abQuery.data.activeSlot.replace(/^_/, "").toUpperCase()
    : "active";
  const cellLockBypassed = modemBypassed || Boolean(pulseQuery.data?.cellLock?.bypassed);
  const bypassReason = pulseQuery.data?.cellLock?.bypassReason?.trim() || "";

  async function handleConfirmSlot() {
    if (confirmingSlot) return;
    setConfirmingSlot(true);
    try {
      await confirmFirmwareAbSlot();
      await qc.invalidateQueries({ queryKey: ["firmware-ab"] });
      toast("Active firmware slot confirmed", "success", `Slot ${activeSlotLabel} marked permanently bootable.`);
    } catch (e) {
      toast("Could not confirm slot", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setConfirmingSlot(false);
    }
  }

  if (!trialBootActive && !failoverActive && !cellLockBypassed) {
    return null;
  }

  const liveBps = rxBps + txBps > 0 ? rxBps + txBps : (failover?.avgBps ?? 0);
  const epBytes = failover?.episode?.bytes ?? null;
  const epDuration =
    failover?.episode?.startedAt != null
      ? formatDuration(Math.max(0, nowSec - failover.episode.startedAt))
      : null;

  return (
    <div
      role="region"
      aria-label="Critical gateway status"
      className="border-b border-line bg-paper/90 backdrop-blur-sm"
    >
      <div className="divide-y divide-line/60">
        {trialBootActive && (
          <div
            role="status"
            className="flex flex-wrap items-center justify-between gap-2.5 bg-saffron-soft/85 px-4 py-2 text-[12.5px] text-saffron-ink sm:px-6 lg:px-10"
          >
            <div className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span className="font-semibold">
                Trial boot active on Slot {activeSlotLabel} — confirm once stable
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 shrink-0">
              <Button
                variant="secondary"
                size="sm"
                className="h-7 px-2.5 text-[11.5px]"
                onClick={() => void handleConfirmSlot()}
                disabled={confirmingSlot}
              >
                {confirmingSlot ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-3.5 w-3.5" />
                )}
                {confirmingSlot ? "Confirming…" : "Confirm Slot"}
              </Button>
              <a
                href={hrefFor("/system", "ota")}
                className="inline-flex h-7 items-center rounded-full border border-saffron/40 bg-surface/80 px-2.5 text-[11.5px] font-semibold text-saffron-ink hover:bg-surface transition"
              >
                Open A/B Updates
              </a>
            </div>
          </div>
        )}

        {failoverActive && (
          <div
            role="status"
            className="flex flex-wrap items-center justify-between gap-2 bg-saffron-soft/65 px-4 py-1.5 text-[12px] text-saffron-ink sm:px-6 lg:px-10 qm-tabular"
          >
            <div className="flex items-center gap-2 min-w-0">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              <span className="font-bold tracking-wide">FAILOVER ACTIVE</span>
              <span>· {formatBitrate(liveBps)}</span>
              {epBytes != null && (
                <span>
                  · {formatBytes(epBytes, 1)}
                  {epDuration ? ` (${epDuration})` : ""}
                </span>
              )}
            </div>
            <a
              href={hrefFor("/diagnostics", "events")}
              className="shrink-0 text-[11.5px] font-bold underline decoration-saffron/50 underline-offset-2 hover:decoration-current"
            >
              View events →
            </a>
          </div>
        )}

        {cellLockBypassed && (
          <div
            role="alert"
            className="flex flex-wrap items-center justify-between gap-2 bg-crimson-soft/80 px-4 py-1.5 text-[12px] text-crimson-ink sm:px-6 lg:px-10"
          >
            <div className="flex items-center gap-2 min-w-0">
              <Lock className="h-3.5 w-3.5 shrink-0" />
              <span className="font-semibold">
                Cell-lock dead-man switch bypassed
                {bypassReason ? ` · ${bypassReason}` : " — modem temporarily roaming freely"}
              </span>
            </div>
            <a
              href={hrefFor("/cellular", "lock")}
              className="inline-flex h-7 shrink-0 items-center rounded-full border border-crimson/40 bg-surface/80 px-2.5 text-[11.5px] font-semibold text-crimson-ink hover:bg-surface transition"
            >
              Inspect Cell Lock
            </a>
          </div>
        )}
      </div>
    </div>
  );
});

/* ───────────────────────── Live WS Alerts Strip ───────────────────────── */

function AlertsStrip() {
  const alerts = useWsStore((s) => s.alerts);
  const dismissAlert = useWsStore((s) => s.dismissAlert);
  const clearAlerts = useWsStore((s) => s.clearAlerts);

  if (alerts.length === 0) return null;

  return (
    <div className="space-y-2" role="region" aria-label="Live gateway alerts">
      {alerts.slice(0, 3).map((a, idx) => {
        const isCritical = a.type === "cell-lock-alert" || /bypass|fail|down|error|critical|ssr/i.test(a.message);
        return (
          <div
            key={`${a.type}-${a.timestamp}-${idx}`}
            role="alert"
            className={cn(
              "flex items-start gap-2.5 rounded-2xl border px-3.5 py-2.5 text-[12.5px] leading-snug qm-rise",
              isCritical
                ? "border-crimson/45 bg-crimson-soft text-crimson-ink"
                : "border-saffron/45 bg-saffron-soft text-saffron-ink"
            )}
          >
            {isCritical ? (
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            ) : (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            )}
            <div className="min-w-0 flex-1">
              <span className="font-bold uppercase tracking-wide text-[10.5px] mr-2 opacity-85">
                {a.type.replace(/-/g, " ")}
              </span>
              <span className="font-medium break-words">{a.message}</span>
              {a.timestamp && (
                <span className="ml-2 text-[11px] opacity-75 qm-tabular">{a.timestamp}</span>
              )}
            </div>
            <div className="flex items-center gap-1 shrink-0">
              {idx === 0 && alerts.length > 1 && (
                <button
                  type="button"
                  onClick={clearAlerts}
                  className="rounded-full px-2 py-0.5 text-[11px] font-semibold hover:bg-black/10 dark:hover:bg-white/10 cursor-pointer"
                >
                  Clear all ({alerts.length})
                </button>
              )}
              <button
                type="button"
                onClick={() => dismissAlert(idx)}
                aria-label="Dismiss alert"
                className="rounded-full p-1 hover:bg-black/10 dark:hover:bg-white/10 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ───────────────────────── Shell ───────────────────────── */

export function AppShell({ route, children }: { route: NavRoute; onNavigate?: (r: NavRoute) => void; children: React.ReactNode }) {
  const [rebootModal, setRebootModal] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [appearanceOpen, setAppearanceOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  const theme = useThemeStore((s) => s.theme);
  const toggleTheme = useThemeStore((s) => s.toggleTheme);
  const skin = useThemeStore((s) => s.skin);
  const setSkin = useThemeStore((s) => s.setSkin);
  const layoutPref = useThemeStore((s) => s.layoutPref);
  const setLayoutPref = useThemeStore((s) => s.setLayoutPref);
  const layout = resolveLayout(skin, layoutPref);
  const darkOnly = Boolean(skinMeta(skin).darkOnly);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const sub = useRouteStore((s) => s.sub);
  const toast = useToastStore((s) => s.push);

  const publicIp = useWsStore((s) => s.modem?.publicIp ?? null);
  const modelName = useWsStore((s) => s.modem?.identity?.model || "RM551E-GL");
  const hydrateBootstrap = useWsStore((s) => s.hydrateBootstrap);

  // Failover state + recent events (the WebSocket keeps them fresh after this).
  useEffect(() => {
    void useObsStore.getState().load();
  }, []);

  useEffect(() => {
    if (!mobileMenuOpen) return;
    const onPointerDown = (e: PointerEvent) => {
      if (mobileMenuRef.current && !mobileMenuRef.current.contains(e.target as Node)) {
        setMobileMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileMenuOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [mobileMenuOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const onLogout = useCallback(async () => {
    try {
      await apiFetch("/api/v1/auth/logout", { method: "POST", body: "{}" });
    } catch {
      // always clear client state
    } finally {
      clearAuth();
    }
  }, [clearAuth]);

  async function handleReboot() {
    setRebooting(true);
    try {
      await disruptiveFetch("reboot", "/api/v1/system/reboot", { method: "POST", body: JSON.stringify({ confirm: true }) }, { confirmed: true });
      toast("Rebooting gateway", "info", "The console will reconnect in about a minute.");
    } catch (err) {
      if (!isCancelled(err)) toast("Reboot failed", "error", err instanceof Error ? err.message : undefined);
    } finally {
      setRebooting(false);
      setRebootModal(false);
    }
  }

  const actions = useMemo<PaletteAction[]>(
    () => [
      {
        id: "speedtest",
        label: "Run a speedtest",
        hint: "Native Cloudflare throughput + loaded latency grade",
        keywords: "speed test bandwidth cloudflare bufferbloat",
        icon: <Gauge className="h-4 w-4" />,
        run: () => {
          window.location.hash = hrefFor("/diagnostics", "speedtest");
          disruptiveFetch("speedtest", "/api/v1/speedtest/start", { method: "POST", body: "{}" })
            .then(() => toast("Speedtest started", "success"))
            .catch((e) => {
              if (!isCancelled(e)) toast("Speedtest failed to start", "error", e instanceof Error ? e.message : undefined);
            });
        },
      },
      {
        id: "refresh",
        label: "Refresh radio telemetry",
        hint: "Re-poll serving cell, carriers and MIMO",
        keywords: "reload rf signal",
        icon: <RefreshCw className="h-4 w-4" />,
        run: () => {
          apiFetch("/api/v1/modem/refresh", { method: "POST", body: "{}" })
            .then(() => hydrateBootstrap())
            .then(() => toast("Telemetry refreshed", "success"))
            .catch(() => toast("Refresh failed", "error"));
        },
      },
      {
        id: "at",
        label: "Open AT console",
        hint: "Send a raw AT command",
        keywords: "terminal",
        icon: <Terminal className="h-4 w-4" />,
        run: () => (window.location.hash = hrefFor("/diagnostics", "at")),
      },
      {
        id: "diagnostic-snapshot",
        label: "Download diagnostic snapshot",
        hint: "Redacted JSON bundle (zero IMEI, ICCID, or tokens)",
        keywords: "diagnostics snapshot export bundle debug json support redacted",
        icon: <FileDown className="h-4 w-4" />,
        run: () => {
          toast("Capturing diagnostic snapshot…", "info");
          apiFetch<unknown>("/api/v1/diagnostics/snapshot")
            .then((data) => {
              const now = new Date();
              const pad = (n: number) => String(n).padStart(2, "0");
              const filename = `cellcore-diag-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}.json`;
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = filename;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
              toast("Diagnostic snapshot downloaded", "success", `${filename} · Redacted (zero IMEI, ICCID, or tokens)`);
            })
            .catch((e) => {
              toast("Diagnostic snapshot failed", "error", e instanceof Error ? e.message : "Could not capture snapshot");
            });
        },
      },
      {
        id: "copy-ip",
        label: "Copy public IP",
        hint: publicIp ?? "Not known yet",
        keywords: "address wan",
        icon: <Copy className="h-4 w-4" />,
        run: () => {
          if (publicIp) void copyToClipboard(publicIp).then(() => toast("Public IP copied", "success", publicIp));
        },
      },
      {
        id: "appearance",
        label: "Appearance…",
        hint: "Theme, light/dark and layout",
        keywords: "theme skin layout look style",
        icon: <Palette className="h-4 w-4" />,
        run: () => setAppearanceOpen(true),
      },
      ...SKINS.map((sk) => ({
        id: `skin-${sk.id}`,
        label: `Theme: ${sk.label}${sk.id === skin ? " (current)" : ""}`,
        hint: sk.hint,
        keywords: "theme skin style look palette design",
        icon: <Palette className="h-4 w-4" />,
        run: () => setSkin(sk.id),
      })),
      ...LAYOUTS.map((l) => ({
        id: `layout-${l.id}`,
        label: `Layout: ${l.label}${l.id === layoutPref ? " (current)" : ""}`,
        hint: l.hint,
        keywords: "layout navigation sidebar topbar dock",
        icon: <Palette className="h-4 w-4" />,
        run: () => setLayoutPref(l.id),
      })),
      ...(!darkOnly
        ? [
            {
              id: "theme",
              label: theme === "dark" ? "Switch to light mode" : "Switch to dark mode",
              keywords: "theme dark light mode",
              icon: theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />,
              run: toggleTheme,
            },
          ]
        : []),
      {
        id: "reboot",
        label: "Reboot gateway…",
        hint: "Asks for confirmation",
        keywords: "restart power",
        icon: <Power className="h-4 w-4" />,
        tone: "danger",
        run: () => setRebootModal(true),
      },
      { id: "logout", label: "Sign out", keywords: "logout", icon: <LogOut className="h-4 w-4" />, run: () => void onLogout() },
    ],
    [darkOnly, hydrateBootstrap, layoutPref, onLogout, publicIp, setLayoutPref, setSkin, skin, theme, toast, toggleTheme]
  );

  const activeSection = sectionFor(route as Section);
  /** Section sharing this phone tab (System ⇄ Admin), linked from the phone header. */
  const mobileSibling =
    NAV.find((s) => s.mobileTab === activeSection.route) ??
    (activeSection.mobileTab ? sectionFor(activeSection.mobileTab) : undefined);
  const subActive = (secRoute: Section, id: string, idx: number) => {
    const sec = sectionFor(secRoute);
    return sub === id || (!sec.subs.some((x) => x.id === sub) && idx === 0);
  };
  const modeButton = !darkOnly && (
    <Button variant="ghost" size="sm" className="px-2.5" onClick={toggleTheme} aria-label="Toggle light or dark mode" title="Light / dark">
      {theme === "dark" ? <Sun className="h-4 w-4 text-saffron" /> : <Moon className="h-4 w-4" />}
    </Button>
  );

  /* ── Sidebar layout ── */
  const rail = (
    <aside className="hidden lg:flex lg:w-[264px] shrink-0 flex-col gap-4 sticky top-0 h-screen px-4 py-5 border-r border-line/70">
      <a href="#/" className="px-1">
        <BrandLogo subtitle={modelName} />
      </a>
      <LinkCapsule />
      <button
        type="button"
        onClick={() => setPaletteOpen(true)}
        className="flex items-center gap-2 rounded-xl border border-line bg-surface/60 px-3 py-2 text-[12.5px] text-muted hover:border-line-strong hover:text-ink transition cursor-pointer"
      >
        <Search className="h-3.5 w-3.5" />
        <span className="flex-1 text-left">Jump to…</span>
        <Kbd>⌘K</Kbd>
      </button>
      <nav className="flex-1 overflow-y-auto -mx-1 px-1 space-y-0.5" aria-label="Primary">
        {NAV.map((sec) => {
          const active = sec.route === route;
          return (
            <div key={sec.route}>
              <a
                href={hrefFor(sec.route)}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "group flex items-center gap-3 rounded-xl px-3 py-2 text-[14px] font-semibold transition",
                  active ? "bg-surface text-ink shadow-[var(--qm-shadow)]" : "text-ink-2 hover:bg-surface/70 hover:text-ink"
                )}
              >
                <span className={cn("flex h-7 w-7 items-center justify-center rounded-lg transition", active ? "qm-sun text-on-ember" : "bg-sunk text-muted group-hover:text-ember-ink")}>
                  <NavIcon name={sec.icon} className="h-4 w-4" />
                </span>
                {sec.label}
              </a>
              {active && sec.subs.length > 0 && (
                <div className="ml-[1.6rem] mt-1 mb-2 border-l border-line pl-3 space-y-0.5">
                  {sec.subs.map((s, i) => {
                    const on = subActive(sec.route, s.id, i);
                    return (
                      <a
                        key={s.id}
                        href={hrefFor(sec.route, s.id)}
                        className={cn("relative block rounded-lg px-2.5 py-1.5 text-[13px] transition", on ? "font-bold text-ember-ink bg-ember-soft" : "font-medium text-muted hover:text-ink")}
                      >
                        {on && <span className="absolute -left-[13.5px] top-1.5 bottom-1.5 w-[3px] rounded-full qm-sun" />}
                        {s.label}
                      </a>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>
      <AppearanceButton onClick={() => setAppearanceOpen(true)} />
      <div className="flex items-center gap-1 border-t border-line/70 pt-3">
        {modeButton}
        <Button variant="ghost" size="sm" className="px-2.5 text-crimson-ink" onClick={() => setRebootModal(true)} aria-label="Reboot gateway" title="Reboot gateway">
          <Power className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm" className="ml-auto" onClick={onLogout}>
          <LogOut className="h-3.5 w-3.5" />
          Sign out
        </Button>
      </div>
    </aside>
  );

  /* ── Top-bar layout ── */
  const topbar = (
    <header className="hidden lg:block sticky top-0 z-30 border-b border-line bg-paper/90 backdrop-blur-md">
      {/* Budgeted so the row never overflows at >= 1024 px (lg) with every section (Admin included) and a
          long link readout: below xl the brand collapses to its mark; only the active section shows its
          label (every item keeps aria-label/title); the link pill and the nav may shrink, never the buttons. */}
      <div className="mx-auto flex h-16 max-w-[1360px] items-center gap-3 px-5 xl:gap-5 xl:px-8">
        <a href="#/" className="shrink-0" aria-label="CellCore" title="CellCore">
          <span className="xl:hidden">
            <BrandLogo compact />
          </span>
          <span className="hidden xl:block">
            <BrandLogo />
          </span>
        </a>
        <nav className="flex min-w-0 items-center gap-1" aria-label="Primary">
          {NAV.map((sec) => {
            const active = sec.route === route;
            return (
              <a
                key={sec.route}
                href={hrefFor(sec.route)}
                aria-current={active ? "page" : undefined}
                aria-label={sec.label}
                title={sec.label}
                className={cn(
                  "flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-2 text-[13px] font-bold transition xl:gap-2 xl:px-3.5 xl:text-[13.5px]",
                  active ? "bg-ink text-paper" : "text-ink-2 hover:bg-sunk hover:text-ink"
                )}
              >
                <NavIcon name={sec.icon} className="h-4 w-4 shrink-0" />
                <span className="xl:hidden">{sec.short}</span>
                <span className="hidden xl:inline">{sec.label}</span>
              </a>
            );
          })}
        </nav>
        <div className="ml-auto flex min-w-0 items-center gap-1.5 [&>*:not(:first-child)]:shrink-0">
          <LinkPill className="min-w-0 overflow-hidden" />
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex items-center gap-2 rounded-full border border-line px-3 py-1.5 text-[12.5px] text-muted hover:text-ink hover:border-line-strong transition cursor-pointer"
          >
            <Search className="h-3.5 w-3.5" /> <Kbd>⌘K</Kbd>
          </button>
          <AppearanceButton compact onClick={() => setAppearanceOpen(true)} />
          {modeButton}
          <Button variant="ghost" size="sm" className="px-2.5 text-crimson-ink" onClick={() => setRebootModal(true)} aria-label="Reboot gateway" title="Reboot gateway">
            <Power className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" className="px-2.5" onClick={onLogout} aria-label="Sign out" title="Sign out">
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {activeSection.subs.length > 0 && (
        <div className="border-t border-line/70">
          <nav className="mx-auto flex max-w-[1360px] flex-wrap items-center gap-x-6 px-6 xl:px-8" aria-label={`${activeSection.label} sections`}>
            {activeSection.subs.map((s, i) => {
              const on = subActive(activeSection.route, s.id, i);
              return (
                <a
                  key={s.id}
                  href={hrefFor(activeSection.route, s.id)}
                  className={cn(
                    "relative shrink-0 whitespace-nowrap py-2.5 text-[13px] font-semibold transition",
                    on ? "text-ink" : "text-muted hover:text-ink"
                  )}
                >
                  {s.label}
                  {on && <span className="absolute inset-x-0 -bottom-px h-[3px] rounded-full qm-sun" />}
                </a>
              );
            })}
          </nav>
        </div>
      )}
    </header>
  );

  /* ── Dock layout ── */
  const dock = (
    <aside className="hidden lg:flex w-[84px] shrink-0 flex-col items-center gap-2 sticky top-0 h-screen py-4 border-r border-line bg-surface/50">
      <a href="#/" className="mb-3" title="CellCore">
        <BrandMark />
      </a>
      <nav className="flex flex-col items-center gap-1" aria-label="Primary">
        {NAV.map((sec) => {
          const active = sec.route === route;
          return (
            <a
              key={sec.route}
              href={hrefFor(sec.route)}
              aria-current={active ? "page" : undefined}
              title={sec.hint}
              className={cn("flex w-[68px] flex-col items-center gap-1 rounded-xl py-2 text-[10.5px] font-bold transition", active ? "text-ink" : "text-muted hover:text-ink")}
            >
              <span className={cn("flex h-9 w-9 items-center justify-center rounded-xl transition", active ? "qm-sun text-on-ember shadow-[var(--qm-shadow-pop)]" : "bg-sunk")}>
                <NavIcon name={sec.icon} className="h-[1.1rem] w-[1.1rem]" />
              </span>
              {sec.short}
            </a>
          );
        })}
      </nav>
      <div className="mt-auto flex flex-col items-center gap-1">
        <Button variant="ghost" size="sm" className="px-2.5" onClick={() => setPaletteOpen(true)} aria-label="Search" title="Jump to… (⌘K)">
          <Search className="h-4 w-4" />
        </Button>
        <AppearanceButton compact onClick={() => setAppearanceOpen(true)} />
        {modeButton}
        <Button variant="ghost" size="sm" className="px-2.5 text-crimson-ink" onClick={() => setRebootModal(true)} aria-label="Reboot gateway" title="Reboot gateway">
          <Power className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm" className="px-2.5" onClick={onLogout} aria-label="Sign out" title="Sign out">
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </aside>
  );

  return (
    <div className={cn("min-h-screen", layout !== "top" && "lg:flex")}>
      {layout === "rail" && rail}
      {layout === "dock" && dock}
      {layout === "top" && topbar}

      {/* Phones: compact top bar (all layouts) */}
      <header className="lg:hidden sticky top-0 z-30 flex items-center justify-between gap-2 border-b border-line/70 bg-paper/85 px-4 py-2.5 backdrop-blur-md">
        <div className="flex min-w-0 items-center gap-2">
          <a href="#/" className="flex items-center gap-2">
            <BrandMark className="h-8 w-8" />
            <span className="qm-display text-[1.05rem]">{activeSection.label}</span>
          </a>
          {mobileSibling && (
            <a
              href={hrefFor(mobileSibling.route)}
              className="shrink-0 whitespace-nowrap rounded-full border border-line bg-surface px-2.5 py-1 text-[11.5px] font-semibold text-ink-2 hover:text-ink"
            >
              {mobileSibling.label} ›
            </a>
          )}
        </div>
        <div className="flex items-center gap-1">
          <LinkPill />
          <Button variant="ghost" size="sm" className="px-2" onClick={() => setPaletteOpen(true)} aria-label="Search">
            <Search className="h-4 w-4" />
          </Button>
          <div ref={mobileMenuRef} className="relative">
            <Button
              variant="ghost"
              size="sm"
              className="px-2"
              onClick={() => setMobileMenuOpen((v) => !v)}
              aria-label="Quick actions"
              aria-expanded={mobileMenuOpen}
              aria-haspopup="menu"
            >
              <MoreVertical className="h-4 w-4" />
            </Button>
            {mobileMenuOpen && (
              <div
                role="menu"
                className="qm-card qm-dialog qm-rise absolute right-0 top-full mt-2 w-52 p-1.5 shadow-[var(--qm-shadow-pop)] z-50"
              >
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    setAppearanceOpen(true);
                  }}
                  className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-semibold text-ink hover:bg-sunk cursor-pointer"
                >
                  <Palette className="h-4 w-4 text-muted" />
                  Appearance…
                </button>
                {!darkOnly && (
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMobileMenuOpen(false);
                      toggleTheme();
                    }}
                    className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-semibold text-ink hover:bg-sunk cursor-pointer"
                  >
                    {theme === "dark" ? <Sun className="h-4 w-4 text-saffron" /> : <Moon className="h-4 w-4 text-muted" />}
                    {theme === "dark" ? "Light mode" : "Dark mode"}
                  </button>
                )}
                <div className="my-1 border-t border-line" />
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    setRebootModal(true);
                  }}
                  className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-semibold text-crimson-ink hover:bg-crimson-soft cursor-pointer"
                >
                  <Power className="h-4 w-4" />
                  Reboot gateway…
                </button>
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    void onLogout();
                  }}
                  className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-semibold text-ink-2 hover:bg-sunk hover:text-ink cursor-pointer"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="min-w-0 flex-1">
        {layout === "dock" && <StatusLine onSearch={() => setPaletteOpen(true)} />}
        <GlobalStatusBanners />
        <div className={cn("px-4 sm:px-6 lg:px-10 pt-5 pb-28 lg:pb-12", layout === "rail" ? "lg:pt-9" : "lg:pt-8")}>
          <div className={cn("mx-auto w-full space-y-6", layout === "rail" ? "max-w-[1240px]" : "max-w-[1320px]")}>
            <AlertsStrip />
            <div key={route} className="space-y-6 qm-rise">
              {children}
            </div>
          </div>
        </div>
      </main>

      {/* Phones: bottom tab bar (all layouts) */}
      <nav className="lg:hidden fixed bottom-0 inset-x-0 z-30 border-t border-line bg-surface/92 backdrop-blur-md pb-[env(safe-area-inset-bottom)]" aria-label="Primary">
        <div className="grid grid-cols-5">
          {NAV.filter((sec) => !sec.mobileTab).map((sec) => {
            const active = sec.route === route || activeSection.mobileTab === sec.route;
            return (
              <a
                key={sec.route}
                href={hrefFor(sec.route)}
                aria-current={active ? "page" : undefined}
                className={cn("flex flex-col items-center gap-0.5 py-2 text-[10.5px] font-bold transition", active ? "text-ember-ink" : "text-muted")}
              >
                <span className={cn("flex h-7 w-11 items-center justify-center rounded-full transition", active && "qm-sun text-on-ember")}>
                  <NavIcon name={sec.icon} className="h-4 w-4" />
                </span>
                {sec.short}
              </a>
            );
          })}
        </div>
      </nav>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} actions={actions} />
      <AppearanceDialog open={appearanceOpen} onClose={() => setAppearanceOpen(false)} />

      <Modal open={rebootModal} onClose={() => setRebootModal(false)} title="Reboot the gateway?">
        <FailoverWarning action="Rebooting" />
        <p className="mt-3">
          OpenWrt and the cellular modem restart together. The cellular session drops for about a minute, and the backup WAN is unavailable until the modem
          re-attaches.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setRebootModal(false)}>
            Keep running
          </Button>
          <Button variant="danger" onClick={handleReboot} disabled={rebooting}>
            <Power className="h-4 w-4" />
            {rebooting ? "Rebooting…" : "Reboot now"}
          </Button>
        </div>
      </Modal>

      {/* Last in the DOM so it stacks above any page dialog that is still open. */}
      <FailoverConfirmHost />
    </div>
  );
}
