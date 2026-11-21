import React from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  Clock,
  Download,
  Droplets,
  Gauge,
  Globe,
  Layers,
  LifeBuoy,
  MessageSquare,
  Network,
  Play,
  Power,
  Radio,
  Router,
  ShieldAlert,
  ShieldCheck,
  Shield,
  Wifi,
  WifiOff,
} from "lucide-react";
import { cn, formatBitrate, formatBytes, formatDuration } from "../lib/utils";
import { useObsStore } from "../stores/obs-store";
import type { EventSeverity, EventType, ObsEvent } from "../types/obs";
import { Badge, Button, Modal, type BadgeVariant } from "./ui";

/* ───────────────────────── Event vocabulary ───────────────────────── */

export type EventGroup = "radio" | "link" | "recovery" | "failover" | "usage" | "system";

export const EVENT_META: Record<EventType, { label: string; group: EventGroup; icon: React.ComponentType<{ className?: string }> }> = {
  handover: { label: "Handover", group: "radio", icon: ArrowLeftRight },
  band_change: { label: "Band change", group: "radio", icon: Radio },
  rat_change: { label: "RAT change", group: "radio", icon: Radio },
  ca_change: { label: "Carrier aggregation", group: "radio", icon: Layers },
  registration_lost: { label: "Registration lost", group: "link", icon: WifiOff },
  registration_regained: { label: "Registration regained", group: "link", icon: Wifi },
  bearer_change: { label: "Data bearer", group: "link", icon: Network },
  public_ip_change: { label: "Public IP", group: "link", icon: Globe },
  quecwatch_recovery: { label: "LinkWatch recovery", group: "recovery", icon: LifeBuoy },
  r10_action: { label: "Router recovery (IPC)", group: "recovery", icon: Router },
  scheduled_reboot: { label: "Scheduled reboot", group: "system", icon: Power },
  daemon_start: { label: "Daemon start", group: "system", icon: Play },
  ota_install: { label: "Update installed", group: "system", icon: Download },
  failover_start: { label: "Failover started", group: "failover", icon: ShieldAlert },
  failover_end: { label: "Failover ended", group: "failover", icon: ShieldCheck },
  work_deferred: { label: "Work deferred", group: "failover", icon: Clock },
  forced_action: { label: "Forced action", group: "failover", icon: AlertTriangle },
  usage_threshold: { label: "Usage threshold", group: "usage", icon: Gauge },
  standby_leak: { label: "Standby leak", group: "usage", icon: Droplets },
  sms_received: { label: "SMS received", group: "system", icon: MessageSquare },
  vpn: { label: "VPN", group: "link", icon: Shield },
  antenna_degraded: { label: "Antenna degraded", group: "radio", icon: AlertTriangle },
  thermal_throttle: { label: "Thermal throttle", group: "system", icon: Gauge },
  sar_backoff: { label: "SAR backoff", group: "radio", icon: Radio },
  air_cipher_null: { label: "Null air cipher", group: "link", icon: ShieldAlert },
  modem_ssr: { label: "Modem SSR", group: "recovery", icon: LifeBuoy },
};

export const EVENT_GROUPS: Array<{ id: EventGroup; label: string }> = [
  { id: "radio", label: "Radio" },
  { id: "link", label: "Link" },
  { id: "recovery", label: "Recovery" },
  { id: "failover", label: "Failover" },
  { id: "usage", label: "Usage" },
  { id: "system", label: "System" },
];

export function eventLabel(t: string): string {
  return EVENT_META[t as EventType]?.label ?? t.replace(/_/g, " ");
}

/** Good news reads as good, not as neutral info. */
const POSITIVE: EventType[] = ["registration_regained", "failover_end"];

export function eventTone(e: Pick<ObsEvent, "type" | "severity">): { badge: BadgeVariant; dot: string; text: string } {
  if (e.severity === "critical") return { badge: "danger", dot: "bg-crimson", text: "text-crimson-ink" };
  if (e.severity === "warning") return { badge: "warning", dot: "bg-saffron", text: "text-saffron-ink" };
  if (POSITIVE.includes(e.type)) return { badge: "success", dot: "bg-jade", text: "text-jade-ink" };
  return { badge: "neutral", dot: "bg-line-strong", text: "text-ink-2" };
}

export function severityLabel(s: EventSeverity): string {
  return s === "critical" ? "Critical" : s === "warning" ? "Warning" : "Info";
}

export function relTime(ts: number, now = Date.now() / 1000): string {
  const d = Math.max(0, Math.round(now - ts));
  if (d < 45) return "just now";
  if (d < 3600) return `${Math.round(d / 60)} min ago`;
  if (d < 86400) return `${Math.round(d / 3600)} h ago`;
  return `${Math.round(d / 86400)} d ago`;
}

export function clockTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

/** One event line: icon, title, meta. */
export function EventRow({ event, showDate = false }: { event: ObsEvent; showDate?: boolean }) {
  const meta = EVENT_META[event.type];
  const Icon = meta?.icon ?? Activity;
  const tone = eventTone(event);
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-line last:border-0 min-w-0">
      <span className={cn("mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-sunk", tone.text)}>
        <Icon className="h-3.5 w-3.5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-semibold text-ink leading-snug break-words">{event.title}</div>
        <div className="mt-0.5 text-[11.5px] text-muted qm-tabular">
          {eventLabel(event.type)} · {showDate ? new Date(event.ts * 1000).toLocaleString() : `${clockTime(event.ts)} · ${relTime(event.ts)}`}
        </div>
      </div>
      {event.severity !== "info" && (
        <Badge variant={tone.badge} className="shrink-0">
          {severityLabel(event.severity)}
        </Badge>
      )}
    </div>
  );
}

/* ───────────────────────── Failover state ───────────────────────── */

export function useFailoverActive(): boolean {
  return useObsStore((s) => Boolean(s.failover?.active));
}

/** Small badge for the shell and the Now hero; renders nothing in standby. */
export function FailoverBadge({ compact = false, className }: { compact?: boolean; className?: string }) {
  const f = useObsStore((s) => s.failover);
  if (!f?.active) return null;
  const why = f.source === "hint" ? "Upstream router reported this link as active" : "Sustained traffic above the baseline";
  return (
    <span title={`Carrying failover traffic. ${why}.`} className={cn("inline-flex", className)}>
      <Badge variant="warning" dot>
        {compact ? "Failover" : "Carrying failover traffic"}
      </Badge>
    </span>
  );
}

/** Inline callout for confirm dialogs of disruptive actions. */
export function FailoverWarning({ action }: { action?: string }) {
  const f = useObsStore((s) => s.failover);
  if (!f?.active) return null;
  const since = f.episode ? formatDuration(Date.now() / 1000 - f.episode.startedAt) : null;
  return (
    <div role="alert" className="flex items-start gap-2.5 rounded-xl bg-crimson-soft px-3 py-2.5 text-crimson-ink">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="text-[12.5px] leading-snug">
        <div className="font-bold">This modem is carrying failover traffic</div>
        <div className="mt-0.5">
          The primary link is down and production traffic runs over cellular{since ? ` (for ${since}` : ""}
          {since ? `, ${formatBytes(f.episode?.bytes ?? 0, 1)} so far)` : ""}. {action ? `${action} will` : "This will"} interrupt it.
        </div>
      </div>
    </div>
  );
}

/** Global confirm dialog used by `disruptiveFetch` when no page dialog was shown. */
export function FailoverConfirmHost() {
  const pending = useObsStore((s) => s.pendingConfirm);
  const resolve = useObsStore((s) => s.resolveConfirm);
  const f = useObsStore((s) => s.failover);
  return (
    <Modal open={pending != null} onClose={() => resolve(false)} title={`Run ${pending?.label ?? "this action"} anyway?`} zIndexClass="z-[65]">
      <div className="space-y-4">
        <FailoverWarning action={pending?.label ? pending.label[0].toUpperCase() + pending.label.slice(1) : undefined} />
        {f && (
          <p className="text-[12.5px] text-muted qm-tabular">
            Current cellular load {formatBitrate(f.avgBps)} · baseline {formatBitrate(f.baselineBps)}
          </p>
        )}
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button variant="secondary" onClick={() => resolve(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => resolve(true)}>
            Run it anyway
          </Button>
        </div>
      </div>
    </Modal>
  );
}
