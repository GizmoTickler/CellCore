/** Types for the observability endpoints (events, failover, usage cycle, notifications). */

export type EventSeverity = "info" | "warning" | "critical";

export type EventType =
  | "handover"
  | "band_change"
  | "rat_change"
  | "ca_change"
  | "registration_lost"
  | "registration_regained"
  | "bearer_change"
  | "public_ip_change"
  | "quecwatch_recovery"
  | "r10_action"
  | "scheduled_reboot"
  | "daemon_start"
  | "ota_install"
  | "failover_start"
  | "failover_end"
  | "work_deferred"
  | "forced_action"
  | "usage_threshold"
  | "standby_leak"
  | "sms_received"
  | "vpn";

export interface ObsEvent {
  id: number;
  /** Unix seconds. */
  ts: number;
  type: EventType;
  severity: EventSeverity;
  title: string;
  detail: Record<string, unknown> | null;
}

export interface EventsResponse {
  events: ObsEvent[];
  stored: number;
  countsSinceStart: Record<string, number>;
  types: EventType[];
}

export interface FailoverEpisode {
  startedAt: number;
  bytes: number;
  source: "hint" | "throughput";
}

export interface FailoverSummary {
  startedAt: number;
  endedAt: number;
  durationSecs: number;
  bytes: number;
  source: "hint" | "throughput";
}

export interface FailoverConfig {
  throughputDetect: boolean;
  baselineBps: number;
  sustainSecs: number;
  releaseSecs: number;
  hintTtlSecs: number;
}

export interface FailoverStatus {
  active: boolean;
  source: "hint" | "throughput" | null;
  since: number;
  avgBps: number;
  baselineBps: number;
  throughputActive: boolean;
  hint: { role: "active" | "standby"; ageSecs: number; fresh: boolean } | null;
  episode: FailoverEpisode | null;
  lastEpisode: FailoverSummary | null;
  episodesTotal: number;
  config: FailoverConfig;
}

export interface UsageCycle {
  cycleDay: number;
  cycleStart: string;
  cycleEnd: string;
  nextCycleStart: string;
  cycleDays: number;
  daysElapsed: number;
  daysRemaining: number;
  rxBytes: number;
  txBytes: number;
  totalBytes: number;
  projectedBytes: number;
  quotaBytes: number | null;
  usedPct: number | null;
  projectedPct: number | null;
  thresholds: number[];
  thresholdsFired: number[];
  today: { date: string; rxBytes: number; txBytes: number };
  daily: Array<{ date: string; rxBytes: number; txBytes: number }>;
  previousCycle: { start: string; end: string; rxBytes: number; txBytes: number; totalBytes: number } | null;
  lifetime: { rxBytes: number; txBytes: number };
  standby: { todayBytes: number; floorBytes: number; alertedToday: boolean };
  alerts: { thresholdsEnabled: boolean; standbyFloorBytes: number };
}

export interface NotifyConfigView {
  enabled: boolean;
  kinds: Record<string, boolean>;
  dedupeSecs: number;
  ratePerHour: number;
  quiet: { enabled: boolean; start: string; end: string; allowCritical: boolean };
  email: { enabled: boolean };
  webhook: { enabled: boolean; url: string; format: "json" | "alertmanager"; headers: Array<{ name: string; valueSet: boolean }> };
  ntfy: { enabled: boolean; url: string; tokenSet: boolean };
  smsForward: { enabled: boolean; intervalSecs: number };
}

export interface NotifyResponse {
  config: NotifyConfigView;
  status: {
    sent: Record<string, number>;
    failed: Record<string, number>;
    suppressed: Record<string, number>;
    dropped: number;
    lastError: { sink: string; error: string; ts: number } | null;
    lastSentAt: number;
    emailReady: boolean;
  };
  types: Array<{ type: EventType; default: boolean }>;
}
