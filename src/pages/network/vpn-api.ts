import { apiFetch } from "../../lib/api";
import { disruptiveFetch } from "../../lib/disruptive";

export const VPN = "/api/v1/vpn";

export type WarpMode = "off" | "modem" | "lan";

export interface PkgJob {
  state: "running" | "succeeded" | "failed" | string;
  package: string;
  action: string;
  startedAt: number;
  finishedAt?: number | null;
  exitCode?: number | null;
  installedAfter?: string | null;
  message?: string | null;
}

export interface PkgJobView {
  job: PkgJob | null;
  log: string[];
}

export interface WarpStatus {
  tools: { wgcf: boolean; wg: boolean; curl: boolean; kernelModule: boolean };
  account: {
    kind: "consumer" | "teams" | null;
    consumer: { deviceId: string; licenseSet: boolean; profileReady: boolean } | null;
    teams: {
      team: string;
      deviceId: string;
      accountType: string;
      organization: string;
      endpoint: string;
      addressV4: string;
      tunnelProtocol: string;
      enrolledAt: number;
    } | null;
  };
  interface: {
    installed: boolean;
    autostart: boolean;
    up: boolean;
    uptime: number | null;
    devicePresent: boolean;
    mtu: number;
    keepalive: number;
    endpointOverride: string | null;
    publicKey: string | null;
    endpoint: string | null;
    handshakeAge: number | null;
    rxBytes: number | null;
    txBytes: number | null;
  };
  policy: {
    mode: WarpMode;
    changedAt: number;
    usable: boolean;
    routeInstalled: boolean;
    failingBack: boolean;
    failbacks: number;
    lastTransition: number;
    lastError: string | null;
    pref: number;
    table: number;
    lanDevice: string;
    rules: Array<{ pref: number; rule: string }>;
    staleSecs: number;
  };
  failoverActive: boolean;
  warnings: string[];
}

export interface WgcfAccount {
  kind: "consumer" | "teams" | null;
  status?: {
    accountId: string;
    accountType: string;
    premiumData: string;
    quota: string;
    role: string;
    devices: Array<{ id: string; current: boolean; kind: string; model: string; name: string; active: boolean; created: string; activated: string; role: string }>;
  };
}

export interface TsPeer {
  hostName: string;
  dnsName: string;
  os: string;
  ips: string[];
  online: boolean;
  active: boolean;
  lastSeen: string | null;
  exitNodeOption: boolean;
  exitNode: boolean;
  rxBytes: number;
  txBytes: number;
}

export interface TsSettings {
  hostname: string;
  acceptRoutes: boolean;
  advertiseRoutes: string[];
  advertiseExitNode: boolean;
  exitNode: string;
  ssh: boolean;
  shieldsUp: boolean;
}

export interface TailscaleStatus {
  package: { name: string; version: string } | null;
  installed: boolean;
  service: { running: boolean; enabledAtBoot: boolean };
  status: {
    backendState: string;
    version: string;
    authUrl: string | null;
    tailnet: string | null;
    magicDnsSuffix: string | null;
    health: string[];
    selfNode: TsPeer | null;
    peers: TsPeer[];
    exitNodeInUse: string | null;
  } | null;
  settings: TsSettings;
  capabilities: { flags: string[]; unsupported: string[]; tiny: boolean; oauthKeys: boolean; dns: boolean };
  lanCidr: string | null;
  warnings: string[];
  warpLanActive: boolean;
  job: PkgJobView;
}

export function vpnPost<T = Record<string, unknown>>(path: string, body: unknown = {}): Promise<T> {
  return apiFetch<T>(`${VPN}${path}`, { method: "POST", body: JSON.stringify(body) });
}

/** POST that the failover guard may hold back (409 → confirm → force). */
export function vpnPostGuarded<T = Record<string, unknown>>(label: string, path: string, body: unknown = {}): Promise<T> {
  return disruptiveFetch<T>(label, `${VPN}${path}`, { method: "POST", body: JSON.stringify(body) });
}

export function ageText(secs: number | null | undefined): string {
  if (secs == null) return "never";
  if (secs < 60) return `${secs} s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
  return `${Math.round(secs / 3600)} h ago`;
}
