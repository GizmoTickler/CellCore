import React, { useId, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Cloud, Cpu, Gauge, Network, Radio, RefreshCw, Server, ShieldCheck } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { resetAll, useDraft } from "../../lib/draft";
import { RollingNumber, useEffectiveMotion } from "../../lib/motion";
import { cn, formatBytes } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, LiveDot, Select, Skeleton, Switch } from "../../components/ui";
import { FailoverWarning } from "../../components/obs";
import { useObsStore } from "../../stores/obs-store";
import { useToastStore } from "../../stores/toast-store";
import { useWsStore } from "../../stores/ws-store";
import { LoadError, Notice, errText, useGuarded } from "../admin/shared";
import { Fact } from "./VpnParts";

const KEY_STATUS = ["dataplane", "status"];
const KEY_PROFILES = ["dataplane", "profiles"];

interface QrtrServiceEndpoint {
  service: number;
  name: string;
  version: number;
  instance: number;
  node: number;
  port: number;
}

interface NetlinkLink {
  ifindex: number;
  name: string;
  up: boolean;
  lowerUp: boolean;
  mtu: number;
  kind: string | null;
  rmnetMuxId: number | null;
  masterIndex: number | null;
}

interface NetlinkAddr {
  ifindex: number;
  family: number;
  address: string;
  prefixLen: number;
  scope: number;
}

interface WdsFamilySnapshot {
  state: string;
  handle: number | null;
  pktStatus: { status: string; reconfigRequired: boolean; ipFamily: number | null } | null;
  runtime: {
    ipv4Addr: string | null;
    ipv4Gateway: string | null;
    ipv4Dns1: string | null;
    ipv6Addr: string | null;
    ipv6PrefixLen: number | null;
    mtu: number | null;
  } | null;
  lastError: string | null;
}

interface DataplaneStatusResp {
  status: string;
  config: {
    mode: "coexist" | "native";
    iface: string;
    muxId: number;
    epType: number;
    epIfaceId: number;
    profileIndex: number;
    ipFamily: "ipv4" | "ipv6" | "ipv4v6";
    routeTable: number;
    ippt: boolean;
    ipptMac: string | null;
    ipptDevType: string;
    ipptSkipNat: boolean;
    ipptVlan: number;
    manageDns: boolean;
    ipv6PrefixSharing: boolean;
    preserveIpaOffload: boolean;
    kernelTuning: "default" | "high-throughput";
    sfeFastpath?: boolean;
  };
  snapshot: {
    updatedAt: number;
    mode: "coexist" | "native";
    supervisorState: string;
    sfeLoaded?: boolean;
    qrtr: {
      available: boolean;
      localNode: number | null;
      modemNode: number;
      ssrCount: number;
      lastSsrEpoch: number | null;
      services: QrtrServiceEndpoint[];
      error: string | null;
    };
    deviceRev: string | null;
    operatingMode: string | null;
    uim: {
      numSlots: number;
      slots: Array<{ slot: number; cardState: string; pin1State: string; appType: string; appState: string }>;
    } | null;
    nasSys: {
      registered: boolean;
      rat: string;
      endcAvailable: boolean | null;
      ltePsAttached: boolean;
      nr5gPsAttached: boolean;
    } | null;
    nasSignal: {
      lteRsrpDbm: number | null;
      nr5gRsrpDbm: number | null;
      nr5gRsrqDb: number | null;
      nr5gSnrDb: number | null;
    } | null;
    wdaFormat: {
      linkProtocol: number | null;
      ulAggProtocol: number | null;
      dlAggProtocol: number | null;
      dlMaxDatagrams: number | null;
      dlMaxSize: number | null;
      flowControl?: number | null;
    } | null;
    wdsV4: WdsFamilySnapshot;
    wdsV6: WdsFamilySnapshot;
    links: NetlinkLink[];
    addrs: NetlinkAddr[];
    kernel: {
      tcpCongestionControl: string;
      tcpAvailableCongestionControl: string[];
      defaultQdisc: string;
      rmemMax: number | null;
      wmemMax: number | null;
      tcpRmem: string;
      tcpWmem: string;
      netdevMaxBacklog: number | null;
      netdevBudget: number | null;
      tcpSlowStartAfterIdle: number | null;
      tcpMtuProbing: number | null;
      rpsSockFlowEntries: number | null;
      tcpFastopen: number | null;
      conntrackMax: number | null;
      conntrackCount: number | null;
      cpuGovernor: string | null;
      cpuCurFreqMhz: number | null;
      cpuMaxFreqMhz: number | null;
      rpsMaps: Record<string, string>;
      xpsMaps: Record<string, string>;
      ipaDevPresent: boolean;
      ipacmRunning: boolean;
      qcmapRunning: boolean;
      netmgrdRunning: boolean;
      ipaOffload: {
        hwType: string | null;
        clkRateMhz: number | null;
        clockScalingEnabled: boolean | null;
        nominalMbps: number | null;
        turboMbps: number | null;
        napiChainEnabled: boolean | null;
        ethOffloadDriver: string | null;
        ethHwpRxPackets: number | null;
        ethExpRxPackets: number | null;
        ethHwpTxPackets: number | null;
        ethExpTxPackets: number | null;
        ethHardwareOffloadPct: number | null;
      };
      activeTuning: "default" | "high-throughput";
      tuningWarnings: string[];
    };
    appliedDns: string[];
    activeIpptMac: string | null;
    ipaIpptActive: boolean;
    ipaV6SharingPrefix: string | null;
    ipaCliPresent: boolean;
    indicationsReceived: number;
    reconnectAttempts: number;
    netlinkUpdates: number;
    lastIndication: string | null;
    warnings: string[];
  };
}

interface ProfilesResp {
  status: string;
  source: string | null;
  profiles: Array<{
    index: number;
    name: string;
    pdpType: string | null;
    apn: string;
    username: string;
    auth: string | null;
    hasPassword: boolean;
    cid: number | null;
  }>;
}

function linkProtLabel(p: number | null | undefined): string {
  if (p === 2) return "Raw-IP";
  if (p === 1) return "802.3";
  return p != null ? `proto(${p})` : "--";
}

function aggLabel(p: number | null | undefined): string {
  if (p === 9) return "QMAPv5";
  if (p === 8) return "QMAPv4";
  if (p === 5) return "QMAPv1";
  if (p === 0) return "None";
  return p != null ? `agg(${p})` : "--";
}

function verdict(s: DataplaneStatusResp["snapshot"]) {
  if (!s.qrtr.available) {
    return {
      title: "QRTR Unavailable",
      body: s.qrtr.error ?? "Kernel AF_QIPCRTR socket is not available in this environment.",
      tone: "saffron" as const,
    };
  }
  if (s.mode === "native") {
    const ok = s.supervisorState === "native-connected";
    return {
      title: ok ? "Native Connected" : s.supervisorState,
      body: "Rust QMI + RTNETLINK directly owns cellular bearers while preserving IPA hardware offload.",
      tone: ok ? ("jade" as const) : ("saffron" as const),
    };
  }
  return {
    title: "Coexist (Live Probe)",
    body: "Native AF_QIPCRTR QMI and RTNETLINK are observing the modem DSP and links alongside the vendor connection manager.",
    tone: "jade" as const,
  };
}

function splitBitrate(bps: number | null | undefined): { value: number; decimals: number; unit: string } {
  const v = bps != null && Number.isFinite(bps) && bps > 0 ? bps : 0;
  if (v >= 1_000_000_000) return { value: v / 1_000_000_000, decimals: 2, unit: "Gbps" };
  if (v >= 100_000_000) return { value: v / 1_000_000, decimals: 0, unit: "Mbps" };
  if (v >= 1_000_000) return { value: v / 1_000_000, decimals: 1, unit: "Mbps" };
  if (v >= 1_000) return { value: v / 1_000, decimals: 0, unit: "Kbps" };
  return { value: Math.round(v), decimals: 0, unit: "bps" };
}

const ConduitStream = React.memo(function ConduitStream({
  color,
  durationSec,
  animate,
  label,
}: {
  color: string;
  durationSec: number;
  animate: boolean;
  label?: React.ReactNode;
}) {
  const gid = useId().replace(/:/g, "");
  return (
    <div className="flex flex-col items-center justify-center gap-1 py-1 md:py-0 min-w-0">
      <svg
        viewBox="0 0 120 26"
        preserveAspectRatio="none"
        className="h-6 w-full max-w-[180px] md:max-w-none overflow-visible"
        aria-hidden
      >
        <defs>
          <filter id={`conduit-glow-${gid}`} x="-15%" y="-80%" width="130%" height="260%">
            <feGaussianBlur stdDeviation="2.2" />
          </filter>
        </defs>
        {/* Base conduit rail */}
        <line x1="2" y1="9" x2="118" y2="9" className="stroke-line" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="2" y1="17" x2="118" y2="17" className="stroke-line" strokeWidth="1.5" strokeLinecap="round" />

        {/* Glow underlay */}
        <line
          x1="2"
          y1="9"
          x2="118"
          y2="9"
          stroke={color}
          strokeWidth="3"
          strokeDasharray="10 14"
          strokeLinecap="round"
          opacity={animate ? "0.42" : "0.18"}
          filter={`url(#conduit-glow-${gid})`}
          className={animate ? "qm-flow-dash" : undefined}
          style={animate ? { animationDuration: `${durationSec}s` } : undefined}
        />

        {/* Forward DL light stream (left → right) */}
        <line
          x1="2"
          y1="9"
          x2="118"
          y2="9"
          stroke={color}
          strokeWidth="2"
          strokeDasharray="10 14"
          strokeLinecap="round"
          opacity={animate ? "0.95" : "0.35"}
          className={animate ? "qm-flow-dash" : undefined}
          style={animate ? { animationDuration: `${durationSec}s` } : undefined}
        />

        {/* Reverse UL light stream (right → left) */}
        <line
          x1="2"
          y1="17"
          x2="118"
          y2="17"
          stroke={color}
          strokeWidth="1.6"
          strokeDasharray="6 18"
          strokeLinecap="round"
          opacity={animate ? "0.75" : "0.28"}
          className={animate ? "qm-flow-dash" : undefined}
          style={animate ? { animationDuration: `${(durationSec * 1.18).toFixed(2)}s`, animationDirection: "reverse" } : undefined}
        />

        {/* Endpoint chevrons */}
        <path d="M 113 6 L 118 9 L 113 12" fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" opacity="0.85" />
        <path d="M 7 14 L 2 17 L 7 20" fill="none" stroke={color} strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" opacity="0.65" />
      </svg>
      {label && <div className="flex flex-wrap items-center justify-center gap-x-2.5 gap-y-0.5 text-[11px] font-mono qm-tabular">{label}</div>}
    </div>
  );
});

const PacketFlowConduit = React.memo(function PacketFlowConduit({
  config,
  snapshot: s,
}: {
  config: DataplaneStatusResp["config"];
  snapshot: DataplaneStatusResp["snapshot"];
}) {
  const traffic = useWsStore((st) => st.traffic);
  const modem = useWsStore((st) => st.modem);
  const internals = useWsStore((st) => st.internals);
  const failoverActive = useObsStore((st) => Boolean(st.failover?.active));
  const motion = useEffectiveMotion();

  const managedLink =
    s.links.find((l) => l.name === config.iface) ??
    s.links.find((l) => /^rmnet_data\d+$/.test(l.name) && l.up) ??
    null;

  const managedAddrs = managedLink ? s.addrs.filter((a) => a.ifindex === managedLink.ifindex) : [];
  const hasLinkV4 = managedAddrs.some((a) => a.family === 2 && a.scope < 254);
  const hasLinkV6 = managedAddrs.some((a) => a.family === 10 && a.scope === 0);

  const wdsV4Connected =
    s.wdsV4.state.toLowerCase() === "connected" ||
    s.wdsV4.pktStatus?.status?.toLowerCase() === "connected";
  const wdsV6Connected =
    s.wdsV6.state.toLowerCase() === "connected" ||
    s.wdsV6.pktStatus?.status?.toLowerCase() === "connected";

  const v4Usable =
    wdsV4Connected ||
    Boolean(s.wdsV4.runtime?.ipv4Addr) ||
    hasLinkV4 ||
    Boolean(modem?.bearers.some((b) => Boolean(b.ipv4)));
  const v6Usable =
    wdsV6Connected ||
    Boolean(s.wdsV6.runtime?.ipv6Addr) ||
    hasLinkV6 ||
    Boolean(modem?.bearers.some((b) => Boolean(b.ipv6)));

  const linkDown =
    !s.qrtr.available ||
    (s.nasSys != null && !s.nasSys.registered) ||
    (managedLink != null && !managedLink.up) ||
    (!v4Usable && !v6Usable && config.mode === "native" && s.supervisorState !== "native-connected");

  const conduitColor = linkDown
    ? "var(--qm-crimson)"
    : failoverActive
      ? "var(--qm-saffron)"
      : "var(--qm-jade)";
  const conduitTone: "crimson" | "saffron" | "jade" = linkDown
    ? "crimson"
    : failoverActive
      ? "saffron"
      : "jade";

  const totalMbps = (traffic.rxBps + traffic.txBps) / 1_000_000;
  const flowIntensity = Math.max(0, Math.min(1, Math.pow(Math.max(0, totalMbps) / 400, 0.42)));
  const durationSec = Number((2.6 - flowIntensity * (2.6 - 0.45)).toFixed(2));
  const animateFlow = motion !== "reduced" && !linkDown;

  const rat = modem?.serving?.rat || s.nasSys?.rat || "Cellular";
  const band = modem?.serving?.band || (s.nasSys?.nr5gPsAttached ? "NR5G" : "—");
  const caCount = modem?.carriers?.length ?? 0;
  const rsrp = modem?.serving?.rsrp ?? s.nasSignal?.nr5gRsrpDbm ?? s.nasSignal?.lteRsrpDbm ?? null;
  const sinr = modem?.serving?.sinr ?? s.nasSignal?.nr5gSnrDb ?? null;

  const modeLabel = config.mode === "native" ? "Native QMI" : "Vendor";
  const ifaceLabel = config.iface || traffic.primaryIface || "rmnet_data0";
  const ipaActive = s.kernel.ipaDevPresent && s.kernel.ipacmRunning;
  const ipaHw = s.kernel.ipaOffload.hwType ? `IPAv${s.kernel.ipaOffload.hwType}` : "IPA";
  const ipaPct = s.kernel.ipaOffload.ethHardwareOffloadPct;

  const lanIface = traffic.lanIface || "eth0";
  const ethSpeed = internals?.ethSpeed?.trim() || "";
  const cfRunning = Boolean(internals?.cloudflaredRunning);
  const cfHa = internals?.cloudflaredHaConnections ?? null;

  const rxRate = splitBitrate(traffic.rxBps);
  const txRate = splitBitrate(traffic.txBps);

  return (
    <Card className="lg:col-span-12 qm-hud-card qm-reticle p-4 sm:p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3.5">
        <div className="flex items-center gap-2">
          <LiveDot tone={conduitTone} />
          <span className="qm-eyebrow">Live Packet-Flow Conduit</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-semibold">
          {failoverActive && (
            <Badge variant="warning" dot>
              Failover active
            </Badge>
          )}
          <Badge variant={linkDown ? "danger" : failoverActive ? "warning" : "success"}>
            {linkDown ? "Link down" : failoverActive ? "Carrying failover" : totalMbps >= 10 ? "High-speed flow" : "Conduit nominal"}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_minmax(76px,0.52fr)_minmax(0,1.2fr)_minmax(108px,0.72fr)_minmax(0,1fr)] items-center gap-2.5 md:gap-3">
        {/* Node 1: 5G RF Link */}
        <div className="qm-subcard p-3 sm:p-3.5 space-y-1.5 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-muted">
              <Radio className="h-3.5 w-3.5 text-ember-ink shrink-0" />
              5G RF Link
            </span>
            <LiveDot tone={conduitTone} className="h-1.5 w-1.5" />
          </div>
          <div className="qm-display text-[1.02rem] font-semibold text-ink truncate">
            {rat} · {band}
            {caCount > 0 ? ` · ${caCount}CA` : ""}
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono qm-tabular text-muted">
            <span>{rsrp != null ? `${rsrp} dBm` : "— dBm"}</span>
            {sinr != null && <span>· SINR {sinr} dB</span>}
          </div>
        </div>

        {/* Conduit 1: RF → Modem */}
        <ConduitStream
          color={conduitColor}
          durationSec={durationSec}
          animate={animateFlow}
          label={
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
              {linkDown ? "No RF" : "RF ⇄ DSP"}
            </span>
          }
        />

        {/* Node 2: SDX75 Engine */}
        <div className="qm-subcard p-3 sm:p-3.5 space-y-2 min-w-0 border-ember/25">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-muted">
              <Cpu className="h-3.5 w-3.5 text-ember-ink shrink-0" />
              SDX75 Engine
            </span>
            <span className="font-mono text-[11px] font-semibold text-ink-2 truncate">{ifaceLabel}</span>
          </div>
          <div className="qm-display text-[1.02rem] font-semibold text-ink truncate">
            {modeLabel}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10.5px] font-bold qm-tabular",
                v4Usable ? "bg-jade-soft text-jade-ink" : "bg-sunk text-muted border border-line"
              )}
              title={wdsV4Connected ? "QMI WDS IPv4 connected" : v4Usable ? "IPv4 address active" : "IPv4 inactive"}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full", v4Usable ? "bg-jade" : "bg-muted/60")} />
              v4
            </span>
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10.5px] font-bold qm-tabular",
                v6Usable ? "bg-jade-soft text-jade-ink" : "bg-sunk text-muted border border-line"
              )}
              title={wdsV6Connected ? "QMI WDS IPv6 connected" : v6Usable ? "IPv6 address active" : "IPv6 inactive"}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full", v6Usable ? "bg-jade" : "bg-muted/60")} />
              v6
            </span>
            <Badge variant={ipaActive ? "success" : "warning"} className="text-[10.5px] px-2 py-0">
              {ipaHw}
              {ipaActive && ipaPct != null ? ` ${ipaPct}%` : ipaActive ? " HW" : " off"}
            </Badge>
          </div>
        </div>

        {/* Conduit 2: Modem → LAN with live rolling throughput */}
        <ConduitStream
          color={conduitColor}
          durationSec={durationSec}
          animate={animateFlow}
          label={
            <>
              <span className="inline-flex items-center gap-0.5 font-semibold text-jade-ink">
                <ArrowDown className="h-3 w-3" />
                <RollingNumber
                  value={rxRate.value}
                  decimals={rxRate.decimals}
                  suffix={` ${rxRate.unit}`}
                  stiffness={180}
                  damping={26}
                />
              </span>
              <span className="inline-flex items-center gap-0.5 font-semibold text-berry-ink">
                <ArrowUp className="h-3 w-3" />
                <RollingNumber
                  value={txRate.value}
                  decimals={txRate.decimals}
                  suffix={` ${txRate.unit}`}
                  stiffness={180}
                  damping={26}
                />
              </span>
            </>
          }
        />

        {/* Node 3: LAN / Egress */}
        <div className="qm-subcard p-3 sm:p-3.5 space-y-2 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-muted">
              <Network className="h-3.5 w-3.5 text-ember-ink shrink-0" />
              LAN / Egress
            </span>
            <LiveDot tone={traffic.lanState?.toLowerCase() === "down" ? "crimson" : "jade"} className="h-1.5 w-1.5" />
          </div>
          <div className="qm-display text-[1.02rem] font-semibold text-ink truncate">
            {lanIface}
            {ethSpeed ? ` · ${ethSpeed}` : ""}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {cfRunning ? (
              <Badge variant="info" dot className="text-[10.5px] px-2 py-0">
                <Cloud className="h-2.5 w-2.5" />
                Cloudflared{cfHa != null ? ` · ${cfHa} HA` : ""}
              </Badge>
            ) : (
              <span className="text-[11px] text-muted">Direct LAN egress</span>
            )}
            {s.ipaIpptActive && (
              <Badge variant="plum" className="text-[10.5px] px-2 py-0">
                IPPT
              </Badge>
            )}
          </div>
        </div>
      </div>
    </Card>
  );
});

export function DataPlaneView() {
  const toast = useToastStore((s) => s.push);
  const qc = useQueryClient();
  const guard = useGuarded();
  const [busy, setBusy] = useState<string | null>(null);
  const [showVendorSvcs, setShowVendorSvcs] = useState(false);

  const q = useQuery({
    queryKey: KEY_STATUS,
    queryFn: () => apiFetch<DataplaneStatusResp>("/api/v1/dataplane/status"),
    refetchInterval: 15000,
  });

  const cfg = q.data?.config;
  const [ifaceDraft, setIfaceDraft, ifaceD] = useDraft(cfg?.iface ?? null, "rmnet_data0");
  const [manageDnsDraft, setManageDnsDraft, manageDnsD] = useDraft(cfg?.manageDns ?? null, true);
  const [v6ShareDraft, setV6ShareDraft, v6ShareD] = useDraft(cfg?.ipv6PrefixSharing ?? null, true);
  const [ipptDraft, setIpptDraft, ipptD] = useDraft(cfg?.ippt ?? null, false);
  const [ipptMacDraft, setIpptMacDraft, ipptMacD] = useDraft(cfg ? cfg.ipptMac ?? "" : null, "");
  const [ipptDevDraft, setIpptDevDraft, ipptDevD] = useDraft(cfg?.ipptDevType || null, "eth0");
  const [ipptSkipNatDraft, setIpptSkipNatDraft, ipptSkipNatD] = useDraft(cfg?.ipptSkipNat ?? null, true);

  const pq = useQuery({
    queryKey: KEY_PROFILES,
    queryFn: () => apiFetch<ProfilesResp>("/api/v1/dataplane/profiles"),
    refetchInterval: 30000,
  });

  const refresh = async () => {
    await Promise.all([qc.invalidateQueries({ queryKey: KEY_STATUS }), qc.invalidateQueries({ queryKey: KEY_PROFILES })]);
  };

  async function saveBearerSettings() {
    setBusy("bearer");
    try {
      await apiFetch("/api/v1/dataplane/config", {
        method: "POST",
        body: JSON.stringify({
          iface: ifaceDraft,
          manageDns: manageDnsDraft,
          ipv6PrefixSharing: v6ShareDraft,
          ippt: ipptDraft,
          ipptMac: ipptMacDraft.trim(),
          ipptDevType: ipptDevDraft,
          ipptSkipNat: ipptSkipNatDraft,
        }),
      });
      resetAll(ifaceD, manageDnsD, v6ShareD, ipptD, ipptMacD, ipptDevD, ipptSkipNatD);
      toast("Bearer & IPPT settings saved", "success");
      await refresh();
    } catch (e) {
      if (!isCancelled(e)) toast("Could not save bearer settings", "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  async function triggerReconnect() {
    setBusy("reconnect");
    try {
      const isNative = q.data?.config.mode === "native";
      if (isNative) {
        await disruptiveFetch("data plane reconnect", "/api/v1/dataplane/reconnect", { method: "POST", body: "{}" });
      } else {
        await apiFetch("/api/v1/dataplane/reconnect", { method: "POST", body: "{}" });
      }
      toast(isNative ? "Data plane reconnect triggered" : "Data plane probe triggered", "success");
      await refresh();
    } catch (e) {
      if (!isCancelled(e)) toast("Probe failed", "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  function applyMode(nextMode: "coexist" | "native") {
    if (!q.data || nextMode === q.data.config.mode) return;
    const isNative = nextMode === "native";
    guard.run({
      title: isNative ? "Switch to Native Rust Data Plane?" : "Return to Coexist Mode?",
      body: isNative ? (
        <div className="space-y-2 text-[13px] text-ink-2">
          <FailoverWarning action="Switching to Native mode" />
          <p>cellcored will stop QCMAP / netmgrd and manage dual-stack QMI WDS bearers + RTNETLINK directly.</p>
          <p>Qualcomm IPA hardware offload (ipacm / rmnet_ipa0) remains active.</p>
        </div>
      ) : (
        <div className="space-y-2 text-[13px] text-ink-2">
          <FailoverWarning action="Switching back to Coexist mode" />
          <p>Restores vendor QCMAP / netmgrd control and keeps Rust QRTR/QMI in read-only observation mode.</p>
        </div>
      ),
      tone: isNative ? "danger" : "primary",
      confirmLabel: isNative ? "Enable Native Mode" : "Switch to Coexist",
      action: (confirm) =>
        disruptiveFetch(
          "data plane mode switch",
          "/api/v1/dataplane/config",
          {
            method: "POST",
            body: JSON.stringify(confirm ? { mode: nextMode, confirm } : { mode: nextMode }),
          },
          { confirmed: true }
        ),
      onDone: () => void refresh(),
      success: `Data plane mode: ${nextMode}`,
    });
  }

  function applyTuning(nextProfile: "default" | "high-throughput") {
    if (!q.data || nextProfile === q.data.config.kernelTuning) return;
    const ht = nextProfile === "high-throughput";
    guard.run({
      title: ht ? "Enable High-Throughput Kernel Profile?" : "Restore Default Kernel Profile?",
      body: ht ? (
        <div className="space-y-2 text-[13px] text-ink-2">
          <p>
            Applies fq_codel qdisc, 16 MiB TCP/socket buffers, tcp_fastopen=3, nf_conntrack_max=65536, RFS/XPS across eth0, rmnet_ipa0, and rmnet_data0, and performance CPU governor.
          </p>
        </div>
      ) : (
        <p className="text-[13px] text-ink-2">Restores the kernel sysctl and RPS settings captured before tuning was enabled.</p>
      ),
      tone: "primary",
      confirmLabel: "Apply",
      action: () =>
        apiFetch("/api/v1/dataplane/config", {
          method: "POST",
          body: JSON.stringify({ kernelTuning: nextProfile }),
        }),
      onDone: () => void refresh(),
      success: ht ? "High-throughput profile applied" : "Default kernel settings restored",
    });
  }

  async function toggleSfeFastpath(next: boolean) {
    setBusy("sfe");
    try {
      await disruptiveFetch("SFE fastpath toggle", "/api/v1/dataplane/config", {
        method: "POST",
        body: JSON.stringify({ sfeFastpath: next }),
      });
      toast(next ? "Qualcomm SFE fastpath enabled" : "Qualcomm SFE fastpath disabled", "success");
      await refresh();
    } catch (e) {
      if (!isCancelled(e)) toast("SFE fastpath update failed", "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  if (q.error) return <LoadError error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return <Skeleton className="h-64 w-full" />;

  const { config, snapshot: s } = q.data;
  const v = verdict(s);
  const k = s.kernel;
  const modemSvcs = s.qrtr.services.filter((x) => x.node === s.qrtr.modemNode);
  const knownSvcs = modemSvcs.filter((x) => x.name !== "UNKNOWN");
  const vendorSvcs = modemSvcs.filter((x) => x.name === "UNKNOWN");
  const rmnetByName = new Map(s.links.filter((l) => /^rmnet_data\d+$/.test(l.name)).map((l) => [l.name, l]));
  const ifaceOptions = Array.from(new Set([...rmnetByName.keys(), config.iface || "rmnet_data0", "rmnet_data0"])).sort(
    (a, b) => a.localeCompare(b, undefined, { numeric: true }),
  );

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <PacketFlowConduit config={config} snapshot={s} />

      <div className="lg:col-span-7 min-w-0 space-y-5">
        <Card className="space-y-5">
          <CardHeader
            title="Data Plane"
            subtitle="Native Rust AF_QIPCRTR QMI + RTNETLINK supervisor"
            icon={<Cpu className="h-4 w-4" />}
            action={
              <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void triggerReconnect()}>
                <RefreshCw className={cn("h-3.5 w-3.5", busy === "reconnect" && "animate-spin")} />
                {config.mode === "native" ? "Reconnect" : "Re-probe"}
              </Button>
            }
          />
          <div className="qm-subcard p-5 space-y-2">
            <div className="flex items-center gap-2.5">
              <LiveDot tone={v.tone} />
              <span className="qm-display text-[1.9rem] font-semibold leading-none text-ink">{v.title}</span>
            </div>
            <p className="text-[13px] text-ink-2 max-w-prose">{v.body}</p>
          </div>
          {s.warnings.map((w) => (
            <Notice key={w} tone="warn">
              {w}
            </Notice>
          ))}
          <dl className="grid gap-3 sm:grid-cols-2">
            <Fact label="AF_QIPCRTR bus">
              {s.qrtr.available ? (
                <Badge variant="success" dot>
                  Connected (node {s.qrtr.localNode ?? 0} → modem {s.qrtr.modemNode})
                </Badge>
              ) : (
                <Badge variant="warning">Unavailable</Badge>
              )}
            </Fact>
            <Fact label="Modem DSP services">
              {modemSvcs.length} services · SSR {s.qrtr.ssrCount}
            </Fact>
            <Fact label="NAS registration">
              {s.nasSys ? (s.nasSys.registered ? `${s.nasSys.rat} attached` : `Not attached (${s.nasSys.rat})`) : "--"}
            </Fact>
            <Fact label="WDA data format">
              {s.wdaFormat ? `${linkProtLabel(s.wdaFormat.linkProtocol)} · ${aggLabel(s.wdaFormat.dlAggProtocol)}` : "--"}
            </Fact>
            <Fact label="Firmware / Mode">
              {s.deviceRev ? `${s.deviceRev}${s.operatingMode ? ` (${s.operatingMode})` : ""}` : "--"}
            </Fact>
            <Fact label="QMI / Netlink telemetry">
              IND {s.indicationsReceived} · NL {s.netlinkUpdates}
            </Fact>
          </dl>
          {modemSvcs.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {knownSvcs.map((svc) => (
                <Badge key={`${svc.service}-${svc.port}`} variant="neutral">
                  {svc.name} ({svc.node}:{svc.port})
                </Badge>
              ))}
              {vendorSvcs.length > 0 && (
                <button
                  type="button"
                  aria-expanded={showVendorSvcs}
                  onClick={() => setShowVendorSvcs((v) => !v)}
                  className="cursor-pointer rounded-full"
                >
                  <Badge variant="neutral">
                    {showVendorSvcs ? "Hide vendor DSP" : `+${vendorSvcs.length} vendor DSP`}
                  </Badge>
                </button>
              )}
              {showVendorSvcs &&
                vendorSvcs.map((svc) => (
                  <Badge key={`${svc.service}-${svc.port}`} variant="neutral">
                    0x{svc.service.toString(16)} ({svc.node}:{svc.port})
                  </Badge>
                ))}
            </div>
          )}
        </Card>

        <Card className="space-y-4">
          <CardHeader title="RTNETLINK Interfaces" subtitle="Kernel links, MUX bindings, and addresses read directly via NETLINK_ROUTE" icon={<Network className="h-4 w-4" />} />
          {s.links.length === 0 ? (
            <p className="text-[13px] text-muted">No rmnet / LAN links reported.</p>
          ) : (
            <div className="space-y-2.5">
              {s.links.map((link) => {
                const linkAddrs = s.addrs.filter((a) => a.ifindex === link.ifindex && a.scope < 254);
                return (
                  <div key={link.ifindex} className="qm-subcard p-3.5 space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[13px] font-semibold text-ink">{link.name}</span>
                        {link.kind && <Badge variant="neutral">{link.kind}</Badge>}
                        {link.rmnetMuxId != null && <Badge variant="info">mux {link.rmnetMuxId}</Badge>}
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={link.up ? "success" : "neutral"} dot={link.up}>
                          {link.up ? (link.lowerUp ? "UP · LOWER_UP" : "UP") : "DOWN"}
                        </Badge>
                        <span className="font-mono text-[12px] text-ink-2">MTU {link.mtu}</span>
                      </div>
                    </div>
                    {linkAddrs.length > 0 && (
                      <div className="flex flex-wrap gap-2 font-mono text-[12px] text-ink-2">
                        {linkAddrs.map((a) => (
                          <span key={`${a.address}/${a.prefixLen}`}>
                            {a.address}/{a.prefixLen}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      <div className="lg:col-span-5 min-w-0 space-y-5">
        <Card className="space-y-4">
          <CardHeader title="Control Mode & IPA Offload" subtitle="Preserve Qualcomm IPA hardware forwarding" icon={<ShieldCheck className="h-4 w-4" />} />
          <div role="radiogroup" aria-label="Data plane control mode" className="grid gap-2.5">
            {(
              [
                {
                  id: "coexist",
                  title: "Coexist (observe alongside vendor CM)",
                  body: "Safe boot default: QCMAP/netmgrd keep current routing while Rust QRTR/QMI and Netlink monitor the DSP.",
                },
                {
                  id: "native",
                  title: "Native Rust (QRTR/QMI + Netlink)",
                  body: "Stops QCMAP/netmgrd and brings up dual-stack rmnet bearers natively while keeping ipacm IPA hardware offload.",
                },
              ] as const
            ).map((opt) => {
              const on = config.mode === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  onClick={() => applyMode(opt.id)}
                  className={cn(
                    "w-full rounded-2xl border p-3.5 text-left transition-colors cursor-pointer",
                    on ? "border-ember bg-ember-soft" : "border-line bg-sunk hover:border-line-strong"
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13.5px] font-semibold text-ink">{opt.title}</span>
                    {on && <Badge variant="info">Active</Badge>}
                  </div>
                  <p className="mt-1 text-[12px] text-ink-2">{opt.body}</p>
                </button>
              );
            })}
          </div>
          <div className="flex flex-wrap gap-2 pt-1 min-w-0">
            <Badge variant={k.ipaDevPresent ? "success" : "danger"} dot={k.ipaDevPresent}>
              /dev/ipa {k.ipaDevPresent ? "present" : "missing"}
            </Badge>
            <Badge variant={k.ipacmRunning ? "success" : "warning"} dot={k.ipacmRunning}>
              ipacm {k.ipacmRunning ? "running" : "stopped"}
            </Badge>
            <Badge variant={k.qcmapRunning ? "info" : "neutral"}>QCMAP {k.qcmapRunning ? "running" : "stopped"}</Badge>
            <Badge variant={k.netmgrdRunning ? "info" : "neutral"}>netmgrd {k.netmgrdRunning ? "running" : "stopped"}</Badge>
            <Badge variant={s.ipaCliPresent ? "success" : "neutral"}>ipa CLI {s.ipaCliPresent ? "ready" : "absent"}</Badge>
            {s.ipaIpptActive && (
              <Badge variant="info" dot className="max-w-full whitespace-normal break-words">
                IPA IPPT · {s.activeIpptMac ?? config.ipptMac ?? "active"}
              </Badge>
            )}
            {s.ipaV6SharingPrefix && (
              <Badge variant="info" className="max-w-full whitespace-normal break-all">
                IPv6 {s.ipaV6SharingPrefix}::/64
              </Badge>
            )}
            {s.appliedDns.length > 0 && (
              <Badge variant="neutral" className="max-w-full whitespace-normal break-all">
                DNS {s.appliedDns.join(", ")}
              </Badge>
            )}
          </div>
          {(k.ipaOffload.hwType || k.ipaOffload.ethOffloadDriver) && (
            <dl className="grid gap-3 sm:grid-cols-2 pt-1">
              <Fact label="IPA HW / Clock">
                {k.ipaOffload.hwType ? `IPAv${k.ipaOffload.hwType}` : "IPA"}
                {k.ipaOffload.clkRateMhz != null ? ` · ${k.ipaOffload.clkRateMhz} MHz` : ""}
                {k.ipaOffload.nominalMbps != null && k.ipaOffload.turboMbps != null ? ` (${k.ipaOffload.nominalMbps}/${k.ipaOffload.turboMbps}M)` : ""}
              </Fact>
              <Fact label="Ethernet IOSS offload">
                {k.ipaOffload.ethOffloadDriver ?? "--"}
                {k.ipaOffload.ethHwpRxPackets != null
                  ? ` · ${k.ipaOffload.ethHardwareOffloadPct ?? 0}% HW (${Math.max(0, k.ipaOffload.ethHwpRxPackets - (k.ipaOffload.ethExpRxPackets ?? 0))} offloaded / ${k.ipaOffload.ethExpRxPackets ?? 0} CPU)`
                  : ""}
              </Fact>
            </dl>
          )}
          <details className="qm-subcard p-3.5 min-w-0">
            <summary className="cursor-pointer select-none text-[12.5px] font-semibold text-ink">
              Native Bearer &amp; Hardware IPPT Settings
            </summary>
            <div className="mt-3 space-y-3 min-w-0">
              <label className="block space-y-1 min-w-0">
                <span className="text-[11.5px] font-medium text-ink-2">Managed rmnet interface</span>
                <Select value={ifaceDraft} onChange={(e) => setIfaceDraft(e.target.value)} aria-label="Managed rmnet interface">
                  {ifaceOptions.map((name) => {
                    const mux = rmnetByName.get(name)?.rmnetMuxId;
                    return (
                      <option key={name} value={name}>
                        {name}
                        {mux != null ? ` (mux ${mux})` : ""}
                      </option>
                    );
                  })}
                </Select>
              </label>
              <Switch
                checked={manageDnsDraft}
                onChange={setManageDnsDraft}
                label="QMI DNS handoff"
                description="Write /tmp/resolv.conf.d/resolv.conf*.auto and reload dnsmasq in Native mode"
              />
              <Switch
                checked={v6ShareDraft}
                onChange={setV6ShareDraft}
                label="IPAv5 IPv6 prefix sharing"
                description="Program ipa idu_ipv6_config sharing for downstream /64"
              />
              <Switch
                checked={ipptDraft}
                onChange={setIpptDraft}
                label="Hardware IPAv5 IP Passthrough"
                description="Program ipa ippass + /32 br-lan host route in Native mode"
              />
              <div className="grid gap-3 sm:grid-cols-2 min-w-0">
                <label className="block space-y-1 min-w-0">
                  <span className="text-[11.5px] font-medium text-ink-2">Passthrough client MAC</span>
                  <Input
                    value={ipptMacDraft}
                    onChange={(e) => setIpptMacDraft(e.target.value)}
                    placeholder="aa:bb:cc:dd:ee:ff"
                    aria-label="Passthrough client MAC"
                  />
                </label>
                <label className="block space-y-1 min-w-0">
                  <span className="text-[11.5px] font-medium text-ink-2">Downstream port type</span>
                  <Select value={ipptDevDraft} onChange={(e) => setIpptDevDraft(e.target.value)} aria-label="Downstream port type">
                    <option value="eth0">eth0</option>
                    <option value="eth1">eth1</option>
                    <option value="usb">usb</option>
                    <option value="any">any</option>
                  </Select>
                </label>
              </div>
              <Switch
                checked={ipptSkipNatDraft}
                onChange={setIpptSkipNatDraft}
                label="Skip IPA NAT (skip_nat=1)"
              />
              <div className="pt-1">
                <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void saveBearerSettings()}>
                  Save Bearer Settings
                </Button>
              </div>
            </div>
          </details>
        </Card>

        <Card className="space-y-4">
          <CardHeader title="Kernel Offload & Socket Tuning" subtitle="Reversible TCP buffer, qdisc, and RPS/XPS profile" icon={<Gauge className="h-4 w-4" />} />
          {k.tuningWarnings.length > 0 && (
            <div className="space-y-2">
              {k.tuningWarnings.map((w) => (
                <Notice key={w} tone="warn">
                  {w}
                </Notice>
              ))}
            </div>
          )}
          <dl className="grid gap-3 sm:grid-cols-2">
            <Fact label="TCP CC / qdisc">
              {k.tcpCongestionControl || "--"} · {k.defaultQdisc || "--"}
            </Fact>
            <Fact label="rmem_max / wmem_max">
              {k.rmemMax != null ? formatBytes(k.rmemMax, 0) : "--"} / {k.wmemMax != null ? formatBytes(k.wmemMax, 0) : "--"}
            </Fact>
            <Fact label="Backlog / Budget">
              {k.netdevMaxBacklog ?? "--"} / {k.netdevBudget ?? "--"}
            </Fact>
            <Fact label="RPS sock flows">{k.rpsSockFlowEntries ?? "--"}</Fact>
            <Fact label="CPU Governor / Freq">
              {k.cpuGovernor ?? "--"}
              {k.cpuCurFreqMhz != null && k.cpuMaxFreqMhz != null ? ` · ${k.cpuCurFreqMhz}/${k.cpuMaxFreqMhz} MHz` : ""}
            </Fact>
            <Fact label="Conntrack / TFO">
              {k.conntrackCount ?? "--"}/{k.conntrackMax ?? "--"} · TFO {k.tcpFastopen ?? "--"}
            </Fact>
          </dl>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant={k.activeTuning === "high-throughput" ? "secondary" : "primary"}
              onClick={() => applyTuning("high-throughput")}
              disabled={k.activeTuning === "high-throughput"}
            >
              Enable High-Throughput Profile
            </Button>
            {k.activeTuning === "high-throughput" && (
              <Button size="sm" variant="ghost" onClick={() => applyTuning("default")}>
                Restore Defaults
              </Button>
            )}
          </div>
          <div className="qm-subcard p-3.5 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <Switch
                checked={Boolean(config.sfeFastpath)}
                disabled={busy === "sfe"}
                onChange={(next) => void toggleSfeFastpath(next)}
                label="Qualcomm SFE Software Fastpath (Experimental)"
                description="Load shortcut-fe kernel fastpath modules for software-accelerated flows when IPA hardware offload misses"
              />
              <Badge variant={s.sfeLoaded ? "info" : "neutral"} className="shrink-0">
                {s.sfeLoaded ? "SFE loaded" : "SFE off"}
              </Badge>
            </div>
          </div>
        </Card>

        <Card className="space-y-3">
          <CardHeader title="3GPP Profiles (QMI WDS)" subtitle={pq.data?.source ? `Source: ${pq.data.source}` : "Carrier APN profiles read via QRTR"} icon={<Server className="h-4 w-4" />} />
          {pq.error ? (
            <Notice tone="warn">{errText(pq.error)}</Notice>
          ) : !pq.data ? (
            <Skeleton className="h-24 w-full" />
          ) : pq.data.profiles.length === 0 ? (
            <p className="text-[13px] text-muted">No QMI WDS profiles reported yet.</p>
          ) : (
            <div className="space-y-2">
              {pq.data.profiles.map((p) => (
                <div key={p.index} className="qm-subcard flex flex-wrap items-center justify-between gap-2 px-3.5 py-2.5 text-[12.5px]">
                  <div className="min-w-0">
                    <span className="font-mono font-semibold text-ink">#{p.index}</span>{" "}
                    <span className="font-semibold text-ink">{p.apn || "(empty)"}</span>
                    {p.name && p.name !== p.apn && <span className="text-muted"> · {p.name}</span>}
                  </div>
                  <div className="flex items-center gap-1.5">
                    {p.pdpType && <Badge variant="neutral">{p.pdpType}</Badge>}
                    {p.auth && <Badge variant="neutral">{p.auth}</Badge>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
      {guard.modal}
    </div>
  );
}
