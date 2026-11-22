import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Cpu, Gauge, Network, RefreshCw, Server, ShieldCheck } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { resetAll, useDraft } from "../../lib/draft";
import { cn, formatBytes } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, LiveDot, Select, Skeleton, Switch } from "../../components/ui";
import { FailoverWarning } from "../../components/obs";
import { useToastStore } from "../../stores/toast-store";
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
