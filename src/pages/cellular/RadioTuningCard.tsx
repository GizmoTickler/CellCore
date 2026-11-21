import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Check, Cpu, Radio, RefreshCw, ShieldAlert, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { useToastStore } from "../../stores/toast-store";
import { Badge, Button, Card, CardHeader, Input, Meter, Select, Skeleton, Switch } from "../../components/ui";
import { LoadError, errText } from "../admin/shared";

interface CsiMetrics {
  mcs: number;
  ri: number;
  cqi: number;
  pmi: number;
}

interface TxPowerDetail {
  puschDbm: number;
  pucchDbm: number;
  maxDbm: number;
  srsDbm: number;
  headroomDb: number;
}

interface McsDetail {
  mcs: number;
  modOrder: number;
  modulation: string;
}

interface SsbBeamEntry {
  pci: number;
  beamId: number;
  servingBeamId: number;
  rsrpDbm: number;
  rsrqDb: number;
  isServing: boolean;
}

interface QosBearerEntry {
  cid: number;
  apn: string;
  qfi: number;
  fiveQi: number;
  priorityLabel: string;
}

interface AmbrEntry {
  apn: string;
  ulMbps: number;
  dlMbps: number;
}

interface AirSecurityInfo {
  rat: string;
  cipherId: number;
  cipherName: string;
  integrityId: number;
  integrityName: string;
  nullCipherAlert: boolean;
}

interface RrcStateInfo {
  rat: string;
  stateCode: number;
  stateName: string;
}

interface RadioTuningState {
  lteCaEnabled: boolean | null;
  nrCaEnabled: boolean | null;
  lte4mimoEnabled: boolean | null;
  nr4mimoEnabled: boolean | null;
  nrUl256qamFr1: boolean | null;
  nrUl256qamFr2: boolean | null;
  dssEnabled: boolean | null;
  nrdcEnabled: boolean | null;
  ratAcqOrder: string | null;
  lteCdrxEnabled: boolean | null;
  nrCdrxEnabled: boolean | null;
  rrcInactiveEnabled: boolean | null;
  dataCentric: boolean | null;
  overheatIndEnabled: boolean | null;
  lteBandPriority: string[];
  nr5gBandPriority: string[];
  nr5gPrefFreqList: string[];
  nr5gEarfcnLock: string[];
  eventA3Enabled: boolean | null;
  eventA3Offset: number | null;
  simSlot: number | null;
  simDetEnabled: boolean | null;
}

interface PhyDiagnostics {
  nr5gCsi: CsiMetrics | null;
  lteCsi: CsiMetrics | null;
  nr5gMimoLayers: number | null;
  nr5gTxPwr: string | null;
  nr5gTxPwrDetail: TxPowerDetail | null;
  nr5gPathlossDb: number | null;
  nr5gDlMcs: McsDetail | null;
  nr5gUlMcs: McsDetail | null;
  ssbBeams: SsbBeamEntry[];
  qosBearers: QosBearerEntry[];
  ambrCaps: AmbrEntry[];
  nr5gAmbr: string | null;
  airSecurity: AirSecurityInfo | null;
  rrcState: RrcStateInfo | null;
  cRnti: number | null;
  overheatInd: boolean | null;
  sfeEnabled: boolean | null;
}

interface TuningResp {
  status: string;
  tuning: RadioTuningState;
  phy: PhyDiagnostics;
}

interface TmdDeviceInfo {
  name: string;
  maxLevel: number;
  currentLevel: number;
  requestedLevel: number;
  throttling: boolean;
}

interface DspCapabilities {
  tmd: boolean;
  sar: boolean;
  smartTransmit: boolean;
  antSwitch: boolean;
  locGnss: boolean;
  wmsSms: boolean;
  timeSvc: boolean;
}

interface DspTelemetrySnapshot {
  qrtrAvailable: boolean;
  dspServiceCount: number;
  capabilities: DspCapabilities;
  sarRfState: number | null;
  sarLabel: string;
  tmdDevices: TmdDeviceInfo[];
  anyThrottling: boolean;
  updatedAt: number;
}

interface DspResp {
  status: string;
  dsp: DspTelemetrySnapshot;
}

const KEY = ["cellular-tuning"];
const DSP_KEY = ["cellular-dsp"];
const RAT_OPTIONS = ["LTE:NR5G:WCDMA", "NR5G:LTE:WCDMA", "NR5G:LTE", "LTE:NR5G"];

function parseBandText(raw: string): string[] {
  return raw
    .split(/[\s,:]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseArfcnText(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => /^\d+(?::(?:15|30|60|120))?$/.test(s));
}

export function RadioTuningCard() {
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const q = useQuery({
    queryKey: KEY,
    queryFn: () => apiFetch<TuningResp>("/api/v1/cellular/tuning"),
    staleTime: 15_000,
  });

  async function forceReload() {
    resetDraft();
    try {
      const fresh = await apiFetch<TuningResp>("/api/v1/cellular/tuning?refresh=1");
      qc.setQueryData(KEY, fresh);
    } catch {
      void q.refetch();
    }
    void dspQ.refetch();
  }
  const dspQ = useQuery({
    queryKey: DSP_KEY,
    queryFn: () => apiFetch<DspResp>("/api/v1/cellular/dsp"),
    staleTime: 20_000,
  });

  const [draft, setDraft] = useState<RadioTuningState | null>(null);
  const [ltePrioText, setLtePrioText] = useState("");
  const [nrPrioText, setNrPrioText] = useState("");
  const [prefFreqText, setPrefFreqText] = useState("");
  const [earfcnLockText, setEarfcnLockText] = useState("");
  const [a3OffsetText, setA3OffsetText] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!q.data) return;
    setDraft(q.data.tuning);
    setLtePrioText(q.data.tuning.lteBandPriority.join(":"));
    setNrPrioText(q.data.tuning.nr5gBandPriority.join(":"));
    setPrefFreqText((q.data.tuning.nr5gPrefFreqList ?? []).join(", "));
    setEarfcnLockText((q.data.tuning.nr5gEarfcnLock ?? []).join(", "));
    setA3OffsetText(q.data.tuning.eventA3Offset != null ? String(q.data.tuning.eventA3Offset) : "");
  }, [q.data]);

  const saved = q.data?.tuning;
  const phy = q.data?.phy;
  const dsp = dspQ.data?.dsp;

  function buildPatch(): Record<string, unknown> {
    if (!saved || !draft) return {};
    const patch: Record<string, unknown> = {};
    const boolKeys = [
      "lteCaEnabled",
      "nrCaEnabled",
      "lte4mimoEnabled",
      "nr4mimoEnabled",
      "nrUl256qamFr1",
      "nrUl256qamFr2",
      "dssEnabled",
      "nrdcEnabled",
      "lteCdrxEnabled",
      "nrCdrxEnabled",
      "rrcInactiveEnabled",
      "dataCentric",
      "overheatIndEnabled",
      "eventA3Enabled",
    ] as const;
    for (const k of boolKeys) {
      if (draft[k] !== null && draft[k] !== saved[k]) {
        patch[k] = draft[k];
      }
    }
    if (draft.ratAcqOrder && draft.ratAcqOrder !== saved.ratAcqOrder) {
      patch.ratAcqOrder = draft.ratAcqOrder;
    }
    const nextLte = parseBandText(ltePrioText);
    if (nextLte.join(":") !== saved.lteBandPriority.join(":")) {
      patch.lteBandPriority = nextLte;
    }
    const nextNr = parseBandText(nrPrioText);
    if (nextNr.join(":") !== saved.nr5gBandPriority.join(":")) {
      patch.nr5gBandPriority = nextNr;
    }
    const nextPref = parseArfcnText(prefFreqText);
    if (nextPref.join(",") !== (saved.nr5gPrefFreqList ?? []).join(",")) {
      patch.nr5gPrefFreqList = nextPref;
    }
    const nextLock = parseArfcnText(earfcnLockText);
    if (nextLock.join(",") !== (saved.nr5gEarfcnLock ?? []).join(",")) {
      patch.nr5gEarfcnLock = nextLock;
    }
    const trimmedA3 = a3OffsetText.trim();
    if (trimmedA3 !== "" && Number.isInteger(Number(trimmedA3))) {
      const parsedA3 = Number(trimmedA3);
      if (parsedA3 >= 0 && parsedA3 <= 255 && parsedA3 !== saved.eventA3Offset) {
        patch.eventA3Offset = parsedA3;
      }
    }
    if (draft.simSlot != null && draft.simSlot !== saved.simSlot) {
      patch.simSlot = draft.simSlot;
    }
    return patch;
  }

  const patch = buildPatch();
  const dirty = Object.keys(patch).length > 0;

  function resetDraft() {
    if (!saved) return;
    setDraft(saved);
    setLtePrioText(saved.lteBandPriority.join(":"));
    setNrPrioText(saved.nr5gBandPriority.join(":"));
    setPrefFreqText((saved.nr5gPrefFreqList ?? []).join(", "));
    setEarfcnLockText((saved.nr5gEarfcnLock ?? []).join(", "));
    setA3OffsetText(saved.eventA3Offset != null ? String(saved.eventA3Offset) : "");
  }

  async function apply() {
    if (!dirty) return;
    setBusy(true);
    try {
      const res = await apiFetch<{ note?: string }>("/api/v1/cellular/tuning", {
        method: "POST",
        body: JSON.stringify(patch),
      });
      toast("Radio tuning applied", "success", res.note);
      await qc.invalidateQueries({ queryKey: KEY });
    } catch (e) {
      toast("Radio tuning failed", "error", errText(e));
    } finally {
      setBusy(false);
    }
  }

  const caSwitches = draft
    ? ([
        { key: "lteCaEnabled", label: "LTE Carrier Aggregation", desc: "Aggregate multiple LTE carriers (disable_lte_ca=0)" },
        { key: "nrCaEnabled", label: "NR5G Carrier Aggregation", desc: "Aggregate Sub-6 5G NR carriers (disable_nr_ca=0)" },
        { key: "lte4mimoEnabled", label: "LTE 4×4 MIMO", desc: "4-layer downlink spatial multiplexing on LTE (dis_4mimo_enable=0)" },
        { key: "nr4mimoEnabled", label: "NR5G 4×4 MIMO", desc: "4-layer downlink spatial multiplexing on 5G NR" },
        { key: "nrUl256qamFr1", label: "NR5G UL 256QAM (FR1)", desc: "Higher-order Sub-6 uplink modulation when RF margin allows" },
        { key: "dssEnabled", label: "Dynamic Spectrum Sharing", desc: "Share spectrum between LTE and NR5G on DSS towers" },
        { key: "nrdcEnabled", label: "NR-DC Dual Connectivity", desc: "Aggregate FR1 and FR2 NR carriers (nrdc_mode)" },
      ] as const).filter((item) => draft[item.key] !== null)
    : [];

  const latencySwitches = draft
    ? ([
        { key: "lteCdrxEnabled", label: "LTE C-DRX", desc: "Connected DRX sleep cycle; disabling lowers jitter on AC-powered gateways" },
        { key: "nrCdrxEnabled", label: "NR5G C-DRX", desc: "5G connected sleep cycle; disabling cuts wake-up latency spikes" },
        { key: "rrcInactiveEnabled", label: "RRC Inactive", desc: "Keep RAN context suspended instead of full idle release" },
        { key: "dataCentric", label: "Data-centric mode", desc: "Prefer packet throughput over voice CS/IMS paging (ue_usage_setting=1)" },
        { key: "overheatIndEnabled", label: "Overheat indication", desc: "Enable thermal mitigation indications in NR5G stack (overheat_ind)" },
      ] as const).filter((item) => draft[item.key] !== null)
    : [];

  const ratOptions = draft?.ratAcqOrder && !RAT_OPTIONS.includes(draft.ratAcqOrder)
    ? [draft.ratAcqOrder, ...RAT_OPTIONS]
    : RAT_OPTIONS;

  const txDetail = phy?.nr5gTxPwrDetail;
  const txPct = txDetail && txDetail.maxDbm > 0
    ? Math.max(0, Math.min(100, Math.round(((txDetail.puschDbm + 20) / (txDetail.maxDbm + 20)) * 100)))
    : 0;

  return (
    <Card className="space-y-5">
      <CardHeader
        title="RF, Carrier Aggregation & SDX75 PHY Telemetry"
        subtitle="Baseband steering, Dual-SIM switching, live 5G PHY/QoS/Security counters, and QMI DSP thermal/SAR status"
        icon={<SlidersHorizontal className="h-4 w-4" />}
        action={
          <Button
            size="sm"
            variant="ghost"
            disabled={q.isFetching || dspQ.isFetching}
            onClick={() => void forceReload()}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", (q.isFetching || dspQ.isFetching) && "animate-spin")} />
            Reload
          </Button>
        }
      />

      {q.error ? (
        <LoadError error={q.error} onRetry={() => void q.refetch()} />
      ) : !draft || !phy ? (
        <Skeleton className="h-48 w-full" />
      ) : (
        <div className="space-y-5">
          {/* ── Live SDX75 PHY, QoS & Air-Security Telemetry ── */}
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-[12.5px] font-semibold text-ink-2">
                <Activity className="h-3.5 w-3.5 text-ember-ink" />
                Live SDX75 PHY, QoS & Air Security
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {phy.rrcState && (
                  <Badge variant={phy.rrcState.stateCode === 2 ? "success" : "neutral"}>
                    RRC {phy.rrcState.stateName}
                  </Badge>
                )}
                {phy.cRnti != null && (
                  <Badge variant="neutral">C-RNTI 0x{phy.cRnti.toString(16).toUpperCase()}</Badge>
                )}
                {phy.airSecurity && (
                  <Badge variant={phy.airSecurity.nullCipherAlert ? "danger" : phy.airSecurity.cipherId > 0 ? "success" : "neutral"}>
                    {phy.airSecurity.nullCipherAlert ? (
                      <ShieldAlert className="h-3 w-3 mr-1 inline" />
                    ) : (
                      <ShieldCheck className="h-3 w-3 mr-1 inline" />
                    )}
                    {phy.airSecurity.cipherName}
                  </Badge>
                )}
              </div>
            </div>

            {phy.airSecurity?.nullCipherAlert && (
              <div className="rounded-xl border border-crimson/40 bg-crimson-soft px-3.5 py-2.5 text-[12.5px] text-crimson-ink">
                <strong>Unencrypted Air-Interface Warning:</strong> RRC is CONNECTED with null cipher ({phy.airSecurity.cipherName}). Verify your serving cell and PCI.
              </div>
            )}

            <div className="grid gap-2.5 grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">UL TX Power / HPUE</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular truncate">
                  {txDetail ? `${txDetail.puschDbm} / ${txDetail.maxDbm} dBm` : (phy.nr5gTxPwr ?? "--")}
                </div>
                {txDetail && (
                  <div className="mt-1.5 space-y-1">
                    <Meter pct={txPct} tone={txDetail.headroomDb <= 2 ? "saffron" : "jade"} thin />
                    <div className="text-[10.5px] text-muted qm-tabular">
                      Headroom {txDetail.headroomDb} dB · PUCCH {txDetail.pucchDbm}
                    </div>
                  </div>
                )}
              </div>

              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">RF Pathloss</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular">
                  {phy.nr5gPathlossDb != null ? `${phy.nr5gPathlossDb} dB` : "--"}
                </div>
                <div className="mt-0.5 text-[10.5px] text-muted">
                  {phy.nr5gPathlossDb != null
                    ? phy.nr5gPathlossDb < 105
                      ? "Low attenuation"
                      : phy.nr5gPathlossDb < 125
                        ? "Moderate link loss"
                        : "High cell-edge loss"
                    : "Awaiting NR5G"}
                </div>
              </div>

              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">DL MCS / Mod</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular">
                  {phy.nr5gDlMcs ? `MCS ${phy.nr5gDlMcs.mcs}` : "--"}
                </div>
                <div className="mt-0.5">
                  <Badge variant={phy.nr5gDlMcs?.modOrder === 3 ? "success" : "neutral"}>
                    {phy.nr5gDlMcs?.modulation ?? "--"}
                  </Badge>
                </div>
              </div>

              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">UL MCS / Mod</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular">
                  {phy.nr5gUlMcs ? `MCS ${phy.nr5gUlMcs.mcs}` : "--"}
                </div>
                <div className="mt-0.5">
                  <Badge variant={phy.nr5gUlMcs && phy.nr5gUlMcs.modOrder >= 2 ? "info" : "neutral"}>
                    {phy.nr5gUlMcs?.modulation ?? "--"}
                  </Badge>
                </div>
              </div>

              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">MIMO / CSI</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular truncate">
                  {phy.nr5gMimoLayers != null ? `${phy.nr5gMimoLayers}×L` : "--"}
                  {phy.nr5gCsi ? ` · CQI ${phy.nr5gCsi.cqi}` : ""}
                </div>
                <div className="mt-0.5 text-[10.5px] text-muted truncate">
                  {phy.nr5gCsi ? `RI ${phy.nr5gCsi.ri} · PMI ${phy.nr5gCsi.pmi}` : "Spatial rank"}
                </div>
              </div>

              <div className="qm-subcard p-3 min-w-0 space-y-1">
                <div className="text-[11px] font-semibold text-muted">Overheat / SFE</div>
                <div className="flex flex-wrap gap-1">
                  <Badge variant={phy.overheatInd ? "warning" : "neutral"}>
                    {phy.overheatInd == null ? "THM --" : phy.overheatInd ? "THM On" : "THM Off"}
                  </Badge>
                  <Badge variant={phy.sfeEnabled ? "info" : "neutral"}>
                    {phy.sfeEnabled == null ? "SFE --" : phy.sfeEnabled ? "SFE On" : "SFE Off"}
                  </Badge>
                </div>
              </div>
            </div>

            {/* Carrier 5QI QoS Priority & Session-AMBR Caps */}
            {(phy.qosBearers.length > 0 || phy.ambrCaps.length > 0) && (
              <div className="grid gap-3 md:grid-cols-2">
                {phy.qosBearers.length > 0 && (
                  <div className="qm-subcard p-3.5 space-y-2">
                    <div className="text-[11.5px] font-semibold text-muted">Carrier 5QI / QoS Priority</div>
                    <div className="space-y-1.5">
                      {phy.qosBearers.map((q) => (
                        <div key={`${q.cid}-${q.qfi}`} className="flex items-center justify-between gap-2 text-[12px]">
                          <span className="font-mono text-ink truncate">{q.apn}</span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <Badge variant={q.fiveQi <= 6 ? "success" : q.fiveQi <= 7 ? "info" : "warning"}>
                              5QI {q.fiveQi}
                            </Badge>
                            <span className="text-[11px] text-muted hidden sm:inline">{q.priorityLabel}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {phy.ambrCaps.length > 0 && (
                  <div className="qm-subcard p-3.5 space-y-2">
                    <div className="text-[11.5px] font-semibold text-muted">Provisioned Session-AMBR Caps</div>
                    <div className="space-y-1.5">
                      {phy.ambrCaps.map((a) => (
                        <div key={a.apn} className="flex items-center justify-between gap-2 text-[12px]">
                          <span className="font-mono text-ink truncate">{a.apn}</span>
                          <span className="font-mono text-ink-2 qm-tabular shrink-0">
                            ↓ {a.dlMbps.toLocaleString()} / ↑ {a.ulMbps.toLocaleString()} Mbps
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 5G SSB Beam Array */}
            {phy.ssbBeams.length > 0 && (
              <div className="qm-subcard p-3.5 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-[11.5px] font-semibold text-muted">
                    <Radio className="h-3.5 w-3.5" />
                    5G NR SSB Beamforming Array ({phy.ssbBeams.length} tracked beams)
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {phy.ssbBeams.slice(0, 8).map((b, idx) => (
                    <div
                      key={`${b.pci}-${b.beamId}-${idx}`}
                      className={cn(
                        "rounded-xl border px-2.5 py-1.5 text-[11.5px] font-mono qm-tabular",
                        b.isServing
                          ? "border-ember/50 bg-ember-soft text-ember-ink font-semibold"
                          : "border-line bg-surface text-ink-2"
                      )}
                    >
                      <span>{b.isServing ? "★ " : ""}Beam #{b.beamId}</span>
                      <span className="text-muted"> · PCI {b.pci} · </span>
                      <span>{b.rsrpDbm} dBm</span>
                      <span className="text-muted"> ({b.rsrqDb} dB)</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* QMI DSP Hardware Telemetry (TMD + SAR + QRTR Services) */}
            {dsp && (
              <div className="qm-subcard p-3.5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-[11.5px] font-semibold text-muted">
                    <Cpu className="h-3.5 w-3.5" />
                    SDX75 QRTR QMI DSP Services ({dsp.dspServiceCount} active)
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={dsp.anyThrottling ? "warning" : "success"}>
                      {dsp.anyThrottling ? "Thermal Mitigation Active" : "TMD Nominal (No Throttle)"}
                    </Badge>
                    <Badge variant={dsp.sarRfState && dsp.sarRfState > 0 ? "warning" : "neutral"}>
                      {dsp.sarLabel}
                    </Badge>
                  </div>
                </div>
                {dsp.tmdDevices.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {dsp.tmdDevices.map((d) => (
                      <Badge key={d.name} variant={d.throttling ? "warning" : "neutral"}>
                        {d.name}: L{d.currentLevel}/{d.maxLevel}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {caSwitches.length > 0 && (
            <div className="space-y-2.5 border-t border-line pt-4">
              <div className="text-[12.5px] font-semibold text-ink-2">Carrier Aggregation & MIMO</div>
              <div className="grid gap-3 md:grid-cols-2">
                {caSwitches.map((item) => (
                  <div key={item.key} className="qm-subcard p-3.5 min-w-0">
                    <Switch
                      checked={Boolean(draft[item.key])}
                      onChange={(next) => setDraft({ ...draft, [item.key]: next })}
                      label={item.label}
                      description={item.desc}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-2.5">
            <div className="text-[12.5px] font-semibold text-ink-2">Latency, Acquisition & Dual-SIM</div>
            <div className="grid gap-3 md:grid-cols-2">
              {latencySwitches.map((item) => (
                <div key={item.key} className="qm-subcard p-3.5 min-w-0">
                  <Switch
                    checked={Boolean(draft[item.key])}
                    onChange={(next) => setDraft({ ...draft, [item.key]: next })}
                    label={item.label}
                    description={item.desc}
                  />
                </div>
              ))}
              {draft.ratAcqOrder !== null && (
                <label className="qm-subcard p-3.5 min-w-0 block">
                  <div className="text-[13px] font-semibold text-ink">RAT acquisition order</div>
                  <div className="text-[12px] text-muted mt-0.5 mb-2">Scan order during initial attach and recovery (rat_acq_order)</div>
                  <Select
                    aria-label="RAT acquisition order"
                    value={draft.ratAcqOrder}
                    onChange={(e) => setDraft({ ...draft, ratAcqOrder: e.target.value })}
                  >
                    {ratOptions.map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </Select>
                </label>
              )}
              {draft.simSlot !== null && (
                <label className="qm-subcard p-3.5 min-w-0 block">
                  <div className="text-[13px] font-semibold text-ink">Active SIM slot (Dual-SIM)</div>
                  <div className="text-[12px] text-muted mt-0.5 mb-2">
                    Switch hardware USIM slot (AT+QUIMSLOT){draft.simDetEnabled != null ? ` · Hot-detect ${draft.simDetEnabled ? "On" : "Off"}` : ""}
                  </div>
                  <Select
                    aria-label="Active SIM slot"
                    value={String(draft.simSlot)}
                    onChange={(e) => setDraft({ ...draft, simSlot: Number(e.target.value) })}
                  >
                    <option value="1">SIM Slot 1 (Primary)</option>
                    <option value="2">SIM Slot 2 (Secondary / eSIM)</option>
                  </Select>
                </label>
              )}
            </div>
          </div>

          <div className="space-y-2.5">
            <div className="text-[12.5px] font-semibold text-ink-2">Band Priority, Frequency Steering & Handover Offset</div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="qm-subcard p-3.5 min-w-0 block">
                <div className="text-[13px] font-semibold text-ink">NR5G band priority</div>
                <div className="text-[12px] text-muted mt-0.5 mb-2">Colon-separated priority list; leave blank to clear (0)</div>
                <Input
                  className="font-mono"
                  placeholder="41:77:25:71"
                  value={nrPrioText}
                  onChange={(e) => setNrPrioText(e.target.value)}
                />
              </label>
              <label className="qm-subcard p-3.5 min-w-0 block">
                <div className="text-[13px] font-semibold text-ink">LTE band priority</div>
                <div className="text-[12px] text-muted mt-0.5 mb-2">Colon-separated priority list; leave blank to clear (0)</div>
                <Input
                  className="font-mono"
                  placeholder="66:2:41"
                  value={ltePrioText}
                  onChange={(e) => setLtePrioText(e.target.value)}
                />
              </label>
              <label className="qm-subcard p-3.5 min-w-0 block">
                <div className="text-[13px] font-semibold text-ink">Preferred 5G NR-ARFCN list</div>
                <div className="text-[12px] text-muted mt-0.5 mb-2">Up to 32 preferred ARFCN:SCS pairs (e.g. 501390:30; SCS auto-defaults if omitted)</div>
                <Input
                  className="font-mono"
                  placeholder="501390:30, 521310:30"
                  value={prefFreqText}
                  onChange={(e) => setPrefFreqText(e.target.value)}
                />
              </label>
              <label className="qm-subcard p-3.5 min-w-0 block">
                <div className="text-[13px] font-semibold text-ink">Multi-ARFCN 5G frequency lock</div>
                <div className="text-[12px] text-muted mt-0.5 mb-2">Lock PCC attach to ARFCN:SCS pairs (still aggregates SCCs); leave blank to unlock</div>
                <Input
                  className="font-mono"
                  placeholder="501390:30"
                  value={earfcnLockText}
                  onChange={(e) => setEarfcnLockText(e.target.value)}
                />
              </label>
              {draft.eventA3Enabled !== null && (
                <div className="qm-subcard p-3.5 min-w-0 md:col-span-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <Switch
                    checked={Boolean(draft.eventA3Enabled)}
                    onChange={(next) => setDraft({ ...draft, eventA3Enabled: next })}
                    label="Event A3 handover hysteresis offset"
                    description="Reduce ping-pong handovers between equal-strength sectors (event_a3_offset)"
                  />
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[12px] text-muted">Offset (0–255)</span>
                    <Input
                      type="number"
                      min={0}
                      max={255}
                      className="w-24 font-mono"
                      value={a3OffsetText}
                      onChange={(e) => setA3OffsetText(e.target.value)}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
            <span className="text-[12px] text-muted">
              Some baseband switches (CA / MIMO / C-DRX / SIM slot) require a cellular reconnect or reboot to take effect.
            </span>
            <div className="flex items-center gap-2">
              {dirty && (
                <Button size="sm" variant="ghost" disabled={busy} onClick={resetDraft}>
                  Discard
                </Button>
              )}
              <Button size="sm" variant="primary" disabled={!dirty || busy} onClick={() => void apply()}>
                <Check className="h-3.5 w-3.5" />
                {busy ? "Applying…" : "Apply Radio Tuning"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
