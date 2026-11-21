import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, RefreshCw, SlidersHorizontal } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { useToastStore } from "../../stores/toast-store";
import { Badge, Button, Card, CardHeader, Input, Select, Skeleton, Switch } from "../../components/ui";
import { LoadError, errText } from "../admin/shared";

interface CsiMetrics {
  mcs: number;
  ri: number;
  cqi: number;
  pmi: number;
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
}

interface PhyDiagnostics {
  nr5gCsi: CsiMetrics | null;
  lteCsi: CsiMetrics | null;
  nr5gMimoLayers: number | null;
  nr5gTxPwr: string | null;
  nr5gAmbr: string | null;
  overheatInd: boolean | null;
  sfeEnabled: boolean | null;
}

interface TuningResp {
  status: string;
  tuning: RadioTuningState;
  phy: PhyDiagnostics;
}

const KEY = ["cellular-tuning"];
const RAT_OPTIONS = ["LTE:NR5G:WCDMA", "NR5G:LTE:WCDMA", "NR5G:LTE", "LTE:NR5G"];

function parseBandText(raw: string): string[] {
  return raw
    .split(/[\s,:]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function RadioTuningCard() {
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const q = useQuery({
    queryKey: KEY,
    queryFn: () => apiFetch<TuningResp>("/api/v1/cellular/tuning"),
    staleTime: 15_000,
  });

  const [draft, setDraft] = useState<RadioTuningState | null>(null);
  const [ltePrioText, setLtePrioText] = useState("");
  const [nrPrioText, setNrPrioText] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!q.data) return;
    setDraft(q.data.tuning);
    setLtePrioText(q.data.tuning.lteBandPriority.join(":"));
    setNrPrioText(q.data.tuning.nr5gBandPriority.join(":"));
  }, [q.data]);

  const saved = q.data?.tuning;
  const phy = q.data?.phy;

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
    return patch;
  }

  const patch = buildPatch();
  const dirty = Object.keys(patch).length > 0;

  function resetDraft() {
    if (!saved) return;
    setDraft(saved);
    setLtePrioText(saved.lteBandPriority.join(":"));
    setNrPrioText(saved.nr5gBandPriority.join(":"));
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

  return (
    <Card className="space-y-5">
      <CardHeader
        title="RF, Carrier Aggregation & Latency Tuning"
        subtitle="Opt-in baseband features, band priority, and live PHY link-adaptation diagnostics"
        icon={<SlidersHorizontal className="h-4 w-4" />}
        action={
          <Button
            size="sm"
            variant="ghost"
            disabled={q.isFetching}
            onClick={() => {
              resetDraft();
              void q.refetch();
            }}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} />
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
          {caSwitches.length > 0 && (
            <div className="space-y-2.5">
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
            <div className="text-[12.5px] font-semibold text-ink-2">Latency & Acquisition</div>
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
            </div>
          </div>

          <div className="space-y-2.5">
            <div className="text-[12.5px] font-semibold text-ink-2">Band Priority (PCC preference without hard-locking)</div>
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
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
            <span className="text-[12px] text-muted">
              Some baseband switches (CA / MIMO / C-DRX) require a cellular reconnect or reboot to take effect.
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

          <div className="space-y-2 border-t border-line pt-4">
            <div className="text-[12px] font-semibold text-muted">Live PHY & Offload</div>
            <div className="grid gap-2.5 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">NR5G CSI (MCS / RI / CQI)</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular truncate">
                  {phy.nr5gCsi ? `${phy.nr5gCsi.mcs} / ${phy.nr5gCsi.ri} / ${phy.nr5gCsi.cqi}` : "--"}
                </div>
              </div>
              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">MIMO layers</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular truncate">
                  {phy.nr5gMimoLayers ?? "--"}
                </div>
              </div>
              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">NR5G TX power</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular truncate">
                  {phy.nr5gTxPwr ?? "--"}
                </div>
              </div>
              <div className="qm-subcard p-3 min-w-0">
                <div className="text-[11px] font-semibold text-muted">NR5G AMBR</div>
                <div className="mt-1 font-mono text-[13px] font-semibold text-ink qm-tabular truncate">
                  {phy.nr5gAmbr ?? "--"}
                </div>
              </div>
              <div className="qm-subcard p-3 min-w-0 space-y-1">
                <div className="text-[11px] font-semibold text-muted">Overheat / SFE</div>
                <div className="flex flex-wrap gap-1">
                  <Badge variant={phy.overheatInd ? "warning" : "neutral"}>
                    {phy.overheatInd == null ? "THM --" : phy.overheatInd ? "THM Ind On" : "THM Off"}
                  </Badge>
                  <Badge variant={phy.sfeEnabled ? "info" : "neutral"}>
                    {phy.sfeEnabled == null ? "SFE --" : phy.sfeEnabled ? "SFE On" : "SFE Off"}
                  </Badge>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
