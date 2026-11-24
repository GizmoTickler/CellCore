import React, { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../lib/api";
import { disruptiveFetch, isCancelled } from "../lib/disruptive";
import { describeChannel } from "../lib/rf";
import { cn } from "../lib/utils";
import { useWsStore } from "../stores/ws-store";
import { useSubRoute } from "../stores/route-store";
import { useToastStore } from "../stores/toast-store";
import type {
  AntennaAlignState,
  CarrierComponent,
  DaemonSettings,
  MbnProfile,
  NeighborCellInfo,
  QuecProfileItem,
} from "../types/cellcore";
import { Button, Input, LiveDot, Modal, PageHeader, Select, Skeleton, signalQuality } from "../components/ui";
import { ConfirmModal, Field, TONE_TEXT, rsrpTone } from "./cellular/shared";
import { FailoverWarning } from "../components/obs";
import { useDraft } from "../lib/draft";
import { useLockForm } from "./cellular/lock-form";
import { ProfilesView } from "./cellular/ProfilesView";
import { BandsView, type BandGroup, type BandGroupId } from "./cellular/BandsView";
import { LockView } from "./cellular/LockView";
import { ScanView, type QscanEntry } from "./cellular/ScanView";

const RadioTuningCard = lazy(() => import("./cellular/RadioTuningCard").then((m) => ({ default: m.RadioTuningCard })));
const AlignView = lazy(() => import("./cellular/AlignView").then((m) => ({ default: m.AlignView })));

const CELL_TABS = ["profiles", "bands", "tuning", "lock", "align", "scan"] as const;
type CellTab = (typeof CELL_TABS)[number];

const NO_BANDS: string[] = [];

const LTE_BANDS = ["2", "4", "5", "12", "13", "14", "25", "26", "30", "41", "48", "66", "71"];
const NR5G_BANDS = ["2", "5", "12", "25", "30", "41", "48", "66", "71", "77"];

/**
 * Band groups the modem would use under this mode (nr5gDisable 1 = SA off, 2 = NSA off)
 * that have no band selected. Mirrors the daemon's check; the daemon has the final say.
 */
function emptyActiveBandGroups(modePref: string, nrDisable: number, sel: { lte: string[]; nsa: string[]; sa: string[] }) {
  const mode = modePref.trim().toUpperCase();
  const active: Array<["lte" | "nsa" | "sa", string]> =
    mode === "LTE" ? [["lte", "LTE"]]
    : mode === "NR5G" ? (nrDisable !== 1 ? [["sa", "NR5G-SA"]] : [])
    : [["lte", "LTE"], ...(nrDisable !== 2 ? [["nsa", "NR5G-NSA"] as ["nsa", string]] : []), ...(nrDisable !== 1 ? [["sa", "NR5G-SA"] as ["sa", string]] : [])];
  return active.filter(([k]) => sel[k].length === 0).map(([, label]) => label);
}

/** Hard-coded list plus anything the modem reports, so no enabled band is ever hidden. */
function bandUniverse(base: string[], ...extra: string[][]) {
  const set = new Set(base);
  for (const list of extra) for (const b of list) if (b) set.add(b);
  return [...set].sort((a, b) => Number(a) - Number(b));
}

const EMPTY_CARRIERS: CarrierComponent[] = [];

const ServingChip = React.memo(function ServingChip() {
  const serving = useWsStore((s) => s.modem?.serving ?? null);
  if (!serving) return null;
  const quality = signalQuality(serving.rsrp ?? null, serving.sinr ?? null);
  return (
    <div className="flex items-center gap-3 rounded-full border border-line bg-surface py-1.5 pl-3 pr-4 shadow-[var(--qm-shadow)]">
      <LiveDot tone={quality.tone} />
      <div className="leading-tight">
        <div className="text-[11px] font-semibold text-muted">
          {serving.rat} · cell <span className="font-mono">{serving.pci ?? "—"}</span>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="qm-display text-[1.05rem] font-semibold text-ink">{serving.band}</span>
          <span className={cn("text-[12.5px] font-bold qm-tabular", TONE_TEXT[rsrpTone(serving.rsrp)])}>
            {serving.rsrp ?? "—"} dBm
          </span>
          <span className="text-[11.5px] text-muted">{quality.label}</span>
        </div>
      </div>
    </div>
  );
});

const BandsTab = React.memo(function BandsTab(
  props: Omit<React.ComponentProps<typeof BandsView>, "serving" | "carriers">
) {
  // Only re-render when RAT, serving band, or carrier aggregation composition actually changes.
  useWsStore((s) => {
    const sv = s.modem?.serving;
    const cs = s.modem?.carriers;
    return sv ? `${sv.rat}|${sv.band}|${(cs ?? []).map((c) => `${c.role}:${c.band}:${c.arfcn}`).join(",")}` : "";
  });
  const modem = useWsStore.getState().modem;
  return <BandsView {...props} serving={modem?.serving ?? null} carriers={modem?.carriers ?? EMPTY_CARRIERS} />;
});

const LockTab = React.memo(function LockTab(
  props: Omit<React.ComponentProps<typeof LockView>, "serving">
) {
  useWsStore((s) => {
    const sv = s.modem?.serving;
    return sv ? `${sv.rat}|${sv.band}|${sv.pci ?? ""}|${sv.arfcn ?? ""}|${sv.scsKhz ?? ""}|${sv.rsrp ?? ""}` : "";
  });
  const serving = useWsStore.getState().modem?.serving ?? null;
  return <LockView {...props} serving={serving} />;
});

const ScanTab = React.memo(function ScanTab(
  props: Omit<React.ComponentProps<typeof ScanView>, "serving">
) {
  useWsStore((s) => {
    const sv = s.modem?.serving;
    return sv ? `${sv.band}|${sv.pci ?? ""}|${sv.arfcn ?? ""}|${sv.rsrp ?? ""}|${sv.mcc}|${sv.mnc}` : "";
  });
  const serving = useWsStore.getState().modem?.serving ?? null;
  return <ScanView {...props} serving={serving} />;
});

const AlignTab = React.memo(function AlignTab({
  busy,
  setBusy,
  notify,
}: {
  busy: string | null;
  setBusy: React.Dispatch<React.SetStateAction<string | null>>;
  notify: (kind: "ok" | "err", msg: string) => void;
}) {
  const antennaAlign = useWsStore((s) => s.antennaAlign);
  const mimo = useWsStore((s) => s.modem?.mimo ?? null);
  const antennaLabels = useWsStore((s) => s.settings?.antennaLabels);
  const setAntennaAlign = useWsStore((s) => s.setAntennaAlign);
  const setSettings = useWsStore((s) => s.setSettings);
  const sendWsCommand = useWsStore((s) => s.sendWsCommand);

  const [resetSeq, setResetSeq] = useState(0);
  const keepAwake = Boolean(antennaAlign?.keepAwake);
  const userKeepAwakeRef = useRef<boolean | null>(null);
  const keepAwakeRef = useRef(keepAwake);
  keepAwakeRef.current = keepAwake;

  // Activate 400 ms high-rate Antenna Alignment polling while mounted (auto-enabling 4x4 RX keep-awake
  // unless explicitly turned off), renew 300s lease every 120s, and clean up on exit/unmount.
  useEffect(() => {
    let active = true;
    sendWsCommand({ action: "set_fast_rf", enabled: true });
    const renew = () => {
      const wantAwake = userKeepAwakeRef.current ?? true;
      void apiFetch<{ align?: AntennaAlignState }>("/api/v1/cellular/align", {
        method: "POST",
        body: JSON.stringify({ active: true, resetPeaks: false, keepAwake: wantAwake }),
      })
        .then((res) => {
          if (active && res.align) setAntennaAlign(res.align);
        })
        .catch(() => {
          // ignore if unmounted early
        });
    };
    renew();
    const leaseId = window.setInterval(renew, 120_000);
    return () => {
      active = false;
      window.clearInterval(leaseId);
      sendWsCommand({ action: "set_fast_rf", enabled: false });
      void apiFetch("/api/v1/cellular/align", {
        method: "POST",
        skipAuthRedirect: true,
        body: JSON.stringify({ active: false, resetPeaks: false, keepAwake: false }),
      }).catch(() => {});
    };
  }, [sendWsCommand, setAntennaAlign]);

  async function resetAlignPeaks() {
    setBusy("align-reset");
    try {
      const res = await apiFetch<{ align?: AntennaAlignState }>("/api/v1/cellular/align", {
        method: "POST",
        body: JSON.stringify({ active: true, resetPeaks: true, keepAwake: keepAwakeRef.current }),
      });
      if (res.align) setAntennaAlign(res.align);
      setResetSeq((n) => n + 1);
      notify("ok", "All peaks reset");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Reset failed");
    } finally {
      setBusy(null);
    }
  }

  async function resetAlignChainPeak(chainIdx: number) {
    setBusy("align-reset");
    try {
      const res = await apiFetch<{ align?: AntennaAlignState }>("/api/v1/cellular/align", {
        method: "POST",
        body: JSON.stringify({
          active: true,
          resetPeaks: false,
          resetChain: chainIdx,
          keepAwake: keepAwakeRef.current,
        }),
      });
      if (res.align) setAntennaAlign(res.align);
      notify("ok", `RX${chainIdx} peak reset`);
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Reset failed");
    } finally {
      setBusy(null);
    }
  }

  async function toggleAlignKeepAwake(next: boolean) {
    userKeepAwakeRef.current = next;
    setBusy("align-awake");
    try {
      const res = await apiFetch<{ align?: AntennaAlignState }>("/api/v1/cellular/align", {
        method: "POST",
        body: JSON.stringify({ active: true, resetPeaks: false, keepAwake: next }),
      });
      if (res.align) setAntennaAlign(res.align);
      notify("ok", next ? "4×4 RX Awake enabled" : "4×4 RX Awake paused");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Failed toggling keep-awake");
    } finally {
      setBusy(null);
    }
  }

  async function saveAntennaLabels(labels: [string, string, string, string]) {
    setBusy("align-labels");
    try {
      const res = await apiFetch<{ status: string; settings?: DaemonSettings }>("/api/v1/system/settings", {
        method: "POST",
        body: JSON.stringify({ antennaLabels: labels }),
      });
      if (res.settings) setSettings(res.settings);
      notify("ok", "Saved antenna jack labels");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Failed saving labels");
    } finally {
      setBusy(null);
    }
  }

  const alignData = antennaAlign;
  const liveAlignRsrp = alignData?.rsrp ?? mimo?.rsrp ?? [null, null, null, null];
  const liveAlignSinr = alignData?.sinr ?? mimo?.sinr ?? [null, null, null, null];
  const liveAlignRsrq = alignData?.rsrq ?? mimo?.rsrq ?? [null, null, null, null];
  const peakRsrp = alignData?.peakRsrp ?? [null, null, null, null];
  const peakSinr = alignData?.peakSinr ?? [null, null, null, null];

  const alignSummary = useMemo(() => {
    const activeCur = liveAlignRsrp.filter((v): v is number => v != null);
    const activePeak = peakRsrp.filter((v): v is number => v != null);
    const activeSinr = liveAlignSinr.filter((v): v is number => v != null);
    const meanCur =
      activeCur.length > 0 ? Math.round((activeCur.reduce((a, b) => a + b, 0) / activeCur.length) * 10) / 10 : null;
    const computedPeak =
      activePeak.length > 0
        ? Math.round((activePeak.reduce((a, b) => a + b, 0) / activePeak.length) * 10) / 10
        : null;
    const meanPeak = alignData?.peakMeanRsrp ?? computedPeak;
    const meanSinr =
      activeSinr.length > 0
        ? Math.round((activeSinr.reduce((a, b) => a + b, 0) / activeSinr.length) * 10) / 10
        : null;
    const score =
      meanCur != null
        ? Math.max(0, Math.min(100, Math.round(((meanCur + 125) / 55) * 70 + ((meanSinr ?? 5) + 5) * 1.2)))
        : 0;
    return {
      meanCur,
      meanPeak,
      meanSinr,
      peakMeanSinr: alignData?.peakMeanSinr ?? null,
      score,
    };
  }, [liveAlignRsrp, peakRsrp, liveAlignSinr, alignData?.peakMeanRsrp, alignData?.peakMeanSinr]);

  return (
    <Suspense fallback={<Skeleton className="h-64" />}>
      <AlignView
        active={Boolean(alignData?.active)}
        samples={alignData?.samples ?? 0}
        rsrp={liveAlignRsrp}
        sinr={liveAlignSinr}
        rsrq={liveAlignRsrq}
        peakRsrp={peakRsrp}
        peakSinr={peakSinr}
        summary={alignSummary}
        align={alignData}
        resetSeq={resetSeq}
        keepAwake={keepAwake}
        onToggleKeepAwake={(next) => void toggleAlignKeepAwake(next)}
        busy={busy}
        onResetPeaks={() => void resetAlignPeaks()}
        onResetChainPeak={(idx) => void resetAlignChainPeak(idx)}
        antennaLabels={antennaLabels}
        onSaveAntennaLabels={(labels) => void saveAntennaLabels(labels)}
      />
    </Suspense>
  );
});

export function CellularPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useSubRoute<CellTab>("/cellular", CELL_TABS, "profiles");
  const pushToast = useToastStore((s) => s.push);
  const [busy, setBusy] = useState<string | null>(null);

  const [mbnQuery, setMbnQuery] = useState("");
  const [profileModal, setProfileModal] = useState<QuecProfileItem | null>(null);


  const lockForm = useLockForm();
  const { nrPci, nrArfcn, nrScs, nrBand, ltePci, lteEarfcn } = lockForm;
  const setLockForm = lockForm.set;
  const [confirmLink, setConfirmLink] = useState<null | "bands" | "nr" | "lte">(null);

  const hydrateBootstrap = useWsStore((s) => s.hydrateBootstrap);

  function notify(kind: "ok" | "err", msg: string) {
    pushToast(msg, kind === "ok" ? "success" : "error");
  }

  const profilesQuery = useQuery({
    queryKey: ["cellular-profiles"],
    queryFn: () =>
      apiFetch<{
        profiles?: QuecProfileItem[];
        mbnProfiles?: MbnProfile[];
        mbnAutoSel?: boolean;
        apnRaw?: string;
      }>("/api/v1/cellular/profiles"),
    enabled: tab === "profiles",
  });

  const bandsQuery = useQuery({
    queryKey: ["cellular-bands"],
    queryFn: () =>
      apiFetch<{
        lteBands?: string[];
        nsaNr5gBands?: string[];
        nr5gBands?: string[];
        policyRaw?: string;
      }>("/api/v1/cellular/bands"),
    enabled: tab === "bands",
  });

  const modeQuery = useQuery({
    queryKey: ["cellular-mode"],
    queryFn: () =>
      apiFetch<{
        modePref?: string;
        nr5gDisableMode?: number;
        simSlot?: number;
        apnRaw?: string;
      }>("/api/v1/cellular/mode"),
    enabled: tab === "bands",
  });

  const cellLockQuery = useQuery({
    queryKey: ["cell-lock-state"],
    queryFn: () =>
      apiFetch<{
        lteRaw?: string;
        nr5gRaw?: string;
        saveCtrlRaw?: string;
        bypassed?: boolean;
        cellLockDeadmanEnabled?: boolean;
        cellLockDeadmanSecs?: number;
        schedule?: {
          enabled: boolean;
          startTime: string;
          endTime: string;
          lteLock: string;
          nr5gLock: string;
          ltePersist: boolean;
          nr5gPersist: boolean;
          deadmanEnabled?: boolean;
          deadmanSecs?: number;
          bypassed?: boolean;
        };
      }>("/api/v1/cellular/cell-lock"),
    enabled: tab === "lock",
  });

  const scanQuery = useQuery({
    queryKey: ["cellular-scan"],
    queryFn: () =>
      apiFetch<{
        neighbors?: NeighborCellInfo[];
        scanRunning?: boolean;
        scanResult?: {
          status?: string;
          timestamp?: string;
          entries?: QscanEntry[];
          raw?: string;
          error?: string;
        } | null;
      }>("/api/v1/cellular/scan"),
    enabled: tab === "scan",
    refetchInterval: (q) => (q.state.data?.scanRunning ? 3000 : false),
  });

  // Drafts: refetches (after another apply, a page remount, a schedule toggle) never overwrite a
  // band, mode or schedule selection the user is still editing.
  const [modePref, setModePref, modeD] = useDraft(modeQuery.data?.modePref || null, "AUTO");
  const [nrDisable, setNrDisable, nrD] = useDraft(
    modeQuery.data?.nr5gDisableMode != null ? String(modeQuery.data.nr5gDisableMode) : null,
    "0"
  );
  const [selLte, setSelLte, lteD] = useDraft(bandsQuery.data ? bandsQuery.data.lteBands ?? NO_BANDS : null, NO_BANDS);
  const [selSa, setSelSa, saD] = useDraft(bandsQuery.data ? bandsQuery.data.nr5gBands ?? NO_BANDS : null, NO_BANDS);
  const [selNsa, setSelNsa, nsaD] = useDraft(bandsQuery.data ? bandsQuery.data.nsaNr5gBands ?? NO_BANDS : null, NO_BANDS);
  const modeChanged = modeQuery.data?.modePref != null && modeQuery.data.modePref !== modePref;
  const resetBandDrafts = () => [modeD, nrD, lteD, saD, nsaD].forEach((x) => x.reset());
  const sched0 = cellLockQuery.data?.schedule;
  const [schedStart, setSchedStart, schedStartD] = useDraft(sched0?.startTime || null, "08:00");
  const [schedEnd, setSchedEnd, schedEndD] = useDraft(sched0?.endTime || null, "22:00");
  const serverDeadmanEnabled =
    cellLockQuery.data?.cellLockDeadmanEnabled ?? sched0?.deadmanEnabled ?? null;
  const serverDeadmanSecs =
    cellLockQuery.data?.cellLockDeadmanSecs ?? sched0?.deadmanSecs ?? null;
  const [deadmanEnabled, setDeadmanEnabled, deadmanEnD] = useDraft(serverDeadmanEnabled, true);
  const [deadmanSecs, setDeadmanSecs, deadmanSecsD] = useDraft(serverDeadmanSecs, 180);
  const cellLockBypassed = Boolean(cellLockQuery.data?.bypassed ?? sched0?.bypassed);
  const deadmanDirty =
    (serverDeadmanEnabled != null && deadmanEnabled !== serverDeadmanEnabled) ||
    (serverDeadmanSecs != null && deadmanSecs !== serverDeadmanSecs);
  const schedDirty =
    (sched0?.startTime != null && schedStart !== sched0.startTime) ||
    (sched0?.endTime != null && schedEnd !== sched0.endTime);

  const mbnState = useMemo(() => {
    const list = profilesQuery.data?.mbnProfiles ?? [];
    const filtered = list.filter((m) =>
      m.name.toLowerCase().includes(mbnQuery.trim().toLowerCase())
    );
    return {
      autoOn: Boolean(profilesQuery.data?.mbnAutoSel),
      all: list,
      list: filtered,
      totalCount: list.length,
    };
  }, [profilesQuery.data, mbnQuery]);

  const activeLocks = useMemo(() => {
    const lteRaw = cellLockQuery.data?.lteRaw ?? "";
    const nrRaw = cellLockQuery.data?.nr5gRaw ?? "";
    const saveRaw = cellLockQuery.data?.saveCtrlRaw ?? "";
    const saveMatch = saveRaw.match(/"save_ctrl"\s*,\s*(\d)\s*,\s*(\d)/);
    return {
      lteLocked: /"common\/4g"\s*,\s*[1-9]/.test(lteRaw) || Boolean(cellLockQuery.data?.schedule?.lteLock),
      nrLocked: /"common\/5g"\s*,\s*[1-9]/.test(nrRaw) || Boolean(cellLockQuery.data?.schedule?.nr5gLock),
      ltePersist: saveMatch?.[1] === "1" || Boolean(cellLockQuery.data?.schedule?.ltePersist),
      nrPersist: saveMatch?.[2] === "1" || Boolean(cellLockQuery.data?.schedule?.nr5gPersist),
    };
  }, [cellLockQuery.data]);

  const [nrPersistDraft, setNrPersistDraft, nrPersistD] = useDraft<boolean>(
    cellLockQuery.data ? activeLocks.nrPersist : null,
    false
  );
  const [ltePersistDraft, setLtePersistDraft, ltePersistD] = useDraft<boolean>(
    cellLockQuery.data ? activeLocks.ltePersist : null,
    false
  );

  async function toggleMbnAutoSel(next: boolean) {
    setBusy("autosel");
    try {
      await disruptiveFetch("MBN change", "/api/v1/cellular/mbn", {
        method: "POST",
        body: JSON.stringify({ action: "autosel", enabled: next }),
      });
      await qc.invalidateQueries({ queryKey: ["cellular-profiles"] });
      notify("ok", `Automatic carrier selection ${next ? "on" : "off"}`);
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed to update AutoSel");
    } finally {
      setBusy(null);
    }
  }

  async function selectMbn(name: string) {
    setBusy(`mbn-${name}`);
    try {
      await disruptiveFetch(
        "MBN change",
        "/api/v1/cellular/mbn",
        {
          method: "POST",
          body: JSON.stringify({ action: "select", profileName: name }),
        },
        { confirmed: true }
      );
      await qc.invalidateQueries({ queryKey: ["cellular-profiles"] });
      notify("ok", `Carrier profile ${name} activated`);
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed to select MBN");
    } finally {
      setBusy(null);
    }
  }

  async function fillCurrentSimIccid() {
    setBusy("fill-iccid");
    try {
      const s = await apiFetch<{ iccid?: string }>("/api/v1/modem/secrets");
      if (s.iccid) {
        setProfileModal((cur) => (cur ? { ...cur, iccid: s.iccid ?? cur.iccid } : cur));
        notify("ok", "Filled in current SIM ICCID");
      } else {
        notify("err", "SIM ICCID is not available");
      }
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Could not read SIM ICCID");
    } finally {
      setBusy(null);
    }
  }

  async function saveProfile(e: React.FormEvent) {
    e.preventDefault();
    if (!profileModal) return;
    setBusy("save-prof");
    try {
      await apiFetch("/api/v1/cellular/profiles", {
        method: "POST",
        body: JSON.stringify({
          index: profileModal.index,
          name: profileModal.name,
          iccid: profileModal.iccid,
          imei: profileModal.imei ?? "",
          apn: profileModal.apn,
          pdpType: profileModal.pdp_type,
          networkType: profileModal.network_type,
          ttl: profileModal.ttl || "0",
          lteBands: profileModal.lte_bands ?? "",
          saNr5gBands: profileModal.sa_nr5g_bands ?? "",
          nsaNr5gBands: profileModal.nsa_nr5g_bands ?? "",
          mobileProvider: profileModal.mobile_provider ?? "Other",
          mbnProfile: profileModal.mbn_profile ?? "",
        }),
      });
      setProfileModal(null);
      await qc.invalidateQueries({ queryKey: ["cellular-profiles"] });
      notify("ok", "Profile saved");
    } catch (err) {
      notify("err", err instanceof Error ? err.message : "Profile save failed");
    } finally {
      setBusy(null);
    }
  }

  async function deleteProfile(index: number | undefined) {
    if (index == null) return;
    setBusy(`del-${index}`);
    try {
      await apiFetch(`/api/v1/cellular/profiles?index=${index}`, { method: "DELETE" });
      await qc.invalidateQueries({ queryKey: ["cellular-profiles"] });
      notify("ok", "Profile deleted");
    } catch (err) {
      notify("err", err instanceof Error ? err.message : "Delete failed");
    } finally {
      setBusy(null);
    }
  }

  async function toggleProfilePause(p: QuecProfileItem) {
    if (p.index == null) return;
    const isPaused = String(p.paused) === "1" || p.paused === true;
    setBusy(`pause-${p.index}`);
    try {
      await apiFetch("/api/v1/cellular/profiles/pause", {
        method: "POST",
        body: JSON.stringify({ index: p.index, paused: !isPaused }),
      });
      await qc.invalidateQueries({ queryKey: ["cellular-profiles"] });
      notify("ok", `Profile ${!isPaused ? "paused" : "resumed"}`);
    } catch (err) {
      notify("err", err instanceof Error ? err.message : "Failed to toggle profile");
    } finally {
      setBusy(null);
    }
  }

  const groupSetter: Record<BandGroupId, React.Dispatch<React.SetStateAction<string[]>>> = {
    sa: setSelSa,
    nsa: setSelNsa,
    lte: setSelLte,
  };

  function toggleBand(setter: React.Dispatch<React.SetStateAction<string[]>>, band: string) {
    setter((prev) => (prev.includes(band) ? prev.filter((b) => b !== band) : [...prev, band]));
  }

  function setBandGroup(group: BandGroupId, bands: string[]) {
    groupSetter[group](bands);
  }

  function reloadBands() {
    resetBandDrafts();
    void bandsQuery.refetch();
    void modeQuery.refetch();
  }

  async function applyBandLocks() {
    if (modePref.trim().toUpperCase() === "NR5G" && Number(nrDisable) === 1) {
      notify("err", "NR5G-only mode with 5G SA disabled leaves the modem no network to use: enable 5G SA or choose another network mode");
      return;
    }
    const empty = emptyActiveBandGroups(modePref, Number(nrDisable), { lte: selLte, nsa: selNsa, sa: selSa });
    if (empty.length) {
      notify("err", `Select at least one band for ${empty.join(", ")}: an empty list would leave the modem without a usable band`);
      return;
    }
    setBusy("apply-bands");
    try {
      // One request: the daemon validates bands and mode together, writes them
      // in an order that never strands the modem without a usable band, and on
      // failure reports what was applied and what it rolled back.
      // The confirm Modal (with the failover warning) was already shown.
      await disruptiveFetch(
        "band and network mode change",
        "/api/v1/cellular/bands",
        {
          method: "POST",
          body: JSON.stringify({
            lteBands: selLte,
            nsaNr5gBands: selNsa,
            nr5gBands: selSa,
            modePref,
            nr5gDisableMode: Number(nrDisable),
          }),
        },
        { confirmed: true }
      );
      await qc.invalidateQueries({ queryKey: ["cellular-bands"] });
      await qc.invalidateQueries({ queryKey: ["cellular-mode"] });
      resetBandDrafts();
      void hydrateBootstrap();
      notify("ok", "Network mode and bands applied");
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed applying band locks");
    } finally {
      setBusy(null);
    }
  }

  function prefillFromServingCell() {
    const serving = useWsStore.getState().modem?.serving ?? null;
    if (!serving) {
      notify("err", "No serving cell detected yet");
      return;
    }
    if (serving.rat.includes("NR5G")) {
      const bandNum = serving.band.replace(/^n/i, "");
      const scs =
        serving.scsKhz != null
          ? String(serving.scsKhz)
          : bandNum === "41" || bandNum === "77" || bandNum === "78"
            ? "30"
            : "15";
      setLockForm({
        nrPci: serving.pci != null ? String(serving.pci) : "",
        nrArfcn: serving.arfcn != null ? String(serving.arfcn) : "",
        nrBand: bandNum,
        nrScs: scs,
      });
      notify("ok", `Filled in 5G cell ${serving.pci} · ARFCN ${serving.arfcn}`);
    } else {
      setLockForm({
        ltePci: serving.pci != null ? String(serving.pci) : "",
        lteEarfcn: serving.arfcn != null ? String(serving.arfcn) : "",
      });
      notify("ok", `Filled in LTE cell ${serving.pci} · EARFCN ${serving.arfcn}`);
    }
  }

  function askNrCellLock() {
    if (!nrPci.trim() || !nrArfcn.trim() || !nrBand.trim()) {
      notify("err", "5G lock needs a cell ID (PCI), channel (ARFCN) and band");
      return;
    }
    setConfirmLink("nr");
  }

  function askLteCellLock() {
    if (!ltePci.trim() || !lteEarfcn.trim()) {
      notify("err", "LTE lock needs a cell ID (PCI) and channel (EARFCN)");
      return;
    }
    setConfirmLink("lte");
  }

  async function applyNrCellLock() {
    setBusy("nr-lock");
    try {
      await disruptiveFetch(
        "cell lock",
        "/api/v1/cellular/cell-lock",
        {
          method: "POST",
          body: JSON.stringify({
            rat: "nr5g",
            pci: Number(nrPci),
            arfcn: Number(nrArfcn),
            scs: Number(nrScs),
            band: Number(nrBand),
            persist: nrPersistDraft,
          }),
        },
        { confirmed: true }
      );
      await qc.invalidateQueries({ queryKey: ["cell-lock-state"] });
      nrPersistD.reset();
      notify("ok", `5G pinned to cell ${nrPci} on ARFCN ${nrArfcn}`);
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed locking NR5G");
    } finally {
      setBusy(null);
    }
  }

  async function applyLteCellLock() {
    setBusy("lte-lock");
    try {
      await disruptiveFetch(
        "cell lock",
        "/api/v1/cellular/cell-lock",
        {
          method: "POST",
          body: JSON.stringify({
            rat: "lte",
            pci: Number(ltePci),
            arfcn: Number(lteEarfcn),
            persist: ltePersistDraft,
          }),
        },
        { confirmed: true }
      );
      await qc.invalidateQueries({ queryKey: ["cell-lock-state"] });
      ltePersistD.reset();
      notify("ok", `LTE pinned to cell ${ltePci} on EARFCN ${lteEarfcn}`);
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed locking LTE");
    } finally {
      setBusy(null);
    }
  }

  async function saveDeadman() {
    setBusy("deadman");
    try {
      await apiFetch("/api/v1/cellular/cell-lock", {
        method: "POST",
        body: JSON.stringify({
          deadmanEnabled,
          deadmanSecs,
        }),
      });
      await qc.invalidateQueries({ queryKey: ["cell-lock-state"] });
      deadmanEnD.reset();
      deadmanSecsD.reset();
      notify("ok", deadmanEnabled ? `Dead-Man's Switch armed (${deadmanSecs}s)` : "Dead-Man's Switch disabled");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Failed saving dead-man settings");
    } finally {
      setBusy(null);
    }
  }

  const canRearmBypassed = Boolean(sched0?.nr5gLock || sched0?.lteLock);

  async function rearmBypassedLock() {
    setBusy("rearm");
    try {
      let applied = false;
      const nrParts = (sched0?.nr5gLock ?? "").split(",").map((x) => Number(x.trim()));
      if (nrParts.length >= 4 && nrParts.every((n) => Number.isFinite(n))) {
        await disruptiveFetch("re-arm 5G cell lock", "/api/v1/cellular/cell-lock", {
          method: "POST",
          body: JSON.stringify({
            rat: "nr5g",
            pci: nrParts[0],
            arfcn: nrParts[1],
            scs: nrParts[2],
            band: nrParts[3],
            persist: activeLocks.nrPersist,
          }),
        });
        applied = true;
      }
      const lteParts = (sched0?.lteLock ?? "").split(",").map((x) => Number(x.trim()));
      if (lteParts.length >= 3 && lteParts.every((n) => Number.isFinite(n))) {
        await disruptiveFetch("re-arm LTE cell lock", "/api/v1/cellular/cell-lock", {
          method: "POST",
          body: JSON.stringify({
            rat: "lte",
            arfcn: lteParts[1],
            pci: lteParts[2],
            persist: activeLocks.ltePersist,
          }),
        });
        applied = true;
      }
      if (!applied) {
        notify("err", "No saved cell lock parameters available to re-arm");
        return;
      }
      await qc.invalidateQueries({ queryKey: ["cell-lock-state"] });
      notify("ok", "Cell lock re-armed");
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Failed re-arming cell lock");
    } finally {
      setBusy(null);
    }
  }

  async function clearCellLock(rat: "lte" | "nr5g" | "all") {
    setBusy(`clear-${rat}`);
    try {
      await disruptiveFetch("cell unlock", `/api/v1/cellular/cell-lock?rat=${rat}`, { method: "DELETE" });
      await qc.invalidateQueries({ queryKey: ["cell-lock-state"] });
      notify("ok", rat === "all" ? "All cell locks released" : `${rat === "lte" ? "LTE" : "5G"} cell lock released`);
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "Unlock failed");
    } finally {
      setBusy(null);
    }
  }

  async function saveSchedule(enabled: boolean, message?: string) {
    setBusy("sched");
    try {
      await apiFetch("/api/v1/cellular/cell-lock", {
        method: "POST",
        body: JSON.stringify({
          scheduleEnabled: enabled,
          startTime: schedStart,
          endTime: schedEnd,
        }),
      });
      await qc.invalidateQueries({ queryKey: ["cell-lock-state"] });
      schedStartD.reset();
      schedEndD.reset();
      notify("ok", message ?? `Lock schedule ${enabled ? "on" : "off"}`);
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Schedule update failed");
    } finally {
      setBusy(null);
    }
  }

  function toggleSchedule(enabled: boolean) {
    void saveSchedule(enabled);
  }

  async function startFullQscan() {
    setBusy("qscan");
    try {
      // ScanView's confirm dialog shows the failover warning.
      await disruptiveFetch("cell survey", "/api/v1/cellular/scan", { method: "POST", body: "{}" }, { confirmed: true });
      await qc.invalidateQueries({ queryKey: ["cellular-scan"] });
      notify("ok", "Survey started. Results appear here as it finishes.");
    } catch (e) {
      if (!isCancelled(e)) notify("err", e instanceof Error ? e.message : "QSCAN start error");
    } finally {
      setBusy(null);
    }
  }

  async function clearScanResult() {
    setBusy("qscan-clear");
    try {
      await apiFetch("/api/v1/cellular/scan", { method: "DELETE" });
      await qc.invalidateQueries({ queryKey: ["cellular-scan"] });
      notify("ok", "Survey results cleared");
    } catch (e) {
      notify("err", e instanceof Error ? e.message : "Clear failed");
    } finally {
      setBusy(null);
    }
  }

  const neighbors = scanQuery.data?.neighbors ?? [];

  const bandGroups: BandGroup[] = useMemo(() => {
    const d = bandsQuery.data;
    return [
      {
        id: "sa",
        title: "5G standalone",
        term: "NR5G SA",
        prefix: "n",
        supported: bandUniverse(NR5G_BANDS, d?.nr5gBands ?? [], selSa),
        selected: selSa,
        saved: d?.nr5gBands ?? [],
      },
      {
        id: "nsa",
        title: "5G non-standalone",
        term: "NR5G NSA",
        prefix: "n",
        supported: bandUniverse(NR5G_BANDS, d?.nsaNr5gBands ?? [], selNsa),
        selected: selNsa,
        saved: d?.nsaNr5gBands ?? [],
      },
      {
        id: "lte",
        title: "LTE",
        term: "4G LTE",
        prefix: "B",
        supported: bandUniverse(LTE_BANDS, d?.lteBands ?? [], selLte),
        selected: selLte,
        saved: d?.lteBands ?? [],
      },
    ];
  }, [bandsQuery.data, selSa, selNsa, selLte]);

  function goLockNr(pci: number | null | undefined, arfcn: number | null | undefined, extra?: { band?: string; scs?: string }) {
    setLockForm({ nrPci: String(pci ?? ""), nrArfcn: String(arfcn ?? ""), ...(extra?.band != null ? { nrBand: extra.band } : {}), ...(extra?.scs != null ? { nrScs: extra.scs } : {}) });
    setTab("lock");
  }

  function goLockLte(pci: number | null | undefined, arfcn: number | null | undefined) {
    setLockForm({ ltePci: String(pci ?? ""), lteEarfcn: String(arfcn ?? "") });
    setTab("lock");
  }

  return (
    <div className="space-y-6">
      <PageHeader section="/cellular" sub={tab} onSubChange={(id) => setTab(id as CellTab)} actions={<ServingChip />} />

      {tab === "profiles" && (
        <ProfilesView
          loading={profilesQuery.isLoading}
          profiles={profilesQuery.data?.profiles ?? []}
          mbnAll={mbnState.all}
          mbnList={mbnState.list}
          mbnAutoOn={mbnState.autoOn}
          mbnQuery={mbnQuery}
          setMbnQuery={setMbnQuery}
          busy={busy}
          onNewProfile={() =>
            setProfileModal({
              name: "",
              iccid: "",
              apn: "",
              pdp_type: "IPV4V6",
              network_type: "LTE:NR5G",
            })
          }
          onEditProfile={(p, idx) => setProfileModal({ ...p, index: idx, id: String(idx) })}
          onDeleteProfile={deleteProfile}
          onTogglePause={toggleProfilePause}
          onToggleAutoSel={toggleMbnAutoSel}
          onSelectMbn={selectMbn}
        />
      )}

      {tab === "bands" && (
        <BandsTab
          loading={bandsQuery.isLoading}
          groups={bandGroups}
          modePref={modePref}
          setModePref={setModePref}
          nrDisable={nrDisable}
          setNrDisable={setNrDisable}
          savedModePref={modeQuery.data?.modePref}
          savedNrDisable={modeQuery.data?.nr5gDisableMode != null ? String(modeQuery.data.nr5gDisableMode) : undefined}
          busy={busy}
          onToggle={(g, b) => toggleBand(groupSetter[g], b)}
          onSetGroup={setBandGroup}
          onReload={reloadBands}
          onApply={() => setConfirmLink("bands")}
        />
      )}

      {tab === "tuning" && (
        <Suspense fallback={<Skeleton className="h-64" />}>
          <RadioTuningCard />
        </Suspense>
      )}

      {tab === "lock" && (
        <LockTab
          loading={cellLockQuery.isLoading}
          status={activeLocks}
          lteRaw={cellLockQuery.data?.lteRaw}
          nrRaw={cellLockQuery.data?.nr5gRaw}
          bypassed={cellLockBypassed}
          deadmanEnabled={deadmanEnabled}
          deadmanSecs={deadmanSecs}
          deadmanDirty={deadmanDirty}
          setDeadmanEnabled={setDeadmanEnabled}
          setDeadmanSecs={setDeadmanSecs}
          onSaveDeadman={() => void saveDeadman()}
          onRearmBypassed={() => void rearmBypassedLock()}
          canRearm={canRearmBypassed}
          nrPersistDraft={nrPersistDraft}
          setNrPersistDraft={setNrPersistDraft}
          ltePersistDraft={ltePersistDraft}
          setLtePersistDraft={setLtePersistDraft}
          schedule={cellLockQuery.data?.schedule}
          schedStart={schedStart}
          schedEnd={schedEnd}
          schedDirty={schedDirty}
          setSchedStart={setSchedStart}
          setSchedEnd={setSchedEnd}
          onSaveSchedule={() => void saveSchedule(Boolean(cellLockQuery.data?.schedule?.enabled), "Lock schedule times saved")}
          busy={busy}
          onPrefill={prefillFromServingCell}
          onLockNr={askNrCellLock}
          onLockLte={askLteCellLock}
          onClear={clearCellLock}
          onToggleSchedule={toggleSchedule}
        />
      )}

      {tab === "align" && <AlignTab busy={busy} setBusy={setBusy} notify={notify} />}

      {tab === "scan" && (
        <ScanTab
          loading={scanQuery.isLoading}
          fetching={scanQuery.isFetching}
          neighbors={neighbors}
          scanRunning={Boolean(scanQuery.data?.scanRunning)}
          scanResult={scanQuery.data?.scanResult}
          busy={busy}
          onRefresh={() => void scanQuery.refetch()}
          onStartScan={startFullQscan}
          onClearScan={clearScanResult}
          onUseNeighbor={(n) => {
            if (n.rat.toUpperCase().includes("NR")) {
              const ch = describeChannel(n.rat, n.arfcn ?? 0, n.band);
              const bandNum = ch.band.replace(/^n/i, "");
              const scs = bandNum === "41" || bandNum === "77" || bandNum === "78" ? "30" : "15";
              goLockNr(n.pci, n.arfcn, { band: /^\d+$/.test(bandNum) ? bandNum : "", scs });
            } else {
              goLockLte(n.pci, n.arfcn);
            }
          }}
          onUseScan={(c) => {
            if (c.rat.toUpperCase().includes("NR")) {
              const ch = describeChannel(c.rat, c.arfcn, c.band);
              const bandNum = ch.band.replace(/^n/i, "");
              const scsClean = c.scs?.replace(/\D/g, "");
              const scs = scsClean || (bandNum === "41" || bandNum === "77" || bandNum === "78" ? "30" : "15");
              goLockNr(c.pci, c.arfcn, { band: /^\d+$/.test(bandNum) ? bandNum : "", scs });
            } else {
              goLockLte(c.pci, c.arfcn);
            }
          }}
        />
      )}

      {/* Link-dropping actions confirm first (DESIGN.md), with the failover warning when active. */}
      <ConfirmModal
        open={confirmLink != null}
        title={
          confirmLink === "bands"
            ? modeChanged
              ? "Change network mode and bands?"
              : "Apply the new band lock?"
            : confirmLink === "nr"
              ? "Lock 5G to this cell?"
              : "Lock LTE to this cell?"
        }
        body={
          <div className="space-y-2">
            <FailoverWarning action={confirmLink === "bands" ? "Changing bands" : "A cell lock"} />
            {confirmLink === "bands" ? (
              <p>
                The modem re-registers with the network{modeChanged ? " in the new mode" : ""}. The cellular link drops briefly, usually for 10 to 30
                seconds, and anything using it reconnects.
              </p>
            ) : (
              <p>
                The modem re-attaches to {confirmLink === "nr" ? `5G cell ${nrPci} on ARFCN ${nrArfcn}` : `LTE cell ${ltePci} on EARFCN ${lteEarfcn}`}. The
                cellular link drops briefly while it does, and stays down if that cell is out of reach.
              </p>
            )}
          </div>
        }
        confirmLabel={confirmLink === "bands" ? "Apply and reconnect" : "Lock and reconnect"}
        tone="primary"
        busy={busy === "apply-bands" || busy === "nr-lock" || busy === "lte-lock"}
        onClose={() => setConfirmLink(null)}
        onConfirm={() => {
          const kind = confirmLink;
          setConfirmLink(null);
          if (kind === "bands") void applyBandLocks();
          else if (kind === "nr") void applyNrCellLock();
          else if (kind === "lte") void applyLteCellLock();
        }}
      />

      {/* Profile editor */}
      <Modal
        open={Boolean(profileModal)}
        onClose={() => setProfileModal(null)}
        title={profileModal?.id != null ? `Edit ${profileModal.name || "profile"}` : "New SIM profile"}
      >
        {profileModal && (
          <form onSubmit={saveProfile} className="space-y-4">
            <p className="text-[12.5px] text-muted">
              Applied automatically whenever a SIM with this ICCID is in the modem.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Field label="Name" htmlFor="pf-name">
                <Input
                  id="pf-name"
                  value={profileModal.name}
                  onChange={(e) => setProfileModal({ ...profileModal, name: e.target.value })}
                  placeholder="T-Mobile home"
                  required
                />
              </Field>
              <Field label="SIM number" term="ICCID" htmlFor="pf-iccid">
                <div className="flex gap-1.5">
                  <Input
                    id="pf-iccid"
                    value={profileModal.iccid}
                    onChange={(e) => setProfileModal({ ...profileModal, iccid: e.target.value })}
                    className="font-mono"
                    required
                  />
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="h-10 shrink-0 rounded-xl px-2.5 text-[11.5px]"
                    onClick={() => void fillCurrentSimIccid()}
                    disabled={busy === "fill-iccid"}
                    title="Read the inserted SIM's full ICCID from the modem"
                  >
                    {busy === "fill-iccid" ? "…" : "Use current SIM"}
                  </Button>
                </div>
              </Field>
              <Field label="Access point" term="APN" htmlFor="pf-apn" className="sm:col-span-2">
                <Input
                  id="pf-apn"
                  value={profileModal.apn}
                  onChange={(e) => setProfileModal({ ...profileModal, apn: e.target.value })}
                  placeholder="fast.t-mobile.com"
                  className="font-mono"
                  required
                />
              </Field>
              <Field label="IP version" term="PDP type" htmlFor="pf-pdp">
                <Select
                  id="pf-pdp"
                  value={profileModal.pdp_type}
                  onChange={(e) => setProfileModal({ ...profileModal, pdp_type: e.target.value })}
                >
                  <option value="IPV4V6">IPv4 + IPv6 (IPV4V6)</option>
                  <option value="IPV6">IPv6 only (IPV6)</option>
                  <option value="IP">IPv4 only (IP)</option>
                </Select>
              </Field>
              <Field label="Networks" term="network type" htmlFor="pf-net">
                <Input
                  id="pf-net"
                  list="pf-net-options"
                  value={profileModal.network_type}
                  onChange={(e) => setProfileModal({ ...profileModal, network_type: e.target.value })}
                  className="font-mono"
                />
                <datalist id="pf-net-options">
                  <option value="LTE:NR5G" />
                  <option value="NR5G" />
                  <option value="LTE" />
                  <option value="AUTO" />
                </datalist>
              </Field>
              <Field label="TTL override" term="0 = off" htmlFor="pf-ttl">
                <Input
                  id="pf-ttl"
                  inputMode="numeric"
                  value={profileModal.ttl ?? ""}
                  onChange={(e) => setProfileModal({ ...profileModal, ttl: e.target.value })}
                  placeholder="65"
                  className="qm-tabular"
                />
              </Field>
            </div>
            <div className="flex flex-col-reverse gap-2 pt-1 sm:flex-row sm:justify-end">
              <Button variant="secondary" onClick={() => setProfileModal(null)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={busy === "save-prof"}>
                {busy === "save-prof" ? "Saving…" : "Save profile"}
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}
