import { useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Crosshair, ExternalLink, Radar, RefreshCw, Trash2 } from "lucide-react";
import { Badge, Button, Card, CardHeader, Skeleton } from "../../components/ui";
import { buildCellMapperUrl, describeChannel, getCarrierMeta, normalizePlmn } from "../../lib/rf";
import { cn } from "../../lib/utils";
import type { NeighborCellInfo, ServingCellInfo } from "../../types/cellcore";
import { ConfirmModal, EmptyState, SignalBar, TONE_TEXT, rsrpTone } from "./shared";
import { FailoverWarning } from "../../components/obs";

export interface QscanEntry {
  rat: string;
  mcc: string;
  mnc: string;
  arfcn: number;
  pci: number;
  rsrp: number | null;
  rsrq: number | null;
  scs: string;
  band: string;
}

export function ScanView({
  loading,
  fetching,
  neighbors,
  serving,
  scanRunning,
  scanResult,
  busy,
  onRefresh,
  onStartScan,
  onClearScan,
  onUseNeighbor,
  onUseScan,
}: {
  loading: boolean;
  fetching: boolean;
  neighbors: NeighborCellInfo[];
  serving: ServingCellInfo | null;
  scanRunning: boolean;
  scanResult?: { status?: string; timestamp?: string; entries?: QscanEntry[]; raw?: string; error?: string } | null;
  busy: string | null;
  onRefresh: () => void;
  onStartScan: () => Promise<void>;
  onClearScan: () => void;
  onUseNeighbor: (n: NeighborCellInfo) => void;
  onUseScan: (c: QscanEntry) => void;
}) {
  const [confirmScan, setConfirmScan] = useState(false);
  const [carrierFilter, setCarrierFilter] = useState<string>("all");
  const sortedNeighbors = useMemo(
    () => [...neighbors].sort((a, b) => (b.rsrp ?? -999) - (a.rsrp ?? -999)),
    [neighbors]
  );
  const best = sortedNeighbors[0] ?? null;
  const servingRsrp = serving?.rsrp ?? null;
  const advantage = best?.rsrp != null && servingRsrp != null ? Math.round((best.rsrp - servingRsrp) * 10) / 10 : null;
  const betterExists = advantage != null && advantage >= 3;

  const entries = scanResult?.entries ?? [];
  const groups = useMemo(() => {
    const map = new Map<string, QscanEntry[]>();
    for (const e of entries) {
      const k = normalizePlmn(e.mcc, e.mnc);
      map.set(k, [...(map.get(k) ?? []), e]);
    }
    return [...map.entries()]
      .map(([k, list]) => {
        const sorted = [...list].sort((a, b) => (b.rsrp ?? -999) - (a.rsrp ?? -999));
        const meta = getCarrierMeta(sorted[0].mcc, sorted[0].mnc);
        const top = sorted[0];
        const topChan = top ? describeChannel(top.rat, top.arfcn, top.band) : null;
        return {
          key: k,
          mcc: top.mcc,
          mnc: top.mnc,
          name: meta.name,
          badge: meta.badge,
          cells: sorted,
          best: Math.max(...sorted.map((c) => c.rsrp ?? -999)),
          topCell: top,
          topChan,
          hasNr: sorted.some((c) => c.rat.toUpperCase().includes("NR")),
        };
      })
      .sort((a, b) => b.best - a.best || b.cells.length - a.cells.length);
  }, [entries]);
  const visibleGroups = useMemo(
    () => (carrierFilter === "all" ? groups : groups.filter((g) => g.key === carrierFilter)),
    [groups, carrierFilter]
  );
  const servingPlmn = serving ? normalizePlmn(serving.mcc, serving.mnc) : null;

  return (
    <div className="space-y-5">
      {/* Answer first: is there a better cell than the one we're on? */}
      <Card className="qm-grain overflow-hidden">
        <div className="relative z-[1] flex flex-wrap items-center gap-5">
          <div
            className={cn(
              "flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl",
              loading || neighbors.length === 0 ? "bg-sunk text-muted" : betterExists ? "bg-saffron-soft text-saffron-ink" : "bg-jade-soft text-jade-ink"
            )}
          >
            {betterExists ? (
              <AlertTriangle className="h-6 w-6" />
            ) : neighbors.length === 0 ? (
              <Radar className="h-6 w-6" />
            ) : (
              <CheckCircle2 className="h-6 w-6" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            {loading ? (
              <Skeleton className="h-8 w-2/3" />
            ) : (
              <>
                <div className="qm-display text-[1.45rem] sm:text-[1.65rem] font-semibold leading-tight text-ink">
                  {neighbors.length === 0
                    ? "No neighbours heard right now"
                    : betterExists
                      ? `A neighbour is ${advantage} dB stronger`
                      : "You're on the strongest cell nearby"}
                </div>
                <div className="mt-1 text-[13px] text-ink-2 qm-tabular">
                  {serving && (
                    <>
                      On <strong className="text-ink">{serving.band}</strong> · cell {serving.pci ?? "—"} ·{" "}
                      <span className={TONE_TEXT[rsrpTone(servingRsrp)]}>{servingRsrp ?? "—"} dBm</span>
                    </>
                  )}
                  {best && (
                    <span className="text-muted">
                      {serving ? " · " : ""}best neighbour cell {best.pci ?? "—"} at {best.rsrp ?? "—"} dBm
                    </span>
                  )}
                </div>
              </>
            )}
          </div>
          {betterExists && best && (
            <Button variant="tier3" onClick={() => onUseNeighbor(best)}>
              <Crosshair className="h-4 w-4" />
              Pin that cell
            </Button>
          )}
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Neighbours: live and instant */}
        <Card className="lg:col-span-5 min-w-0">
          <CardHeader
            title="Neighbours"
            subtitle="Cells the modem is measuring right now, strongest first."
            action={
              <Button variant="ghost" size="sm" onClick={onRefresh} disabled={fetching} aria-label="Refresh neighbours">
                <RefreshCw className={cn("h-3.5 w-3.5", fetching && "animate-spin")} />
                Refresh
              </Button>
            }
          />
          {loading ? (
            <Skeleton className="h-40" />
          ) : sortedNeighbors.length === 0 ? (
            <EmptyState icon={<Radar className="h-5 w-5" />} title="Nothing to compare">
              The modem isn't reporting neighbour cells at the moment. Try refreshing in a few seconds.
            </EmptyState>
          ) : (
            <ul className="space-y-2">
              {sortedNeighbors.map((n, i) => {
                const diff = n.rsrp != null && servingRsrp != null ? Math.round((n.rsrp - servingRsrp) * 10) / 10 : null;
                return (
                  <li
                    key={`${n.arfcn}-${n.pci}-${i}`}
                    className={cn("rounded-2xl border px-3.5 py-3", i === 0 ? "border-line-strong bg-raised" : "border-line bg-surface")}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="qm-display text-[1.1rem] font-semibold text-ink">Cell {n.pci ?? "—"}</span>
                          <Badge variant={n.rat.includes("NR") ? "plum" : "neutral"}>{n.rat.includes("NR") ? "5G" : "LTE"}</Badge>
                          <span className="text-[11.5px] text-muted">{n.type === "intra" ? "same channel" : "other channel"}</span>
                        </div>
                        <div className="mt-0.5 text-[11.5px] text-muted qm-tabular">
                          <span className="font-mono">ARFCN {n.arfcn ?? "—"}</span> · SINR {n.sinr ?? "—"} dB
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className={cn("text-[15px] font-bold qm-tabular", TONE_TEXT[rsrpTone(n.rsrp)])}>{n.rsrp ?? "—"}</div>
                        {diff != null && (
                          <div className={cn("text-[11px] font-semibold qm-tabular", diff >= 0 ? "text-jade-ink" : "text-muted")}>
                            {diff >= 0 ? "+" : ""}
                            {diff} vs yours
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="mt-2.5 flex items-center gap-3">
                      <SignalBar value={n.rsrp} reference={servingRsrp} className="flex-1" />
                      <Button variant="ghost" size="sm" onClick={() => onUseNeighbor(n)} className="-mr-2">
                        Pin
                      </Button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        {/* Full survey */}
        <Card className="lg:col-span-7 min-w-0">
          <CardHeader
            title="Full survey"
            subtitle={
              scanRunning
                ? "Sweeping every band… this takes 30 to 90 seconds."
                : scanResult?.timestamp
                  ? `Last survey ${scanResult.timestamp}`
                  : "Every tower on every carrier within reach."
            }
            action={
              <>
                {(entries.length > 0 || scanResult?.raw || scanResult?.status === "completed") && !scanRunning && (
                  <Button variant="ghost" size="sm" onClick={onClearScan} disabled={busy === "qscan-clear"}>
                    <Trash2 className="h-3.5 w-3.5" />
                    Clear
                  </Button>
                )}
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => setConfirmScan(true)}
                  disabled={busy === "qscan" || scanRunning}
                >
                  <Radar className={cn("h-3.5 w-3.5", scanRunning && "animate-[qm-sweep_1.6s_linear_infinite]")} />
                  {scanRunning ? "Scanning…" : entries.length ? "Scan again" : "Start survey"}
                </Button>
              </>
            }
          />

          {scanResult?.error && (
            <div className="mb-3 flex items-start gap-2 rounded-xl bg-crimson-soft px-3 py-2 text-[12.5px] text-crimson-ink">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              {scanResult.error}
            </div>
          )}

          {scanRunning && entries.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-10">
              <div className="relative h-24 w-24 rounded-full border border-line-strong">
                <div className="absolute inset-3 rounded-full border border-line" />
                <div className="absolute inset-7 rounded-full border border-line" />
                <div
                  className="absolute inset-0 rounded-full animate-[qm-sweep_2s_linear_infinite]"
                  style={{ background: "conic-gradient(from 0deg, transparent 0deg, color-mix(in oklab, var(--qm-ember) 45%, transparent) 60deg, transparent 61deg)" }}
                />
              </div>
              <div className="text-[13px] text-muted">Listening on every band…</div>
            </div>
          ) : groups.length > 0 ? (
            <div className="space-y-4">
              {/* Visual Radio Finder: Operator Summary Cards & Filter */}
              <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
                {groups.map((g) => (
                  <button
                    key={`card-${g.key}`}
                    type="button"
                    onClick={() => setCarrierFilter((cur) => (cur === g.key ? "all" : g.key))}
                    className={cn(
                      "qm-subcard p-3 text-left transition cursor-pointer",
                      carrierFilter === g.key ? "ring-2 ring-ember border-ember" : "hover:border-line-strong"
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <Badge variant={g.badge}>{g.name}</Badge>
                      <span className="text-[10.5px] text-muted qm-tabular">
                        {g.cells.length} {g.cells.length === 1 ? "cell" : "cells"}
                      </span>
                    </div>
                    <div className="mt-2 flex items-baseline justify-between gap-2 qm-tabular">
                      <span className={cn("qm-display text-[1.25rem] font-semibold", TONE_TEXT[rsrpTone(g.best > -900 ? g.best : null)])}>
                        {g.best > -900 ? `${g.best} dBm` : "—"}
                      </span>
                      <span className="text-[11px] font-semibold text-ink-2">
                        {g.topChan ? `${g.topChan.band}${g.topChan.mhz ? ` · ${Math.round(g.topChan.mhz)} MHz` : ""}` : "—"}
                      </span>
                    </div>
                    <SignalBar value={g.best > -900 ? g.best : null} className="mt-1.5" />
                  </button>
                ))}
              </div>

              {carrierFilter !== "all" && (
                <div className="flex items-center justify-between text-[12px]">
                  <span className="text-muted">Filtered to {groups.find((g) => g.key === carrierFilter)?.name}</span>
                  <Button size="sm" variant="ghost" onClick={() => setCarrierFilter("all")}>
                    Show all carriers
                  </Button>
                </div>
              )}

              {visibleGroups.map((g) => (
                <section key={g.key}>
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge variant={g.badge}>{g.name}</Badge>
                      <span className="font-mono text-[11px] text-muted">{g.key}</span>
                      {g.key === servingPlmn && <Badge variant="success">your carrier</Badge>}
                    </div>
                    <div className="flex items-center gap-2">
                      <a
                        href={buildCellMapperUrl(g.mcc, g.mnc, g.hasNr ? "NR5G" : "LTE")}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded-lg border border-line bg-raised px-2 py-0.5 text-[11px] font-semibold text-ink-2 hover:text-ink"
                      >
                        <ExternalLink className="h-3 w-3" />
                        CellMapper
                      </a>
                      <span className="text-[11.5px] text-muted qm-tabular">
                        {g.cells.length} {g.cells.length === 1 ? "cell" : "cells"}
                      </span>
                    </div>
                  </div>
                  <div className="overflow-x-auto rounded-2xl border border-line">
                    <table className="w-full min-w-[540px] text-[12.5px]">
                      <thead className="bg-sunk text-left text-[11px] font-semibold text-muted">
                        <tr>
                          <th className="px-3 py-2 font-semibold">Band / Freq</th>
                          <th className="px-3 py-2 font-semibold">Cell <span className="font-mono">PCI</span></th>
                          <th className="px-3 py-2 font-semibold">Channel <span className="font-mono">ARFCN</span></th>
                          <th className="px-3 py-2 font-semibold w-[30%]">Signal <span className="font-mono">RSRP</span></th>
                          <th className="px-3 py-2 text-right font-semibold">
                            Quality <span className="font-mono">RSRQ</span>
                          </th>
                          <th className="px-3 py-2" />
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line bg-raised">
                        {g.cells.map((c, idx) => {
                          const isServing = serving != null && serving.pci === c.pci && serving.arfcn === c.arfcn;
                          const ch = describeChannel(c.rat, c.arfcn, c.band);
                          return (
                            <tr key={`${c.arfcn}-${c.pci}-${idx}`} className={cn(isServing && "bg-jade-soft")}>
                              <td className="px-3 py-2">
                                <div className="flex items-center gap-1.5">
                                  <span className="font-semibold text-ink">{ch.band}</span>
                                  <span className="text-[10.5px] font-bold text-muted">{c.rat.toUpperCase().includes("NR") ? "5G" : "LTE"}</span>
                                </div>
                                <div className="text-[10.5px] text-muted qm-tabular">
                                  {ch.mhz != null ? `${Math.round(ch.mhz)} MHz` : ""}
                                  {c.scs ? `${ch.mhz != null ? " · " : ""}${c.scs} kHz` : ""}
                                </div>
                              </td>
                              <td className="px-3 py-2 font-mono font-semibold text-ink qm-tabular">
                                {c.pci}
                                {isServing && <span className="ml-1.5 font-sans text-[10.5px] font-bold text-jade-ink">serving</span>}
                              </td>
                              <td className="px-3 py-2 font-mono text-ink-2 qm-tabular">{c.arfcn}</td>
                              <td className="px-3 py-2">
                                <div className="flex items-center gap-2">
                                  <span className={cn("w-10 shrink-0 text-right font-bold qm-tabular", TONE_TEXT[rsrpTone(c.rsrp)])}>
                                    {c.rsrp ?? "—"}
                                  </span>
                                  <SignalBar value={c.rsrp} className="flex-1" />
                                </div>
                              </td>
                              <td className="px-3 py-2 text-right text-ink-2 qm-tabular">{c.rsrq ?? "—"}</td>
                              <td className="px-2 py-1.5 text-right">
                                <Button variant="ghost" size="sm" onClick={() => onUseScan(c)}>
                                  Pin
                                </Button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </section>
              ))}
            </div>
          ) : scanResult?.raw ? (
            <pre className="qm-subcard max-h-64 overflow-x-auto p-3 font-mono text-[11px] text-ink-2">{scanResult.raw}</pre>
          ) : scanResult?.status === "completed" ? (
            <EmptyState icon={<Radar className="h-5 w-5" />} title="No cells found">
              The survey completed without detecting any cells in range.
            </EmptyState>
          ) : (
            <EmptyState icon={<Radar className="h-5 w-5" />} title="No survey yet">
              A survey lists every tower in range, for every carrier, grouped by operator. It pauses data briefly while
              the radio tunes through each band.
            </EmptyState>
          )}
        </Card>
      </div>

      <ConfirmModal
        open={confirmScan}
        title="Run a full survey?"
        body={
          <div className="space-y-2">
            <FailoverWarning action="A survey" />
            <p>The modem tunes through every band to find all towers in range. It takes 30 to 90 seconds.</p>
            <p className="flex items-start gap-2 rounded-xl bg-saffron-soft px-3 py-2 text-saffron-ink">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              Data pauses while the survey runs.
            </p>
          </div>
        }
        confirmLabel="Start survey"
        tone="primary"
        busy={busy === "qscan"}
        onClose={() => setConfirmScan(false)}
        onConfirm={async () => {
          setConfirmScan(false);
          await onStartScan();
        }}
      />
    </div>
  );
}
