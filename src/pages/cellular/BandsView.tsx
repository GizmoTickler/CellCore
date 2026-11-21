import { AlertTriangle, Check, RefreshCw, Undo2 } from "lucide-react";
import { Badge, Button, Card, CardHeader, LiveDot, Skeleton } from "../../components/ui";
import { cn } from "../../lib/utils";
import type { CarrierComponent, ServingCellInfo } from "../../types/cellcore";
import { ChoiceTile } from "./shared";

export type BandGroupId = "sa" | "nsa" | "lte";

/** US-centric band facts: centre frequency (MHz) and the name people know it by. */
const BAND_INFO: Record<string, { mhz: number; name: string; duplex: "FDD" | "TDD" }> = {
  "2": { mhz: 1900, name: "PCS", duplex: "FDD" },
  "4": { mhz: 1700, name: "AWS-1", duplex: "FDD" },
  "5": { mhz: 850, name: "Cellular", duplex: "FDD" },
  "7": { mhz: 2600, name: "IMT-E", duplex: "FDD" },
  "12": { mhz: 700, name: "Lower 700", duplex: "FDD" },
  "13": { mhz: 700, name: "Upper 700", duplex: "FDD" },
  "14": { mhz: 700, name: "FirstNet", duplex: "FDD" },
  "17": { mhz: 700, name: "Lower 700", duplex: "FDD" },
  "25": { mhz: 1900, name: "PCS+G", duplex: "FDD" },
  "26": { mhz: 850, name: "ESMR", duplex: "FDD" },
  "29": { mhz: 700, name: "SDL", duplex: "FDD" },
  "30": { mhz: 2300, name: "WCS", duplex: "FDD" },
  "38": { mhz: 2600, name: "TD 2600", duplex: "TDD" },
  "41": { mhz: 2500, name: "BRS", duplex: "TDD" },
  "46": { mhz: 5200, name: "LAA", duplex: "TDD" },
  "48": { mhz: 3550, name: "CBRS", duplex: "TDD" },
  "66": { mhz: 1700, name: "AWS-3", duplex: "FDD" },
  "70": { mhz: 1700, name: "AWS-4", duplex: "FDD" },
  "71": { mhz: 600, name: "600 MHz", duplex: "FDD" },
  "77": { mhz: 3700, name: "C-band", duplex: "TDD" },
  "78": { mhz: 3500, name: "C-band", duplex: "TDD" },
  "79": { mhz: 4700, name: "4.7 GHz", duplex: "TDD" },
};

type Tier = "low" | "mid" | "high";
const TIERS: { id: Tier; label: string; hint: string }[] = [
  { id: "low", label: "Low band", hint: "Long reach, gets indoors" },
  { id: "mid", label: "Mid band", hint: "Balanced speed and range" },
  { id: "high", label: "High band", hint: "Most capacity, shortest reach" },
];

function tierOf(band: string): Tier {
  const mhz = BAND_INFO[band]?.mhz ?? 2000;
  if (mhz < 1000) return "low";
  if (mhz < 3000) return "mid";
  return "high";
}

function freqLabel(band: string): string {
  const mhz = BAND_INFO[band]?.mhz;
  if (!mhz) return "—";
  return mhz >= 1000 ? `${(mhz / 1000).toFixed(mhz % 1000 === 0 ? 0 : 1)} GHz` : `${mhz} MHz`;
}

const MODES = [
  { value: "AUTO", label: "Automatic", hint: "5G and LTE, modem decides", term: "AUTO" },
  { value: "LTE:NR5G", label: "LTE + 5G", hint: "Both, LTE-anchored preference", term: "LTE:NR5G" },
  { value: "NR5G", label: "5G only", hint: "Never falls back to LTE", term: "NR5G" },
  { value: "LTE", label: "LTE only", hint: "5G radio off", term: "LTE" },
];

const NR_MODES = [
  { value: "0", label: "Standalone + non-standalone", hint: "All 5G modes allowed", term: "SA + NSA" },
  { value: "1", label: "Non-standalone only", hint: "5G rides on an LTE anchor", term: "SA off" },
  { value: "2", label: "Standalone only", hint: "Pure 5G core, no LTE anchor", term: "NSA off" },
];

export interface BandGroup {
  id: BandGroupId;
  title: string;
  term: string;
  prefix: "n" | "B";
  supported: string[];
  selected: string[];
  saved: string[];
}

function BandChip({
  band,
  prefix,
  on,
  inUse,
  changed,
  onClick,
}: {
  band: string;
  prefix: string;
  on: boolean;
  inUse: boolean;
  changed: boolean;
  onClick: () => void;
}) {
  const info = BAND_INFO[band];
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={on}
      aria-label={`${prefix}${band}`}
      onClick={onClick}
      title={`${prefix}${band}${info ? ` · ${info.name} · ${info.duplex}` : ""}`}
      className={cn(
        "group relative flex min-h-[3.6rem] min-w-[5.4rem] flex-col items-start justify-center rounded-2xl border px-3 py-2 text-left transition cursor-pointer active:translate-y-px",
        on
          ? "border-ember bg-ember-soft text-ink shadow-[0_6px_16px_-12px_var(--qm-ember)]"
          : "border-dashed border-line-strong bg-transparent text-muted hover:border-ink-2/40 hover:text-ink-2"
      )}
    >
      <span className="flex w-full items-center justify-between gap-2">
        <span className={cn("qm-display text-[1.15rem] font-semibold leading-none", on ? "text-ink" : "text-muted")}>
          {prefix}
          {band}
        </span>
        <span
          className={cn(
            "flex h-4 w-4 items-center justify-center rounded-full transition",
            on ? "bg-ember text-on-ember" : "border border-line-strong"
          )}
        >
          {on && <Check className="h-2.5 w-2.5" strokeWidth={3.5} />}
        </span>
      </span>
      <span className="mt-1 text-[11px] font-medium leading-none qm-tabular">
        {freqLabel(band)}
        {info && info.name !== freqLabel(band) && <span className="text-muted"> · {info.name}</span>}
      </span>
      {(inUse || changed) && (
        <span className="absolute -top-2 left-2.5 flex gap-1">
          {inUse && (
            <span className="inline-flex items-center gap-1 rounded-full bg-jade px-1.5 py-[1px] text-[10px] font-bold text-on-jade">
              <span className="h-1 w-1 rounded-full bg-on-jade" />
              in use
            </span>
          )}
          {changed && (
            <span className="rounded-full bg-saffron px-1.5 py-[1px] text-[10px] font-bold text-black">
              {on ? "added" : "removed"}
            </span>
          )}
        </span>
      )}
    </button>
  );
}

export function BandsView({
  loading,
  groups,
  modePref,
  setModePref,
  nrDisable,
  setNrDisable,
  savedModePref,
  savedNrDisable,
  bandsDirty,
  busy,
  serving,
  carriers,
  onToggle,
  onSetGroup,
  onReload,
  onApply,
}: {
  loading: boolean;
  groups: BandGroup[];
  modePref: string;
  setModePref: (v: string) => void;
  nrDisable: string;
  setNrDisable: (v: string) => void;
  savedModePref?: string;
  savedNrDisable?: string;
  bandsDirty: boolean;
  busy: string | null;
  serving: ServingCellInfo | null;
  carriers: CarrierComponent[];
  onToggle: (group: BandGroupId, band: string) => void;
  onSetGroup: (group: BandGroupId, bands: string[]) => void;
  onReload: () => void;
  onApply: () => void;
}) {
  const isSa = Boolean(serving?.rat?.toUpperCase().includes("SA") && !serving?.rat?.toUpperCase().includes("NSA"));
  const inUse = (g: BandGroupId, band: string) =>
    carriers.some((c) => {
      const nr = /^n/i.test(c.band);
      const num = c.band.replace(/\D/g, "");
      if (num !== band) return false;
      if (g === "lte") return !nr;
      if (g === "sa") return nr && isSa;
      return nr && !isSa;
    });

  const modeChanged = savedModePref != null && savedModePref !== modePref;
  const nrChanged = savedNrDisable != null && savedNrDisable !== nrDisable;
  const pending = bandsDirty || modeChanged || nrChanged;

  const diffs = groups.map((g) => ({
    g,
    added: g.selected.filter((b) => !g.saved.includes(b)),
    removed: g.saved.filter((b) => !g.selected.includes(b)),
  }));
  const changeCount = diffs.reduce((n, d) => n + d.added.length + d.removed.length, 0) + (modeChanged ? 1 : 0) + (nrChanged ? 1 : 0);
  const droppingLive = groups.some((g) => g.saved.some((b) => inUse(g.id, b) && !g.selected.includes(b)));
  const emptyGroup = groups.find((g) => g.selected.length === 0);

  const modeLabel = MODES.find((m) => m.value === modePref)?.label ?? modePref;

  return (
    <div className="space-y-5 pb-24">
      {/* Answer first: what the modem is allowed to use right now */}
      <Card className="qm-grain overflow-hidden">
        <div className="relative z-[1] grid gap-5 lg:grid-cols-12 lg:items-center">
          <div className="lg:col-span-5 min-w-0">
            <div className="qm-eyebrow">Allowed right now</div>
            {loading ? (
              <Skeleton className="mt-2 h-10 w-3/4" />
            ) : (
              <div className="mt-1 qm-display text-[1.9rem] font-semibold leading-tight text-ink">
                {modeLabel}
                <span className="text-muted"> · </span>
                <span className="qm-sun-text">{groups.reduce((n, g) => n + g.saved.length, 0)} bands</span>
              </div>
            )}
            {serving && (
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-2">
                <LiveDot tone="jade" />
                Connected on <strong className="text-ink">{serving.band}</strong>
                {carriers.length > 1 && (
                  <span className="text-muted">
                    with {carriers.filter((c) => c.role === "SCC").map((c) => c.band).join(", ")} aggregated
                  </span>
                )}
              </div>
            )}
          </div>
          <div className="lg:col-span-7 grid grid-cols-3 gap-2.5">
            {groups.map((g) => (
              <div key={g.id} className="qm-subcard px-3.5 py-3 min-w-0">
                <div className="truncate text-[11.5px] font-semibold text-muted">{g.title}</div>
                <div className="mt-0.5 flex items-baseline gap-1">
                  <span className="qm-display text-[1.6rem] font-semibold text-ink qm-tabular leading-none">{g.saved.length}</span>
                  <span className="text-[11.5px] text-muted">/ {g.supported.length}</span>
                </div>
                <div className="mt-1 truncate font-mono text-[10.5px] text-muted">{g.term}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* Network mode */}
      <Card>
        <CardHeader
          title="Which networks to use"
          subtitle="Pick how the modem chooses between 5G and LTE."
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={onReload}
              title="Discard edits and reload from the modem"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Reload
            </Button>
          }
        />
        <div className="grid gap-5 lg:grid-cols-2">
          <div>
            <div className="mb-2 flex items-baseline gap-1.5 text-[12.5px] font-semibold text-ink-2">
              Network mode <span className="font-mono text-[11px] font-medium text-muted">mode_pref</span>
            </div>
            <div role="radiogroup" aria-label="Network mode" className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {MODES.map((m) => (
                <ChoiceTile
                  key={m.value}
                  selected={modePref === m.value}
                  onClick={() => setModePref(m.value)}
                  label={m.label}
                  hint={m.hint}
                  term={m.term}
                />
              ))}
            </div>
          </div>
          <div>
            <div className="mb-2 flex items-baseline gap-1.5 text-[12.5px] font-semibold text-ink-2">
              5G flavour <span className="font-mono text-[11px] font-medium text-muted">nr5g_disable_mode</span>
            </div>
            <div role="radiogroup" aria-label="5G mode" className="grid grid-cols-1 gap-2">
              {NR_MODES.map((m) => (
                <ChoiceTile
                  key={m.value}
                  selected={nrDisable === m.value}
                  onClick={() => setNrDisable(m.value)}
                  label={m.label}
                  hint={m.hint}
                  term={`${m.term} (${m.value})`}
                />
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Bands */}
      {groups.map((g) => {
        const tiers = TIERS.map((t) => ({ ...t, bands: g.supported.filter((b) => tierOf(b) === t.id) })).filter(
          (t) => t.bands.length > 0
        );
        return (
          <Card key={g.id}>
            <CardHeader
              title={g.title}
              subtitle={
                <>
                  <span className="qm-tabular">
                    {g.selected.length} of {g.supported.length} allowed
                  </span>
                  <span className="font-mono text-[11px]"> · {g.term}</span>
                </>
              }
              action={
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => onSetGroup(g.id, [...g.supported])}>
                    All
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => onSetGroup(g.id, [])}>
                    None
                  </Button>
                  {g.selected.join(",") !== g.saved.join(",") && (
                    <Button variant="ghost" size="sm" onClick={() => onSetGroup(g.id, [...g.saved])}>
                      <Undo2 className="h-3.5 w-3.5" />
                      Undo
                    </Button>
                  )}
                </div>
              }
            />
            {loading ? (
              <Skeleton className="h-20" />
            ) : (
              <div className="grid gap-4 md:grid-cols-3">
                {tiers.map((t) => (
                  <div key={t.id} className="min-w-0">
                    <div className="mb-2.5 flex items-baseline justify-between gap-2 border-b border-line pb-1.5">
                      <span className="text-[12.5px] font-semibold text-ink-2">{t.label}</span>
                      <span className="text-[11px] text-muted truncate">{t.hint}</span>
                    </div>
                    <div className="flex flex-wrap gap-2 pt-1">
                      {t.bands.map((b) => {
                        const on = g.selected.includes(b);
                        return (
                          <BandChip
                            key={b}
                            band={b}
                            prefix={g.prefix}
                            on={on}
                            inUse={inUse(g.id, b)}
                            changed={on !== g.saved.includes(b)}
                            onClick={() => onToggle(g.id, b)}
                          />
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        );
      })}

      {/* Review & apply bar */}
      {pending && (
        <div className="fixed inset-x-0 bottom-[4.5rem] lg:bottom-5 z-40 flex justify-center px-3 lg:pl-[264px] pointer-events-none">
          <div className="qm-card qm-rise pointer-events-auto flex w-full max-w-3xl flex-wrap items-center gap-3 px-4 py-3 shadow-[var(--qm-shadow-pop)]">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-ink">
                <span className="h-2 w-2 rounded-full bg-saffron" />
                {changeCount} unsaved {changeCount === 1 ? "change" : "changes"}
              </div>
              <div className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[12px] text-muted qm-tabular">
                {modeChanged && <span>Mode → {modeLabel}</span>}
                {nrChanged && <span>5G → {NR_MODES.find((m) => m.value === nrDisable)?.term}</span>}
                {diffs.map(({ g, added, removed }) =>
                  added.length + removed.length > 0 ? (
                    <span key={g.id}>
                      {g.title}:{" "}
                      {added.length > 0 && <span className="text-jade-ink">+{added.map((b) => g.prefix + b).join(" ")}</span>}
                      {added.length > 0 && removed.length > 0 && " "}
                      {removed.length > 0 && <span className="text-crimson-ink">−{removed.map((b) => g.prefix + b).join(" ")}</span>}
                    </span>
                  ) : null
                )}
              </div>
              {(droppingLive || emptyGroup) && (
                <div className="mt-1 flex items-start gap-1.5 text-[12px] font-semibold text-saffron-ink">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  {droppingLive
                    ? "You're removing a band the modem is using now. The link will drop and re-attach."
                    : `No ${emptyGroup?.title} bands selected.`}
                </div>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" onClick={onReload}>
                Discard
              </Button>
              <Button variant="tier1" size="md" onClick={onApply} disabled={busy === "apply-bands"}>
                <Check className="h-4 w-4" />
                {busy === "apply-bands" ? "Applying…" : "Apply to modem"}
              </Button>
            </div>
          </div>
        </div>
      )}
      {!pending && !loading && (
        <div className="flex justify-center">
          <Badge variant="success" dot>
            Matches the modem
          </Badge>
        </div>
      )}
    </div>
  );
}
