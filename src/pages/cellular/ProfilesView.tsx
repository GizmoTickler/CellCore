import { useState } from "react";
import { CheckCircle2, Cpu, Layers, Pause, Pencil, Play, Plus, Search, Sparkles, Trash2 } from "lucide-react";
import { Badge, Button, Card, CardHeader, Input, Skeleton, Switch } from "../../components/ui";
import { cn, maskSecretId } from "../../lib/utils";
import type { MbnProfile, QuecProfileItem } from "../../types/cellcore";
import { ConfirmModal, EmptyState } from "./shared";
import { FailoverWarning } from "../../components/obs";

function isPaused(p: QuecProfileItem) {
  return String(p.paused) === "1" || p.paused === true;
}

/** Quectel MBN dates come back as YYYYMMDD(+rev) — show a readable date when it parses. */
function mbnDate(raw: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})/.exec(raw ?? "");
  if (!m) return raw;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  if (Number.isNaN(d.getTime()) || Number(m[1]) < 2000) return raw;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short" });
}

export function ProfilesView({
  loading,
  profiles,
  mbnAll,
  mbnList,
  mbnAutoOn,
  mbnQuery,
  setMbnQuery,
  busy,
  onNewProfile,
  onEditProfile,
  onDeleteProfile,
  onTogglePause,
  onToggleAutoSel,
  onSelectMbn,
}: {
  loading: boolean;
  profiles: QuecProfileItem[];
  mbnAll: MbnProfile[];
  mbnList: MbnProfile[];
  mbnAutoOn: boolean;
  mbnQuery: string;
  setMbnQuery: (v: string) => void;
  busy: string | null;
  onNewProfile: () => void;
  onEditProfile: (p: QuecProfileItem, idx: number) => void;
  onDeleteProfile: (idx: number) => Promise<void>;
  onTogglePause: (p: QuecProfileItem) => void;
  onToggleAutoSel: (next: boolean) => void;
  onSelectMbn: (name: string) => Promise<void>;
}) {
  const [confirmDelete, setConfirmDelete] = useState<{ idx: number; name: string } | null>(null);
  const [confirmMbn, setConfirmMbn] = useState<string | null>(null);

  const activeMbn = mbnAll.find((m) => m.activated) ?? null;
  const selectedMbn = mbnAll.find((m) => m.selected && !m.activated) ?? null;
  const others = mbnList.filter((m) => !m.activated);

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      {/* SIM profiles: the primary task */}
      <Card className="lg:col-span-7 min-w-0">
        <CardHeader
          title="SIM profiles"
          subtitle="When a SIM matches a profile, its APN, bands and TTL are applied automatically."
          icon={<Layers className="h-4 w-4" />}
          action={
            <Button variant="primary" size="sm" onClick={onNewProfile}>
              <Plus className="h-3.5 w-3.5" />
              New profile
            </Button>
          }
        />
        {loading ? (
          <Skeleton className="h-32" />
        ) : profiles.length === 0 ? (
          <EmptyState icon={<Layers className="h-5 w-5" />} title="No profiles yet">
            Create one to have the APN and bands set for you whenever this SIM is inserted.
          </EmptyState>
        ) : (
          <ul className="space-y-3">
            {profiles.map((p, i) => {
              const idx = p.index ?? i;
              const paused = isPaused(p);
              const chips = [
                p.pdp_type && { k: "IP", v: p.pdp_type },
                p.network_type && { k: "Network", v: p.network_type },
                p.ttl && p.ttl !== "0" && { k: "TTL", v: p.ttl },
                p.mbn_profile && { k: "MBN", v: p.mbn_profile },
                p.lte_bands && { k: "LTE", v: p.lte_bands },
                p.sa_nr5g_bands && { k: "SA", v: p.sa_nr5g_bands },
                p.nsa_nr5g_bands && { k: "NSA", v: p.nsa_nr5g_bands },
              ].filter(Boolean) as { k: string; v: string }[];
              return (
                <li
                  key={`${idx}-${p.iccid}`}
                  className={cn(
                    "relative overflow-hidden rounded-2xl border bg-raised p-4 sm:p-5 transition",
                    paused ? "border-line border-dashed" : "border-line"
                  )}
                >
                  {!paused && <span className="absolute inset-y-0 left-0 w-1 qm-sun" aria-hidden />}
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h4 className={cn("qm-display text-[1.25rem] font-semibold leading-tight", paused ? "text-ink-2" : "text-ink")}>
                          {p.name || "Untitled"}
                        </h4>
                        <Badge variant={paused ? "warning" : "success"} dot>
                          {paused ? "Paused" : "Applying automatically"}
                        </Badge>
                      </div>
                      <div className="mt-2 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                        <span className="text-[11.5px] font-semibold text-muted">APN</span>
                        <span className="font-mono text-[13.5px] font-semibold text-ink break-all">{p.apn || "—"}</span>
                      </div>
                      <div className="mt-0.5 text-[12px] text-muted">
                        SIM <span className="font-mono">{maskSecretId(p.iccid)}</span>
                        {p.mobile_provider && p.mobile_provider !== "Other" && <> · {p.mobile_provider}</>}
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onTogglePause({ ...p, index: idx })}
                        disabled={busy === `pause-${idx}`}
                        title={paused ? "Resume this profile" : "Pause this profile"}
                      >
                        {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
                        <span className="hidden sm:inline">{paused ? "Resume" : "Pause"}</span>
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => onEditProfile(p, idx)} title="Edit profile">
                        <Pencil className="h-3.5 w-3.5" />
                        <span className="hidden sm:inline">Edit</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirmDelete({ idx, name: p.name })}
                        disabled={busy === `del-${idx}`}
                        className="text-crimson-ink hover:text-crimson-ink hover:bg-crimson-soft"
                        aria-label={`Delete profile ${p.name}`}
                        title="Delete profile"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                  {chips.length > 0 && (
                    <div className="mt-3.5 flex flex-wrap gap-1.5">
                      {chips.map((c) => (
                        <span
                          key={c.k}
                          className="inline-flex items-baseline gap-1.5 rounded-lg border border-line bg-sunk px-2 py-1 text-[12px]"
                        >
                          <span className="font-semibold text-muted">{c.k}</span>
                          <span className="font-mono font-semibold text-ink-2 break-all">{c.v}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {/* Carrier firmware (MBN) */}
      <Card className="lg:col-span-5 min-w-0 space-y-4">
        <CardHeader
          title="Carrier configuration"
          subtitle={`Modem firmware profile (MBN) · ${mbnAll.length} available`}
          icon={<Cpu className="h-4 w-4" />}
        />

        <div className="rounded-2xl qm-sun p-[1.5px]">
          <div className="rounded-[calc(1rem-1.5px)] bg-surface p-4">
            <div className="flex items-center justify-between gap-2">
              <div className="qm-eyebrow">In use now</div>
              {activeMbn && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setConfirmMbn(activeMbn.name)}
                  disabled={busy === `mbn-${activeMbn.name}`}
                  className="-my-1 -mr-2"
                >
                  Re-apply
                </Button>
              )}
            </div>
            {loading ? (
              <Skeleton className="mt-2 h-8 w-2/3" />
            ) : activeMbn ? (
              <>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-jade-ink shrink-0" />
                  <span className="qm-display text-[1.45rem] font-semibold leading-tight text-ink break-all">{activeMbn.name}</span>
                </div>
                <div className="mt-1 text-[12px] text-muted qm-tabular">
                  Version <span className="font-mono">{activeMbn.version}</span> · {mbnDate(activeMbn.date)} · slot {activeMbn.index}
                </div>
              </>
            ) : (
              <div className="mt-1 text-[13px] text-ink-2">No MBN reported as active.</div>
            )}
            {selectedMbn && (
              <div className="mt-2">
                <Badge variant="warning">Selected next: {selectedMbn.name}</Badge>
              </div>
            )}
          </div>
        </div>

        <div className="qm-subcard p-3.5">
          <Switch
            label="Choose automatically from the SIM"
            description="MBN AutoSel · the modem picks the carrier profile that matches the inserted SIM"
            checked={mbnAutoOn}
            onChange={onToggleAutoSel}
            disabled={busy === "autosel"}
          />
        </div>

        <div className="space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[12.5px] font-semibold text-ink-2">Switch to another carrier</span>
            <span className="text-[11.5px] text-muted qm-tabular">{others.length} shown</span>
          </div>
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-muted absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <Input
              value={mbnQuery}
              onChange={(e) => setMbnQuery(e.target.value)}
              placeholder="Search carriers (TMO, ATT, VZW…)"
              className="pl-9"
              aria-label="Search carrier profiles"
            />
          </div>
          <ul className="max-h-[340px] overflow-y-auto rounded-2xl border border-line divide-y divide-line bg-raised">
            {others.map((m) => (
              <li key={`${m.index}-${m.name}`} className="flex items-center justify-between gap-3 px-3.5 py-2.5">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate text-[13px] font-semibold text-ink">{m.name}</span>
                    {m.selected && <Badge variant="warning">Selected</Badge>}
                  </div>
                  <div className="text-[11.5px] text-muted qm-tabular">
                    <span className="font-mono">{m.version}</span> · {mbnDate(m.date)}
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={busy === `mbn-${m.name}`}
                  onClick={() => setConfirmMbn(m.name)}
                >
                  Use this
                </Button>
              </li>
            ))}
            {others.length === 0 && !loading && (
              <li className="px-4 py-6 text-center text-[13px] text-muted">
                {mbnQuery ? `No carrier matches “${mbnQuery}”.` : "No other carrier profiles."}
              </li>
            )}
          </ul>
        </div>
      </Card>

      <ConfirmModal
        open={confirmDelete != null}
        title="Delete this profile?"
        body={
          <>
            <strong className="text-ink">{confirmDelete?.name || "This profile"}</strong> will be removed. The modem keeps
            its current settings; they just won't be re-applied automatically for this SIM.
          </>
        }
        confirmLabel="Delete profile"
        busy={confirmDelete != null && busy === `del-${confirmDelete.idx}`}
        onClose={() => setConfirmDelete(null)}
        onConfirm={async () => {
          if (!confirmDelete) return;
          const idx = confirmDelete.idx;
          setConfirmDelete(null);
          await onDeleteProfile(idx);
        }}
      />

      <ConfirmModal
        open={confirmMbn != null}
        title={activeMbn?.name === confirmMbn ? "Re-apply carrier profile?" : "Switch carrier profile?"}
        body={
          <div className="space-y-2">
            <FailoverWarning action="Switching carrier profile" />
            <p>
              The modem will load <strong className="text-ink">{confirmMbn}</strong> and re-register with the network.
            </p>
            <p className="flex items-start gap-2 rounded-xl bg-saffron-soft px-3 py-2 text-saffron-ink">
              <Sparkles className="mt-0.5 h-4 w-4 shrink-0" />
              Expect the cellular link to drop for up to a minute.
            </p>
          </div>
        }
        confirmLabel={activeMbn?.name === confirmMbn ? "Re-apply" : "Switch now"}
        tone="primary"
        busy={confirmMbn != null && busy === `mbn-${confirmMbn}`}
        onClose={() => setConfirmMbn(null)}
        onConfirm={async () => {
          if (!confirmMbn) return;
          const name = confirmMbn;
          setConfirmMbn(null);
          await onSelectMbn(name);
        }}
      />
    </div>
  );
}
