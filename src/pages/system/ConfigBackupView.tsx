import { useRef, useState } from "react";
import { ArrowRight, Download, FileJson, RadioTower, Upload } from "lucide-react";
import { ApiError, apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Switch } from "../../components/ui";
import { useFailoverActive } from "../../components/obs";
import { useToastStore } from "../../stores/toast-store";
import { Mono, Notice, errText, useGuarded } from "../admin/shared";

const BASE = "/api/v1/system/config-backup";
const MAX_BYTES = 128 * 1024;

interface Change {
  field: string;
  from: unknown;
  to: unknown;
}

interface ItemPreview {
  id: string;
  label: string;
  radio: boolean;
  defaultSelected: boolean;
  applicable: boolean;
  changes: Change[];
  note: string | null;
}

interface Preview {
  bundle: { createdAt: number; appVersion: string; includesIdentifiers: boolean; hasRadio: boolean; hasDataplane?: boolean; profiles: number };
  failoverActive: boolean;
  items: ItemPreview[];
}

interface ItemResult {
  id: string;
  ok: boolean;
  message: string;
}

function show(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v === "" ? "(empty)" : v;
  return JSON.stringify(v);
}

function ItemRow({ item, checked, onToggle }: { item: ItemPreview; checked: boolean; onToggle: (v: boolean) => void }) {
  const [open, setOpen] = useState(false);
  const n = item.changes.length;
  return (
    <li className="py-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-ink">{item.label}</span>
            {!item.applicable ? (
              <Badge variant="neutral">not in bundle</Badge>
            ) : n === 0 ? (
              <Badge variant="neutral">no change</Badge>
            ) : (
              <Badge variant={item.radio ? "warning" : "info"}>
                {n} change{n === 1 ? "" : "s"}
              </Badge>
            )}
          </div>
          {item.note && <p className="mt-1 text-[12px] text-saffron-ink">{item.note}</p>}
          {n > 0 && (
            <button type="button" className="mt-1 text-[12px] font-semibold text-ember-ink cursor-pointer" onClick={() => setOpen((x) => !x)} aria-expanded={open}>
              {open ? "Hide changes" : "Show changes"}
            </button>
          )}
        </div>
        <Switch checked={checked} onChange={onToggle} disabled={!item.applicable} ariaLabel={`Restore ${item.label}`} />
      </div>
      {open && n > 0 && (
        <ul className="mt-2 space-y-1 rounded-xl border border-line bg-sunk p-2.5">
          {item.changes.map((c) => (
            <li key={c.field} className="grid gap-1 text-[12px] sm:grid-cols-[minmax(0,12rem)_1fr]">
              <Mono className="text-muted">{c.field}</Mono>
              <span className="flex min-w-0 flex-wrap items-center gap-1.5">
                <Mono className="text-ink-2 line-through decoration-1">{show(c.from)}</Mono>
                <ArrowRight className="h-3 w-3 shrink-0 text-muted" />
                <Mono className="text-ink">{show(c.to)}</Mono>
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function ConfigBackupView() {
  const toast = useToastStore((s) => s.push);
  const guard = useGuarded();
  const failoverLive = useFailoverActive();
  const fileRef = useRef<HTMLInputElement>(null);
  const [identifiers, setIdentifiers] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [bundle, setBundle] = useState<{ name: string; json: unknown } | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [checking, setChecking] = useState(false);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<ItemResult[] | null>(null);

  async function exportBundle() {
    setExporting(true);
    try {
      const b = await apiFetch<{ createdAt: number; radio?: unknown }>(`${BASE}/export${identifiers ? "?identifiers=1" : ""}`);
      const blob = new Blob([JSON.stringify(b, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cellcore-config-${b.createdAt}.json`;
      a.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("Configuration exported", "success", b.radio ? "Includes the current radio preferences." : "The modem did not answer; radio preferences are not included.");
    } catch (e) {
      toast("Export failed", "error", errText(e));
    } finally {
      setExporting(false);
    }
  }

  function reset() {
    setBundle(null);
    setPreview(null);
    setSelected({});
    if (fileRef.current) fileRef.current.value = "";
  }

  async function choose(f: File | null) {
    setPreview(null);
    setResults(null);
    setBundle(null);
    if (!f) return;
    if (f.size > MAX_BYTES) {
      toast("File too large", "error", "Configuration bundles are well under 128 KiB.");
      reset();
      return;
    }
    setChecking(true);
    try {
      const text = await f.text();
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error("Not a JSON file");
      }
      const p = await apiFetch<Preview>(`${BASE}/preview`, { method: "POST", body: text });
      setBundle({ name: f.name, json });
      setPreview(p);
      setSelected(Object.fromEntries(p.items.map((i) => [i.id, i.defaultSelected])));
    } catch (e) {
      const errs = e instanceof ApiError && Array.isArray(e.data?.errors) ? (e.data?.errors as string[]) : [];
      toast("Bundle rejected", "error", errs.length ? errs.slice(0, 3).join("; ") : errText(e));
      reset();
    } finally {
      setChecking(false);
    }
  }

  const items = preview?.items ?? [];
  const chosen = items.filter((i) => selected[i.id] && i.applicable);
  const chosenRadio = chosen.filter((i) => i.radio);

  const apply = () => {
    if (!bundle || chosen.length === 0) return;
    guard.run({
      title: "Restore the selected settings?",
      body: (
        <>
          <p>
            {chosen.length} item{chosen.length === 1 ? "" : "s"} from <b>{bundle.name}</b> are written over the current configuration, settings first and radio
            items last. There is no undo; export the current configuration first if unsure.
          </p>
          {chosenRadio.length > 0 && (
            <p className="text-crimson-ink text-[12.5px]">
              Radio: {chosenRadio.map((i) => i.label).join(", ")}. The cellular link can drop while these apply.
            </p>
          )}
        </>
      ),
      confirmLabel: "Restore",
      action: (confirm) =>
        apiFetch<{ status: string; results: ItemResult[] }>(`${BASE}/apply`, {
          method: "POST",
          body: JSON.stringify({ bundle: bundle.json, items: chosen.map((i) => i.id), ...(confirm ? { confirm } : {}) }),
        }),
      onDone: (res) => {
        setResults(res.results);
        const failed = res.results.filter((r) => !r.ok).length;
        toast(failed ? "Restore finished with errors" : "Configuration restored", failed ? "error" : "success", failed ? `${failed} item(s) failed` : undefined);
        reset();
      },
    });
  };

  const group = (radio: boolean) => items.filter((i) => i.radio === radio);

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="min-w-0 lg:col-span-5">
          <CardHeader title="Export settings" subtitle="CellCore configuration as a versioned JSON bundle" icon={<Download className="h-4 w-4" />} />
          <div className="space-y-4">
            <p className="text-[13px] text-ink-2">
              Units, monitoring, maintenance, data plan, TTL/MTU/DNS policy, APN profiles, the cell-lock schedule, dataplane/kernel tuning config, radio tuning
              settings, and the radio preferences read from the modem now (bands, network mode, cell locks, carrier firmware).
            </p>
            <Notice tone="info" title="Never included (by design)">
              The SMTP password, API tokens, login sessions, and Qualcomm EFS NV / XQCN factory calibration items (never auto-overwritten on restore; back up
              XQCN separately with QPST/QFIL if needed). For OpenWrt itself use Admin › Backup &amp; LuCI.
            </Notice>
            <Switch
              label="Include SIM identifiers"
              description="ICCID and IMEI in APN profiles. Needed to restore profiles on a different gateway; treat the file as private."
              checked={identifiers}
              onChange={setIdentifiers}
            />
            <Button variant="primary" onClick={exportBundle} disabled={exporting}>
              <FileJson className="h-4 w-4" />
              {exporting ? "Reading modem…" : "Download bundle"}
            </Button>
          </div>
        </Card>

        <Card className="min-w-0 lg:col-span-7">
          <CardHeader title="Restore settings" subtitle="Check what would change, pick items, then apply" icon={<Upload className="h-4 w-4" />} />
          <div className="space-y-4">
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              className="block w-full text-[13px] text-ink-2 file:mr-3 file:cursor-pointer file:rounded-full file:border file:border-line file:bg-raised file:px-3 file:py-1.5 file:text-[12.5px] file:font-semibold file:text-ink"
              onChange={(e) => void choose(e.target.files?.[0] ?? null)}
              aria-label="Configuration bundle"
            />
            {checking && <p className="text-[12.5px] text-muted">Validating and comparing with the current configuration…</p>}
            {!preview && !checking && <p className="text-[12.5px] text-muted">Nothing is changed until you review the differences and confirm.</p>}

            {preview && (
              <>
                <Notice tone="info" title={`Exported ${new Date(preview.bundle.createdAt * 1000).toLocaleString()} · v${preview.bundle.appVersion}`}>
                  {preview.bundle.profiles} APN profile{preview.bundle.profiles === 1 ? "" : "s"}
                  {preview.bundle.includesIdentifiers ? " with SIM identifiers" : " without SIM identifiers"}
                  {preview.bundle.hasRadio ? ", radio preferences included." : ", no radio preferences."}
                </Notice>
                {(failoverLive || preview.failoverActive) && (
                  <Notice tone="danger" title="WAN is failed over to this modem">
                    Restores are refused while traffic depends on the cellular link. Try again after it fails back.
                  </Notice>
                )}

                <div>
                  <div className="qm-eyebrow">Settings</div>
                  <ul className="divide-y divide-line">
                    {group(false).map((i) => (
                      <ItemRow key={i.id} item={i} checked={Boolean(selected[i.id])} onToggle={(v) => setSelected((s) => ({ ...s, [i.id]: v }))} />
                    ))}
                  </ul>
                </div>

                <div className="rounded-2xl border border-saffron/45 p-3">
                  <div className="flex items-center gap-2 text-[12.5px] font-semibold text-saffron-ink">
                    <RadioTower className="h-4 w-4" /> Radio (applied last, off by default)
                  </div>
                  <p className="mt-1 text-[12px] text-muted">These change how the modem attaches. Pick each one deliberately; the link can drop while they apply.</p>
                  <ul className="divide-y divide-line">
                    {group(true).map((i) => (
                      <ItemRow key={i.id} item={i} checked={Boolean(selected[i.id])} onToggle={(v) => setSelected((s) => ({ ...s, [i.id]: v }))} />
                    ))}
                  </ul>
                </div>

                <div className="flex flex-wrap items-center justify-end gap-2">
                  <Button variant="secondary" onClick={reset} disabled={guard.busy}>
                    Discard
                  </Button>
                  <Button
                    variant={chosenRadio.length ? "danger" : "primary"}
                    onClick={apply}
                    disabled={guard.busy || chosen.length === 0 || failoverLive || preview.failoverActive}
                  >
                    Restore {chosen.length || ""} item{chosen.length === 1 ? "" : "s"}…
                  </Button>
                </div>
              </>
            )}

            {results && (
              <ul className="space-y-1 rounded-xl border border-line bg-sunk p-3">
                {results.map((r) => (
                  <li key={r.id} className="flex flex-wrap items-center gap-2 text-[12.5px]">
                    <Badge variant={r.ok ? "success" : "danger"}>{r.ok ? "ok" : "failed"}</Badge>
                    <Mono className="text-ink">{r.id}</Mono>
                    <span className={cn("min-w-0", r.ok ? "text-muted" : "text-crimson-ink")}>{r.message}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
      </div>
      {guard.modal}
    </div>
  );
}
