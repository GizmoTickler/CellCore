import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Info, Package, RefreshCw, Search, Trash2 } from "lucide-react";
import { cn, formatBytes } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, Meter, Modal, SegmentedTabs, Skeleton } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { ApiError, apiFetch } from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { ADMIN, DataTable, EmptyRow, LoadError, Mono, Notice, Pre, Td, TextArea, adminSend, errText, formatAgo, useAdmin, useGuarded } from "./shared";

type Guard = "none" | "protected" | "blocked";
interface Installed {
  name: string;
  version: string;
  guard: Guard;
}
interface SoftwareResp {
  installed: Installed[];
  space: { totalKb: number; freeKb: number } | null;
  listsAgeSecs: number | null;
  quecmanagerDepends: string[];
}
interface Avail {
  name: string;
  version: string;
  description?: string;
}
interface SelfUpgradeState {
  active: boolean;
  phase: string;
  package: string;
  fromVersion?: string | null;
  targetVersion?: string | null;
  startedAt: number;
  updatedAt: number;
  error?: string | null;
  rolledBack?: boolean;
}
interface UpdateCheckResp {
  status: string;
  package: string;
  installedVersion: string | null;
  availableVersion: string | null;
  updateAvailable: boolean;
  listsAgeSecs: number | null;
  overlayFreeBytes: number | null;
  minOverlayBytes: number;
  state: SelfUpgradeState;
  warning?: string;
}
interface SelfUpgradeStatusResp {
  status: string;
  state: SelfUpgradeState;
  log: string[];
}

function InfoModal({ name, onClose }: { name: string | null; onClose: () => void }) {
  const q = useQuery({
    queryKey: ["admin", "software-info", name],
    queryFn: () => apiFetch<{ stanzas: Record<string, string>[] }>(`${ADMIN}/software/info?name=${encodeURIComponent(name ?? "")}`),
    enabled: !!name,
  });
  return (
    <Modal open={!!name} onClose={onClose} title={name ?? ""}>
      {q.isLoading && <Skeleton className="h-40" />}
      {q.error && <p className="text-crimson-ink">{errText(q.error)}</p>}
      {q.data?.stanzas.map((s, i) => (
        <dl key={i} className={cn("grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[12.5px]", i > 0 && "mt-4 border-t border-line pt-4")}>
          {Object.entries(s)
            .filter(([k]) => ["Version", "Status", "Depends", "Size", "Description", "Section", "Installed-Time"].includes(k))
            .map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="font-semibold text-muted">{k}</dt>
                <dd className="min-w-0 break-words text-ink-2">{k === "Installed-Time" ? new Date(Number(v) * 1000).toLocaleString() : v}</dd>
              </div>
            ))}
        </dl>
      ))}
      {q.data && q.data.stanzas.length === 0 && <p className="text-muted">No details from opkg (update the package lists?).</p>}
    </Modal>
  );
}

function FeedsPanel() {
  const q = useAdmin<{ customPath: string; custom: string; distPath: string; dist: string }>("/software/feeds");
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const [text, setText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (q.data && !dirty) setText(q.data.custom);
  }, [q.data, dirty]);

  if (q.isLoading) return <Skeleton className="h-48" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;

  async function save() {
    setSaving(true);
    try {
      await adminSend("PUT", "/software/feeds", { content: text });
      toast("Custom feeds saved", "success", "Update lists to fetch metadata from edited feeds.");
      setDirty(false);
      await qc.invalidateQueries({ queryKey: ["admin", "/software/feeds"] });
    } catch (e) {
      toast("Feeds not saved", "error", errText(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="text-[12.5px] font-semibold text-ink">
          Custom feeds (<Mono>{q.data.customPath}</Mono>)
        </div>
        <TextArea
          rows={8}
          className="font-mono text-[12.5px] leading-relaxed"
          value={text}
          spellCheck={false}
          placeholder={"# src/gz feed_name https://example.com/packages"}
          onChange={(e) => {
            setText(e.target.value);
            setDirty(true);
          }}
          aria-label="Custom opkg feeds"
        />
        <div className="flex flex-wrap justify-end gap-2">
          {dirty && (
            <Button
              variant="ghost"
              disabled={saving}
              onClick={() => {
                setText(q.data?.custom ?? "");
                setDirty(false);
              }}
            >
              Discard
            </Button>
          )}
          <Button variant="primary" onClick={() => void save()} disabled={saving}>
            {saving ? "Saving…" : "Save custom feeds"}
          </Button>
        </div>
      </div>
      <details className="qm-subcard p-3">
        <summary className="cursor-pointer text-[12.5px] font-semibold text-ink">
          Distribution feeds (<Mono>{q.data.distPath}</Mono> · read-only)
        </summary>
        <Pre className="mt-2">{q.data.dist || "(empty)"}</Pre>
      </details>
    </div>
  );
}

export function SoftwareView() {
  const q = useAdmin<SoftwareResp>("/software");
  const uc = useAdmin<UpdateCheckResp>("/software/update-check");
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const guard = useGuarded();
  const [tab, setTab] = useState<"installed" | "available" | "feeds">("installed");
  const [term, setTerm] = useState("");
  const [results, setResults] = useState<{ results: Avail[]; total: number } | null>(null);
  const [searching, setSearching] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [upgradeWatch, setUpgradeWatch] = useState(false);
  const [upgradeStatus, setUpgradeStatus] = useState<SelfUpgradeStatusResp | null>(null);
  const [upgradeReconnecting, setUpgradeReconnecting] = useState(false);
  const [log, setLog] = useState<{ title: string; text: string } | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  useEffect(() => {
    if (uc.data?.state?.active) {
      setUpgradeWatch(true);
    }
  }, [uc.data?.state?.active]);

  useEffect(() => {
    if (!upgradeWatch) return;
    let alive = true;
    const poll = async () => {
      try {
        const res = await apiFetch<SelfUpgradeStatusResp>(`${ADMIN}/software/self-upgrade`, {
          skipAuthRedirect: true,
        });
        if (!alive) return;
        setUpgradeReconnecting(false);
        setUpgradeStatus(res);
        if (!res.state.active && (res.state.phase === "succeeded" || res.state.phase === "rolled_back")) {
          setUpgradeWatch(false);
          void qc.invalidateQueries({ queryKey: ["admin", "/software"] });
          void qc.invalidateQueries({ queryKey: ["admin", "/software/update-check"] });
        }
      } catch {
        if (alive) setUpgradeReconnecting(true);
      }
    };
    void poll();
    const id = window.setInterval(() => {
      void poll();
    }, 2000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [upgradeWatch, qc]);

  const installed = useMemo(() => {
    const t = term.trim().toLowerCase();
    return (q.data?.installed ?? []).filter((p) => !t || p.name.toLowerCase().includes(t));
  }, [q.data, term]);
  const installedSet = useMemo(() => new Set((q.data?.installed ?? []).map((p) => p.name)), [q.data]);

  if (q.isLoading) return <Skeleton className="h-96" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const space = d.space;
  const usedPct = space ? 100 - (space.freeKb / Math.max(1, space.totalKb)) * 100 : 0;
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["admin", "/software"] });
    void qc.invalidateQueries({ queryKey: ["admin", "/software/update-check"] });
  };

  async function checkUpdates() {
    setCheckingUpdate(true);
    try {
      const fresh = await apiFetch<UpdateCheckResp>(`${ADMIN}/software/update-check?refresh=1`);
      qc.setQueryData(["admin", "/software/update-check"], fresh);
      toast(
        fresh.updateAvailable ? `Update ready: ${fresh.availableVersion}` : "CellCore is up to date",
        "success"
      );
    } catch (e) {
      toast("Update check failed", "error", errText(e));
    } finally {
      setCheckingUpdate(false);
    }
  }

  const startSelfUpgrade = () => {
    const ucData = uc.data;
    guard.run({
      title: "Upgrade CellCore?",
      body: (
        <>
          <p>
            Downloads and upgrades <b className="font-mono">{ucData?.package ?? "sdxpinn-cellcore"}</b>
            {ucData?.availableVersion ? ` to ${ucData.availableVersion}` : ""}.
          </p>
          <p className="text-[12.5px] text-muted">
            The daemon restarts briefly (under a detached supervisor) and automatically rolls back to the previous binary and UI if health verification fails within 45 s.
          </p>
        </>
      ),
      confirmLabel: "Start upgrade",
      tone: "danger",
      action: async (confirm) => {
        try {
          return await disruptiveFetch<{ status: string; targetVersion?: string }>(
            "CellCore upgrade",
            `${ADMIN}/software/self-upgrade`,
            {
              method: "POST",
              body: JSON.stringify(confirm ? { confirm } : {}),
            }
          );
        } catch (e) {
          if (isCancelled(e)) throw new Error("Upgrade cancelled during active WAN failover");
          throw e;
        }
      },
      onDone: () => {
        setUpgradeWatch(true);
        toast("CellCore upgrade started", "success", "Tracking progress across daemon restart…");
      },
    });
  };

  async function search() {
    setSearching(true);
    try {
      setResults(await apiFetch(`${ADMIN}/software/available?q=${encodeURIComponent(term.trim())}`));
    } catch (e) {
      toast("Search failed", "error", errText(e));
    } finally {
      setSearching(false);
    }
  }

  async function updateLists() {
    setUpdating(true);
    try {
      const r = await adminSend<{ log: string }>("POST", "/software/update");
      setLog({ title: "Package lists updated", text: r.log });
      await refresh();
    } catch (e) {
      const text = e instanceof ApiError && typeof e.data?.log === "string" ? (e.data.log as string) : errText(e);
      setLog({ title: "Update failed", text });
    } finally {
      setUpdating(false);
    }
  }

  const opDone = (title: string) => (r: { log?: string }) => {
    setLog({ title, text: r.log ?? "" });
    setResults(null);
    void refresh();
  };

  const install = (p: Avail) =>
    guard.run({
      title: `Install ${p.name}?`,
      body: (
        <>
          <p>
            opkg downloads <b className="font-mono">{p.name}</b> {p.version} and its dependencies onto the overlay ({space ? formatBytes(space.freeKb * 1024, 0) : "?"} free).
          </p>
          <p className="text-muted text-[12.5px]">New packages can add services or change config files. Packages from the OpenWrt feeds are not built for this QSDK kernel, so kernel modules (kmod-*) may not load.</p>
        </>
      ),
      confirmLabel: "Install",
      tone: "primary",
      action: () => adminSend<{ log: string }>("POST", "/software/install", { name: p.name }),
      onDone: opDone(`Installed ${p.name}`),
    });

  const remove = (p: Installed) =>
    guard.run({
      title: `Remove ${p.name}?`,
      body: (
        <>
          <p>
            opkg removes <b className="font-mono">{p.name}</b>. Its files and unchanged config go with it.
          </p>
          {p.guard === "protected" && (
            <p className="text-crimson-ink">CellCore or the platform depends on this package. Removing it can break this UI, networking or SSH, and there is no undo from here.</p>
          )}
        </>
      ),
      confirmLabel: "Remove",
      action: (confirm) => adminSend<{ log: string }>("POST", "/software/remove", { name: p.name, confirm }),
      onDone: opDone(`Removed ${p.name}`),
    });

  const ucData = uc.data;
  const activeUpgrade = upgradeStatus?.state ?? (ucData?.state?.active ? ucData.state : null);
  const freeBytes = ucData?.overlayFreeBytes ?? (space ? space.freeKb * 1024 : null);
  const minBytes = ucData?.minOverlayBytes ?? 15 * 1024 * 1024;
  const spaceEnough = freeBytes === null || freeBytes >= minBytes;

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader
          title="CellCore Update"
          subtitle={`Package ${ucData?.package ?? "sdxpinn-cellcore"} · auto-rollback watchdog on 45s verify failure`}
          icon={<Download className="h-4 w-4" />}
          action={
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="secondary" size="sm" onClick={() => void checkUpdates()} disabled={checkingUpdate || upgradeWatch}>
                <RefreshCw className={cn("h-3.5 w-3.5", checkingUpdate && "animate-spin")} />
                {checkingUpdate ? "Checking…" : "Check for updates"}
              </Button>
              {activeUpgrade?.phase === "succeeded" ? (
                <Button variant="primary" size="sm" onClick={() => window.location.reload()}>
                  Reload UI
                </Button>
              ) : (
                <Button
                  variant={ucData?.updateAvailable ? "primary" : "secondary"}
                  size="sm"
                  onClick={startSelfUpgrade}
                  disabled={guard.busy || upgradeWatch || !spaceEnough}
                >
                  {upgradeWatch
                    ? "Upgrading…"
                    : ucData?.updateAvailable
                      ? `Upgrade to ${ucData.availableVersion}`
                      : "Reinstall / Upgrade"}
                </Button>
              )}
            </div>
          }
        />
        <div className="grid gap-3 sm:grid-cols-3 text-[13px]">
          <div className="qm-subcard p-3">
            <div className="text-[11px] font-semibold text-muted">Installed version</div>
            <div className="mt-1 font-mono text-[14px] font-bold text-ink">{ucData?.installedVersion ?? "—"}</div>
          </div>
          <div className="qm-subcard p-3">
            <div className="text-[11px] font-semibold text-muted">Feed latest</div>
            <div className="mt-1 flex items-center gap-2">
              <span className="font-mono text-[14px] font-bold text-ink">{ucData?.availableVersion ?? "Run Check"}</span>
              {ucData?.updateAvailable && <Badge variant="success">Update available</Badge>}
            </div>
          </div>
          <div className="qm-subcard p-3">
            <div className="text-[11px] font-semibold text-muted">Overlay check (min {formatBytes(minBytes, 0)})</div>
            <div className="mt-1 flex items-center gap-2">
              <span className={cn("font-mono text-[13px] font-semibold", spaceEnough ? "text-jade-ink" : "text-crimson-ink")}>
                {freeBytes != null ? `${formatBytes(freeBytes, 1)} free` : "—"}
              </span>
              {!spaceEnough && <Badge variant="danger">Too low</Badge>}
            </div>
          </div>
        </div>
        {ucData?.warning && <p className="mt-2.5 text-[12px] text-saffron-ink">{ucData.warning}</p>}
        {(activeUpgrade && activeUpgrade.phase !== "idle") && (
          <div className="mt-3 rounded-2xl border border-line bg-sunk p-3 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 text-[12.5px]">
              <span className="flex items-center gap-2 font-semibold text-ink">
                Phase:
                <Badge variant={activeUpgrade.phase === "succeeded" ? "success" : activeUpgrade.rolledBack ? "danger" : "info"}>
                  {activeUpgrade.phase}
                </Badge>
                {upgradeReconnecting && <span className="text-saffron-ink">Waiting for daemon restart…</span>}
              </span>
              {activeUpgrade.targetVersion && (
                <Mono className="text-muted">
                  {activeUpgrade.fromVersion ?? "?"} → {activeUpgrade.targetVersion}
                </Mono>
              )}
            </div>
            {activeUpgrade.error && <p className="text-[12px] text-crimson-ink">{activeUpgrade.error}</p>}
            {upgradeStatus?.log && upgradeStatus.log.length > 0 && (
              <pre className="max-h-40 overflow-y-auto rounded-xl border border-line bg-raised p-2.5 font-mono text-[11px] text-ink-2 whitespace-pre-wrap">
                {upgradeStatus.log.join("\n")}
              </pre>
            )}
          </div>
        )}
      </Card>

      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="min-w-0 lg:col-span-5">
          <CardHeader title="Overlay space" subtitle="Where packages are installed" icon={<Package className="h-4 w-4" />} />
          {space ? (
            <div className="space-y-2">
              <div className="flex items-baseline justify-between">
                <span className="qm-display text-[1.75rem] font-semibold text-ink">{formatBytes(space.freeKb * 1024, 1)}</span>
                <span className="text-[12px] text-muted">free of {formatBytes(space.totalKb * 1024, 0)}</span>
              </div>
              <Meter pct={usedPct} tone={usedPct > 85 ? "crimson" : usedPct > 70 ? "saffron" : "jade"} />
            </div>
          ) : (
            <p className="text-muted">Unknown</p>
          )}
        </Card>
        <Card className="min-w-0 lg:col-span-7">
          <CardHeader
            title="Package lists"
            subtitle={`Last updated ${formatAgo(d.listsAgeSecs)}. Lists live in RAM and are lost on reboot.`}
            action={
              <Button variant="secondary" size="sm" onClick={updateLists} disabled={updating}>
                <RefreshCw className={cn("h-3.5 w-3.5", updating && "animate-spin")} />
                {updating ? "Updating…" : "Update lists"}
              </Button>
            }
          />
          <p className="text-[12.5px] text-muted">
            {d.installed.length} packages installed. CellCore depends on {d.quecmanagerDepends.join(", ") || "—"}; those are marked Protected.
          </p>
        </Card>
      </div>

      <Card>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            options={[
              { id: "installed", label: "Installed", badge: d.installed.length },
              { id: "available", label: "Available" },
              { id: "feeds", label: "Feeds" },
            ]}
          />
          {tab !== "feeds" && (
            <form
              className="relative flex min-w-0 flex-1 basis-56 gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (tab === "available" && term.trim().length >= 2) void search();
              }}
            >
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input className="pl-9" placeholder={tab === "installed" ? "Filter installed packages" : "Search the feeds (2+ characters)"} value={term} onChange={(e) => setTerm(e.target.value)} aria-label="Search packages" />
              {tab === "available" && (
                <Button type="submit" variant="secondary" disabled={term.trim().length < 2 || searching}>
                  {searching ? "…" : "Search"}
                </Button>
              )}
            </form>
          )}
        </div>

        {tab === "feeds" ? (
          <FeedsPanel />
        ) : tab === "installed" ? (
          <DataTable head={["Package", "Version", ""]}>
            {installed.length === 0 && <EmptyRow cols={3}>No packages match.</EmptyRow>}
            {installed.slice(0, 400).map((p) => (
              <tr key={p.name}>
                <Td>
                  <span className="font-mono text-[12.5px] text-ink">{p.name}</span>{" "}
                  {p.guard === "protected" && <Badge variant="warning">Protected</Badge>}
                  {p.guard === "blocked" && <Badge variant="plum">CellCore</Badge>}
                </Td>
                <Td mono className="text-muted">
                  {p.version}
                </Td>
                <Td>
                  <div className="flex justify-end">
                    <Button variant="ghost" size="sm" className="px-2" aria-label={`Details for ${p.name}`} onClick={() => setInfo(p.name)}>
                      <Info className="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="ghost" size="sm" className="px-2 text-crimson-ink" aria-label={`Remove ${p.name}`} disabled={p.guard === "blocked"} onClick={() => remove(p)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </Td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <>
            {d.listsAgeSecs == null && <Notice tone="warn" className="mb-3">Package lists are not downloaded yet. Use “Update lists” first.</Notice>}
            <DataTable head={["Package", "Version", ""]}>
              {!results && <EmptyRow cols={3}>Search the feeds by name or description.</EmptyRow>}
              {results && results.results.length === 0 && <EmptyRow cols={3}>Nothing found.</EmptyRow>}
              {results?.results.map((p) => (
                <tr key={p.name}>
                  <Td className="max-w-[min(60vw,560px)]">
                    <span className="font-mono text-[12.5px] text-ink">{p.name}</span>
                    {p.description && <span className="block truncate text-[12px] text-muted">{p.description}</span>}
                  </Td>
                  <Td mono className="text-muted">
                    {p.version}
                  </Td>
                  <Td>
                    <div className="flex justify-end">
                      {installedSet.has(p.name) ? (
                        <Badge variant="success">Installed</Badge>
                      ) : (
                        <Button variant="tier3" size="sm" onClick={() => install(p)}>
                          <Download className="h-3.5 w-3.5" /> Install
                        </Button>
                      )}
                    </div>
                  </Td>
                </tr>
              ))}
            </DataTable>
            {results && results.total > results.results.length && <p className="mt-3 text-[12px] text-muted">Showing {results.results.length} of {results.total}; refine the search.</p>}
          </>
        )}
      </Card>

      <InfoModal name={info} onClose={() => setInfo(null)} />
      <Modal open={!!log} onClose={() => setLog(null)} title={log?.title ?? ""}>
        <Pre>{log?.text || "(no output)"}</Pre>
        <p className="mt-2 text-[12px] text-muted">
          <Mono>opkg</Mono> output
        </p>
      </Modal>
      {guard.modal}
    </div>
  );
}
