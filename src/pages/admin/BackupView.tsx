import { useRef, useState } from "react";
import { Archive, Download, ExternalLink, Power, Upload } from "lucide-react";
import { ApiError } from "../../lib/api";
import { disruptiveFetch, isCancelled } from "../../lib/disruptive";
import { FailoverWarning } from "../../components/obs";
import { useAuthStore } from "../../stores/auth-store";
import { formatBytes } from "../../lib/utils";
import { Button, Card, CardHeader, Modal, Skeleton } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { ADMIN, LoadError, Mono, Notice, errText, useAdmin, useGuarded } from "./shared";

interface Inspect {
  entries: number;
  files: string[];
  sensitive: string[];
  bytes: number;
}

function authHeaders(): Headers {
  const { token, csrfToken } = useAuthStore.getState();
  const h = new Headers();
  h.set("X-QM-CSRF", csrfToken || "1");
  if (token && /^[0-9a-fA-F]{16,64}$/.test(token)) h.set("Authorization", `Bearer ${token}`);
  return h;
}

async function postArchive<T>(path: string, file: File): Promise<T> {
  const h = authHeaders();
  h.set("Content-Type", "application/gzip");
  const res = await fetch(`${ADMIN}${path}`, { method: "POST", body: file, headers: h, credentials: "same-origin" });
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text);
  } catch {
    // non-JSON
  }
  if (!res.ok) throw new ApiError(res.status, (body.error as string) || text || `HTTP ${res.status}`, body);
  return body as T;
}

export function BackupView() {
  const q = useAdmin<{
    files: string[];
    count: number;
    luciAvailable?: boolean;
    luciInstalled?: boolean;
    luciProxyEnabled?: boolean;
  }>("/backup");
  const toast = useToastStore((s) => s.push);
  const guard = useGuarded();
  const fileRef = useRef<HTMLInputElement>(null);
  const [downloading, setDownloading] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [inspect, setInspect] = useState<Inspect | null>(null);
  const [checking, setChecking] = useState(false);
  const [rebootAsk, setRebootAsk] = useState(false);
  const [rebooting, setRebooting] = useState(false);

  async function download() {
    setDownloading(true);
    try {
      const res = await fetch(`${ADMIN}/backup/download`, { headers: authHeaders(), credentials: "same-origin", cache: "no-store" });
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") ?? "";
      const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? "backup.tar.gz";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast("Backup downloaded", "success", `${name} · ${formatBytes(blob.size, 1)}`);
    } catch (e) {
      toast("Backup failed", "error", errText(e));
    } finally {
      setDownloading(false);
    }
  }

  async function choose(f: File | null) {
    setFile(f);
    setInspect(null);
    if (!f) return;
    if (f.size > 32 * 1024 * 1024) {
      toast("File too large", "error", "Backups are well under 32 MiB.");
      return;
    }
    setChecking(true);
    try {
      setInspect(await postArchive<Inspect>("/backup/inspect", f));
    } catch (e) {
      toast("Not a usable backup", "error", errText(e));
      setFile(null);
    } finally {
      setChecking(false);
    }
  }

  const restore = () => {
    if (!file || !inspect) return;
    guard.run({
      title: "Restore this backup?",
      body: (
        <>
          <p>
            {inspect.entries} entries from <b>{file.name}</b> are written over /etc. This replaces the root password, SSH keys, firewall, network, QCMAP and CellCore
            settings with the archived copies. Nothing is merged and there is no undo, so download a fresh backup first if unsure.
          </p>
          {inspect.sensitive.length > 0 && (
            <p className="text-crimson-ink text-[12.5px]">
              Includes: <Mono>{inspect.sensitive.slice(0, 8).join(", ")}</Mono>
              {inspect.sensitive.length > 8 ? ` and ${inspect.sensitive.length - 8} more` : ""}
            </p>
          )}
          <p>The gateway needs a reboot afterwards.</p>
        </>
      ),
      confirmLabel: "Restore",
      action: (confirm) => {
        const qs = confirm ? `?confirm=${encodeURIComponent(confirm)}` : "";
        return postArchive(`/backup/restore${qs}`, file);
      },
      onDone: () => {
        setFile(null);
        setInspect(null);
        if (fileRef.current) fileRef.current.value = "";
        setRebootAsk(true);
      },
    });
  };

  async function reboot() {
    setRebooting(true);
    try {
      await disruptiveFetch("reboot", "/api/v1/system/reboot", { method: "POST" }, { confirmed: true });
      toast("Rebooting", "info", "The gateway will be back in about a minute.");
      setRebootAsk(false);
    } catch (e) {
      if (!isCancelled(e)) toast("Reboot failed", "error", errText(e));
    } finally {
      setRebooting(false);
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="min-w-0 lg:col-span-6">
          <CardHeader title="Download a backup" subtitle="Standard OpenWrt sysupgrade -b archive" icon={<Archive className="h-4 w-4" />} />
          <p className="mb-4 text-[13px] text-ink-2">
            Contains changed files under /etc, including the password hash, SSH keys and Wi-Fi/VPN secrets. Store it somewhere private.
          </p>
          <Button variant="primary" onClick={download} disabled={downloading}>
            <Download className="h-4 w-4" />
            {downloading ? "Preparing…" : "Download backup"}
          </Button>
          <details className="mt-4">
            <summary className="cursor-pointer text-[12.5px] font-semibold text-ink-2">What is included{q.data ? ` (${q.data.count} files)` : ""}</summary>
            {q.isLoading ? (
              <Skeleton className="mt-2 h-24" />
            ) : q.error ? (
              <LoadError error={q.error} />
            ) : (
              <ul className="mt-2 max-h-64 overflow-auto">
                {q.data?.files.map((f) => (
                  <li key={f}>
                    <Mono className="text-muted">{f}</Mono>
                  </li>
                ))}
              </ul>
            )}
          </details>
        </Card>

        <Card className="min-w-0 lg:col-span-6">
          <CardHeader title="Restore a backup" subtitle="Replaces /etc from an archive, then reboot" icon={<Upload className="h-4 w-4" />} />
          <div className="space-y-3">
            <input
              ref={fileRef}
              type="file"
              accept=".tar.gz,.tgz,application/gzip"
              className="block w-full text-[13px] text-ink-2 file:mr-3 file:cursor-pointer file:rounded-full file:border file:border-line file:bg-raised file:px-3 file:py-1.5 file:text-[12.5px] file:font-semibold file:text-ink"
              onChange={(e) => void choose(e.target.files?.[0] ?? null)}
              aria-label="Backup archive"
            />
            {checking && <p className="text-[12.5px] text-muted">Checking archive…</p>}
            {inspect && (
              <Notice tone={inspect.sensitive.length ? "warn" : "info"} title={`${inspect.entries} entries, ${formatBytes(inspect.bytes, 1)}`}>
                Paths are all under etc/. {inspect.sensitive.length > 0 && <>It overwrites {inspect.sensitive.length} sensitive files (passwords, SSH, firewall, network/QCMAP).</>}
              </Notice>
            )}
            <Notice tone="info">
              Sysupgrade image flashing is disabled here. For R02A02+ dual-slot modems, use Zero-USB A/B firmware flashing under{" "}
              <a href="#/system/ota" className="font-semibold text-ember-ink underline underline-offset-2 hover:opacity-80">
                System › Updates
              </a>
              .
            </Notice>
            <div className="flex justify-end">
              <Button variant="danger" onClick={restore} disabled={!inspect || guard.busy}>
                Restore…
              </Button>
            </div>
          </div>
        </Card>
      </div>

      {q.data?.luciAvailable === true ? (
        <Card>
          <CardHeader title="Legacy LuCI" subtitle="Escape hatch for anything not covered here" />
          <p className="mb-3 text-[13px] text-ink-2">LuCI still runs behind CellCore. It has its own login and shows the same configuration files.</p>
          <a
            href="/cgi-bin/luci"
            target="_blank"
            rel="noopener"
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-line bg-raised px-4 text-[13px] font-semibold text-ink hover:border-line-strong"
          >
            Open legacy LuCI <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </Card>
      ) : q.data?.luciInstalled && !q.data?.luciProxyEnabled ? (
        <Notice tone="info">
          Legacy LuCI is installed, but the same-origin proxy is disabled by default for origin isolation (set{" "}
          <Mono>CELLCORE_ENABLE_LUCI_PROXY=1</Mono> to opt in).
        </Notice>
      ) : q.data ? (
        <Notice tone="info">LuCI is not installed on this gateway; CellCore manages the system directly.</Notice>
      ) : null}

      <Modal open={rebootAsk} onClose={() => !rebooting && setRebootAsk(false)} title="Backup restored. Reboot now?">
        <FailoverWarning action="Rebooting" />
        <p className="mt-3">Most restored settings only take effect after a reboot. The cellular link drops for about a minute.</p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setRebootAsk(false)} disabled={rebooting}>
            Later
          </Button>
          <Button variant="danger" onClick={reboot} disabled={rebooting}>
            <Power className="h-4 w-4" /> {rebooting ? "Rebooting…" : "Reboot now"}
          </Button>
        </div>
      </Modal>
      {guard.modal}
    </div>
  );
}
