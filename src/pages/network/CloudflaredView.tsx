import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, KeyRound, Play, RefreshCw, ShieldAlert, ShieldCheck, Square, Terminal, Trash2 } from "lucide-react";
import { ApiError, apiFetch } from "../../lib/api";
import { isCancelled } from "../../lib/disruptive";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, LiveDot, Modal, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { LoadError, Notice, errText } from "../admin/shared";
import { Fact } from "./VpnParts";
import { VPN, vpnPost, vpnPostGuarded, type CloudflaredConfig, type CloudflaredStatus } from "./vpn-api";

const KEY = ["vpn", "cloudflared"];

const EDGE_OPTS: Array<{ id: CloudflaredConfig["edgeIpVersion"]; label: string; hint: string }> = [
  { id: "auto", label: "Auto (v4 + v6)", hint: "Best default — uses IPv6 natively on 5G SA" },
  { id: "6", label: "IPv6 Only", hint: "Forces IPv6 edge connections" },
  { id: "4", label: "IPv4 Only", hint: "Forces IPv4 edge connections" },
];

const PROTO_OPTS: Array<{ id: CloudflaredConfig["protocol"]; label: string; hint: string }> = [
  { id: "http2", label: "HTTP/2", hint: "Most reliable over cellular / 464XLAT MTU" },
  { id: "quic", label: "QUIC", hint: "UDP/7844 transport" },
  { id: "auto", label: "Auto", hint: "Tries QUIC then falls back to HTTP/2" },
];

function verdict(d: CloudflaredStatus) {
  if (!d.installed) {
    return {
      title: "Not installed",
      body: "Install the official cloudflared binary to publish this modem's UI & SSH securely through Cloudflare Zero Trust.",
      tone: "muted" as const,
    };
  }
  if (!d.tokenConfigured) {
    return {
      title: "Needs tunnel token",
      body: "Paste a Zero Trust tunnel token below to connect this modem to Cloudflare.",
      tone: "saffron" as const,
    };
  }
  if (!d.service.running) {
    return {
      title: "Stopped",
      body: "The tunnel is configured, but the cloudflared daemon is currently stopped.",
      tone: "crimson" as const,
    };
  }
  if (!d.metrics.connected) {
    return {
      title: "Connecting",
      body: "cloudflared is running and establishing edge connections with Cloudflare.",
      tone: "saffron" as const,
    };
  }
  return {
    title: "Connected",
    body: `Active Zero Trust tunnel with ${d.metrics.haConnections} HA edge connections proxying loopback UI (:443), SSH (:22), and WARP private routing.`,
    tone: "jade" as const,
  };
}

export function CloudflaredView() {
  const toast = useToastStore((s) => s.push);
  const qc = useQueryClient();

  const q = useQuery({
    queryKey: KEY,
    queryFn: () => apiFetch<CloudflaredStatus>(`${VPN}/cloudflared`),
    refetchInterval: (qq) => (qq.state.data?.job?.job?.state === "running" ? 2000 : 10000),
  });

  const d = q.data;
  const [busy, setBusy] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [edgeIp, setEdgeIp] = useState<CloudflaredConfig["edgeIpVersion"]>("auto");
  const [protocol, setProtocol] = useState<CloudflaredConfig["protocol"]>("http2");
  const [loopbackIp, setLoopbackIp] = useState("");
  const [autostart, setAutostart] = useState(true);
  const [dirty, setDirty] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [removePhrase, setRemovePhrase] = useState("REMOVE CLOUDFLARE TUNNEL");
  const [removeServerMsg, setRemoveServerMsg] = useState<string | null>(null);
  const [removeTyped, setRemoveTyped] = useState("");
  const [delToken, setDelToken] = useState(false);
  const [delBin, setDelBin] = useState(false);

  useEffect(() => {
    if (!d || dirty) return;
    setEdgeIp(d.config.edgeIpVersion || "auto");
    setProtocol(d.config.protocol || "http2");
    setLoopbackIp(d.config.loopbackIp ?? "");
    setAutostart(d.config.autostart);
  }, [d, dirty]);

  const refresh = () => qc.invalidateQueries({ queryKey: KEY });

  async function act(tag: string, fn: () => Promise<unknown>, okMsg: string) {
    setBusy(tag);
    try {
      await fn();
      toast(okMsg, "success");
      await refresh();
    } catch (e) {
      if (!isCancelled(e)) toast(`Cloudflare Tunnel: ${okMsg.toLowerCase()} failed`, "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  if (q.error) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  if (!d) return <Skeleton className="h-64 w-full" />;

  const v = verdict(d);
  const job = d.job?.job;
  const jobRunning = job?.state === "running";

  const saveConfig = () =>
    act(
      "save",
      async () => {
        await vpnPost("/cloudflared/config", {
          ...(token.trim() ? { tunnelToken: token.trim() } : {}),
          edgeIpVersion: edgeIp,
          protocol,
          loopbackIp: loopbackIp.trim(),
          autostart,
        });
        setToken("");
        setDirty(false);
      },
      "Tunnel configuration saved"
    );

  const openRemoveModal = () => {
    setDelToken(false);
    setDelBin(false);
    setRemoveTyped("");
    setRemovePhrase("REMOVE CLOUDFLARE TUNNEL");
    setRemoveServerMsg(null);
    setRemoveOpen(true);
  };

  async function confirmRemove() {
    setBusy("remove");
    try {
      await vpnPostGuarded("Remove Cloudflare Tunnel", "/cloudflared/remove", {
        confirm: removeTyped.trim(),
        deleteToken: delToken,
        deleteBinary: delBin,
      });
      setRemoveOpen(false);
      setDirty(false);
      toast("Cloudflare Tunnel removed", "success");
      await refresh();
    } catch (e) {
      if (isCancelled(e)) {
        setRemoveOpen(false);
        return;
      }
      if (e instanceof ApiError && e.status === 428 && typeof e.data?.confirm === "string") {
        setRemovePhrase(e.data.confirm);
        setRemoveServerMsg(e.message);
        setRemoveTyped("");
      } else {
        toast("Remove Cloudflare Tunnel failed", "error", errText(e));
      }
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <div className="lg:col-span-7 min-w-0 space-y-5">
        <Card className="space-y-5">
          <CardHeader
            title="Remote Access (Cloudflare Tunnel)"
            subtitle="Reach this modem's UI & SSH securely via Cloudflare Zero Trust — works even if your router is down"
            icon={<ShieldCheck className="h-4 w-4" />}
            action={
              <Badge variant={d.metrics.connected ? "success" : d.service.running ? "warning" : "neutral"}>
                {d.metrics.connected
                  ? `${d.metrics.haConnections} HA edges`
                  : d.service.running
                    ? "Connecting"
                    : d.installed
                      ? "Stopped"
                      : "Not installed"}
              </Badge>
            }
          />
          <div className="qm-subcard p-5 space-y-2">
            <div className="flex items-center gap-2.5">
              <LiveDot tone={v.tone} />
              <span className="qm-display text-[1.9rem] font-semibold leading-none text-ink">{v.title}</span>
            </div>
            <p className="text-[13px] text-ink-2 max-w-prose">{v.body}</p>
            {d.metrics.edgeLocations.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-2">
                {d.metrics.edgeLocations.map((colo) => (
                  <span
                    key={colo}
                    className="rounded-full border border-line bg-surface px-2.5 py-0.5 font-mono text-[11px] text-ink-2"
                  >
                    {colo}
                  </span>
                ))}
              </div>
            )}
          </div>

          <dl className="grid gap-3 grid-cols-2 sm:grid-cols-4">
            <Fact label="Version">
              <span className="font-mono text-[12px]">{d.version ?? "--"}</span>
            </Fact>
            <Fact label="HA Edges">{d.metrics.haConnections}</Fact>
            <Fact label="Requests">{d.metrics.totalRequests}</Fact>
            <Fact label="Loopback IP">
              <span className="font-mono text-[12px]">{d.config.loopbackIp ?? "none"}</span>
            </Fact>
          </dl>

          {d.installed && (
            <div className="flex flex-wrap gap-2">
              {d.service.running ? (
                <>
                  <Button
                    variant="secondary"
                    disabled={busy !== null}
                    onClick={() => act("restart", () => vpnPost("/cloudflared/service", { action: "restart" }), "Tunnel restarted")}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    Restart
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={busy !== null}
                    onClick={() => act("stop", () => vpnPost("/cloudflared/service", { action: "stop" }), "Tunnel stopped")}
                  >
                    <Square className="h-3.5 w-3.5" />
                    Stop
                  </Button>
                </>
              ) : (
                <Button
                  variant="primary"
                  disabled={busy !== null || !d.tokenConfigured}
                  onClick={() => act("start", () => vpnPost("/cloudflared/service", { action: "start" }), "Tunnel started")}
                >
                  <Play className="h-3.5 w-3.5" />
                  Start tunnel
                </Button>
              )}
              <Button variant="ghost" onClick={() => setShowLogs((s) => !s)}>
                <Terminal className="h-3.5 w-3.5" />
                {showLogs ? "Hide logs" : `Logs (${d.logs.length})`}
              </Button>
            </div>
          )}
        </Card>

        {showLogs && (
          <Card className="space-y-3">
            <CardHeader title="Recent cloudflared Logs" subtitle="Filtered from syslog (last 20 entries)" icon={<Terminal className="h-4 w-4" />} />
            {d.logs.length === 0 ? (
              <p className="text-[13px] text-muted">No recent cloudflared log lines in syslog.</p>
            ) : (
              <pre className="max-h-60 overflow-auto rounded-xl bg-surface-2 p-3 font-mono text-[11px] leading-relaxed text-ink-2 whitespace-pre-wrap break-all">
                {d.logs.join("\n")}
              </pre>
            )}
          </Card>
        )}

        <Card className="space-y-4">
          <CardHeader
            title="Tunnel Configuration"
            subtitle="Remote ingress rules are managed in Cloudflare Zero Trust; paste your tunnel token here"
            icon={<KeyRound className="h-4 w-4" />}
            action={
              <Badge variant={d.tokenConfigured ? "success" : "warning"}>
                {d.tokenConfigured ? "Token saved" : "No token"}
              </Badge>
            }
          />

          <div className="space-y-1.5">
            <label htmlFor="cf-tunnel-token" className="text-[12px] font-medium text-ink">
              Tunnel Token <span className="text-muted font-normal">(write-only, stored 0600)</span>
            </label>
            <Input
              id="cf-tunnel-token"
              type="password"
              autoComplete="off"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                setDirty(true);
              }}
              placeholder={d.tokenConfigured ? "Token saved on modem — paste a new token only to replace it" : "eyJhIjoi… (from Cloudflare Zero Trust → Tunnels)"}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <div className="text-[12px] font-medium text-ink">Edge IP Version</div>
              <div className="grid gap-1.5">
                {EDGE_OPTS.map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => {
                      setEdgeIp(opt.id);
                      setDirty(true);
                    }}
                    className={cn(
                      "rounded-xl border px-3 py-2 text-left transition cursor-pointer",
                      edgeIp === opt.id ? "border-ember bg-ember-soft" : "border-line bg-surface hover:border-line-strong"
                    )}
                  >
                    <div className="text-[13px] font-medium text-ink">{opt.label}</div>
                    <div className="text-[11px] text-muted">{opt.hint}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-[12px] font-medium text-ink">Transport Protocol</div>
              <div className="grid gap-1.5">
                {PROTO_OPTS.map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => {
                      setProtocol(opt.id);
                      setDirty(true);
                    }}
                    className={cn(
                      "rounded-xl border px-3 py-2 text-left transition cursor-pointer",
                      protocol === opt.id ? "border-ember bg-ember-soft" : "border-line bg-surface hover:border-line-strong"
                    )}
                  >
                    <div className="text-[13px] font-medium text-ink">{opt.label}</div>
                    <div className="text-[11px] text-muted">{opt.hint}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="cf-loopback-ip" className="text-[12px] font-medium text-ink">
              WARP Private Loopback IP <span className="text-muted font-normal">(optional `/32` on `lo`)</span>
            </label>
            <Input
              id="cf-loopback-ip"
              value={loopbackIp}
              onChange={(e) => {
                setLoopbackIp(e.target.value);
                setDirty(true);
              }}
              placeholder="e.g. 10.254.224.1"
            />
            <p className="text-[11px] text-muted">
              Optional non-overlapping private IPv4 bound to loopback so WARP clients can reach SSH & UI directly when routed in Zero Trust.
            </p>
          </div>

          <div className="flex items-center justify-between rounded-xl border border-line bg-surface px-4 py-3">
            <div>
              <div className="text-[13px] font-medium text-ink">Start automatically on boot</div>
              <div className="text-[11px] text-muted">Enables `/etc/init.d/cloudflared` under procd auto-respawn</div>
            </div>
            <Switch
              checked={autostart}
              onChange={(v) => {
                setAutostart(v);
                setDirty(true);
              }}
              label="Autostart cloudflared on boot"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" disabled={busy !== null || (!dirty && !token.trim())} onClick={saveConfig}>
                {busy === "save" ? "Saving…" : "Save & Apply"}
              </Button>
              {dirty && (
                <Button variant="ghost" onClick={() => { setDirty(false); setToken(""); }}>
                  Reset
                </Button>
              )}
            </div>
            {(d.installed || d.tokenConfigured) && (
              <Button variant="danger" size="sm" disabled={busy !== null} onClick={openRemoveModal}>
                <Trash2 className="h-3.5 w-3.5" />
                Remove tunnel
              </Button>
            )}
          </div>
        </Card>
      </div>

      <div className="lg:col-span-5 min-w-0 space-y-5">
        <Card className="space-y-4">
          <CardHeader
            title="cloudflared Binary"
            subtitle="Official static ARM64 binary from GitHub Releases"
            icon={<Download className="h-4 w-4" />}
            action={<Badge variant={d.installed ? "success" : "neutral"}>{d.version ?? "Not installed"}</Badge>}
          />
          <p className="text-[13px] text-ink-2">
            Downloads the official static `cloudflared-linux-arm64` binary (~36 MiB), verifies `--version` before swapping in `/usr/bin/cloudflared`, and runs with `GOMEMLIMIT=48MiB` and `--no-autoupdate`.
          </p>
          <Button
            variant={d.installed ? "secondary" : "primary"}
            disabled={busy !== null || jobRunning}
            onClick={() => act("install", () => vpnPost("/cloudflared/install", {}), d.installed ? "Update started" : "Install started")}
          >
            <Download className="h-3.5 w-3.5" />
            {jobRunning ? "Downloading…" : d.installed ? "Update cloudflared" : "Install cloudflared"}
          </Button>
          {job && (
            <div className="space-y-2">
              <Notice tone={job.state === "failed" ? "danger" : "info"}>
                {job.action}: <strong>{job.state}</strong>
                {job.versionAfter ? ` (${job.versionAfter})` : ""}
                {job.message ? ` — ${job.message}` : ""}
              </Notice>
              {d.job.log.length > 0 && (
                <pre className="max-h-40 overflow-auto rounded-xl bg-surface-2 p-2.5 font-mono text-[11px] text-ink-2 whitespace-pre-wrap break-all">
                  {d.job.log.join("\n")}
                </pre>
              )}
            </div>
          )}
        </Card>

        <Card className="space-y-3">
          <CardHeader title="How Ingress Works" subtitle="Loopback targets inside this modem" icon={<ShieldCheck className="h-4 w-4" />} />
          <p className="text-[13px] text-ink-2">
            Point your Cloudflare Zero Trust tunnel public hostnames at this modem's loopback listeners:
          </p>
          <ul className="space-y-1.5 text-[12px] text-ink-2 font-mono">
            <li>• UI: <code>https://127.0.0.1:443</code> (enable No TLS Verify)</li>
            <li>• SSH: <code>ssh://127.0.0.1:22</code></li>
          </ul>
          <p className="text-[12px] text-muted">
            Because `cloudflared` dials outbound over IPv6/IPv4, your remote UI & SSH stay reachable even if your downstream router or fiber ISP is down.
          </p>
        </Card>
      </div>

      <Modal
        open={removeOpen}
        onClose={() => {
          if (busy !== "remove") setRemoveOpen(false);
        }}
        title="Remove Cloudflare Tunnel?"
      >
        <div className="space-y-3 text-[13px] text-ink-2">
          <p>Stops and disables the cloudflared service and removes its init script and loopback IP.</p>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={delToken}
              onChange={(e) => setDelToken(e.target.checked)}
              disabled={busy === "remove"}
            />
            <span>
              Also delete the stored tunnel token (<code className="font-mono">/etc/cloudflared/token</code>)
            </span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={delBin}
              onChange={(e) => setDelBin(e.target.checked)}
              disabled={busy === "remove"}
            />
            <span>
              Also delete the <code className="font-mono">cloudflared</code> binary (~36 MiB)
            </span>
          </label>
          <div className="rounded-xl border border-crimson/40 bg-crimson-soft p-3 space-y-2">
            {removeServerMsg && (
              <p className="flex gap-2 text-[12.5px] text-crimson-ink">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{removeServerMsg}</span>
              </p>
            )}
            <label className="block text-[12px] font-semibold text-ink-2">
              Type <span className="font-mono text-ink">{removePhrase}</span> to continue
              <Input
                autoFocus
                className="mt-1.5 font-mono"
                value={removeTyped}
                onChange={(e) => setRemoveTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                disabled={busy === "remove"}
                aria-label={`Type ${removePhrase} to confirm`}
              />
            </label>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={() => setRemoveOpen(false)} disabled={busy === "remove"}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={confirmRemove}
            disabled={busy === "remove" || removeTyped.trim() !== removePhrase}
          >
            {busy === "remove" ? "Removing…" : "Remove"}
          </Button>
        </div>
      </Modal>
    </div>
  );
}
