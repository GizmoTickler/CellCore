import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Laptop, LogIn, Settings2, Shield } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { isCancelled } from "../../lib/disruptive";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, CopyButton, Input, LiveDot, Select, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { LoadError, Notice, errText, useGuarded } from "../admin/shared";
import { ApplyNote } from "./shared";
import { Fact, PackageCard } from "./VpnParts";
import { VPN, vpnPost, vpnPostGuarded, type TailscaleStatus, type TsSettings } from "./vpn-api";

const KEY = ["vpn", "tailscale"];

function lastSeen(iso: string | null): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 3600) return `seen ${Math.max(1, Math.round(s / 60))} min ago`;
  if (s < 172800) return `seen ${Math.round(s / 3600)} h ago`;
  return `seen ${Math.round(s / 86400)} days ago`;
}

export function TailscaleView() {
  const toast = useToastStore((s) => s.push);
  const qc = useQueryClient();
  const guard = useGuarded();
  const q = useQuery({
    queryKey: KEY,
    queryFn: () => apiFetch<TailscaleStatus>(`${VPN}/tailscale`),
    refetchInterval: (qq) => (qq.state.data?.job?.job?.state === "running" || qq.state.data?.status?.backendState === "NeedsLogin" ? 3000 : 15000),
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [authKey, setAuthKey] = useState("");
  const [form, setForm] = useState<TsSettings | null>(null);
  const [routesText, setRoutesText] = useState("");

  const d = q.data;
  useEffect(() => {
    if (d && !form) {
      setForm(d.settings);
      setRoutesText(d.settings.advertiseRoutes.join(", "));
    }
  }, [d, form]);

  const refresh = () => qc.invalidateQueries({ queryKey: KEY });

  async function act(tag: string, fn: () => Promise<unknown>, okMsg: string) {
    setBusy(tag);
    try {
      await fn();
      toast(okMsg, "success");
      await refresh();
    } catch (e) {
      if (!isCancelled(e)) toast("Tailscale: action failed", "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  if (q.error) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  if (!d || !form) return <Skeleton className="h-64 w-full" />;

  const st = d.status;
  const me = st?.selfNode;
  const peers = st?.peers ?? [];
  const online = peers.filter((p) => p.online).length;
  const exitPeers = peers.filter((p) => p.exitNodeOption);
  const unsupported = new Set(d.capabilities.unsupported);

  const v = !d.installed
    ? { title: "Not installed", body: "Install tailscale-tiny below to reach this modem from your tailnet.", tone: "muted" as const }
    : !d.service.running
      ? { title: "Stopped", body: "Tailscale is installed but not running. Remote access over the tailnet is off.", tone: "muted" as const }
      : st?.backendState === "Running"
        ? { title: "Connected", body: `Reachable from your tailnet${st.tailnet ? ` (${st.tailnet})` : ""}.`, tone: "jade" as const }
        : st?.backendState === "NeedsLogin" || st?.backendState === "NeedsMachineAuth"
          ? { title: "Needs sign-in", body: "Running, but this modem has not joined a tailnet yet. Sign in below.", tone: "saffron" as const }
          : { title: st?.backendState || "Starting", body: "Tailscale is starting.", tone: "saffron" as const };

  const changed = (k: keyof TsSettings) => JSON.stringify(form[k]) !== JSON.stringify(d.settings[k]);

  function save() {
    if (!form) return;
    const routes = routesText
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    const body: Record<string, unknown> = {};
    if (changed("hostname")) body.hostname = form.hostname;
    if (changed("acceptRoutes")) body.acceptRoutes = form.acceptRoutes;
    if (JSON.stringify(routes) !== JSON.stringify(d!.settings.advertiseRoutes)) body.advertiseRoutes = routes;
    if (changed("advertiseExitNode")) body.advertiseExitNode = form.advertiseExitNode;
    if (changed("exitNode")) body.exitNode = form.exitNode;
    if (changed("ssh")) body.ssh = form.ssh;
    if (changed("shieldsUp")) body.shieldsUp = form.shieldsUp;
    if (Object.keys(body).length === 0) {
      toast("Nothing changed", "info");
      return;
    }
    const usingExit = "exitNode" in body && form.exitNode !== "";
    guard.run({
      title: usingExit ? `Use ${form.exitNode} as exit node?` : "Apply Tailscale settings?",
      body: usingExit ? (
        <div className="space-y-2 text-[13px] text-ink-2">
          <p>This modem's traffic, and LAN traffic it forwards, will leave through {form.exitNode}.</p>
          <ul className="list-disc pl-5 space-y-1">
            <li>Latency and the public IP become those of that device.</li>
            <li>If that device or its connection fails, forwarded LAN / failover traffic stops until the exit node is cleared.</li>
          </ul>
        </div>
      ) : (
        <p className="text-[13px] text-ink-2">Changes take effect immediately{d!.service.running ? "" : " the next time Tailscale runs"}.</p>
      ),
      tone: usingExit || body.shieldsUp === true ? "danger" : "primary",
      confirmLabel: "Apply",
      action: (confirm) => vpnPostGuarded("Tailscale exit node change", "/tailscale/settings", { ...body, confirm }),
      onDone: () => {
        setForm(null);
        refresh();
      },
      success: "Tailscale settings applied",
    });
  }

  const set = <K extends keyof TsSettings>(k: K, val: TsSettings[K]) => setForm({ ...form, [k]: val });
  const noFlag = (f: string) => (unsupported.has(f) ? " (not in this build)" : "");

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <div className="lg:col-span-7 min-w-0 space-y-5">
        <Card className="space-y-5">
          <CardHeader
            title="Tailscale"
            subtitle="Private mesh VPN for reaching this modem remotely"
            icon={<Shield className="h-4 w-4" />}
            action={d.package && <Badge>{`${d.package.name} ${d.package.version}`}</Badge>}
          />
          <div className="qm-subcard p-5 space-y-2">
            <div className="flex items-center gap-2.5">
              <LiveDot tone={v.tone} />
              <span className="qm-display text-[1.9rem] font-semibold leading-none text-ink">{v.title}</span>
            </div>
            <p className="text-[13px] text-ink-2 max-w-prose">{v.body}</p>
          </div>
          {d.warnings.map((w) => (
            <Notice key={w} tone="warn">
              {w}
            </Notice>
          ))}
          {st?.health && st.health.length > 0 && (
            <Notice tone="info" title="Tailscale reports">
              <ul className="list-disc pl-4">
                {st.health.map((h) => (
                  <li key={h}>{h}</li>
                ))}
              </ul>
            </Notice>
          )}
          {me && st?.backendState === "Running" && (
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact label="Tailnet address">
                <span className="flex items-center gap-1.5 font-mono text-[13px]">
                  {me.ips[0] ?? "--"}
                  {me.ips[0] && <CopyButton value={me.ips[0]} />}
                </span>
              </Fact>
              <Fact label="Name">{me.dnsName || me.hostName}</Fact>
              <Fact label="Tailnet">{st.tailnet ?? "--"}</Fact>
              <Fact label="Version">{st.version}</Fact>
            </dl>
          )}
          {st?.authUrl && (
            <a
              href={st.authUrl}
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-between gap-3 rounded-2xl border border-saffron/40 bg-saffron-soft px-4 py-3 text-[13px] font-semibold text-saffron-ink hover:brightness-[0.98]"
            >
              <span className="min-w-0 truncate">Approve this modem: {st.authUrl}</span>
              <ExternalLink className="h-4 w-4 shrink-0" />
            </a>
          )}
          {d.installed && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {d.service.running ? (
                  <Button
                    variant="secondary"
                    disabled={busy !== null}
                    onClick={() =>
                      guard.run({
                        title: "Stop Tailscale?",
                        body: <p className="text-[13px] text-ink-2">Any remote session over the tailnet (including this page, if you are using it that way) is cut.</p>,
                        confirmLabel: "Stop",
                        action: () => vpnPost("/tailscale/service", { action: "stop" }),
                        onDone: () => refresh(),
                        success: "Tailscale stopped",
                      })
                    }
                  >
                    Stop
                  </Button>
                ) : (
                  <Button variant="primary" disabled={busy !== null} onClick={() => act("start", () => vpnPost("/tailscale/service", { action: "start" }), "Tailscale started")}>
                    Start
                  </Button>
                )}
                {st?.backendState === "Running" && (
                  <Button
                    variant="ghost"
                    disabled={busy !== null}
                    onClick={() =>
                      guard.run({
                        title: "Log out of the tailnet?",
                        body: <p className="text-[13px] text-ink-2">Remote access over Tailscale stops until this modem is approved again.</p>,
                        confirmLabel: "Log out",
                        action: (confirm) => vpnPost("/tailscale/logout", { confirm }),
                        onDone: () => refresh(),
                        success: "Logged out",
                      })
                    }
                  >
                    Log out
                  </Button>
                )}
              </div>
              <Switch
                checked={d.service.enabledAtBoot}
                disabled={busy !== null}
                onChange={(on) => act("boot", () => vpnPost("/tailscale/service", { action: on ? "enable" : "disable" }), on ? "Starts at boot" : "Won't start at boot")}
                label="Start at boot"
              />
              {d.service.running && st?.backendState !== "Running" && (
                <div className="space-y-2 border-t border-line pt-4">
                  <div className="text-[13px] font-semibold text-ink">Sign in</div>
                  <p className="text-[12px] text-muted">
                    Leave the key empty to get an approval link, or paste a pre-auth key (tskey-auth-…).{!d.capabilities.oauthKeys && " OAuth client secrets are not supported by this build."}
                  </p>
                  <Input type="password" autoComplete="off" className="font-mono" placeholder="tskey-auth-… (optional)" value={authKey} onChange={(e) => setAuthKey(e.target.value)} />
                  <Button
                    size="sm"
                    variant="tier3"
                    disabled={busy !== null}
                    onClick={() =>
                      act("login", async () => {
                        await vpnPost("/tailscale/login", authKey.trim() ? { authKey: authKey.trim() } : {});
                        setAuthKey("");
                      }, authKey.trim() ? "Signed in with the auth key" : "Approval link requested")
                    }
                  >
                    <LogIn className="h-3.5 w-3.5" />
                    Sign in
                  </Button>
                </div>
              )}
            </div>
          )}
        </Card>

        {d.installed && (
          <Card className="space-y-4">
            <CardHeader title="Settings" subtitle="Applied live with tailscale set; kept across reboots" icon={<Settings2 className="h-4 w-4" />} />
            {unsupported.size > 0 && (
              <Notice tone="info" title="Not available in this Tailscale build">
                {[...unsupported].map((f) => `--${f}`).join(", ")}
              </Notice>
            )}
            <label className="block text-[12.5px] font-semibold text-ink-2">
              Device name{noFlag("hostname")}
              <Input className="mt-1.5" placeholder={me?.hostName ?? "modem-gateway"} value={form.hostname} onChange={(e) => set("hostname", e.target.value)} disabled={unsupported.has("hostname")} />
            </label>
            <label className="block text-[12.5px] font-semibold text-ink-2">
              Share these LAN subnets with the tailnet{noFlag("advertise-routes")}
              <Input className="mt-1.5 font-mono" placeholder={d.lanCidr ?? "192.168.1.0/24"} value={routesText} onChange={(e) => setRoutesText(e.target.value)} disabled={unsupported.has("advertise-routes")} />
            </label>
            {d.lanCidr && !routesText.includes(d.lanCidr) && (
              <Button size="sm" variant="ghost" onClick={() => setRoutesText(routesText.trim() ? `${routesText.trim()}, ${d.lanCidr}` : d.lanCidr!)}>
                Add this modem's LAN ({d.lanCidr})
              </Button>
            )}
            <Switch checked={form.acceptRoutes} onChange={(x) => set("acceptRoutes", x)} disabled={unsupported.has("accept-routes")} label={`Use subnets other devices share${noFlag("accept-routes")}`} />
            <Switch
              checked={form.advertiseExitNode}
              onChange={(x) => set("advertiseExitNode", x)}
              disabled={unsupported.has("advertise-exit-node") || form.exitNode !== ""}
              label={`Offer this modem as an exit node${noFlag("advertise-exit-node")}`}
              description="Tailnet devices that choose it browse over cellular data"
            />
            <label className="block text-[12.5px] font-semibold text-ink-2">
              Send this modem's traffic through{noFlag("exit-node")}
              <Select className="mt-1.5" value={form.exitNode} onChange={(e) => set("exitNode", e.target.value)} disabled={unsupported.has("exit-node") || d.warpLanActive || form.advertiseExitNode}>
                <option value="">No exit node (normal cellular path)</option>
                {form.exitNode && !exitPeers.some((p) => p.hostName === form.exitNode || p.dnsName === form.exitNode || p.ips.includes(form.exitNode)) && (
                  <option value={form.exitNode}>{form.exitNode}</option>
                )}
                {exitPeers.map((p) => (
                  <option key={p.hostName} value={p.ips[0] ?? p.hostName} disabled={!p.online}>
                    {p.hostName}
                    {p.online ? "" : " (offline)"}
                  </option>
                ))}
              </Select>
            </label>
            {d.warpLanActive && <p className="text-[12px] text-muted">Unavailable while WARP routes LAN traffic.</p>}
            <Switch checked={form.ssh} onChange={(x) => set("ssh", x)} disabled={unsupported.has("ssh")} label={`Tailscale SSH${noFlag("ssh")}`} description="SSH into this modem with tailnet identity and ACLs" />
            <Switch checked={form.shieldsUp} onChange={(x) => set("shieldsUp", x)} disabled={unsupported.has("shields-up")} label={`Shields up${noFlag("shields-up")}`} description="Block every incoming tailnet connection to this modem" />
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" disabled={busy !== null} onClick={save}>
                Apply
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setForm(d.settings);
                  setRoutesText(d.settings.advertiseRoutes.join(", "));
                }}
              >
                Reset
              </Button>
            </div>
            <ApplyNote effect="Only the settings you changed are sent to Tailscale." persist="Saved in /etc/config/tailscale and Tailscale's own state; both survive reboots." />
          </Card>
        )}
      </div>

      <div className="lg:col-span-5 min-w-0 space-y-5">
        <Card className="min-w-0">
          <CardHeader title="Peers" subtitle={st ? `${online} of ${peers.length} online` : "Visible while Tailscale is running"} icon={<Laptop className="h-4 w-4" />} />
          {peers.length > 0 ? (
            <ul className="rounded-2xl border border-line divide-y divide-line overflow-hidden">
              {peers.map((p) => (
                <li key={`${p.hostName}-${p.ips[0] ?? ""}`} className="flex items-center gap-3 bg-surface px-4 py-2.5">
                  <span className={cn("h-2 w-2 shrink-0 rounded-full", p.online ? "bg-jade" : "bg-line-strong")} />
                  <div className="min-w-0 flex-1">
                    <div className={cn("truncate text-[13px] font-semibold", p.online ? "text-ink" : "text-muted")}>{p.hostName}</div>
                    <div className="text-[11px] text-muted">
                      {[p.os, p.online ? "" : lastSeen(p.lastSeen)].filter(Boolean).join(" · ")}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="font-mono text-[12px] text-ink-2">{p.ips[0] ?? "--"}</span>
                    {p.exitNode ? <Badge variant="warning">exit node in use</Badge> : p.exitNodeOption ? <Badge variant="neutral">exit node</Badge> : null}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="qm-subcard p-4 text-[13px] text-muted">{d.installed ? "No peers to show." : "Install Tailscale to see your tailnet here."}</div>
          )}
        </Card>

        <PackageCard
          title="Tailscale package"
          queryKey={KEY}
          job={d.job}
          packages={[{ name: "tailscale-tiny", installed: d.package?.name === "tailscale-tiny" ? d.package.version : null, why: "Small static Tailscale build for this modem" }]}
        />
      </div>
      {guard.modal}
    </div>
  );
}
