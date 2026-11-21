import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Cloud, KeyRound, Route as RouteIcon, Settings2 } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { isCancelled } from "../../lib/disruptive";
import { cn, formatBytes } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, LiveDot, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { LoadError, Notice, errText, useGuarded } from "../admin/shared";
import { ApplyNote, BigValue } from "./shared";
import { Fact, PackageCard } from "./VpnParts";
import { VPN, ageText, vpnPost, vpnPostGuarded, type WarpMode, type WarpStatus, type WgcfAccount } from "./vpn-api";

const KEY = ["vpn", "warp"];

const MODES: Array<{ id: WarpMode; title: string; body: string }> = [
  { id: "off", title: "Off", body: "Nothing is sent through Cloudflare, even while the tunnel is up." },
  {
    id: "modem",
    title: "This modem only",
    body: "The modem's own traffic (notifications, updates, time sync) goes through Cloudflare. Forwarded LAN traffic is untouched.",
  },
  {
    id: "lan",
    title: "Everything, including LAN clients",
    body: "Also sends all LAN traffic this modem forwards, including any downstream router's failover traffic, through Cloudflare.",
  },
];

function verdict(d: WarpStatus) {
  const i = d.interface;
  if (!d.account.kind) return { title: "Not set up", body: "Register a free WARP device or enroll this modem in your Zero Trust organization.", tone: "muted" as const };
  if (!i.installed) return { title: "Ready to install", body: "The account is ready. Install the tunnel to create the WireGuard interface.", tone: "saffron" as const };
  if (!i.devicePresent) return { title: "Tunnel off", body: "The WARP interface is installed but down. Traffic uses the normal cellular path.", tone: "muted" as const };
  if (d.policy.mode !== "off" && d.policy.failingBack)
    return { title: "Using cellular", body: "The tunnel is not answering, so traffic fell back to the normal cellular path. It switches back once Cloudflare answers.", tone: "crimson" as const };
  if (i.handshakeAge == null) return { title: "Connecting", body: "Waiting for the first handshake with Cloudflare.", tone: "saffron" as const };
  return {
    title: "Connected",
    body: d.policy.mode === "off" ? "The tunnel is up, but routing is off: nothing is sent through it yet." : "Traffic is going through Cloudflare as configured below.",
    tone: "jade" as const,
  };
}

export function WarpView() {
  const toast = useToastStore((s) => s.push);
  const qc = useQueryClient();
  const guard = useGuarded();
  const q = useQuery({ queryKey: KEY, queryFn: () => apiFetch<WarpStatus>(`${VPN}/warp`), refetchInterval: 10000 });
  const pk = useQuery({
    queryKey: ["vpn", "packages"],
    queryFn: () => apiFetch<{ packages: Array<{ name: string; installed: string | null }>; job: import("./vpn-api").PkgJobView }>(`${VPN}/packages`),
    refetchInterval: (qq) => (qq.state.data?.job?.job?.state === "running" ? 2000 : 30000),
  });
  const [acct, setAcct] = useState<WgcfAccount | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [license, setLicense] = useState("");
  const [team, setTeam] = useState("");
  const [teamToken, setTeamToken] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [useService, setUseService] = useState(false);
  const [mtu, setMtu] = useState<string>("");
  const [keepalive, setKeepalive] = useState<string>("");
  const [endpoint, setEndpoint] = useState<string>("");

  const d = q.data;
  const refresh = () => qc.invalidateQueries({ queryKey: KEY });

  async function act(tag: string, fn: () => Promise<unknown>, okMsg: string) {
    setBusy(tag);
    try {
      await fn();
      toast(okMsg, "success");
      await refresh();
    } catch (e) {
      if (!isCancelled(e)) toast("WARP: " + okMsg.toLowerCase().replace(/\.$/, "") + " failed", "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  if (q.error) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  if (!d) return <Skeleton className="h-64 w-full" />;

  const v = verdict(d);
  const i = d.interface;
  const pkgs = pk.data?.packages ?? [];
  const inst = (n: string) => pkgs.find((p) => p.name === n)?.installed ?? null;
  const replacing = !!d.account.kind;

  const register = () =>
    guard.run({
      title: replacing ? "Replace the WARP registration?" : "Register a WARP device?",
      body: (
        <p className="text-[13px] text-ink-2">
          {replacing
            ? "The current registration's keys are deleted and a new free WARP device is created. A WARP+ license has to be applied again."
            : "Creates a free Cloudflare WARP device for this modem (accepting Cloudflare's terms of service)."}
        </p>
      ),
      tone: "primary",
      confirmLabel: "Register",
      action: (confirm) => vpnPost("/warp/register", { confirm }),
      onDone: () => refresh(),
      success: "WARP device registered",
    });

  const enroll = () =>
    guard.run({
      title: "Enroll in Zero Trust?",
      body: (
        <div className="space-y-2 text-[13px] text-ink-2">
          <p>This modem joins your Cloudflare Zero Trust organization as a WireGuard device.</p>
          <p className="text-[12px] text-muted">
            The device profile that applies to it must use the WireGuard tunnel protocol, not MASQUE. See docs/WARP.md for the limits of this method.
          </p>
        </div>
      ),
      tone: "primary",
      confirmLabel: "Enroll",
      action: (confirm) =>
        vpnPost("/warp/teams", useService ? { team, clientId, clientSecret, confirm } : { team, teamToken, confirm }),
      onDone: () => {
        setTeamToken("");
        setClientSecret("");
        refresh();
      },
      success: "Enrolled in Zero Trust",
    });

  const setMode = (mode: WarpMode) =>
    guard.run({
      title: mode === "lan" ? "Send forwarded LAN traffic through Cloudflare?" : mode === "modem" ? "Route this modem's traffic through WARP?" : "Stop routing through WARP?",
      body:
        mode === "lan" ? (
          <div className="space-y-2 text-[13px] text-ink-2">
            <p>All traffic forwarded from LAN clients and any downstream router will leave through Cloudflare.</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>Latency goes up by the detour through Cloudflare.</li>
              <li>Websites see a Cloudflare IP, not the carrier's. Geolocation and some logins change.</li>
              <li>The carrier's CGNAT and QoS see one tunnel instead of individual flows; inbound port forwards stop working for that traffic.</li>
              <li>If the tunnel stops answering, traffic returns to the normal cellular path within about 3 minutes.</li>
            </ul>
            {d.failoverActive && <Notice tone="warn" title="Upstream failover is active through this modem right now">Its traffic switches path the moment you confirm.</Notice>}
          </div>
        ) : (
          <p className="text-[13px] text-ink-2">
            {mode === "modem"
              ? "The modem's own connections go through Cloudflare. Forwarded LAN traffic stays on the normal cellular path. Health checks keep measuring the cellular link."
              : "Routing rules are removed. The tunnel may stay up but nothing is sent through it."}
          </p>
        ),
      tone: mode === "lan" ? "danger" : "primary",
      confirmLabel: "Apply",
      action: (confirm) => vpnPostGuarded("WARP routing change", "/warp/policy", { mode, confirm }, ),
      onDone: () => refresh(),
      success: "Routing updated",
    });

  const remove = () =>
    guard.run({
      title: "Remove WARP?",
      body: <p className="text-[13px] text-ink-2">Removes the WARP interface, its firewall zone and the routing rules. Traffic goes back to the plain cellular path. The account is kept so you can reinstall.</p>,
      confirmLabel: "Remove",
      action: (confirm) => vpnPostGuarded("WARP removal", "/warp/remove", { confirm }),
      onDone: () => refresh(),
      success: "WARP removed",
    });

  const install = () =>
    act(
      "install",
      () =>
        vpnPost("/warp/install", {
          ...(mtu ? { mtu: Number(mtu) } : {}),
          ...(keepalive ? { keepalive: Number(keepalive) } : {}),
          ...(endpoint !== "" ? { endpoint } : {}),
        }),
      i.installed ? "Tunnel settings applied" : "WARP tunnel installed"
    );

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <div className="lg:col-span-7 min-w-0 space-y-5">
        <Card className="space-y-5">
          <CardHeader
            title="Cloudflare WARP"
            subtitle="Encrypted tunnel to Cloudflare over the cellular link"
            icon={<Cloud className="h-4 w-4" />}
            action={
              <Badge variant={d.account.kind === "teams" ? "plum" : d.account.kind ? "info" : "neutral"}>
                {d.account.kind === "teams" ? "Zero Trust" : d.account.kind ? (d.account.consumer?.licenseSet ? "WARP+" : "WARP") : "No account"}
              </Badge>
            }
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
          {i.installed && (
            <dl className="grid gap-3 grid-cols-2 sm:grid-cols-4">
              <Fact label="Last handshake">{ageText(i.handshakeAge)}</Fact>
              <Fact label="Received">{formatBytes(i.rxBytes ?? 0)}</Fact>
              <Fact label="Sent">{formatBytes(i.txBytes ?? 0)}</Fact>
              <Fact label="Endpoint">
                <span className="font-mono text-[12px] break-all">{i.endpoint ?? "--"}</span>
              </Fact>
            </dl>
          )}
          {i.installed && (
            <div className="flex flex-wrap gap-2">
              {i.devicePresent ? (
                <Button variant="secondary" disabled={busy !== null} onClick={() => act("down", () => vpnPostGuarded("WARP tunnel down", "/warp/connection", { action: "down" }), "Tunnel stopped")}>
                  Stop tunnel
                </Button>
              ) : (
                <Button variant="primary" disabled={busy !== null} onClick={() => act("up", () => vpnPostGuarded("WARP tunnel up", "/warp/connection", { action: "up" }), "Tunnel starting")}>
                  Start tunnel
                </Button>
              )}
            </div>
          )}
        </Card>

        <Card className="space-y-4">
          <CardHeader title="What goes through WARP" subtitle="The cellular path stays the fallback" icon={<RouteIcon className="h-4 w-4" />} />
          <div className="grid gap-2.5">
            {MODES.map((m) => {
              const on = d.policy.mode === m.id;
              return (
                <button
                  key={m.id}
                  type="button"
                  disabled={busy !== null || on || (!i.installed && m.id !== "off")}
                  onClick={() => setMode(m.id)}
                  className={cn(
                    "rounded-2xl border p-4 text-left transition disabled:cursor-default min-h-[44px]",
                    on ? "border-ember bg-ember-soft" : "border-line bg-surface hover:border-line-strong disabled:opacity-60"
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className={cn("text-[14px] font-semibold", on ? "text-ember-ink" : "text-ink")}>{m.title}</span>
                    {on && <Badge variant="info">Active</Badge>}
                  </div>
                  <p className="mt-1 text-[12.5px] text-ink-2">{m.body}</p>
                </button>
              );
            })}
          </div>
          {d.policy.mode !== "off" && (
            <p className="text-[12px] text-muted">
              {d.policy.routeInstalled ? "Steering route installed." : "Steering route withdrawn (fail-back)."} {d.policy.rules.length} rules at priority {d.policy.pref}, table {d.policy.table}.
              {d.policy.failbacks > 0 && ` Fell back ${d.policy.failbacks}× since the daemon started.`}
            </p>
          )}
          <ApplyNote
            effect="Changes the modem's routing rules at once. If the tunnel stops answering for 3 minutes, traffic returns to the cellular path by itself."
            persist="Kept across reboots; restored when the daemon starts."
          />
        </Card>
      </div>

      <div className="lg:col-span-5 min-w-0 space-y-5">
        <Card className="space-y-4">
          <CardHeader title="Account" subtitle="Keys and tokens are never shown again" icon={<KeyRound className="h-4 w-4" />} />
          {d.account.kind === "consumer" && d.account.consumer && (
            <dl className="grid gap-3 grid-cols-2">
              <Fact label="Plan">{d.account.consumer.licenseSet ? "WARP+" : "Free"}</Fact>
              <Fact label="Device">
                <span className="font-mono text-[11.5px]">{d.account.consumer.deviceId.slice(0, 8)}…</span>
              </Fact>
            </dl>
          )}
          {d.account.kind === "teams" && d.account.teams && (
            <dl className="grid gap-3 grid-cols-2">
              <Fact label="Team">{d.account.teams.team}</Fact>
              <Fact label="Tunnel address">
                <span className="font-mono text-[12px] break-all">{d.account.teams.addressV4}</span>
              </Fact>
            </dl>
          )}
          {d.account.kind === "consumer" && (
            <>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy !== null}
                onClick={() =>
                  act("acct", async () => setAcct(await apiFetch<WgcfAccount>(`${VPN}/warp/account`)), "Account details loaded")
                }
              >
                Show quota and devices
              </Button>
              {acct?.status && (
                <div className="space-y-2">
                  <div className="flex items-baseline gap-2">
                    <BigValue value={acct.status.quota} className="text-[1.4rem]" />
                    <span className="text-[12px] text-muted">{acct.status.accountType} · WARP+ quota</span>
                  </div>
                  <ul className="divide-y divide-line rounded-xl border border-line">
                    {acct.status.devices.map((dv) => (
                      <li key={dv.id} className="flex items-center justify-between gap-2 px-3 py-2 text-[12.5px]">
                        <span className="min-w-0 truncate text-ink">
                          {dv.name} <span className="text-muted">· {dv.model}</span>
                        </span>
                        <span className="flex shrink-0 gap-1">
                          {dv.current && <Badge variant="info">this modem</Badge>}
                          <Badge variant={dv.active ? "success" : "neutral"}>{dv.active ? "active" : "inactive"}</Badge>
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="space-y-2">
                <label className="block text-[12.5px] font-semibold text-ink-2">
                  WARP+ license key
                  <Input
                    type="password"
                    autoComplete="off"
                    className="mt-1.5 font-mono"
                    placeholder="xxxxxxxx-xxxxxxxx-xxxxxxxx"
                    value={license}
                    onChange={(e) => setLicense(e.target.value)}
                  />
                </label>
                <Button
                  size="sm"
                  variant="tier3"
                  disabled={busy !== null || license.trim().length < 26}
                  onClick={() =>
                    act("lic", async () => {
                      await vpnPost("/warp/license", { licenseKey: license.trim() });
                      setLicense("");
                    }, "WARP+ license applied")
                  }
                >
                  Apply license
                </Button>
              </div>
            </>
          )}

          <div className="space-y-2 border-t border-line pt-4">
            <div className="text-[13px] font-semibold text-ink">{replacing ? "Replace with…" : "Set up"}</div>
            {!d.tools.wgcf && <p className="text-[12px] text-muted">Install wgcf below for a free or WARP+ device.</p>}
            <Button size="sm" variant={replacing ? "secondary" : "primary"} disabled={busy !== null || !d.tools.wgcf} onClick={register}>
              Free / WARP+ device
            </Button>
          </div>

          <div className="space-y-2.5 border-t border-line pt-4">
            <div className="text-[13px] font-semibold text-ink">Zero Trust organization</div>
            <label className="block text-[12.5px] font-semibold text-ink-2">
              Team name
              <Input className="mt-1.5" placeholder="your-team" value={team} onChange={(e) => setTeam(e.target.value)} autoComplete="off" />
            </label>
            <Switch checked={useService} onChange={setUseService} label="Use a service token" description="Headless enrollment with an Access service token instead of a browser login" />
            {useService ? (
              <>
                <Input placeholder="Client ID (….access)" value={clientId} onChange={(e) => setClientId(e.target.value)} autoComplete="off" className="font-mono" />
                <Input type="password" placeholder="Client Secret" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} autoComplete="off" className="font-mono" />
              </>
            ) : (
              <>
                <p className="text-[12px] text-muted break-words">
                  Sign in at <span className="font-mono break-all">https://{team || "<team>"}.cloudflareaccess.com/warp</span>, then paste the{" "}
                  <span className="font-mono break-all">com.cloudflare.warp://…</span> link from the success page's source.
                </p>
                <Input type="password" placeholder="com.cloudflare.warp://…?token=…" value={teamToken} onChange={(e) => setTeamToken(e.target.value)} autoComplete="off" className="font-mono" />
              </>
            )}
            <Button
              size="sm"
              variant="tier3"
              disabled={busy !== null || !team.trim() || (useService ? !clientId || !clientSecret : !teamToken) || !d.tools.wg}
              onClick={enroll}
            >
              Enroll
            </Button>
            {!d.tools.wg && <p className="text-[12px] text-muted">Needs wireguard-tools (install below).</p>}
          </div>
        </Card>

        {d.account.kind && (
          <Card className="space-y-4">
            <CardHeader title="Tunnel" subtitle="Native OpenWrt WireGuard interface" icon={<Settings2 className="h-4 w-4" />} />
            <div className="grid gap-3 grid-cols-2">
              <label className="block text-[12.5px] font-semibold text-ink-2">
                MTU
                <Input className="mt-1.5" inputMode="numeric" placeholder={String(i.mtu)} value={mtu} onChange={(e) => setMtu(e.target.value.replace(/\D/g, ""))} />
              </label>
              <label className="block text-[12.5px] font-semibold text-ink-2">
                Keepalive (s)
                <Input className="mt-1.5" inputMode="numeric" placeholder={String(i.keepalive)} value={keepalive} onChange={(e) => setKeepalive(e.target.value.replace(/\D/g, ""))} />
              </label>
            </div>
            <label className="block text-[12.5px] font-semibold text-ink-2">
              Endpoint override <span className="font-normal text-muted">(empty = from the account)</span>
              <Input className="mt-1.5 font-mono" placeholder={i.endpointOverride ?? "engage.cloudflareclient.com:2408"} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} />
            </label>
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" disabled={busy !== null} onClick={install}>
                {i.installed ? "Apply" : "Install tunnel"}
              </Button>
              {i.installed && (
                <Button variant="danger" disabled={busy !== null} onClick={remove}>
                  Remove
                </Button>
              )}
            </div>
            <ApplyNote
              effect="Writes the warp interface and an outbound-only firewall zone, then reloads network and firewall. The cellular WAN is not touched."
              persist="Kept across reboots; the tunnel starts at boot."
            />
          </Card>
        )}

        <PackageCard
          title="WARP packages"
          queryKey={["vpn", "packages"]}
          job={pk.data?.job}
          packages={[
            { name: "wgcf", installed: inst("wgcf"), why: "Registers free / WARP+ devices" },
            { name: "wireguard-tools", installed: inst("wireguard-tools"), why: "Tunnel statistics and Zero Trust keys" },
          ]}
        />
      </div>
      {guard.modal}
    </div>
  );
}
