import { useMemo, useState } from "react";
import { ArrowRightLeft, Check, EthernetPort, Laptop, Network } from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, CopyButton, Input, LiveDot, Modal, Select, Skeleton } from "../../components/ui";
import { FailoverWarning } from "../../components/obs";
import { ApplyNote, BigValue, FieldLabel, netmaskBits, netmaskDotted, netmaskSummary, type NetMutator, type NetworkLanResponse } from "./shared";

const USBNET_MAP: Record<string, string> = {
  "0": "RMNET / QMI (0)",
  "1": "ECM (1)",
  "2": "MBIM (2)",
  "3": "RNDIS (3)",
  "5": "NCM (5)",
};

const ETH_LIMITS: Array<{ id: string; label: string; hint: string }> = [
  { id: "auto", label: "Automatic", hint: "Fastest both ends support" },
  { id: "1000", label: "1 Gb/s", hint: "Cap at gigabit" },
  { id: "100", label: "100 Mb/s", hint: "For fussy or long cables" },
  { id: "10", label: "10 Mb/s", hint: "Legacy devices only" },
];

function ipToInt(ip: string | undefined): number | null {
  if (!ip) return null;
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

/** "2500Mb/s" → ["2.5", "Gb/s"]; non-positive speeds mean no cable / no link. */
function parseSpeed(raw: string | undefined): { value: string; unit: string; up: boolean } {
  const n = Number((raw ?? "").replace(/[^0-9.-]/g, ""));
  if (!raw || !Number.isFinite(n) || n <= 0) return { value: "No link", unit: "", up: false };
  if (n >= 1000) return { value: String(Math.round((n / 1000) * 10) / 10), unit: "Gb/s", up: true };
  return { value: String(n), unit: "Mb/s", up: true };
}

function modeLabel(r: { mode: string; mac: string }): string {
  return r.mode === "1"
    ? "ETH Passthrough"
    : r.mode === "2"
      ? "USB-RNDIS Passthrough"
      : r.mac
        ? `Mode ${r.mode}`
        : "Inactive";
}

export function LanView({ d, loading, net }: { d: NetworkLanResponse | undefined; loading: boolean; net: NetMutator }) {
  const { busy, mutate } = net;
  const [mpdnSlot, setMpdnSlot] = useState("0");
  const [mpdnMode, setMpdnMode] = useState("1");
  const [mpdnMac, setMpdnMac] = useState("");
  const [pendingEth, setPendingEth] = useState<(typeof ETH_LIMITS)[number] | null>(null);

  const usbnetCodeMatch = (d?.usbnetRaw ?? "").match(/,\s*(\d)/);
  const usbnetLabel = (usbnetCodeMatch && USBNET_MAP[usbnetCodeMatch[1]]) || "RMNET / IPA";

  const rules = d?.mpdnRules ?? [];
  const clients = d?.arpClients ?? [];
  const activeRules = rules.filter((r) => r.mode !== "0");
  const nameForMac = (mac: string) => {
    const c = clients.find((x) => x.mac.toLowerCase() === mac.toLowerCase());
    return c ? (c.hostname !== "*" ? c.hostname : c.ip) : null;
  };

  const speed = parseSpeed(d?.ethLink?.actualSpeed);
  const limit = d?.ethLink?.currentLimit ?? "auto";

  // Where the DHCP pool and the gateway sit inside the subnet, for the range strip.
  const pool = useMemo(() => {
    const lan = d?.lanIp;
    const bits = netmaskBits(lan?.netmask);
    const gw = ipToInt(lan?.gatewayIp);
    const s = ipToInt(lan?.poolStart);
    const e = ipToInt(lan?.poolEnd);
    if (bits == null || gw == null || s == null || e == null || bits < 8) return null;
    const size = 2 ** (32 - bits);
    const base = Math.floor(gw / size) * size;
    const pct = (v: number) => Math.max(0, Math.min(100, ((v - base) / (size - 1)) * 100));
    return { from: pct(s), to: pct(e), gw: pct(gw), count: e - s + 1 };
  }, [d?.lanIp]);

  const passOn = mpdnMode === "1";

  return (
    <div className="space-y-6">
      <div className="grid gap-5 lg:grid-cols-12">
        {/* LAN identity: the answer to "what network are my devices on?" */}
        <Card className="lg:col-span-7 min-w-0 space-y-5">
          <CardHeader
            title="Local network"
            subtitle="What devices plugged into the gateway see"
            icon={<Network className="h-4 w-4" />}
            action={<Badge variant="plum">USB mode · {usbnetLabel}</Badge>}
           
          />
          {d?.lanIp ? (
            <>
              <div>
                <div className="text-[12px] font-semibold text-muted">Gateway address</div>
                <div className="mt-1 flex items-center gap-2 min-w-0">
                  <BigValue value={d.lanIp.gatewayIp || "--"} className="text-[2rem] sm:text-[2.6rem] break-all" />
                  {d.lanIp.gatewayIp && <CopyButton value={d.lanIp.gatewayIp} label="Copy" />}
                </div>
              </div>

              {pool && (
                <div className="space-y-2">
                  <div className="relative h-3 rounded-full bg-sunk border border-line overflow-hidden">
                    <div
                      className="absolute inset-y-0 bg-ember/70 rounded-full"
                      style={{ left: `${pool.from}%`, width: `${Math.max(1.5, pool.to - pool.from)}%` }}
                    />
                    <div
                      className="absolute inset-y-0 z-10 w-1 bg-ink rounded-full"
                      style={{ left: `clamp(2px, calc(${pool.gw}% - 2px), calc(100% - 6px))` }}
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-muted">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-ink" /> Gateway
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-ember/70" /> Handed out by DHCP ({pool.count.toLocaleString()})
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full border border-line-strong bg-sunk" /> Free for static use
                    </span>
                  </div>
                </div>
              )}

              <dl className="grid gap-3 sm:grid-cols-2">
                <div className="qm-subcard p-3.5 min-w-0">
                  <dt className="text-[12px] font-semibold text-muted">
                    Addresses handed out <span className="font-mono font-medium">· DHCP pool</span>
                  </dt>
                  <dd className="mt-1.5 font-mono text-[13px] text-ink break-all">
                    {d.lanIp.poolStart && d.lanIp.poolEnd ? `${d.lanIp.poolStart} → ${d.lanIp.poolEnd}` : "Disabled"}
                  </dd>
                </div>
                <div className="qm-subcard p-3.5 min-w-0">
                  <dt className="text-[12px] font-semibold text-muted">
                    Network size <span className="font-mono font-medium">· netmask</span>
                  </dt>
                  <dd className="mt-1.5 text-[13px] text-ink">
                    {netmaskSummary(d.lanIp.netmask)}
                    <span className="ml-2 font-mono text-[12px] text-muted">{netmaskDotted(d.lanIp.netmask)}</span>
                  </dd>
                </div>
              </dl>
            </>
          ) : loading ? (
            <div className="space-y-3">
              <Skeleton className="h-12 w-2/3" />
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : (
            <div className="qm-subcard p-4 text-[13px] text-muted">The modem didn't report its LAN bridge settings.</div>
          )}
        </Card>

        {/* Ethernet PHY: current link first, then the cap. */}
        <Card className="lg:col-span-5 min-w-0 space-y-4">
          <CardHeader
            title="Ethernet port"
            subtitle="Physical link to the LAN cable"
            icon={<EthernetPort className="h-4 w-4" />}
           
          />
          <div className="flex items-end justify-between gap-3">
            <div>
              <div className="text-[12px] font-semibold text-muted">Negotiated speed</div>
              <div className="mt-1 flex items-center gap-2.5">
                {speed.up && <LiveDot tone="jade" />}
                <BigValue value={speed.value} unit={speed.unit} className={cn("text-[2.4rem]", !speed.up && "text-muted text-[1.8rem]")} />
              </div>
            </div>
            <Badge variant={limit === "auto" ? "neutral" : "warning"}>
              {limit === "auto" ? "No cap" : `Capped at ${limit}M`}
            </Badge>
          </div>

          <div>
            <div className="mb-2 flex items-baseline justify-between gap-2 text-[12.5px] font-semibold text-ink-2">
              <span>Speed cap</span>
              <span className="font-mono text-[11px] font-medium text-muted">ethtool advertise</span>
            </div>
            <div role="radiogroup" aria-label="Ethernet speed cap" className="grid grid-cols-2 gap-2">
              {ETH_LIMITS.map((opt) => {
                const active = limit === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    disabled={busy === "eth"}
                    onClick={() => {
                      if (!active) setPendingEth(opt);
                    }}
                    className={cn(
                      "min-h-[3.4rem] rounded-2xl border px-3 py-2 text-left transition cursor-pointer disabled:opacity-50 disabled:cursor-wait",
                      active
                        ? "border-ember bg-ember-soft"
                        : "border-line bg-raised hover:border-line-strong hover:bg-sunk"
                    )}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className={cn("text-[13px] font-semibold", active ? "text-ember-ink" : "text-ink")}>{opt.label}</span>
                      {active && <Check className="h-3.5 w-3.5 text-ember-ink" />}
                    </div>
                    <div className="text-[11px] text-muted leading-snug">{opt.hint}</div>
                  </button>
                );
              })}
            </div>
          </div>
          <ApplyNote
            effect="Takes effect on tap: the port renegotiates, so wired devices drop for a few seconds."
            persist="Saved to the gateway config; kept after reboot."
          />
        </Card>
      </div>

      {/* IP passthrough: rules in force first, then the editor. */}
      <Card className="space-y-5">
        <CardHeader
          title="IP passthrough"
          subtitle="Hand the cellular public IP straight to one device, bypassing the gateway's NAT"
          icon={<ArrowRightLeft className="h-4 w-4" />}
          action={
            activeRules.length > 0 ? (
              <Badge variant="success" dot>
                On · {activeRules.length} rule{activeRules.length > 1 ? "s" : ""}
              </Badge>
            ) : (
              <Badge variant="neutral">Off</Badge>
            )
          }
         
        />

        <div className="grid gap-5 lg:grid-cols-12">
          <div className="lg:col-span-6 min-w-0 space-y-2">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-[12.5px] font-semibold text-ink-2">Rules in the modem</span>
              <span className="font-mono text-[11px] text-muted">AT+QMAP="MPDN_RULE"</span>
            </div>
            {rules.length > 0 ? (
              <ul className="rounded-2xl border border-line divide-y divide-line overflow-hidden">
                {rules.map((r) => {
                  const on = r.mode !== "0";
                  const name = r.mac ? nameForMac(r.mac) : null;
                  return (
                    <li key={`${r.slot}-${r.apnSlot}`} className={cn("flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5", on ? "bg-jade-soft" : "bg-surface")}>
                      <span className="w-14 shrink-0 text-[12.5px] font-semibold text-ink">Slot {r.slot}</span>
                      <Badge variant={on ? "success" : "neutral"}>{modeLabel(r)}</Badge>
                      <span className="text-[11.5px] text-muted qm-tabular">APN #{r.apnSlot}</span>
                      <span className="ml-auto flex min-w-0 items-center gap-1.5">
                        {name && <span className="truncate text-[12.5px] font-semibold text-ink">{name}</span>}
                        <span className={cn("font-mono text-[12px]", r.mac ? "text-ink-2" : "text-muted")}>{r.mac || "No device"}</span>
                        {r.mac && <CopyButton value={r.mac}/>}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <div className="qm-subcard p-4 text-[13px] text-muted">No MPDN rules returned.</div>
            )}
          </div>

          <div className="lg:col-span-6 min-w-0 qm-subcard p-4 sm:p-5 space-y-4">
            <div className="text-[14px] font-semibold text-ink">Change a rule</div>

            <div>
              <div className="mb-1.5 flex items-baseline justify-between gap-2 text-[12.5px] font-semibold text-ink-2">
                <span>Pick a device on the LAN</span>
                <span className="font-mono text-[11px] font-medium text-muted">ARP table</span>
              </div>
              {clients.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {clients.map((c) => {
                    const on = mpdnMac.toLowerCase() === c.mac.toLowerCase();
                    return (
                      <button
                        key={`${c.ip}-${c.mac}`}
                        type="button"
                        onClick={() => setMpdnMac(c.mac)}
                        className={cn(
                          "inline-flex min-h-9 items-center gap-2 rounded-full border px-3 py-1 text-left transition cursor-pointer",
                          on ? "border-ember bg-ember-soft text-ember-ink" : "border-line bg-raised text-ink-2 hover:border-line-strong"
                        )}
                      >
                        <Laptop className="h-3.5 w-3.5 shrink-0" />
                        <span className="text-[12px] font-semibold">{c.hostname !== "*" ? c.hostname : c.ip}</span>
                        <span className="font-mono text-[11px] opacity-80">{c.mac}</span>
                      </button>
                    );
                  })}
                </div>
              ) : (
                <div className="text-[12px] text-muted">No devices seen yet. Type a MAC address below.</div>
              )}
            </div>

            <div>
              <FieldLabel htmlFor="mpdn-mac" term="MAC">Device hardware address</FieldLabel>
              <Input id="mpdn-mac" value={mpdnMac} onChange={(e) => setMpdnMac(e.target.value)} placeholder="aa:bb:cc:dd:ee:ff" className="font-mono" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel htmlFor="mpdn-slot" term="rule slot">Slot</FieldLabel>
                <Select id="mpdn-slot" value={mpdnSlot} onChange={(e) => setMpdnSlot(e.target.value)}>
                  <option value="0">Slot 0</option>
                  <option value="1">Slot 1</option>
                </Select>
              </div>
              <div>
                <FieldLabel htmlFor="mpdn-mode" term="mode">Passthrough</FieldLabel>
                <Select id="mpdn-mode" value={mpdnMode} onChange={(e) => setMpdnMode(e.target.value)}>
                  <option value="1">ETH Passthrough (1)</option>
                  <option value="0">Disable Passthrough (0)</option>
                </Select>
              </div>
            </div>

            <Button
              variant={passOn ? "primary" : "secondary"}
              className="w-full sm:w-auto"
              disabled={busy === "mpdn"}
              onClick={() =>
                mutate(
                  "mpdn",
                  {
                    action: "mpdn_rule",
                    slot: Number(mpdnSlot),
                    mode: Number(mpdnMode),
                    mac: mpdnMac.trim() || undefined,
                  },
                  `Updated MPDN rule slot ${mpdnSlot}`
                )
              }
            >
              {passOn ? `Pass the public IP through on slot ${mpdnSlot}` : `Turn off passthrough on slot ${mpdnSlot}`}
            </Button>
          </div>
        </div>

        <ApplyNote
          effect="Written to the modem on Apply. The chosen device gets the carrier IP on its next DHCP renewal; others keep using the LAN."
          persist="Stored in the modem's own config; survives reboots until you turn it off."
        />
      </Card>
      {/* Renegotiating the port drops every wired device: confirm first (DESIGN.md). */}
      <Modal open={pendingEth != null} onClose={() => setPendingEth(null)} title="Change the Ethernet speed?">
        <div className="space-y-4">
          <FailoverWarning action="Renegotiating the Ethernet port" />
          <p>
            The Ethernet port renegotiates at {pendingEth?.label ?? ""}. The wired link (and everything behind it, including the router using this
            modem) drops for a few seconds and then reconnects.
          </p>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button variant="secondary" onClick={() => setPendingEth(null)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={busy === "eth"}
              onClick={() => {
                const opt = pendingEth;
                setPendingEth(null);
                if (opt) void mutate("eth", { action: "eth_limit", limit: opt.id }, `Ethernet limit set to ${opt.id}`);
              }}
            >
              Change speed
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
