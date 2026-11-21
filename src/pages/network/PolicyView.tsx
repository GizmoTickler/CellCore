import { useDraft } from "../../lib/draft";
import { Globe, Ruler, Timer } from "lucide-react";
import { Badge, Button, Card, CardHeader, Input } from "../../components/ui";
import { ApplyNote, BigValue, FieldLabel, PresetChip, type NetMutator, type NetworkLanResponse } from "./shared";

const TTL_PRESETS = [64, 65, 128];
const MTU_PRESETS = [1500, 1460, 1420, 1280];
const DNS_PRESETS: Array<{ label: string; servers: [string, string] }> = [
  { label: "Cloudflare", servers: ["1.1.1.1", "1.0.0.1"] },
  { label: "Google", servers: ["8.8.8.8", "8.8.4.4"] },
  { label: "Quad9", servers: ["9.9.9.9", "149.112.112.112"] },
];

function dnsFromOption(opt: string | undefined): string[] {
  if (!opt) return [];
  return opt
    .split(/[\s,]+/)
    .filter((t) => /^\d{1,3}(\.\d{1,3}){3}$/.test(t));
}

export function PolicyView({ d, net }: { d: NetworkLanResponse | undefined; net: NetMutator }) {
  const { busy, mutate } = net;
  // Drafts: polling (and the first load) never overwrite a field the user is editing.
  const [ttlVal, setTtlVal, ttlD] = useDraft(d?.ttl?.ttl ? String(d.ttl.ttl) : null, "65");
  const [hlVal, setHlVal, hlD] = useDraft(d?.ttl?.hl ? String(d.ttl.hl) : null, "65");
  const [mtuVal, setMtuVal, mtuD] = useDraft(d?.mtu?.value ? String(d.mtu.value) : null, "1500");
  const [dns1, setDns1, dns1D] = useDraft(d?.dns?.custom?.[0] || null, "1.1.1.1");
  const [dns2, setDns2, dns2D] = useDraft(d?.dns?.custom?.[1] || null, "8.8.8.8");
  const apply = async (tag: string, payload: Record<string, unknown>, msg: string, drafts: Array<{ reset: () => void }>) => {
    if (await mutate(tag, payload, msg)) drafts.forEach((x) => x.reset());
  };

  const ttlOn = !!d?.ttl?.enabled;
  const mtuCustom = !!d?.mtu?.enabled;
  const liveDns = dnsFromOption(d?.dns?.uciOption);
  const dnsCustom = !!d?.dns?.uciOption;

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      {/* TTL / hop limit */}
      <Card className="lg:col-span-7 min-w-0 space-y-5">
        <CardHeader
          title="Outgoing hop count"
          subtitle="Rewrites the TTL on everything leaving over cellular, so LAN traffic looks like it came from the gateway itself"
          icon={<Timer className="h-4 w-4" />}
          action={
            ttlOn ? (
              <Badge variant="success" dot>
                Override on
              </Badge>
            ) : (
              <Badge variant="neutral">Off</Badge>
            )
          }
         
        />

        <div className="grid grid-cols-2 gap-3">
          <div className="qm-subcard p-4">
            <div className="text-[12px] font-semibold text-muted">
              IPv4 <span className="font-mono font-medium">· TTL</span>
            </div>
            <BigValue value={ttlOn ? d?.ttl?.ttl ?? "--" : "As sent"} className={ttlOn ? "mt-2 text-[2.4rem]" : "mt-3 text-[1.35rem] text-muted"} />
          </div>
          <div className="qm-subcard p-4">
            <div className="text-[12px] font-semibold text-muted">
              IPv6 <span className="font-mono font-medium">· hop limit</span>
            </div>
            <BigValue value={ttlOn ? d?.ttl?.hl ?? "--" : "As sent"} className={ttlOn ? "mt-2 text-[2.4rem]" : "mt-3 text-[1.35rem] text-muted"} />
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[12px] text-muted">Quick fill</span>
            {TTL_PRESETS.map((v) => (
              <PresetChip
                key={v}
                active={ttlVal === String(v) && hlVal === String(v)}
                onClick={() => {
                  setTtlVal(String(v));
                  setHlVal(String(v));
                }}
              >
                {v}
              </PresetChip>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel htmlFor="ttl-v4" term="1–255">IPv4 TTL</FieldLabel>
              <Input id="ttl-v4" type="number" min={1} max={255} value={ttlVal} onChange={(e) => setTtlVal(e.target.value)} className="qm-tabular" />
            </div>
            <div>
              <FieldLabel htmlFor="ttl-v6" term="1–255">IPv6 hop limit</FieldLabel>
              <Input id="ttl-v6" type="number" min={1} max={255} value={hlVal} onChange={(e) => setHlVal(e.target.value)} className="qm-tabular" />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              disabled={busy === "ttl"}
              onClick={() =>
                apply(
                  "ttl",
                  { action: "ttl", enabled: true, ttl: Number(ttlVal) || 65, hl: Number(hlVal) || 65 },
                  "Applied TTL / Hop Limit override",
                  [ttlD, hlD]
                )
              }
            >
              {ttlOn ? "Update override" : "Turn on override"}
            </Button>
            <Button
              variant="ghost"
              disabled={busy === "ttl"}
              onClick={() => apply("ttl", { action: "ttl", enabled: false, ttl: 0, hl: 0 }, "Disabled TTL override", [ttlD, hlD])}
            >
              Turn off
            </Button>
          </div>
        </div>

        <ApplyNote
          effect="Applies instantly to the cellular interfaces (mangle rule on rmnet+). Open connections aren't interrupted."
          persist="Saved as a firewall include, so it comes back after reboot."
        />
      </Card>

      {/* MTU */}
      <Card className="lg:col-span-5 min-w-0 space-y-5">
        <CardHeader
          title="Largest packet size"
          subtitle="Lower it if some sites stall or VPNs misbehave"
          icon={<Ruler className="h-4 w-4" />}
          action={<Badge variant={mtuCustom ? "warning" : "neutral"}>{mtuCustom ? "Custom" : "Default"}</Badge>}
         
        />
        <div className="qm-subcard p-4">
          <div className="text-[12px] font-semibold text-muted">
            Cellular interface <span className="font-mono font-medium">· MTU</span>
          </div>
          <BigValue value={d?.mtu?.value ?? 1500} unit="bytes" className="mt-2 text-[2.4rem]" />
        </div>

        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {MTU_PRESETS.map((v) => (
              <PresetChip key={v} active={mtuVal === String(v)} onClick={() => setMtuVal(String(v))}>
                {v}
              </PresetChip>
            ))}
          </div>
          <div>
            <FieldLabel htmlFor="mtu" term="1280–1500">New size</FieldLabel>
            <Input id="mtu" type="number" min={1280} max={1500} value={mtuVal} onChange={(e) => setMtuVal(e.target.value)} className="qm-tabular" />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              disabled={busy === "mtu"}
              onClick={() => apply("mtu", { action: "mtu", enabled: true, mtu: Number(mtuVal) || 1420 }, `Set MTU to ${mtuVal}`, [mtuD])}
            >
              Set to {mtuVal || "…"}
            </Button>
            <Button
              variant="ghost"
              disabled={busy === "mtu"}
              onClick={() => apply("mtu", { action: "mtu", enabled: false, mtu: 1500 }, "Reset MTU to 1500", [mtuD])}
            >
              Reset to 1500
            </Button>
          </div>
        </div>

        <ApplyNote
          effect="Changes every rmnet data interface immediately."
          persist="A custom size is saved and re-applied at boot; Reset removes it."
        />
      </Card>

      {/* LAN DNS */}
      <Card className="lg:col-span-12 min-w-0 space-y-5">
        <CardHeader
          title="DNS for LAN devices"
          subtitle="Which resolvers the gateway tells DHCP clients to use"
          icon={<Globe className="h-4 w-4" />}
          action={
            <Badge variant={dnsCustom ? "success" : "neutral"} dot={dnsCustom}>
              {dnsCustom ? "Custom DNS" : "Carrier Auto"}
            </Badge>
          }
         
        />

        <div className="grid gap-5 lg:grid-cols-12">
          <div className="lg:col-span-5 min-w-0 space-y-3">
            <div className="text-[12px] font-semibold text-muted">
              Handing out now <span className="font-mono font-medium">· DHCP option 6</span>
            </div>
            {dnsCustom ? (
              <ol className="space-y-2">
                {(liveDns.length ? liveDns : [d?.dns?.uciOption ?? ""]).map((s, i) => (
                  <li key={`${s}-${i}`} className="qm-subcard flex items-center gap-3 px-4 py-3">
                    <span className="text-[11px] font-semibold text-muted w-16">{i === 0 ? "Primary" : i === 1 ? "Secondary" : `#${i + 1}`}</span>
                    <span className="font-mono text-[15px] font-semibold text-ink">{s}</span>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="qm-subcard px-4 py-4">
                <div className="qm-display text-[1.35rem] font-semibold text-ink">Carrier DNS</div>
                <div className="mt-1 text-[12.5px] text-muted">Devices get the gateway as resolver, which forwards to the carrier's servers.</div>
              </div>
            )}
            {d?.dhcpDnsRaw?.trim() && (
              <details className="text-[12px] text-muted">
                <summary className="cursor-pointer select-none font-semibold">Modem's own DHCP DNS report</summary>
                <pre className="mt-2 qm-subcard p-3 font-mono text-[11.5px] whitespace-pre-wrap break-all text-ink-2">{d.dhcpDnsRaw.trim()}</pre>
              </details>
            )}
          </div>

          <div className="lg:col-span-7 min-w-0 space-y-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[12px] text-muted">Quick fill</span>
              {DNS_PRESETS.map((p) => (
                <PresetChip
                  key={p.label}
                  active={dns1 === p.servers[0] && dns2 === p.servers[1]}
                  onClick={() => {
                    setDns1(p.servers[0]);
                    setDns2(p.servers[1]);
                  }}
                >
                  {p.label}
                </PresetChip>
              ))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel htmlFor="dns1" term="IPv4">Primary</FieldLabel>
                <Input id="dns1" value={dns1} onChange={(e) => setDns1(e.target.value)} placeholder="1.1.1.1" className="font-mono" />
              </div>
              <div>
                <FieldLabel htmlFor="dns2" term="IPv4">Secondary</FieldLabel>
                <Input id="dns2" value={dns2} onChange={(e) => setDns2(e.target.value)} placeholder="8.8.8.8" className="font-mono" />
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="primary"
                disabled={busy === "dns"}
                onClick={() =>
                  apply(
                    "dns",
                    {
                      action: "dns",
                      enabled: true,
                      nic: "lan",
                      servers: [dns1.trim(), dns2.trim()].filter(Boolean),
                    },
                    "Applied custom LAN DHCP DNS",
                    [dns1D, dns2D]
                  )
                }
              >
                Use these servers
              </Button>
              <Button
                variant="ghost"
                disabled={busy === "dns"}
                onClick={() => apply("dns", { action: "dns", enabled: false, nic: "lan" }, "Restored carrier DNS", [dns1D, dns2D])}
              >
                Go back to carrier DNS
              </Button>
            </div>
          </div>
        </div>

        <ApplyNote
          effect="Restarts the gateway's DHCP/DNS service (a second or two). Devices switch on their next DHCP renewal, or reconnect them."
          persist="Saved to the DHCP config; kept after reboot."
        />
      </Card>
    </div>
  );
}
