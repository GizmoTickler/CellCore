import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Activity, Cable, Pencil, Play, Plus, RotateCw, Route as RouteIcon, Square, Trash2, Users } from "lucide-react";
import { formatBytes, formatDuration } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, Modal, SegmentedTabs, Select, Skeleton, StatTile, Switch } from "../../components/ui";
import { Field } from "../system/parts";
import { DataTable, EmptyRow, LoadError, Mono, Notice, Td, adminSend, useAdmin, useGuarded } from "./shared";

interface Iface {
  name: string;
  up: boolean;
  proto: string;
  device: string;
  l3Device: string;
  uptime: number;
  ipv4: string[];
  ipv6: string[];
  dns: string[];
  rxBytes: number | null;
  txBytes: number | null;
}
interface Route {
  kind: string;
  dst: string;
  via: string | null;
  dev: string | null;
  table: string;
  proto: string | null;
  scope: string | null;
  src: string | null;
  metric: number | null;
  mtu: string | null;
  flags: string[];
}
interface Neighbour {
  address: string;
  dev: string;
  lladdr: string | null;
  state: string;
  router: boolean;
  family: string;
}
interface Conn {
  family: string;
  proto: string;
  state: string | null;
  ttl: number;
  src: string;
  dst: string;
  sport: number | null;
  dport: number | null;
  bytes: number;
  packets: number;
}
interface ConnResp {
  count: number;
  max: number | null;
  byProto: Record<string, number>;
  topTalkers: { address: string; flows: number; bytes: number }[];
  connections: Conn[];
  accounting: boolean;
}

function Interfaces({ guard }: { guard: ReturnType<typeof useGuarded> }) {
  const q = useAdmin<{ interfaces: Iface[] }>("/network/interfaces", { refetchInterval: 10000 });
  const qc = useQueryClient();
  if (q.isLoading) return <Skeleton className="h-64" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const list = [...q.data.interfaces].sort((a, b) => Number(b.up) - Number(a.up) || a.name.localeCompare(b.name));

  const act = (name: string, action: "up" | "down" | "renew") =>
    guard.run({
      title: `${action[0].toUpperCase()}${action.slice(1)} interface “${name}”?`,
      body: (
        <p>
          Runs <b className="font-mono">ubus call network.interface.{name} {action}</b>. Active flows on <b className="font-mono">{name}</b> may reconnect.
        </p>
      ),
      confirmLabel: action[0].toUpperCase() + action.slice(1),
      tone: action === "down" ? "danger" : "primary",
      action: (confirm) => adminSend("POST", "/network/interfaces/action", { name, action, confirm }),
      success: `${name}: ${action} completed`,
      onDone: () => {
        void qc.invalidateQueries({ queryKey: ["admin", "/network/interfaces"] });
        void qc.invalidateQueries({ queryKey: ["admin", "/network/routes"] });
      },
    });

  return (
    <Card>
      <CardHeader title="Interfaces" subtitle="netifd logical interfaces" icon={<Cable className="h-4 w-4" />} />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {list.map((i) => {
          const downDisabled = i.name === "lan" || i.name === "loopback";
          return (
            <div key={i.name} className="qm-subcard min-w-0 space-y-1.5 p-3.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-ink">{i.name}</span>
                <Badge variant={i.up ? "success" : "neutral"} dot>
                  {i.up ? formatDuration(i.uptime) : "down"}
                </Badge>
              </div>
              <div className="text-[11.5px] text-muted">
                {i.proto} · <Mono>{i.l3Device || i.device || "—"}</Mono>
              </div>
              {[...i.ipv4, ...i.ipv6].map((a) => (
                <Mono key={a} className="block text-ink-2">
                  {a}
                </Mono>
              ))}
              {i.dns.length > 0 && <div className="text-[11.5px] text-muted">DNS {i.dns.join(", ")}</div>}
              {i.rxBytes != null && (
                <div className="text-[11.5px] text-muted qm-tabular">
                  ↓ {formatBytes(i.rxBytes, 1)} · ↑ {formatBytes(i.txBytes ?? 0, 1)}
                </div>
              )}
              <div className="flex flex-wrap gap-1 pt-1">
                <Button variant="ghost" size="sm" className="h-7 px-2 text-[11.5px]" onClick={() => act(i.name, "renew")}>
                  <RotateCw className="h-3 w-3" /> Renew
                </Button>
                {i.up ? (
                  <Button variant="ghost" size="sm" className="h-7 px-2 text-[11.5px]" disabled={downDisabled} title={downDisabled ? "Protected management interface" : "Bring interface down"} onClick={() => act(i.name, "down")}>
                    <Square className="h-3 w-3" /> Down
                  </Button>
                ) : (
                  <Button variant="ghost" size="sm" className="h-7 px-2 text-[11.5px]" onClick={() => act(i.name, "up")}>
                    <Play className="h-3 w-3" /> Up
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function Routes() {
  const q = useAdmin<{ ipv4: Route[]; ipv6: Route[]; rules: string[] }>("/network/routes");
  const [fam, setFam] = useState<"ipv4" | "ipv6">("ipv4");
  const [all, setAll] = useState(false);
  const rows = useMemo(() => (q.data?.[fam] ?? []).filter((r) => all || (r.table !== "local" && r.kind === "unicast")), [q.data, fam, all]);
  return (
    <Card>
      <CardHeader
        title="Routing tables"
        subtitle="ip route show table all"
        icon={<RouteIcon className="h-4 w-4" />}
        action={
          <SegmentedTabs
            value={fam}
            onChange={setFam}
            options={[
              { id: "ipv4", label: "IPv4" },
              { id: "ipv6", label: "IPv6" },
            ]}
          />
        }
      />
      {q.isLoading ? (
        <Skeleton className="h-48" />
      ) : q.error ? (
        <LoadError error={q.error} />
      ) : (
        <>
          <div className="mb-3">
            <Switch label="Show local, broadcast and multicast routes" checked={all} onChange={setAll} />
          </div>
          <DataTable head={["Destination", "Via", "Device", "Table", "Metric", "Source"]}>
            {rows.length === 0 && <EmptyRow cols={6}>No routes.</EmptyRow>}
            {rows.map((r, i) => (
              <tr key={i}>
                <Td mono className="text-ink">
                  {r.kind !== "unicast" && <span className="text-muted">{r.kind} </span>}
                  {r.dst}
                </Td>
                <Td mono>{r.via ?? "—"}</Td>
                <Td mono>
                  {r.dev ?? "—"} {r.flags.includes("linkdown") && <Badge variant="warning">link down</Badge>}
                </Td>
                <Td>{r.table}</Td>
                <Td num>{r.metric ?? ""}</Td>
                <Td mono className="text-muted">
                  {r.src ?? ""}
                  {r.mtu ? ` mtu ${r.mtu}` : ""}
                </Td>
              </tr>
            ))}
          </DataTable>
          {q.data && q.data.rules.length > 0 && (
            <details className="mt-4">
              <summary className="cursor-pointer text-[12.5px] font-semibold text-ink-2">Policy rules ({q.data.rules.length})</summary>
              <ul className="mt-2 space-y-0.5">
                {q.data.rules.map((r) => (
                  <li key={r}>
                    <Mono className="text-muted">{r}</Mono>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </Card>
  );
}

function Neighbours() {
  const q = useAdmin<{ neighbours: Neighbour[] }>("/network/neighbours", { refetchInterval: 15000 });
  return (
    <Card>
      <CardHeader title="Neighbours" subtitle="ARP and IPv6 neighbour cache" icon={<Users className="h-4 w-4" />} />
      {q.isLoading ? (
        <Skeleton className="h-32" />
      ) : q.error || !q.data ? (
        <LoadError error={q.error} />
      ) : (
        <DataTable head={["Address", "MAC", "Device", "State"]}>
          {q.data.neighbours.length === 0 && <EmptyRow cols={4}>No neighbours.</EmptyRow>}
          {q.data.neighbours.map((n) => (
            <tr key={`${n.address}-${n.dev}`}>
              <Td mono className="text-ink">
                {n.address} {n.router && <Badge variant="info">router</Badge>}
              </Td>
              <Td mono>{n.lladdr ?? "—"}</Td>
              <Td mono>{n.dev}</Td>
              <Td>
                <Badge variant={n.state === "REACHABLE" || n.state === "PERMANENT" ? "success" : n.state === "FAILED" ? "danger" : "neutral"}>{n.state || "—"}</Badge>
              </Td>
            </tr>
          ))}
        </DataTable>
      )}
    </Card>
  );
}

function Connections() {
  const q = useAdmin<ConnResp>("/network/connections", { refetchInterval: 10000 });
  if (q.isLoading) return <Skeleton className="h-64" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const pct = d.max ? (d.count / d.max) * 100 : null;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Tracked connections" value={String(d.count)} sub={d.max ? `${pct!.toFixed(1)}% of ${d.max}` : undefined} tone={pct && pct > 80 ? "amber" : "neutral"} />
        {Object.entries(d.byProto)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([p, n]) => (
            <StatTile key={p} label={p.toUpperCase()} value={String(n)} sub="flows" />
          ))}
      </div>
      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="min-w-0 lg:col-span-4">
          <CardHeader title="Top talkers" subtitle={d.accounting ? "By bytes, original source" : "By flows (byte counters off)"} icon={<Activity className="h-4 w-4" />} />
          <ul className="space-y-2">
            {d.topTalkers.map((t) => (
              <li key={t.address} className="flex items-center justify-between gap-3 text-[12.5px]">
                <Mono className="text-ink">{t.address}</Mono>
                <span className="shrink-0 text-muted qm-tabular">
                  {t.flows} · {formatBytes(t.bytes, 1)}
                </span>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="min-w-0 lg:col-span-8">
          <CardHeader title="Active connections" subtitle={`Largest ${d.connections.length} by bytes`} />
          {!d.accounting && <Notice className="mb-3">Byte counters are off (net.netfilter.nf_conntrack_acct=0), so sizes show as 0.</Notice>}
          <DataTable head={["Proto", "Source", "Destination", "State", "Bytes"]}>
            {d.connections.length === 0 && <EmptyRow cols={5}>No connections.</EmptyRow>}
            {d.connections.map((c, i) => (
              <tr key={i}>
                <Td className="uppercase text-[12px]">{c.proto}</Td>
                <Td mono>
                  {c.src}
                  {c.sport != null ? `:${c.sport}` : ""}
                </Td>
                <Td mono>
                  {c.dst}
                  {c.dport != null ? `:${c.dport}` : ""}
                </Td>
                <Td className="text-[12px] text-muted">{c.state ?? `${c.ttl}s`}</Td>
                <Td num>{formatBytes(c.bytes, 1)}</Td>
              </tr>
            ))}
          </DataTable>
        </Card>
      </div>
    </div>
  );
}

interface StaticRoute {
  id: string;
  family: "ipv4" | "ipv6";
  interface: string;
  target: string;
  netmask: string | null;
  gateway: string | null;
  metric: number | null;
  table: number | null;
  disabled: boolean;
}

interface StaticRouteForm {
  id?: string;
  family: "ipv4" | "ipv6";
  interface: string;
  target: string;
  netmask: string;
  gateway: string;
  metric: string;
  table: string;
  disabled: boolean;
}

function StaticRoutes({ guard }: { guard: ReturnType<typeof useGuarded> }) {
  const q = useAdmin<{ routes: StaticRoute[] }>("/network/static-routes");
  const ifacesQ = useAdmin<{ interfaces: Iface[] }>("/network/interfaces");
  const qc = useQueryClient();
  const [form, setForm] = useState<StaticRouteForm | null>(null);
  const ifaceNames = useMemo(() => (ifacesQ.data?.interfaces ?? []).map((i) => i.name), [ifacesQ.data]);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["admin", "/network/static-routes"] });
    void qc.invalidateQueries({ queryKey: ["admin", "/network/routes"] });
  };

  const blank = (): StaticRouteForm => ({
    family: "ipv4",
    interface: ifaceNames[0] ?? "lan",
    target: "",
    netmask: "",
    gateway: "",
    metric: "",
    table: "",
    disabled: false,
  });

  const submit = () => {
    if (!form) return;
    const f = form;
    setForm(null);
    guard.run({
      title: `${f.id ? "Update" : "Add"} static route “${f.target}”?`,
      body: <p>Saves this route into UCI <b className="font-mono">network</b> and reloads netifd.</p>,
      confirmLabel: "Save",
      tone: "primary",
      action: (confirm) =>
        adminSend("POST", "/network/static-route", {
          id: f.id,
          family: f.family,
          interface: f.interface,
          target: f.target,
          netmask: f.family === "ipv4" && f.netmask.trim() ? f.netmask.trim() : null,
          gateway: f.gateway.trim() || null,
          metric: f.metric.trim() ? Number(f.metric.trim()) : null,
          table: f.table.trim() ? Number(f.table.trim()) : null,
          disabled: f.disabled,
          confirm,
        }),
      success: "Static route saved",
      onDone: refresh,
    });
  };

  const del = (r: StaticRoute) =>
    guard.run({
      title: `Delete static route “${r.target}”?`,
      body: <p>Removes this static route from UCI <b className="font-mono">network</b> and reloads netifd.</p>,
      confirmLabel: "Delete",
      action: (confirm) => adminSend("DELETE", "/network/static-route", { id: r.id, confirm }),
      success: "Static route removed",
      onDone: refresh,
    });

  return (
    <Card>
      <CardHeader
        title="Static Routes (UCI)"
        subtitle="Persistent IPv4/IPv6 routes in /etc/config/network"
        icon={<RouteIcon className="h-4 w-4" />}
        action={
          <Button variant="tier3" size="sm" onClick={() => setForm(blank())}>
            <Plus className="h-3.5 w-3.5" /> Add
          </Button>
        }
      />
      {q.isLoading ? (
        <Skeleton className="h-36" />
      ) : q.error || !q.data ? (
        <LoadError error={q.error} onRetry={() => q.refetch()} />
      ) : (
        <DataTable head={["Family", "Target", "Gateway", "Interface", "Metric / Table", ""]}>
          {q.data.routes.length === 0 && <EmptyRow cols={6}>No persistent static routes configured.</EmptyRow>}
          {q.data.routes.map((r) => (
            <tr key={r.id} className={r.disabled ? "text-muted" : ""}>
              <Td className="uppercase text-[12px]">{r.family}</Td>
              <Td mono className="text-ink">
                {r.target}
                {r.netmask ? ` / ${r.netmask}` : ""}
                {r.disabled && <Badge variant="neutral" className="ml-1.5">Off</Badge>}
              </Td>
              <Td mono>{r.gateway ?? "—"}</Td>
              <Td mono>{r.interface}</Td>
              <Td mono className="text-muted">
                {r.metric != null ? `m=${r.metric}` : "—"}
                {r.table != null ? ` t=${r.table}` : ""}
              </Td>
              <Td>
                <div className="flex justify-end">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="px-2"
                    aria-label={`Edit static route ${r.target}`}
                    onClick={() =>
                      setForm({
                        id: r.id,
                        family: r.family,
                        interface: r.interface,
                        target: r.target,
                        netmask: r.netmask ?? "",
                        gateway: r.gateway ?? "",
                        metric: r.metric != null ? String(r.metric) : "",
                        table: r.table != null ? String(r.table) : "",
                        disabled: r.disabled,
                      })
                    }
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="sm" className="px-2 text-crimson-ink" aria-label={`Delete static route ${r.target}`} onClick={() => del(r)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </Td>
            </tr>
          ))}
        </DataTable>
      )}
      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? "Edit static route" : "New static route"}>
        {form && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <div className="grid grid-cols-2 gap-3">
              <Field label="Family" htmlFor="sr-fam">
                <Select id="sr-fam" value={form.family} disabled={!!form.id} onChange={(e) => setForm({ ...form, family: e.target.value as "ipv4" | "ipv6" })}>
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </Select>
              </Field>
              <Field label="Interface" htmlFor="sr-iface">
                {ifaceNames.length > 0 ? (
                  <Select id="sr-iface" value={form.interface} onChange={(e) => setForm({ ...form, interface: e.target.value })}>
                    {!ifaceNames.includes(form.interface) && <option value={form.interface}>{form.interface}</option>}
                    {ifaceNames.map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <Input id="sr-iface" value={form.interface} onChange={(e) => setForm({ ...form, interface: e.target.value })} required />
                )}
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Target" htmlFor="sr-tgt" hint={form.family === "ipv4" ? "e.g. 10.20.0.0/16" : "e.g. fd00:1::/64"}>
                <Input id="sr-tgt" className="font-mono" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} required />
              </Field>
              <Field label="Gateway (optional)" htmlFor="sr-gw">
                <Input id="sr-gw" className="font-mono" value={form.gateway} onChange={(e) => setForm({ ...form, gateway: e.target.value })} />
              </Field>
            </div>
            <div className="grid grid-cols-3 gap-3">
              {form.family === "ipv4" && (
                <Field label="Netmask" htmlFor="sr-nm" hint="If not CIDR">
                  <Input id="sr-nm" className="font-mono" value={form.netmask} onChange={(e) => setForm({ ...form, netmask: e.target.value })} />
                </Field>
              )}
              <Field label="Metric" htmlFor="sr-met">
                <Input id="sr-met" inputMode="numeric" value={form.metric} onChange={(e) => setForm({ ...form, metric: e.target.value })} />
              </Field>
              <Field label="Table" htmlFor="sr-tbl" hint="excl. 255, 51820">
                <Input id="sr-tbl" inputMode="numeric" value={form.table} onChange={(e) => setForm({ ...form, table: e.target.value })} />
              </Field>
            </div>
            <Switch label="Disabled" checked={form.disabled} onChange={(b) => setForm({ ...form, disabled: b })} />
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setForm(null)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={!form.target.trim()}>
                Save
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </Card>
  );
}

export function NetStatusView() {
  const guard = useGuarded();
  return (
    <div className="space-y-5">
      <Interfaces guard={guard} />
      <Routes />
      <StaticRoutes guard={guard} />
      <Neighbours />
      <Connections />
      {guard.modal}
    </div>
  );
}
