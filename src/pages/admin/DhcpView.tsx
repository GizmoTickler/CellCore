import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Globe, Pencil, Plus, Trash2, Users } from "lucide-react";
import { formatDuration } from "../../lib/utils";
import { useDraft } from "../../lib/draft";
import { Badge, Button, Card, CardHeader, Input, Modal, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { Field } from "../system/parts";
import { DataTable, EmptyRow, LoadError, Mono, Notice, Td, adminSend, errText, useAdmin, useGuarded } from "./shared";

interface Host {
  id: string;
  name: string;
  macs: string[];
  ip: string;
  leasetime: string;
  dns: boolean;
}
interface Lease {
  expires: number;
  mac: string;
  ip: string;
  hostname: string | null;
}
interface DomainHost {
  id: string;
  name: string;
  ip: string;
}
interface DhcpResp {
  hosts: Host[];
  domains?: DomainHost[];
  leases: Lease[];
  now: number;
  dnsmasq: { id: string; options: Record<string, string | string[]> }[];
  editableFlags: string[];
  pools: { id: string; interface: string; ignore: boolean; start: string | null; limit: string | null; leasetime: string | null }[];
  lanSubnet: string | null;
}

const FLAG_LABEL: Record<string, string> = {
  domainneeded: "Never forward plain names",
  boguspriv: "Never forward private reverse lookups",
  rebind_protection: "Rebind protection",
  rebind_localhost: "Allow localhost rebinding",
  localise_queries: "Localise queries",
  expandhosts: "Expand hosts with local domain",
  authoritative: "Authoritative DHCP",
  logqueries: "Log queries",
};

interface HostForm {
  id?: string;
  name: string;
  mac: string;
  ip: string;
  leasetime: string;
  dns: boolean;
}

function DnsmasqCard({ inst, flags, onSaved }: { inst: DhcpResp["dnsmasq"][number]; flags: string[]; onSaved: () => unknown }) {
  const toast = useToastStore((s) => s.push);
  const str = (k: string) => {
    const v = inst.options[k];
    return Array.isArray(v) ? v.join(" ") : (v ?? "");
  };
  // Drafts: the 30 s poll never overwrites options being edited.
  const [domain, setDomain, domainD] = useDraft(str("domain"), "");
  const [local, setLocal, localD] = useDraft(str("local"), "");
  const serverVals = useMemo(
    () => Object.fromEntries(flags.map((f) => [f, str(f) === "1"])) as Record<string, boolean>,
    [inst, flags] // eslint-disable-line react-hooks/exhaustive-deps -- str() only reads inst
  );
  const [vals, setVals, valsD] = useDraft(serverVals, {} as Record<string, boolean>);
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      await adminSend("POST", "/dhcp/dnsmasq", { id: inst.id, domain, local, flags: vals });
      toast("DNS options saved", "success", "dnsmasq reloaded.");
      await onSaved();
      domainD.reset();
      localD.reset();
      valsD.reset();
    } catch (e) {
      toast("Not saved", "error", errText(e));
    } finally {
      setSaving(false);
    }
  }

  const readOnly = Object.entries(inst.options).filter(([k]) => !flags.includes(k) && k !== "domain" && k !== "local");
  return (
    <Card className="min-w-0 lg:col-span-5">
      <CardHeader title="DNS (dnsmasq)" subtitle={`Instance ${inst.id}`} icon={<Globe className="h-4 w-4" />} />
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Local domain" htmlFor={`dm-${inst.id}`}>
            <Input id={`dm-${inst.id}`} value={domain} onChange={(e) => setDomain(e.target.value)} />
          </Field>
          <Field label="Local server" htmlFor={`ls-${inst.id}`} hint="e.g. /lan/">
            <Input id={`ls-${inst.id}`} value={local} onChange={(e) => setLocal(e.target.value)} />
          </Field>
        </div>
        <div className="space-y-3">
          {flags.map((f) => (
            <Switch key={f} label={FLAG_LABEL[f] ?? f} checked={!!vals[f]} onChange={(b) => setVals((v) => ({ ...v, [f]: b }))} />
          ))}
        </div>
        <details>
          <summary className="cursor-pointer text-[12.5px] font-semibold text-ink-2">Other options (read-only)</summary>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[12px]">
            {readOnly.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted">{k}</dt>
                <dd>
                  <Mono>{Array.isArray(v) ? v.join(" ") : v}</Mono>
                </dd>
              </div>
            ))}
          </dl>
        </details>
        <div className="flex justify-end">
          <Button variant="primary" onClick={save} disabled={saving}>
            {saving ? "Saving…" : "Save DNS options"}
          </Button>
        </div>
      </div>
    </Card>
  );
}

export function DhcpView() {
  const q = useAdmin<DhcpResp>("/dhcp", { refetchInterval: 30000 });
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const guard = useGuarded();
  const [form, setForm] = useState<HostForm | null>(null);
  const [saving, setSaving] = useState(false);
  const [domainForm, setDomainForm] = useState<{ id?: string; name: string; ip: string } | null>(null);
  const [savingDomain, setSavingDomain] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin", "/dhcp"] });

  if (q.isLoading) return <Skeleton className="h-96" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const reserved = new Set(d.hosts.flatMap((h) => h.macs));

  async function saveDomain() {
    if (!domainForm) return;
    setSavingDomain(true);
    try {
      await adminSend("POST", "/dhcp/domain", domainForm);
      toast(domainForm.id ? "Hostname updated" : "Hostname added", "success", "dnsmasq reloaded.");
      setDomainForm(null);
      refresh();
    } catch (e) {
      toast("Not saved", "error", errText(e));
    } finally {
      setSavingDomain(false);
    }
  }

  const delDomain = (item: DomainHost) =>
    guard.run({
      title: `Remove hostname ${item.name}?`,
      body: <p>DNS queries for {item.name} will no longer resolve to {item.ip}.</p>,
      confirmLabel: "Remove",
      action: () => adminSend("DELETE", "/dhcp/domain", { id: item.id }),
      success: "Custom hostname removed",
      onDone: refresh,
    });

  async function saveHost() {
    if (!form) return;
    setSaving(true);
    try {
      await adminSend("POST", "/dhcp/host", form);
      toast(form.id ? "Reservation updated" : "Reservation added", "success", "dnsmasq reloaded; the client gets it at its next renewal.");
      setForm(null);
      refresh();
    } catch (e) {
      toast("Not saved", "error", errText(e));
    } finally {
      setSaving(false);
    }
  }

  const del = (h: Host) =>
    guard.run({
      title: `Remove reservation for ${h.name}?`,
      body: <p>{h.ip} goes back to the pool. The device keeps its address until its lease runs out.</p>,
      confirmLabel: "Remove",
      action: () => adminSend("DELETE", "/dhcp/host", { id: h.id }),
      success: "Reservation removed",
      onDone: refresh,
    });

  const pool = d.pools.find((p) => p.interface === "lan");
  return (
    <div className="space-y-5">
      <Notice tone="info">
        LAN addressing and the DHCP pool belong to QCMAP; change them in{" "}
        <a className="font-semibold text-ember-ink underline-offset-2 hover:underline" href="#/network/lan">
          Network › LAN & Link
        </a>
        . {d.lanSubnet && <>LAN is {d.lanSubnet}</>}
        {pool && !pool.ignore && pool.start && (
          <>
            , pool starts at .{pool.start} for {pool.limit} hosts, leases {pool.leasetime ?? "12h"}
          </>
        )}
        .
      </Notice>

      <Card>
        <CardHeader title="Active leases" subtitle={`${d.leases.length} from ${"dnsmasq"}`} icon={<Users className="h-4 w-4" />} />
        <DataTable head={["Host", "IP", "MAC", "Expires", ""]}>
          {d.leases.length === 0 && <EmptyRow cols={5}>No active DHCP leases.</EmptyRow>}
          {d.leases.map((l) => (
            <tr key={l.mac + l.ip}>
              <Td className="font-semibold text-ink">{l.hostname ?? "—"}</Td>
              <Td mono>{l.ip}</Td>
              <Td mono>{l.mac}</Td>
              <Td className="text-muted">{l.expires === 0 ? "never" : `in ${formatDuration(Math.max(0, l.expires - d.now))}`}</Td>
              <Td>
                {reserved.has(l.mac) ? (
                  <Badge variant="success">Reserved</Badge>
                ) : (
                  <Button variant="ghost" size="sm" onClick={() => setForm({ name: (l.hostname ?? "").replace(/[^A-Za-z0-9-]/g, "-"), mac: l.mac, ip: l.ip, leasetime: "", dns: true })}>
                    Reserve
                  </Button>
                )}
              </Td>
            </tr>
          ))}
        </DataTable>
      </Card>

      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="min-w-0 lg:col-span-7">
          <CardHeader
            title="Static leases"
            subtitle="Always give a device the same address"
            action={
              <Button variant="tier3" size="sm" onClick={() => setForm({ name: "", mac: "", ip: "", leasetime: "", dns: true })}>
                <Plus className="h-3.5 w-3.5" /> Add
              </Button>
            }
          />
          <DataTable head={["Name", "IP", "MAC", ""]}>
            {d.hosts.length === 0 && <EmptyRow cols={4}>No reservations.</EmptyRow>}
            {d.hosts.map((h) => (
              <tr key={h.id}>
                <Td className="font-semibold text-ink">
                  {h.name} {h.leasetime && <Badge variant="neutral">{h.leasetime}</Badge>}
                </Td>
                <Td mono>{h.ip}</Td>
                <Td mono>{h.macs.join(" ")}</Td>
                <Td>
                  <div className="flex justify-end">
                    <Button variant="ghost" size="sm" className="px-2" aria-label={`Edit ${h.name}`} onClick={() => setForm({ id: h.id, name: h.name, mac: h.macs.join(" "), ip: h.ip, leasetime: h.leasetime, dns: h.dns })}>
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="ghost" size="sm" className="px-2 text-crimson-ink" aria-label={`Remove ${h.name}`} onClick={() => del(h)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </Td>
              </tr>
            ))}
          </DataTable>
        </Card>
        {d.dnsmasq.map((inst) => (
          <DnsmasqCard key={inst.id} inst={inst} flags={d.editableFlags} onSaved={refresh} />
        ))}
      </div>

      <Card>
        <CardHeader
          title="Custom hostnames"
          subtitle="Local DNS A/AAAA records (uci dhcp domain)"
          action={
            <Button variant="tier3" size="sm" onClick={() => setDomainForm({ name: "", ip: "" })}>
              <Plus className="h-3.5 w-3.5" /> Add
            </Button>
          }
        />
        <DataTable head={["Hostname", "IP address", ""]}>
          {(d.domains ?? []).length === 0 && <EmptyRow cols={3}>No custom hostnames.</EmptyRow>}
          {(d.domains ?? []).map((dm) => (
            <tr key={dm.id}>
              <Td className="font-semibold text-ink">{dm.name}</Td>
              <Td mono>{dm.ip}</Td>
              <Td>
                <div className="flex justify-end">
                  <Button variant="ghost" size="sm" className="px-2" aria-label={`Edit hostname ${dm.name}`} onClick={() => setDomainForm({ id: dm.id, name: dm.name, ip: dm.ip })}>
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="sm" className="px-2 text-crimson-ink" aria-label={`Remove hostname ${dm.name}`} onClick={() => delDomain(dm)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </Td>
            </tr>
          ))}
        </DataTable>
      </Card>

      <Modal open={!!domainForm} onClose={() => !savingDomain && setDomainForm(null)} title={domainForm?.id ? "Edit custom hostname" : "New custom hostname"}>
        {domainForm && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void saveDomain();
            }}
          >
            <Field label="Hostname" htmlFor="dom-name" hint="e.g. nas.lan">
              <Input id="dom-name" value={domainForm.name} onChange={(e) => setDomainForm({ ...domainForm, name: e.target.value })} required />
            </Field>
            <Field label="IP address" htmlFor="dom-ip" hint="IPv4 or IPv6 address">
              <Input id="dom-ip" className="font-mono" value={domainForm.ip} onChange={(e) => setDomainForm({ ...domainForm, ip: e.target.value })} required />
            </Field>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setDomainForm(null)} disabled={savingDomain}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={savingDomain}>
                {savingDomain ? "Saving…" : "Save"}
              </Button>
            </div>
          </form>
        )}
      </Modal>

      <Modal open={!!form} onClose={() => !saving && setForm(null)} title={form?.id ? "Edit reservation" : "New reservation"}>
        {form && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void saveHost();
            }}
          >
            <Field label="Hostname" htmlFor="dh-name">
              <Input id="dh-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field label="MAC address" htmlFor="dh-mac" hint="Up to 4, separated by spaces">
              <Input id="dh-mac" className="font-mono" value={form.mac} onChange={(e) => setForm({ ...form, mac: e.target.value })} required />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="IPv4 address" htmlFor="dh-ip">
                <Input id="dh-ip" className="font-mono" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} required />
              </Field>
              <Field label="Lease time" htmlFor="dh-lt" hint="Blank = pool default">
                <Input id="dh-lt" value={form.leasetime} onChange={(e) => setForm({ ...form, leasetime: e.target.value })} placeholder="12h" />
              </Field>
            </div>
            <Switch label="Add to local DNS" checked={form.dns} onChange={(b) => setForm({ ...form, dns: b })} />
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setForm(null)} disabled={saving}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={saving}>
                {saving ? "Saving…" : "Save"}
              </Button>
            </div>
          </form>
        )}
      </Modal>
      {guard.modal}
    </div>
  );
}
