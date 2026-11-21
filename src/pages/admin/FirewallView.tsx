import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowRight, FileLock2, Pencil, Plus, Shield, Trash2 } from "lucide-react";
import { Badge, Button, Card, CardHeader, Input, Modal, Select, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { Field } from "../system/parts";
import { DataTable, EmptyRow, LoadError, Mono, Notice, Pre, Td, adminSend, errText, useAdmin, useGuarded } from "./shared";

interface Zone {
  id: string;
  name: string;
  networks: string[];
  input: string;
  output: string;
  forward: string;
  masq: boolean;
  mtuFix?: boolean;
}
interface Entry {
  id: string;
  enabled: boolean;
  name?: string;
  src?: string;
  dest?: string;
  proto?: string;
  src_ip?: string;
  src_port?: string;
  src_dport?: string;
  dest_ip?: string;
  dest_port?: string;
  family?: string;
  target?: string;
  passthrough?: boolean;
}
interface Pending {
  token: string;
  secondsLeft: number;
  summary: string;
}
interface FwResp {
  zones: Zone[];
  forwardings: { id: string; src: string; dest: string; enabled: boolean }[];
  rules: Entry[];
  redirects: Entry[];
  includes: { id: string; path: string; type: string; enabled: boolean }[];
  hardening: { path: string; size: number; content: string; truncated: boolean }[];
  pending: Pending | null;
  confirmSecs: number;
}

const POLICY_BADGE: Record<string, "success" | "danger" | "warning"> = { ACCEPT: "success", REJECT: "danger", DROP: "danger" };
const PROTOS = [
  ["tcp udp", "TCP + UDP"],
  ["tcp", "TCP"],
  ["udp", "UDP"],
  ["icmp", "ICMP"],
  ["all", "Any"],
];

/* ───────────── Commit-confirm banner ───────────── */

function usePending(initial: Pending | null | undefined, onSettled: () => void) {
  const toast = useToastStore((s) => s.push);
  const [p, setP] = useState<(Pending & { auto: boolean; phase: "verifying" | "waiting" }) | null>(null);
  const settled = useRef(onSettled);
  settled.current = onSettled;
  /** Tokens already confirmed or reverted here; stale query data must not resurrect them. */
  const handled = useRef(new Set<string>());

  useEffect(() => {
    if (initial && !p && !handled.current.has(initial.token)) setP({ ...initial, auto: false, phase: "waiting" });
  }, [initial, p]);

  useEffect(() => {
    if (!p) return;
    const t = window.setInterval(() => setP((x) => (x ? { ...x, secondsLeft: Math.max(0, x.secondsLeft - 1) } : x)), 1000);
    return () => window.clearInterval(t);
  }, [p?.token]);

  const confirm = async (token: string) => {
    handled.current.add(token);
    try {
      await adminSend("POST", "/firewall/confirm", { token });
      toast("Firewall change kept", "success", "This browser can still reach the gateway.");
    } catch (e) {
      toast("Could not confirm the firewall change", "error", `${errText(e)}. It rolls back automatically.`);
    } finally {
      setP(null);
      settled.current();
    }
  };

  const revert = async (token: string) => {
    handled.current.add(token);
    try {
      await adminSend("POST", "/firewall/revert", { token });
      toast("Firewall change reverted", "info");
    } catch (e) {
      toast("Revert failed", "error", errText(e));
    } finally {
      setP(null);
      settled.current();
    }
  };

  /** Called with the server's pending record after a successful change. */
  const start = (pending: Pending) => {
    setP({ ...pending, auto: true, phase: "verifying" });
    // Give fw4 a moment, then prove this browser still reaches the gateway.
    window.setTimeout(() => void confirm(pending.token), 3000);
  };

  const banner = p ? (
    <Notice tone="warn" title={p.phase === "verifying" ? "Checking you can still reach the gateway…" : "A firewall change is waiting for confirmation"}>
      <span className="block">
        {p.summary}. If it is not confirmed in <b className="qm-tabular">{p.secondsLeft}s</b> the previous rules are restored.
      </span>
      {!p.auto && (
        <span className="mt-2 flex flex-wrap gap-2">
          <Button size="sm" variant="primary" onClick={() => void confirm(p.token)}>
            Keep change
          </Button>
          <Button size="sm" variant="secondary" onClick={() => void revert(p.token)}>
            Revert now
          </Button>
        </span>
      )}
    </Notice>
  ) : null;
  return { start, banner, active: !!p };
}

/* ───────────── Forms ───────────── */

interface FormState {
  kind: "redirect" | "rule";
  id?: string;
  v: Record<string, string>;
  enabled: boolean;
}

function blankRedirect(): FormState {
  return { kind: "redirect", v: { name: "", proto: "tcp udp", src: "wan", src_dport: "", dest_ip: "", dest_port: "", src_ip: "" }, enabled: true };
}
function blankRule(): FormState {
  return { kind: "rule", v: { name: "", src: "wan", dest: "", proto: "tcp udp", dest_port: "", src_ip: "", dest_ip: "", family: "any", target: "ACCEPT" }, enabled: true };
}
function fromEntry(kind: "redirect" | "rule", e: Entry): FormState {
  const base = kind === "redirect" ? blankRedirect() : blankRule();
  const v = { ...base.v };
  for (const k of Object.keys(v)) {
    const val = (e as unknown as Record<string, unknown>)[k];
    if (typeof val === "string") v[k] = val;
  }
  if (kind === "rule" && !e.family) v.family = "any";
  if (kind === "redirect" && !e.proto) v.proto = "tcp udp";
  return { kind, id: e.id, v, enabled: e.enabled };
}

function EntryForm({ form, zones, onChange, onClose, onSubmit }: { form: FormState; zones: Zone[]; onChange: (f: FormState) => void; onClose: () => void; onSubmit: () => void }) {
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => onChange({ ...form, v: { ...form.v, [k]: e.target.value } });
  const ports = ["tcp", "udp", "tcp udp"].includes(form.v.proto);
  const isRedirect = form.kind === "redirect";
  return (
    <Modal open onClose={onClose} title={`${form.id ? "Edit" : "New"} ${isRedirect ? "port forward" : "traffic rule"}`}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
      >
        <Field label="Name" htmlFor="fw-name">
          <Input id="fw-name" value={form.v.name} onChange={set("name")} required maxLength={64} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Protocol" htmlFor="fw-proto">
            <Select id="fw-proto" value={form.v.proto} onChange={set("proto")}>
              {PROTOS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </Select>
          </Field>
          <Field label={isRedirect ? "From zone" : "Source zone"} htmlFor="fw-src">
            <Select id="fw-src" value={form.v.src} onChange={set("src")}>
              {!isRedirect && <option value="*">Any zone</option>}
              {zones.map((z) => (
                <option key={z.id} value={z.name}>
                  {z.name}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        {isRedirect ? (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Field label="External port" htmlFor="fw-sport" hint={ports ? "e.g. 8443 or 8000-8100" : "Ports need TCP/UDP"}>
                <Input id="fw-sport" value={form.v.src_dport} onChange={set("src_dport")} disabled={!ports} inputMode="numeric" />
              </Field>
              <Field label="Internal port" htmlFor="fw-dport" hint="Blank = same">
                <Input id="fw-dport" value={form.v.dest_port} onChange={set("dest_port")} disabled={!ports} inputMode="numeric" />
              </Field>
            </div>
            <Field label="Internal IP" htmlFor="fw-dip" hint="LAN host that receives the traffic">
              <Input id="fw-dip" value={form.v.dest_ip} onChange={set("dest_ip")} placeholder="192.168.1.x" />
            </Field>
            <Field label="Only from (optional)" htmlFor="fw-sip" hint="Source address or CIDR">
              <Input id="fw-sip" value={form.v.src_ip} onChange={set("src_ip")} />
            </Field>
          </>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Destination" htmlFor="fw-dest">
                <Select id="fw-dest" value={form.v.dest} onChange={set("dest")}>
                  <option value="">This gateway</option>
                  <option value="*">Any zone</option>
                  {zones.map((z) => (
                    <option key={z.id} value={z.name}>
                      {z.name} (forward)
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Port" htmlFor="fw-rport" hint={ports ? "Blank = all" : "Ports need TCP/UDP"}>
                <Input id="fw-rport" value={form.v.dest_port} onChange={set("dest_port")} disabled={!ports} inputMode="numeric" />
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Source IP" htmlFor="fw-rsip">
                <Input id="fw-rsip" value={form.v.src_ip} onChange={set("src_ip")} placeholder="any" />
              </Field>
              <Field label="Destination IP" htmlFor="fw-rdip">
                <Input id="fw-rdip" value={form.v.dest_ip} onChange={set("dest_ip")} placeholder="any" />
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Family" htmlFor="fw-fam">
                <Select id="fw-fam" value={form.v.family} onChange={set("family")}>
                  <option value="any">IPv4 + IPv6</option>
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </Select>
              </Field>
              <Field label="Action" htmlFor="fw-target">
                <Select id="fw-target" value={form.v.target} onChange={set("target")}>
                  <option value="ACCEPT">Accept</option>
                  <option value="REJECT">Reject</option>
                  <option value="DROP">Drop</option>
                </Select>
              </Field>
            </div>
          </>
        )}
        <Switch label="Enabled" checked={form.enabled} onChange={(b) => onChange({ ...form, enabled: b })} />
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!form.v.name.trim()}>
            Review
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/* ───────────── View ───────────── */

export function FirewallView() {
  const q = useAdmin<FwResp>("/firewall");
  const qc = useQueryClient();
  const guard = useGuarded();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["admin", "/firewall"] });
  const pend = usePending(q.data?.pending, refresh);
  const [form, setForm] = useState<FormState | null>(null);
  const [zoneForm, setZoneForm] = useState<Zone | null>(null);
  const [fwdForm, setFwdForm] = useState<{ src: string; dest: string } | null>(null);

  if (q.isLoading) return <Skeleton className="h-96" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const secs = d.confirmSecs;
  const after = (r: { pending?: Pending }) => {
    if (r.pending) pend.start(r.pending);
    refresh();
  };
  const rollbackNote = <p className="text-muted text-[12.5px]">The firewall reloads now. If this page cannot confirm within {secs} s (for example because the change cut you off), the previous rules come back on their own.</p>;

  const submit = () => {
    if (!form) return;
    const f = form;
    setForm(null);
    const isRedirect = f.kind === "redirect";
    const body = isRedirect
      ? { id: f.id, name: f.v.name, proto: f.v.proto, src: f.v.src, srcDport: f.v.src_dport, destIp: f.v.dest_ip, destPort: f.v.dest_port, srcIp: f.v.src_ip, enabled: f.enabled }
      : { id: f.id, name: f.v.name, src: f.v.src, dest: f.v.dest, proto: f.v.proto, destPort: f.v.dest_port, srcIp: f.v.src_ip, destIp: f.v.dest_ip, family: f.v.family, target: f.v.target, enabled: f.enabled };
    guard.run({
      title: `${f.id ? "Save" : "Add"} ${isRedirect ? "port forward" : "rule"} “${f.v.name}”?`,
      body: rollbackNote,
      confirmLabel: "Apply",
      tone: "primary",
      action: (confirm) => adminSend<{ pending?: Pending }>("POST", isRedirect ? "/firewall/redirect" : "/firewall/rule", { ...body, confirm }),
      onDone: after,
    });
  };

  const del = (kind: "redirect" | "rule", e: Entry) =>
    guard.run({
      title: `Delete “${e.name ?? e.id}”?`,
      body: (
        <>
          {e.passthrough && <p className="text-crimson-ink">This forward passes every WAN port to {e.dest_ip}. The downstream router depends on it for its backup WAN.</p>}
          {rollbackNote}
        </>
      ),
      confirmLabel: "Delete",
      action: (confirm) => adminSend<{ pending?: Pending }>("DELETE", kind === "redirect" ? "/firewall/redirect" : "/firewall/rule", { id: e.id, confirm }),
      onDone: after,
    });

  const editBtns = (kind: "redirect" | "rule", e: Entry) => (
    <div className="flex justify-end">
      <Button variant="ghost" size="sm" className="px-2" aria-label={`Edit ${e.name ?? e.id}`} disabled={pend.active} onClick={() => setForm(fromEntry(kind, e))}>
        <Pencil className="h-3.5 w-3.5" />
      </Button>
      <Button variant="ghost" size="sm" className="px-2 text-crimson-ink" aria-label={`Delete ${e.name ?? e.id}`} disabled={pend.active} onClick={() => del(kind, e)}>
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );

  const submitZone = () => {
    if (!zoneForm) return;
    const z = zoneForm;
    setZoneForm(null);
    guard.run({
      title: `Update zone “${z.name}”?`,
      body: rollbackNote,
      confirmLabel: "Apply",
      tone: "primary",
      action: (confirm) =>
        adminSend<{ pending?: Pending }>("POST", "/firewall/zone", {
          id: z.id,
          input: z.input,
          output: z.output,
          forward: z.forward,
          masq: z.masq,
          mtuFix: !!z.mtuFix,
          confirm,
        }),
      onDone: after,
    });
  };

  const submitForwarding = () => {
    if (!fwdForm) return;
    const f = fwdForm;
    setFwdForm(null);
    guard.run({
      title: `Add forwarding ${f.src} -> ${f.dest}?`,
      body: rollbackNote,
      confirmLabel: "Apply",
      tone: "primary",
      action: () => adminSend<{ pending?: Pending }>("POST", "/firewall/forwarding", { src: f.src, dest: f.dest, enabled: true }),
      onDone: after,
    });
  };

  const delForwarding = (f: { id: string; src: string; dest: string }) =>
    guard.run({
      title: `Remove forwarding ${f.src} -> ${f.dest}?`,
      body: rollbackNote,
      confirmLabel: "Delete",
      action: (confirm) => adminSend<{ pending?: Pending }>("DELETE", "/firewall/forwarding", { id: f.id, confirm }),
      onDone: after,
    });

  return (
    <div className="space-y-5">
      {pend.banner}
      <Notice tone="info">
        Zones, forwardings, port forwards, and traffic rules can be edited here with automatic {secs} s commit-confirm rollback. Cellular daemon includes and the hand-written files
        under /etc/nftables.d and /etc/firewall.user* are shown read-only and never written.
      </Notice>

      <Card>
        <CardHeader
          title="Zones"
          subtitle={`${d.zones.length} zones · default policies per direction`}
          icon={<Shield className="h-4 w-4" />}
          action={
            <Button
              variant="tier3"
              size="sm"
              disabled={pend.active || d.zones.length < 2}
              onClick={() => setFwdForm({ src: d.zones[0]?.name ?? "lan", dest: d.zones[1]?.name ?? "wan" })}
            >
              <Plus className="h-3.5 w-3.5" /> Add forwarding
            </Button>
          }
        />
        <DataTable head={["Zone", "Networks", "Input", "Output", "Forward", "Masquerade", ""]}>
          {d.zones.map((z) => (
            <tr key={z.id}>
              <Td className="font-semibold text-ink">{z.name}</Td>
              <Td mono className="text-ink-2">
                {z.networks.join(" ") || "—"}
              </Td>
              {[z.input, z.output, z.forward].map((p, i) => (
                <Td key={i}>
                  <Badge variant={POLICY_BADGE[p] ?? "neutral"}>{p}</Badge>
                </Td>
              ))}
              <Td>{z.masq ? <Badge variant="info">NAT</Badge> : <span className="text-muted">—</span>}</Td>
              <Td>
                <div className="flex justify-end">
                  <Button variant="ghost" size="sm" className="px-2" aria-label={`Edit zone ${z.name}`} disabled={pend.active} onClick={() => setZoneForm({ ...z })}>
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </Td>
            </tr>
          ))}
        </DataTable>
        <div className="mt-4 flex flex-wrap gap-2">
          {d.forwardings.map((f) => (
            <span key={f.id} className="inline-flex items-center gap-1.5 rounded-full border border-line bg-sunk pl-3 pr-1.5 py-1 text-[12px] font-semibold text-ink-2">
              {f.src} <ArrowRight className="h-3 w-3" /> {f.dest}
              <Button
                variant="ghost"
                size="sm"
                className="h-5 w-5 p-0 text-crimson-ink"
                aria-label={`Remove forwarding ${f.src} to ${f.dest}`}
                disabled={pend.active}
                onClick={() => delForwarding(f)}
              >
                <Trash2 className="h-3 w-3" />
              </Button>
            </span>
          ))}
          {d.forwardings.length === 0 && <span className="text-[12px] text-muted">No zone forwardings.</span>}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Port forwards"
          subtitle="DNAT from a zone to a LAN host"
          action={
            <Button variant="tier3" size="sm" disabled={pend.active} onClick={() => setForm(blankRedirect())}>
              <Plus className="h-3.5 w-3.5" /> Add
            </Button>
          }
        />
        <DataTable head={["Name", "From", "External", "To", "Proto", ""]}>
          {d.redirects.length === 0 && <EmptyRow cols={6}>No port forwards.</EmptyRow>}
          {d.redirects.map((r) => (
            <tr key={r.id} className={r.enabled ? "" : "text-muted"}>
              <Td>
                <span className={r.enabled ? "font-semibold text-ink" : "font-semibold text-muted"}>{r.name || r.id}</span>{" "}
                {r.passthrough && <Badge variant={r.enabled ? "warning" : "neutral"}>All ports</Badge>}
                {!r.enabled && <Badge variant="neutral">Off</Badge>}
              </Td>
              <Td>{r.src}</Td>
              <Td mono>{r.src_dport || "all"}</Td>
              <Td mono>
                {r.dest_ip || "gateway"}
                {r.dest_port ? `:${r.dest_port}` : ""}
              </Td>
              <Td>{r.proto || "tcp udp"}</Td>
              <Td>{editBtns("redirect", r)}</Td>
            </tr>
          ))}
        </DataTable>
      </Card>

      <Card>
        <CardHeader
          title="Traffic rules"
          subtitle="Allow or block traffic to the gateway or between zones"
          action={
            <Button variant="tier3" size="sm" disabled={pend.active} onClick={() => setForm(blankRule())}>
              <Plus className="h-3.5 w-3.5" /> Add
            </Button>
          }
        />
        <DataTable head={["Name", "Match", "Action", ""]}>
          {d.rules.length === 0 && <EmptyRow cols={4}>No rules.</EmptyRow>}
          {d.rules.map((r) => (
            <tr key={r.id} className={r.enabled ? "" : "text-muted"}>
              <Td>
                <span className={r.enabled ? "font-semibold text-ink" : "font-semibold text-muted"}>{r.name || r.id}</span> {!r.enabled && <Badge variant="neutral">Off</Badge>}
              </Td>
              <Td className={r.enabled ? "text-[12.5px] text-ink-2" : "text-[12.5px] text-muted"}>
                {r.src ?? "*"} → {r.dest ? r.dest : "gateway"} · {r.proto || "tcp udp"}
                {r.dest_port ? ` :${r.dest_port}` : ""}
                {r.family ? ` · ${r.family}` : ""}
              </Td>
              <Td>
                <Badge variant={r.enabled ? (POLICY_BADGE[r.target ?? ""] ?? "neutral") : "neutral"}>{r.target ?? "—"}</Badge>
              </Td>
              <Td>{editBtns("rule", r)}</Td>
            </tr>
          ))}
        </DataTable>
      </Card>

      <Card>
        <CardHeader title="Includes and hand-written rules" subtitle="Read-only" icon={<FileLock2 className="h-4 w-4" />} />
        <ul className="mb-4 space-y-1.5">
          {d.includes.map((i) => (
            <li key={i.id} className="flex flex-wrap items-center gap-2 text-[13px]">
              <Mono>{i.path}</Mono>
              <Badge variant="neutral">{i.type}</Badge>
              {!i.enabled && <Badge variant="warning">Disabled</Badge>}
            </li>
          ))}
        </ul>
        <div className="space-y-2">
          {d.hardening.map((h) => (
            <details key={h.path} className="qm-subcard p-3">
              <summary className="cursor-pointer text-[13px] font-semibold text-ink">
                <Mono>{h.path}</Mono> <span className="font-normal text-muted">· {h.size} bytes</span>
              </summary>
              <Pre className="mt-2">{h.content || "(empty)"}</Pre>
            </details>
          ))}
          {d.hardening.length === 0 && <p className="text-[12.5px] text-muted">No nftables.d or firewall.user files.</p>}
        </div>
      </Card>

      {form && <EntryForm form={form} zones={d.zones} onChange={setForm} onClose={() => setForm(null)} onSubmit={submit} />}
      <Modal open={!!zoneForm} onClose={() => setZoneForm(null)} title={`Edit zone “${zoneForm?.name ?? ""}”`}>
        {zoneForm && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              submitZone();
            }}
          >
            <div className="grid grid-cols-3 gap-3">
              {(["input", "output", "forward"] as const).map((dir) => (
                <Field key={dir} label={dir[0].toUpperCase() + dir.slice(1)} htmlFor={`zn-${dir}`}>
                  <Select
                    id={`zn-${dir}`}
                    value={zoneForm[dir]}
                    onChange={(e) => setZoneForm({ ...zoneForm, [dir]: e.target.value })}
                  >
                    <option value="ACCEPT">ACCEPT</option>
                    <option value="REJECT">REJECT</option>
                    <option value="DROP">DROP</option>
                  </Select>
                </Field>
              ))}
            </div>
            <Switch label="Masquerade (NAT)" checked={zoneForm.masq} onChange={(b) => setZoneForm({ ...zoneForm, masq: b })} />
            <Switch label="MSS clamping (mtu_fix)" checked={!!zoneForm.mtuFix} onChange={(b) => setZoneForm({ ...zoneForm, mtuFix: b })} />
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setZoneForm(null)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary">
                Review
              </Button>
            </div>
          </form>
        )}
      </Modal>
      <Modal open={!!fwdForm} onClose={() => setFwdForm(null)} title="Add zone forwarding">
        {fwdForm && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              submitForwarding();
            }}
          >
            <div className="grid grid-cols-2 gap-3">
              <Field label="Source zone" htmlFor="fwd-src">
                <Select id="fwd-src" value={fwdForm.src} onChange={(e) => setFwdForm({ ...fwdForm, src: e.target.value })}>
                  {d.zones.map((z) => (
                    <option key={z.id} value={z.name}>
                      {z.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Destination zone" htmlFor="fwd-dest">
                <Select id="fwd-dest" value={fwdForm.dest} onChange={(e) => setFwdForm({ ...fwdForm, dest: e.target.value })}>
                  {d.zones.map((z) => (
                    <option key={z.id} value={z.name}>
                      {z.name}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setFwdForm(null)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={fwdForm.src === fwdForm.dest}>
                Review
              </Button>
            </div>
          </form>
        )}
      </Modal>
      {guard.modal}
    </div>
  );
}
