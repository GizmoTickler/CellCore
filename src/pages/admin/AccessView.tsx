import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, Terminal, Trash2 } from "lucide-react";
import { useDraft } from "../../lib/draft";
import { Badge, Button, Card, CardHeader, CopyButton, Input, Select, Skeleton, Switch } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { Field, Verdict } from "../system/parts";
import { LoadError, Mono, Notice, TextArea, adminSend, errText, useAdmin, useGuarded } from "./shared";

interface DropbearCfg {
  id: string;
  enabled: boolean;
  port: number;
  passwordAuth: boolean;
  rootPasswordAuth: boolean;
  interface: string;
}
interface AuthKey {
  line: number;
  keyType: string;
  bits: number;
  fingerprint: string;
  comment: string;
  options: string | null;
  forcedCommand: string | null;
}
interface AccessResp {
  instances: DropbearCfg[];
  service: { running: boolean; pid: number | null };
  listening: number[];
  interfaces: string[];
  keys: AuthKey[];
  keyErrors: { line: number; error: string }[];
  shellKeys: number;
}

function DropbearCard({ cfg, data, onSaved }: { cfg: DropbearCfg; data: AccessResp; onSaved: () => unknown }) {
  // Drafts: a refetch never overwrites settings being edited.
  const [port, setPort, portD] = useDraft(String(cfg.port), "");
  const [pw, setPw, pwD] = useDraft(cfg.passwordAuth, false);
  const [rootPw, setRootPw, rootPwD] = useDraft(cfg.rootPasswordAuth, false);
  const [iface, setIface, ifaceD] = useDraft(cfg.interface, "");
  const guard = useGuarded();
  const dirty = port !== String(cfg.port) || pw !== cfg.passwordAuth || rootPw !== cfg.rootPasswordAuth || iface !== cfg.interface;
  const pwLogin = pw && rootPw;
  const noShellKey = data.shellKeys === 0;
  const listening = data.listening.includes(cfg.port);

  const apply = () =>
    guard.run({
      title: "Apply SSH settings?",
      body: (
        <>
          <p>Dropbear restarts with the new settings. Open SSH sessions stay up; new logins use the new settings.</p>
          {port !== String(cfg.port) && <p>New logins must use port <b className="font-mono">{port}</b>, including automation that connects to this gateway.</p>}
          {iface !== cfg.interface && <p>SSH will only listen on <b>{iface || "all interfaces"}</b>.</p>}
          <p className="text-muted text-[12.5px]">If dropbear does not come back listening on the new port, the previous settings are restored automatically.</p>
        </>
      ),
      confirmLabel: "Apply",
      tone: "primary",
      action: (confirm) => adminSend("POST", "/access/dropbear", { id: cfg.id, port, passwordAuth: pw, rootPasswordAuth: rootPw, interface: iface, confirm }),
      success: "SSH settings applied and verified",
      onDone: async () => {
        await onSaved();
        for (const x of [portD, pwD, rootPwD, ifaceD]) x.reset();
      },
    });

  return (
    <Card className="min-w-0 lg:col-span-5">
      <CardHeader
        title="SSH server"
        subtitle="Dropbear, /etc/config/dropbear"
        icon={<Terminal className="h-4 w-4" />}
        action={<Badge variant={data.service.running ? "success" : "danger"} dot>{data.service.running ? "Running" : "Stopped"}</Badge>}
      />
      <div className="space-y-4">
        <Verdict tone={listening ? "jade" : "saffron"} className="text-[13px]">
          {listening ? `Listening on port ${cfg.port}` : `Not listening on port ${cfg.port}`}
        </Verdict>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Port" htmlFor="adm-ssh-port">
            <Input id="adm-ssh-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, "").slice(0, 5))} />
          </Field>
          <Field label="Listen on" htmlFor="adm-ssh-if">
            <Select id="adm-ssh-if" value={iface} onChange={(e) => setIface(e.target.value)}>
              <option value="">All interfaces</option>
              {data.interfaces.map((i) => (
                <option key={i} value={i}>
                  {i}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Switch label="Password authentication" description="Allow any password login" checked={pw} onChange={setPw} disabled={noShellKey && pw} />
        <Switch label="Root may log in with a password" description="Root is the only account on this gateway" checked={rootPw} onChange={setRootPw} disabled={noShellKey && rootPw} />
        <p className="text-[12px] text-muted">
          Password login is <b className="text-ink-2">{pwLogin ? "possible" : "off"}</b>.{" "}
          {noShellKey ? "Add a key that can open a shell before turning it off." : "Keys keep working either way."}
        </p>
        <div className="flex justify-end">
          <Button variant="primary" disabled={!dirty || guard.busy} onClick={apply}>
            Apply
          </Button>
        </div>
      </div>
      {guard.modal}
    </Card>
  );
}

export function AccessView() {
  const q = useAdmin<AccessResp>("/access");
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const guard = useGuarded();
  const [newKey, setNewKey] = useState("");
  const [adding, setAdding] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin", "/access"] });

  if (q.isLoading) return <Skeleton className="h-80" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const pwLogin = d.instances.some((i) => i.passwordAuth && i.rootPasswordAuth);

  async function addKey() {
    setAdding(true);
    try {
      await adminSend("POST", "/access/keys", { key: newKey.trim() });
      toast("Key authorized", "success");
      setNewKey("");
      await refresh();
    } catch (e) {
      toast("Key not added", "error", errText(e));
    } finally {
      setAdding(false);
    }
  }

  const remove = (k: AuthKey) =>
    guard.run({
      title: "Remove this key?",
      body: (
        <>
          <p>
            <Mono>{k.fingerprint}</Mono>
            {k.comment && <> ({k.comment})</>} will no longer be able to log in. Sessions already open stay up.
          </p>
          {k.forcedCommand && <p>This key runs a fixed command, so something automated probably uses it.</p>}
        </>
      ),
      confirmLabel: "Remove key",
      action: (confirm) => adminSend("DELETE", "/access/keys", { fingerprint: k.fingerprint, confirm }),
      success: "Key removed",
      onDone: () => void refresh(),
    });

  return (
    <div className="space-y-5">
      {!pwLogin && d.shellKeys <= 1 && (
        <Notice tone="warn" title={d.shellKeys === 0 ? "No key can open a shell and password login is off" : "Only one key can open a shell"}>
          Keep a second admin key authorized so losing one does not lock you out of SSH.
        </Notice>
      )}
      <div className="grid gap-5 lg:grid-cols-12">
        {d.instances.map((cfg) => (
          <DropbearCard key={cfg.id} cfg={cfg} data={d} onSaved={refresh} />
        ))}
        <Card className="min-w-0 lg:col-span-7">
          <CardHeader title="Authorized keys" subtitle="/etc/dropbear/authorized_keys" icon={<KeyRound className="h-4 w-4" />} />
          <ul className="divide-y divide-line">
            {d.keys.length === 0 && <li className="py-4 text-[13px] text-muted">No keys yet.</li>}
            {d.keys.map((k) => (
              <li key={k.fingerprint + k.line} className="flex items-start gap-3 py-3">
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[13px] font-semibold text-ink">{k.comment || "No comment"}</span>
                    <Badge variant="neutral">
                      {k.keyType.replace(/^ssh-|ecdsa-sha2-/, "")} · {k.bits}
                    </Badge>
                    {k.forcedCommand ? <Badge variant="warning">Fixed command</Badge> : <Badge variant="success">Shell</Badge>}
                  </div>
                  <div className="flex items-center gap-1">
                    <Mono className="text-muted">{k.fingerprint}</Mono>
                    <CopyButton value={k.fingerprint} label="" />
                  </div>
                  {k.forcedCommand && <div className="text-[11.5px] text-muted">Runs <Mono>{k.forcedCommand}</Mono></div>}
                </div>
                <Button variant="ghost" size="sm" className="text-crimson-ink" aria-label={`Remove key ${k.comment || k.fingerprint}`} onClick={() => remove(k)}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </li>
            ))}
          </ul>
          {d.keyErrors.length > 0 && (
            <Notice tone="warn" className="mt-3" title="Some lines could not be read">
              {d.keyErrors.map((e) => `line ${e.line}: ${e.error}`).join("; ")}
            </Notice>
          )}
          <div className="mt-4 space-y-2 border-t border-line pt-4">
            <Field label="Add a public key" htmlFor="adm-newkey" hint="Paste one line, e.g. ssh-ed25519 AAAA… you@laptop">
              <TextArea id="adm-newkey" rows={3} className="font-mono text-[12px]" value={newKey} onChange={(e) => setNewKey(e.target.value)} spellCheck={false} />
            </Field>
            <div className="flex justify-end">
              <Button variant="primary" onClick={addKey} disabled={!newKey.trim() || adding}>
                {adding ? "Adding…" : "Authorize key"}
              </Button>
            </div>
          </div>
        </Card>
      </div>
      {guard.modal}
    </div>
  );
}
