import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, CopyButton, Input, Modal, Select, Skeleton } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { DataTable, EmptyRow, LoadError, Mono, Notice, Td, errText, formatAgo } from "../admin/shared";
import { Field } from "./parts";

type Kind = "read" | "rw";

interface TokenInfo {
  id: string;
  name: string;
  kind: Kind;
  createdAt: number;
  expiresAt: number | null;
  expired: boolean;
  lastUsedAt: number | null;
  lastUsedIp: string | null;
}

const KINDS: Array<{ id: Kind; label: string; hint: string }> = [
  {
    id: "read",
    label: "Read-only",
    hint: "Reads /metrics, status, radio telemetry, dataplane, failover and VPN status. Cannot mutate state or read sensitive/admin views (events, logs, SMS, profiles, OTA, ACME, notifications, SSH access, backups, processes, netstat, audit log, IMEI/ICCID).",
  },
  {
    id: "rw",
    label: "Read-write",
    hint: "Full access, like being signed in: radio, admin tools, AT console, IMEI, firmware updates, backups and reboot. Only token management and the password change stay browser-only.",
  },
];

const EXPIRY: Array<{ id: string; label: string }> = [
  { id: "30", label: "30 days" },
  { id: "90", label: "90 days" },
  { id: "365", label: "1 year" },
  { id: "never", label: "Never" },
];

const now = () => Math.floor(Date.now() / 1000);

function fmtDate(secs: number | null): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

function KindBadge({ kind }: { kind: Kind }) {
  return kind === "rw" ? <Badge variant="danger">read-write</Badge> : <Badge variant="info">read-only</Badge>;
}

export function ApiTokensCard() {
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const q = useQuery({
    queryKey: ["security", "tokens"],
    queryFn: () => apiFetch<{ tokens: TokenInfo[] }>("/api/v1/security/tokens"),
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Kind>("read");
  const [expiry, setExpiry] = useState("90");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);
  const [revoke, setRevoke] = useState<TokenInfo | null>(null);
  const [typed, setTyped] = useState("");

  const nameOk = /^[A-Za-z0-9 _.-]{1,40}$/.test(name.trim());

  async function create() {
    setBusy(true);
    try {
      const effectiveExpiry = kind === "rw" && expiry === "never" ? "90" : expiry;
      const res = await apiFetch<{ token: string; info: TokenInfo }>("/api/v1/security/tokens", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          kind,
          expiresInDays: effectiveExpiry === "never" ? null : Number(effectiveExpiry),
        }),
      });
      setCreateOpen(false);
      setCreated({ name: res.info.name, token: res.token });
      setName("");
      setKind("read");
      void qc.invalidateQueries({ queryKey: ["security", "tokens"] });
    } catch (e) {
      toast("Could not create token", "error", errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function doRevoke() {
    if (!revoke) return;
    setBusy(true);
    try {
      await apiFetch(`/api/v1/security/tokens/${encodeURIComponent(revoke.id)}`, { method: "DELETE" });
      toast("Token revoked", "success", `${revoke.name} stops working immediately.`);
      setRevoke(null);
      void qc.invalidateQueries({ queryKey: ["security", "tokens"] });
    } catch (e) {
      toast("Revoke failed", "error", errText(e));
    } finally {
      setBusy(false);
    }
  }

  const tokens = q.data?.tokens ?? [];

  return (
    <Card className="min-w-0">
      <CardHeader
        title="API tokens"
        subtitle="Long-lived bearer tokens for scripts and monitoring"
        icon={<KeyRound className="h-4 w-4" />}
        action={
          <Button size="sm" variant="secondary" onClick={() => setCreateOpen(true)} disabled={tokens.length >= 16}>
            <Plus className="h-3.5 w-3.5" /> New token
          </Button>
        }
      />
      <p className="mb-4 text-[12.5px] text-muted">
        Send as <Mono className="text-ink-2">Authorization: Bearer qmt_…</Mono>. Read-only tokens can
        only read (and never secrets); read-write tokens can do anything a signed-in browser can, except manage tokens or change the password.
      </p>
      {q.isLoading ? (
        <Skeleton className="h-24" />
      ) : q.error ? (
        <LoadError error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <DataTable head={["Name", "Type", "Expires", "Last used", ""]}>
          {tokens.length === 0 && <EmptyRow cols={5}>No API tokens yet.</EmptyRow>}
          {tokens.map((t) => (
            <tr key={t.id}>
              <Td>
                <div className="font-semibold text-ink">{t.name}</div>
                <div className="text-[11px] text-muted">created {fmtDate(t.createdAt)}</div>
              </Td>
              <Td>
                <KindBadge kind={t.kind} />
              </Td>
              <Td>{t.expired ? <Badge variant="danger">expired</Badge> : <span className="qm-tabular text-ink-2">{t.expiresAt ? fmtDate(t.expiresAt) : "never"}</span>}</Td>
              <Td>
                <div className="text-ink-2">{t.lastUsedAt ? formatAgo(now() - t.lastUsedAt) : "never"}</div>
                {t.lastUsedIp && <div className="font-mono text-[11px] text-muted">{t.lastUsedIp}</div>}
              </Td>
              <Td className="text-right">
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={`Revoke ${t.name}`}
                  onClick={() => {
                    setTyped("");
                    setRevoke(t);
                  }}
                >
                  <Trash2 className="h-3.5 w-3.5" /> Revoke
                </Button>
              </Td>
            </tr>
          ))}
        </DataTable>
      )}

      <Modal open={createOpen} onClose={() => !busy && setCreateOpen(false)} title="New API token">
        <div className="space-y-4">
          <Field label="Name" htmlFor="qm-tok-name" hint="Letters, digits, space, '-', '_' and '.'; at most 40.">
            <Input id="qm-tok-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="router-monitor" autoComplete="off" />
          </Field>
          <div role="radiogroup" aria-label="Token type">
            <div className="mb-1.5 text-[12.5px] font-semibold text-ink-2">Type</div>
            <div className="grid gap-2">
              {KINDS.map((k) => {
                const on = kind === k.id;
                const danger = k.id === "rw";
                return (
                  <button
                    key={k.id}
                    type="button"
                    role="radio"
                    aria-checked={on}
                    onClick={() => {
                      setKind(k.id);
                      if (k.id === "rw" && expiry === "never") setExpiry("90");
                    }}
                    className={cn(
                      "min-h-[44px] rounded-xl border px-3 py-2.5 text-left transition cursor-pointer",
                      on ? (danger ? "border-crimson bg-crimson-soft" : "border-ember bg-ember-soft") : "border-line bg-raised hover:border-line-strong"
                    )}
                  >
                    <div className={cn("text-[13px] font-semibold", on ? (danger ? "text-crimson-ink" : "text-ember-ink") : "text-ink")}>{k.label}</div>
                    <div className="mt-0.5 text-[11.5px] leading-snug text-muted">{k.hint}</div>
                  </button>
                );
              })}
            </div>
          </div>
          {kind === "rw" && (
            <Notice tone="danger" title="This is the keys to the gateway">
              Anyone holding a read-write token can reconfigure or brick the backup WAN modem, change the IMEI, install software, open the firewall, restore
              backups and reboot, without a password. Give it the shortest expiry that works, keep it in a secrets store, and revoke it the moment it may
              have leaked. Every change it makes is recorded in the audit log under its name.
            </Notice>
          )}
          <Field
            label="Expires"
            htmlFor="qm-tok-exp"
            hint={kind === "rw" ? "Read-write tokens require an expiry (90 days default)." : undefined}
          >
            <Select
              id="qm-tok-exp"
              value={kind === "rw" && expiry === "never" ? "90" : expiry}
              onChange={(e) => setExpiry(e.target.value)}
            >
              {(kind === "rw" ? EXPIRY.filter((x) => x.id !== "never") : EXPIRY).map((x) => (
                <option key={x.id} value={x.id}>
                  {x.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={() => setCreateOpen(false)} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={create} disabled={busy || !nameOk}>
            {busy ? "Creating…" : "Create token"}
          </Button>
        </div>
      </Modal>

      <Modal open={created !== null} onClose={() => setCreated(null)} title="Copy your new token">
        {created && (
          <div className="space-y-3">
            <Notice tone="warn" title="Shown once">
              Only a hash is stored. If you lose it, revoke <b>{created.name}</b> and create another.
            </Notice>
            <div className="flex items-start gap-2 rounded-xl border border-line bg-sunk p-3">
              <Mono className="min-w-0 flex-1 text-ink select-all">{created.token}</Mono>
              <CopyButton value={created.token} label="Copy" />
            </div>
            <div className="flex justify-end">
              <Button variant="primary" onClick={() => setCreated(null)}>
                Done
              </Button>
            </div>
          </div>
        )}
      </Modal>

      <Modal open={revoke !== null} onClose={() => !busy && setRevoke(null)} title="Revoke this token?">
        {revoke && (
          <div className="space-y-3">
            <p>
              Anything using <b>{revoke.name}</b> loses access immediately. This cannot be undone.
            </p>
            <label className="block text-[12px] font-semibold text-ink-2">
              Type <span className="font-mono text-ink">{revoke.name}</span> to continue
              <Input
                autoFocus
                className="mt-1.5 font-mono"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                aria-label={`Type ${revoke.name} to confirm`}
              />
            </label>
            <div className="flex flex-wrap justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setRevoke(null)} disabled={busy}>
                Cancel
              </Button>
              <Button variant="danger" onClick={doRevoke} disabled={busy || typed.trim() !== revoke.name}>
                {busy ? "Revoking…" : "Revoke"}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </Card>
  );
}
