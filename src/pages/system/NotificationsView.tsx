import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, MessageSquare, Plus, Send, ShieldAlert, Trash2, Webhook } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn, formatBitrate } from "../../lib/utils";
import { useObsStore } from "../../stores/obs-store";
import { useToastStore } from "../../stores/toast-store";
import type { FailoverStatus, NotifyResponse } from "../../types/obs";
import { Badge, Button, Card, CardHeader, Input, Select, Skeleton, Switch } from "../../components/ui";
import { EVENT_GROUPS, EVENT_META, eventLabel } from "../../components/obs";
import { Field, Verdict } from "./parts";
import { LoadError } from "../admin/shared";
import { useDraft } from "../../lib/draft";

type Sink = "email" | "webhook" | "ntfy";

interface HeaderRow {
  name: string;
  /** Typed value; empty with `saved` = keep the stored secret. */
  value: string;
  saved: boolean;
}

interface Draft {
  enabled: boolean;
  kinds: Record<string, boolean>;
  dedupeMin: string;
  ratePerHour: string;
  quietEnabled: boolean;
  quietStart: string;
  quietEnd: string;
  allowCritical: boolean;
  email: boolean;
  webhook: boolean;
  webhookUrl: string;
  webhookFormat: "json" | "alertmanager";
  headers: HeaderRow[];
  ntfy: boolean;
  ntfyUrl: string;
  /** Typed token; "" = keep (unless clearToken). */
  ntfyToken: string;
  ntfyTokenSet: boolean;
  clearToken: boolean;
  sms: boolean;
  smsMin: string;
}

function toDraft(r: NotifyResponse): Draft {
  const c = r.config;
  return {
    enabled: c.enabled,
    kinds: { ...c.kinds },
    dedupeMin: String(Math.round(c.dedupeSecs / 60)),
    ratePerHour: String(c.ratePerHour),
    quietEnabled: c.quiet.enabled,
    quietStart: c.quiet.start,
    quietEnd: c.quiet.end,
    allowCritical: c.quiet.allowCritical,
    email: c.email.enabled,
    webhook: c.webhook.enabled,
    webhookUrl: c.webhook.url,
    webhookFormat: c.webhook.format,
    headers: c.webhook.headers.map((h) => ({ name: h.name, value: "", saved: h.valueSet })),
    ntfy: c.ntfy.enabled,
    ntfyUrl: c.ntfy.url,
    ntfyToken: "",
    ntfyTokenSet: c.ntfy.tokenSet,
    clearToken: false,
    sms: c.smsForward.enabled,
    smsMin: String(Math.round(c.smsForward.intervalSecs / 60)),
  };
}

/** Request body: secrets only when typed (write-only on the server). */
function toBody(d: Draft) {
  return {
    enabled: d.enabled,
    kinds: d.kinds,
    dedupeSecs: Math.max(0, Math.round(Number(d.dedupeMin) || 0) * 60),
    ratePerHour: Math.round(Number(d.ratePerHour) || 0),
    quiet: { enabled: d.quietEnabled, start: d.quietStart, end: d.quietEnd, allowCritical: d.allowCritical },
    email: { enabled: d.email },
    webhook: {
      enabled: d.webhook,
      url: d.webhookUrl.trim(),
      format: d.webhookFormat,
      headers: d.headers
        .filter((h) => h.name.trim())
        .map((h) => (h.value || !h.saved ? { name: h.name.trim(), value: h.value } : { name: h.name.trim() })),
    },
    ntfy: {
      enabled: d.ntfy,
      url: d.ntfyUrl.trim(),
      ...(d.clearToken ? { token: "" } : d.ntfyToken ? { token: d.ntfyToken } : {}),
    },
    smsForward: { enabled: d.sms, intervalSecs: Math.round(Number(d.smsMin) || 0) * 60 },
  };
}

function SinkBlock({
  icon,
  title,
  hint,
  on,
  onToggle,
  onTest,
  testing,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  hint: React.ReactNode;
  on: boolean;
  onToggle: (v: boolean) => void;
  onTest: () => void;
  testing: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div className="qm-subcard p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-ember-soft text-ember-ink">{icon}</span>
          <div className="min-w-0">
            <div className="text-[13.5px] font-semibold text-ink">{title}</div>
            <div className="text-[12px] text-muted mt-0.5">{hint}</div>
          </div>
        </div>
        <Switch checked={on} onChange={onToggle} ariaLabel={`Send to ${title}`} />
      </div>
      {children}
      <div className="flex justify-end">
        <Button variant="ghost" size="sm" onClick={onTest} disabled={testing}>
          <Send className="h-3.5 w-3.5" /> {testing ? "Sending…" : "Send test"}
        </Button>
      </div>
    </div>
  );
}

export function NotificationsCard({ smtpConfigured }: { smtpConfigured: boolean }) {
  const qc = useQueryClient();
  const push = useToastStore((s) => s.push);
  const q = useQuery({ queryKey: ["obs-notify"], queryFn: () => apiFetch<NotifyResponse>("/api/v1/notify") });
  const [busy, setBusy] = useState<string | null>(null);
  // Draft: the form follows the server until the first edit; refetches never clobber edits.
  const serverDraft = useMemo(() => (q.data ? toDraft(q.data) : null), [q.data]);
  const [d, setD, draft] = useDraft<Draft | null>(serverDraft, null);

  const set = (patch: Partial<Draft>) => setD((cur) => (cur ? { ...cur, ...patch } : cur));
  const types = q.data?.types ?? [];
  const st = q.data?.status;
  const sentTotal = st ? Object.values(st.sent).reduce((a, b) => a + b, 0) : 0;
  const failedTotal = st ? Object.values(st.failed).reduce((a, b) => a + b, 0) : 0;

  const grouped = useMemo(
    () =>
      EVENT_GROUPS.map((g) => ({
        ...g,
        types: types.filter((t) => EVENT_META[t.type]?.group === g.id),
      })).filter((g) => g.types.length > 0),
    [types]
  );

  async function save(): Promise<boolean> {
    if (!d) return false;
    setBusy("save");
    try {
      const res = await apiFetch<NotifyResponse>("/api/v1/notify", { method: "POST", body: JSON.stringify(toBody(d)) });
      qc.setQueryData(["obs-notify"], res);
      draft.reset();
      push("Notification settings saved", "success");
      return true;
    } catch (e) {
      push("Couldn't save notifications", "error", e instanceof Error ? e.message : undefined);
      return false;
    } finally {
      setBusy(null);
    }
  }

  async function test(sink: Sink | "all") {
    // Test what is on screen: save first so a typed URL or token is used.
    if (!(await save())) return;
    setBusy(`test-${sink}`);
    try {
      const res = await apiFetch<{ results: Array<{ sink: string; ok: boolean; error?: string | null }> }>("/api/v1/notify/test", {
        method: "POST",
        body: JSON.stringify({ sink }),
      });
      for (const r of res.results) {
        if (r.ok) push(`Test sent via ${r.sink}`, "success");
        else push(`Test via ${r.sink} failed`, "error", r.error ?? undefined);
      }
      await qc.invalidateQueries({ queryKey: ["obs-notify"] });
    } catch (e) {
      push("Test failed", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  if (q.isError && !d) {
    return (
      <Card className="lg:col-span-12">
        <LoadError title="Could not load notification settings" error={q.error} onRetry={() => void q.refetch()} />
      </Card>
    );
  }
  if (q.isLoading || !d) {
    return (
      <Card className="lg:col-span-12">
        <Skeleton className="h-64" />
      </Card>
    );
  }

  return (
    <>
      <Card className="lg:col-span-7 min-w-0">
        <CardHeader
          title="Notifications"
          subtitle="Push events to your phone, inbox or monitoring"
          icon={<BellRing className="h-4 w-4" />}
          action={
            <div className="flex items-center gap-1.5">
              {draft.dirty && <Badge variant="warning">Unsaved</Badge>}
              <Badge variant={!d.enabled ? "neutral" : failedTotal > 0 && st?.lastError ? "warning" : "success"} dot>
                {!d.enabled ? "Off" : `${sentTotal} sent${failedTotal ? ` · ${failedTotal} failed` : ""}`}
              </Badge>
            </div>
          }
        />
        <div className="space-y-4">
          <Switch
            checked={d.enabled}
            onChange={(v) => set({ enabled: v })}
            label="Send notifications"
            description="Events still appear in Diagnostics › Events when this is off"
          />
          {st?.lastError && (
            <div className="rounded-xl bg-saffron-soft px-3 py-2 text-[12px] text-saffron-ink break-words">
              Last failure ({st.lastError.sink}): {st.lastError.error}
            </div>
          )}

          <SinkBlock
            icon={<BellRing className="h-4 w-4" />}
            title="Email"
            hint={
              smtpConfigured || st?.emailReady ? (
                <Verdict tone="jade">Uses the email account above</Verdict>
              ) : (
                <Verdict tone="saffron">Set up the email account above first</Verdict>
              )
            }
            on={d.email}
            onToggle={(v) => set({ email: v })}
            onTest={() => void test("email")}
            testing={busy === "test-email"}
          />

          <SinkBlock
            icon={<Webhook className="h-4 w-4" />}
            title="Webhook"
            hint="POST JSON to any URL, or alerts in Alertmanager's v2 format"
            on={d.webhook}
            onToggle={(v) => set({ webhook: v })}
            onTest={() => void test("webhook")}
            testing={busy === "test-webhook"}
          >
            <div className="grid gap-3 sm:grid-cols-[1fr_170px]">
              <Field label="URL" htmlFor="qm-wh-url">
                <Input
                  id="qm-wh-url"
                  inputMode="url"
                  autoComplete="off"
                  value={d.webhookUrl}
                  onChange={(e) => set({ webhookUrl: e.target.value })}
                  placeholder="https://hooks.example.com/modem"
                />
              </Field>
              <Field label="Format" htmlFor="qm-wh-fmt">
                <Select id="qm-wh-fmt" value={d.webhookFormat} onChange={(e) => set({ webhookFormat: e.target.value as Draft["webhookFormat"] })}>
                  <option value="json">JSON event</option>
                  <option value="alertmanager">Alertmanager</option>
                </Select>
              </Field>
            </div>
            {d.webhookFormat === "alertmanager" && (
              <p className="text-[12px] text-muted">Use the full endpoint, e.g. http://alertmanager:9093/api/v2/alerts. Events resolve after 15 minutes.</p>
            )}
            <div className="space-y-2">
              <div className="text-[12.5px] font-semibold text-ink-2">Headers</div>
              {d.headers.map((h, i) => (
                <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2">
                  <Input
                    aria-label="Header name"
                    value={h.name}
                    onChange={(e) => set({ headers: d.headers.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })}
                    placeholder="Authorization"
                  />
                  <Input
                    aria-label={`Value for ${h.name || "header"}`}
                    type="password"
                    autoComplete="new-password"
                    value={h.value}
                    onChange={(e) => set({ headers: d.headers.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })}
                    placeholder={h.saved ? "Saved; type to replace" : "Value"}
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-10 px-2.5"
                    aria-label={`Remove header ${h.name}`}
                    onClick={() => set({ headers: d.headers.filter((_, j) => j !== i) })}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
              {d.headers.length < 8 && (
                <Button variant="ghost" size="sm" onClick={() => set({ headers: [...d.headers, { name: "", value: "", saved: false }] })}>
                  <Plus className="h-3.5 w-3.5" /> Add header
                </Button>
              )}
              <p className="text-[11.5px] text-muted">Header values are stored on the gateway and never shown again.</p>
            </div>
          </SinkBlock>

          <SinkBlock
            icon={<Send className="h-4 w-4" />}
            title="ntfy"
            hint="Phone push through ntfy.sh or your own ntfy server"
            on={d.ntfy}
            onToggle={(v) => set({ ntfy: v })}
            onTest={() => void test("ntfy")}
            testing={busy === "test-ntfy"}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Topic URL" htmlFor="qm-ntfy-url">
                <Input
                  id="qm-ntfy-url"
                  inputMode="url"
                  autoComplete="off"
                  value={d.ntfyUrl}
                  onChange={(e) => set({ ntfyUrl: e.target.value })}
                  placeholder="https://ntfy.sh/your-topic"
                />
              </Field>
              <Field
                label="Access token"
                htmlFor="qm-ntfy-token"
                aside={
                  d.ntfyTokenSet && !d.clearToken ? (
                    <button type="button" className="text-[11.5px] font-semibold text-crimson-ink hover:underline cursor-pointer" onClick={() => set({ clearToken: true, ntfyToken: "" })}>
                      Remove
                    </button>
                  ) : undefined
                }
              >
                <Input
                  id="qm-ntfy-token"
                  type="password"
                  autoComplete="new-password"
                  value={d.ntfyToken}
                  onChange={(e) => set({ ntfyToken: e.target.value, clearToken: false })}
                  placeholder={d.clearToken ? "Will be removed on save" : d.ntfyTokenSet ? "Saved; type to replace" : "Optional"}
                />
              </Field>
            </div>
          </SinkBlock>

          <div className="flex flex-wrap justify-end gap-2 pt-1">
            <Button variant="secondary" onClick={() => void test("all")} disabled={busy != null}>
              <Send className="h-4 w-4" /> Test all enabled
            </Button>
            <Button variant="primary" onClick={() => void save()} disabled={busy != null}>
              {busy === "save" ? "Saving…" : "Save notifications"}
            </Button>
          </div>
        </div>
      </Card>

      <Card className="lg:col-span-5 min-w-0">
        <CardHeader
          title="What to send"
          subtitle="Per event type, with quiet hours and limits"
          icon={<ShieldAlert className="h-4 w-4" />}
          action={draft.dirty ? <Badge variant="warning">Unsaved</Badge> : undefined}
        />
        <div className="space-y-5">
          {grouped.map((g) => (
            <div key={g.id}>
              <div className="qm-eyebrow mb-2">{g.label}</div>
              <div className="space-y-2.5">
                {g.types.map((t) => (
                  <Switch
                    key={t.type}
                    checked={d.kinds[t.type] ?? t.default}
                    onChange={(v) => set({ kinds: { ...d.kinds, [t.type]: v } })}
                    label={eventLabel(t.type)}
                  />
                ))}
              </div>
            </div>
          ))}

          <div className="grid grid-cols-2 gap-3 border-t border-line pt-4">
            <Field label="Repeat after" htmlFor="qm-dedupe" hint="Same event, minutes">
              <Input id="qm-dedupe" type="number" min={0} max={1440} value={d.dedupeMin} onChange={(e) => set({ dedupeMin: e.target.value })} className="qm-tabular" />
            </Field>
            <Field label="At most" htmlFor="qm-rate" hint="Messages per hour">
              <Input id="qm-rate" type="number" min={1} max={120} value={d.ratePerHour} onChange={(e) => set({ ratePerHour: e.target.value })} className="qm-tabular" />
            </Field>
          </div>

          <div className="space-y-3 border-t border-line pt-4">
            <Switch checked={d.quietEnabled} onChange={(v) => set({ quietEnabled: v })} label="Quiet hours" description="Hold back non-urgent messages overnight" />
            <div className={cn("grid grid-cols-2 gap-3", !d.quietEnabled && "opacity-50")}>
              <Field label="From" htmlFor="qm-quiet-start">
                <Input id="qm-quiet-start" type="time" value={d.quietStart} onChange={(e) => set({ quietStart: e.target.value })} disabled={!d.quietEnabled} className="qm-tabular" />
              </Field>
              <Field label="Until" htmlFor="qm-quiet-end">
                <Input id="qm-quiet-end" type="time" value={d.quietEnd} onChange={(e) => set({ quietEnd: e.target.value })} disabled={!d.quietEnabled} className="qm-tabular" />
              </Field>
            </div>
            <Switch
              checked={d.allowCritical}
              onChange={(v) => set({ allowCritical: v })}
              disabled={!d.quietEnabled}
              label="Critical still gets through"
              description="Registration lost, quota at 95% and above"
            />
          </div>

          <div className="space-y-3 border-t border-line pt-4">
            <div className="flex items-start gap-3">
              <MessageSquare className="mt-0.5 h-4 w-4 shrink-0 text-muted" />
              <div className="min-w-0 flex-1">
                <Switch checked={d.sms} onChange={(v) => set({ sms: v })} label="Forward carrier SMS" description="New texts on the SIM become SMS received events" />
              </div>
            </div>
            {d.sms && (
              <Field label="Check every" htmlFor="qm-sms-min" hint="Minutes (2 or more)">
                <Input id="qm-sms-min" type="number" min={2} max={1440} value={d.smsMin} onChange={(e) => set({ smsMin: e.target.value })} className="qm-tabular" />
              </Field>
            )}
            <p className="rounded-xl bg-saffron-soft px-3 py-2 text-[12px] text-saffron-ink">
              This is the only feature here that talks to the modem: each check reads the SIM inbox (a few light AT commands). Everything else uses data the
              daemon already has.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-4">
            {draft.dirty && (
              <Button variant="ghost" size="sm" onClick={() => draft.reset()} disabled={busy != null}>
                Discard
              </Button>
            )}
            <Button variant="primary" size="sm" onClick={() => void save()} disabled={busy != null || !draft.dirty}>
              {busy === "save" ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </div>
      </Card>
    </>
  );
}

/** Failover detection tuning; deferral rules explained in plain language. */
export function FailoverCard() {
  const push = useToastStore((s) => s.push);
  const setFailover = useObsStore((s) => s.setFailover);
  const f = useObsStore((s) => s.failover);
  // Drafts: live failover pushes (every few seconds while active) never clobber an edit.
  const [mbps, setMbps, mbpsD] = useDraft(f ? String(Math.round((f.config.baselineBps / 1_000_000) * 10) / 10) : null, "");
  const [sustain, setSustain, sustainD] = useDraft(f ? String(f.config.sustainSecs) : null, "");
  const [release, setRelease, releaseD] = useDraft(f ? String(Math.round(f.config.releaseSecs / 60)) : null, "");
  const [detect, setDetect, detectD] = useDraft(f ? f.config.throughputDetect : null, true);
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      const res = await apiFetch<FailoverStatus>("/api/v1/failover/config", {
        method: "POST",
        body: JSON.stringify({
          throughputDetect: detect,
          baselineBps: Math.round((Number(mbps) || 0) * 1_000_000),
          sustainSecs: Math.round(Number(sustain) || 0),
          releaseSecs: Math.round((Number(release) || 0) * 60),
        }),
      });
      setFailover(res);
      for (const x of [mbpsD, sustainD, releaseD, detectD]) x.reset();
      push("Failover detection saved", "success");
    } catch (e) {
      push("Couldn't save failover detection", "error", e instanceof Error ? e.message : undefined);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="lg:col-span-12 min-w-0">
      <CardHeader
        title="Failover awareness"
        subtitle="When this modem carries production traffic, it holds back its own disruptive work"
        icon={<ShieldAlert className="h-4 w-4" />}
        action={<Badge variant={f?.active ? "warning" : "success"} dot>{f?.active ? "Carrying failover traffic" : "Standby"}</Badge>}
      />
      <div className="grid gap-5 lg:grid-cols-12">
        <div className="lg:col-span-7 space-y-4">
          <Switch
            checked={detect}
            onChange={setDetect}
            label="Detect from traffic"
            description="Without an upstream router hint, sustained cellular traffic above the baseline counts as failover"
          />
          <div className={cn("grid gap-3 sm:grid-cols-3", !detect && "opacity-50")}>
            <Field label="Baseline" htmlFor="qm-fo-mbps" hint="Mbit/s, down + up">
              <Input id="qm-fo-mbps" type="number" min={0.1} step={0.1} value={mbps} onChange={(e) => setMbps(e.target.value)} disabled={!detect} className="qm-tabular" />
            </Field>
            <Field label="Above it for" htmlFor="qm-fo-sustain" hint="Seconds">
              <Input id="qm-fo-sustain" type="number" min={10} value={sustain} onChange={(e) => setSustain(e.target.value)} disabled={!detect} className="qm-tabular" />
            </Field>
            <Field label="Quiet for" htmlFor="qm-fo-release" hint="Minutes to return to standby">
              <Input id="qm-fo-release" type="number" min={1} value={release} onChange={(e) => setRelease(e.target.value)} disabled={!detect} className="qm-tabular" />
            </Field>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-[12px] text-muted qm-tabular">
              Now {formatBitrate(f?.avgBps ?? 0)}
              {f?.hint ? ` · Router hint "${f.hint.role}" ${f.hint.fresh ? `${f.hint.ageSecs} s ago` : "(expired)"}` : " · no router hint"}
            </span>
            <Button variant="primary" onClick={() => void save()} disabled={busy || !f}>
              {busy ? "Saving…" : "Save detection"}
            </Button>
          </div>
        </div>
        <div className="lg:col-span-5 qm-subcard p-4 text-[12.5px] text-ink-2 space-y-2">
          <div className="font-semibold text-ink">While carrying failover traffic</div>
          <ul className="list-disc space-y-1 pl-4">
            <li>The scheduled reboot waits until the link has been quiet for 10 minutes (and is skipped after 6 hours).</li>
            <li>The cell-lock schedule, MBN/APN realignment and LinkWatch resets are held.</li>
            <li>Surveys, updates, speedtests, band and cell locks and reboots ask before running.</li>
            <li>External router IPC recovery commands always run.</li>
          </ul>
        </div>
      </div>
    </Card>
  );
}
