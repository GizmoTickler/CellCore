import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, Inbox, RefreshCw, Send, SquarePen, Trash2 } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { SMS_UNKNOWN_TIME, parseSmsTimestamp } from "../../lib/parsers";
import { cn } from "../../lib/utils";
import { useToastStore } from "../../stores/toast-store";
import type { SmsMessage } from "../../types/cellcore";
import { Button, Card, CopyButton, Input, Modal, Skeleton } from "../../components/ui";
import { LoadError } from "../admin/shared";
import { errMsg, useDiagSession, type HeaderFn } from "./shared";

interface Thread {
  key: string;
  sender: string;
  messages: Array<SmsMessage & { when: string; sortKey: string }>;
  last: string;
}

const NEW = "__new__";

function normPhone(p: string) {
  return p.replace(/[^\dA-Za-z]/g, "").replace(/^1(?=\d{10}$)/, "");
}

function initials(sender: string) {
  if (/[A-Za-z]/.test(sender)) return sender.replace(/[^A-Za-z]/g, "").slice(0, 2).toUpperCase();
  const d = sender.replace(/\D/g, "");
  return d.slice(-2) || "#";
}

function shortWhen(when: string) {
  // "2026-11-18 12:21:42" → "Nov 18 · 12:21"
  if (!when) return SMS_UNKNOWN_TIME;
  const m = when.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})/);
  if (!m) return when;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay ? m[4] : `${d.toLocaleDateString([], { month: "short", day: "numeric" })} · ${m[4]}`;
}

export function SmsView({ header }: { header: HeaderFn }) {
  const qc = useQueryClient();
  const push = useToastStore((s) => s.push);
  const sentSms = useDiagSession((s) => s.sentSms);
  const addSent = useDiagSession((s) => s.addSent);

  const [busy, setBusy] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [smsPhone, setSmsPhone] = useState("");
  const [smsBody, setSmsBody] = useState("");
  const [confirm, setConfirm] = useState<{ indices: number[]; title: string; body: string } | null>(null);

  const smsInboxQuery = useQuery({
    queryKey: ["sms-inbox"],
    queryFn: () => apiFetch<{ messages?: SmsMessage[] }>("/api/v1/sms"),
  });
  const smsMessages = smsInboxQuery.data?.messages ?? [];

  const threads = useMemo<Thread[]>(() => {
    const map = new Map<string, Thread>();
    for (const m of smsMessages) {
      const key = normPhone(m.sender) || m.sender;
      const t = map.get(key) ?? { key, sender: m.sender, messages: [], last: "" };
      const when = parseSmsTimestamp(m.timestamp);
      // undated messages sort before dated ones and never win "last"
      const sortKey = when === SMS_UNKNOWN_TIME ? "" : when;
      t.messages.push({ ...m, indices: Array.isArray(m.indices) ? m.indices : [], when, sortKey });
      if (sortKey > t.last) t.last = sortKey;
      map.set(key, t);
    }
    const out = [...map.values()];
    const first = (m: { indices: number[] }) => m.indices[0] ?? 0;
    for (const t of out) t.messages.sort((a, b) => (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : first(a) - first(b)));
    return out.sort((a, b) => (a.last < b.last ? 1 : -1));
  }, [smsMessages]);

  // On wide screens a thread is always open; on phones `selected` toggles list ↔ conversation.
  const activeKey = selected ?? threads[0]?.key ?? NEW;
  const composingNew = activeKey === NEW;
  const active = threads.find((t) => t.key === activeKey) ?? null;
  const recipient = composingNew ? smsPhone : active?.sender ?? "";
  const sentHere = sentSms.filter((s) => !composingNew && active && normPhone(s.phone) === active.key);

  const smsIsUnicode = /[^\u0000-\u007f]/.test(smsBody);
  const smsSegmentSize = smsIsUnicode ? 70 : 160;
  const smsSegments = smsBody.length === 0 ? 0 : Math.ceil(smsBody.length / smsSegmentSize);

  async function sendSms(e?: React.FormEvent) {
    e?.preventDefault();
    const phone = recipient;
    if (!phone.trim() || !smsBody.trim()) return;
    setBusy("sms-send");
    try {
      await apiFetch("/api/v1/sms", {
        method: "POST",
        body: JSON.stringify({ phone: phone.trim(), message: smsBody }),
      });
      addSent({ phone: phone.trim(), message: smsBody, ts: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false }) });
      setSmsBody("");
      await qc.invalidateQueries({ queryKey: ["sms-inbox"] });
      push("SMS sent", "success", `To ${phone.trim()}`);
      if (composingNew) {
        const k = normPhone(phone);
        if (threads.some((t) => t.key === k)) setSelected(k);
      }
    } catch (err) {
      push("SMS not sent", "error", errMsg(err, "SMS send error"));
    } finally {
      setBusy(null);
    }
  }

  async function deleteSms(raw: number[]) {
    // only real storage slots; never send null/NaN indices
    const indices = raw.filter((i) => Number.isInteger(i) && i >= 0);
    if (indices.length === 0) return;
    setBusy("sms-del");
    try {
      await apiFetch("/api/v1/sms", {
        method: "DELETE",
        body: JSON.stringify({ indices }),
      });
      await qc.invalidateQueries({ queryKey: ["sms-inbox"] });
      push(indices.length > 1 ? "Messages deleted" : "Message deleted", "success");
    } catch (err) {
      push("Delete failed", "error", errMsg(err, "Delete failed"));
    } finally {
      setBusy(null);
      setConfirm(null);
    }
  }

  function startNew() {
    setSelected(NEW);
    setSmsBody("");
  }

  return (
    <>
      {header(
        <>
          <Button variant="secondary" size="sm" onClick={() => smsInboxQuery.refetch()} aria-label="Refresh inbox">
            <RefreshCw className={cn("h-3.5 w-3.5", smsInboxQuery.isFetching && "animate-spin")} />
            Refresh
          </Button>
          <Button variant="primary" size="sm" onClick={startNew}>
            <SquarePen className="h-3.5 w-3.5" />
            New message
          </Button>
        </>
      )}

      <Card className="p-0 sm:p-0 overflow-hidden">
        <div className="grid lg:grid-cols-12 lg:h-[640px]">
          {/* ── Thread list ── */}
          <aside className={cn("lg:col-span-4 lg:border-r border-line flex-col min-h-0", selected ? "hidden lg:flex" : "flex")}>
            <div className="flex items-center justify-between gap-2 border-b border-line px-4 py-3">
              <div>
                <div className="qm-display text-[1.05rem] font-semibold text-ink">Conversations</div>
                <div className="text-[11.5px] text-muted qm-tabular">
                  {smsMessages.length} message{smsMessages.length === 1 ? "" : "s"} on the SIM
                </div>
              </div>
              {smsMessages.length > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-crimson-ink"
                  onClick={() =>
                    setConfirm({
                      indices: smsMessages.flatMap((m) => m.indices ?? []),
                      title: "Clear the whole inbox?",
                      body: `This permanently deletes all ${smsMessages.length} messages stored on the SIM / modem.`,
                    })
                  }
                  disabled={busy === "sms-del"}
                >
                  Clear all
                </Button>
              )}
            </div>
            <div className="flex-1 overflow-y-auto min-h-0">
              {smsInboxQuery.isLoading && (
                <div className="p-3 space-y-2">
                  {[0, 1, 2].map((i) => (
                    <Skeleton key={i} className="h-16" />
                  ))}
                </div>
              )}
              {smsInboxQuery.isError && !smsInboxQuery.data && (
                <div className="p-3">
                  <LoadError
                    title="Could not load SMS inbox"
                    error={smsInboxQuery.error}
                    onRetry={() => void smsInboxQuery.refetch()}
                  />
                </div>
              )}
              {!smsInboxQuery.isLoading && !smsInboxQuery.isError && threads.length === 0 && (
                <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-sunk text-muted">
                    <Inbox className="h-5 w-5" />
                  </div>
                  <div className="text-[14px] font-semibold text-ink">Inbox is empty</div>
                  <p className="text-[12.5px] text-muted">Texts sent to this SIM will show up here.</p>
                  <Button variant="tier3" size="sm" className="mt-2 lg:hidden" onClick={startNew}>
                    <SquarePen className="h-3.5 w-3.5" />
                    Write a message
                  </Button>
                </div>
              )}
              <ul className="p-2 space-y-0.5">
                {threads.map((t) => {
                  const lastMsg = t.messages[t.messages.length - 1];
                  const on = t.key === activeKey;
                  return (
                    <li key={t.key}>
                      <button
                        type="button"
                        onClick={() => setSelected(t.key)}
                        className={cn(
                          "flex w-full items-center gap-3 rounded-2xl px-3 py-2.5 text-left transition cursor-pointer",
                          on ? "bg-ember-soft" : "hover:bg-sunk"
                        )}
                      >
                        <span
                          className={cn(
                            "flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-[13px] font-bold qm-tabular",
                            on ? "bg-ember text-on-ember" : "bg-sunk text-ink-2 border border-line"
                          )}
                        >
                          {initials(t.sender)}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="flex items-baseline justify-between gap-2">
                            <span className="truncate text-[13.5px] font-semibold text-ink">{t.sender}</span>
                            <span className="shrink-0 text-[11px] text-muted qm-tabular">{shortWhen(t.last)}</span>
                          </span>
                          <span className="flex items-center gap-2">
                            <span className="truncate text-[12.5px] text-muted">{lastMsg?.text}</span>
                            {t.messages.length > 1 && (
                              <span className="ml-auto shrink-0 rounded-full border border-line bg-sunk px-1.5 text-[10.5px] font-semibold text-ink-2 qm-tabular">
                                {t.messages.length}
                              </span>
                            )}
                          </span>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </aside>

          {/* ── Conversation ── */}
          <section className={cn("lg:col-span-8 flex-col min-h-0 bg-sunk/40", selected ? "flex" : "hidden lg:flex")}>
            <div className="flex items-center gap-2 border-b border-line bg-surface px-3 sm:px-4 py-3">
              <Button variant="ghost" size="sm" className="lg:hidden px-2" onClick={() => setSelected(null)} aria-label="Back to conversations">
                <ChevronLeft className="h-4 w-4" />
              </Button>
              {composingNew ? (
                <div className="flex flex-1 items-center gap-2 min-w-0">
                  <span className="text-[13px] font-semibold text-muted">To</span>
                  <Input
                    value={smsPhone}
                    onChange={(e) => setSmsPhone(e.target.value)}
                    placeholder="+15551234567"
                    inputMode="tel"
                    aria-label="Recipient number"
                    className="font-mono"
                    autoFocus={selected === NEW}
                  />
                </div>
              ) : active ? (
                <>
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-sunk border border-line text-[12.5px] font-bold text-ink-2">
                    {initials(active.sender)}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1">
                      <span className="truncate text-[14px] font-semibold text-ink">{active.sender}</span>
                      <CopyButton value={active.sender} label="" />
                    </div>
                    <div className="text-[11.5px] text-muted qm-tabular">
                      {active.messages.length} received{sentHere.length ? ` · ${sentHere.length} sent this session` : ""}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="px-2 text-muted hover:text-crimson-ink"
                    aria-label="Delete conversation"
                    title="Delete conversation"
                    onClick={() =>
                      setConfirm({
                        indices: active.messages.flatMap((m) => m.indices),
                        title: `Delete conversation with ${active.sender}?`,
                        body: `This permanently deletes ${active.messages.length} message${active.messages.length === 1 ? "" : "s"} from the SIM / modem.`,
                      })
                    }
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </>
              ) : null}
            </div>

            <div className="flex-1 min-h-[280px] max-h-[60vh] lg:max-h-none overflow-y-auto px-3 sm:px-5 py-4 space-y-3">
              {composingNew && (
                <div className="m-auto max-w-xs py-10 text-center text-[12.5px] text-muted">
                  Enter a number above and write your message below. Replies land in Conversations.
                </div>
              )}
              {active?.messages.map((m) => (
                <div key={m.indices.join(",") || m.rawPdu || m.when} className="group flex items-end gap-1.5 max-w-[88%] sm:max-w-[75%]">
                  <div className="rounded-[1.1rem] rounded-bl-md bg-surface border border-line px-3.5 py-2.5 shadow-[var(--qm-shadow)]">
                    <p className="whitespace-pre-wrap break-words text-[13.5px] leading-relaxed text-ink">{m.text}</p>
                    <div className="mt-1 flex items-center gap-2 text-[10.5px] text-muted qm-tabular">
                      <span>{m.when}</span>
                      {m.totalParts > 1 && m.receivedParts < m.totalParts ? (
                        <span>
                          · {m.receivedParts} of {m.totalParts} parts received
                        </span>
                      ) : null}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      setConfirm({
                        indices: m.indices,
                        title: "Delete this message?",
                        body: `This permanently deletes this message from ${active.sender} on the SIM / modem.`,
                      })
                    }
                    disabled={busy === "sms-del"}
                    aria-label="Delete message"
                    title="Delete message"
                    className="mb-1 shrink-0 rounded-full p-1.5 text-muted opacity-60 hover:opacity-100 hover:text-crimson-ink hover:bg-crimson-soft cursor-pointer sm:opacity-0 sm:group-hover:opacity-100 focus:opacity-100"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              {sentHere.map((s) => (
                <div key={s.id} className="ml-auto max-w-[88%] sm:max-w-[75%] w-fit">
                  <div className="rounded-[1.1rem] rounded-br-md bg-ember-soft px-3.5 py-2.5">
                    <p className="whitespace-pre-wrap break-words text-[13.5px] leading-relaxed text-ink">{s.message}</p>
                    <div className="mt-1 text-right text-[10.5px] text-ember-ink qm-tabular">Sent {s.ts} · this session</div>
                  </div>
                </div>
              ))}
              {!composingNew && !active && !smsInboxQuery.isLoading && (
                <div className="py-16 text-center text-[13px] text-muted">Pick a conversation or start a new message.</div>
              )}
            </div>

            {/* Composer */}
            <form onSubmit={sendSms} className="border-t border-line bg-surface p-3 sm:p-4 space-y-2">
              <div className="flex items-end gap-2">
                <textarea
                  rows={2}
                  value={smsBody}
                  onChange={(e) => setSmsBody(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                      e.preventDefault();
                      void sendSms();
                    }
                  }}
                  placeholder={recipient ? `Text ${recipient}` : "Write a message"}
                  aria-label="Message body"
                  className="min-h-[44px] max-h-40 flex-1 resize-y rounded-2xl border border-line bg-raised px-3.5 py-2.5 text-[16px] sm:text-[13.5px] text-ink placeholder:text-muted/80 focus:outline-none focus:ring-4 focus:ring-ember/15 focus:border-ember"
                  required
                />
                <Button
                  type="submit"
                  variant="primary"
                  className="h-11 w-11 shrink-0 rounded-2xl px-0"
                  disabled={busy === "sms-send" || !recipient.trim() || !smsBody.trim()}
                  aria-label="Send SMS"
                  title="Send (Ctrl+Enter)"
                >
                  <Send className={cn("h-4 w-4", busy === "sms-send" && "animate-pulse")} />
                </Button>
              </div>
              <div className="flex flex-wrap justify-between gap-2 px-1 text-[11px] text-muted qm-tabular">
                <span>
                  {smsBody.length} chars · {smsSegments} {smsSegments === 1 ? "segment" : "segments"} ({smsIsUnicode ? "UCS-2" : "GSM-7"})
                </span>
                <span className="hidden sm:inline">Ctrl + Enter to send</span>
              </div>
            </form>
          </section>
        </div>
      </Card>

      <Modal open={confirm != null} onClose={() => setConfirm(null)} title={confirm?.title ?? ""}>
        <p>{confirm?.body} This can't be undone.</p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirm(null)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => confirm && deleteSms(confirm.indices)} disabled={busy === "sms-del"}>
            <Trash2 className="h-3.5 w-3.5" />
            Delete
          </Button>
        </div>
      </Modal>
    </>
  );
}
