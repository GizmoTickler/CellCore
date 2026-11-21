import { useEffect, useRef, useState } from "react";
import { CornerDownLeft, Eraser, ShieldAlert, Terminal } from "lucide-react";
import { ApiError, classifyAtCommand, sendAtCommand, type AtClass, type AtClassification } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CopyButton, Input, Kbd, LiveDot, Modal } from "../../components/ui";
import { useDiagSession, type HeaderFn } from "./shared";

const AT_PRESETS: Array<{ group: string; items: Array<{ label: string; cmd: string }> }> = [
  {
    group: "Radio & CA",
    items: [
      { label: "Serving Cell", cmd: 'AT+QENG="servingcell"' },
      { label: "CA Info", cmd: "AT+QCAINFO" },
      { label: "RSRP / SINR", cmd: "AT+QRSRP;+QSINR" },
      { label: "NR Time Adv", cmd: 'AT+QNWCFG="nr5g_time_advance"' },
    ],
  },
  {
    group: "Device Info",
    items: [
      { label: "Firmware", cmd: "AT+QGMR" },
      { label: "Model / Vendor", cmd: "AT+CGMI;+CGMM" },
      { label: "Thermals", cmd: "AT+QTEMP" },
      { label: "3GPP Release", cmd: 'AT+QNWCFG="3gpp_rel"' },
    ],
  },
  {
    group: "Bearer & Locks",
    items: [
      { label: "PDP & DNS64", cmd: "AT+CGCONTRDP" },
      { label: "WWAN Map", cmd: 'AT+QMAP="WWAN"' },
      { label: "Cell Locks", cmd: 'AT+QNWLOCK="common/4g";+QNWLOCK="common/5g"' },
      { label: "MBN List", cmd: 'AT+QMBNCFG="List"' },
    ],
  },
];

const CLASS_BADGE: Record<AtClass, { label: string; variant: "success" | "warning" | "danger" }> = {
  read: { label: "read-only", variant: "success" },
  caution: { label: "caution", variant: "warning" },
  dangerous: { label: "dangerous", variant: "danger" },
};

const CONFIRM_WORD = "SEND";

/** Colour the modem's reply: final result codes get status colour, `+TAG:` prefixes go bold. */
function ResponseLines({ text, failed }: { text: string; failed: boolean }) {
  const lines = text.replace(/\r/g, "").split("\n");
  return (
    <>
      {lines.map((line, i) => {
        const t = line.trim();
        if (t === "OK") return <div key={i} className="text-jade-ink font-semibold">OK</div>;
        if (/^(\+CM[ES] )?ERROR/.test(t)) return <div key={i} className="text-crimson-ink font-semibold">{line}</div>;
        const m = line.match(/^(\s*\+[A-Z0-9]+:)(.*)$/);
        if (m)
          return (
            <div key={i}>
              <span className="font-semibold text-ink">{m[1]}</span>
              <span className="text-ink-2">{m[2]}</span>
            </div>
          );
        return (
          <div key={i} className={cn(failed ? "text-crimson-ink" : "text-ink-2", !line && "h-[1.4em]")}>
            {line}
          </div>
        );
      })}
    </>
  );
}

export function AtConsoleView({ header }: { header: HeaderFn }) {
  const atLog = useDiagSession((s) => s.atLog);
  const recall = useDiagSession((s) => s.atRecall);
  const atInput = useDiagSession((s) => s.atDraft);
  const setAtInput = useDiagSession((s) => s.setAtDraft);
  const addAt = useDiagSession((s) => s.addAt);
  const clearAt = useDiagSession((s) => s.clearAt);

  const [running, setRunning] = useState<string | null>(null);
  const [recallIdx, setRecallIdx] = useState(-1);
  const [verdict, setVerdict] = useState<{ cmd: string; v: AtClassification | null; error?: string } | null>(null);
  const [pending, setPending] = useState<{ cmd: string; v: AtClassification | null } | null>(null);
  const [typed, setTyped] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const entries = [...atLog].reverse(); // oldest at top, like a real scrollback

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [atLog.length, running]);

  // Classify the line as it is typed (debounced): the daemon's AT guard is the single source of truth.
  useEffect(() => {
    const cmd = atInput.trim();
    if (!cmd) {
      setVerdict(null);
      return;
    }
    let alive = true;
    const t = window.setTimeout(() => {
      classifyAtCommand(cmd)
        .then((v) => alive && setVerdict({ cmd, v }))
        .catch((e) => alive && setVerdict({ cmd, v: null, error: e instanceof Error ? e.message : "Invalid command" }));
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [atInput]);

  useEffect(() => {
    // Keyboard-first on desktop; don't pop the soft keyboard on phones.
    if (window.matchMedia("(min-width: 1024px)").matches && !document.querySelector('[role="dialog"]')) inputRef.current?.focus();
  }, []);

  async function runAtCommand(cmdToRun?: string, confirmed = false) {
    const cmd = (cmdToRun ?? atInput).trim();
    if (!cmd || running) return;
    const ts = () => new Date().toLocaleTimeString([], { hour12: false });
    if (!confirmed) {
      // Ask before anything dangerous leaves the browser; the daemon enforces it again (HTTP 428).
      let v: AtClassification | null = verdict?.cmd === cmd ? verdict.v : null;
      if (!v) {
        try {
          v = await classifyAtCommand(cmd);
        } catch (e) {
          if (e instanceof ApiError && e.status === 400) {
            addAt({ cmd, resp: e.message, ok: false, latencyMs: 0, ts: ts() });
            return;
          }
        }
      }
      if (v?.class === "dangerous") {
        setTyped("");
        setPending({ cmd, v });
        return;
      }
    }
    setAtInput("");
    setRecallIdx(-1);
    setRunning(cmd);
    try {
      const res = await sendAtCommand(cmd, 12, confirmed);
      addAt({
        cmd,
        resp: res.response || res.status || "OK",
        ok: res.status === "success",
        latencyMs: res.latencyMs ?? 0,
        ts: ts(),
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 428 && !confirmed) {
        setTyped("");
        setPending({ cmd, v: (e.data?.classification as AtClassification | undefined) ?? null });
        return;
      }
      addAt({ cmd, resp: e instanceof Error ? e.message : "Error", ok: false, latencyMs: 0, ts: ts() });
    } finally {
      setRunning(null);
      if (!document.querySelector('[role="dialog"]')) inputRef.current?.focus();
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowUp") {
      if (recall.length === 0) return;
      e.preventDefault();
      const next = Math.min(recall.length - 1, recallIdx + 1);
      setRecallIdx(next);
      setAtInput(recall[next]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = recallIdx - 1;
      setRecallIdx(Math.max(-1, next));
      setAtInput(next >= 0 ? recall[next] : "");
    } else if (e.key === "Escape") {
      setAtInput("");
      setRecallIdx(-1);
    } else if (e.key.toLowerCase() === "l" && e.ctrlKey) {
      e.preventDefault();
      clearAt();
    }
  }

  const transcript = entries.map((x) => `> ${x.cmd}\n${x.resp}`).join("\n\n");

  const presetButtons = (compact: boolean) =>
    AT_PRESETS.map((grp) => (
      <div key={grp.group} className={compact ? "contents" : "space-y-2"}>
        {!compact && <div className="qm-eyebrow pt-2">{grp.group}</div>}
        <div className={compact ? "contents" : "flex flex-wrap gap-1.5"}>
        {grp.items.map((p) => (
          <button
            key={p.cmd}
            type="button"
            title={p.cmd}
            disabled={Boolean(running)}
            onClick={() => runAtCommand(p.cmd)}
            className={cn(
              "group text-left transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed",
              "shrink-0 rounded-full border border-line bg-raised px-3.5 py-2 text-[12.5px] font-semibold text-ink hover:border-ember hover:text-ember-ink"
            )}
          >
            {p.label}
          </button>
        ))}
        </div>
      </div>
    ));

  return (
    <>
      {header(
        atLog.length > 0 ? (
          <Button variant="secondary" size="sm" onClick={clearAt}>
            <Eraser className="h-3.5 w-3.5" />
            Clear screen
          </Button>
        ) : undefined
      )}

      {/* Quick commands as chips on small screens */}
      <div className="lg:hidden -mx-4 px-4 overflow-x-auto">
        <div className="flex gap-1.5 w-max pb-1">{presetButtons(true)}</div>
      </div>

      <div className="grid gap-5 lg:grid-cols-12 items-start">
        <div className="lg:col-span-8 min-w-0 space-y-2">
          <div
            className="qm-card overflow-hidden flex flex-col"
            onClick={(e) => {
              if ((e.target as HTMLElement).closest("button,a,pre")) return;
              if (!window.getSelection()?.toString()) inputRef.current?.focus();
            }}
          >
            {/* Title bar */}
            <div className="flex items-center justify-between gap-2 border-b border-line bg-sunk px-4 py-2.5">
              <div className="flex items-center gap-2 min-w-0 font-mono text-[12px] text-ink-2">
                <Terminal className="h-3.5 w-3.5 shrink-0 text-muted" />
                <span className="truncate">cellcored ▸ /dev/smd11</span>
                {running ? <LiveDot tone="ember" /> : <span className="h-2 w-2 rounded-full bg-jade" title="Ready" />}
              </div>
              {entries.length > 0 && <CopyButton value={transcript} label="Copy all" />}
            </div>

            {/* Scrollback */}
            <div ref={scrollRef} className="h-[42vh] min-h-[260px] lg:h-[480px] overflow-y-auto bg-sunk/40 px-4 py-3 font-mono text-[12.5px] leading-[1.55]">
              {entries.length === 0 && !running && (
                <div className="text-muted space-y-1">
                  <div>Modem console ready. Commands run in a priority queue alongside the daemon.</div>
                  <div>Type a command and press Enter, or pick one from Quick commands.</div>
                </div>
              )}
              {entries.map((item) => (
                <div key={item.id} className="group py-2 first:pt-0">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 break-all">
                      <span className="text-ember-ink font-bold select-none">❯ </span>
                      <span className="font-semibold text-ink">{item.cmd}</span>
                    </div>
                    <div className="flex shrink-0 items-center gap-2 text-[11px] text-muted">
                      <span className={item.ok ? "text-jade-ink" : "text-crimson-ink"}>{item.ok ? "ok" : "err"}</span>
                      <span className="qm-tabular">{item.latencyMs} ms</span>
                      <span className="hidden sm:inline qm-tabular">{item.ts}</span>
                      <CopyButton value={item.resp} className="opacity-60 group-hover:opacity-100" />
                    </div>
                  </div>
                  <pre className="mt-1 whitespace-pre-wrap break-words pl-4 font-mono text-[12.5px]">
                    <ResponseLines text={item.resp} failed={!item.ok} />
                  </pre>
                </div>
              ))}
              {running && (
                <div className="py-2">
                  <span className="text-ember-ink font-bold">❯ </span>
                  <span className="font-semibold text-ink">{running}</span>
                  <div className="pl-4 text-muted">
                    waiting for modem<span className="inline-block w-2 h-[1.1em] align-text-bottom ml-1 bg-ember qm-live-dot" />
                  </div>
                </div>
              )}
            </div>

            {/* Prompt */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void runAtCommand();
              }}
              className="flex items-center gap-2 border-t border-line bg-raised px-3 sm:px-4 py-2.5"
            >
              <span className="font-mono font-bold text-ember-ink select-none">❯</span>
              <input
                ref={inputRef}
                value={atInput}
                onChange={(e) => {
                  setAtInput(e.target.value);
                  setRecallIdx(-1);
                }}
                onKeyDown={onKeyDown}
                placeholder="AT+QENG=&quot;servingcell&quot;"
                aria-label="AT command"
                spellCheck={false}
                autoCapitalize="characters"
                autoComplete="off"
                className="min-w-0 flex-1 h-10 bg-transparent font-mono text-[13.5px] text-ink placeholder:text-muted/70 focus:outline-none"
              />
              <Button type="submit" variant="primary" size="sm" disabled={Boolean(running) || !atInput.trim()} className="h-9">
                {running ? "Running…" : "Run"}
                <CornerDownLeft className="h-3.5 w-3.5" />
              </Button>
            </form>
            {verdict && verdict.cmd === atInput.trim() && (
              <div className="flex min-w-0 items-center gap-2 border-t border-line bg-raised px-3 sm:px-4 py-2 text-[12px]" aria-live="polite">
                {verdict.v ? (
                  <>
                    <Badge variant={CLASS_BADGE[verdict.v.class].variant} dot>
                      {CLASS_BADGE[verdict.v.class].label}
                    </Badge>
                    <span className="min-w-0 truncate text-muted">
                      {verdict.v.parts.length > 1 ? `${verdict.v.parts.length} commands · ` : ""}
                      {verdict.v.reason}
                    </span>
                  </>
                ) : (
                  <>
                    <Badge variant="danger">refused</Badge>
                    <span className="min-w-0 truncate text-crimson-ink">{verdict.error}</span>
                  </>
                )}
              </div>
            )}
          </div>
          <div className="hidden sm:flex flex-wrap items-center gap-x-4 gap-y-1 px-1 text-[11.5px] text-muted">
            <span className="flex items-center gap-1"><Kbd>↵</Kbd> run</span>
            <span className="flex items-center gap-1"><Kbd>↑</Kbd><Kbd>↓</Kbd> recall</span>
            <span className="flex items-center gap-1"><Kbd>Esc</Kbd> clear line</span>
            <span className="flex items-center gap-1"><Kbd>Ctrl</Kbd><Kbd>L</Kbd> clear screen</span>
            <span className="ml-auto">Keeps the last 15 replies · 12 s timeout</span>
          </div>
        </div>

        <Card className="hidden lg:block lg:col-span-4 min-w-0 space-y-1">
          <div>
            <div className="qm-display text-[1.05rem] font-semibold text-ink">Quick commands</div>
            <p className="text-[12px] text-muted">Click to run instantly · hover to see the command</p>
          </div>
          <div className="space-y-2">{presetButtons(false)}</div>
          {recall.length > 0 && (
            <div className="mt-4 border-t border-line pt-2">
              <div className="qm-eyebrow pt-2 pb-1">Recent</div>
              {recall.slice(0, 6).map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => {
                    setAtInput(c);
                    if (!document.querySelector('[role="dialog"]')) inputRef.current?.focus();
                  }}
                  className="block w-full truncate rounded-xl px-2 py-1.5 text-left font-mono text-[12px] text-ink-2 hover:bg-sunk hover:text-ink cursor-pointer"
                  title="Put in the prompt"
                >
                  {c}
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>
      <Modal open={pending !== null} onClose={() => setPending(null)} title="Send a dangerous AT command?">
        {pending && (
          <div className="space-y-3">
            <div className="rounded-xl border border-line bg-sunk px-3 py-2 font-mono text-[12.5px] text-ink break-all">{pending.cmd}</div>
            {pending.v && (
              <ul className="space-y-1">
                {pending.v.parts
                  .filter((p) => p.class !== "read")
                  .map((p, i) => (
                    <li key={i} className="flex items-start gap-2 text-[12.5px]">
                      <Badge variant={CLASS_BADGE[p.class].variant}>{CLASS_BADGE[p.class].label}</Badge>
                      <span>
                        <span className="font-mono text-ink">{p.name}</span> {p.reason}
                      </span>
                    </li>
                  ))}
              </ul>
            )}
            <div className="rounded-xl border border-crimson/40 bg-crimson-soft p-3 space-y-2">
              <p className="flex gap-2 text-[12.5px] text-crimson-ink">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                <span>This modem is the backup WAN. The command can drop the cellular link or change modem identity until it is undone, and it is recorded in the audit log.</span>
              </p>
              <label className="block text-[12px] font-semibold text-ink-2">
                Type <span className="font-mono text-ink">{CONFIRM_WORD}</span> to continue
                <Input
                  autoFocus
                  className="mt-1.5 font-mono"
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  aria-label={`Type ${CONFIRM_WORD} to confirm`}
                />
              </label>
            </div>
            <div className="flex flex-wrap justify-end gap-2 pt-1">
              <Button variant="secondary" onClick={() => setPending(null)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                disabled={typed.trim() !== CONFIRM_WORD}
                onClick={() => {
                  const cmd = pending.cmd;
                  setPending(null);
                  void runAtCommand(cmd, true);
                }}
              >
                Send command
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}
