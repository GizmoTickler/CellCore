import React, { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDownToLine, FileText, RefreshCw, Search, X } from "lucide-react";
import { cn } from "../../lib/utils";
import { Button, Card, CopyButton, Input, LiveDot, SegmentedTabs, Select, Skeleton, Switch } from "../../components/ui";
import type { SystemController } from "./useSystemController";

type Level = "error" | "warn" | "info" | "debug" | "other";

interface LogLine {
  n: number;
  raw: string;
  ts: string | null;
  level: Level;
  levelText: string | null;
  source: string | null;
  msg: string;
}

const LEVEL_MAP: Record<string, Level> = {
  emerg: "error",
  alert: "error",
  crit: "error",
  critical: "error",
  err: "error",
  error: "error",
  fatal: "error",
  panic: "error",
  warn: "warn",
  warning: "warn",
  notice: "info",
  info: "info",
  debug: "debug",
  trace: "debug",
};

// OpenWrt logread: "Wed Nov 18 10:00:00 2026 daemon.info cellcored[123]: message"
const LOGREAD_RE = /^(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) ([a-z0-9]+)\.([a-z]+) ([^:]+?):\s?(.*)$/i;
// ISO-ish or bracketed timestamp prefix
const TS_RE = /^\[?(\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\]?\s*/;
const LEVEL_RE = /(?:^|[\s[(|"])(?:level=)?"?(emerg|alert|crit|critical|err|error|fatal|panic|warn|warning|notice|info|debug|trace)"?(?=[\s\]):|,"]|$)/i;

function parseLine(raw: string, n: number): LogLine {
  const m = LOGREAD_RE.exec(raw);
  if (m) {
    const lv = LEVEL_MAP[m[3].toLowerCase()] ?? "other";
    return { n, raw, ts: m[1], level: lv, levelText: m[3].toLowerCase(), source: m[4], msg: m[5] };
  }
  let rest = raw;
  let ts: string | null = null;
  const t = TS_RE.exec(rest);
  if (t) {
    ts = t[1];
    rest = rest.slice(t[0].length);
  }
  const l = LEVEL_RE.exec(rest);
  const levelText = l ? l[1].toLowerCase() : null;
  return { n, raw, ts, level: levelText ? (LEVEL_MAP[levelText] ?? "other") : "other", levelText, source: null, msg: rest };
}

/** "Wed Nov 18 08:18:18 2026" or ISO → "08:18:18" for narrow screens. */
function shortTs(ts: string): string {
  const m = /(\d{2}:\d{2}:\d{2})/.exec(ts);
  return m ? m[1] : ts;
}

const LEVEL_STYLE: Record<Level, { pill: string; row: string; label: string }> = {
  error: { pill: "bg-crimson-soft text-crimson-ink", row: "bg-crimson/[0.06]", label: "Errors" },
  warn: { pill: "bg-saffron-soft text-saffron-ink", row: "bg-saffron/[0.06]", label: "Warnings" },
  info: { pill: "bg-ember-soft text-ember-ink", row: "", label: "Info" },
  debug: { pill: "bg-sunk text-muted", row: "", label: "Debug" },
  other: { pill: "bg-sunk text-muted", row: "", label: "Other" },
};

function Highlight({ text, term }: { text: string; term: string }) {
  if (!term) return <>{text}</>;
  const lower = text.toLowerCase();
  const needle = term.toLowerCase();
  const out: React.ReactNode[] = [];
  let i = 0;
  let k = 0;
  while (i < text.length) {
    const j = lower.indexOf(needle, i);
    if (j < 0) {
      out.push(text.slice(i));
      break;
    }
    if (j > i) out.push(text.slice(i, j));
    out.push(
      <mark key={k++} className="rounded-[3px] bg-saffron/35 px-0.5 text-ink">
        {text.slice(j, j + needle.length)}
      </mark>
    );
    i = j + needle.length;
  }
  return <>{out}</>;
}

export function LogsView({ ctl }: { ctl: SystemController }) {
  const [level, setLevel] = useState<"all" | Level>("all");
  const scroller = useRef<HTMLDivElement>(null);
  const q = ctl.logsQuery;
  const raw = q.data?.logs;

  const lines = useMemo(() => (raw ?? []).map((l, i) => parseLine(l, i + 1)), [raw]);
  const counts = useMemo(() => {
    const c: Record<Level, number> = { error: 0, warn: 0, info: 0, debug: 0, other: 0 };
    for (const l of lines) c[l.level]++;
    return c;
  }, [lines]);
  const shown = level === "all" ? lines : lines.filter((l) => l.level === level);

  // Keep the newest lines in view as the buffer refreshes.
  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [raw, level]);

  const levelOptions = [
    { id: "all" as const, label: "All", badge: lines.length },
    ...(["error", "warn", "info", "debug"] as const)
      .filter((lv) => counts[lv] > 0 || lv === "error" || lv === "warn")
      .map((lv) => ({ id: lv, label: LEVEL_STYLE[lv].label, badge: counts[lv] })),
  ];

  return (
    <Card className="p-0 sm:p-0 overflow-hidden">
      {/* Toolbar */}
      <div className="space-y-3 p-4 sm:p-5 border-b border-line">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-ember-soft text-ember-ink">
              <FileText className="h-4 w-4" />
            </div>
            <SegmentedTabs
              value={ctl.logSource}
              onChange={ctl.setLogSource}
              options={[
                { id: "system", label: "System (logread)" },
                { id: "quecmanager", label: "cellcored" },
              ]}
            />
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              {ctl.logAutoRefresh && <LiveDot tone="jade" />}
              <Switch label="Live" checked={ctl.logAutoRefresh} onChange={ctl.setLogAutoRefresh} />
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 basis-full sm:basis-auto min-w-[180px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <Input
              value={ctl.logSearch}
              onChange={(e) => ctl.setLogSearch(e.target.value)}
              placeholder="Search logs…"
              aria-label="Search logs"
              className="pl-9 pr-9 font-mono text-[12.5px]"
            />
            {ctl.logSearch && (
              <button
                type="button"
                onClick={() => ctl.setLogSearch("")}
                aria-label="Clear search"
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-full p-1 text-muted hover:bg-sunk hover:text-ink cursor-pointer"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
          <Select value={ctl.logLines} onChange={(e) => ctl.setLogLines(e.target.value)} className="w-[118px]" aria-label="Lines to fetch">
            <option value="50">Last 50</option>
            <option value="100">Last 100</option>
            <option value="250">Last 250</option>
          </Select>
          <Button variant="secondary" className="h-10 w-10 px-0" onClick={() => q.refetch()} aria-label="Refresh logs" title="Refresh">
            <RefreshCw className={cn("h-4 w-4", q.isFetching && "animate-spin")} />
          </Button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="-mx-1 max-w-full overflow-x-auto px-1">
            <SegmentedTabs value={level} onChange={setLevel} options={levelOptions} className="flex-nowrap" />
          </div>
          <div className="flex items-center gap-1 text-[12px] text-muted">
            <span className="qm-tabular">
              {shown.length} of {lines.length} lines
            </span>
            <CopyButton value={shown.map((l) => l.raw).join("\n")} label="Copy" />
          </div>
        </div>
      </div>

      {/* Viewer */}
      <div
        ref={scroller}
        className="relative max-h-[62vh] min-h-[240px] overflow-auto bg-sunk font-mono text-[12px] leading-[1.55]"
        role="log"
        aria-live="off"
      >
        {q.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-4 rounded-md" />
            ))}
          </div>
        ) : q.isError ? (
          <div className="p-6 text-center font-sans text-[13px] text-crimson-ink">
            {q.error instanceof Error ? q.error.message : "Could not load logs."}
          </div>
        ) : shown.length === 0 ? (
          <div className="p-8 text-center font-sans text-[13px] text-muted">
            {lines.length === 0 ? "No matching log entries." : `No ${LEVEL_STYLE[level as Level].label.toLowerCase()} in these lines.`}
          </div>
        ) : (
          <ol className="py-1.5">
            {shown.map((l) => (
              <li
                key={l.n}
                className={cn(
                  "grid grid-cols-[2.6rem_minmax(0,1fr)] gap-x-2 px-2 sm:px-3 py-[3px] hover:bg-ember/[0.05]",
                  LEVEL_STYLE[l.level].row
                )}
              >
                <span className="select-none pt-px text-right text-[11px] text-muted qm-tabular">{l.n}</span>
                <div className="min-w-0 break-words [overflow-wrap:anywhere]">
                  {l.ts && (
                    <span className="mr-2 text-muted" title={l.ts}>
                      <span className="hidden sm:inline">{l.ts}</span>
                      <span className="sm:hidden">{shortTs(l.ts)}</span>
                    </span>
                  )}
                  {l.levelText && (
                    <span
                      className={cn(
                        "mr-2 inline-block rounded px-1.5 text-[10.5px] font-semibold uppercase leading-[1.5]",
                        LEVEL_STYLE[l.level].pill
                      )}
                    >
                      {l.levelText}
                    </span>
                  )}
                  {l.source && <span className="mr-1.5 font-semibold text-berry-ink">{l.source}</span>}
                  <span className={cn(l.level === "error" ? "text-crimson-ink" : l.level === "debug" ? "text-muted" : "text-ink")}>
                    <Highlight text={l.msg} term={ctl.logSearch} />
                  </span>
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 px-4 sm:px-5 py-2.5 text-[11.5px] text-muted">
        <span>
          {ctl.logSource === "system" ? "OpenWrt logread ring buffer" : "cellcored in-memory log"} · IMEI and ICCID are redacted
        </span>
        <button
          type="button"
          onClick={() => scroller.current?.scrollTo({ top: scroller.current.scrollHeight, behavior: "smooth" })}
          className="inline-flex items-center gap-1 rounded-full px-2 py-1 font-semibold hover:bg-sunk hover:text-ink cursor-pointer"
        >
          <ArrowDownToLine className="h-3.5 w-3.5" /> Newest
        </button>
      </div>
    </Card>
  );
}
