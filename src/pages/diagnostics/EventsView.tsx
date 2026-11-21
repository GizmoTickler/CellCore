import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, ChevronDown, RefreshCw } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn, formatBitrate, formatBytes, formatDuration } from "../../lib/utils";
import { useObsStore } from "../../stores/obs-store";
import type { EventType, EventsResponse, ObsEvent } from "../../types/obs";
import { Badge, Button, Card, CardHeader, LiveDot, SegmentedTabs, Skeleton } from "../../components/ui";
import { EVENT_GROUPS, EVENT_META, clockTime, eventLabel, eventTone, severityLabel, type EventGroup } from "../../components/obs";
import type { HeaderFn } from "./shared";

type Range = "24h" | "7d" | "all";
type SevFilter = "all" | "attention";

const RANGE_SECS: Record<Range, number | null> = { "24h": 86_400, "7d": 7 * 86_400, all: null };

function typesFor(groups: EventGroup[]): EventType[] {
  return (Object.keys(EVENT_META) as EventType[]).filter((t) => groups.includes(EVENT_META[t].group));
}

function dayKey(ts: number): string {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function dayLabel(ts: number): string {
  const d = new Date(ts * 1000);
  const today = new Date();
  const yest = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yest.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
}

function detailEntries(detail: ObsEvent["detail"]): Array<[string, string]> {
  if (!detail || typeof detail !== "object") return [];
  return Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => {
      const label = k.replace(/([A-Z])/g, " $1").toLowerCase();
      if (typeof v === "number" && /bytes/i.test(k)) return [label, formatBytes(v, 1)];
      if (typeof v === "number" && /secs$/i.test(k)) return [label, formatDuration(v)];
      if (typeof v === "number" && /(At|ts)$/.test(k) && v > 1e9) return [label, new Date(v * 1000).toLocaleString()];
      if (typeof v === "object") return [label, JSON.stringify(v)];
      return [label, String(v)];
    });
}

/** Hour (24 h) or day (7 d / all) buckets, each tinted by its worst severity. */
function Density({ events, range }: { events: ObsEvent[]; range: Range }) {
  const now = Date.now() / 1000;
  const slots = range === "24h" ? 24 : 14;
  const width = range === "24h" ? 3600 : 86_400;
  const buckets = useMemo(() => {
    const b = Array.from({ length: slots }, () => ({ n: 0, worst: 0 }));
    for (const e of events) {
      const idx = slots - 1 - Math.floor((now - e.ts) / width);
      if (idx < 0 || idx >= slots) continue;
      b[idx].n += 1;
      b[idx].worst = Math.max(b[idx].worst, e.severity === "critical" ? 2 : e.severity === "warning" ? 1 : 0);
    }
    return b;
  }, [events, slots, width, now]);
  const max = Math.max(1, ...buckets.map((x) => x.n));
  return (
    <div>
      <div className="flex h-14 items-end gap-[3px]" role="img" aria-label={`Events per ${range === "24h" ? "hour" : "day"}`}>
        {buckets.map((b, i) => (
          <div
            key={i}
            title={`${b.n} event${b.n === 1 ? "" : "s"}`}
            className={cn(
              "flex-1 rounded-t-md min-h-[3px]",
              b.n === 0 ? "bg-line" : b.worst === 2 ? "bg-crimson" : b.worst === 1 ? "bg-saffron" : "bg-ember/70"
            )}
            style={{ height: `${b.n === 0 ? 6 : 18 + (b.n / max) * 82}%` }}
          />
        ))}
      </div>
      <div className="mt-1.5 flex justify-between text-[11px] text-muted qm-tabular">
        <span>{range === "24h" ? "24 h ago" : "14 days ago"}</span>
        <span>now</span>
      </div>
    </div>
  );
}

function TimelineItem({ e }: { e: ObsEvent }) {
  const [open, setOpen] = useState(false);
  const meta = EVENT_META[e.type];
  const Icon = meta?.icon ?? Activity;
  const tone = eventTone(e);
  const rows = detailEntries(e.detail);
  return (
    <li className="relative pl-9">
      <span className={cn("absolute left-0 top-0.5 flex h-7 w-7 items-center justify-center rounded-full border-2 border-surface bg-sunk", tone.text)}>
        <Icon className="h-3.5 w-3.5" />
      </span>
      <button
        type="button"
        onClick={() => rows.length && setOpen((v) => !v)}
        className={cn("w-full text-left min-h-[36px]", rows.length ? "cursor-pointer" : "cursor-default")}
        aria-expanded={rows.length ? open : undefined}
      >
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1">
            <div className="text-[13.5px] font-semibold text-ink leading-snug break-words">{e.title}</div>
            <div className="mt-0.5 text-[11.5px] text-muted qm-tabular">
              {clockTime(e.ts)} · {eventLabel(e.type)}
            </div>
          </div>
          {e.severity !== "info" && <Badge variant={tone.badge}>{severityLabel(e.severity)}</Badge>}
          {rows.length > 0 && <ChevronDown className={cn("mt-1 h-4 w-4 shrink-0 text-muted transition-transform", open && "rotate-180")} />}
        </div>
      </button>
      {open && rows.length > 0 && (
        <dl className="qm-subcard mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 p-3 text-[12px]">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted capitalize">{k}</dt>
              <dd className="min-w-0 break-all font-mono text-[11.5px] text-ink-2">{v}</dd>
            </div>
          ))}
        </dl>
      )}
    </li>
  );
}

export function EventsView({ header }: { header: HeaderFn }) {
  const qc = useQueryClient();
  const [range, setRange] = useState<Range>("24h");
  const [sev, setSev] = useState<SevFilter>("all");
  const [groups, setGroups] = useState<EventGroup[]>([]);
  const eventSeq = useObsStore((s) => s.eventSeq);
  const failover = useObsStore((s) => s.failover);

  const typeParam = groups.length ? typesFor(groups).join(",") : "";
  const sinceSecs = RANGE_SECS[range];
  const q = useQuery({
    queryKey: ["obs-events", range, typeParam],
    queryFn: () => {
      const p = new URLSearchParams({ limit: "1000" });
      if (sinceSecs) p.set("since", String(Math.floor(Date.now() / 1000) - sinceSecs));
      if (typeParam) p.set("type", typeParam);
      return apiFetch<EventsResponse>(`/api/v1/events?${p.toString()}`);
    },
    refetchInterval: 60_000,
  });

  // A pushed event means the list is stale.
  useEffect(() => {
    if (eventSeq > 0) void qc.invalidateQueries({ queryKey: ["obs-events"] });
  }, [eventSeq, qc]);

  const events = useMemo(() => {
    const all = q.data?.events ?? [];
    return sev === "attention" ? all.filter((e) => e.severity !== "info") : all;
  }, [q.data, sev]);

  const byDay = useMemo(() => {
    const out: Array<{ key: string; label: string; items: ObsEvent[] }> = [];
    for (const e of events) {
      const k = dayKey(e.ts);
      const last = out[out.length - 1];
      if (last && last.key === k) last.items.push(e);
      else out.push({ key: k, label: dayLabel(e.ts), items: [e] });
    }
    return out;
  }, [events]);

  const attention = (q.data?.events ?? []).filter((e) => e.severity !== "info").length;
  const total = q.data?.events.length ?? 0;
  const rangeText = range === "24h" ? "in the last 24 hours" : range === "7d" ? "in the last 7 days" : "stored";

  function toggleGroup(g: EventGroup) {
    setGroups((cur) => (cur.includes(g) ? cur.filter((x) => x !== g) : [...cur, g]));
  }

  return (
    <>
      {header(
        <>
          <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] font-semibold text-ink-2">
            <LiveDot tone="jade" /> Live
          </span>
          <Button variant="secondary" size="sm" onClick={() => void q.refetch()} disabled={q.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} /> Refresh
          </Button>
        </>
      )}

      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="lg:col-span-8">
          <CardHeader
            title={
              q.isLoading
                ? "Loading events…"
                : total === 0
                  ? `Quiet: no events ${rangeText}`
                  : `${total} event${total === 1 ? "" : "s"} ${rangeText}`
            }
            subtitle={attention > 0 ? `${attention} need${attention === 1 ? "s" : ""} attention (warning or critical)` : "Nothing above info level"}
            action={
              <SegmentedTabs
                options={[
                  { id: "24h", label: "24 h" },
                  { id: "7d", label: "7 days" },
                  { id: "all", label: "All" },
                ]}
                value={range}
                onChange={setRange}
              />
            }
          />
          <Density events={q.data?.events ?? []} range={range} />
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader
            title={failover?.active ? "Carrying failover traffic" : "Standby"}
            subtitle={
              failover?.active
                ? failover.source === "hint"
                  ? "Upstream router reported this link as active"
                  : "Sustained traffic above the baseline"
                : "Backup link idle; fiber is primary"
            }
            action={<Badge variant={failover?.active ? "warning" : "success"} dot>{failover?.active ? "Active" : "Standby"}</Badge>}
          />
          <div className="space-y-2 text-[13px] qm-tabular">
            {failover?.active && failover.episode && (
              <div className="flex justify-between gap-3">
                <span className="text-muted">This episode</span>
                <span className="font-semibold text-ink">
                  {formatDuration(Date.now() / 1000 - failover.episode.startedAt)} · {formatBytes(failover.episode.bytes, 1)}
                </span>
              </div>
            )}
            <div className="flex justify-between gap-3">
              <span className="text-muted">Cellular load</span>
              <span className="font-semibold text-ink">
                {formatBitrate(failover?.avgBps ?? 0)} <span className="text-muted">/ {formatBitrate(failover?.baselineBps ?? 0)}</span>
              </span>
            </div>
            {failover?.lastEpisode && (
              <div className="flex justify-between gap-3">
                <span className="text-muted">Last episode</span>
                <span className="font-semibold text-ink text-right">
                  {formatDuration(failover.lastEpisode.durationSecs)} · {formatBytes(failover.lastEpisode.bytes, 1)}
                </span>
              </div>
            )}
            <div className="flex justify-between gap-3">
              <span className="text-muted">Episodes recorded</span>
              <span className="font-semibold text-ink">{failover?.episodesTotal ?? 0}</span>
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <span className="qm-eyebrow mr-1">Show</span>
          {EVENT_GROUPS.map((g) => {
            const on = groups.includes(g.id);
            return (
              <button
                key={g.id}
                type="button"
                aria-pressed={on}
                onClick={() => toggleGroup(g.id)}
                className={cn(
                  "min-h-[36px] rounded-full border px-3.5 text-[12.5px] font-semibold transition cursor-pointer",
                  on ? "border-transparent bg-ink text-paper" : "border-line bg-surface text-ink-2 hover:border-line-strong"
                )}
              >
                {g.label}
              </button>
            );
          })}
          {groups.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => setGroups([])}>
              Clear
            </Button>
          )}
          <SegmentedTabs
            className="sm:ml-auto"
            options={[
              { id: "all", label: "All levels" },
              { id: "attention", label: "Warnings+" },
            ]}
            value={sev}
            onChange={setSev}
          />
        </div>

        {q.isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : q.isError ? (
          <div className="rounded-2xl bg-crimson-soft px-4 py-4 text-[13px] text-crimson-ink">
            Could not load events: {q.error instanceof Error ? q.error.message : "unknown error"}
          </div>
        ) : byDay.length === 0 ? (
          <div className="rounded-2xl bg-sunk px-4 py-8 text-center text-[13px] text-muted">No events match these filters.</div>
        ) : (
          <div className="space-y-6">
            {byDay.map((day) => (
              <section key={day.key}>
                <h4 className="qm-eyebrow mb-3">
                  {day.label} · {day.items.length}
                </h4>
                <ol className="relative space-y-4 before:absolute before:left-[13px] before:top-2 before:bottom-2 before:w-px before:bg-line">
                  {day.items.map((e) => (
                    <TimelineItem key={e.id} e={e} />
                  ))}
                </ol>
              </section>
            ))}
          </div>
        )}
        <p className="mt-5 text-[11.5px] text-muted">
          The modem keeps the latest 1,000 events ({q.data?.stored ?? 0} stored now) and saves them to flash hourly and on shutdown.
        </p>
      </Card>
    </>
  );
}
