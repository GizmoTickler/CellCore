import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CalendarClock } from "lucide-react";
import { Badge, Button, Card, CardHeader, Skeleton } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { ApiError } from "../../lib/api";
import { LoadError, Mono, Notice, TextArea, adminSend, errText, useAdmin } from "./shared";

interface CronLine {
  line: number;
  kind: "blank" | "comment" | "env" | "job" | "invalid";
  schedule: string | null;
  command: string | null;
  error: string | null;
}
interface CronResp {
  content: string;
  lines: CronLine[];
  cronRunning: boolean;
  cronEnabled: boolean;
}

const EXAMPLES: [string, string][] = [
  ["0 4 * * *", "every day at 04:00"],
  ["*/15 * * * *", "every 15 minutes"],
  ["30 2 * * 1-5", "02:30 on weekdays"],
  ["0 3 1 * *", "03:00 on the 1st of each month"],
];

export function CronView() {
  const q = useAdmin<CronResp>("/cron");
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const [text, setText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [problems, setProblems] = useState<CronLine[]>([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (q.data && !dirty) setText(q.data.content);
  }, [q.data, dirty]);

  // Server-side validation as you type (debounced).
  useEffect(() => {
    if (!dirty) {
      setProblems([]);
      return;
    }
    const t = window.setTimeout(() => {
      adminSend<{ valid: boolean; lines: CronLine[] }>("POST", "/cron/validate", { content: text })
        .then((r) => setProblems(r.valid ? [] : r.lines))
        .catch(() => undefined);
    }, 400);
    return () => window.clearTimeout(t);
  }, [text, dirty]);

  const jobs = useMemo(() => (q.data?.lines ?? []).filter((l) => l.kind === "job"), [q.data]);

  if (q.isLoading) return <Skeleton className="h-80" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;

  async function save() {
    setSaving(true);
    try {
      const r = await adminSend<{ jobs: number }>("PUT", "/cron", { content: text });
      toast("Crontab saved", "success", `${r.jobs} job${r.jobs === 1 ? "" : "s"} scheduled; crond reloaded.`);
      setDirty(false);
      await qc.invalidateQueries({ queryKey: ["admin", "/cron"] });
    } catch (e) {
      if (e instanceof ApiError && Array.isArray(e.data?.lines)) setProblems(e.data.lines as CronLine[]);
      toast("Not saved", "error", errText(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      <Card className="min-w-0 lg:col-span-8">
        <CardHeader
          title="Root crontab"
          subtitle="/etc/crontabs/root · busybox crond"
          icon={<CalendarClock className="h-4 w-4" />}
          action={
            <Badge variant={q.data.cronRunning ? "success" : "warning"} dot>
              crond {q.data.cronRunning ? "running" : "stopped"}
            </Badge>
          }
        />
        <div className="space-y-3">
          <TextArea
            rows={12}
            className="font-mono text-[12.5px] leading-relaxed"
            value={text}
            spellCheck={false}
            placeholder={"# minute hour day month weekday command\n0 4 * * * /sbin/reboot"}
            onChange={(e) => {
              setText(e.target.value);
              setDirty(true);
            }}
            aria-label="Crontab"
          />
          {problems.length > 0 && (
            <Notice tone="danger" title="Fix these lines before saving">
              <ul className="space-y-0.5">
                {problems.map((p) => (
                  <li key={p.line}>{p.line > 0 ? `Line ${p.line}: ${p.error}` : p.error}</li>
                ))}
              </ul>
            </Notice>
          )}
          {!q.data.cronRunning && jobs.length > 0 && (
            <Notice tone="warn">crond is not running, so these jobs will not fire. Start or enable “cron” in Services.</Notice>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            {dirty && (
              <Button variant="ghost" onClick={() => setDirty(false)} disabled={saving}>
                Discard
              </Button>
            )}
            <Button variant="primary" onClick={save} disabled={!dirty || saving || problems.length > 0}>
              {saving ? "Saving…" : "Save crontab"}
            </Button>
          </div>
        </div>
      </Card>
      <Card className="min-w-0 lg:col-span-4">
        <CardHeader title="Scheduled now" subtitle={`${jobs.length} job${jobs.length === 1 ? "" : "s"}`} />
        <ul className="space-y-2.5">
          {jobs.length === 0 && <li className="text-[13px] text-muted">Nothing scheduled.</li>}
          {jobs.map((j) => (
            <li key={j.line} className="qm-subcard p-3">
              <Mono className="text-ember-ink">{j.schedule}</Mono>
              <div className="mt-1">
                <Mono className="text-ink-2">{j.command}</Mono>
              </div>
            </li>
          ))}
        </ul>
        <div className="mt-5 space-y-1.5 border-t border-line pt-4 text-[12px] text-muted">
          <div className="font-semibold text-ink-2">Format</div>
          {EXAMPLES.map(([s, t]) => (
            <div key={s} className="flex justify-between gap-3">
              <Mono>{s}</Mono>
              <span>{t}</span>
            </div>
          ))}
          <p className="pt-1">@reboot and @daily are not supported by this crond.</p>
        </div>
      </Card>
    </div>
  );
}
