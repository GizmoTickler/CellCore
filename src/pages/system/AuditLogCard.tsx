import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { RefreshCw, ScrollText } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Input, Select, Skeleton } from "../../components/ui";
import { DataTable, EmptyRow, LoadError, Notice, Td } from "../admin/shared";

interface AuditEntry {
  id: number;
  ts: number;
  kind: "http" | "event";
  method: string;
  route: string;
  status: number;
  peer: string;
  auth: "session" | "token" | "ipc" | "system";
  tokenName?: string;
  summary: string;
}

interface TokenReads {
  tokenName: string;
  count: number;
  errors: number;
  lastTs: number;
  lastRoute: string;
  lastPeer: string;
}

interface AuthFailure {
  peer: string;
  count: number;
  firstTs: number;
  lastTs: number;
  lastRoute: string;
}

function statusBadge(e: AuditEntry) {
  if (e.kind === "event") return <Badge variant="neutral">event</Badge>;
  const v = e.status >= 500 ? "danger" : e.status >= 400 ? "warning" : "success";
  return <Badge variant={v}>{e.status}</Badge>;
}

function fmtTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function AuditLogCard() {
  const [auth, setAuth] = useState("");
  const [status, setStatus] = useState("");
  const [text, setText] = useState("");
  const [search, setSearch] = useState("");
  useEffect(() => {
    const t = window.setTimeout(() => setSearch(text.trim()), 300);
    return () => window.clearTimeout(t);
  }, [text]);

  const params = useMemo(() => {
    const p = new URLSearchParams({ limit: "200" });
    if (auth) p.set("auth", auth);
    if (status) p.set("status", status);
    if (search) p.set("q", search);
    return p.toString();
  }, [auth, status, search]);

  const q = useQuery({
    queryKey: ["security", "audit", params],
    queryFn: () => apiFetch<{ entries: AuditEntry[]; retained: number; authFailures: AuthFailure[]; authFailuresOther: number; tokenReads: TokenReads[] }>(`/api/v1/audit?${params}`),
    refetchInterval: 30_000,
  });
  const entries = q.data?.entries ?? [];
  const failures = q.data?.authFailures ?? [];
  const otherFailures = q.data?.authFailuresOther ?? 0;
  const tokenReads = q.data?.tokenReads ?? [];

  return (
    <Card className="min-w-0">
      <CardHeader
        title="Audit log"
        subtitle={`Every change made through the API, external IPC recovery actions and firewall rollbacks${q.data ? ` · ${q.data.retained} kept` : ""}`}
        icon={<ScrollText className="h-4 w-4" />}
        action={
          <Button size="sm" variant="ghost" onClick={() => void q.refetch()} disabled={q.isFetching} aria-label="Refresh audit log">
            <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} /> Refresh
          </Button>
        }
      />
      <div className="mb-4 grid gap-2 sm:grid-cols-[10rem_10rem_1fr]">
        <Select value={auth} onChange={(e) => setAuth(e.target.value)} aria-label="Filter by caller">
          <option value="">Any caller</option>
          <option value="session">Browser session</option>
          <option value="token">API token</option>
          <option value="ipc">External IPC</option>
          <option value="system">System</option>
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by result">
          <option value="">Any result</option>
          <option value="ok">Succeeded</option>
          <option value="error">Failed</option>
        </Select>
        <Input value={text} onChange={(e) => setText(e.target.value)} placeholder="Search route or details" aria-label="Search audit log" />
      </div>
      {(failures.length > 0 || otherFailures > 0) && (
        <Notice tone="warn" title="Rejected API tokens" className="mb-3">
          {failures.slice(0, 5).map((f) => (
            <span key={f.peer} className="block">
              <span className="font-mono">{f.peer}</span>: {f.count} failed attempt{f.count === 1 ? "" : "s"}, last {fmtTime(f.lastTs)}
            </span>
          ))}
          {failures.length > 5 && <span className="block">and {failures.length - 5} more addresses</span>}
          {otherFailures > 0 && <span className="block">{otherFailures} more from untracked addresses</span>}
        </Notice>
      )}
      {tokenReads.length > 0 && (
        <Notice tone="info" title="Reads by API tokens" className="mb-3">
          {tokenReads.slice(0, 6).map((r) => (
            <span key={r.tokenName} className="block">
              <b>{r.tokenName}</b>: {r.count} read{r.count === 1 ? "" : "s"}
              {r.errors ? ` (${r.errors} refused or failed)` : ""}, last <span className="font-mono">{r.lastRoute}</span> from{" "}
              <span className="font-mono">{r.lastPeer}</span> at {fmtTime(r.lastTs)}
            </span>
          ))}
        </Notice>
      )}
      <p className="mb-3 text-[11.5px] text-muted">Passwords, SMTP secrets, tokens, keys and IMEI/ICCID/IMSI are redacted before anything is stored.</p>
      {q.isLoading ? (
        <Skeleton className="h-40" />
      ) : q.error ? (
        <LoadError error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <div className="max-h-[32rem] overflow-y-auto">
          <DataTable head={["Time", "Action", "Result", "Caller", "Details"]}>
            {entries.length === 0 && <EmptyRow cols={5}>Nothing recorded for this filter.</EmptyRow>}
            {entries.map((e) => (
              <tr key={e.id} className="align-top">
                <Td className="whitespace-nowrap qm-tabular text-ink-2">{fmtTime(e.ts)}</Td>
                <Td>
                  <span className="font-mono text-[12px]">
                    {e.kind === "http" && <span className="font-semibold text-ink">{e.method} </span>}
                    <span className="text-ink-2">{e.route}</span>
                  </span>
                </Td>
                <Td>{statusBadge(e)}</Td>
                <Td className="whitespace-nowrap">
                  <div className="text-ink-2">{e.tokenName ? `token · ${e.tokenName}` : e.auth}</div>
                  <div className="font-mono text-[11px] text-muted">{e.peer}</div>
                </Td>
                <Td>
                  <div className="max-w-[28rem] whitespace-normal break-words font-mono text-[11.5px] text-muted">{e.summary}</div>
                </Td>
              </tr>
            ))}
          </DataTable>
        </div>
      )}
    </Card>
  );
}
