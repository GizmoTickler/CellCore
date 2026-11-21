import { useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Search, Zap } from "lucide-react";
import { formatBytes } from "../../lib/utils";
import { Badge, Button, Card, Input, Meter, Select, Skeleton, StatTile, Switch } from "../../components/ui";
import { DataTable, EmptyRow, LoadError, Mono, Td, adminSend, useAdmin, useGuarded } from "./shared";

interface Proc {
  pid: number;
  ppid: number;
  name: string;
  cmd: string;
  user: string | null;
  state: string;
  threads: number;
  cpu: number;
  rssKb: number;
  mem: number;
  starttime: number;
  kernel: boolean;
  guard: "none" | "critical" | "blocked";
}
interface ProcResp {
  processes: Proc[];
  cpus: number;
  memTotalKb: number;
  memAvailableKb: number;
  load: string[];
}

const SIGNALS: [string, string][] = [
  ["TERM", "TERM: ask it to exit"],
  ["HUP", "HUP: reload / hang up"],
  ["INT", "INT: interrupt"],
  ["KILL", "KILL: force kill now"],
  ["USR1", "USR1"],
  ["USR2", "USR2"],
  ["STOP", "STOP: pause"],
  ["CONT", "CONT: resume"],
];

export function ProcessesView() {
  const [live, setLive] = useState(true);
  const q = useAdmin<ProcResp>("/processes", { refetchInterval: live ? 5000 : false });
  const qc = useQueryClient();
  const guard = useGuarded();
  const [term, setTerm] = useState("");
  const [showKernel, setShowKernel] = useState(false);
  // The guarded modal captures its body once, so the chosen signal lives in a ref.
  const sigRef = useRef("TERM");

  const rows = useMemo(() => {
    const t = term.trim().toLowerCase();
    return (q.data?.processes ?? []).filter((p) => (showKernel || !p.kernel) && (!t || p.cmd.toLowerCase().includes(t) || p.name.toLowerCase().includes(t) || String(p.pid) === t));
  }, [q.data, term, showKernel]);

  if (q.isLoading) return <Skeleton className="h-96" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const usedPct = 100 - (d.memAvailableKb / Math.max(1, d.memTotalKb)) * 100;
  const cpuSum = d.processes.reduce((a, p) => a + p.cpu, 0);

  const signal = (p: Proc) => {
    sigRef.current = "TERM";
    guard.run({
      title: `Signal ${p.name} (PID ${p.pid})?`,
      body: <SignalBody p={p} onSig={(v) => (sigRef.current = v)} />,
      confirmLabel: "Send signal",
      action: (confirm) => adminSend("POST", "/processes/signal", { pid: p.pid, starttime: p.starttime, signal: sigRef.current, confirm }),
      success: `Signal sent to ${p.name}`,
      onDone: () => void qc.invalidateQueries({ queryKey: ["admin", "/processes"] }),
    });
  };

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Load (1/5/15 min)" value={d.load.join(" · ") || "—"} sub={`${d.cpus} CPU cores`} />
        <StatTile label="CPU in use" value={`${Math.min(100, cpuSum).toFixed(0)}%`} sub="of all cores, last 0.5 s" tone={cpuSum > 80 ? "amber" : "neutral"} />
        <StatTile label="Memory used" value={`${usedPct.toFixed(0)}%`} sub={`${formatBytes(d.memAvailableKb * 1024, 0)} available`} tone={usedPct > 85 ? "amber" : "neutral"} />
        <StatTile label="Processes" value={String(d.processes.filter((p) => !p.kernel).length)} sub={`${d.processes.filter((p) => p.kernel).length} kernel threads`} />
      </div>
      <Card>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative min-w-0 flex-1 basis-56">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <Input className="pl-9" placeholder="Filter by name, command or PID" value={term} onChange={(e) => setTerm(e.target.value)} aria-label="Filter processes" />
          </div>
          <div className="flex items-center gap-4">
            <Switch label="Kernel" checked={showKernel} onChange={setShowKernel} ariaLabel="Show kernel threads" />
            <Switch label="Live" checked={live} onChange={setLive} ariaLabel="Refresh every 5 seconds" />
          </div>
        </div>
        <DataTable head={["PID", "Process", "User", "CPU", "Memory", ""]}>
          {rows.length === 0 && <EmptyRow cols={6}>No processes match.</EmptyRow>}
          {rows.slice(0, 300).map((p) => (
            <tr key={`${p.pid}-${p.starttime}`}>
              <Td num>{p.pid}</Td>
              <Td className="max-w-[min(52vw,520px)]">
                <div className="flex items-center gap-1.5">
                  <span className="font-semibold text-ink">{p.name}</span>
                  {p.guard === "critical" && <Badge variant="warning">Critical</Badge>}
                  {p.state === "Z" && <Badge variant="danger">Zombie</Badge>}
                </div>
                <Mono className="block truncate text-muted">{p.cmd}</Mono>
              </Td>
              <Td className="text-ink-2">{p.user ?? "—"}</Td>
              <Td num>
                <div className="flex items-center justify-end gap-2">
                  <Meter pct={Math.min(100, p.cpu)} thin className="hidden w-12 sm:block" tone={p.cpu > 50 ? "saffron" : "ember"} />
                  {p.cpu.toFixed(1)}%
                </div>
              </Td>
              <Td num>{formatBytes(p.rssKb * 1024, 1)}</Td>
              <Td>
                <Button variant="ghost" size="sm" className="px-2" disabled={p.guard === "blocked"} aria-label={`Signal ${p.name}`} title={p.guard === "blocked" ? "Protected" : "Send a signal"} onClick={() => signal(p)}>
                  <Zap className="h-3.5 w-3.5" />
                </Button>
              </Td>
            </tr>
          ))}
        </DataTable>
        {rows.length > 300 && <p className="mt-3 text-[12px] text-muted">Showing the busiest 300 of {rows.length}.</p>}
      </Card>
      {guard.modal}
    </div>
  );
}

function SignalBody({ p, onSig }: { p: Proc; onSig: (s: string) => void }) {
  const [v, setV] = useState("TERM");
  return (
    <>
      <p>
        <Mono>{p.cmd}</Mono>
      </p>
      <Select
        value={v}
        aria-label="Signal"
        onChange={(e) => {
          setV(e.target.value);
          onSig(e.target.value);
        }}
      >
        {SIGNALS.map(([s, label]) => (
          <option key={s} value={s}>
            {label}
          </option>
        ))}
      </Select>
      {p.guard === "critical" && <p>This process belongs to the modem, routing, DNS, SSH or this UI. Signalling it can drop the cellular link or your session.</p>}
    </>
  );
}
