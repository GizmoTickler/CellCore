import { useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { Badge, Button, Card, CardHeader, Input, SegmentedTabs, Select } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { Field } from "../system/parts";
import { ADMIN, Pre, adminSend, errText } from "./shared";

type Tool = "ping" | "traceroute" | "nslookup";
interface JobChunk {
  chunk: string;
  offset: number;
  done: boolean;
  exitCode: number | null;
  timedOut: boolean;
  truncated: boolean;
  elapsedMs: number;
}

const HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$|^[0-9a-fA-F:.]+$/;

export function ToolsView() {
  const toast = useToastStore((s) => s.push);
  const [tool, setTool] = useState<Tool>("ping");
  const [host, setHost] = useState("1.1.1.1");
  const [family, setFamily] = useState("auto");
  const [count, setCount] = useState("4");
  const [server, setServer] = useState("");
  const [out, setOut] = useState("");
  const [job, setJob] = useState<{ id: number; argv: string[] } | null>(null);
  const [status, setStatus] = useState<JobChunk | null>(null);
  const offset = useRef(0);
  const pre = useRef<HTMLDivElement>(null);

  // Poll the running job for new output.
  useEffect(() => {
    if (!job) return;
    let alive = true;
    const tick = async () => {
      try {
        const r = await apiFetch<JobChunk>(`${ADMIN}/diag/jobs/${job.id}?offset=${offset.current}`);
        if (!alive) return;
        offset.current = r.offset;
        if (r.chunk) setOut((o) => o + r.chunk);
        setStatus(r);
        if (!r.done) window.setTimeout(tick, 700);
      } catch (e) {
        if (alive) setStatus((s) => (s ? { ...s, done: true } : s));
        toast("Lost track of the job", "error", errText(e));
      }
    };
    void tick();
    return () => {
      alive = false;
    };
  }, [job, toast]);

  useEffect(() => {
    pre.current?.querySelector("pre")?.scrollTo({ top: 1e9 });
  }, [out]);

  const valid = HOST_RE.test(host.trim()) && !host.trim().startsWith("-");
  const running = !!job && !status?.done;

  async function run() {
    setOut("");
    setStatus(null);
    offset.current = 0;
    try {
      const r = await adminSend<{ id: number; argv: string[] }>("POST", "/diag/run", {
        tool,
        host: host.trim(),
        family,
        count: Number(count) || 4,
        server: server.trim() || undefined,
      });
      setJob(r);
    } catch (e) {
      toast("Could not start", "error", errText(e));
    }
  }

  return (
    <Card>
      <CardHeader
        title="Network tools"
        subtitle="Runs on the gateway itself, through the cellular WAN"
        action={
          <SegmentedTabs
            value={tool}
            onChange={setTool}
            options={[
              { id: "ping", label: "Ping" },
              { id: "traceroute", label: "Traceroute" },
              { id: "nslookup", label: "DNS lookup" },
            ]}
          />
        }
      />
      <form
        className="grid gap-3 sm:grid-cols-[1fr_auto_auto_auto] sm:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid && !running) void run();
        }}
      >
        <Field label="Host or IP" htmlFor="tool-host">
          <Input id="tool-host" value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="off" spellCheck={false} aria-invalid={!valid} />
        </Field>
        {tool !== "nslookup" ? (
          <Field label="Family" htmlFor="tool-fam">
            <Select id="tool-fam" value={family} onChange={(e) => setFamily(e.target.value)}>
              <option value="auto">Auto</option>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
            </Select>
          </Field>
        ) : (
          <Field label="DNS server" htmlFor="tool-srv">
            <Input id="tool-srv" value={server} onChange={(e) => setServer(e.target.value)} placeholder="system" />
          </Field>
        )}
        {tool === "ping" ? (
          <Field label="Count" htmlFor="tool-count">
            <Select id="tool-count" value={count} onChange={(e) => setCount(e.target.value)}>
              {["1", "4", "10"].map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </Field>
        ) : (
          <span className="hidden sm:block" />
        )}
        <Button type="submit" variant="primary" size="lg" className="h-10" disabled={!valid || running}>
          {running ? <Square className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          {running ? "Running…" : "Run"}
        </Button>
      </form>
      <div ref={pre} className="mt-4 space-y-2">
        {job && (
          <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted">
            <span className="font-mono">{job.argv.join(" ")}</span>
            {status?.done &&
              (status.timedOut ? (
                <Badge variant="warning">Stopped after time limit</Badge>
              ) : (
                <Badge variant={status.exitCode === 0 ? "success" : "danger"}>exit {status.exitCode ?? "?"}</Badge>
              ))}
            {status?.truncated && <Badge variant="warning">Output truncated</Badge>}
          </div>
        )}
        <Pre className="min-h-40">{out || (running ? "…" : "Output appears here.")}</Pre>
      </div>
    </Card>
  );
}
