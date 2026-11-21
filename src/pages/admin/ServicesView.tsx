import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Play, Power, PowerOff, RotateCw, Search, Square } from "lucide-react";
import { Badge, Button, Card, CardHeader, Input, SegmentedTabs, Skeleton } from "../../components/ui";
import { DataTable, EmptyRow, LoadError, Notice, Td, TextArea, adminSend, useAdmin, useGuarded } from "./shared";

type Protection = "none" | "critical" | "locked" | "blocked";
interface Svc {
  name: string;
  enabled: boolean;
  running: boolean;
  start: number | null;
  protection: Protection;
}

const PROT: Record<Protection, { label: string; variant: "neutral" | "warning" | "danger" | "plum" } | null> = {
  none: null,
  critical: { label: "Critical", variant: "warning" },
  locked: { label: "Platform", variant: "danger" },
  blocked: { label: "CellCore", variant: "plum" },
};

const ACTION_TEXT: Record<string, string> = {
  start: "starts",
  stop: "stops",
  restart: "restarts",
  enable: "will start at boot",
  disable: "will no longer start at boot",
};

function LocalStartupTab({ guard }: { guard: ReturnType<typeof useGuarded> }) {
  const q = useAdmin<{ path: string; exists: boolean; content: string; maxBytes: number }>("/services/rc-local");
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (q.data && !dirty) setText(q.data.content);
  }, [q.data, dirty]);

  if (q.isLoading) return <Skeleton className="h-80" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;

  const save = () =>
    guard.run({
      title: "Save Local Startup (/etc/rc.local)?",
      body: (
        <p>
          Commands in <b className="font-mono">/etc/rc.local</b> execute as root at the end of boot. Keep <b className="font-mono">exit 0</b> at the bottom.
        </p>
      ),
      confirmLabel: "Save",
      tone: "danger",
      action: (confirm) => adminSend("PUT", "/services/rc-local", { content: text, confirm }),
      success: "Local startup saved",
      onDone: () => {
        setDirty(false);
        void qc.invalidateQueries({ queryKey: ["admin", "/services/rc-local"] });
      },
    });

  return (
    <div className="space-y-4">
      <Notice tone="warn">
        Lines here run as root on boot before <span className="font-mono">exit 0</span>. Avoid blocking foreground commands without backgrounding them, or the boot sequence may stall.
      </Notice>
      <Card>
        <CardHeader title="Local Startup" subtitle={`${q.data.path} · max ${q.data.maxBytes} bytes`} />
        <div className="space-y-3">
          <TextArea
            rows={14}
            className="font-mono text-[12.5px] leading-relaxed"
            value={text}
            spellCheck={false}
            placeholder={"# Put your custom commands here that should be executed once\n# the system init finished.\n\nexit 0"}
            onChange={(e) => {
              setText(e.target.value);
              setDirty(true);
            }}
            aria-label="Local startup script"
          />
          <div className="flex flex-wrap justify-end gap-2">
            {dirty && (
              <Button
                variant="ghost"
                onClick={() => {
                  setText(q.data?.content ?? "");
                  setDirty(false);
                }}
              >
                Discard
              </Button>
            )}
            <Button variant="primary" onClick={save}>
              Save /etc/rc.local
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

export function ServicesView() {
  const q = useAdmin<{ services: Svc[] }>("/services");
  const qc = useQueryClient();
  const guard = useGuarded();
  const [section, setSection] = useState<"scripts" | "rc-local">("scripts");
  const [term, setTerm] = useState("");
  const [filter, setFilter] = useState<"all" | "running" | "enabled" | "stopped">("all");

  const list = useMemo(() => {
    const t = term.trim().toLowerCase();
    return (q.data?.services ?? []).filter(
      (s) =>
        (!t || s.name.toLowerCase().includes(t)) &&
        (filter === "all" || (filter === "running" && s.running) || (filter === "enabled" && s.enabled) || (filter === "stopped" && s.enabled && !s.running))
    );
  }, [q.data, term, filter]);

  const tabBar = (
    <div className="flex items-center justify-between gap-3">
      <SegmentedTabs
        value={section}
        onChange={setSection}
        options={[
          { id: "scripts", label: "Init Scripts", badge: q.data?.services.length },
          { id: "rc-local", label: "Local Startup" },
        ]}
      />
    </div>
  );

  if (section === "rc-local") {
    return (
      <div className="space-y-5">
        {tabBar}
        <LocalStartupTab guard={guard} />
        {guard.modal}
      </div>
    );
  }

  if (q.isLoading) {
    return (
      <div className="space-y-5">
        {tabBar}
        <Skeleton className="h-96" />
      </div>
    );
  }
  if (q.error || !q.data) {
    return (
      <div className="space-y-5">
        {tabBar}
        <LoadError error={q.error} onRetry={() => q.refetch()} />
      </div>
    );
  }
  const all = q.data.services;

  const act = (s: Svc, action: string) =>
    guard.run({
      title: `${action[0].toUpperCase()}${action.slice(1)} ${s.name}?`,
      body: (
        <>
          <p>
            <b className="font-mono">{s.name}</b> {ACTION_TEXT[action]}.
          </p>
          {s.protection === "critical" && <p>This service carries SSH, DNS/DHCP, the firewall, routing or the web server. Stopping it can cut you off.</p>}
          {s.protection === "locked" && <p>This is modem or data-path plumbing. Restarting it drops the cellular link for a while.</p>}
        </>
      ),
      confirmLabel: action[0].toUpperCase() + action.slice(1),
      tone: action === "start" || action === "enable" ? "primary" : "danger",
      action: (confirm) => adminSend("POST", "/services/action", { name: s.name, action, confirm }),
      success: `${s.name}: ${action} done`,
      onDone: () => void qc.invalidateQueries({ queryKey: ["admin", "/services"] }),
    });

  const btn = (s: Svc, action: string, icon: React.ReactNode, label: string) => {
    const blocked = s.protection === "blocked" || (s.protection === "locked" && (action === "stop" || action === "disable"));
    return (
      <Button variant="ghost" size="sm" className="px-2" title={blocked ? "Protected" : label} aria-label={`${label} ${s.name}`} disabled={blocked} onClick={() => act(s, action)}>
        {icon}
      </Button>
    );
  };

  return (
    <div className="space-y-5">
      {tabBar}
      <Notice tone="info">
        Services marked <b>Platform</b> keep the modem and data path alive: they cannot be stopped or disabled here, and restarting one asks you to type its name.{" "}
        <b>Critical</b> services ask for the same before any stop or restart.
      </Notice>
      <Card>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative min-w-0 flex-1 basis-56">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <Input className="pl-9" placeholder="Filter services" value={term} onChange={(e) => setTerm(e.target.value)} aria-label="Filter services" />
          </div>
          <SegmentedTabs
            value={filter}
            onChange={setFilter}
            options={[
              { id: "all", label: "All", badge: all.length },
              { id: "running", label: "Running", badge: all.filter((s) => s.running).length },
              { id: "enabled", label: "At boot", badge: all.filter((s) => s.enabled).length },
              { id: "stopped", label: "Down", badge: all.filter((s) => s.enabled && !s.running).length },
            ]}
          />
        </div>
        <DataTable head={["Service", "Boot", "State", "Actions"]}>
          {list.length === 0 && <EmptyRow cols={4}>No services match.</EmptyRow>}
          {list.map((s) => (
            <tr key={s.name}>
              <Td>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[12.5px] text-ink">{s.name}</span>
                  {PROT[s.protection] && <Badge variant={PROT[s.protection]!.variant}>{PROT[s.protection]!.label}</Badge>}
                </div>
              </Td>
              <Td>{s.enabled ? <Badge variant="info">Enabled{s.start != null ? ` · ${s.start}` : ""}</Badge> : <span className="text-muted text-[12px]">Disabled</span>}</Td>
              <Td>
                <Badge variant={s.running ? "success" : s.enabled ? "warning" : "neutral"} dot>
                  {s.running ? "Running" : "Stopped"}
                </Badge>
              </Td>
              <Td>
                <div className="flex items-center">
                  {s.running ? btn(s, "stop", <Square className="h-3.5 w-3.5" />, "Stop") : btn(s, "start", <Play className="h-3.5 w-3.5" />, "Start")}
                  {btn(s, "restart", <RotateCw className="h-3.5 w-3.5" />, "Restart")}
                  {s.enabled ? btn(s, "disable", <PowerOff className="h-3.5 w-3.5" />, "Disable at boot") : btn(s, "enable", <Power className="h-3.5 w-3.5" />, "Enable at boot")}
                </div>
              </Td>
            </tr>
          ))}
        </DataTable>
      </Card>
      {guard.modal}
    </div>
  );
}
