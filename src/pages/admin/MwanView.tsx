import { GitFork } from "lucide-react";
import { formatDuration } from "../../lib/utils";
import { Badge, Card, CardHeader, Skeleton } from "../../components/ui";
import { DataTable, LoadError, Mono, Notice, Td, useAdmin } from "./shared";

interface MwanIface {
  name: string;
  status: string;
  enabled: boolean;
  up: boolean;
  uptime: number;
  score: number;
  lost: number;
  trackIps: { ip: string; status: string; latency: number; packetloss: number }[];
}
interface MwanResp {
  available: boolean;
  interfaces: MwanIface[];
  policies: { family: string; name: string; members: { interface: string; percent: number }[] }[];
  config: { id: string; type: string; options: Record<string, string | string[]> }[];
}

const STATUS: Record<string, "success" | "warning" | "danger" | "neutral"> = { online: "success", connecting: "warning", disconnecting: "warning", offline: "danger", notracking: "neutral", disabled: "neutral" };

export function MwanView() {
  const q = useAdmin<MwanResp>("/mwan3", { refetchInterval: 10000 });
  if (q.isLoading) return <Skeleton className="h-96" />;
  if (q.error || !q.data) return <LoadError error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data;
  const enabled = d.interfaces.filter((i) => i.enabled);
  const online = enabled.filter((i) => i.status === "online");

  return (
    <div className="space-y-5">
      <Notice tone="danger" title="Read-only on purpose">
        mwan3 is kept on this gateway because the QSDK data path relies on its routing tables and marks. Editing it can take the cellular WAN down, so this view only
        shows status and config. Change it from a shell only if you know what QCMAP expects.
      </Notice>
      {!d.available && <Notice tone="warn">mwan3 is not answering on ubus (service stopped?). Config is shown below.</Notice>}

      <Card>
        <CardHeader
          title="Interfaces"
          subtitle={`${online.length} of ${enabled.length} tracked interfaces online`}
          icon={<GitFork className="h-4 w-4" />}
        />
        <DataTable head={["Interface", "Status", "Uptime", "Score", "Lost", "Tracking"]}>
          {d.interfaces.map((i) => (
            <tr key={i.name} className={i.enabled ? "" : "text-muted"}>
              <Td className={i.enabled ? "font-semibold text-ink" : "font-semibold text-muted"}>{i.name}</Td>
              <Td>
                <Badge variant={STATUS[i.status] ?? "neutral"} dot>
                  {i.status}
                </Badge>
              </Td>
              <Td num>{i.up ? formatDuration(i.uptime) : "—"}</Td>
              <Td num>{i.score}</Td>
              <Td num>{i.lost}</Td>
              <Td className="text-[12px] text-muted">{i.trackIps.length ? i.trackIps.map((t) => `${t.ip} (${t.status})`).join(", ") : "—"}</Td>
            </tr>
          ))}
        </DataTable>
      </Card>

      <div className="grid gap-5 lg:grid-cols-12">
        <Card className="min-w-0 lg:col-span-5">
          <CardHeader title="Active policies" subtitle="Where new connections go" />
          <ul className="space-y-2">
            {d.policies.map((p) => (
              <li key={`${p.family}-${p.name}`} className="qm-subcard flex items-center justify-between gap-3 p-3">
                <div>
                  <div className="text-[13px] font-semibold text-ink">{p.name}</div>
                  <div className="text-[11.5px] text-muted">{p.family}</div>
                </div>
                <div className="flex flex-wrap justify-end gap-1">
                  {p.members.length ? (
                    p.members.map((m) => (
                      <Badge key={m.interface} variant="info">
                        {m.interface} {m.percent}%
                      </Badge>
                    ))
                  ) : (
                    <Badge variant="danger">unreachable</Badge>
                  )}
                </div>
              </li>
            ))}
            {d.policies.length === 0 && <li className="text-[13px] text-muted">No policy data.</li>}
          </ul>
        </Card>
        <Card className="min-w-0 lg:col-span-7">
          <CardHeader title="Configuration" subtitle="/etc/config/mwan3 (read-only)" />
          <div className="space-y-2">
            {d.config.map((s) => (
              <details key={s.id} className="qm-subcard p-3">
                <summary className="cursor-pointer text-[13px]">
                  <span className="font-semibold text-ink">{s.id}</span> <span className="text-muted">· {s.type}</span>
                </summary>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[12px]">
                  {Object.entries(s.options).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="text-muted">{k}</dt>
                      <dd>
                        <Mono>{Array.isArray(v) ? v.join(" ") : v}</Mono>
                      </dd>
                    </div>
                  ))}
                </dl>
              </details>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
