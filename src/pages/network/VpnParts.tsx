import type React from "react";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Package } from "lucide-react";
import { Badge, Button, Card, CardHeader } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";
import { Pre, errText } from "../admin/shared";
import { vpnPost, type PkgJobView } from "./vpn-api";

/** Install / update one VPN package from the opkg feeds; progress of the detached job. */
export function PackageCard({
  title,
  packages,
  job,
  queryKey,
}: {
  title: string;
  packages: Array<{ name: string; installed: string | null | undefined; why: string }>;
  job: PkgJobView | undefined;
  queryKey: unknown[];
}) {
  const toast = useToastStore((s) => s.push);
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const running = job?.job?.state === "running";

  async function start(name: string, action: "install" | "upgrade") {
    setBusy(name);
    try {
      await vpnPost("/packages", { package: name, action });
      toast(`${action === "install" ? "Installing" : "Updating"} ${name}`, "info", "This runs in the background; the log below follows it.");
      await qc.invalidateQueries({ queryKey });
    } catch (e) {
      toast(`Could not start ${name}`, "error", errText(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card className="min-w-0">
      <CardHeader title={title} subtitle="From the configured opkg feeds" icon={<Package className="h-4 w-4" />} />
      <ul className="space-y-3">
        {packages.map((p) => (
          <li key={p.name} className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[12.5px] text-ink">{p.name}</span>
                {p.installed ? <Badge variant="success">{p.installed}</Badge> : <Badge>not installed</Badge>}
              </div>
              <div className="text-[12px] text-muted mt-0.5">{p.why}</div>
            </div>
            <Button size="sm" variant={p.installed ? "secondary" : "tier3"} disabled={running || busy !== null} onClick={() => start(p.name, p.installed ? "upgrade" : "install")}>
              {p.installed ? "Update" : "Install"}
            </Button>
          </li>
        ))}
      </ul>
      {job?.job && (
        <div className="mt-4 space-y-2">
          <div className="flex items-center gap-2 text-[12.5px] text-ink-2">
            <span className="font-semibold">Last job:</span>
            <span className="font-mono">
              {job.job.action} {job.job.package}
            </span>
            <Badge variant={job.job.state === "succeeded" ? "success" : job.job.state === "running" ? "info" : "danger"} dot={job.job.state === "running"}>
              {job.job.state}
            </Badge>
          </div>
          {job.log.length > 0 && <Pre className="max-h-48">{job.log.join("\n")}</Pre>}
        </div>
      )}
    </Card>
  );
}

/** Label/value tile used by both VPN views. */
export function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="qm-subcard p-3.5 min-w-0">
      <dt className="text-[11.5px] font-semibold text-muted">{label}</dt>
      <dd className="mt-1.5 text-[14px] font-semibold text-ink break-words qm-tabular">{children}</dd>
    </div>
  );
}
