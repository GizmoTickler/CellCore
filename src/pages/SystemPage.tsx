import React, { Suspense, lazy } from "react";
import { RefreshCw } from "lucide-react";
import { cn } from "../lib/utils";
import { useSubRoute } from "../stores/route-store";
import { useLiveness } from "../stores/ws-store";
import { Button, LiveDot, PageHeader, Skeleton } from "../components/ui";
import { SYS_TABS, type SysTab, useSystemController } from "./system/useSystemController";
import { InternalsView } from "./system/InternalsView";
import { LogsView } from "./system/LogsView";
import { MaintenanceView } from "./system/MaintenanceView";
import { ConfigBackupView } from "./system/ConfigBackupView";

const HardwareView = lazy(() => import("./system/HardwareView").then((m) => ({ default: m.HardwareView })));
const OtaView = lazy(() => import("./system/OtaView").then((m) => ({ default: m.OtaView })));
const SecurityView = lazy(() => import("./system/SecurityView").then((m) => ({ default: m.SecurityView })));

export { validateImeiLuhn } from "./system/useSystemController";

export function SystemPage() {
  const [tab, setTab] = useSubRoute<SysTab>("/system", SYS_TABS, "hardware");
  const ctl = useSystemController(tab);
  const liveness = useLiveness();

  let actions: React.ReactNode = null;
  if (tab === "internals") {
    actions = (
      <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] font-semibold text-ink-2">
        <LiveDot tone={liveness.tone} /> {liveness.live ? "Live · every 5 s" : liveness.label.split(" ·")[0]}
      </span>
    );
  } else if (tab === "ota") {
    const checking = ctl.busy === "ota-check";
    actions = (
      <Button variant="secondary" size="sm" onClick={ctl.checkOtaFeed} disabled={checking}>
        <RefreshCw className={cn("h-3.5 w-3.5", checking && "animate-spin")} />
        {checking ? "Checking…" : "Check for updates"}
      </Button>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader section="/system" sub={tab} onSubChange={(id) => setTab(id as SysTab)} actions={actions} />
      <div key={tab} className="qm-rise">
        {tab === "hardware" && (
          <Suspense fallback={<Skeleton className="h-64" />}>
            <HardwareView ctl={ctl} />
          </Suspense>
        )}
        {tab === "internals" && <InternalsView ctl={ctl} />}
        {tab === "logs" && <LogsView ctl={ctl} />}
        {tab === "alerts" && <MaintenanceView ctl={ctl} />}
        {tab === "ota" && (
          <Suspense fallback={<Skeleton className="h-64" />}>
            <OtaView ctl={ctl} />
          </Suspense>
        )}
        {tab === "backup" && <ConfigBackupView />}
        {tab === "security" && (
          <Suspense fallback={<Skeleton className="h-64" />}>
            <SecurityView ctl={ctl} />
          </Suspense>
        )}
      </div>
    </div>
  );
}
