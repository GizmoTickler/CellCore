import React from "react";
import { RefreshCw } from "lucide-react";
import { cn } from "../lib/utils";
import { useSubRoute } from "../stores/route-store";
import { Button, LiveDot, PageHeader } from "../components/ui";
import { SYS_TABS, type SysTab, useSystemController } from "./system/useSystemController";
import { HardwareView } from "./system/HardwareView";
import { InternalsView } from "./system/InternalsView";
import { LogsView } from "./system/LogsView";
import { MaintenanceView } from "./system/MaintenanceView";
import { OtaView } from "./system/OtaView";
import { ConfigBackupView } from "./system/ConfigBackupView";
import { SecurityView } from "./system/SecurityView";

export { validateImeiLuhn } from "./system/useSystemController";

export function SystemPage() {
  const [tab, setTab] = useSubRoute<SysTab>("/system", SYS_TABS, "hardware");
  const ctl = useSystemController(tab);

  let actions: React.ReactNode = null;
  if (tab === "internals") {
    actions = (
      <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1.5 text-[12px] font-semibold text-ink-2">
        <LiveDot tone="jade" /> Live · every 5 s
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
        {tab === "hardware" && <HardwareView ctl={ctl} />}
        {tab === "internals" && <InternalsView ctl={ctl} />}
        {tab === "logs" && <LogsView ctl={ctl} />}
        {tab === "alerts" && <MaintenanceView ctl={ctl} />}
        {tab === "ota" && <OtaView ctl={ctl} />}
        {tab === "backup" && <ConfigBackupView />}
        {tab === "security" && <SecurityView ctl={ctl} />}
      </div>
    </div>
  );
}
