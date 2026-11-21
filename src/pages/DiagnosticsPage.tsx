import { useCallback } from "react";
import type React from "react";
import { PageHeader } from "../components/ui";
import { useSubRoute } from "../stores/route-store";
import { SpeedtestView } from "./diagnostics/SpeedtestView";
import { HealthView } from "./diagnostics/HealthView";
import { LatencyView } from "./diagnostics/LatencyView";
import { AtConsoleView } from "./diagnostics/AtConsoleView";
import { SmsView } from "./diagnostics/SmsView";
import { EventsView } from "./diagnostics/EventsView";
import type { HeaderFn } from "./diagnostics/shared";

const DIAG_TABS = ["speedtest", "health", "latency", "at", "sms", "events"] as const;
type DiagTab = (typeof DIAG_TABS)[number];

export function DiagnosticsPage() {
  const [tab, setTab] = useSubRoute<DiagTab>("/diagnostics", DIAG_TABS, "speedtest");

  const onSubChange = useCallback(
    (id: string) => {
      if ((DIAG_TABS as readonly string[]).includes(id)) setTab(id as DiagTab);
    },
    [setTab]
  );

  // Every sub-view opens with the page header; each supplies its own actions.
  const header: HeaderFn = (actions?: React.ReactNode) => (
    <PageHeader section="/diagnostics" sub={tab} onSubChange={onSubChange} actions={actions} />
  );

  return (
    <div className="space-y-6">
      {tab === "speedtest" && <SpeedtestView header={header} />}
      {tab === "health" && <HealthView header={header} />}
      {tab === "latency" && <LatencyView header={header} />}
      {tab === "at" && <AtConsoleView header={header} />}
      {tab === "sms" && <SmsView header={header} />}
      {tab === "events" && <EventsView header={header} />}
    </div>
  );
}
