import { useCallback, useState } from "react";
import type React from "react";
import { FileDown, Loader2 } from "lucide-react";
import { Button, PageHeader } from "../components/ui";
import { apiFetch } from "../lib/api";
import { useSubRoute } from "../stores/route-store";
import { useToastStore } from "../stores/toast-store";
import { SpeedtestView } from "./diagnostics/SpeedtestView";
import { HealthView } from "./diagnostics/HealthView";
import { LatencyView } from "./diagnostics/LatencyView";
import { AtConsoleView } from "./diagnostics/AtConsoleView";
import { SmsView } from "./diagnostics/SmsView";
import { EventsView } from "./diagnostics/EventsView";
import type { HeaderFn } from "./diagnostics/shared";

const DIAG_TABS = ["speedtest", "health", "latency", "at", "sms", "events"] as const;
type DiagTab = (typeof DIAG_TABS)[number];

function snapshotFilename(now = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `cellcore-diag-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}.json`;
}

export function DiagnosticsPage() {
  const [tab, setTab] = useSubRoute<DiagTab>("/diagnostics", DIAG_TABS, "speedtest");
  const [snapBusy, setSnapBusy] = useState(false);
  const pushToast = useToastStore((s) => s.push);

  const onSubChange = useCallback(
    (id: string) => {
      if ((DIAG_TABS as readonly string[]).includes(id)) setTab(id as DiagTab);
    },
    [setTab]
  );

  const handleDiagnosticSnapshot = useCallback(async () => {
    if (snapBusy) return;
    setSnapBusy(true);
    try {
      const data = await apiFetch<unknown>("/api/v1/diagnostics/snapshot");
      const filename = snapshotFilename();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      pushToast(
        "Diagnostic snapshot downloaded",
        "success",
        `${filename} · Redacted (zero IMEI, ICCID, or tokens)`
      );
    } catch (e) {
      pushToast(
        "Diagnostic snapshot failed",
        "error",
        e instanceof Error ? e.message : "Could not capture diagnostic snapshot"
      );
    } finally {
      setSnapBusy(false);
    }
  }, [pushToast, snapBusy]);

  // Every sub-view opens with the page header; each supplies its own actions.
  const header: HeaderFn = (actions?: React.ReactNode) => (
    <PageHeader
      section="/diagnostics"
      sub={tab}
      onSubChange={onSubChange}
      actions={
        <>
          {actions}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void handleDiagnosticSnapshot()}
            disabled={snapBusy}
            title="Download redacted JSON snapshot (zero IMEI, ICCID, or tokens)"
          >
            {snapBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileDown className="h-3.5 w-3.5" />}
            {snapBusy ? "Capturing…" : "Diagnostic Snapshot"}
          </Button>
        </>
      }
    />
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
