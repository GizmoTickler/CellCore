import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn } from "../lib/utils";
import { useWsStore } from "../stores/ws-store";
import { useToastStore } from "../stores/toast-store";
import { navigate, useRouteStore, useSubRoute } from "../stores/route-store";
import type { DataUsageState } from "../types/cellcore";
import { Button, PageHeader } from "../components/ui";
import type { NetMutator, NetworkLanResponse } from "./network/shared";
import { LanView } from "./network/LanView";
import { PolicyView } from "./network/PolicyView";
import { UsageView } from "./network/UsageView";
import { DataPlaneView } from "./network/DataPlaneView";
import { WarpView } from "./network/WarpView";
import { TailscaleView } from "./network/TailscaleView";

const TABS = ["lan", "policy", "usage", "dataplane", "warp", "tailscale"] as const;
type Tab = (typeof TABS)[number];

export function NetworkPage() {
  const qc = useQueryClient();
  const push = useToastStore((s) => s.push);
  const [tab, setTab] = useSubRoute<Tab>("/network", TABS, "lan");
  // 4.1.1 bookmarks: #/network/vpn was the Tailscale view.
  const rawSub = useRouteStore((s) => s.sub);
  useEffect(() => {
    if (rawSub === "vpn") navigate("/network", "tailscale");
  }, [rawSub]);
  const [busy, setBusy] = useState<string | null>(null);

  const wsUsage = useWsStore((s) => s.dataUsage);

  const lanQuery = useQuery({
    queryKey: ["network-lan"],
    queryFn: () => apiFetch<NetworkLanResponse>("/api/v1/network/lan"),
    enabled: tab === "lan" || tab === "policy",
    refetchInterval: tab === "lan" || tab === "policy" ? 20000 : false,
  });

  const usageQuery = useQuery({
    queryKey: ["network-data-usage"],
    queryFn: () => apiFetch<DataUsageState>("/api/v1/network/data-usage"),
    enabled: tab === "usage",
    refetchInterval: tab === "usage" ? 30000 : false,
  });

  const effectiveUsage = wsUsage ?? usageQuery.data ?? null;

  async function mutateNetwork(actionTag: string, payload: Record<string, unknown>, okMsg: string): Promise<boolean> {
    setBusy(actionTag);
    try {
      await apiFetch("/api/v1/network/lan", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      push(okMsg, "success");
      await qc.invalidateQueries({ queryKey: ["network-lan"] });
      return true;
    } catch (e) {
      push("Network update failed", "error", e instanceof Error ? e.message : undefined);
      return false;
    } finally {
      setBusy(null);
    }
  }

  const net: NetMutator = { busy, mutate: mutateNetwork };
  const d = lanQuery.data;
  const fetching = tab === "usage" ? usageQuery.isFetching : lanQuery.isFetching;
  const standaloneTab = tab === "warp" || tab === "tailscale" || tab === "dataplane";

  return (
    <div className="space-y-6">
      <PageHeader
        section="/network"
        sub={tab}
        onSubChange={(id) => setTab(id as Tab)}
        actions={
          !standaloneTab && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => (tab === "usage" ? usageQuery.refetch() : lanQuery.refetch())}
            aria-label="Refresh"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", fetching && "animate-spin")} />
            Refresh
          </Button>
          )
        }
      />

      {tab === "lan" && <LanView d={d} loading={lanQuery.isLoading} net={net} />}
      {tab === "policy" && <PolicyView d={d} net={net} />}
      {tab === "usage" && <UsageView usage={effectiveUsage} loading={usageQuery.isLoading} />}
      {tab === "dataplane" && <DataPlaneView />}
      {tab === "warp" && <WarpView />}
      {tab === "tailscale" && <TailscaleView />}
    </div>
  );
}
