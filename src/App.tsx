import { Suspense, lazy, useEffect } from "react";
import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppShell } from "@/components/AppShell";
import { Skeleton, ToastViewport } from "@/components/ui";
import { ApiError, apiFetch } from "@/lib/api";
import { useToastStore } from "@/stores/toast-store";
import { LoginPage } from "@/pages/LoginPage";

import { OverviewPage } from "@/pages/OverviewPage";
import { useAuthStore } from "@/stores/auth-store";
import { useRouteStore } from "@/stores/route-store";
import { useWsStore } from "@/stores/ws-store";
import type { AuthStateResponse } from "@/types/cellcore";

const CellularPage = lazy(() => import("@/pages/CellularPage").then((m) => ({ default: m.CellularPage })));
const DiagnosticsPage = lazy(() => import("@/pages/DiagnosticsPage").then((m) => ({ default: m.DiagnosticsPage })));
const NetworkPage = lazy(() => import("@/pages/NetworkPage").then((m) => ({ default: m.NetworkPage })));
const SystemPage = lazy(() => import("@/pages/SystemPage").then((m) => ({ default: m.SystemPage })));
const AdminPage = lazy(() => import("@/pages/AdminPage").then((m) => ({ default: m.AdminPage })));

/**
 * A view whose data never arrived must say so instead of spinning or rendering blanks. Every
 * query that fails before it ever had data raises one error toast (per query, at most every
 * 30 s); views add their own inline error state. Failed background refreshes of data already
 * on screen stay quiet (the stale indicator covers those), and 401 is handled by the login flow.
 */
const lastErrorToast = new Map<string, number>();
const queryCache = new QueryCache({
  onError: (error, query) => {
    if (query.state.data !== undefined) return;
    if (error instanceof ApiError && error.status === 401) return;
    const now = Date.now();
    if (now - (lastErrorToast.get(query.queryHash) ?? 0) < 30_000) return;
    lastErrorToast.set(query.queryHash, now);
    useToastStore.getState().push("Couldn't load data", "error", error instanceof Error ? error.message : undefined);
  },
});

const queryClient = new QueryClient({
  queryCache,
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function RouterView() {
  const { authenticated, checking, setAuthenticated } = useAuthStore();
  const hydrateBootstrap = useWsStore((s) => s.hydrateBootstrap);
  const connectWs = useWsStore((s) => s.connect);
  const disconnectWs = useWsStore((s) => s.disconnect);
  const route = useRouteStore((s) => s.section);

  useEffect(() => {
    let active = true;
    apiFetch<AuthStateResponse>("/api/v1/auth/status", { skipAuthRedirect: true })
      .then((res) => {
        if (!active) return;
        const ok = Boolean(res?.authenticated || res?.state === "valid");
        setAuthenticated(ok, undefined, res?.csrfToken ?? null);
        if (!ok && useRouteStore.getState().section !== "/login") {
          window.location.hash = "#/login";
        }
      })
      .catch(() => {
        if (!active) return;
        setAuthenticated(false);
        if (useRouteStore.getState().section !== "/login") {
          window.location.hash = "#/login";
        }
      });
    return () => {
      active = false;
    };
  }, [setAuthenticated]);

  useEffect(() => {
    if (authenticated) {
      void hydrateBootstrap();
      connectWs();
    } else {
      disconnectWs();
    }
    return () => {
      disconnectWs();
    };
  }, [authenticated, hydrateBootstrap, connectWs, disconnectWs]);

  useEffect(() => {
    if (authenticated && route === "/login") {
      window.location.hash = "#/";
    }
  }, [authenticated, route]);

  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [route]);

  if (checking) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 text-[13px] text-muted">
        <span className="h-10 w-10 rounded-2xl qm-sun animate-pulse" />
        Warming up…
      </div>
    );
  }

  if (!authenticated || route === "/login") {
    return <LoginPage />;
  }

  return (
    <AppShell route={route}>
      <Suspense fallback={<Skeleton className="h-[60vh]" />}>
        {route === "/" && <OverviewPage />}
        {route === "/cellular" && <CellularPage />}
        {route === "/network" && <NetworkPage />}
        {route === "/diagnostics" && <DiagnosticsPage />}
        {route === "/system" && <SystemPage />}
        {route === "/admin" && <AdminPage />}
      </Suspense>
    </AppShell>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterView />
      <ToastViewport />
    </QueryClientProvider>
  );
}

export default App;
