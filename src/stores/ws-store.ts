import { create } from "zustand";
import { apiFetch } from "../lib/api";
import { pickActiveRmnetInterfaces } from "../lib/parsers";
import { useAuthStore } from "./auth-store";
import { useObsStore } from "./obs-store";
import type { FailoverStatus, ObsEvent } from "../types/obs";
import type {
  AntennaAlignState,
  BootstrapPayload,
  DataUsageState,
  ModemSnapshot,
  PingPoint,
  SpeedtestLiveState,
  SpeedtestRun,
  TrafficInterfaceStats,
  UptimeTelemetry,
  WsStoreState,
} from "../types/cellcore";

const INITIAL_SPEEDTEST: SpeedtestLiveState = {
  running: false,
  phase: "idle",
  pingMs: null,
  jitterMs: null,
  downloadMbps: null,
  uploadMbps: null,
  dlLatencyIqm: null,
  ulLatencyIqm: null,
  bufferbloatGrade: null,
  packetLoss: null,
  progress: 0,
  samples: [],
};

let socket: WebSocket | null = null;
let reconnectTimer: number | null = null;
let hydrating = false;
let watchdog: number | null = null;

/**
 * The daemon pushes traffic frames every second. A frozen or unreachable gateway does not close
 * the TCP connection, so "connected" alone would keep claiming LIVE forever: after
 * STALE_AFTER_MS without any frame the UI says the data is stale, and after RECONNECT_AFTER_MS
 * the socket is dropped and re-opened (a half-open connection never recovers on its own).
 */
export const STALE_AFTER_MS = 8_000;
export const RECONNECT_AFTER_MS = 20_000;

function normalizePing(raw: Partial<PingPoint>, fallbackTs = Date.now()): PingPoint {
  const loss = Number(raw.packetLoss ?? raw.packet_loss ?? 0);
  return {
    timestamp: String(raw.timestamp ?? new Date(fallbackTs).toISOString()),
    ts: typeof raw.ts === "number" ? raw.ts : Date.parse(String(raw.timestamp ?? "")) || fallbackTs,
    host: String(raw.host ?? "8.8.8.8"),
    latency: Number(raw.latency ?? 0),
    packetLoss: loss,
    packet_loss: loss,
    ok: raw.ok !== false,
  };
}

function normalizeUptime(raw: UptimeTelemetry | null | undefined): UptimeTelemetry | null {
  if (!raw) return null;
  const secs = Number(raw.uptimeSeconds ?? raw.uptime_seconds ?? 0);
  const fmt = String(raw.uptimeFormatted ?? raw.uptime_formatted ?? "--");
  const conn = raw.isConnected ?? raw.is_connected;
  const disc = raw.disconnectCount ?? raw.disconnect_count;
  return {
    ...raw,
    uptimeSeconds: secs,
    uptime_seconds: secs,
    uptimeFormatted: fmt,
    uptime_formatted: fmt,
    isConnected: conn,
    is_connected: conn,
    disconnectCount: disc,
    disconnect_count: disc,
  };
}

function buildTrafficState(
  interfaces: TrafficInterfaceStats[],
  history: BootstrapPayload["traffic"]["history"],
  prev: WsStoreState["traffic"],
  primaryName?: string,
  lanName?: string
): WsStoreState["traffic"] {
  const { primary, lan } = pickActiveRmnetInterfaces(interfaces);
  const effPrimary = interfaces.find((i) => i.name === primaryName) ?? primary;
  const effLan = interfaces.find((i) => i.name === lanName) ?? lan;

  const rxBps = Number(effPrimary?.rx?.bps ?? prev.rxBps ?? 0);
  const txBps = Number(effPrimary?.tx?.bps ?? prev.txBps ?? 0);

  return {
    primaryIface: effPrimary?.name ?? primaryName ?? prev.primaryIface,
    primaryState: effPrimary?.state ?? prev.primaryState,
    rxBps,
    txBps,
    rxPps: Number(effPrimary?.rx?.packetsPerSec ?? effPrimary?.rx?.packets_per_sec ?? 0),
    txPps: Number(effPrimary?.tx?.packetsPerSec ?? effPrimary?.tx?.packets_per_sec ?? 0),
    rxTotalBytes: Number(effPrimary?.rx?.bytesTotal ?? effPrimary?.rx?.bytes_total ?? prev.rxTotalBytes),
    txTotalBytes: Number(effPrimary?.tx?.bytesTotal ?? effPrimary?.tx?.bytes_total ?? prev.txTotalBytes),
    lanIface: effLan?.name ?? lanName ?? prev.lanIface,
    lanState: effLan?.state ?? prev.lanState,
    lanRxBps: Number(effLan?.rx?.bps ?? 0),
    lanTxBps: Number(effLan?.tx?.bps ?? 0),
    lanRxTotalBytes: Number(effLan?.rx?.bytesTotal ?? effLan?.rx?.bytes_total ?? prev.lanRxTotalBytes),
    lanTxTotalBytes: Number(effLan?.tx?.bytesTotal ?? effLan?.tx?.bytes_total ?? prev.lanTxTotalBytes),
    interfaces,
    history,
  };
}

export const useWsStore = create<WsStoreState>((set, get) => ({
  status: "disconnected",
  lastFrameAt: null,
  stale: false,
  version: "4.0.0",
  modem: null,
  signalHistory: { rsrp: [], sinr: [] },
  rsrqHistory: [],
  traffic: {
    primaryIface: "rmnet_data1",
    primaryState: "up",
    rxBps: 0,
    txBps: 0,
    rxPps: 0,
    txPps: 0,
    rxTotalBytes: 0,
    txTotalBytes: 0,
    lanIface: "eth0",
    lanState: "up",
    lanRxBps: 0,
    lanTxBps: 0,
    lanRxTotalBytes: 0,
    lanTxTotalBytes: 0,
    interfaces: [],
    history: [],
  },
  dataUsage: null,
  ping: null,
  pingHistory: [],
  memory: null,
  sessionUptime: null,
  deviceUptime: null,
  internals: null,
  settings: null,
  speedtest: { ...INITIAL_SPEEDTEST },
  speedtestHistory: [],
  antennaAlign: null,
  alerts: [],
  hydrated: false,

  resetSpeedtest: () => set({ speedtest: { ...INITIAL_SPEEDTEST } }),
  setAntennaAlign: (antennaAlign) => set({ antennaAlign }),
  setInternals: (internals) => set({ internals }),
  setDataUsage: (dataUsage) => set({ dataUsage }),
  setSettings: (settings) => set({ settings }),

  sendWsCommand: (payload) => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(payload));
    }
  },

  refreshSpeedtestHistory: async () => {
    try {
      const res = await apiFetch<{ live?: SpeedtestLiveState; history?: SpeedtestRun[] }>(
        "/api/v1/speedtest/history"
      );
      set((s) => ({
        speedtest: res.live ?? s.speedtest,
        speedtestHistory: Array.isArray(res.history) ? res.history : s.speedtestHistory,
      }));
    } catch {
      // ignore transient poll errors
    }
  },

  hydrateBootstrap: async () => {
    if (hydrating) return;
    hydrating = true;
    try {
      const boot = await apiFetch<BootstrapPayload>("/api/v1/bootstrap");
      set((state) => {
        const pings = Array.isArray(boot.pingHistory)
          ? boot.pingHistory.map((p) => normalizePing(p)).slice(-180)
          : state.pingHistory;
        const ifaces = Array.isArray(boot.traffic?.interfaces) ? boot.traffic.interfaces : [];
        const hist = Array.isArray(boot.traffic?.history) ? boot.traffic.history : state.traffic.history;
        return {
          hydrated: true,
          version: boot.version || state.version,
          modem: boot.modem ?? state.modem,
          signalHistory: boot.signalHistory ?? state.signalHistory,
          rsrqHistory: boot.rsrqHistory ?? state.rsrqHistory,
          traffic: buildTrafficState(
            ifaces,
            hist,
            state.traffic,
            boot.traffic?.primaryIface,
            boot.traffic?.lanIface
          ),
          dataUsage: boot.dataUsage ?? state.dataUsage,
          pingHistory: pings,
          ping: pings[pings.length - 1] ?? state.ping,
          memory: boot.memory ?? state.memory,
          deviceUptime: normalizeUptime(boot.deviceUptime) ?? state.deviceUptime,
          sessionUptime: normalizeUptime(boot.sessionUptime) ?? state.sessionUptime,
          internals: boot.internals ?? state.internals,
          settings: boot.settings ?? state.settings,
          speedtest: boot.speedtest ?? state.speedtest,
          speedtestHistory: Array.isArray(boot.speedtestHistory)
            ? boot.speedtestHistory
            : state.speedtestHistory,
          antennaAlign: boot.antennaAlign ?? state.antennaAlign,
          alerts: Array.isArray(boot.alerts) ? boot.alerts : state.alerts,
        };
      });
    } catch {
      set({ hydrated: true });
    } finally {
      hydrating = false;
    }
  },

  connect: () => {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    if (reconnectTimer != null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const tok = useAuthStore.getState().token;
    const url = tok
      ? `${proto}//${host}/api/v1/ws?token=${encodeURIComponent(tok)}`
      : `${proto}//${host}/api/v1/ws`;
    set({ status: "connecting" });
    startWatchdog(get, set);

    try {
      const ws = new WebSocket(url);
      socket = ws;

      ws.onopen = () => {
        if (socket !== ws) return;
        set({ status: "connected", lastFrameAt: Date.now(), stale: false });
        // Catch up on events / failover state missed while disconnected.
        void useObsStore.getState().load();
      };

      ws.onmessage = (ev) => {
        if (socket !== ws) return;
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(String(ev.data));
        } catch {
          return;
        }

        const now = Date.now();
        const ch = String(msg?.channel ?? msg?.type ?? "");
        // Any frame proves the gateway is alive.
        if (get().stale || get().lastFrameAt == null || now - (get().lastFrameAt ?? 0) > 1_000) set({ lastFrameAt: now, stale: false });

        if (ch === "rf_snapshot" && msg.modem) {
          set({ lastFrameAt: now, modem: msg.modem as ModemSnapshot });
          return;
        }

        if (ch === "antenna_align" && msg.align) {
          set({ lastFrameAt: now, antennaAlign: msg.align as AntennaAlignState });
          return;
        }

        if (ch === "network-monitor" && Array.isArray(msg.interfaces)) {
          const ifaces = msg.interfaces as TrafficInterfaceStats[];
          const usageSum = msg.usageSummary as DataUsageState["usageSummary"] | undefined;
          set((s) => {
            const nextTraffic = buildTrafficState(ifaces, s.traffic.history, s.traffic);
            const history = [
              ...s.traffic.history,
              { ts: now, rxBps: nextTraffic.rxBps, txBps: nextTraffic.txBps },
            ].slice(-120);
            return {
              lastFrameAt: now,
              traffic: { ...nextTraffic, history },
              dataUsage: s.dataUsage && usageSum ? { ...s.dataUsage, usageSummary: usageSum } : s.dataUsage,
            };
          });
          return;
        }

        if (ch === "ping") {
          const point = normalizePing(msg as unknown as Partial<PingPoint>, now);
          set((s) => ({
            lastFrameAt: now,
            ping: point,
            pingHistory: [...s.pingHistory, point].slice(-180),
          }));
          return;
        }

        if (ch === "memory") {
          const total = Number(msg.total ?? 0);
          const used = Number(msg.used ?? 0);
          const available = Number(msg.available ?? Math.max(0, total - used));
          const computed = total > 0 ? Math.round((used / total) * 1000) / 10 : 0;
          const percent = msg.percent != null ? Number(msg.percent) : computed;
          set({
            lastFrameAt: now,
            memory: {
              total,
              used,
              available,
              percent: Number.isFinite(percent) ? percent : 0,
              timestamp: String(msg.timestamp ?? new Date(now).toISOString()),
            },
          });
          return;
        }

        if (ch === "uptime") {
          const norm = normalizeUptime(msg as unknown as UptimeTelemetry);
          if (norm) set({ lastFrameAt: now, sessionUptime: norm });
          return;
        }

        if (ch === "device-uptime" || ch === "device_uptime") {
          const norm = normalizeUptime(msg as unknown as UptimeTelemetry);
          if (norm) set({ lastFrameAt: now, deviceUptime: norm });
          return;
        }

        if (ch === "speedtest") {
          const live = msg as unknown as SpeedtestLiveState;
          set({ lastFrameAt: now, speedtest: live });
          if (!live.running && live.phase === "complete") {
            void get().refreshSpeedtestHistory();
          }
          return;
        }

        if (ch === "event" && msg.event) {
          useObsStore.getState().pushEvent(msg.event as ObsEvent);
          return;
        }

        if (ch === "failover" && msg.failover) {
          useObsStore.getState().setFailover(msg.failover as FailoverStatus);
          return;
        }

        if (ch === "cell-lock-alert" || ch === "alert" || ch === "quecwatch") {
          set((s) => ({
            lastFrameAt: now,
            alerts: [
              {
                type: ch,
                message: String(msg.message ?? JSON.stringify(msg)),
                timestamp: String(msg.timestamp ?? new Date(now).toISOString()),
              },
              ...s.alerts,
            ].slice(0, 20),
          }));
        }
      };

      ws.onerror = () => {
        if (socket !== ws) return;
        set({ status: "error" });
      };

      ws.onclose = () => {
        if (socket !== ws) return;
        socket = null;
        set({ status: "disconnected" });
        if (reconnectTimer == null && useAuthStore.getState().authenticated) {
          reconnectTimer = window.setTimeout(() => {
            reconnectTimer = null;
            get().connect();
          }, 3000);
        }
      };
    } catch {
      set({ status: "error" });
    }
  },

  disconnect: () => {
    if (watchdog != null) {
      window.clearInterval(watchdog);
      watchdog = null;
    }
    if (reconnectTimer != null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (socket) {
      const ws = socket;
      socket = null;
      ws.close();
    }
    set({ status: "disconnected", stale: false });
  },
}));

function startWatchdog(get: () => WsStoreState, set: (p: Partial<WsStoreState>) => void) {
  if (watchdog != null) return;
  watchdog = window.setInterval(() => {
    const s = get();
    if (s.status !== "connected" || s.lastFrameAt == null) return;
    const age = Date.now() - s.lastFrameAt;
    if (age > STALE_AFTER_MS && !s.stale) set({ stale: true });
    if (age > RECONNECT_AFTER_MS && socket) {
      // Half-open: abandon this socket (its handlers ignore it once `socket` moves on) and redial.
      const dead = socket;
      socket = null;
      try {
        dead.close();
      } catch {
        /* ignore */
      }
      set({ status: "disconnected" });
      s.connect();
    }
  }, 1_000);
}

export type Liveness = { live: boolean; tone: "jade" | "saffron" | "crimson"; label: string };

/** One answer to "is what I see live?" for every badge and status line. */
export function livenessOf(status: WsStoreState["status"], stale: boolean, everConnected: boolean): Liveness {
  if (status === "connected" && !stale) return { live: true, tone: "jade", label: "Live" };
  if (status === "connected") return { live: false, tone: "saffron", label: "Stale · gateway not responding" };
  if (status === "connecting") return { live: false, tone: "saffron", label: everConnected ? "Reconnecting…" : "Connecting…" };
  return { live: false, tone: "crimson", label: "Disconnected" };
}

export function useLiveness(): Liveness {
  const status = useWsStore((s) => s.status);
  const stale = useWsStore((s) => s.stale);
  const ever = useWsStore((s) => s.lastFrameAt != null);
  return livenessOf(status, stale, ever);
}
