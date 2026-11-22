export interface AtCommandItem {
  command: string;
  response: string;
  status: "success" | "error" | string;
  latencyMs?: number;
}

export interface AuthStateResponse {
  status?: string;
  authenticated?: boolean;
  state?: "valid" | "invalid" | "success" | "failed";
  token?: string;
  csrfToken?: string;
  version?: string;
  message?: string;
  error?: string;
}

export type AppRoute = "/" | "/cellular" | "/network" | "/diagnostics" | "/system" | "/admin" | "/login";

export interface ServingCellInfo {
  state: string;
  rat: string;
  duplexMode: string;
  mcc: string;
  mnc: string;
  cellId: string;
  pci: number | null;
  tac: string;
  arfcn: number | null;
  band: string;
  ulBandwidthMhz: number | null;
  dlBandwidthMhz: number | null;
  rsrp: number | null;
  rsrq: number | null;
  sinr: number | null;
  txPower: number | null;
  scsKhz?: number | null;
  nsaNr5gPci?: number | null;
  nsaNr5gArfcn?: number | null;
  nsaNr5gBand?: string | null;
  nsaNr5gRsrp?: number | null;
  nsaNr5gSinr?: number | null;
  nsaNr5gRsrq?: number | null;
  nsaNr5gBwMhz?: number | null;
  srxlev: number | null;
  raw: string;
}

export interface MimoSignalData {
  rsrp: (number | null)[];
  rsrq: (number | null)[];
  sinr: (number | null)[];
  rat: string;
}

export interface CarrierComponent {
  role: "PCC" | "SCC";
  arfcn: number;
  bandwidthCode: number;
  bandwidthMhz: number | null;
  band: string;
  pci: number | null;
  pcellState?: number | null;
  ulConfigured?: boolean;
  ulArfcn?: number | null;
  ulBandwidthMhz?: number | null;
  rsrp?: number | null;
  rsrq?: number | null;
  rssi?: number | null;
  sinr?: number | null;
  dlMimoLayers?: number | null;
  ulMimoLayers?: number | null;
}

export interface WwanBearerInfo {
  iface: string;
  cid: number;
  ipType: "IPV4" | "IPV6" | "IPV4V6";
  status: string;
  apn: string;
  ipv4?: string;
  ipv4Gateway?: string;
  ipv4Dns1?: string;
  ipv4Dns2?: string;
  ipv6?: string;
  ipv6Gateway?: string;
  ipv6Dns1?: string;
  ipv6Dns2?: string;
  ipv6PrefixLength?: number | null;
}

export interface TimeAdvanceInfo {
  nr5gRaw?: number | null;
  nr5gSteps?: number | null;
  nr5gMeters?: number | null;
  lteTa?: number | null;
  lteMeters?: number | null;
  activeMeters?: number | null;
}

export interface ModemIdentity {
  manufacturer: string;
  model: string;
  revision: string;
  rel: string;
  maskedImei: string;
  maskedIccid: string;
  maskedImsi: string;
  phoneNumber: string;
  simSlot: number;
  cfun: number;
  hasPreviousImei: boolean;
}

export interface TempSensor {
  sensor: string;
  celsius: number;
  domain?: string;
}

export interface ModemSnapshot {
  updatedAt: number;
  operator: string;
  serving: ServingCellInfo | null;
  carriers: CarrierComponent[];
  mimo: MimoSignalData;
  bearers: WwanBearerInfo[];
  timeAdvance: TimeAdvanceInfo;
  thermals: TempSensor[];
  identity: ModemIdentity;
  publicIp?: string | null;
  rawCommands?: Record<string, string>;
}

export interface PublicPreviewResponse {
  version: string;
  model: string;
  operator: string;
  rat: string;
  carriers: CarrierComponent[];
  carrierCount: number;
  totalBandwidthMhz: number;
  mimo: MimoSignalData;
}

export interface TrafficDirectionStats {
  bytesTotal?: number;
  bytes_total?: number;
  bps: number;
  packetsPerSec?: number;
  packets_per_sec?: number;
}

export interface TrafficInterfaceStats {
  name: string;
  state: string;
  rx: TrafficDirectionStats;
  tx: TrafficDirectionStats;
}

export interface TrafficHistoryPoint {
  ts: number;
  rxBps: number;
  txBps: number;
}

export interface DailyUsageEntry {
  date: string;
  rxBytes: number;
  txBytes: number;
}

export interface MonthlyUsageEntry {
  month: string;
  rxBytes: number;
  txBytes: number;
}

export interface DataUsageState {
  billingCycleDay: number;
  quotaBytes: number | null;
  lastIface: string;
  lastRawRx: number;
  lastRawTx: number;
  daily: DailyUsageEntry[];
  monthly: MonthlyUsageEntry[];
  usageSummary?: {
    todayRx: number;
    todayTx: number;
    monthRx: number;
    monthTx: number;
  };
}

export interface PingPoint {
  timestamp: string;
  ts: number;
  host: string;
  latency: number;
  packetLoss?: number;
  packet_loss?: number;
  ok: boolean;
}

export interface MemoryTelemetry {
  total: number;
  used: number;
  available: number;
  percent: number;
  timestamp: string;
}

export interface UptimeTelemetry {
  uptimeSeconds?: number;
  uptimeFormatted?: string;
  isConnected?: boolean;
  disconnectCount?: number;
  uptime_seconds?: number;
  uptime_formatted?: string;
  is_connected?: boolean;
  disconnect_count?: number;
  last_disconnect?: number;
  timestamp?: number | string;
}

export interface MbnProfile {
  index: number;
  selected: boolean;
  activated: boolean;
  name: string;
  version: string;
  date: string;
}

export interface QuecProfileItem {
  id?: string;
  index?: number;
  name: string;
  iccid: string;
  imei?: string;
  apn: string;
  pdp_type: string;
  lte_bands?: string;
  sa_nr5g_bands?: string;
  nsa_nr5g_bands?: string;
  network_type: string;
  ttl?: string;
  mobile_provider?: string;
  mbn_profile?: string;
  paused?: string | boolean;
}

export interface MpdnRule {
  slot: number;
  apnSlot: number;
  vlanId: number;
  mode: string;
  mac: string;
  raw?: string;
}

export interface NeighborCellInfo {
  rat: string;
  type: string;
  arfcn: number | null;
  pci: number | null;
  rsrp: number | null;
  rsrq: number | null;
  sinr: number | null;
  srxlev: number | null;
  band?: string;
  raw: string;
}

export interface SignalHistoryPoint {
  ts: number;
  label: string;
  value: number;
  chains: (number | null)[];
}

export interface SpeedtestSample {
  ts: number;
  phase: string;
  mbps: number;
  latencyIqm?: number | null;
}

export interface SpeedtestRun {
  id: string;
  timestamp: string;
  ts: number;
  downloadMbps: number;
  uploadMbps: number;
  pingMs: number;
  jitterMs: number;
  packetLoss?: number | null;
  dlLatencyIqm?: number | null;
  ulLatencyIqm?: number | null;
  bufferbloatGrade: string;
  isp?: string | null;
  serverId?: number | null;
  serverName?: string | null;
  serverLocation?: string | null;
  externalIp?: string | null;
  resultUrl?: string | null;
  engine?: string | null;
}

export interface SpeedtestServerOption {
  id: number;
  host: string;
  port: number;
  name: string;
  location: string;
  country: string;
}

export interface SpeedtestLiveState {
  running: boolean;
  phase: "idle" | "starting" | "ping" | "download" | "upload" | "complete" | "stopped" | "error";
  progress: number;
  pingMs: number | null;
  jitterMs: number | null;
  downloadMbps: number | null;
  uploadMbps: number | null;
  dlLatencyIqm?: number | null;
  ulLatencyIqm?: number | null;
  bufferbloatGrade?: string | null;
  packetLoss?: number | null;
  isp?: string | null;
  serverName?: string | null;
  serverLocation?: string | null;
  externalIp?: string | null;
  resultUrl?: string | null;
  engine?: string | null;
  error?: string | null;
  samples?: SpeedtestSample[];
}

export interface CarrierMimoLayer {
  pci: number;
  arfcn: number;
  band: string;
  dlLayers: number;
  ulLayers: number;
}

export interface AntennaAlignState {
  active: boolean;
  expiresAt: number;
  rsrp: (number | null)[];
  sinr: (number | null)[];
  rsrq: (number | null)[];
  peakRsrp: (number | null)[];
  peakSinr: (number | null)[];
  samples: number;
  updatedAt: number;
  keepAwake?: boolean;
  updatedAtMs?: number;
  peakMeanRsrp?: number | null;
  peakMeanSinr?: number | null;
  rsrpSpread?: number | null;
  pair01Skew?: number | null;
  pair23Skew?: number | null;
  activeChains?: number;
  servingPci?: number | null;
  servingBand?: string;
  servingRat?: string;
  rrcState?: string;
  caCount?: number;
  caTotalMhz?: number;
  ssbBeamId?: number | null;
  nr5gPathlossDb?: number | null;
  nr5gTxPwr?: string | null;
  nr5gMcs?: number | null;
  nr5gRi?: number | null;
  nr5gCqi?: number | null;
  taMeters?: number | null;
  mimoLayers?: CarrierMimoLayer[];
}

export interface ReconcileReport {
  timestamp: number;
  actions: string[];
  warnings: string[];
  pcieAspm: string;
  autosleep: string;
  conntrackHashsize: number;
  conntrackMax: number;
  usbUdc: string;
}

export interface SystemInternals {
  conntrackCount: number;
  conntrackMax: number;
  conntrackHashsize: number;
  pcieAspm: string;
  autosleep: string;
  bootSlot: string;
  usrdataTotalBytes: number;
  usrdataUsedBytes: number;
  usrdataAvailBytes: number;
  usbUdc: string;
  usbController: string;
  usbAdbPresent: boolean;
  mwan3Running: boolean;
  keepAliveEnabled: boolean;
  ethSpeed: string;
  cloudflaredHaConnections?: number | null;
  cloudflaredRunning?: boolean;
  lastReconcile?: ReconcileReport | null;
}

export interface DaemonSettings {
  temperatureUnit: "celsius" | "fahrenheit";
  measurementUnit: "mi" | "km";
  httpsRedirect: boolean;
  pingEnabled: boolean;
  pingHost: string;
  pingIntervalSec: number;
  keepAliveEnabled: boolean;
  ethLinkSpeed: string;
  ttlValue?: number | null;
  hlValue?: number | null;
  mtuValue?: number | null;
  customDns?: string[] | null;
  scheduledRebootEnabled: boolean;
  scheduledRebootTime: string;
  scheduledRebootDays: string[];
  quecwatchEnabled: boolean;
  quecwatchTarget: string;
  quecwatchIntervalSec: number;
  quecwatchFailures: number;
  quecwatchMaxRetries: number;
  quecwatchConnectionRefresh: boolean;
  quecwatchAutoSimFailover: boolean;
  preferredSimSlot?: number;
  simFailbackMins?: number;
  quecwatchHighLatency: boolean;
  quecwatchLatencyCeiling: number;
  cellLockSchedEnabled: boolean;
  cellLockStartTime: string;
  cellLockEndTime: string;
  cellLockLte: string;
  cellLockNr5g: string;
  cellLockLtePersist: boolean;
  cellLockNr5gPersist: boolean;
  cellLockDeadmanEnabled?: boolean;
  cellLockDeadmanSecs?: number;
  antennaLabels?: string[];
}

/**
 * One message as GET /api/v1/sms returns it (daemon `sms::SmsMessage`, camelCase). A concatenated
 * message is reassembled by the daemon: `indices` lists every SIM storage slot it occupies, and
 * DELETE /api/v1/sms takes `{ indices: number[] }`. `timestamp` is "YYYY-MM-DD hh:mm:ss", or ""
 * when the PDU carried no valid time stamp.
 */
export interface SmsMessage {
  indices: number[];
  sender: string;
  timestamp: string;
  text: string;
  reference?: string | null;
  totalParts: number;
  receivedParts: number;
  rawPdu?: string;
}

export interface BootstrapPayload {
  version: string;
  modem: ModemSnapshot;
  signalHistory: {
    rsrp: SignalHistoryPoint[];
    sinr: SignalHistoryPoint[];
  };
  rsrqHistory?: SignalHistoryPoint[];
  traffic: {
    primaryIface: string;
    lanIface: string;
    interfaces: TrafficInterfaceStats[];
    history: TrafficHistoryPoint[];
  };
  dataUsage: DataUsageState;
  pingHistory: PingPoint[];
  memory: MemoryTelemetry;
  deviceUptime: UptimeTelemetry;
  sessionUptime: UptimeTelemetry;
  internals: SystemInternals;
  speedtest: SpeedtestLiveState;
  speedtestHistory: SpeedtestRun[];
  settings: DaemonSettings;
  antennaAlign: AntennaAlignState;
  alerts: Array<{ type: string; message: string; timestamp: string }>;
}

export interface WsStoreState {
  status: "connecting" | "connected" | "disconnected" | "error";
  lastFrameAt: number | null;
  /** True when the socket looks open but no telemetry frame arrived for STALE_AFTER_MS. */
  stale: boolean;
  version: string;
  modem: ModemSnapshot | null;
  signalHistory: {
    rsrp: SignalHistoryPoint[];
    sinr: SignalHistoryPoint[];
  };
  rsrqHistory: SignalHistoryPoint[];
  traffic: {
    primaryIface: string;
    primaryState: string;
    rxBps: number;
    txBps: number;
    rxPps: number;
    txPps: number;
    rxTotalBytes: number;
    txTotalBytes: number;
    lanIface: string;
    lanState: string;
    lanRxBps: number;
    lanTxBps: number;
    lanRxTotalBytes: number;
    lanTxTotalBytes: number;
    interfaces: TrafficInterfaceStats[];
    history: TrafficHistoryPoint[];
  };
  dataUsage: DataUsageState | null;
  ping: PingPoint | null;
  pingHistory: PingPoint[];
  memory: MemoryTelemetry | null;
  sessionUptime: UptimeTelemetry | null;
  deviceUptime: UptimeTelemetry | null;
  internals: SystemInternals | null;
  settings: DaemonSettings | null;
  speedtest: SpeedtestLiveState;
  speedtestHistory: SpeedtestRun[];
  antennaAlign: AntennaAlignState | null;
  alerts: Array<{ type: string; message: string; timestamp: string }>;
  hydrated: boolean;
  connect: () => void;
  disconnect: () => void;
  hydrateBootstrap: () => Promise<void>;
  refreshSpeedtestHistory: () => Promise<void>;
  sendWsCommand: (payload: Record<string, unknown>) => void;
  setAntennaAlign: (align: AntennaAlignState) => void;
  setInternals: (internals: SystemInternals) => void;
  setDataUsage: (usage: DataUsageState) => void;
  setSettings: (settings: DaemonSettings) => void;
  resetSpeedtest: () => void;
  dismissAlert: (index: number) => void;
  clearAlerts: () => void;
}
