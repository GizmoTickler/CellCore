use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock, broadcast, mpsc};

use crate::{
    auth::AuthStore,
    parsers::{
        CarrierComponent, MimoSignalData, ServingCellInfo, TempSensor, TimeAdvanceInfo,
        WwanBearerInfo,
    },
    reconcile::ReconcileReport,
    smd::SmdClient,
};

pub const ETC_QM_DIR: &str = "/etc/cellcore";
pub const TMP_QM_DIR: &str = "/tmp/cellcore";
/// 2025-01-01T00:00:00Z — wall-clock timestamps below this indicate pre-NTP 1970 boot clock.
pub const MIN_VALID_WALL_CLOCK_SECS: u64 = 1_735_689_600;

static STARTUP_INSTANT: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Monotonic milliseconds elapsed since daemon startup (`CLOCK_MONOTONIC`).
/// Returns `>= 1` so `0` can serve as an "unset" sentinel in `AtomicU64`s.
pub fn mono_ms() -> u64 {
    let base = STARTUP_INSTANT.get_or_init(std::time::Instant::now);
    (base.elapsed().as_millis() as u64).saturating_add(1)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ModemIdentity {
    pub manufacturer: String,
    pub model: String,
    pub revision: String,
    pub rel: String,
    pub masked_imei: String,
    pub masked_iccid: String,
    pub masked_imsi: String,
    pub phone_number: String,
    pub sim_slot: i32,
    pub cfun: i32,
    pub has_previous_imei: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ModemSecrets {
    pub imei: String,
    pub iccid: String,
    pub imsi: String,
    pub previous_imei: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellLockBypassReason {
    #[default]
    None,
    Deadman,
    LinkWatch,
}

impl CellLockBypassReason {
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Deadman => 1,
            Self::LinkWatch => 2,
        }
    }

    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Deadman,
            2 => Self::LinkWatch,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ModemSnapshot {
    pub updated_at: u64,
    #[serde(skip)]
    pub updated_mono_ms: u64,
    pub operator: String,
    pub serving: Option<ServingCellInfo>,
    pub carriers: Vec<CarrierComponent>,
    pub mimo: MimoSignalData,
    pub bearers: Vec<WwanBearerInfo>,
    pub time_advance: TimeAdvanceInfo,
    pub thermals: Vec<TempSensor>,
    pub identity: ModemIdentity,
    pub public_ip: Option<String>,
    pub raw_commands: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalHistoryPoint {
    pub ts: u64,
    pub label: String,
    pub value: f64,
    pub chains: Vec<Option<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrafficDirectionStats {
    pub bytes_total: u64,
    pub bps: u64,
    pub packets_per_sec: u64,
    #[serde(default)]
    pub errors: u64,
    #[serde(default)]
    pub drops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrafficInterfaceStats {
    pub name: String,
    pub state: String,
    pub rx: TrafficDirectionStats,
    pub tx: TrafficDirectionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficHistoryPoint {
    pub ts: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DailyUsageEntry {
    pub date: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct MonthlyUsageEntry {
    pub month: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DataUsageState {
    pub billing_cycle_day: u8,
    pub quota_bytes: Option<u64>,
    pub last_iface: String,
    pub last_raw_rx: u64,
    pub last_raw_tx: u64,
    pub daily: Vec<DailyUsageEntry>,
    pub monthly: Vec<MonthlyUsageEntry>,
}

impl Default for DataUsageState {
    fn default() -> Self {
        Self {
            billing_cycle_day: 1,
            quota_bytes: None,
            last_iface: "rmnet_data1".into(),
            last_raw_rx: 0,
            last_raw_tx: 0,
            daily: Vec::new(),
            monthly: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingPoint {
    pub timestamp: String,
    pub ts: u64,
    pub host: String,
    pub latency: f64,
    pub packet_loss: f64,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MemoryTelemetry {
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub percent: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UptimeTelemetry {
    pub uptime_seconds: u64,
    pub uptime_formatted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_count: Option<u32>,
    pub timestamp: String,
}

impl UptimeTelemetry {
    pub fn disconnected(disconnect_count: u32, timestamp: String) -> Self {
        Self {
            uptime_seconds: 0,
            uptime_formatted: "0s".into(),
            is_connected: Some(false),
            disconnect_count: Some(disconnect_count),
            timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedtestSample {
    pub ts: u64,
    pub phase: String,
    pub mbps: f64,
    pub latency_iqm: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SpeedtestRun {
    pub id: String,
    pub timestamp: String,
    pub ts: u64,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub ping_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss: Option<f64>,
    pub dl_latency_iqm: Option<f64>,
    pub ul_latency_iqm: Option<f64>,
    pub bufferbloat_grade: String,
    pub isp: Option<String>,
    pub server_id: Option<i64>,
    pub server_name: Option<String>,
    pub server_location: Option<String>,
    pub external_ip: Option<String>,
    pub result_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedtestLiveState {
    pub running: bool,
    pub phase: String,
    pub progress: u8,
    pub ping_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub dl_latency_iqm: Option<f64>,
    pub ul_latency_iqm: Option<f64>,
    pub bufferbloat_grade: Option<String>,
    pub packet_loss: Option<f64>,
    pub isp: Option<String>,
    pub server_name: Option<String>,
    pub server_location: Option<String>,
    pub external_ip: Option<String>,
    pub result_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    pub error: Option<String>,
    pub samples: Vec<SpeedtestSample>,
}

impl Default for SpeedtestLiveState {
    fn default() -> Self {
        Self {
            running: false,
            phase: "idle".into(),
            progress: 0,
            ping_ms: None,
            jitter_ms: None,
            download_mbps: None,
            upload_mbps: None,
            dl_latency_iqm: None,
            ul_latency_iqm: None,
            bufferbloat_grade: None,
            packet_loss: None,
            isp: None,
            server_name: None,
            server_location: None,
            external_ip: None,
            result_url: None,
            engine: None,
            error: None,
            samples: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct CarrierMimoLayer {
    pub pci: i32,
    pub arfcn: i64,
    pub band: String,
    pub dl_layers: u8,
    pub ul_layers: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AntennaAlignState {
    pub active: bool,
    pub expires_at: u64,
    pub rsrp: Vec<Option<f64>>,
    pub sinr: Vec<Option<f64>>,
    pub rsrq: Vec<Option<f64>>,
    pub peak_rsrp: Vec<Option<f64>>,
    pub peak_sinr: Vec<Option<f64>>,
    pub samples: u64,
    pub updated_at: u64,
    pub keep_awake: bool,
    pub updated_at_ms: u64,
    pub peak_mean_rsrp: Option<f64>,
    pub peak_mean_sinr: Option<f64>,
    pub rsrp_spread: Option<f64>,
    pub pair01_skew: Option<f64>,
    pub pair23_skew: Option<f64>,
    pub active_chains: u8,
    pub serving_pci: Option<i32>,
    pub serving_band: String,
    pub serving_rat: String,
    pub rrc_state: String,
    pub ca_count: usize,
    pub ca_total_mhz: f64,
    pub ssb_beam_id: Option<i32>,
    pub nr5g_pathloss_db: Option<f64>,
    pub nr5g_tx_pwr: Option<String>,
    pub nr5g_mcs: Option<i32>,
    pub nr5g_ri: Option<i32>,
    pub nr5g_cqi: Option<i32>,
    pub ta_meters: Option<i64>,
    pub mimo_layers: Vec<CarrierMimoLayer>,
    #[serde(skip)]
    pub last_chain_ms: [u64; 4],
}

impl Default for AntennaAlignState {
    fn default() -> Self {
        Self {
            active: false,
            expires_at: 0,
            rsrp: vec![None, None, None, None],
            sinr: vec![None, None, None, None],
            rsrq: vec![None, None, None, None],
            peak_rsrp: vec![None, None, None, None],
            peak_sinr: vec![None, None, None, None],
            samples: 0,
            updated_at: 0,
            keep_awake: false,
            updated_at_ms: 0,
            peak_mean_rsrp: None,
            peak_mean_sinr: None,
            rsrp_spread: None,
            pair01_skew: None,
            pair23_skew: None,
            active_chains: 0,
            serving_pci: None,
            serving_band: String::new(),
            serving_rat: String::new(),
            rrc_state: String::new(),
            ca_count: 0,
            ca_total_mhz: 0.0,
            ssb_beam_id: None,
            nr5g_pathloss_db: None,
            nr5g_tx_pwr: None,
            nr5g_mcs: None,
            nr5g_ri: None,
            nr5g_cqi: None,
            ta_meters: None,
            mimo_layers: Vec::new(),
            last_chain_ms: [0; 4],
        }
    }
}

pub fn sanitize_antenna_label(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(32)
        .collect::<String>()
        .trim()
        .to_string()
}

fn default_cell_lock_deadman_enabled() -> bool {
    true
}

fn default_cell_lock_deadman_secs() -> u64 {
    180
}

fn default_sim_failback_mins() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DaemonSettings {
    pub temperature_unit: String,
    pub measurement_unit: String,
    pub https_redirect: bool,
    pub ping_enabled: bool,
    pub ping_host: String,
    pub ping_interval_sec: u64,
    pub keep_alive_enabled: bool,
    pub eth_link_speed: String,
    pub ttl_value: Option<u8>,
    pub hl_value: Option<u8>,
    pub mtu_value: Option<u16>,
    pub custom_dns: Option<Vec<String>>,
    pub scheduled_reboot_enabled: bool,
    pub scheduled_reboot_time: String,
    pub scheduled_reboot_days: Vec<String>,
    pub quecwatch_enabled: bool,
    pub quecwatch_target: String,
    pub quecwatch_interval_sec: u64,
    pub quecwatch_failures: u32,
    pub quecwatch_max_retries: u32,
    pub quecwatch_connection_refresh: bool,
    pub quecwatch_auto_sim_failover: bool,
    pub quecwatch_high_latency: bool,
    pub quecwatch_latency_ceiling: u64,
    pub cell_lock_sched_enabled: bool,
    pub cell_lock_start_time: String,
    pub cell_lock_end_time: String,
    pub cell_lock_lte: String,
    pub cell_lock_nr5g: String,
    pub cell_lock_lte_persist: bool,
    pub cell_lock_nr5g_persist: bool,
    #[serde(default = "default_cell_lock_deadman_enabled")]
    pub cell_lock_deadman_enabled: bool,
    #[serde(default = "default_cell_lock_deadman_secs")]
    pub cell_lock_deadman_secs: u64,
    #[serde(default)]
    pub preferred_sim_slot: u8,
    #[serde(default = "default_sim_failback_mins")]
    pub sim_failback_mins: u64,
    #[serde(default)]
    pub antenna_labels: [String; 4],
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            temperature_unit: "celsius".into(),
            measurement_unit: "mi".into(),
            https_redirect: true,
            ping_enabled: true,
            ping_host: "8.8.8.8".into(),
            ping_interval_sec: 5,
            keep_alive_enabled: false,
            eth_link_speed: "auto".into(),
            ttl_value: Some(65),
            hl_value: Some(65),
            mtu_value: None,
            custom_dns: None,
            scheduled_reboot_enabled: false,
            scheduled_reboot_time: "04:00".into(),
            scheduled_reboot_days: vec!["sunday".into()],
            quecwatch_enabled: false,
            quecwatch_target: "8.8.8.8".into(),
            quecwatch_interval_sec: 60,
            quecwatch_failures: 3,
            quecwatch_max_retries: 5,
            quecwatch_connection_refresh: true,
            quecwatch_auto_sim_failover: false,
            quecwatch_high_latency: false,
            quecwatch_latency_ceiling: 150,
            cell_lock_sched_enabled: false,
            cell_lock_start_time: "08:00".into(),
            cell_lock_end_time: "22:00".into(),
            cell_lock_lte: String::new(),
            cell_lock_nr5g: String::new(),
            cell_lock_lte_persist: false,
            cell_lock_nr5g_persist: false,
            cell_lock_deadman_enabled: default_cell_lock_deadman_enabled(),
            cell_lock_deadman_secs: default_cell_lock_deadman_secs(),
            preferred_sim_slot: 0,
            sim_failback_mins: default_sim_failback_mins(),
            antenna_labels: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LinkWatchRuntime {
    pub status: String,
    pub message: String,
    pub retry: u32,
    pub current_latency: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SystemInternals {
    pub conntrack_count: u64,
    pub conntrack_max: u64,
    pub conntrack_hashsize: u64,
    pub pcie_aspm: String,
    pub autosleep: String,
    pub boot_slot: String,
    pub usrdata_total_bytes: u64,
    pub usrdata_used_bytes: u64,
    pub usrdata_avail_bytes: u64,
    pub usb_udc: String,
    pub usb_controller: String,
    pub usb_adb_present: bool,
    pub mwan3_running: bool,
    pub keep_alive_enabled: bool,
    pub eth_speed: String,
    #[serde(default)]
    pub cloudflared_present: bool,
    #[serde(default)]
    pub cloudflared_running: bool,
    #[serde(default)]
    pub cloudflared_up: bool,
    #[serde(default)]
    pub cloudflared_ha_connections: u64,
    pub last_reconcile: Option<ReconcileReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertLogEntry {
    pub r#type: String,
    pub message: String,
    pub timestamp: String,
}

pub struct TrafficRuntime {
    pub primary_iface: String,
    pub lan_iface: String,
    pub interfaces: Vec<TrafficInterfaceStats>,
    pub history: VecDeque<TrafficHistoryPoint>,
}

impl Default for TrafficRuntime {
    fn default() -> Self {
        Self {
            primary_iface: "rmnet_data1".into(),
            lan_iface: "eth0".into(),
            interfaces: Vec::new(),
            history: VecDeque::with_capacity(96),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub version: String,
    pub build_package: String,
    pub www_dir: PathBuf,
    pub smd: SmdClient,
    pub auth: AuthStore,
    pub ws_tx: broadcast::Sender<axum::extract::ws::Utf8Bytes>,
    #[allow(dead_code)]
    pub rf_refresh_tx: mpsc::Sender<()>,
    pub modem: Arc<RwLock<ModemSnapshot>>,
    pub secrets: Arc<RwLock<ModemSecrets>>,
    pub rsrp_hist: Arc<RwLock<VecDeque<SignalHistoryPoint>>>,
    pub rsrq_hist: Arc<RwLock<VecDeque<SignalHistoryPoint>>>,
    pub sinr_hist: Arc<RwLock<VecDeque<SignalHistoryPoint>>>,
    pub traffic: Arc<RwLock<TrafficRuntime>>,
    pub data_usage: Arc<RwLock<DataUsageState>>,
    pub ping_realtime: Arc<RwLock<VecDeque<PingPoint>>>,
    pub ping_hourly: Arc<RwLock<VecDeque<PingPoint>>>,
    pub ping_twelvehour: Arc<RwLock<VecDeque<PingPoint>>>,
    pub ping_daily: Arc<RwLock<VecDeque<PingPoint>>>,
    pub memory: Arc<RwLock<MemoryTelemetry>>,
    pub device_uptime: Arc<RwLock<UptimeTelemetry>>,
    pub session_uptime: Arc<RwLock<UptimeTelemetry>>,
    pub internals: Arc<RwLock<SystemInternals>>,
    pub speedtest_live: Arc<RwLock<SpeedtestLiveState>>,
    pub speedtest_history: Arc<RwLock<Vec<SpeedtestRun>>>,
    pub speedtest_pid: Arc<tokio::sync::Mutex<Option<u32>>>,
    pub speedtest_cancel: Arc<tokio::sync::Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    pub antenna_align: Arc<RwLock<AntennaAlignState>>,
    pub align_notify: Arc<Notify>,
    pub phy_diag: Arc<RwLock<crate::radio_tuning::PhyDiagnostics>>,
    pub dsp_telemetry: Arc<RwLock<crate::qmi::dsp::DspTelemetrySnapshot>>,
    pub tls_cert_info: Arc<RwLock<crate::acme::ActiveCertInfo>>,
    pub tuning_cache: Arc<RwLock<Option<(crate::radio_tuning::RadioTuningState, crate::radio_tuning::PhyDiagnostics, std::time::Instant)>>>,
    pub settings: Arc<RwLock<DaemonSettings>>,
    pub quecwatch: Arc<RwLock<LinkWatchRuntime>>,
    pub alerts: Arc<RwLock<VecDeque<AlertLogEntry>>>,
    pub qscan_running: Arc<tokio::sync::Mutex<Option<serde_json::Value>>>,
    pub qscan_last: Arc<RwLock<Option<serde_json::Value>>>,
    pub daemon_logs: Arc<RwLock<VecDeque<String>>>,
    pub audit: crate::audit::AuditLog,
    pub tokens: crate::tokens::TokenStore,
    /// What the band-lock checks remember about the radio (supported bands, last mode).
    pub radio: Arc<std::sync::Mutex<crate::handlers::RadioCache>>,
    /// Held by every radio-changing read-plan-write (band lock, network mode,
    /// cell lock, console / IPC radio writes, scheduled locks): see crate::radio::lock.
    pub radio_lock: Arc<tokio::sync::Mutex<()>>,
    /// True while the cell-lock dead-man's-switch (or LinkWatch stage 3) has temporarily bypassed live modem locks.
    pub cell_lock_bypassed: Arc<std::sync::atomic::AtomicBool>,
    /// Why live cell locks are bypassed (`CellLockBypassReason::to_u8`).
    pub cell_lock_bypass_reason: Arc<std::sync::atomic::AtomicU8>,
    /// True while LinkWatch or cell-lock deadman recovery is actively manipulating the modem.
    pub recovery_in_progress: Arc<std::sync::atomic::AtomicBool>,
    /// Lock-free cached copy of `settings.https_redirect` for hot-path HTTP/HSTS middleware.
    pub https_redirect_cached: Arc<std::sync::atomic::AtomicBool>,
    /// Monotonic heartbeat timestamp (`mono_ms()`) of the RF snapshot loop.
    pub hb_rf_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Monotonic heartbeat timestamp (`mono_ms()`) of the network/usage/vitals loop.
    pub hb_net_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Monotonic heartbeat timestamp (`mono_ms()`) of the ICMP/LinkWatch loop.
    pub hb_linkwatch_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Monotonic heartbeat timestamp (`mono_ms()`) of the HTTP/TLS watcher & request path.
    pub hb_http_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Monotonic timestamp (`mono_ms()`) when an active `AT+QSCAN` started (`0` = none).
    pub qscan_started_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Monotonic timestamp (`mono_ms()`) of the last `phy_diag` refresh (`0` = never).
    pub phy_diag_updated_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Monotonic timestamp (`mono_ms()`) of the last `dsp_telemetry` refresh (`0` = never).
    pub dsp_telemetry_updated_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Sampled daemon resident memory in bytes (`/proc/self/statm`).
    pub process_rss_bytes: Arc<std::sync::atomic::AtomicU64>,
    /// Sampled daemon open file descriptor count (`/proc/self/fd`).
    pub process_open_fds: Arc<std::sync::atomic::AtomicU64>,
    /// Last observed active SIM slot (`0` = not yet observed, `1` or `2`).
    pub last_sim_slot: Arc<std::sync::atomic::AtomicI32>,
    /// Monotonic timestamp (`mono_ms()`) of the most recent SIM slot switch (`0` = none).
    pub sim_switched_at_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Whether `profiles::tick_cell_lock_scheduler` has performed its one-time startup modem lock check.
    pub sched_boot_checked: Arc<std::sync::atomic::AtomicBool>,
    /// Cached `(mcc, mnc, spn)` for `AT+QSPN` chatter avoidance when PLMN is unchanged.
    pub spn_cache: Arc<RwLock<(String, String, String)>>,
}

impl AppState {
    /// Minimal state for router-level tests (no modem: the AT actor's
    /// opener always fails). New AppState fields must be added here too.
    #[cfg(test)]
    pub fn for_tests(www_dir: PathBuf, auth: AuthStore) -> Self {
        Self::for_tests_with_smd(www_dir, auth, SmdClient::spawn_with_opener(Box::new(|| Err("no modem in tests".to_string()))))
    }

    /// Like [`AppState::for_tests`], with the given AT client (e.g. a fake modem).
    #[cfg(test)]
    pub fn for_tests_with_smd(www_dir: PathBuf, auth: AuthStore, smd: SmdClient) -> Self {
        let (ws_tx, _) = broadcast::channel(4);
        let (rf_refresh_tx, _) = mpsc::channel(1);
        let init_hb = mono_ms();
        Self {
            version: "test".into(),
            build_package: "sdxpinn-cellcore".into(),
            www_dir,
            smd,
            auth,
            ws_tx,
            rf_refresh_tx,
            modem: Default::default(),
            secrets: Default::default(),
            rsrp_hist: Default::default(),
            rsrq_hist: Default::default(),
            sinr_hist: Default::default(),
            traffic: Default::default(),
            data_usage: Default::default(),
            ping_realtime: Default::default(),
            ping_hourly: Default::default(),
            ping_twelvehour: Default::default(),
            ping_daily: Default::default(),
            memory: Default::default(),
            device_uptime: Default::default(),
            session_uptime: Arc::new(RwLock::new(UptimeTelemetry::disconnected(0, String::new()))),
            internals: Default::default(),
            speedtest_live: Default::default(),
            speedtest_history: Default::default(),
            speedtest_pid: Default::default(),
            speedtest_cancel: Default::default(),
            antenna_align: Default::default(),
            align_notify: Arc::new(Notify::new()),
            phy_diag: Default::default(),
            dsp_telemetry: Default::default(),
            tls_cert_info: Default::default(),
            tuning_cache: Default::default(),
            settings: Default::default(),
            quecwatch: Default::default(),
            alerts: Default::default(),
            qscan_running: Default::default(),
            qscan_last: Default::default(),
            daemon_logs: Default::default(),
            audit: crate::audit::AuditLog::ram_only(),
            tokens: crate::tokens::TokenStore::ram_only(),
            radio: Default::default(),
            radio_lock: Default::default(),
            cell_lock_bypassed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cell_lock_bypass_reason: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            recovery_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            https_redirect_cached: Arc::new(std::sync::atomic::AtomicBool::new(
                DaemonSettings::default().https_redirect,
            )),
            hb_rf_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
            hb_net_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
            hb_linkwatch_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
            hb_http_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
            qscan_started_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            phy_diag_updated_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dsp_telemetry_updated_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            process_rss_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            process_open_fds: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_sim_slot: Arc::new(std::sync::atomic::AtomicI32::new(0)),
            sim_switched_at_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sched_boot_checked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            spn_cache: Default::default(),
        }
    }

    pub fn push_daemon_log(&self, line: impl Into<String>) {
        let msg = redact_sensitive(&line.into());
        // The process log (procd forwards stderr to syslog / logread) is the
        // durable ledger of what the daemon did, e.g. how many times a Route10
        // recovery action ran. The RAM ring below only feeds the UI and may
        // skip a line under lock contention, so stderr gets every line.
        // Never panic if stderr is gone (panic=abort).
        {
            use std::io::Write;
            let mut se = std::io::stderr().lock();
            let _ = writeln!(se, "cellcored: {msg}");
        }
        let tx_line = format!("[{}] {msg}", format_now_hms());
        if let Ok(mut logs) = self.daemon_logs.try_write() {
            if logs.len() >= 250 {
                logs.pop_front();
            }
            logs.push_back(tx_line);
        }
    }

    pub fn broadcast_json(&self, value: &serde_json::Value) {
        if self.ws_tx.receiver_count() == 0 {
            return;
        }
        if let Ok(text) = serde_json::to_string(value) {
            let _ = self.ws_tx.send(axum::extract::ws::Utf8Bytes::from(text));
        }
    }

    pub fn broadcast_with<F>(&self, build: F)
    where
        F: FnOnce() -> serde_json::Value,
    {
        if self.ws_tx.receiver_count() == 0 {
            return;
        }
        let value = build();
        if let Ok(text) = serde_json::to_string(&value) {
            let _ = self.ws_tx.send(axum::extract::ws::Utf8Bytes::from(text));
        }
    }
}

/// Load persisted JSON state.
///
/// * missing file -> `Default`
/// * file present but unreadable/unparsable (e.g. truncated to 0 bytes by a
///   power cut) -> the bad file is moved aside to `<path>.corrupt.<ts>` so the
///   next flush cannot silently overwrite the evidence/history, then `Default`.
///
/// Persisted structs carry `#[serde(default)]`, so files written by older
/// versions that lack newer fields still load instead of resetting.
pub fn load_json_or_default<T: for<'de> Deserialize<'de> + Default>(path: &str) -> T {
    let mapped = crate::paths::p(path);
    let path = mapped.as_str();
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => {
            eprintln!("cellcored: cannot read {path}: {e}; using defaults");
            return T::default();
        }
    };
    match serde_json::from_slice::<T>(&bytes) {
        Ok(v) => v,
        Err(e) => {
            let aside = format!("{path}.corrupt.{}", crate::auth::now_secs());
            let moved = fs::rename(path, &aside).is_ok();
            eprintln!(
                "cellcored: {path} is unparsable ({e}); {} and using defaults",
                if moved { format!("preserved as {aside}") } else { "could not move it aside".to_string() }
            );
            T::default()
        }
    }
}

static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Create a brand-new temp file whose permissions are `mode` from the moment
/// it exists (never briefly world-readable), regardless of umask.
pub fn create_private_tmp(tmp: &Path, mode: u32) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode & 0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(tmp)?;
    // umask can only remove bits; set the exact final mode on the fd.
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(f)
}

fn fsync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Crash-safe replace: write a uniquely named temp file in the same directory
/// (created with `mode`), fsync it, rename over `path`, then fsync the
/// directory so the rename itself is durable.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    atomic_write_inner(path, data, mode, true)
}

/// Atomic rename-replace for volatile tmpfs files (`/tmp/*`): skips `fsync`
/// (meaningless on tmpfs and avoids blocking worker threads). Falls back to
/// full fsynced `atomic_write` if called with any persistent path.
pub fn atomic_write_tmpfs(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let raw = path.to_string_lossy();
    let is_persistent = raw.starts_with("/etc/")
        || raw.starts_with("/root/")
        || raw.starts_with("/overlay/")
        || raw.contains("/etc/")
        || raw.contains("/root/")
        || raw.contains("/overlay/");
    atomic_write_inner(path, data, mode, is_persistent)
}

fn atomic_write_inner(path: &Path, data: &[u8], mode: u32, sync: bool) -> Result<(), String> {
    use std::io::Write;
    let mapped = PathBuf::from(crate::paths::p(&path.to_string_lossy()));
    let path = mapped.as_path();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _ = fs::create_dir_all(parent);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = parent.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
    let res = (|| -> std::io::Result<()> {
        let mut f = create_private_tmp(&tmp, mode)?;
        f.write_all(data)?;
        if sync {
            f.sync_all()?;
        }
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("atomic write {}: {e}", path.display()));
    }
    if sync {
        fsync_dir(parent);
    }
    Ok(())
}

pub fn save_json_atomic<T: Serialize>(path: &str, value: &T, mode: u32) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value).map_err(|e| format!("serialize {path}: {e}"))?;
    atomic_write(Path::new(path), json.as_bytes(), mode)
}

/// Compact JSON atomic write (`serde_json::to_vec`) for high-churn state files
/// (`data_usage`, `obs_state`, `events`) to minimize UBIFS write amplification.
pub fn save_json_compact_atomic<T: Serialize>(path: &str, value: &T, mode: u32) -> Result<(), String> {
    let json = serde_json::to_vec(value).map_err(|e| format!("serialize {path}: {e}"))?;
    atomic_write(Path::new(path), &json, mode)
}

/// Compact JSON atomic write for volatile tmpfs snapshots (no `fsync`).
pub fn save_json_compact_tmpfs<T: Serialize>(path: &str, value: &T, mode: u32) -> Result<(), String> {
    let json = serde_json::to_vec(value).map_err(|e| format!("serialize {path}: {e}"))?;
    atomic_write_tmpfs(Path::new(path), &json, mode)
}

/// Offload `save_json_atomic` onto Tokio's blocking pool while preserving
/// task-local test sandbox path mapping.
pub async fn save_json_atomic_async<T: Serialize + Send + 'static>(
    path: &str,
    value: T,
    mode: u32,
) -> Result<(), String> {
    let mapped = crate::paths::p(path);
    tokio::task::spawn_blocking(move || save_json_atomic(&mapped, &value, mode))
        .await
        .map_err(|e| format!("save task failed: {e}"))?
}

/// Offload compact JSON atomic write onto Tokio's blocking pool.
pub async fn save_json_compact_atomic_async<T: Serialize + Send + 'static>(
    path: &str,
    value: T,
    mode: u32,
) -> Result<(), String> {
    let mapped = crate::paths::p(path);
    tokio::task::spawn_blocking(move || save_json_compact_atomic(&mapped, &value, mode))
        .await
        .map_err(|e| format!("save task failed: {e}"))?
}

/// Offload compact tmpfs JSON atomic write onto Tokio's blocking pool.
pub async fn save_json_compact_tmpfs_async<T: Serialize + Send + 'static>(
    path: &str,
    value: T,
    mode: u32,
) -> Result<(), String> {
    let mapped = crate::paths::p(path);
    tokio::task::spawn_blocking(move || save_json_compact_tmpfs(&mapped, &value, mode))
        .await
        .map_err(|e| format!("save task failed: {e}"))?
}

pub fn format_now_hms() -> String {
    let dt = crate::tz::local_at(crate::auth::now_secs() as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    )
}

pub fn format_today_ymd() -> (String, String, u8) {
    let dt = crate::tz::local_at(crate::auth::now_secs() as i64);
    (
        format!("{:04}-{:02}-{:02}", dt.year, dt.month, dt.day),
        format!("{:04}-{:02}", dt.year, dt.month),
        dt.day as u8,
    )
}

pub fn redact_sensitive(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            run.push(ch);
        } else {
            if (14..=20).contains(&run.len()) {
                out.push_str("[REDACTED_ID]");
            } else {
                out.push_str(&run);
            }
            run.clear();
            out.push(ch);
        }
    }
    if (14..=20).contains(&run.len()) {
        out.push_str("[REDACTED_ID]");
    } else {
        out.push_str(&run);
    }
    out
}

pub fn load_settings_from_uci_and_disk() -> DaemonSettings {
    let mut s = load_json_or_default::<DaemonSettings>("/etc/cellcore/settings.json");
    if let Some(u) = crate::uci::uci_get_blocking("cellcore.preferences.temperature_unit") {
        s.temperature_unit = u;
    }
    if let Some(u) = crate::uci::uci_get_blocking("cellcore.preferences.measurement_unit") {
        s.measurement_unit = u;
    }
    if let Some(h) = crate::uci::uci_get_blocking("cellcore.ping_daemon.host")
        .or_else(|| crate::uci::uci_get_blocking("cellcore.ping_monitoring.host"))
    {
        s.ping_host = h;
    }
    if let Some(v) = crate::uci::uci_get_blocking("cellcore.ping_daemon.enabled")
        .or_else(|| crate::uci::uci_get_blocking("cellcore.ping_monitoring.enabled"))
    {
        s.ping_enabled = v == "1" || v == "true";
    }
    if let Some(i) = crate::uci::uci_get_blocking("cellcore.ping_daemon.interval")
        && let Ok(n) = i.parse::<u64>()
    {
        s.ping_interval_sec = n.clamp(2, 60);
    }
    if let Some(l) = crate::uci::uci_get_blocking("cellcore.eth_link.speed_limit") {
        s.eth_link_speed = l;
    }
    if let Some(e) = crate::uci::uci_get_blocking("cellcore.linkwatch.enabled") {
        s.quecwatch_enabled = e == "1";
    }
    if let Some(t) = crate::uci::uci_get_blocking("cellcore.linkwatch.ping_target") {
        s.quecwatch_target = t;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qm-state-{tag}-{}-{}", std::process::id(), crate::auth::now_secs()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn settings_missing_new_fields_keep_existing_values() {
        // A settings.json written by an older build that lacks most fields.
        let v: DaemonSettings =
            serde_json::from_str(r#"{"pingHost":"1.1.1.1","httpsRedirect":false}"#).expect("partial settings parse");
        assert_eq!(v.ping_host, "1.1.1.1");
        assert!(!v.https_redirect);
        assert_eq!(v.cell_lock_start_time, "08:00");
        assert!(v.cell_lock_deadman_enabled);
        assert_eq!(v.cell_lock_deadman_secs, 180);
        assert_eq!(v.preferred_sim_slot, 0);
        assert_eq!(v.sim_failback_mins, 30);
        let t1 = mono_ms();
        let t2 = mono_ms();
        assert!(t1 >= 1 && t2 >= t1);
        let u: DataUsageState = serde_json::from_str(
            r#"{"quotaBytes":5,"daily":[{"date":"2026-01-01","rxBytes":1}]}"#,
        )
        .expect("partial data usage parse");
        assert_eq!(u.quota_bytes, Some(5));
        assert_eq!(u.billing_cycle_day, 1);
        assert_eq!(u.daily[0].rx_bytes, 1);
        assert_eq!(u.daily[0].tx_bytes, 0);
    }

    #[test]
    fn corrupt_state_file_is_preserved_not_overwritten() {
        let d = tmpdir("corrupt");
        let p = d.join("data_usage.json");
        fs::write(&p, b"").unwrap(); // power-cut truncation
        let ps = p.to_str().unwrap();
        let v: DataUsageState = load_json_or_default(ps);
        assert!(v.daily.is_empty());
        let aside: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("data_usage.json.corrupt."))
            .collect();
        assert_eq!(aside.len(), 1, "corrupt file must be moved aside");
        assert!(!p.exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn atomic_write_replaces_with_exact_mode_and_no_leftovers() {
        let d = tmpdir("atomic");
        let p = d.join("settings.json");
        fs::write(&p, b"old").unwrap();
        atomic_write(&p, b"{\"a\":1}", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"{\"a\":1}");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        atomic_write(&p, b"x", 0o644).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o644);
        let names: Vec<String> = fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        assert_eq!(names, vec!["settings.json".to_string()]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn private_tmp_is_never_world_readable() {
        let d = tmpdir("tmpmode");
        let t = d.join(".shadow.tmp");
        let f = create_private_tmp(&t, 0o600).unwrap();
        // Checked on the freshly created file, before any data is written.
        assert_eq!(f.metadata().unwrap().mode() & 0o777, 0o600);
        drop(f);
        // create_new: never follows/reuses an existing (attacker-planted) file
        assert!(create_private_tmp(&t, 0o600).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    /// HARD-08: every write of persistent state (anything under /etc, /root or
    /// /overlay) goes through `atomic_write`, which fsyncs the temp file before
    /// the rename and the directory after it. A bare `fs::write` / `File::create`
    /// can be torn by a power cut; a hand-rolled rename (or copy) is not
    /// durable without the directory fsync. Scans the production code of
    /// every module (test modules excluded).
    #[test]
    fn persistent_writes_all_go_through_atomic_write() {
        fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
            for e in fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    rs_files(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        rs_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        assert!(files.len() > 20, "source scan found {} files", files.len());
        let sources: Vec<(PathBuf, String)> = files
            .into_iter()
            .map(|f| {
                let text = fs::read_to_string(&f).unwrap();
                (f, text)
            })
            .collect();
        let offenders = persistent_write_offenders(&sources);
        assert!(offenders.is_empty(), "persistent writes bypassing state::atomic_write:\n{}", offenders.join("\n"));
    }

    // ---------------- HARD-08 source scanner ----------------

    fn is_persistent_path(v: &str) -> bool {
        ["/etc/", "/root/", "/overlay/"].iter().any(|pre| v.starts_with(pre))
    }

    fn is_ident_char(ch: char) -> bool {
        ch.is_alphanumeric() || ch == '_'
    }

    /// `name` occurs in `code` as a whole identifier.
    fn mentions_ident(code: &str, name: &str) -> bool {
        !name.is_empty()
            && code.match_indices(name).any(|(i, _)| {
                !code[..i].chars().last().is_some_and(is_ident_char)
                    && !code[i + name.len()..].chars().next().is_some_and(is_ident_char)
            })
    }

    /// The statement that starts on line `i`, joined up to the line ending it.
    fn statement(lines: &[String], i: usize) -> String {
        let mut s = String::new();
        for l in lines.iter().skip(i).take(16) {
            s.push_str(l.trim());
            s.push(' ');
            let t = l.trim_end();
            if t.ends_with(';') || t.ends_with('{') || t.ends_with('}') {
                break;
            }
        }
        s
    }

    /// Arguments of the call whose `(` immediately precedes `text`.
    fn call_args(text: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut cur = String::new();
        let mut depth = 0i32;
        let mut in_str = false;
        let mut prev = ' ';
        for ch in text.chars() {
            if in_str {
                cur.push(ch);
                if ch == '"' && prev != '\\' {
                    in_str = false;
                }
                prev = ch;
                continue;
            }
            match ch {
                '"' => in_str = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => {
                    args.push(cur.trim().to_string());
                    return args;
                }
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    args.push(std::mem::take(&mut cur).trim().to_string());
                    prev = ch;
                    continue;
                }
                _ => {}
            }
            cur.push(ch);
            prev = ch;
        }
        args.push(cur.trim().to_string());
        args
    }

    /// One function of a scanned file: lines `start..end`, its parameter
    /// names (`self` excluded, so they line up with call-site arguments).
    struct FnScope {
        name: String,
        params: Vec<String>,
        sig: String,
        start: usize,
        end: usize,
    }

    fn fn_name(line: &str) -> Option<String> {
        let mut t = line.trim_start();
        loop {
            let before = t;
            for kw in ["pub(crate) ", "pub(super) ", "pub ", "const ", "async ", "unsafe ", "extern \"C\" "] {
                t = t.strip_prefix(kw).unwrap_or(t);
            }
            if t == before {
                break;
            }
        }
        let name: String = t.strip_prefix("fn ")?.chars().take_while(|c| is_ident_char(*c)).collect();
        (!name.is_empty()).then_some(name)
    }

    fn fn_scopes(lines: &[String]) -> Vec<FnScope> {
        let mut scopes = vec![FnScope {
            name: String::new(),
            params: Vec::new(),
            sig: String::new(),
            start: 0,
            end: lines.len(),
        }];
        for (i, line) in lines.iter().enumerate() {
            let Some(name) = fn_name(line) else { continue };
            if let Some(last) = scopes.last_mut() {
                last.end = i;
            }
            let mut sig = String::new();
            for l in lines.iter().skip(i).take(12) {
                sig.push_str(l.trim());
                sig.push(' ');
                if l.contains('{') || l.trim_end().ends_with(';') {
                    break;
                }
            }
            let params = sig
                .find(&format!("{name}("))
                .or_else(|| sig.find(&format!("{name}<")))
                .and_then(|at| sig[at..].find('(').map(|p| at + p + 1))
                .map(|open| call_args(&sig[open..]))
                .unwrap_or_default()
                .into_iter()
                .filter(|a| !a.is_empty() && !a.trim_start_matches('&').trim_start_matches("mut ").starts_with("self"))
                .map(|a| {
                    let pat = a.split(':').next().unwrap_or("").trim().trim_start_matches("mut ").to_string();
                    if pat.chars().all(is_ident_char) { pat } else { String::new() }
                })
                .collect();
            scopes.push(FnScope {
                name,
                params,
                sig,
                start: i,
                end: lines.len(),
            });
        }
        scopes
    }

    /// Names that denote a persistent path anywhere in the crate.
    #[derive(Default)]
    struct PathNames {
        /// `const`/`static` &str items holding a persistent path.
        consts: Vec<String>,
        /// Parameterless functions returning a path built from one.
        helpers: Vec<String>,
    }

    /// `expr` evaluates to (or is built from) a persistent path: a literal
    /// (also inside `format!`), a persistent const, a path helper call, or a
    /// local bound to any of these.
    fn names_persistent(expr: &str, names: &PathNames, locals: &[String]) -> bool {
        expr.split('"').skip(1).step_by(2).any(is_persistent_path)
            || names.consts.iter().any(|c| mentions_ident(expr, c))
            || names.helpers.iter().any(|h| {
                expr.match_indices(&format!("{h}(")).any(|(i, _)| !expr[..i].chars().last().is_some_and(is_ident_char))
            })
            || locals.iter().any(|l| mentions_ident(expr, l))
    }

    /// Locals of `scope` bound (directly or through other locals) to a
    /// persistent path: `let path = p(&format!("/etc/config/{c}"));`,
    /// `let dir = Path::new(KEYS).parent()`, `if let Some(d) = path.parent()`.
    fn tainted_locals(lines: &[String], scope: &FnScope, names: &PathNames) -> Vec<String> {
        let mut locals: Vec<String> = Vec::new();
        loop {
            let mut changed = false;
            for i in scope.start..scope.end {
                let line = &lines[i];
                let Some(at) = line.match_indices("let ").map(|(i, _)| i).find(|&i| !line[..i].chars().last().is_some_and(is_ident_char)) else {
                    continue;
                };
                let mut pat = line[at + 4..].trim_start().trim_start_matches("mut ");
                for wrap in ["Some(", "Ok("] {
                    pat = pat.strip_prefix(wrap).unwrap_or(pat);
                }
                let name: String = pat.chars().take_while(|c| is_ident_char(*c)).collect();
                if name.is_empty() || name == "_" || locals.contains(&name) {
                    continue;
                }
                let stmt = statement(lines, i);
                let Some(eq) = stmt.find(" = ") else { continue };
                if names_persistent(&stmt[eq..], names, &locals) {
                    locals.push(name);
                    changed = true;
                }
            }
            if !changed {
                return locals;
            }
        }
    }

    /// The path argument of a raw write on `stmt`, if it has one:
    /// `fs::write(P, ..)`, `File::create(P)`, `OpenOptions::new()...open(P)`.
    fn raw_write_target(stmt: &str) -> Option<String> {
        for direct in ["fs::write(", "File::create(", "File::create_new("] {
            if let Some(i) = stmt.find(direct) {
                return call_args(&stmt[i + direct.len()..]).into_iter().next();
            }
        }
        for builder in ["OpenOptions::new()", "File::options()"] {
            if let Some(i) = stmt.find(builder) {
                return Some(match stmt[i..].find(".open(") {
                    Some(o) => call_args(&stmt[i + o + ".open(".len()..]).into_iter().next().unwrap_or_default(),
                    // opened elsewhere: judge the whole statement
                    None => stmt.to_string(),
                });
            }
        }
        None
    }

    /// Production-code lines that write a persistent path without
    /// `atomic_write`. Besides literal paths and persistent consts on the
    /// write itself, follows paths through `format!`, local bindings,
    /// parameterless path helpers and function parameters (call sites that
    /// pass a persistent path into a function that writes its parameter raw).
    fn persistent_write_offenders(sources: &[(PathBuf, String)]) -> Vec<String> {
        struct File<'a> {
            path: &'a Path,
            lines: Vec<String>,
            scopes: Vec<FnScope>,
        }
        let files: Vec<File> = sources
            .iter()
            .map(|(f, text)| {
                let prod = match text.find("#[cfg(test)]\nmod tests") {
                    Some(i) => &text[..i],
                    None => text.as_str(),
                };
                let lines: Vec<String> = prod.lines().map(|l| l.split("//").next().unwrap_or("").to_string()).collect();
                let scopes = fn_scopes(&lines);
                File { path: f, lines, scopes }
            })
            .collect();
        let mut names = PathNames::default();
        for file in &files {
            for (i, line) in file.lines.iter().enumerate() {
                let mut l = line.trim_start();
                for kw in ["pub(crate) ", "pub "] {
                    l = l.strip_prefix(kw).unwrap_or(l);
                }
                let Some(rest) = l.strip_prefix("const ").or_else(|| l.strip_prefix("static ")) else { continue };
                let name: String = rest.chars().take_while(|c| is_ident_char(*c)).collect();
                let stmt = statement(&file.lines, i);
                if let Some(eq) = stmt.find('=')
                    && stmt[eq..].split('"').skip(1).step_by(2).any(is_persistent_path)
                {
                    names.consts.push(name);
                }
            }
        }
        loop {
            let mut changed = false;
            for file in &files {
                for s in &file.scopes {
                    let returns_path = ["-> String", "-> PathBuf", "-> std::path::PathBuf", "-> &'static str", "-> &str"]
                        .iter()
                        .any(|r| s.sig.contains(r));
                    if s.name.is_empty() || !s.params.is_empty() || !returns_path || names.helpers.contains(&s.name) {
                        continue;
                    }
                    let body = file.lines[s.start..s.end].join("\n");
                    let body = body.split_once('{').map(|(_, b)| b).unwrap_or("");
                    if names_persistent(body, &names, &[]) {
                        names.helpers.push(s.name.clone());
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let mut offenders = Vec::new();
        // (function name, parameter index, where its raw write is)
        let mut param_sinks: Vec<(String, usize, String)> = Vec::new();
        let mut locals_of: Vec<Vec<Vec<String>>> = Vec::new();
        for file in &files {
            let in_state = file.path.ends_with("state.rs");
            let locals: Vec<Vec<String>> = file.scopes.iter().map(|s| tainted_locals(&file.lines, s, &names)).collect();
            for (si, scope) in file.scopes.iter().enumerate() {
                for n in scope.start..scope.end {
                    let code = file.lines[n].as_str();
                    let raw_write = ["fs::write(", "File::create(", "OpenOptions::new()"].iter().any(|c| code.contains(c));
                    let raw_write = raw_write || ["File::create_new(", "File::options()"].iter().any(|c| code.contains(c));
                    let raw_replace = ["fs::rename(", "fs::copy("].iter().any(|c| code.contains(c));
                    if !raw_write && !raw_replace {
                        continue;
                    }
                    let at = format!("{}:{}: {}", file.path.display(), n + 1, code.trim());
                    // state.rs owns atomic_write (and moves corrupt files aside).
                    if raw_replace && !in_state {
                        offenders.push(at);
                        continue;
                    }
                    if !raw_write {
                        continue;
                    }
                    let target = raw_write_target(&statement(&file.lines, n)).unwrap_or_default();
                    if names_persistent(code, &names, &[]) || names_persistent(&target, &names, &locals[si]) {
                        offenders.push(at);
                    } else if let Some(k) = scope.params.iter().position(|p| mentions_ident(&target, p)) {
                        param_sinks.push((scope.name.clone(), k, at));
                    }
                }
            }
            locals_of.push(locals);
        }
        // Call sites passing a persistent path into a parameter that is
        // written raw (followed through parameters of the callers too).
        let mut done = 0;
        while done < param_sinks.len() {
            let (callee, k, sink) = param_sinks[done].clone();
            done += 1;
            let needle = format!("{callee}(");
            for (fi, file) in files.iter().enumerate() {
                for (si, scope) in file.scopes.iter().enumerate() {
                    for n in scope.start..scope.end {
                        let line = &file.lines[n];
                        let is_call = line.match_indices(&needle).any(|(i, _)| {
                            !line[..i].chars().last().is_some_and(is_ident_char) && !line[..i].trim_end().ends_with("fn")
                        });
                        if !is_call {
                            continue;
                        }
                        let stmt = statement(&file.lines, n);
                        let Some(i) = stmt.find(&needle) else { continue };
                        let Some(arg) = call_args(&stmt[i + needle.len()..]).into_iter().nth(k) else { continue };
                        let at = format!("{}:{}: {} (raw write at {sink})", file.path.display(), n + 1, line.trim());
                        if names_persistent(&arg, &names, &locals_of[fi][si]) {
                            offenders.push(at);
                        } else if let Some(j) = scope.params.iter().position(|p| mentions_ident(&arg, p))
                            && !param_sinks.iter().any(|(f, x, _)| *f == scope.name && *x == j)
                        {
                            param_sinks.push((scope.name.clone(), j, sink.clone()));
                        }
                    }
                }
            }
        }
        offenders
    }

    #[test]
    fn persistent_write_scan_follows_formatted_and_variable_paths() {
        let scan = |src: &str| persistent_write_offenders(&[(PathBuf::from("src/x.rs"), src.to_string())]);
        // The 4.1.0 uci.rs bypass: a formatted /etc/config path bound to a
        // local, written raw on another line.
        let uci = "pub async fn ensure_uci_config_file(config: &str) {\n    let path = crate::paths::p(&format!(\"/etc/config/{config}\"));\n    if !Path::new(&path).exists() {\n        let _ = tokio::fs::write(&path, \"\").await;\n    }\n}\n";
        assert_eq!(scan(uci).len(), 1, "{:?}", scan(uci));
        assert!(scan(uci)[0].contains("tokio::fs::write(&path"));
        // the same path written through the crash-safe writer is fine
        let fixed = uci.replace("tokio::fs::write(&path, \"\").await", "crate::state::atomic_write(Path::new(&path), b\"\", 0o644)");
        assert!(scan(&fixed).is_empty(), "{:?}", scan(&fixed));
        // a temp file next to a persistent const, opened by a builder chain
        let keys = "const KEYS: &str = \"/etc/dropbear/authorized_keys\";\nfn write_keys(content: &str) -> Result<(), String> {\n    let dir = std::path::Path::new(KEYS).parent().ok_or(\"bad path\")?;\n    let tmp = dir.join(\".keys.tmp\");\n    let mut f = std::fs::OpenOptions::new()\n        .write(true)\n        .create(true)\n        .open(&tmp)\n        .map_err(|e| e.to_string())?;\n    f.write_all(content.as_bytes()).map_err(|e| e.to_string())\n}\n";
        assert_eq!(scan(keys).len(), 1, "{:?}", scan(keys));
        // a parameter written raw, called with a persistent path (two hops)
        let param = "fn put(target: &str, body: &[u8]) {\n    let _ = std::fs::write(target, body);\n}\nfn put_cfg(name: &str) {\n    put(name, b\"x\");\n}\nfn caller(n: &str) {\n    put_cfg(&format!(\"/root/{n}\"));\n    put(\"/tmp/scratch\", b\"y\");\n}\n";
        let found = scan(param);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("put_cfg(&format!"), "{found:?}");
        // a parameterless helper returning a persistent path
        let helper = "fn cfg_path() -> String {\n    crate::paths::p(\"/overlay/upper/etc/x\")\n}\nfn save(b: &[u8]) {\n    let _ = std::fs::File::create(cfg_path());\n}\n";
        assert_eq!(scan(helper).len(), 1, "{:?}", scan(helper));
        // volatile paths and persistent *content* are not persistent writes
        let volatile = "fn f(config: &str) {\n    let src = crate::paths::p(&format!(\"/etc/config/{config}\"));\n    let body = std::fs::read(&src).unwrap();\n    let tmp = format!(\"/tmp/{config}\");\n    let _ = std::fs::write(&tmp, body);\n}\n";
        assert!(scan(volatile).is_empty(), "{:?}", scan(volatile));
    }

    #[test]
    fn sanitize_antenna_label_trims_strips_ctrl_and_caps_len() {
        assert_eq!(super::sanitize_antenna_label("  Jack 1 · Far Left \n\t "), "Jack 1 · Far Left");
        let long = "A".repeat(60);
        assert_eq!(super::sanitize_antenna_label(&long).len(), 32);
        let cfg: super::DaemonSettings = serde_json::from_str("{}").expect("empty json defaults");
        assert_eq!(cfg.antenna_labels, ["", "", "", ""]);
    }
}
