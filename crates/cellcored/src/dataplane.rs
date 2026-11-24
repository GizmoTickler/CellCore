//! Clean-room native Rust QRTR/QMI + `RTNETLINK` data-plane supervisor, kernel
//! offload/sysctl inspection & tuning, and `/api/v1/dataplane/*` REST API.

use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock, mpsc};

use crate::{
    admin::{bad, require_confirm, server},
    admin::exec::{ExecOpts, KIB, run},
    auth::now_secs,
    http::HttpCtx,
    netlink::{self, NetlinkAddr, NetlinkLink, NetlinkRoute},
    qmi::{
        self, QmiError, QmiIndication, SVC_DMS, SVC_NAS, SVC_UIM, SVC_WDA, SVC_WDS,
        ServiceEndpoint,
        dms,
        nas::{self, RfBandEntry, SignalInfoSnapshot, SysInfoSnapshot},
        qrtr::{QrtrBus, QrtrBusEvent, QrtrServiceClient},
        uim::{self, UimCardStatus},
        wda::{self, WdaDataFormat},
        wds::{
            self, PktConnStatus, PktSrvcStatus, StartParams, WDS_PKT_SRVC_STATUS_IND,
            WdsProfileSummary, WdsRuntimeSettings,
        },
    },
    state::{AppState, atomic_write, save_json_atomic, save_json_compact_tmpfs},
};

pub const DATAPLANE_CONFIG_PATH: &str = "/etc/cellcore/dataplane.json";
pub const NATIVE_STATE_PATH: &str = "/var/run/cellcore-native-state.json";
pub const CONFIRM_NATIVE: &str = "NATIVE";
const NATIVE_WDS_START_TIMEOUT: Duration = Duration::from_secs(30);
const QMI_IND_DEBOUNCE_WINDOW: Duration = Duration::from_millis(300);

pub fn routes() -> Router<HttpCtx> {
    Router::new()
        .route("/api/v1/dataplane/status", get(get_status))
        .route("/api/v1/dataplane/profiles", get(get_profiles))
        .route("/api/v1/dataplane/config", post(post_config))
        .route("/api/v1/dataplane/reconnect", post(post_reconnect))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DataplaneMode {
    #[default]
    Coexist,
    Native,
}

impl DataplaneMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coexist => "coexist",
            Self::Native => "native",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    Ipv4,
    Ipv6,
    #[default]
    Ipv4v6,
}

impl IpFamily {
    pub fn wants_v4(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv4v6)
    }

    pub fn wants_v6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::Ipv4v6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KernelTuningProfile {
    #[default]
    Default,
    HighThroughput,
}

impl KernelTuningProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::HighThroughput => "high-throughput",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DataplaneConfig {
    pub mode: DataplaneMode,
    pub iface: String,
    pub mux_id: u8,
    pub ep_type: u32,
    pub ep_iface_id: u32,
    pub profile_index: u8,
    pub ip_family: IpFamily,
    pub route_table: u32,
    pub ippt: bool,
    pub ippt_mac: Option<String>,
    pub ippt_dev_type: String,
    pub ippt_skip_nat: bool,
    pub ippt_vlan: u16,
    pub manage_dns: bool,
    pub ipv6_prefix_sharing: bool,
    pub preserve_ipa_offload: bool,
    pub kernel_tuning: KernelTuningProfile,
    #[serde(default)]
    pub sfe_fastpath: bool,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            mode: DataplaneMode::Coexist,
            iface: "rmnet_data0".into(),
            mux_id: 1,
            ep_type: wda::EP_TYPE_EMBEDDED,
            ep_iface_id: 1,
            profile_index: 1,
            ip_family: IpFamily::Ipv4v6,
            route_table: netlink::TABLE_MAIN,
            ippt: false,
            ippt_mac: None,
            ippt_dev_type: "eth0".into(),
            ippt_skip_nat: true,
            ippt_vlan: 0,
            manage_dns: true,
            ipv6_prefix_sharing: true,
            preserve_ipa_offload: true,
            kernel_tuning: KernelTuningProfile::Default,
            sfe_fastpath: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrtrTelemetry {
    pub available: bool,
    pub local_node: Option<u32>,
    pub modem_node: u32,
    pub ssr_count: u64,
    pub last_ssr_epoch: Option<u64>,
    pub services: Vec<ServiceEndpoint>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WdsFamilySnapshot {
    pub state: &'static str,
    pub handle: Option<u32>,
    pub pkt_status: Option<PktSrvcStatus>,
    pub runtime: Option<WdsRuntimeSettings>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpaOffloadTelemetry {
    pub hw_type: Option<String>,
    pub clk_rate_mhz: Option<u64>,
    pub clock_scaling_enabled: Option<bool>,
    pub nominal_mbps: Option<u64>,
    pub turbo_mbps: Option<u64>,
    pub napi_chain_enabled: Option<bool>,
    pub eth_offload_driver: Option<String>,
    pub eth_hwp_rx_packets: Option<u64>,
    pub eth_exp_rx_packets: Option<u64>,
    pub eth_hwp_tx_packets: Option<u64>,
    pub eth_exp_tx_packets: Option<u64>,
    pub eth_hardware_offload_pct: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelTelemetry {
    pub tcp_congestion_control: String,
    pub tcp_available_congestion_control: Vec<String>,
    pub default_qdisc: String,
    pub rmem_max: Option<u64>,
    pub wmem_max: Option<u64>,
    pub tcp_rmem: String,
    pub tcp_wmem: String,
    pub netdev_max_backlog: Option<u64>,
    pub netdev_budget: Option<u64>,
    pub netdev_budget_usecs: Option<u64>,
    pub tcp_slow_start_after_idle: Option<u64>,
    pub tcp_mtu_probing: Option<u64>,
    pub tcp_notsent_lowat: Option<u64>,
    pub rps_sock_flow_entries: Option<u64>,
    pub tcp_fastopen: Option<u64>,
    pub conntrack_max: Option<u64>,
    pub conntrack_count: Option<u64>,
    pub conntrack_hashsize: Option<u64>,
    pub cpu_governor: Option<String>,
    pub cpu_cur_freq_mhz: Option<u64>,
    pub cpu_max_freq_mhz: Option<u64>,
    pub rps_maps: HashMap<String, String>,
    pub xps_maps: HashMap<String, String>,
    pub ipa_dev_present: bool,
    pub ipacm_running: bool,
    pub qcmap_running: bool,
    pub netmgrd_running: bool,
    pub ipa_offload: IpaOffloadTelemetry,
    pub active_tuning: KernelTuningProfile,
    pub tuning_warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataplaneSnapshot {
    pub updated_at: u64,
    pub mode: DataplaneMode,
    pub supervisor_state: String,
    pub qrtr: QrtrTelemetry,
    pub device_rev: Option<String>,
    pub operating_mode: Option<String>,
    pub uim: Option<UimCardStatus>,
    pub nas_sys: Option<SysInfoSnapshot>,
    pub nas_signal: Option<SignalInfoSnapshot>,
    pub nas_bands: Vec<RfBandEntry>,
    pub wda_format: Option<WdaDataFormat>,
    pub wds_v4: WdsFamilySnapshot,
    pub wds_v6: WdsFamilySnapshot,
    pub profiles: Vec<WdsProfileSummary>,
    pub profiles_source: Option<String>,
    pub links: Vec<NetlinkLink>,
    pub addrs: Vec<NetlinkAddr>,
    pub routes: Vec<NetlinkRoute>,
    pub kernel: KernelTelemetry,
    pub applied_dns: Vec<String>,
    pub active_ippt_mac: Option<String>,
    pub ipa_ippt_active: bool,
    pub ipa_v6_sharing_prefix: Option<String>,
    pub ipa_cli_present: bool,
    pub sfe_loaded: bool,
    pub indications_received: u64,
    pub reconnect_attempts: u64,
    pub netlink_updates: u64,
    pub last_indication: Option<String>,
    pub warnings: Vec<String>,
}

/// Exponential backoff sequence `{5, 10, 20, 40, 60}` seconds used in `Native` mode.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    step: usize,
}

impl ReconnectBackoff {
    pub const SCHEDULE_SECS: [u64; 5] = [5, 10, 20, 40, 60];

    pub fn new() -> Self {
        Self { step: 0 }
    }

    pub fn next_delay(&mut self) -> Duration {
        let secs = Self::SCHEDULE_SECS[self.step.min(Self::SCHEDULE_SECS.len() - 1)];
        if self.step + 1 < Self::SCHEDULE_SECS.len() {
            self.step += 1;
        }
        Duration::from_secs(secs)
    }

    pub fn reset(&mut self) {
        self.step = 0;
    }

    #[cfg(test)]
    pub fn current_step(&self) -> usize {
        self.step
    }
}

struct DataplaneHub {
    config: RwLock<DataplaneConfig>,
    snapshot: RwLock<DataplaneSnapshot>,
    wake: Notify,
    tuning_warnings: Mutex<Vec<String>>,
    reconnect_queue: Mutex<Option<String>>,
    shutdown_requested: AtomicBool,
    supervisor_running: AtomicBool,
    done_notify: Notify,
}

type EthtoolGroFeatures = (Option<bool>, Option<bool>);

/// Persistent Native-mode handoff & pre-tuning sysctl baseline saved to
/// `/var/run/cellcore-native-state.json` so stop, crash-restart, or `opkg remove`
/// (`dataplane-restore`) can cleanly restore `netmgrd`/QCMAP, `mwan3`, DNS,
/// firewall rules, and original pre-tuning sysctls.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct PersistedNativeState {
    pub native_active: bool,
    pub vendor_daemons_stopped: bool,
    pub mwan3_stopped: bool,
    pub iface: Option<String>,
    pub route_table: Option<u32>,
    pub created_rmnet_iface: Option<String>,
    pub saved_resolv: Option<SavedResolvSnapshot>,
    pub ippt_dnsmasq_active: bool,
    pub ipa_ippt_active: bool,
    pub ipa_ippt_dev_type: Option<String>,
    pub ipa_ippt_vlan: u16,
    pub ipa_v6_sharing_active: bool,
    /// Original sysctl values captured strictly BEFORE applying high-throughput tuning.
    pub baseline_sysctls: Vec<(String, String)>,
    pub baseline_irq_affinities: HashMap<String, String>,
    pub baseline_ethtool_features: HashMap<String, EthtoolGroFeatures>,
}

static HUB: OnceLock<Arc<DataplaneHub>> = OnceLock::new();
static NATIVE_STATE_LOCK: Mutex<()> = Mutex::new(());
static LAST_WRITTEN_NATIVE_STATE: Mutex<Option<(String, PersistedNativeState)>> = Mutex::new(None);
static BASELINE_SYSCTLS: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();
static BASELINE_IRQ_AFFINITIES: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static BASELINE_ETHTOOL_FEATURES: OnceLock<Mutex<HashMap<String, EthtoolGroFeatures>>> =
    OnceLock::new();
/// Monotonic milliseconds (`crate::state::mono_ms()`) when the native bearer connected (`0` = disconnected).
static NATIVE_CONNECTED_SINCE: AtomicU64 = AtomicU64::new(0);
static NATIVE_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);
static NATIVE_WDS_V4_CONNECTED: AtomicBool = AtomicBool::new(false);
static NATIVE_WDS_V6_CONNECTED: AtomicBool = AtomicBool::new(false);
static FORCE_FW_HEAL: AtomicBool = AtomicBool::new(false);
static SFE_LOADED_BY_US: AtomicBool = AtomicBool::new(false);

fn load_persisted_native_state_locked() -> Option<PersistedNativeState> {
    let p = crate::paths::p(NATIVE_STATE_PATH);
    let raw = fs::read_to_string(&p).ok()?;
    serde_json::from_str::<PersistedNativeState>(&raw).ok()
}

fn save_persisted_native_state_locked(st: &PersistedNativeState) -> Result<(), String> {
    let p = crate::paths::p(NATIVE_STATE_PATH);
    {
        let last = LAST_WRITTEN_NATIVE_STATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((ref last_p, ref last_st)) = *last
            && last_p == &p
            && last_st == st
            && Path::new(&p).exists()
        {
            return Ok(());
        }
    }
    save_json_compact_tmpfs(&p, st, 0o600)?;
    *LAST_WRITTEN_NATIVE_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some((p, st.clone()));
    Ok(())
}

fn clear_persisted_native_state_locked() {
    let p = crate::paths::p(NATIVE_STATE_PATH);
    let _ = fs::remove_file(&p);
    let mut last = LAST_WRITTEN_NATIVE_STATE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if last.as_ref().is_some_and(|(lp, _)| lp == &p) {
        *last = None;
    }
}

pub fn load_persisted_native_state() -> Option<PersistedNativeState> {
    let _guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    load_persisted_native_state_locked()
}

#[cfg(test)]
pub fn save_persisted_native_state(st: &PersistedNativeState) -> Result<(), String> {
    let _guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    save_persisted_native_state_locked(st)
}

pub fn clear_persisted_native_state() {
    let _guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_persisted_native_state_locked();
}

/// True when at least one native QMI WDS family (IPv4 or IPv6) is currently connected.
pub fn is_wds_connected() -> bool {
    NATIVE_WDS_V4_CONNECTED.load(Ordering::Acquire)
        || NATIVE_WDS_V6_CONNECTED.load(Ordering::Acquire)
}

/// Immediately wake the native supervisor to re-assert native fw4/nft/iptables rules
/// (e.g. right after an external or hardening `fw4 reload`).
pub fn request_native_firewall_heal() {
    FORCE_FW_HEAL.store(true, Ordering::Release);
    if let Some(h) = HUB.get() {
        h.wake.notify_one();
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn set_native_wds_state_for_test(native_mode: bool, v4: bool, v6: bool) {
    NATIVE_MODE_ACTIVE.store(native_mode, Ordering::Release);
    NATIVE_WDS_V4_CONNECTED.store(v4, Ordering::Release);
    NATIVE_WDS_V6_CONNECTED.store(v6, Ordering::Release);
}

const IPPT_DNSMASQ_CONF_PATH: &str = "/tmp/dnsmasq.d/99-cellcore-ippt.conf";

/// True when Qualcomm Shortcut Forwarding Engine (`shortcut_fe`) is currently loaded in the kernel.
pub fn is_sfe_loaded() -> bool {
    Path::new(&crate::paths::p("/sys/module/shortcut_fe")).exists()
        || Path::new(&crate::paths::p("/sys/sfe_ipv4")).exists()
}

pub(crate) fn sfe_mutual_exclusion_warning(
    preserve_ipa_offload: bool,
    ippt: bool,
) -> Option<String> {
    match (preserve_ipa_offload, ippt) {
        (true, true) => Some(
            "SFE fastpath refused: mutually exclusive with IPA hardware offload (preserveIpaOffload) and IP Passthrough (ippt)"
                .into(),
        ),
        (true, false) => Some(
            "SFE fastpath refused: mutually exclusive with IPA hardware offload (preserveIpaOffload)"
                .into(),
        ),
        (false, true) => Some(
            "SFE fastpath refused: mutually exclusive with IP Passthrough (ippt)".into(),
        ),
        (false, false) => None,
    }
}

pub(crate) async fn reconcile_sfe_fastpath_with_guard(
    enable: bool,
    force_unload: bool,
    preserve_ipa_offload: bool,
    ippt: bool,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let opt_bin = "/usr/sbin/data_path_opt";
    if enable {
        if let Some(warn) = sfe_mutual_exclusion_warning(preserve_ipa_offload, ippt) {
            warnings.push(warn);
            if SFE_LOADED_BY_US.load(Ordering::Relaxed) && is_sfe_loaded() {
                if Path::new(&crate::paths::p(opt_bin)).exists() {
                    let _ = run(opt_bin, &["-u", "SFE"], ExecOpts::new(10, 16 * KIB)).await;
                }
                if is_sfe_loaded() {
                    for kmod in ["shortcut_fe_cm", "shortcut_fe_ipv6", "shortcut_fe"] {
                        let _ = run("rmmod", &[kmod], ExecOpts::new(5, 16 * KIB)).await;
                    }
                }
                if !is_sfe_loaded() {
                    SFE_LOADED_BY_US.store(false, Ordering::Relaxed);
                }
            }
            crate::radio_tuning::set_cached_sfe_state(Some(is_sfe_loaded()));
            return warnings;
        }
        if !is_sfe_loaded() {
            if Path::new(&crate::paths::p(opt_bin)).exists() {
                let _ = run(opt_bin, &["-l", "SFE"], ExecOpts::new(10, 16 * KIB)).await;
            }
            if !is_sfe_loaded() {
                for kmod in ["shortcut-fe", "shortcut-fe-ipv6", "shortcut-fe-cm"] {
                    let _ = run("modprobe", &[kmod], ExecOpts::new(5, 16 * KIB)).await;
                }
            }
            if is_sfe_loaded() {
                SFE_LOADED_BY_US.store(true, Ordering::Relaxed);
            } else {
                warnings.push("Failed to load Qualcomm SFE fastpath modules (shortcut-fe)".into());
            }
        } else {
            SFE_LOADED_BY_US.store(true, Ordering::Relaxed);
        }
    } else if force_unload || SFE_LOADED_BY_US.load(Ordering::Relaxed) {
        if is_sfe_loaded() {
            if Path::new(&crate::paths::p(opt_bin)).exists() {
                let _ = run(opt_bin, &["-u", "SFE"], ExecOpts::new(10, 16 * KIB)).await;
            }
            if is_sfe_loaded() {
                for kmod in ["shortcut_fe_cm", "shortcut_fe_ipv6", "shortcut_fe"] {
                    let _ = run("rmmod", &[kmod], ExecOpts::new(5, 16 * KIB)).await;
                }
            }
        }
        if !is_sfe_loaded() {
            SFE_LOADED_BY_US.store(false, Ordering::Relaxed);
        } else {
            warnings.push("Failed to unload Qualcomm SFE fastpath modules".into());
        }
    }
    crate::radio_tuning::set_cached_sfe_state(Some(is_sfe_loaded()));
    warnings
}

/// Reconcile opt-in Qualcomm SFE software fastpath kernel modules.
#[allow(dead_code)]
pub async fn reconcile_sfe_fastpath(enable: bool, force_unload: bool) -> Vec<String> {
    let cfg = hub().config.read().await.clone();
    reconcile_sfe_fastpath_with_guard(enable, force_unload, cfg.preserve_ipa_offload, cfg.ippt).await
}

/// True while `DataplaneMode::Native` is active (or stopping QCMAP/netmgrd), so `at_fwd`
/// commands backed by QCMAP (`AT+QMAP`, `+QMAPWAC`, `+QDMZ`, `+QIP6CFG`) are never written
/// to `/dev/smd11` where `atfwd-daemon` would wedge waiting for the stopped daemon.
pub fn is_native_mode() -> bool {
    NATIVE_MODE_ACTIVE.load(Ordering::Relaxed)
}

/// Monotonic seconds since the native cellular bearer became connected (`None` when not connected in native mode).
pub fn native_wan_uptime_secs() -> Option<u64> {
    let since_ms = NATIVE_CONNECTED_SINCE.load(Ordering::Relaxed);
    (since_ms > 0).then(|| (crate::state::mono_ms().saturating_sub(since_ms) / 1000).max(1))
}

#[derive(Debug, Clone, Default)]
pub struct NativeBearerOverlay {
    pub iface: String,
    pub profile_index: u8,
    pub connected: bool,
    pub ipv4: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv4_dns1: Option<String>,
    pub ipv4_dns2: Option<String>,
    pub ipv6: Option<String>,
    pub ipv6_gateway: Option<String>,
    pub ipv6_dns1: Option<String>,
    pub ipv6_dns2: Option<String>,
    pub ipv6_prefix_length: Option<u8>,
}

/// Live QMI WDS bearer settings in `Native` mode for merging into `modem.bearers`
/// (ensures 464XLAT CLAT `192.0.0.2` and live IPv6/DNS appear cleanly in Addressing).
pub async fn native_bearer_overlay() -> Option<NativeBearerOverlay> {
    let h = hub();
    let cfg = h.config.read().await.clone();
    if cfg.mode != DataplaneMode::Native {
        return None;
    }
    let snap = h.snapshot.read().await;
    let r4 = snap.wds_v4.runtime.as_ref();
    let r6 = snap.wds_v6.runtime.as_ref();
    let connected = snap.wds_v4.state == "connected"
        || snap.wds_v6.state == "connected"
        || snap.supervisor_state == "native-connected";
    Some(NativeBearerOverlay {
        iface: cfg.iface,
        profile_index: cfg.profile_index,
        connected,
        ipv4: r4.and_then(|r| r.ipv4_addr.clone()),
        ipv4_gateway: r4.and_then(|r| r.ipv4_gateway.clone()),
        ipv4_dns1: r4.and_then(|r| r.ipv4_dns1.clone()),
        ipv4_dns2: r4.and_then(|r| r.ipv4_dns2.clone()),
        ipv6: r6.and_then(|r| r.ipv6_addr.clone()),
        ipv6_gateway: r6.and_then(|r| r.ipv6_gateway.clone()),
        ipv6_dns1: r6.and_then(|r| r.ipv6_dns1.clone()),
        ipv6_dns2: r6.and_then(|r| r.ipv6_dns2.clone()),
        ipv6_prefix_length: r6.and_then(|r| r.ipv6_prefix_len),
    })
}

/// Queue a full native bearer reconnect if `Native` mode is active.
pub async fn trigger_native_reconnect_if_active() -> bool {
    let h = hub();
    if h.config.read().await.mode == DataplaneMode::Native {
        *h.reconnect_queue.lock().unwrap_or_else(|e| e.into_inner()) = Some("all".into());
        h.wake.notify_one();
        return true;
    }
    false
}

fn hub() -> Arc<DataplaneHub> {
    HUB.get_or_init(|| {
        let cfg = load_config();
        NATIVE_MODE_ACTIVE.store(cfg.mode == DataplaneMode::Native, Ordering::Relaxed);
        let snap = DataplaneSnapshot {
            mode: cfg.mode,
            supervisor_state: "initializing".into(),
            ..Default::default()
        };
        Arc::new(DataplaneHub {
            config: RwLock::new(cfg),
            snapshot: RwLock::new(snap),
            wake: Notify::new(),
            tuning_warnings: Mutex::new(Vec::new()),
            reconnect_queue: Mutex::new(None),
            shutdown_requested: AtomicBool::new(false),
            supervisor_running: AtomicBool::new(false),
            done_notify: Notify::new(),
        })
    })
    .clone()
}

pub fn load_config() -> DataplaneConfig {
    crate::state::load_json_or_default(DATAPLANE_CONFIG_PATH)
}

pub fn save_config(cfg: &DataplaneConfig) -> Result<(), String> {
    let p = crate::paths::p(DATAPLANE_CONFIG_PATH);
    save_json_atomic(&p, cfg, 0o600)
}

pub(crate) fn validate_unicast_mac(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(format!("invalid MAC address {raw:?} (expected xx:xx:xx:xx:xx:xx)"));
    }
    let mut octets = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = u8::from_str_radix(p, 16).map_err(|_| format!("invalid MAC octet {p:?}"))?;
    }
    if octets == [0; 6] {
        return Err("MAC address cannot be 00:00:00:00:00:00".into());
    }
    if octets == [0xff; 6] {
        return Err("MAC address cannot be broadcast ff:ff:ff:ff:ff:ff".into());
    }
    if (octets[0] & 0x01) != 0 {
        return Err("MAC address must be unicast (multicast bit is set)".into());
    }
    Ok(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    ))
}

pub(crate) fn validate_ippt_dev_type(raw: &str) -> Result<String, String> {
    let norm = raw.trim().to_ascii_lowercase();
    if matches!(norm.as_str(), "eth0" | "eth1" | "usb" | "any") {
        return Ok(norm);
    }
    Err(format!("invalid ipptDevType {raw:?} (expected eth0, eth1, usb, or any)"))
}

pub(crate) fn ipv6_upper64_prefix(addr: &str) -> Option<String> {
    let v6: Ipv6Addr = addr.trim().parse().ok()?;
    if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || v6.is_unicast_link_local() {
        return None;
    }
    let s = v6.segments();
    Some(format!("{:04x}:{:04x}:{:04x}:{:04x}", s[0], s[1], s[2], s[3]))
}

/// Stable identity for an IPv6 cellular bearer.
/// Qualcomm QMI `WDS_GET_RUNTIME_SETTINGS` can return a freshly randomized lower-64
/// privacy IID on every poll while the assigned `/64` prefix is unchanged; comparing
/// `(upper64_prefix, prefix_len)` avoids 15-second address/route/NAT teardown churn.
pub(crate) fn ipv6_bearer_key(rt: &WdsRuntimeSettings) -> Option<(String, u8)> {
    let addr = rt.ipv6_addr.as_deref()?;
    let plen = rt.ipv6_prefix_len.unwrap_or(64);
    let key = ipv6_upper64_prefix(addr).unwrap_or_else(|| addr.trim().to_string());
    Some((key, plen))
}

pub(crate) fn ipv6_bearer_changed(
    v6_rt: Option<&WdsRuntimeSettings>,
    last_v6_key: Option<&(String, u8)>,
) -> bool {
    v6_rt.and_then(ipv6_bearer_key).as_ref() != last_v6_key
}

pub(crate) fn build_ipa_ippass_enable_args(cfg: &DataplaneConfig, mac: &str) -> Vec<String> {
    vec![
        "ippass".into(),
        "enable".into(),
        "dev_type".into(),
        cfg.ippt_dev_type.clone(),
        "vlan".into(),
        cfg.ippt_vlan.to_string(),
        "mac".into(),
        mac.to_string(),
        "skip_nat".into(),
        if cfg.ippt_skip_nat { "1" } else { "0" }.into(),
        "default_pdn".into(),
        "1".into(),
        "dev_name".into(),
        cfg.iface.clone(),
    ]
}

pub(crate) fn build_ipa_ippass_disable_args(dev_type: &str, vlan: u16, iface: &str) -> Vec<String> {
    vec![
        "ippass".into(),
        "disable".into(),
        "dev_type".into(),
        dev_type.to_string(),
        "vlan".into(),
        vlan.to_string(),
        "dev_name".into(),
        iface.to_string(),
    ]
}

pub(crate) fn build_ipa_v6_sharing_enable_args(prefix64: &str, iface: &str) -> Vec<String> {
    vec![
        "idu_ipv6_config".into(),
        "sharing".into(),
        "ipv6_prefix".into(),
        prefix64.to_string(),
        "ipv6_mask".into(),
        "ffff:ffff:ffff:ffff".into(),
        "pdn_name".into(),
        iface.to_string(),
    ]
}

pub(crate) fn build_ipa_v6_sharing_disable_args(iface: &str) -> Vec<String> {
    vec![
        "idu_ipv6_config".into(),
        "disable".into(),
        "ipv6_prefix".into(),
        "0".into(),
        "ipv6_mask".into(),
        "0".into(),
        "pdn_name".into(),
        iface.to_string(),
    ]
}

pub(crate) fn collect_runtime_dns(
    v4: Option<&WdsRuntimeSettings>,
    v6: Option<&WdsRuntimeSettings>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_if_ip = |opt: Option<&String>| {
        if let Some(raw) = opt
            && let Ok(ip) = raw.trim().parse::<IpAddr>()
        {
            let s = ip.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    };
    if let Some(r4) = v4 {
        push_if_ip(r4.ipv4_dns1.as_ref());
        push_if_ip(r4.ipv4_dns2.as_ref());
    }
    if let Some(r6) = v6 {
        push_if_ip(r6.ipv6_dns1.as_ref());
        push_if_ip(r6.ipv6_dns2.as_ref());
    }
    out
}

const RESOLV_PATHS: [&str; 2] = [
    "/tmp/resolv.conf.d/resolv.conf.auto",
    "/tmp/resolv.conf.d/resolv.conf.lan.auto",
];

pub(crate) type SavedResolvSnapshot = Vec<(String, Option<Vec<u8>>)>;

async fn reload_dnsmasq_if_present() {
    let init = "/etc/init.d/dnsmasq";
    if Path::new(&crate::paths::p(init)).exists() {
        let _ = run(init, &["reload"], ExecOpts::new(15, 16 * KIB)).await;
    }
}

pub(crate) async fn apply_native_dns(
    saved_resolv: &mut Option<SavedResolvSnapshot>,
    dns: &[String],
) -> Result<bool, String> {
    if dns.is_empty() {
        return Ok(false);
    }
    if saved_resolv.is_none() {
        let mut snap = Vec::with_capacity(RESOLV_PATHS.len());
        for &rel in &RESOLV_PATHS {
            snap.push((rel.to_string(), fs::read(crate::paths::p(rel)).ok()));
        }
        *saved_resolv = Some(snap);
    }
    let mut body = String::from("# Managed by cellcored native dataplane\n");
    for s in dns {
        body.push_str("nameserver ");
        body.push_str(s);
        body.push('\n');
    }
    for &rel in &RESOLV_PATHS {
        atomic_write(Path::new(rel), body.as_bytes(), 0o644)?;
    }
    reload_dnsmasq_if_present().await;
    Ok(true)
}

pub(crate) async fn restore_native_dns(
    saved_resolv: &mut Option<SavedResolvSnapshot>,
) -> Result<(), String> {
    let Some(entries) = saved_resolv.take() else {
        return Ok(());
    };
    for (rel, orig) in entries {
        match orig {
            Some(bytes) => atomic_write(Path::new(&rel), &bytes, 0o644)?,
            None => {
                let real = Path::new(&crate::paths::p(&rel)).to_path_buf();
                let _ = fs::remove_file(&real);
            }
        }
    }
    reload_dnsmasq_if_present().await;
    Ok(())
}

pub(crate) fn build_ippt_dnsmasq_conf(
    mac: &str,
    ip: Ipv4Addr,
    gw: Option<Ipv4Addr>,
) -> Result<String, String> {
    let norm_mac = validate_unicast_mac(mac)?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return Err(format!("invalid IPPT lease IPv4 address {ip}"));
    }
    let mut out = format!(
        "# Managed by cellcored native dataplane IPPT\n\
         dhcp-host={norm_mac},set:cellcore_ippt,{ip},120s\n"
    );
    if let Some(gw_ip) = gw
        && !gw_ip.is_unspecified()
        && !gw_ip.is_loopback()
        && !gw_ip.is_multicast()
        && gw_ip != ip
    {
        out.push_str(&format!(
            "dhcp-option=tag:cellcore_ippt,option:router,{gw_ip}\n"
        ));
    }
    Ok(out)
}

pub(crate) async fn write_ippt_dnsmasq_conf(
    mac: &str,
    ip: Ipv4Addr,
    gw: Option<Ipv4Addr>,
) -> Result<(), String> {
    let body = build_ippt_dnsmasq_conf(mac, ip, gw)?;
    atomic_write(Path::new(IPPT_DNSMASQ_CONF_PATH), body.as_bytes(), 0o644)?;
    reload_dnsmasq_if_present().await;
    Ok(())
}

pub(crate) async fn remove_ippt_dnsmasq_conf() -> Result<bool, String> {
    let real = crate::paths::p(IPPT_DNSMASQ_CONF_PATH);
    if !Path::new(&real).exists() {
        return Ok(false);
    }
    fs::remove_file(&real).map_err(|e| format!("remove {IPPT_DNSMASQ_CONF_PATH}: {e}"))?;
    reload_dnsmasq_if_present().await;
    Ok(true)
}

async fn run_ipa_cli(args: &[String]) -> Result<bool, String> {
    let bin = "/usr/bin/ipa";
    if !Path::new(&crate::paths::p(bin)).exists() {
        return Ok(false);
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run(bin, &refs, ExecOpts::new(10, 16 * KIB)).await {
        Ok(out) if out.code == Some(0) => Ok(true),
        Ok(out) => Err(format!(
            "ipa {} exited {}: {}",
            refs.first().copied().unwrap_or(""),
            out.code.map_or_else(|| "signal".to_string(), |c| c.to_string()),
            out.stderr.trim()
        )),
        Err(e) => Err(format!("ipa exec: {e}")),
    }
}

fn read_trimmed(rel: &str) -> Option<String> {
    fs::read_to_string(crate::paths::p(rel))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_u64_sys(rel: &str) -> Option<u64> {
    read_trimmed(rel).and_then(|s| s.parse::<u64>().ok())
}

fn proc_comms_present(targets: &[&str]) -> Vec<bool> {
    let mut found = vec![false; targets.len()];
    let proc_dir = crate::paths::p("/proc");
    let Ok(rd) = fs::read_dir(&proc_dir) else {
        return found;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(ns) = name.to_str() else { continue };
        if !ns.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(comm) = fs::read_to_string(ent.path().join("comm")) else {
            continue;
        };
        let c = comm.trim();
        for (idx, &t) in targets.iter().enumerate() {
            if c == t || (t.len() > 15 && c == &t[..15]) {
                found[idx] = true;
            }
        }
    }
    found
}

const HIGH_THROUGHPUT_SYSCTLS: &[(&str, &str)] = &[
    ("/proc/sys/net/core/default_qdisc", "fq_codel"),
    ("/proc/sys/net/core/rmem_max", "16777216"),
    ("/proc/sys/net/core/wmem_max", "16777216"),
    ("/proc/sys/net/ipv4/tcp_rmem", "4096 131072 16777216"),
    ("/proc/sys/net/ipv4/tcp_wmem", "4096 65536 16777216"),
    ("/proc/sys/net/core/netdev_max_backlog", "16384"),
    ("/proc/sys/net/core/netdev_budget", "1200"),
    ("/proc/sys/net/core/netdev_budget_usecs", "8000"),
    ("/proc/sys/net/ipv4/tcp_slow_start_after_idle", "0"),
    ("/proc/sys/net/ipv4/tcp_mtu_probing", "1"),
    ("/proc/sys/net/ipv4/tcp_notsent_lowat", "131072"),
    ("/proc/sys/net/core/rps_sock_flow_entries", "32768"),
    ("/proc/sys/net/ipv4/tcp_fastopen", "3"),
    ("/proc/sys/net/netfilter/nf_conntrack_max", "65536"),
    ("/sys/module/nf_conntrack/parameters/hashsize", "16384"),
    ("/sys/class/net/eth0/queues/rx-0/rps_cpus", "c"),
    ("/sys/class/net/eth0/queues/rx-0/rps_flow_cnt", "4096"),
    ("/sys/class/net/eth0/queues/tx-0/xps_cpus", "c"),
    ("/sys/class/net/eth0/gro_flush_timeout", "20000"),
    ("/sys/class/net/eth0/napi_defer_hard_irqs", "2"),
    ("/sys/class/net/rmnet_ipa0/gro_flush_timeout", "20000"),
    ("/sys/class/net/rmnet_ipa0/napi_defer_hard_irqs", "2"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-0/rps_cpus", "c"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-1/rps_cpus", "c"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-2/rps_cpus", "c"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-3/rps_cpus", "c"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-0/rps_flow_cnt", "4096"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-1/rps_flow_cnt", "4096"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-2/rps_flow_cnt", "4096"),
    ("/sys/class/net/rmnet_ipa0/queues/rx-3/rps_flow_cnt", "4096"),
    ("/sys/class/net/rmnet_ipa0/queues/tx-0/xps_cpus", "4"),
    ("/sys/class/net/rmnet_ipa0/queues/tx-1/xps_cpus", "8"),
    ("/sys/class/net/rmnet_ipa0/queues/tx-2/xps_cpus", "4"),
    ("/sys/class/net/rmnet_ipa0/queues/tx-3/xps_cpus", "8"),
    ("/sys/class/net/rmnet_data0/queues/rx-0/rps_cpus", "c"),
    ("/sys/class/net/rmnet_data0/queues/rx-0/rps_flow_cnt", "4096"),
    ("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "performance"),
    ("/sys/devices/system/cpu/cpu1/cpufreq/scaling_governor", "performance"),
    ("/sys/devices/system/cpu/cpu2/cpufreq/scaling_governor", "performance"),
    ("/sys/devices/system/cpu/cpu3/cpufreq/scaling_governor", "performance"),
    ("/sys/power/autosleep", "off"),
];

const OPTIONAL_IPA_SYSCTLS: &[(&str, &str)] = &[
    ("/sys/kernel/debug/ipa/clock_scaling_bw_threshold_nominal_mbps", "100"),
    ("/sys/kernel/debug/ipa/clock_scaling_bw_threshold_turbo_mbps", "300"),
];

pub(crate) fn parse_memtotal_mib(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:")
            && let Some(kb_str) = rest.split_whitespace().next()
            && let Ok(kb) = kb_str.parse::<u64>()
        {
            return Some(kb / 1024);
        }
    }
    None
}

fn total_ram_mib() -> Option<u64> {
    fs::read_to_string(crate::paths::p("/proc/meminfo"))
        .ok()
        .and_then(|s| parse_memtotal_mib(&s))
}

/// Cap socket buffers to 8 MiB on <= 512 MiB RAM boards (16 MiB on > 512 MiB).
pub(crate) fn socket_buf_max_bytes_for_ram(ram_mib: Option<u64>) -> u64 {
    match ram_mib {
        Some(mib) if mib <= 512 => 8_388_608,
        _ => 16_777_216,
    }
}

pub fn apply_kernel_tuning(profile: KernelTuningProfile, active_iface: Option<&str>) -> Vec<String> {
    let baseline_lock = BASELINE_SYSCTLS.get_or_init(|| Mutex::new(Vec::new()));

    let mut dyn_entries: Vec<(String, &'static str)> = Vec::new();
    if let Some(iface) = active_iface
        && netlink::validate_managed_iface(iface).is_ok()
    {
        for (suffix, val) in [("rps_cpus", "c"), ("rps_flow_cnt", "4096")] {
            let rel = format!("/sys/class/net/{iface}/queues/rx-0/{suffix}");
            if !HIGH_THROUGHPUT_SYSCTLS.iter().any(|(r, _)| *r == rel) {
                dyn_entries.push((rel, val));
            }
        }
        for (leaf, val) in [("gro_flush_timeout", "20000"), ("napi_defer_hard_irqs", "2")] {
            let rel = format!("/sys/class/net/{iface}/{leaf}");
            if !HIGH_THROUGHPUT_SYSCTLS.iter().any(|(r, _)| *r == rel) {
                dyn_entries.push((rel, val));
            }
        }
    }

    let mut warnings = Vec::new();
    match profile {
        KernelTuningProfile::HighThroughput => {
            // Strictly BEFORE applying tuning: load any previously persisted original baseline
            // (so crash-restart reuses the original pre-tuning values rather than capturing
            // already-tuned values!), and only capture values for paths not yet recorded.
            {
                let _state_guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                let mut persisted = load_persisted_native_state_locked().unwrap_or_default();
                for rel in HIGH_THROUGHPUT_SYSCTLS
                    .iter()
                    .chain(OPTIONAL_IPA_SYSCTLS.iter())
                    .map(|(r, _)| *r)
                    .chain(dyn_entries.iter().map(|(r, _)| r.as_str()))
                {
                    if !persisted.baseline_sysctls.iter().any(|(k, _)| k == rel)
                        && let Some(orig) = read_trimmed(rel)
                    {
                        persisted.baseline_sysctls.push((rel.to_string(), orig));
                    }
                }
                {
                    let mut mem = baseline_lock.lock().unwrap_or_else(|e| e.into_inner());
                    *mem = persisted.baseline_sysctls.clone();
                }
                let _ = save_persisted_native_state_locked(&persisted);
            }

            let buf_max = socket_buf_max_bytes_for_ram(total_ram_mib());
            let buf_max_s = buf_max.to_string();
            let tcp_rmem_s = format!("4096 131072 {buf_max}");
            let tcp_wmem_s = format!("4096 65536 {buf_max}");
            for (rel, default_val) in HIGH_THROUGHPUT_SYSCTLS
                .iter()
                .map(|(r, v)| (*r, *v))
                .chain(dyn_entries.iter().map(|(r, v)| (r.as_str(), *v)))
            {
                let real = crate::paths::p(rel);
                if !Path::new(&real).exists() {
                    continue;
                }
                let val: &str = match rel {
                    "/proc/sys/net/core/rmem_max" | "/proc/sys/net/core/wmem_max" => &buf_max_s,
                    "/proc/sys/net/ipv4/tcp_rmem" => &tcp_rmem_s,
                    "/proc/sys/net/ipv4/tcp_wmem" => &tcp_wmem_s,
                    _ => default_val,
                };
                if let Err(e) = fs::write(&real, format!("{val}\n")) {
                    warnings.push(format!("{rel}: {e}"));
                }
            }
            for (rel, val) in OPTIONAL_IPA_SYSCTLS {
                let real = crate::paths::p(rel);
                if Path::new(&real).exists() {
                    let _ = fs::write(&real, format!("{val}\n"));
                }
            }
            tune_nic_offloads_and_irqs(active_iface);
        }
        KernelTuningProfile::Default => {
            let persisted = load_persisted_native_state();
            let pairs = persisted
                .as_ref()
                .filter(|st| !st.baseline_sysctls.is_empty())
                .map(|st| st.baseline_sysctls.clone())
                .unwrap_or_else(|| baseline_lock.lock().unwrap_or_else(|e| e.into_inner()).clone());
            for (rel, orig) in pairs {
                let real = crate::paths::p(&rel);
                if !Path::new(&real).exists() {
                    continue;
                }
                if let Err(e) = fs::write(&real, format!("{orig}\n"))
                    && !rel.starts_with("/sys/kernel/debug/")
                {
                    warnings.push(format!("restore {rel}: {e}"));
                }
            }
            restore_nic_offloads_and_irqs(&mut warnings);
            {
                let _state_guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(mut st) = load_persisted_native_state_locked() {
                    st.baseline_sysctls.clear();
                    st.baseline_irq_affinities.clear();
                    st.baseline_ethtool_features.clear();
                    if !st.native_active && !st.vendor_daemons_stopped && !st.mwan3_stopped {
                        clear_persisted_native_state_locked();
                    } else {
                        let _ = save_persisted_native_state_locked(&st);
                    }
                }
            }
        }
    }
    warnings
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IrqPinTarget {
    pub irq: String,
    pub cpu_list: &'static str,
    pub cpu_mask: &'static str,
}

/// Plan IRQ pinning from `/proc/interrupts`:
/// - Active `eth0-*` PCIe MSI vectors split across CPU 2 (`4`) and CPU 3 (`8`) instead of both on `c`.
/// - `gsi` (Qualcomm IPAv5 GSI) pinned to CPU 1 (`2`) so it does not collide with `ipcc_0` on CPU 0 (`1`).
pub(crate) fn plan_irq_affinities(interrupts_text: &str) -> Vec<IrqPinTarget> {
    let mut eth0_irqs: Vec<(u64, u64, String)> = Vec::new();
    let mut gsi_irqs: Vec<(u64, String)> = Vec::new();
    for line in interrupts_text.lines() {
        let Some((num_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let irq = num_raw.trim();
        if irq.is_empty() || !irq.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(irq_num) = irq.parse::<u64>() else {
            continue;
        };
        let total_hits: u64 = rest
            .split_whitespace()
            .take_while(|tok| tok.bytes().all(|b| b.is_ascii_digit()))
            .filter_map(|tok| tok.parse::<u64>().ok())
            .sum();
        let last_tok = rest.split_whitespace().last().unwrap_or("");
        if line.contains("eth0-") {
            eth0_irqs.push((total_hits, irq_num, irq.to_string()));
        } else if last_tok == "gsi" || last_tok.starts_with("gsi_") {
            gsi_irqs.push((irq_num, irq.to_string()));
        }
    }

    // Active eth0 vectors first (non-zero hits before idle), deterministic by IRQ number.
    eth0_irqs.sort_by_key(|(hits, irq_num, _)| (*hits == 0, *irq_num));
    gsi_irqs.sort_by_key(|(irq_num, _)| *irq_num);

    let mut plan = Vec::with_capacity(eth0_irqs.len() + gsi_irqs.len());
    for (_, irq) in gsi_irqs {
        plan.push(IrqPinTarget {
            irq,
            cpu_list: "1",
            cpu_mask: "2",
        });
    }
    for (idx, (_, _, irq)) in eth0_irqs.into_iter().enumerate() {
        let (cpu_list, cpu_mask) = if idx % 2 == 0 { ("2", "4") } else { ("3", "8") };
        plan.push(IrqPinTarget {
            irq,
            cpu_list,
            cpu_mask,
        });
    }
    plan
}

fn irq_affinity_file_for(irq: &str) -> Option<(String, bool)> {
    let list_rel = format!("/proc/irq/{irq}/smp_affinity_list");
    if Path::new(&crate::paths::p(&list_rel)).exists() {
        return Some((list_rel, true));
    }
    let mask_rel = format!("/proc/irq/{irq}/smp_affinity");
    if Path::new(&crate::paths::p(&mask_rel)).exists() {
        return Some((mask_rel, false));
    }
    None
}

/// Pin `eth0-*` PCIe MSI IRQs split across CPU 2 (`4`) and CPU 3 (`8`), and `gsi` to CPU 1 (`2`),
/// saving original IRQ affinities (persisted on disk + in-memory) so reverting to
/// `KernelTuningProfile::Default` restores them even across crash-restarts.
pub(crate) fn pin_eth0_irqs_to_cpu2_3() -> Vec<(String, &'static str)> {
    let irqs_path = crate::paths::p("/proc/interrupts");
    let Ok(text) = fs::read_to_string(&irqs_path) else {
        return Vec::new();
    };
    let plan = plan_irq_affinities(&text);
    let baseline = BASELINE_IRQ_AFFINITIES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut assigned = Vec::with_capacity(plan.len());
    let mut to_write: Vec<(String, &'static str)> = Vec::with_capacity(plan.len());
    {
        let _state_guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut persisted = load_persisted_native_state_locked().unwrap_or_default();
        let mut persisted_dirty = false;
        for target in plan {
            if let Some((rel, is_list)) = irq_affinity_file_for(&target.irq) {
                if !persisted.baseline_irq_affinities.contains_key(&rel)
                    && let Some(orig) = read_trimmed(&rel)
                {
                    persisted.baseline_irq_affinities.insert(rel.clone(), orig.clone());
                    persisted_dirty = true;
                    baseline
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .entry(rel.clone())
                        .or_insert(orig);
                } else if let Some(orig) = persisted.baseline_irq_affinities.get(&rel) {
                    baseline
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .entry(rel.clone())
                        .or_insert_with(|| orig.clone());
                }
                let val = if is_list {
                    target.cpu_list
                } else {
                    target.cpu_mask
                };
                to_write.push((rel, val));
            }
            assigned.push((target.irq, target.cpu_list));
        }
        if persisted_dirty {
            let _ = save_persisted_native_state_locked(&persisted);
        }
    }
    for (rel, val) in to_write {
        let _ = fs::write(crate::paths::p(&rel), format!("{val}\n"));
    }
    assigned
}

pub(crate) fn parse_ethtool_gro_features(stdout: &str) -> (Option<bool>, Option<bool>) {
    let mut gro_list = None;
    let mut udp_gro_fwd = None;
    for line in stdout.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.split_whitespace().next().unwrap_or("");
        let parsed = match val {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        };
        match key {
            "rx-gro-list" => gro_list = parsed,
            "rx-udp-gro-forwarding" => udp_gro_fwd = parsed,
            _ => {}
        }
    }
    (gro_list, udp_gro_fwd)
}

fn tune_nic_offloads_and_irqs(active_iface: Option<&str>) {
    let mut ifaces: Vec<&str> = vec!["eth0"];
    if let Some(iface) = active_iface
        && netlink::validate_managed_iface(iface).is_ok()
        && iface != "eth0"
    {
        ifaces.push(iface);
    }
    let eth_baseline = BASELINE_ETHTOOL_FEATURES.get_or_init(|| Mutex::new(HashMap::new()));
    let known_saved: std::collections::HashSet<String> = load_persisted_native_state()
        .map(|st| st.baseline_ethtool_features.into_keys().collect())
        .unwrap_or_default();
    let mut captured: Vec<(String, EthtoolGroFeatures)> = Vec::new();
    for iface in ifaces {
        let sys_if = crate::paths::p(&format!("/sys/class/net/{iface}"));
        if !Path::new(&sys_if).exists() {
            continue;
        }
        if !known_saved.contains(iface)
            && let Ok(stdout) = crate::uci::run_cmd_blocking_timeout(
                &crate::paths::program("ethtool"),
                &["-k", iface],
                Duration::from_secs(2),
            )
        {
            let feats = parse_ethtool_gro_features(&stdout);
            if feats.0.is_some() || feats.1.is_some() {
                captured.push((iface.to_string(), feats));
            }
        }
        let _ = crate::uci::run_cmd_blocking_timeout(
            &crate::paths::program("ethtool"),
            &["-K", iface, "rx-gro-list", "off", "rx-udp-gro-forwarding", "on"],
            Duration::from_secs(2),
        );
    }
    if !captured.is_empty() {
        let _state_guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut persisted = load_persisted_native_state_locked().unwrap_or_default();
        let mut dirty = false;
        for (iface, feats) in captured {
            if !persisted.baseline_ethtool_features.contains_key(&iface) {
                persisted.baseline_ethtool_features.insert(iface.clone(), feats);
                dirty = true;
            }
            eth_baseline
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(iface)
                .or_insert(feats);
        }
        if dirty {
            let _ = save_persisted_native_state_locked(&persisted);
        }
    }

    let _ = pin_eth0_irqs_to_cpu2_3();
}

fn restore_nic_offloads_and_irqs(warnings: &mut Vec<String>) {
    let persisted = load_persisted_native_state();
    let irq_entries: Vec<(String, String)> = persisted
        .as_ref()
        .filter(|st| !st.baseline_irq_affinities.is_empty())
        .map(|st| {
            st.baseline_irq_affinities
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_else(|| {
            BASELINE_IRQ_AFFINITIES
                .get()
                .map(|b| {
                    b.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default()
        });
    for (rel, orig) in irq_entries {
        let real = crate::paths::p(&rel);
        if Path::new(&real).exists()
            && let Err(e) = fs::write(&real, format!("{orig}\n"))
        {
            warnings.push(format!("restore {rel}: {e}"));
        }
    }

    let eth_entries: Vec<(String, EthtoolGroFeatures)> = persisted
        .as_ref()
        .filter(|st| !st.baseline_ethtool_features.is_empty())
        .map(|st| {
            st.baseline_ethtool_features
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect()
        })
        .unwrap_or_else(|| {
            BASELINE_ETHTOOL_FEATURES
                .get()
                .map(|b| {
                    b.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .iter()
                        .map(|(k, v)| (k.clone(), *v))
                        .collect()
                })
                .unwrap_or_default()
        });
    for (iface, (gro_list, udp_gro_fwd)) in eth_entries {
        let sys_if = crate::paths::p(&format!("/sys/class/net/{iface}"));
        if !Path::new(&sys_if).exists() {
            continue;
        }
        let mut args: Vec<&str> = vec!["-K", &iface];
        if let Some(v) = gro_list {
            args.push("rx-gro-list");
            args.push(if v { "on" } else { "off" });
        }
        if let Some(v) = udp_gro_fwd {
            args.push("rx-udp-gro-forwarding");
            args.push(if v { "on" } else { "off" });
        }
        if args.len() > 2 {
            let _ = crate::uci::run_cmd_blocking_timeout(
                &crate::paths::program("ethtool"),
                &args,
                Duration::from_secs(2),
            );
        }
    }
}

pub(crate) fn parse_ipa_eth_driver(status_text: &str) -> Option<String> {
    for line in status_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.to_ascii_lowercase().contains("protocol") {
            continue;
        }
        if let Some(proto) = trimmed.split('|').next().map(str::trim)
            && !proto.is_empty()
        {
            return Some(proto.to_string());
        }
    }
    None
}

pub(crate) fn parse_ioss_statistics(stats_text: &str) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let mut hwp_rx = None;
    let mut exp_rx = None;
    let mut hwp_tx = None;
    let mut exp_tx = None;
    for line in stats_text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let Ok(n) = v.trim().parse::<u64>() else {
            continue;
        };
        match k.trim() {
            "hwp_rx_packets" => hwp_rx = Some(n),
            "exp_rx_packets" => exp_rx = Some(n),
            "hwp_tx_packets" => hwp_tx = Some(n),
            "exp_tx_packets" => exp_tx = Some(n),
            _ => {}
        }
    }
    (hwp_rx, exp_rx, hwp_tx, exp_tx)
}

fn collect_ipa_offload_telemetry() -> IpaOffloadTelemetry {
    let eth_offload_driver = fs::read_to_string(crate::paths::p("/sys/kernel/debug/ipa/eth/status"))
        .ok()
        .and_then(|s| parse_ipa_eth_driver(&s));
    let (eth_hwp_rx_packets, eth_exp_rx_packets, eth_hwp_tx_packets, eth_exp_tx_packets) =
        fs::read_to_string(crate::paths::p("/sys/kernel/debug/ioss/devices/eth0/statistics"))
            .ok()
            .map(|s| parse_ioss_statistics(&s))
            .unwrap_or((None, None, None, None));
    let eth_hardware_offload_pct = match (eth_hwp_rx_packets, eth_exp_rx_packets) {
        (Some(hwp), Some(exp)) if hwp > 0 => {
            Some(((u128::from(hwp.saturating_sub(exp)) * 100) / u128::from(hwp)).min(100) as u8)
        }
        (Some(hwp), None) if hwp > 0 => Some(100),
        _ => None,
    };
    IpaOffloadTelemetry {
        hw_type: read_trimmed("/sys/kernel/debug/ipa/hw_type"),
        clk_rate_mhz: read_u64_sys("/sys/kernel/debug/ipa/clk_rate").map(|hz| hz / 1_000_000),
        clock_scaling_enabled: read_trimmed("/sys/kernel/debug/ipa/enable_clock_scaling").map(|s| s == "1"),
        nominal_mbps: read_u64_sys("/sys/kernel/debug/ipa/clock_scaling_bw_threshold_nominal_mbps"),
        turbo_mbps: read_u64_sys("/sys/kernel/debug/ipa/clock_scaling_bw_threshold_turbo_mbps"),
        napi_chain_enabled: read_trimmed("/sys/kernel/debug/ipa/enable_napi_chain").map(|s| s == "1"),
        eth_offload_driver,
        eth_hwp_rx_packets,
        eth_exp_rx_packets,
        eth_hwp_tx_packets,
        eth_exp_tx_packets,
        eth_hardware_offload_pct,
    }
}

pub fn collect_kernel_telemetry(
    profile: KernelTuningProfile,
    warnings: Vec<String>,
    active_iface: Option<&str>,
) -> KernelTelemetry {
    let mut rps_paths: Vec<String> = [
        "/sys/class/net/eth0/queues/rx-0/rps_cpus",
        "/sys/class/net/eth0/queues/rx-0/rps_flow_cnt",
        "/sys/class/net/rmnet_ipa0/queues/rx-0/rps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/rx-1/rps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/rx-2/rps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/rx-3/rps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/rx-0/rps_flow_cnt",
        "/sys/class/net/rmnet_data0/queues/rx-0/rps_cpus",
        "/sys/class/net/rmnet_data0/queues/rx-0/rps_flow_cnt",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    if let Some(iface) = active_iface
        && netlink::validate_managed_iface(iface).is_ok()
    {
        for suffix in ["rps_cpus", "rps_flow_cnt"] {
            let p = format!("/sys/class/net/{iface}/queues/rx-0/{suffix}");
            if !rps_paths.contains(&p) {
                rps_paths.push(p);
            }
        }
    }
    let mut rps_maps = HashMap::new();
    for rel in rps_paths {
        if let Some(v) = read_trimmed(&rel) {
            let short = rel
                .trim_start_matches("/sys/class/net/")
                .replace("/queues/", ":");
            rps_maps.insert(short, v);
        }
    }
    let mut xps_maps = HashMap::new();
    for rel in [
        "/sys/class/net/eth0/queues/tx-0/xps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/tx-0/xps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/tx-1/xps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/tx-2/xps_cpus",
        "/sys/class/net/rmnet_ipa0/queues/tx-3/xps_cpus",
    ] {
        if let Some(v) = read_trimmed(rel) {
            let short = rel
                .trim_start_matches("/sys/class/net/")
                .replace("/queues/", ":");
            xps_maps.insert(short, v);
        }
    }
    let procs = proc_comms_present(&["ipacm", "QCMAP_ConnectionManager", "netmgrd"]);
    KernelTelemetry {
        tcp_congestion_control: read_trimmed("/proc/sys/net/ipv4/tcp_congestion_control")
            .unwrap_or_default(),
        tcp_available_congestion_control: read_trimmed(
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
        )
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default(),
        default_qdisc: read_trimmed("/proc/sys/net/core/default_qdisc").unwrap_or_default(),
        rmem_max: read_u64_sys("/proc/sys/net/core/rmem_max"),
        wmem_max: read_u64_sys("/proc/sys/net/core/wmem_max"),
        tcp_rmem: read_trimmed("/proc/sys/net/ipv4/tcp_rmem").unwrap_or_default(),
        tcp_wmem: read_trimmed("/proc/sys/net/ipv4/tcp_wmem").unwrap_or_default(),
        netdev_max_backlog: read_u64_sys("/proc/sys/net/core/netdev_max_backlog"),
        netdev_budget: read_u64_sys("/proc/sys/net/core/netdev_budget"),
        netdev_budget_usecs: read_u64_sys("/proc/sys/net/core/netdev_budget_usecs"),
        tcp_slow_start_after_idle: read_u64_sys("/proc/sys/net/ipv4/tcp_slow_start_after_idle"),
        tcp_mtu_probing: read_u64_sys("/proc/sys/net/ipv4/tcp_mtu_probing"),
        tcp_notsent_lowat: read_u64_sys("/proc/sys/net/ipv4/tcp_notsent_lowat"),
        rps_sock_flow_entries: read_u64_sys("/proc/sys/net/core/rps_sock_flow_entries"),
        tcp_fastopen: read_u64_sys("/proc/sys/net/ipv4/tcp_fastopen"),
        conntrack_max: read_u64_sys("/proc/sys/net/netfilter/nf_conntrack_max"),
        conntrack_count: read_u64_sys("/proc/sys/net/netfilter/nf_conntrack_count"),
        conntrack_hashsize: read_u64_sys("/sys/module/nf_conntrack/parameters/hashsize"),
        cpu_governor: read_trimmed("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        cpu_cur_freq_mhz: read_u64_sys("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq").map(|khz| khz / 1000),
        cpu_max_freq_mhz: read_u64_sys("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq").map(|khz| khz / 1000),
        rps_maps,
        xps_maps,
        ipa_dev_present: Path::new(&crate::paths::p("/dev/ipa")).exists(),
        ipacm_running: procs[0],
        qcmap_running: procs[1],
        netmgrd_running: procs[2],
        ipa_offload: collect_ipa_offload_telemetry(),
        active_tuning: profile,
        tuning_warnings: warnings,
    }
}

pub(crate) fn parse_link_addr_route_filter(
    links: Vec<NetlinkLink>,
    addrs: Vec<NetlinkAddr>,
    routes: Vec<NetlinkRoute>,
    managed_iface: &str,
) -> (Vec<NetlinkLink>, Vec<NetlinkAddr>, Vec<NetlinkRoute>) {
    let links: Vec<NetlinkLink> = links
        .into_iter()
        .filter(|l| {
            l.name.starts_with("rmnet")
                || l.name == "eth0"
                || l.name == "br-lan"
                || l.name == managed_iface
        })
        .collect();
    let keep_idx: Vec<i32> = links.iter().map(|l| l.ifindex).collect();
    let addrs = addrs
        .into_iter()
        .filter(|a| keep_idx.contains(&a.ifindex))
        .collect();
    let routes = routes
        .into_iter()
        .filter(|r| r.dst == "0.0.0.0/0" || r.dst == "::/0" || r.oif.is_some_and(|i| keep_idx.contains(&i)))
        .collect();
    (links, addrs, routes)
}

pub fn start(state: &AppState) {
    let h = hub();
    let cfg = load_config();
    NATIVE_MODE_ACTIVE.store(cfg.mode == DataplaneMode::Native, Ordering::Relaxed);
    let st = state.clone();
    tokio::spawn(async move {
        if cfg.kernel_tuning == KernelTuningProfile::HighThroughput {
            let iface = cfg.iface.clone();
            let warns = tokio::task::spawn_blocking(move || {
                apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some(&iface))
            })
            .await
            .unwrap_or_default();
            *h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()) = warns;
        }
        if cfg.sfe_fastpath {
            let _ = reconcile_sfe_fastpath_with_guard(
                true,
                false,
                cfg.preserve_ipa_offload,
                cfg.ippt,
            )
            .await;
        }
        supervisor_loop(st, h).await;
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedCfgSig {
    iface: String,
    mux_id: u8,
    ep_type: u32,
    ep_iface_id: u32,
    profile_index: u8,
    ip_family: IpFamily,
    route_table: u32,
    ippt: bool,
    ippt_mac: Option<String>,
    ippt_dev_type: String,
    ippt_skip_nat: bool,
    ippt_vlan: u16,
    manage_dns: bool,
    ipv6_prefix_sharing: bool,
}

impl From<&DataplaneConfig> for AppliedCfgSig {
    fn from(c: &DataplaneConfig) -> Self {
        Self {
            iface: c.iface.clone(),
            mux_id: c.mux_id,
            ep_type: c.ep_type,
            ep_iface_id: c.ep_iface_id,
            profile_index: c.profile_index,
            ip_family: c.ip_family,
            route_table: c.route_table,
            ippt: c.ippt,
            ippt_mac: c.ippt_mac.clone(),
            ippt_dev_type: c.ippt_dev_type.clone(),
            ippt_skip_nat: c.ippt_skip_nat,
            ippt_vlan: c.ippt_vlan,
            manage_dns: c.manage_dns,
            ipv6_prefix_sharing: c.ipv6_prefix_sharing,
        }
    }
}

/// True when a config change requires tearing down and restarting the active QMI WDS
/// bearer session(s) (APN profile index, IP family, interface, mux ID, or endpoint changed).
pub(crate) fn bearer_restart_needed(prev: Option<&AppliedCfgSig>, cur: &AppliedCfgSig) -> bool {
    let Some(p) = prev else {
        return false;
    };
    p.profile_index != cur.profile_index
        || p.ip_family != cur.ip_family
        || p.iface != cur.iface
        || p.mux_id != cur.mux_id
        || p.ep_type != cur.ep_type
        || p.ep_iface_id != cur.ep_iface_id
}

fn persist_native_handoff_state(nh: &NativeHandles, cfg: &DataplaneConfig, active: bool) {
    let _state_guard = NATIVE_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut st = load_persisted_native_state_locked().unwrap_or_default();
    st.native_active = active;
    st.vendor_daemons_stopped = nh.vendor_daemons_stopped;
    st.mwan3_stopped = nh.mwan3_stopped;
    st.iface = nh.last_resolved_iface.clone().or_else(|| Some(cfg.iface.clone()));
    st.route_table = Some(
        nh.last_applied_sig
            .as_ref()
            .map(|s| s.route_table)
            .unwrap_or(cfg.route_table),
    );
    st.created_rmnet_iface = nh.created_rmnet_iface.clone();
    st.saved_resolv = nh.saved_resolv.clone();
    st.ippt_dnsmasq_active = nh.ippt_dnsmasq_active;
    st.ipa_ippt_active = nh.ipa_ippt_active;
    st.ipa_ippt_dev_type = Some(cfg.ippt_dev_type.clone());
    st.ipa_ippt_vlan = cfg.ippt_vlan;
    st.ipa_v6_sharing_active = nh.ipa_v6_sharing_prefix.is_some();
    if !st.native_active
        && !st.vendor_daemons_stopped
        && !st.mwan3_stopped
        && st.baseline_sysctls.is_empty()
        && st.baseline_irq_affinities.is_empty()
        && st.baseline_ethtool_features.is_empty()
    {
        clear_persisted_native_state_locked();
    } else {
        let _ = save_persisted_native_state_locked(&st);
    }
}

#[derive(Debug, Clone, Default)]
struct NativeNatState {
    iface: String,
    link_mtu: u32,
    nft_table: bool,
    fw4_forward: bool,
    ipt_nat: bool,
    ipt_forward: bool,
    ip6t_forward: bool,
    ipt_mss_out_arg: Option<String>,
    ipt_mss_in_arg: Option<String>,
    ip6t_mss_out_arg: Option<String>,
    ip6t_mss_in_arg: Option<String>,
}

struct NativeHandles {
    v4_client: Option<Arc<QrtrServiceClient>>,
    v6_client: Option<Arc<QrtrServiceClient>>,
    v4_handle: Option<u32>,
    v6_handle: Option<u32>,
    last_v4_ip: Option<String>,
    last_v6_ip: Option<String>,
    last_v6_key: Option<(String, u8)>,
    /// Preserved across disconnect, reconnect, and SSR so stale WAN conntrack
    /// entries and odhcpd prefixes are always evicted when the bearer returns.
    last_applied_v4_ip: Option<String>,
    last_applied_v6_ip: Option<String>,
    last_applied_v6_key: Option<(String, u8)>,
    last_link_mtu: u32,
    last_applied_sig: Option<AppliedCfgSig>,
    last_resolved_iface: Option<String>,
    applied_dns: Vec<String>,
    saved_resolv: Option<SavedResolvSnapshot>,
    v6_dns_routes: Vec<Ipv6Addr>,
    ippt_host_ip: Option<Ipv4Addr>,
    ippt_dnsmasq_active: bool,
    ipa_ippt_active: bool,
    ipa_ippt_mac: Option<String>,
    ipa_v6_sharing_prefix: Option<String>,
    created_rmnet_iface: Option<String>,
    mwan3_stopped: bool,
    native_nat: Option<NativeNatState>,
    v4_backoff: ReconnectBackoff,
    v6_backoff: ReconnectBackoff,
    v4_next_retry_ms: u64,
    v6_next_retry_ms: u64,
    v4_last_error: Option<String>,
    v6_last_error: Option<String>,
    netlink_backoff: ReconnectBackoff,
    vendor_daemons_stopped: bool,
}

impl NativeHandles {
    fn new() -> Self {
        Self {
            v4_client: None,
            v6_client: None,
            v4_handle: None,
            v6_handle: None,
            last_v4_ip: None,
            last_v6_ip: None,
            last_v6_key: None,
            last_applied_v4_ip: None,
            last_applied_v6_ip: None,
            last_applied_v6_key: None,
            last_link_mtu: 1500,
            last_applied_sig: None,
            last_resolved_iface: None,
            applied_dns: Vec::new(),
            saved_resolv: None,
            v6_dns_routes: Vec::new(),
            ippt_host_ip: None,
            ippt_dnsmasq_active: false,
            ipa_ippt_active: false,
            ipa_ippt_mac: None,
            ipa_v6_sharing_prefix: None,
            created_rmnet_iface: None,
            mwan3_stopped: false,
            native_nat: None,
            v4_backoff: ReconnectBackoff::new(),
            v6_backoff: ReconnectBackoff::new(),
            v4_next_retry_ms: 0,
            v6_next_retry_ms: 0,
            v4_last_error: None,
            v6_last_error: None,
            netlink_backoff: ReconnectBackoff::new(),
            vendor_daemons_stopped: false,
        }
    }

    fn has_native_state(&self) -> bool {
        self.v4_client.is_some()
            || self.v6_client.is_some()
            || self.last_applied_sig.is_some()
            || self.created_rmnet_iface.is_some()
            || self.native_nat.is_some()
            || self.ippt_dnsmasq_active
    }
}

fn mwan3_is_active() -> bool {
    Path::new(&crate::paths::p("/etc/init.d/mwan3")).exists()
        && (Path::new(&crate::paths::p("/var/run/mwan3")).is_dir()
            || Path::new(&crate::paths::p("/tmp/run/mwan3")).is_dir())
}

pub(crate) fn should_re_stop_vendor_cm(
    already_stopped: bool,
    qcmap_running: bool,
    netmgrd_running: bool,
) -> (bool, bool) {
    let late = already_stopped && (qcmap_running || netmgrd_running);
    (!already_stopped || late, late)
}

async fn stop_mwan3_if_active() -> bool {
    if !mwan3_is_active() {
        return false;
    }
    let _ = run("/etc/init.d/mwan3", &["stop"], ExecOpts::new(25, 16 * KIB)).await;
    true
}

async fn start_mwan3() {
    let init = "/etc/init.d/mwan3";
    if Path::new(&crate::paths::p(init)).exists() {
        let _ = run(init, &["start"], ExecOpts::new(25, 16 * KIB)).await;
    }
}

pub(crate) fn fw4_chain_covers_iface(chain_text: &str, iface: &str) -> bool {
    let quoted = format!("\"{iface}\"");
    chain_text
        .lines()
        .any(|line| line.contains("oifname") && line.contains(&quoted))
}

pub(crate) fn build_native_nat_nft_script(
    iface: &str,
    include_masq: bool,
    link_mtu: u32,
) -> Result<String, String> {
    netlink::validate_managed_iface(iface)?;
    let mtu = link_mtu.clamp(1280, 1500);
    let mut s = "add table inet qm_native_nat\n\
         flush table inet qm_native_nat\n\
         add chain inet qm_native_nat forward { type filter hook forward priority mangle; policy accept; }\n"
        .to_string();
    if mtu < 1500 {
        let mss4 = mtu - 40;
        let mss6 = mtu - 60;
        s.push_str(&format!(
            "add rule inet qm_native_nat forward oifname \"{iface}\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size > {mss4} tcp option maxseg size set {mss4}\n\
             add rule inet qm_native_nat forward iifname \"{iface}\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size > {mss4} tcp option maxseg size set {mss4}\n\
             add rule inet qm_native_nat forward oifname \"{iface}\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size > {mss6} tcp option maxseg size set {mss6}\n\
             add rule inet qm_native_nat forward iifname \"{iface}\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size > {mss6} tcp option maxseg size set {mss6}\n"
        ));
    } else {
        s.push_str(&format!(
            "add rule inet qm_native_nat forward oifname \"{iface}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n\
             add rule inet qm_native_nat forward iifname \"{iface}\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size > 1460 tcp option maxseg size set 1460\n\
             add rule inet qm_native_nat forward iifname \"{iface}\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size > 1440 tcp option maxseg size set 1440\n"
        ));
    }
    if include_masq {
        s.push_str(&format!(
            "add chain inet qm_native_nat postrouting {{ type nat hook postrouting priority srcnat + 10; policy accept; }}\n\
             add rule inet qm_native_nat postrouting oifname \"{iface}\" meta nfproto ipv4 masquerade\n"
        ));
    }
    Ok(s)
}

pub(crate) fn extract_qm_native_nft_handles(chain_text: &str) -> Vec<u64> {
    chain_text
        .lines()
        .filter(|line| line.contains("comment \"qm_native\""))
        .filter_map(|line| {
            line.split("# handle ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        })
        .collect()
}

pub(crate) fn ipt_oif_covers_iface(rules_text: &str, iface: &str) -> bool {
    rules_text.lines().any(|line| {
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.windows(2).any(|w| w[0] == "-o" && w[1] == iface)
    })
}

pub(crate) fn ipt_tcpmss_covers_dir(rules_text: &str, dir_flag: &str, iface: &str) -> bool {
    rules_text.lines().any(|line| {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let has_dir = toks.windows(2).any(|w| w[0] == dir_flag && w[1] == iface);
        let has_tcpmss = toks.windows(2).any(|w| w[0] == "-j" && w[1] == "TCPMSS");
        has_dir && has_tcpmss
    })
}

/// Checks whether iptables/ip6tables `mangle FORWARD` rules cover TCPMSS clamping for `iface`
/// on both outbound (`-o`) and inbound (`-i`) paths (ignoring non-TCPMSS rules such as TTL/HL).
pub(crate) fn ipt_rules_cover_iface(rules_text: &str, iface: &str) -> bool {
    ipt_tcpmss_covers_dir(rules_text, "-o", iface)
        && ipt_tcpmss_covers_dir(rules_text, "-i", iface)
}

async fn apply_native_nat(
    nh: &mut NativeHandles,
    iface: &str,
    want_masq: bool,
    link_mtu: u32,
    warnings: &mut Vec<String>,
) {
    if let Err(e) = netlink::validate_managed_iface(iface) {
        warnings.push(format!("native NAT skipped: {e}"));
        return;
    }
    teardown_native_nat(nh, warnings).await;

    let nft_bin = "/usr/sbin/nft";
    let ipt_bin = "/usr/sbin/iptables";
    let ip6t_bin = "/usr/sbin/ip6tables";
    let mtu = link_mtu.clamp(1280, 1500);
    let mut st = NativeNatState {
        iface: iface.to_string(),
        link_mtu: mtu,
        ..Default::default()
    };

    if Path::new(&crate::paths::p(nft_bin)).exists() {
        let include_masq = if want_masq {
            let covered = match run(nft_bin, &["list", "chain", "inet", "fw4", "srcnat"], ExecOpts::new(5, 32 * KIB)).await {
                Ok(out) if out.ok() => fw4_chain_covers_iface(&out.stdout_str(), iface),
                _ => false,
            };
            !covered
        } else {
            false
        };
        match build_native_nat_nft_script(iface, include_masq, mtu) {
            Ok(script) => {
                match run(nft_bin, &["-f", "-"], ExecOpts::new(5, 16 * KIB).stdin(script.into_bytes())).await {
                    Ok(out) if out.ok() => st.nft_table = true,
                    Ok(out) => warnings.push(format!("native NAT/MSS nft: {}", out.err_summary("nft"))),
                    Err(e) => warnings.push(format!("native NAT/MSS nft exec: {e}")),
                }
            }
            Err(e) => warnings.push(format!("native NAT/MSS script: {e}")),
        }
        if let Ok(out) = run(nft_bin, &["list", "chain", "inet", "fw4", "accept_to_wan"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
            && !fw4_chain_covers_iface(&out.stdout_str(), iface)
        {
            match run(
                nft_bin,
                &["add", "rule", "inet", "fw4", "accept_to_wan", "oifname", iface, "counter", "accept", "comment", "qm_native"],
                ExecOpts::new(5, 16 * KIB),
            )
            .await
            {
                Ok(r) if r.ok() => st.fw4_forward = true,
                Ok(r) => warnings.push(format!("native fw4 forward: {}", r.err_summary("nft"))),
                Err(e) => warnings.push(format!("native fw4 forward exec: {e}")),
            }
        }
    } else if Path::new(&crate::paths::p(ipt_bin)).exists() {
        if want_masq
            && let Ok(out) = run(ipt_bin, &["-t", "nat", "-S", "POSTROUTING"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
            && !ipt_oif_covers_iface(&out.stdout_str(), iface)
        {
            match run(
                ipt_bin,
                &["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-m", "comment", "--comment", "qm_native", "-j", "MASQUERADE"],
                ExecOpts::new(5, 16 * KIB),
            )
            .await
            {
                Ok(r) if r.ok() => st.ipt_nat = true,
                Ok(r) => warnings.push(format!("native NAT iptables: {}", r.err_summary("iptables"))),
                Err(e) => warnings.push(format!("native NAT iptables exec: {e}")),
            }
        }
        if let Ok(out) = run(ipt_bin, &["-t", "filter", "-S", "zone_wan_dest_accept"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
            && !ipt_oif_covers_iface(&out.stdout_str(), iface)
        {
            match run(
                ipt_bin,
                &["-t", "filter", "-A", "zone_wan_dest_accept", "-o", iface, "-m", "comment", "--comment", "qm_native", "-j", "ACCEPT"],
                ExecOpts::new(5, 16 * KIB),
            )
            .await
            {
                Ok(r) if r.ok() => st.ipt_forward = true,
                Ok(r) => warnings.push(format!("native forward iptables: {}", r.err_summary("iptables"))),
                Err(e) => warnings.push(format!("native forward iptables exec: {e}")),
            }
        }
        if Path::new(&crate::paths::p(ip6t_bin)).exists()
            && let Ok(out) = run(ip6t_bin, &["-t", "filter", "-S", "zone_wan_dest_accept"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
            && !ipt_oif_covers_iface(&out.stdout_str(), iface)
        {
            match run(
                ip6t_bin,
                &["-t", "filter", "-A", "zone_wan_dest_accept", "-o", iface, "-m", "comment", "--comment", "qm_native", "-j", "ACCEPT"],
                ExecOpts::new(5, 16 * KIB),
            )
            .await
            {
                Ok(r) if r.ok() => st.ip6t_forward = true,
                Ok(r) => warnings.push(format!("native forward ip6tables: {}", r.err_summary("ip6tables"))),
                Err(e) => warnings.push(format!("native forward ip6tables exec: {e}")),
            }
        }
        if let Ok(out) = run(ipt_bin, &["-t", "mangle", "-S", "FORWARD"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
        {
            let rules = out.stdout_str();
            let need_out = !ipt_tcpmss_covers_dir(&rules, "-o", iface);
            let need_in = !ipt_tcpmss_covers_dir(&rules, "-i", iface);
            if mtu < 1500 {
                let mss4 = (mtu - 40).to_string();
                if need_out {
                    let r_out = run(
                        ipt_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss4],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_out.is_ok_and(|r| r.ok()) {
                        st.ipt_mss_out_arg = Some(mss4.clone());
                    }
                }
                if need_in {
                    let r_in = run(
                        ipt_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss4],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_in.is_ok_and(|r| r.ok()) {
                        st.ipt_mss_in_arg = Some(mss4);
                    }
                }
            } else {
                if need_out {
                    let r_out = run(
                        ipt_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_out.is_ok_and(|r| r.ok()) {
                        st.ipt_mss_out_arg = Some("pmtu".into());
                    }
                }
                if need_in {
                    let r_in = run(
                        ipt_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_in.is_ok_and(|r| r.ok()) {
                        st.ipt_mss_in_arg = Some("pmtu".into());
                    }
                }
            }
        }
        if Path::new(&crate::paths::p(ip6t_bin)).exists()
            && let Ok(out) = run(ip6t_bin, &["-t", "mangle", "-S", "FORWARD"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
        {
            let rules = out.stdout_str();
            let need_out = !ipt_tcpmss_covers_dir(&rules, "-o", iface);
            let need_in = !ipt_tcpmss_covers_dir(&rules, "-i", iface);
            if mtu < 1500 {
                let mss6 = (mtu - 60).to_string();
                if need_out {
                    let r_out = run(
                        ip6t_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss6],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_out.is_ok_and(|r| r.ok()) {
                        st.ip6t_mss_out_arg = Some(mss6.clone());
                    }
                }
                if need_in {
                    let r_in = run(
                        ip6t_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss6],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_in.is_ok_and(|r| r.ok()) {
                        st.ip6t_mss_in_arg = Some(mss6);
                    }
                }
            } else {
                if need_out {
                    let r_out = run(
                        ip6t_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_out.is_ok_and(|r| r.ok()) {
                        st.ip6t_mss_out_arg = Some("pmtu".into());
                    }
                }
                if need_in {
                    let r_in = run(
                        ip6t_bin,
                        &["-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await;
                    if r_in.is_ok_and(|r| r.ok()) {
                        st.ip6t_mss_in_arg = Some("pmtu".into());
                    }
                }
            }
        }
    }

    if st.nft_table
        || st.fw4_forward
        || st.ipt_nat
        || st.ipt_forward
        || st.ip6t_forward
        || st.ipt_mss_out_arg.is_some()
        || st.ipt_mss_in_arg.is_some()
        || st.ip6t_mss_out_arg.is_some()
        || st.ip6t_mss_in_arg.is_some()
    {
        nh.native_nat = Some(st);
    }
}

async fn delete_ipt_mss_rule(bin: &str, dir_flag: &str, iface: &str, mss_arg: &str) {
    if mss_arg == "pmtu" {
        let _ = run(
            bin,
            &["-t", "mangle", "-D", "FORWARD", dir_flag, iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            ExecOpts::new(5, 16 * KIB),
        )
        .await;
    } else {
        let _ = run(
            bin,
            &["-t", "mangle", "-D", "FORWARD", dir_flag, iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", mss_arg],
            ExecOpts::new(5, 16 * KIB),
        )
        .await;
    }
}

async fn teardown_native_nat(nh: &mut NativeHandles, warnings: &mut Vec<String>) {
    let Some(st) = nh.native_nat.take() else {
        return;
    };
    let nft_bin = "/usr/sbin/nft";
    let ipt_bin = "/usr/sbin/iptables";
    let ip6t_bin = "/usr/sbin/ip6tables";
    if st.nft_table {
        let _ = run(nft_bin, &["delete", "table", "inet", "qm_native_nat"], ExecOpts::new(5, 16 * KIB)).await;
    }
    if st.fw4_forward {
        match run(nft_bin, &["-a", "list", "chain", "inet", "fw4", "accept_to_wan"], ExecOpts::new(5, 32 * KIB)).await {
            Ok(out) if out.ok() => {
                for h in extract_qm_native_nft_handles(&out.stdout_str()) {
                    let hs = h.to_string();
                    match run(
                        nft_bin,
                        &["delete", "rule", "inet", "fw4", "accept_to_wan", "handle", &hs],
                        ExecOpts::new(5, 16 * KIB),
                    )
                    .await
                    {
                        Ok(r) if !r.ok() => warnings.push(format!("delete fw4 rule {hs}: {}", r.err_summary("nft"))),
                        Err(e) => warnings.push(format!("delete fw4 rule {hs}: {e}")),
                        _ => {}
                    }
                }
            }
            Ok(out) => warnings.push(format!("list fw4 accept_to_wan: {}", out.err_summary("nft"))),
            Err(e) => warnings.push(format!("list fw4 accept_to_wan exec: {e}")),
        }
    }
    if st.ipt_nat {
        let _ = run(
            ipt_bin,
            &["-t", "nat", "-D", "POSTROUTING", "-o", &st.iface, "-m", "comment", "--comment", "qm_native", "-j", "MASQUERADE"],
            ExecOpts::new(5, 16 * KIB),
        )
        .await;
    }
    if st.ipt_forward {
        let _ = run(
            ipt_bin,
            &["-t", "filter", "-D", "zone_wan_dest_accept", "-o", &st.iface, "-m", "comment", "--comment", "qm_native", "-j", "ACCEPT"],
            ExecOpts::new(5, 16 * KIB),
        )
        .await;
    }
    if st.ip6t_forward {
        let _ = run(
            ip6t_bin,
            &["-t", "filter", "-D", "zone_wan_dest_accept", "-o", &st.iface, "-m", "comment", "--comment", "qm_native", "-j", "ACCEPT"],
            ExecOpts::new(5, 16 * KIB),
        )
        .await;
    }
    if let Some(ref mss_arg) = st.ipt_mss_out_arg {
        delete_ipt_mss_rule(ipt_bin, "-o", &st.iface, mss_arg).await;
    }
    if let Some(ref mss_arg) = st.ipt_mss_in_arg {
        delete_ipt_mss_rule(ipt_bin, "-i", &st.iface, mss_arg).await;
    }
    if let Some(ref mss_arg) = st.ip6t_mss_out_arg {
        delete_ipt_mss_rule(ip6t_bin, "-o", &st.iface, mss_arg).await;
    }
    if let Some(ref mss_arg) = st.ip6t_mss_in_arg {
        delete_ipt_mss_rule(ip6t_bin, "-i", &st.iface, mss_arg).await;
    }
}

/// Parse `iptables -S <chain>` output and build `-D ...` delete argv lists for any
/// orphaned rules carrying `--comment qm_native` (or `--comment "qm_native"`).
pub(crate) fn extract_qm_native_ipt_delete_args(rules_text: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for line in rules_text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-A ") {
            continue;
        }
        if !trimmed.contains("--comment qm_native") && !trimmed.contains("--comment \"qm_native\"") {
            continue;
        }
        let mut args = Vec::new();
        for tok in trimmed.split_whitespace() {
            let clean = tok.trim_matches('"');
            if args.is_empty() && clean == "-A" {
                args.push("-D".to_string());
            } else {
                args.push(clean.to_string());
            }
        }
        if args.len() >= 2 {
            out.push(args);
        }
    }
    out
}

/// Remove any orphaned `qm_native` nftables / iptables / ip6tables rules left behind
/// by a previous crash before re-applying or restoring vendor mode (all non-blocking).
pub(crate) async fn cleanup_orphaned_native_firewall_rules(warnings: &mut Vec<String>) {
    let nft_bin = "/usr/sbin/nft";
    let ipt_bin = "/usr/sbin/iptables";
    let ip6t_bin = "/usr/sbin/ip6tables";

    if Path::new(&crate::paths::p(nft_bin)).exists() {
        let _ = run(nft_bin, &["delete", "table", "inet", "qm_native_nat"], ExecOpts::new(5, 16 * KIB)).await;
        if let Ok(out) = run(nft_bin, &["-a", "list", "chain", "inet", "fw4", "accept_to_wan"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
        {
            for h in extract_qm_native_nft_handles(&out.stdout_str()) {
                let hs = h.to_string();
                if let Ok(r) = run(
                    nft_bin,
                    &["delete", "rule", "inet", "fw4", "accept_to_wan", "handle", &hs],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await
                    && !r.ok()
                {
                    warnings.push(format!("orphan fw4 handle {hs}: {}", r.err_summary("nft")));
                }
            }
        }
    }

    for (bin, table, chain) in [
        (ipt_bin, "nat", "POSTROUTING"),
        (ipt_bin, "filter", "zone_wan_dest_accept"),
        (ipt_bin, "mangle", "FORWARD"),
        (ip6t_bin, "filter", "zone_wan_dest_accept"),
        (ip6t_bin, "mangle", "FORWARD"),
    ] {
        if !Path::new(&crate::paths::p(bin)).exists() {
            continue;
        }
        if let Ok(out) = run(bin, &["-t", table, "-S", chain], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
        {
            for del_tail in extract_qm_native_ipt_delete_args(&out.stdout_str()) {
                let mut argv: Vec<&str> = vec!["-t", table];
                argv.extend(del_tail.iter().map(String::as_str));
                let _ = run(bin, &argv, ExecOpts::new(5, 16 * KIB)).await;
            }
        }
    }
}

async fn heal_native_firewall_if_needed(
    nh: &mut NativeHandles,
    iface: &str,
    want_masq: bool,
    link_mtu: u32,
    warnings: &mut Vec<String>,
) -> bool {
    let nft_bin = "/usr/sbin/nft";
    let ipt_bin = "/usr/sbin/iptables";
    let ip6t_bin = "/usr/sbin/ip6tables";
    let missing = if Path::new(&crate::paths::p(nft_bin)).exists() {
        let table_missing = run(nft_bin, &["list", "table", "inet", "qm_native_nat"], ExecOpts::new(5, 16 * KIB))
            .await
            .is_ok_and(|o| !o.ok());
        let fwd_missing = match run(nft_bin, &["list", "chain", "inet", "fw4", "accept_to_wan"], ExecOpts::new(5, 32 * KIB)).await {
            Ok(o) if o.ok() => !fw4_chain_covers_iface(&o.stdout_str(), iface),
            _ => false,
        };
        table_missing || fwd_missing
    } else if Path::new(&crate::paths::p(ipt_bin)).exists() {
        let fwd_missing = match run(ipt_bin, &["-t", "filter", "-S", "zone_wan_dest_accept"], ExecOpts::new(5, 32 * KIB)).await {
            Ok(o) if o.ok() => !ipt_oif_covers_iface(&o.stdout_str(), iface),
            _ => false,
        };
        let fwd6_missing = if Path::new(&crate::paths::p(ip6t_bin)).exists() {
            match run(ip6t_bin, &["-t", "filter", "-S", "zone_wan_dest_accept"], ExecOpts::new(5, 32 * KIB)).await {
                Ok(o) if o.ok() => !ipt_oif_covers_iface(&o.stdout_str(), iface),
                _ => false,
            }
        } else {
            false
        };
        let mss_missing = match run(ipt_bin, &["-t", "mangle", "-S", "FORWARD"], ExecOpts::new(5, 32 * KIB)).await {
            Ok(o) if o.ok() => !ipt_rules_cover_iface(&o.stdout_str(), iface),
            _ => false,
        };
        let mss6_missing = if Path::new(&crate::paths::p(ip6t_bin)).exists() {
            match run(ip6t_bin, &["-t", "mangle", "-S", "FORWARD"], ExecOpts::new(5, 32 * KIB)).await {
                Ok(o) if o.ok() => !ipt_rules_cover_iface(&o.stdout_str(), iface),
                _ => false,
            }
        } else {
            false
        };
        fwd_missing || fwd6_missing || mss_missing || mss6_missing
    } else {
        false
    };
    let mtu_changed = nh
        .native_nat
        .as_ref()
        .is_some_and(|st| st.link_mtu != link_mtu.clamp(1280, 1500));
    if missing || mtu_changed {
        apply_native_nat(nh, iface, want_masq, link_mtu, warnings).await;
    }
    missing || mtu_changed
}

fn apply_iface_rps_high_throughput(iface: &str) {
    if netlink::validate_managed_iface(iface).is_err() {
        return;
    }
    for (suffix, val) in [("rps_cpus", "c\n"), ("rps_flow_cnt", "4096\n")] {
        let rel = format!("/sys/class/net/{iface}/queues/rx-0/{suffix}");
        let real = crate::paths::p(&rel);
        if Path::new(&real).exists() {
            let _ = fs::write(&real, val);
        }
    }
}

async fn ensure_native_rmnet_link(
    state: &AppState,
    cfg: &DataplaneConfig,
    nh: &mut NativeHandles,
    warnings: &mut Vec<String>,
) {
    if let Some(prev_iface) = nh.created_rmnet_iface.clone()
        && prev_iface != cfg.iface
        && nh.last_resolved_iface.as_deref() != Some(prev_iface.as_str())
    {
        let del_iface = prev_iface.clone();
        if let Ok(Ok(())) =
            tokio::task::spawn_blocking(move || netlink::delete_rmnet_link(&del_iface)).await
        {
            state.push_daemon_log(format!(
                "dataplane: deleted previously created rmnet link {prev_iface}"
            ));
        }
        nh.created_rmnet_iface = None;
    }

    let iface = cfg.iface.clone();
    let mux_id = cfg.mux_id;
    let high_tput = cfg.kernel_tuning == KernelTuningProfile::HighThroughput;
    let res = tokio::task::spawn_blocking(move || {
        let links = netlink::list_links()?;
        if netlink::resolve_rmnet_link(&links, &iface, mux_id).is_some() {
            return Ok::<_, String>(None);
        }
        let (link, created) = netlink::create_rmnet_link("rmnet_ipa0", &iface, u16::from(mux_id))?;
        if created && high_tput {
            apply_iface_rps_high_throughput(&link.name);
        }
        Ok(Some((link, created)))
    })
    .await;

    match res {
        Ok(Ok(Some((link, created)))) => {
            if created {
                nh.created_rmnet_iface = Some(link.name.clone());
                state.push_daemon_log(format!(
                    "dataplane: created rmnet link {} (mux_id={}, ifindex={}) on rmnet_ipa0",
                    link.name, cfg.mux_id, link.ifindex
                ));
            }
        }
        Ok(Ok(None)) => {}
        Ok(Err(e)) => warnings.push(format!("create rmnet link {}: {e}", cfg.iface)),
        Err(e) => warnings.push(format!("create rmnet link {} task panicked: {e}", cfg.iface)),
    }
}

async fn stop_vendor_cm_daemons() {
    for init in [
        "/etc/init.d/QCMAP_ConnectionManagerd.init",
        "/etc/init.d/netmgrd",
        "/etc/init.d/QCMAP_ConnectionManager",
    ] {
        let p = crate::paths::p(init);
        if Path::new(&p).exists() {
            let _ = run(init, &["stop"], ExecOpts::new(15, 16 * KIB)).await;
        }
    }
}

async fn start_vendor_cm_daemons() {
    for init in [
        "/etc/init.d/netmgrd",
        "/etc/init.d/QCMAP_ConnectionManagerd.init",
        "/etc/init.d/QCMAP_ConnectionManager",
    ] {
        let p = crate::paths::p(init);
        if Path::new(&p).exists() {
            let _ = run(init, &["start"], ExecOpts::new(15, 16 * KIB)).await;
        }
    }
}

async fn teardown_ipa_and_routes(
    nh: &mut NativeHandles,
    iface: &str,
    prev: &AppliedCfgSig,
    tear_v4: bool,
    tear_v6: bool,
    warnings: &mut Vec<String>,
) {
    let table = prev.route_table;
    if tear_v4 && nh.ipa_ippt_active {
        let args = build_ipa_ippass_disable_args(&prev.ippt_dev_type, prev.ippt_vlan, iface);
        if let Err(e) = run_ipa_cli(&args).await {
            warnings.push(e);
        }
        nh.ipa_ippt_active = false;
        nh.ipa_ippt_mac = None;
    }
    if tear_v4
        && (nh.ippt_dnsmasq_active || Path::new(&crate::paths::p(IPPT_DNSMASQ_CONF_PATH)).exists())
    {
        if let Err(e) = remove_ippt_dnsmasq_conf().await {
            warnings.push(e);
        }
        nh.ippt_dnsmasq_active = false;
    }
    if tear_v6 && nh.ipa_v6_sharing_prefix.take().is_some() {
        let args = build_ipa_v6_sharing_disable_args(iface);
        if let Err(e) = run_ipa_cli(&args).await {
            warnings.push(e);
        }
    }

    let dns_v6 = if tear_v6 {
        std::mem::take(&mut nh.v6_dns_routes)
    } else {
        Vec::new()
    };
    let ippt_v4 = if tear_v4 { nh.ippt_host_ip.take() } else { None };
    if !dns_v6.is_empty() || ippt_v4.is_some() {
        let tear_iface = iface.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(links) = netlink::list_links() {
                if !dns_v6.is_empty()
                    && let Some(link) = links.iter().find(|l| l.name == tear_iface)
                {
                    for dst in dns_v6 {
                        let _ = netlink::del_host_route_v6(&tear_iface, link.ifindex, dst, table);
                    }
                }
                if let Some(ip) = ippt_v4
                    && let Some(br) = links.iter().find(|l| l.name == "br-lan")
                {
                    let _ = netlink::del_passthrough_host_route_v4("br-lan", br.ifindex, ip, table);
                }
            }
        })
        .await;
    }
}

async fn teardown_ipa_and_dns(
    nh: &mut NativeHandles,
    cfg: &DataplaneConfig,
    restore_dns: bool,
    warnings: &mut Vec<String>,
) {
    teardown_native_nat(nh, warnings).await;

    let prev = nh
        .last_applied_sig
        .take()
        .unwrap_or_else(|| AppliedCfgSig::from(cfg));
    let iface = nh.last_resolved_iface.take().unwrap_or_else(|| prev.iface.clone());

    teardown_ipa_and_routes(nh, &iface, &prev, true, true, warnings).await;

    if restore_dns {
        nh.applied_dns.clear();
        if let Err(e) = restore_native_dns(&mut nh.saved_resolv).await {
            warnings.push(format!("restore native DNS: {e}"));
        }
    }
}

async fn teardown_native_handles(state: &AppState, nh: &mut NativeHandles, cfg: &DataplaneConfig) {
    NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
    NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
    NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
    let iface = nh
        .last_resolved_iface
        .clone()
        .or_else(|| nh.last_applied_sig.as_ref().map(|s| s.iface.clone()))
        .unwrap_or_else(|| cfg.iface.clone());
    let table = nh
        .last_applied_sig
        .as_ref()
        .map(|s| s.route_table)
        .unwrap_or(cfg.route_table);

    let mut warnings = Vec::new();
    teardown_ipa_and_dns(nh, cfg, true, &mut warnings).await;
    cleanup_orphaned_native_firewall_rules(&mut warnings).await;

    if let (Some(cli), Some(hdl)) = (&nh.v4_client, nh.v4_handle.take()) {
        let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
    }
    if let (Some(cli), Some(hdl)) = (&nh.v6_client, nh.v6_handle.take()) {
        let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
    }
    nh.v4_client = None;
    nh.v6_client = None;
    nh.last_v4_ip = None;
    nh.last_v6_ip = None;
    nh.last_v6_key = None;
    nh.last_applied_v4_ip = None;
    nh.last_applied_v6_ip = None;
    nh.last_applied_v6_key = None;
    nh.last_link_mtu = 1500;
    nh.last_applied_sig = None;
    nh.last_resolved_iface = None;
    nh.v4_backoff.reset();
    nh.v6_backoff.reset();
    nh.v4_next_retry_ms = 0;
    nh.v6_next_retry_ms = 0;
    nh.v4_last_error = None;
    nh.v6_last_error = None;
    nh.netlink_backoff.reset();

    flush_rmnet_stale_state(iface, table).await;

    if let Some(created_iface) = nh.created_rmnet_iface.take() {
        let del = created_iface.clone();
        match tokio::task::spawn_blocking(move || netlink::delete_rmnet_link(&del)).await {
            Ok(Ok(())) => {
                state.push_daemon_log(format!(
                    "dataplane: deleted daemon-created rmnet link {created_iface}"
                ));
            }
            Ok(Err(e)) => {
                state.push_daemon_log(format!(
                    "dataplane: delete rmnet link {created_iface}: {e}"
                ));
            }
            Err(e) => {
                state.push_daemon_log(format!(
                    "dataplane: delete rmnet link {created_iface} panicked: {e}"
                ));
            }
        }
    }
}

async fn refresh_netlink_into(snap: &mut DataplaneSnapshot, managed_iface: &str) {
    let iface = managed_iface.to_string();
    let res = tokio::task::spawn_blocking(move || {
        let links = netlink::list_links()?;
        let addrs = netlink::list_addrs()?;
        let routes = netlink::list_routes(None)?;
        Ok::<_, String>(parse_link_addr_route_filter(links, addrs, routes, &iface))
    })
    .await;
    match res {
        Ok(Ok((links, addrs, routes))) => {
            snap.links = links;
            snap.addrs = addrs;
            snap.routes = routes;
        }
        Ok(Err(e)) => snap.warnings.push(format!("netlink probe: {e}")),
        Err(e) => snap.warnings.push(format!("netlink task: {e}")),
    }
}

#[derive(Default)]
struct ProbeHandles {
    dms: Option<Arc<QrtrServiceClient>>,
    uim: Option<Arc<QrtrServiceClient>>,
    nas: Option<Arc<QrtrServiceClient>>,
    wda: Option<Arc<QrtrServiceClient>>,
    wds_probe: Option<Arc<QrtrServiceClient>>,
    nas_ind_registered: bool,
    device_rev: Option<String>,
    wda_format: Option<WdaDataFormat>,
    wda_ep: Option<(u32, u32)>,
    profiles: Vec<WdsProfileSummary>,
    profiles_source: Option<String>,
    profiles_fetched_at: u64,
}

impl ProbeHandles {
    fn clear_on_ssr(&mut self) {
        self.dms = None;
        self.uim = None;
        self.nas = None;
        self.wda = None;
        self.wds_probe = None;
        self.nas_ind_registered = false;
        self.device_rev = None;
        self.wda_format = None;
        self.wda_ep = None;
        self.profiles_fetched_at = 0;
    }
}

fn is_transport_err(e: &QmiError) -> bool {
    matches!(e, QmiError::Io(_) | QmiError::Timeout | QmiError::Ssr)
}

async fn ensure_probe_client(
    slot: &mut Option<Arc<QrtrServiceClient>>,
    bus: &Arc<QrtrBus>,
    service: u32,
    tag: &'static str,
    ind_tx: &mpsc::Sender<QmiIndication>,
    wait: Duration,
) -> Option<Arc<QrtrServiceClient>> {
    if let Some(c) = slot.as_ref().filter(|c| c.is_alive()) {
        return Some(Arc::clone(c));
    }
    *slot = None;
    if let Ok(c) = bus.open_service(service, tag, ind_tx.clone(), wait).await {
        *slot = Some(Arc::clone(&c));
        return Some(c);
    }
    None
}

async fn probe_readonly_qmi(
    bus: &Arc<QrtrBus>,
    ind_tx: &mpsc::Sender<QmiIndication>,
    ph: &mut ProbeHandles,
    snap: &mut DataplaneSnapshot,
    cfg: &DataplaneConfig,
) {
    let wait = Duration::from_secs(2);
    if let Some(dms_c) = ensure_probe_client(&mut ph.dms, bus, SVC_DMS, "DMS", ind_tx, wait).await {
        if ph.device_rev.is_none() {
            match dms::get_device_rev_id(dms_c.as_ref()).await {
                Ok(rev) => ph.device_rev = Some(rev),
                Err(ref e) if is_transport_err(e) => ph.dms = None,
                Err(_) => {}
            }
        }
        snap.device_rev = ph.device_rev.clone();
        if ph.dms.is_some() {
            match dms::get_operating_mode(dms_c.as_ref()).await {
                Ok(om) => snap.operating_mode = Some(om.as_str().to_string()),
                Err(ref e) if is_transport_err(e) => ph.dms = None,
                Err(_) => {}
            }
        }
    }
    if let Some(uim_c) = ensure_probe_client(&mut ph.uim, bus, SVC_UIM, "UIM", ind_tx, wait).await {
        match uim::get_card_status(uim_c.as_ref()).await {
            Ok(cs) => snap.uim = Some(cs),
            Err(ref e) if is_transport_err(e) => ph.uim = None,
            Err(_) => {}
        }
    }
    let nas_was_none = ph.nas.as_ref().filter(|c| c.is_alive()).is_none();
    if let Some(nas_c) = ensure_probe_client(&mut ph.nas, bus, SVC_NAS, "NAS", ind_tx, wait).await {
        if nas_was_none || !ph.nas_ind_registered {
            let _ = nas::register_sys_info_ind(nas_c.as_ref()).await;
            ph.nas_ind_registered = true;
        }
        match nas::get_sys_info(nas_c.as_ref()).await {
            Ok(sys) => snap.nas_sys = Some(sys),
            Err(ref e) if is_transport_err(e) => {
                ph.nas = None;
                ph.nas_ind_registered = false;
            }
            Err(_) => {}
        }
        if ph.nas.is_some() {
            if let Ok(sig) = nas::get_signal_info(nas_c.as_ref()).await {
                snap.nas_signal = Some(sig);
            }
            if let Ok(bands) = nas::get_rf_band_info(nas_c.as_ref()).await {
                snap.nas_bands = bands;
            }
        }
    }
    let want_ep = (cfg.ep_type, cfg.ep_iface_id);
    if (ph.wda_format.is_none() || ph.wda_ep != Some(want_ep))
        && let Some(wda_c) = ensure_probe_client(&mut ph.wda, bus, SVC_WDA, "WDA", ind_tx, wait).await
    {
        match wda::get_data_format(wda_c.as_ref(), Some(want_ep)).await {
            Ok(fmt) => {
                ph.wda_format = Some(fmt);
                ph.wda_ep = Some(want_ep);
            }
            Err(ref e) if is_transport_err(e) => ph.wda = None,
            Err(_) => {}
        }
    }
    snap.wda_format = ph.wda_format.clone();

    let need_profiles =
        ph.profiles_fetched_at == 0 || now_secs().saturating_sub(ph.profiles_fetched_at) >= 600;
    let need_coexist_wds = cfg.mode == DataplaneMode::Coexist;
    if (need_profiles || need_coexist_wds)
        && let Some(wds_c) = ensure_probe_client(&mut ph.wds_probe, bus, SVC_WDS, "WDS_PROBE", ind_tx, wait).await
    {
        if need_coexist_wds {
            match wds::get_pkt_srvc_status(wds_c.as_ref()).await {
                Ok(st) => {
                    snap.wds_v4.pkt_status = Some(st);
                    snap.wds_v4.state = if matches!(
                        snap.wds_v4.pkt_status.as_ref().map(|s| s.status),
                        Some(PktConnStatus::Connected)
                    ) {
                        "connected"
                    } else {
                        "observed"
                    };
                }
                Err(ref e) if is_transport_err(e) => ph.wds_probe = None,
                Err(_) => {}
            }
            if ph.wds_probe.is_some()
                && let Ok(rt) = wds::get_runtime_settings(wds_c.as_ref()).await
            {
                if rt.ipv4_addr.is_some() {
                    snap.wds_v4.runtime = Some(rt.clone());
                }
                if rt.ipv6_addr.is_some() {
                    snap.wds_v6.runtime = Some(rt);
                    snap.wds_v6.state = "observed";
                }
            }
        }
        if need_profiles && ph.wds_probe.is_some() {
            match wds::list_profiles(wds_c.as_ref()).await {
                Ok(p) => {
                    ph.profiles = p;
                    ph.profiles_source = Some("qmi-wds".into());
                    ph.profiles_fetched_at = now_secs();
                }
                Err(ref e) if is_transport_err(e) => {
                    ph.wds_probe = None;
                    ph.profiles_source = Some(format!("unavailable: {e}"));
                }
                Err(e) => {
                    ph.profiles_source = Some(format!("unavailable: {e}"));
                    ph.profiles_fetched_at = now_secs();
                }
            }
        }
    }
    snap.profiles = ph.profiles.clone();
    snap.profiles_source = ph.profiles_source.clone();
}

async fn resolve_effective_mux_id(cfg: &DataplaneConfig) -> u8 {
    let iface = cfg.iface.clone();
    let fallback = cfg.mux_id;
    tokio::task::spawn_blocking(move || {
        netlink::list_links()
            .ok()
            .and_then(|links| {
                netlink::resolve_rmnet_link(&links, &iface, fallback)
                    .and_then(|l| l.rmnet_mux_id)
                    .and_then(|m| u8::try_from(m).ok())
                    .filter(|&m| m > 0)
            })
            .unwrap_or(fallback)
    })
    .await
    .unwrap_or(fallback)
}

async fn bring_up_native_family(
    bus: &Arc<QrtrBus>,
    ind_tx: &mpsc::Sender<QmiIndication>,
    cfg: &DataplaneConfig,
    ip_family: u8,
    tag: &'static str,
    fam_snap: &mut WdsFamilySnapshot,
    warnings: &mut Vec<String>,
) -> Result<(Arc<QrtrServiceClient>, u32, WdsRuntimeSettings), QmiError> {
    let cli = bus
        .open_service(SVC_WDS, tag, ind_tx.clone(), Duration::from_secs(3))
        .await?;
    let mux_id = resolve_effective_mux_id(cfg).await;
    match wds::bind_mux_data_port(cli.as_ref(), cfg.ep_type, cfg.ep_iface_id, mux_id).await {
        Ok(()) => {}
        Err(e) if is_transport_err(&e) => return Err(e),
        Err(e) => warnings.push(format!("WDS bind_mux_data_port({tag}, mux={mux_id}): {e}")),
    }
    wds::set_client_ip_family_pref(cli.as_ref(), ip_family).await?;
    let params = StartParams {
        profile_index: cfg.profile_index,
        ip_family,
        ..Default::default()
    };
    let hdl = tokio::time::timeout(
        NATIVE_WDS_START_TIMEOUT,
        wds::start_network_interface(cli.as_ref(), &params),
    )
    .await
    .map_err(|_| QmiError::Timeout)??;
    let pkt = wds::get_pkt_srvc_status(cli.as_ref()).await.ok();
    let rt = wds::get_runtime_settings(cli.as_ref()).await?;
    fam_snap.handle = Some(hdl);
    fam_snap.pkt_status = pkt;
    fam_snap.runtime = Some(rt.clone());
    fam_snap.state = "connected";
    fam_snap.last_error = None;
    Ok((cli, hdl, rt))
}

/// Resolve dual-stack cellular link MTU using `.min()` across valid reported `mtu4` / `mtu6`
/// (`1280..=1500`), defaulting to `1500` only when neither family reports a valid MTU.
pub(crate) fn resolve_dual_stack_link_mtu(mtu4: Option<u32>, mtu6: Option<u32>) -> u32 {
    [mtu4, mtu6]
        .into_iter()
        .flatten()
        .filter(|m| (1280..=1500).contains(m))
        .min()
        .unwrap_or(1500)
}

struct AppliedNetlinkState {
    resolved_iface: String,
    link_mtu: u32,
    v4_ip: Option<Ipv4Addr>,
    v6_addr_str: Option<String>,
    v6_dns: Vec<Ipv6Addr>,
    ippt_host_ip: Option<Ipv4Addr>,
}

async fn apply_native_netlink(
    cfg: &DataplaneConfig,
    v4: Option<&WdsRuntimeSettings>,
    v6: Option<&WdsRuntimeSettings>,
    apply_v4: bool,
    apply_v6: bool,
    mtu_changed: bool,
) -> Result<AppliedNetlinkState, String> {
    let iface = cfg.iface.clone();
    let mux_id = cfg.mux_id;
    let table = cfg.route_table;
    let do_ippt_route = cfg.ippt && cfg.ippt_mac.is_some();
    let v4 = v4.cloned();
    let v6 = v6.cloned();
    tokio::task::spawn_blocking(move || {
        netlink::validate_managed_iface(&iface)?;
        netlink::validate_managed_table(table)?;
        let links = netlink::list_links()?;
        let link = netlink::resolve_rmnet_link(&links, &iface, mux_id)
            .ok_or_else(|| format!("interface {iface} not present in kernel netlink"))?;
        netlink::validate_managed_iface(&link.name)?;
        let resolved_iface = link.name.clone();
        let ifindex = link.ifindex;
        netlink::set_link_up(&resolved_iface, ifindex, true)?;

        let mtu4 = v4.as_ref().and_then(|r| r.mtu).filter(|m| (1280..=1500).contains(m));
        let mtu6 = v6.as_ref().and_then(|r| r.mtu).filter(|m| (1280..=1500).contains(m));
        let link_mtu = resolve_dual_stack_link_mtu(mtu4, mtu6);
        netlink::set_link_mtu(&resolved_iface, ifindex, link_mtu)?;

        let mut out_v4_ip = None;
        let mut out_ippt_host_ip = None;
        if apply_v4
            && let Some(rt4) = v4.as_ref()
            && let Some(ip_s) = rt4.ipv4_addr.as_deref()
            && let Ok(ip) = ip_s.parse::<Ipv4Addr>()
        {
            out_v4_ip = Some(ip);
            let plen = rt4.ipv4_prefix_len.unwrap_or(32);
            netlink::flush_iface_addrs(&resolved_iface, ifindex, Some(libc::AF_INET as u8))?;
            netlink::replace_addr(&resolved_iface, ifindex, IpAddr::V4(ip), plen)?;
            let gw = rt4
                .ipv4_gateway
                .as_deref()
                .and_then(|s| s.parse::<Ipv4Addr>().ok());
            netlink::replace_default_route_v4(&resolved_iface, ifindex, gw, table, None, mtu4)?;

            if do_ippt_route
                && let Some(br) = links.iter().find(|l| l.name == "br-lan")
            {
                netlink::replace_passthrough_host_route_v4("br-lan", br.ifindex, ip, table)?;
                out_ippt_host_ip = Some(ip);
            }
        } else if !apply_v4
            && mtu_changed
            && let Some(rt4) = v4.as_ref()
            && rt4.ipv4_addr.is_some()
        {
            // MTU changed on the sibling family: update v4 route MTU/metric in place
            // without flushing the healthy v4 address or tearing down IPPT.
            let gw = rt4
                .ipv4_gateway
                .as_deref()
                .and_then(|s| s.parse::<Ipv4Addr>().ok());
            netlink::replace_default_route_v4(&resolved_iface, ifindex, gw, table, None, mtu4)?;
        }

        let mut out_v6_addr_str = None;
        let mut out_v6_dns = Vec::new();
        if apply_v6
            && let Some(rt6) = v6.as_ref()
            && let Some(ip_s) = rt6.ipv6_addr.as_deref()
            && let Ok(ip) = ip_s.parse::<Ipv6Addr>()
        {
            out_v6_addr_str = Some(ip_s.to_string());
            let plen = rt6.ipv6_prefix_len.unwrap_or(64);
            netlink::flush_iface_addrs(&resolved_iface, ifindex, Some(libc::AF_INET6 as u8))?;
            netlink::replace_addr(&resolved_iface, ifindex, IpAddr::V6(ip), plen)?;
            netlink::replace_default_route_v6(&resolved_iface, ifindex, table, None, mtu6)?;

            for dns_raw in [rt6.ipv6_dns1.as_deref(), rt6.ipv6_dns2.as_deref()].into_iter().flatten() {
                if let Ok(dns_ip) = dns_raw.trim().parse::<Ipv6Addr>()
                    && !dns_ip.is_unspecified()
                    && !out_v6_dns.contains(&dns_ip)
                {
                    netlink::replace_host_route_v6(&resolved_iface, ifindex, dns_ip, table, Some(1024))?;
                    out_v6_dns.push(dns_ip);
                }
            }
        } else if !apply_v6
            && mtu_changed
            && let Some(rt6) = v6.as_ref()
            && rt6.ipv6_addr.is_some()
        {
            // MTU changed on the sibling family: update v6 route MTU/metric in place
            // without flushing the healthy v6 address or tearing down IPA v6 sharing.
            netlink::replace_default_route_v6(&resolved_iface, ifindex, table, None, mtu6)?;
        }
        Ok(AppliedNetlinkState {
            resolved_iface,
            link_mtu,
            v4_ip: out_v4_ip,
            v6_addr_str: out_v6_addr_str,
            v6_dns: out_v6_dns,
            ippt_host_ip: out_ippt_host_ip,
        })
    })
    .await
    .map_err(|e| format!("netlink task panicked: {e}"))?
}

pub(crate) fn bus_event_should_wake(ev: &QrtrBusEvent, need_services: bool) -> bool {
    match ev {
        QrtrBusEvent::Ssr { .. } => true,
        QrtrBusEvent::ServiceAdded(_) => need_services,
        QrtrBusEvent::ServiceRemoved { .. } => false,
    }
}

fn qrtr_telemetry_from(bsnap: qmi::qrtr::BusSnapshot) -> QrtrTelemetry {
    QrtrTelemetry {
        available: bsnap.available,
        local_node: bsnap.local_node,
        modem_node: bsnap.modem_node,
        ssr_count: bsnap.ssr_count,
        last_ssr_epoch: bsnap.last_ssr_epoch,
        services: bsnap.services,
        error: bsnap.last_error,
    }
}

async fn recv_bus_wakeup(
    bus_rx: Option<&mut tokio::sync::broadcast::Receiver<QrtrBusEvent>>,
    bus: Option<&QrtrBus>,
    last_ssr_count: u64,
    need_services: bool,
) -> QrtrBusEvent {
    let Some(rx) = bus_rx else {
        return std::future::pending().await;
    };
    loop {
        match rx.recv().await {
            Ok(ev) if bus_event_should_wake(&ev, need_services) => return ev,
            Ok(_) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                if let Some(b) = bus {
                    let bsnap = b.snapshot();
                    if bsnap.ssr_count > last_ssr_count {
                        return QrtrBusEvent::Ssr {
                            node: bsnap.modem_node,
                            reason: format!("QRTR broadcast lagged ({skipped} events) across SSR"),
                        };
                    }
                }
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                return std::future::pending().await;
            }
        }
    }
}

async fn collect_kernel_telemetry_async(
    profile: KernelTuningProfile,
    warnings: Vec<String>,
    iface: Option<String>,
) -> KernelTelemetry {
    tokio::task::spawn_blocking(move || collect_kernel_telemetry(profile, warnings, iface.as_deref()))
        .await
        .unwrap_or_default()
}

fn kernel_tuning_drifted(active_iface: &str) -> bool {
    if read_u64_sys("/proc/sys/net/netfilter/nf_conntrack_max").is_some_and(|v| v < 65536) {
        return true;
    }
    for cpu in 0..=3 {
        let rel = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor");
        if read_trimmed(&rel).is_some_and(|g| g != "performance") {
            return true;
        }
    }
    if read_trimmed("/sys/power/autosleep").is_some_and(|a| a != "off") {
        return true;
    }
    for rel in [
        "/sys/class/net/eth0/gro_flush_timeout",
        "/sys/class/net/rmnet_ipa0/gro_flush_timeout",
    ] {
        if read_trimmed(rel).is_some_and(|v| v != "20000") {
            return true;
        }
    }
    for q in 0..=3 {
        let rps_rel = format!("/sys/class/net/rmnet_ipa0/queues/rx-{q}/rps_cpus");
        if read_trimmed(&rps_rel).is_some_and(|v| v != "c") {
            return true;
        }
        let cnt_rel = format!("/sys/class/net/rmnet_ipa0/queues/rx-{q}/rps_flow_cnt");
        if read_trimmed(&cnt_rel).is_some_and(|v| v != "4096") {
            return true;
        }
        let expected_xps = if q % 2 == 0 { "4" } else { "8" };
        let xps_rel = format!("/sys/class/net/rmnet_ipa0/queues/tx-{q}/xps_cpus");
        if read_trimmed(&xps_rel).is_some_and(|v| v != expected_xps) {
            return true;
        }
    }
    if netlink::validate_managed_iface(active_iface).is_ok() {
        let rel = format!("/sys/class/net/{active_iface}/queues/rx-0/rps_cpus");
        if let Some(rps) = read_trimmed(&rel)
            && (rps == "0" || rps == "00")
        {
            return true;
        }
        let gro_rel = format!("/sys/class/net/{active_iface}/gro_flush_timeout");
        if read_trimmed(&gro_rel).is_some_and(|v| v != "20000") {
            return true;
        }
    }
    if let Ok(irqs) = fs::read_to_string(crate::paths::p("/proc/interrupts")) {
        for target in plan_irq_affinities(&irqs) {
            if let Some((rel, is_list)) = irq_affinity_file_for(&target.irq)
                && let Some(cur) = read_trimmed(&rel)
            {
                let expected = if is_list {
                    target.cpu_list
                } else {
                    target.cpu_mask
                };
                if cur != expected {
                    return true;
                }
            }
        }
    }
    false
}

/// Lightweight read-only snapshot exported to `/api/v1/metrics` without
/// sending any QMI/AT commands or touching sysfs.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct DataplaneMetricsView {
    pub mode: &'static str,
    pub wds_v4_connected: bool,
    pub wds_v6_connected: bool,
    pub ipa_clk_mhz: Option<u64>,
    pub ipa_hardware_offload_pct: Option<u8>,
    pub qrtr_ssr_total: u64,
    pub tuning_warnings: usize,
    pub indications_total: u64,
    pub netlink_updates_total: u64,
    pub sfe_loaded: bool,
    pub reconnect_attempts_total: u64,
    pub ioss_hwp_rx: Option<u64>,
    pub ioss_hwp_tx: Option<u64>,
    pub ioss_exp_rx: Option<u64>,
    pub ioss_exp_tx: Option<u64>,
}

pub async fn metrics_view() -> DataplaneMetricsView {
    let h = hub();
    let mode = h.config.read().await.mode.as_str();
    let snap = h.snapshot.read().await;
    let tuning_warnings = h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()).len();
    DataplaneMetricsView {
        mode,
        wds_v4_connected: snap.wds_v4.state == "connected",
        wds_v6_connected: snap.wds_v6.state == "connected",
        ipa_clk_mhz: snap.kernel.ipa_offload.clk_rate_mhz,
        ipa_hardware_offload_pct: snap.kernel.ipa_offload.eth_hardware_offload_pct,
        qrtr_ssr_total: snap.qrtr.ssr_count,
        tuning_warnings,
        indications_total: snap.indications_received,
        netlink_updates_total: snap.netlink_updates,
        sfe_loaded: snap.sfe_loaded,
        reconnect_attempts_total: snap.reconnect_attempts,
        ioss_hwp_rx: snap.kernel.ipa_offload.eth_hwp_rx_packets,
        ioss_hwp_tx: snap.kernel.ipa_offload.eth_hwp_tx_packets,
        ioss_exp_rx: snap.kernel.ipa_offload.eth_exp_rx_packets,
        ioss_exp_tx: snap.kernel.ipa_offload.eth_exp_tx_packets,
    }
}

async fn flush_rmnet_stale_state(iface: String, table: u32) {
    flush_rmnet_stale_family(iface, table, None).await;
}

/// Immediately strip stale IPv4 or IPv6 addresses and default route on `iface`
/// (or both families when `family` is `None`) via fork-free RTNETLINK.
async fn flush_rmnet_stale_family(iface: String, table: u32, family: Option<u8>) {
    let _ = tokio::task::spawn_blocking(move || {
        if netlink::validate_managed_iface(&iface).is_err()
            || netlink::validate_managed_table(table).is_err()
        {
            return;
        }
        if let Ok(links) = netlink::list_links()
            && let Some(link) = links.into_iter().find(|l| l.name == iface)
        {
            let _ = netlink::del_default_routes_family(&iface, link.ifindex, table, family);
            let _ = netlink::flush_iface_addrs(&iface, link.ifindex, family);
        }
    })
    .await;
}

/// Coalesce a burst of QMI indications arriving within `window` into a single batch,
/// waking early if `wake` fires (e.g. config change or clean shutdown).
pub(crate) async fn drain_coalesced_indications(
    rx: &mut mpsc::Receiver<QmiIndication>,
    wake: &Notify,
    window: Duration,
) -> Vec<QmiIndication> {
    let mut batch = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::select! {
            _ = wake.notified() => break,
            res = tokio::time::timeout(remaining, rx.recv()) => {
                match res {
                    Ok(Some(ind)) => {
                        batch.push(ind);
                        if batch.len() >= 128 {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }
    batch
}

/// Restore vendor CM daemons (`netmgrd`/QCMAP), `mwan3`, DNS, firewall rules,
/// and original pre-tuning sysctls from `/var/run/cellcore-native-state.json`.
/// Safe to invoke on clean shutdown, crash recovery, or `opkg remove` (`postrm`).
pub async fn restore_from_persisted_state() -> Result<Vec<String>, String> {
    let Some(st) = load_persisted_native_state() else {
        return Ok(Vec::new());
    };
    let mut actions = Vec::new();
    let mut warnings = Vec::new();

    NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
    NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
    NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);

    if st.native_active {
        cleanup_orphaned_native_firewall_rules(&mut warnings).await;
        actions.push("Cleaned native nft/iptables/ip6tables rules".into());

        if let Some(ref iface) = st.iface {
            if st.ipa_ippt_active {
                let dt = st.ipa_ippt_dev_type.as_deref().unwrap_or("eth0");
                let args = build_ipa_ippass_disable_args(dt, st.ipa_ippt_vlan, iface);
                let _ = run_ipa_cli(&args).await;
                actions.push(format!("Disabled IPA IPPT on {iface}"));
            }
            if st.ipa_v6_sharing_active {
                let args = build_ipa_v6_sharing_disable_args(iface);
                let _ = run_ipa_cli(&args).await;
                actions.push(format!("Disabled IPA IPv6 prefix sharing on {iface}"));
            }
            let tbl = st.route_table.unwrap_or(netlink::TABLE_MAIN);
            flush_rmnet_stale_state(iface.clone(), tbl).await;
            actions.push(format!("Flushed stale rmnet state on {iface}"));
        }

        if (st.ippt_dnsmasq_active || Path::new(&crate::paths::p(IPPT_DNSMASQ_CONF_PATH)).exists())
            && remove_ippt_dnsmasq_conf().await.unwrap_or(false)
        {
            actions.push("Removed IPPT dnsmasq override".into());
        }

        let mut saved_resolv = st.saved_resolv.clone();
        if saved_resolv.is_some() {
            let _ = restore_native_dns(&mut saved_resolv).await;
            actions.push("Restored pre-native resolv.conf files".into());
        }

        if let Some(created_iface) = st.created_rmnet_iface.clone() {
            let del = created_iface.clone();
            if let Ok(Ok(())) = tokio::task::spawn_blocking(move || netlink::delete_rmnet_link(&del)).await {
                actions.push(format!("Deleted daemon-created rmnet link {created_iface}"));
            }
        }
    }

    if !st.baseline_sysctls.is_empty()
        || !st.baseline_irq_affinities.is_empty()
        || !st.baseline_ethtool_features.is_empty()
    {
        let iface_opt = st.iface.clone();
        let _ = crate::paths::spawn_blocking(move || {
            apply_kernel_tuning(KernelTuningProfile::Default, iface_opt.as_deref())
        })
        .await;
        actions.push("Restored pre-tuning original kernel sysctls and IRQ/NIC baselines".into());
    }

    if st.vendor_daemons_stopped || st.native_active {
        start_vendor_cm_daemons().await;
        actions.push("Restored vendor netmgrd/QCMAP daemons".into());
    }
    if st.mwan3_stopped {
        start_mwan3().await;
        actions.push("Restored mwan3".into());
    }

    NATIVE_MODE_ACTIVE.store(false, Ordering::Release);
    clear_persisted_native_state();
    Ok(actions)
}

/// Clean shutdown hook invoked on `SIGTERM`/`SIGINT` in `main.rs`:
/// stops the supervisor and restores vendor QCMAP/`netmgrd`, `mwan3`, and original
/// pre-tuning sysctls whenever Native mode was active.
pub async fn shutdown_cleanly(state: &AppState) {
    let Some(h) = HUB.get().cloned() else {
        if load_persisted_native_state().is_some_and(|s| s.native_active) {
            let _ = restore_from_persisted_state().await;
        }
        return;
    };
    let was_native = NATIVE_MODE_ACTIVE.load(Ordering::Acquire)
        || load_persisted_native_state().is_some_and(|s| s.native_active);
    h.shutdown_requested.store(true, Ordering::Release);
    h.wake.notify_one();

    if h.supervisor_running.load(Ordering::Acquire) {
        let _ = tokio::time::timeout(Duration::from_secs(12), h.done_notify.notified()).await;
    }

    if was_native && load_persisted_native_state().is_some_and(|s| s.native_active) {
        state.push_daemon_log("dataplane: restoring vendor QCMAP/netmgrd, mwan3, and sysctls on shutdown");
        let _ = restore_from_persisted_state().await;
    }
}

/// CLI entrypoint for `cellcored dataplane-restore` / `cellctl dataplane-restore`
/// (also invoked by `postrm` on `opkg remove` to reverse Native mode cleanly).
pub fn run_dataplane_restore_cli() -> i32 {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dataplane-restore: runtime init failed: {e}");
            return 1;
        }
    };
    match rt.block_on(restore_from_persisted_state()) {
        Ok(actions) => {
            if actions.is_empty() {
                println!("ok=1 restored=0 note=no_persisted_native_state");
            } else {
                for a in &actions {
                    println!("ok=1 action={a}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("dataplane-restore failed: {e}");
            1
        }
    }
}

fn handle_modem_ssr(
    state: &AppState,
    ph: &mut ProbeHandles,
    nh: &mut NativeHandles,
    node: u32,
    ssr_count: u64,
    reason: &str,
) {
    NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
    NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
    NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
    state.push_daemon_log(format!("dataplane: QRTR SSR #{ssr_count} detected on node {node}: {reason}"));
    crate::obs::emit(
        crate::obs::EventKind::ModemSsr,
        crate::obs::Severity::Critical,
        format!("Modem baseband SSR (#{ssr_count})"),
        serde_json::json!({
            "node": node,
            "ssrCount": ssr_count,
            "reason": reason,
        }),
    );
    ph.clear_on_ssr();
    nh.v4_client = None;
    nh.v6_client = None;
    nh.v4_handle = None;
    nh.v6_handle = None;
    nh.last_v4_ip = None;
    nh.last_v6_ip = None;
    nh.last_v6_key = None;
    // Intentionally preserve `last_applied_v4_ip`, `last_applied_v6_ip`, and
    // `last_applied_v6_key` so post-SSR reconnect flushes stale WAN conntrack
    // entries and reloads odhcpd!
    nh.v4_backoff.reset();
    nh.v6_backoff.reset();
    nh.v4_next_retry_ms = 0;
    nh.v6_next_retry_ms = 0;
    nh.v4_last_error = None;
    nh.v6_last_error = None;
    nh.netlink_backoff.reset();
}

pub(crate) fn build_conntrack_eviction_args(
    prev_v4: Option<&str>,
    v4_changed: bool,
    prev_v6_key: Option<&(String, u8)>,
    prev_v6_ip: Option<&str>,
    v6_changed: bool,
) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    // Only flush conntrack entries bound to a *previous* WAN address/prefix when the bearer re-IPs
    // or recovers from SSR; never run global `conntrack -F` (which drops LAN management SSH sessions!).
    if v4_changed
        && let Some(old_ip) = prev_v4
        && old_ip.parse::<Ipv4Addr>().is_ok()
    {
        cmds.push(vec!["-D".into(), "-q".into(), old_ip.into()]);
        cmds.push(vec!["-D".into(), "-s".into(), old_ip.into()]);
    }
    if v6_changed {
        let mut flushed_v6 = false;
        if let Some((prefix64, plen)) = prev_v6_key {
            let prefix_net = format!("{prefix64}::");
            if prefix_net.parse::<Ipv6Addr>().is_ok() && *plen <= 128 {
                let cidr = format!("{prefix_net}/{plen}");
                cmds.push(vec!["-D".into(), "-f".into(), "ipv6".into(), "-s".into(), cidr.clone()]);
                cmds.push(vec!["-D".into(), "-f".into(), "ipv6".into(), "-q".into(), cidr]);
                flushed_v6 = true;
            }
        }
        if !flushed_v6
            && let Some(old_v6) = prev_v6_ip
            && old_v6.parse::<Ipv6Addr>().is_ok()
        {
            cmds.push(vec!["-D".into(), "-f".into(), "ipv6".into(), "-s".into(), old_v6.into()]);
            cmds.push(vec!["-D".into(), "-f".into(), "ipv6".into(), "-q".into(), old_v6.into()]);
        }
    }
    cmds
}

async fn flush_stale_wan_conntrack_and_reload_odhcpd(
    prev_v4: Option<&str>,
    v4_changed: bool,
    prev_v6_key: Option<&(String, u8)>,
    prev_v6_ip: Option<&str>,
    v6_changed: bool,
) {
    let cmds = build_conntrack_eviction_args(prev_v4, v4_changed, prev_v6_key, prev_v6_ip, v6_changed);
    if !cmds.is_empty() {
        for bin in ["/usr/sbin/conntrack", "/sbin/conntrack"] {
            if Path::new(&crate::paths::p(bin)).exists() {
                for argv in &cmds {
                    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                    let _ = run(bin, &refs, ExecOpts::new(3, 16 * KIB)).await;
                }
                break;
            }
        }
    }
    if prev_v6_key.is_some() && v6_changed {
        let odhcpd = "/etc/init.d/odhcpd";
        if Path::new(&crate::paths::p(odhcpd)).exists() {
            let _ = run(odhcpd, &["reload"], ExecOpts::new(5, 16 * KIB)).await;
        }
    }
}

/// Evaluate overall native bearer health with independent per-family backoff.
/// On IPv6-only carriers in `Ipv4v6` mode, if either v4 or v6 is connected and netlink
/// succeeded, the bearer is considered healthy (`native-connected`, 15s poll) while the
/// unavailable family backs off independently.
pub(crate) fn evaluate_native_bearer_health(
    v4_up: bool,
    v6_up: bool,
    netlink_err: bool,
    v4_retry_delay: Option<Duration>,
    v6_retry_delay: Option<Duration>,
    netlink_delay: Option<Duration>,
) -> (bool, Duration, String) {
    let any_up = v4_up || v6_up;
    if netlink_err {
        let delay = netlink_delay.unwrap_or(Duration::from_secs(5));
        return (false, delay, format!("native-backoff-{}s", delay.as_secs()));
    }
    if any_up {
        return (true, Duration::from_secs(15), "native-connected".into());
    }
    let delay = [v4_retry_delay, v6_retry_delay]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(Duration::from_secs(5))
        .clamp(Duration::from_secs(1), Duration::from_secs(60));
    (false, delay, format!("native-backoff-{}s", delay.as_secs()))
}

struct SupervisorRunGuard(Arc<DataplaneHub>);

impl Drop for SupervisorRunGuard {
    fn drop(&mut self) {
        self.0.supervisor_running.store(false, Ordering::Release);
        self.0.done_notify.notify_waiters();
    }
}

async fn apply_qmi_indication(
    h: &DataplaneHub,
    nh: &mut NativeHandles,
    cfg: &DataplaneConfig,
    ind: QmiIndication,
) {
    let mut flush_fam: Option<Option<u8>> = None;
    {
        let mut s = h.snapshot.write().await;
        s.indications_received += 1;
        s.last_indication = Some(format!(
            "{} {:#06x} ({})",
            qmi::service_name(ind.service),
            ind.msg_id,
            ind.tag
        ));
        if ind.service == SVC_NAS && ind.msg_id == nas::NAS_SYS_INFO_IND {
            s.nas_sys = Some(nas::parse_sys_info_tlvs(&ind.tlvs));
        } else if ind.service == SVC_WDS
            && ind.msg_id == WDS_PKT_SRVC_STATUS_IND
            && let Ok(ps) = wds::parse_pkt_srvc_status_tlvs(&ind.tlvs)
            && (ps.reconfig_required || ps.status == PktConnStatus::Disconnected)
        {
            if ind.tag == "WDS_V4" {
                nh.v4_client = None;
                nh.v4_handle = None;
                nh.last_v4_ip = None;
                NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                s.wds_v4.state = "disconnected";
                s.wds_v4.pkt_status = Some(ps);
                flush_fam = Some(if is_wds_connected() {
                    Some(libc::AF_INET as u8)
                } else {
                    NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
                    None
                });
            } else if ind.tag == "WDS_V6" {
                nh.v6_client = None;
                nh.v6_handle = None;
                nh.last_v6_ip = None;
                nh.last_v6_key = None;
                NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                s.wds_v6.state = "disconnected";
                s.wds_v6.pkt_status = Some(ps);
                flush_fam = Some(if is_wds_connected() {
                    Some(libc::AF_INET6 as u8)
                } else {
                    NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
                    None
                });
            }
        }
    }
    if cfg.mode == DataplaneMode::Native
        && let Some(fam) = flush_fam
    {
        let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
        let prev_sig = nh
            .last_applied_sig
            .clone()
            .unwrap_or_else(|| AppliedCfgSig::from(cfg));
        let flush_tbl = prev_sig.route_table;
        let tear_v4 = fam.is_none() || fam == Some(libc::AF_INET as u8);
        let tear_v6 = fam.is_none() || fam == Some(libc::AF_INET6 as u8);
        let mut tear_warns = Vec::new();
        teardown_ipa_and_routes(nh, &flush_if, &prev_sig, tear_v4, tear_v6, &mut tear_warns).await;
        if !is_wds_connected() && cfg.manage_dns && nh.saved_resolv.is_some() {
            nh.applied_dns.clear();
            let _ = restore_native_dns(&mut nh.saved_resolv).await;
        }
        flush_rmnet_stale_family(flush_if, flush_tbl, fam).await;
        persist_native_handoff_state(nh, cfg, true);
    }
}

async fn supervisor_loop(state: AppState, h: Arc<DataplaneHub>) {
    h.supervisor_running.store(true, Ordering::Release);
    let _run_guard = SupervisorRunGuard(Arc::clone(&h));

    let (ind_tx, mut ind_rx) = mpsc::channel::<QmiIndication>(64);
    let mut bus: Option<Arc<QrtrBus>> = None;
    let mut bus_rx: Option<tokio::sync::broadcast::Receiver<QrtrBusEvent>> = None;
    let mut nh = NativeHandles::new();
    let mut ph = ProbeHandles::default();
    let mut native_tick: u64 = 0;
    let mut loop_tick: u64 = 0;
    let mut last_ssr_count: u64 = 0;
    let mut pending_phy_reenable = false;
    let mut flushed_unregistered = false;
    let mut need_orphan_fw_cleanup = true;

    // On crash-restart, hydrate handoff flags from `/var/run/cellcore-native-state.json`
    // so vendor daemons, mwan3, DNS, and created links remain cleanly reversible.
    if let Some(prev) = load_persisted_native_state()
        && prev.native_active
    {
        nh.vendor_daemons_stopped = prev.vendor_daemons_stopped;
        nh.mwan3_stopped = prev.mwan3_stopped;
        nh.created_rmnet_iface = prev.created_rmnet_iface;
        nh.saved_resolv = prev.saved_resolv;
        nh.ippt_dnsmasq_active = prev.ippt_dnsmasq_active;
        nh.ipa_ippt_active = prev.ipa_ippt_active;
        nh.last_resolved_iface = prev.iface;
    }

    loop {
        if h.shutdown_requested.load(Ordering::Acquire) {
            break;
        }
        loop_tick = loop_tick.wrapping_add(1);
        let cfg = h.config.read().await.clone();
        if bus.is_none() {
            match qmi::qrtr::shared_bus() {
                Ok(b) => {
                    last_ssr_count = b.snapshot().ssr_count;
                    bus_rx = Some(b.subscribe());
                    bus = Some(b);
                    state.push_daemon_log("dataplane: AF_QIPCRTR shared control bus connected");
                }
                Err(e) => {
                    let mut snap = DataplaneSnapshot {
                        updated_at: now_secs(),
                        mode: cfg.mode,
                        supervisor_state: match e {
                            QmiError::Unsupported(_) => "qrtr-unsupported".into(),
                            _ => "qrtr-unavailable".into(),
                        },
                        qrtr: QrtrTelemetry {
                            available: false,
                            modem_node: qmi::qrtr::configured_modem_node(),
                            error: Some(e.to_string()),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    snap.ipa_cli_present = Path::new(&crate::paths::p("/usr/bin/ipa")).exists();
                    snap.sfe_loaded = is_sfe_loaded();
                    let tw = h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    snap.kernel = collect_kernel_telemetry_async(cfg.kernel_tuning, tw, Some(cfg.iface.clone())).await;
                    refresh_netlink_into(&mut snap, &cfg.iface).await;
                    *h.snapshot.write().await = snap;
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(15)) => continue,
                        _ = h.wake.notified() => continue,
                    }
                }
            }
        }

        let b = bus.as_ref().expect("QRTR bus initialized");
        let bsnap_initial = b.snapshot();
        if bsnap_initial.ssr_count > last_ssr_count {
            last_ssr_count = bsnap_initial.ssr_count;
            handle_modem_ssr(
                &state,
                &mut ph,
                &mut nh,
                bsnap_initial.modem_node,
                last_ssr_count,
                "SSR counter latched",
            );
            if cfg.mode == DataplaneMode::Native {
                let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                let flush_tbl = nh.last_applied_sig.as_ref().map(|s| s.route_table).unwrap_or(cfg.route_table);
                flush_rmnet_stale_state(flush_if, flush_tbl).await;
            }
            pending_phy_reenable = true;
        }
        let prev_counts = {
            let s = h.snapshot.read().await;
            (s.indications_received, s.reconnect_attempts, s.netlink_updates, s.last_indication.clone())
        };
        let mut snap = DataplaneSnapshot {
            updated_at: now_secs(),
            mode: cfg.mode,
            qrtr: qrtr_telemetry_from(bsnap_initial),
            indications_received: prev_counts.0,
            reconnect_attempts: prev_counts.1,
            netlink_updates: prev_counts.2,
            last_indication: prev_counts.3,
            ..Default::default()
        };

        probe_readonly_qmi(b, &ind_tx, &mut ph, &mut snap, &cfg).await;
        if pending_phy_reenable && (snap.nas_sys.is_some() || snap.operating_mode.is_some()) {
            pending_phy_reenable = false;
            let st_phy = state.clone();
            tokio::spawn(async move {
                crate::radio_tuning::enable_phy_telemetry_counters(&st_phy).await;
            });
        }

        let mut next_sleep = Duration::from_secs(15);
        match cfg.mode {
            DataplaneMode::Coexist => {
                native_tick = 0;
                flushed_unregistered = false;
                need_orphan_fw_cleanup = true;
                NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
                NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                if nh.has_native_state() {
                    teardown_native_handles(&state, &mut nh, &cfg).await;
                }
                if nh.vendor_daemons_stopped {
                    start_vendor_cm_daemons().await;
                    nh.vendor_daemons_stopped = false;
                }
                NATIVE_MODE_ACTIVE.store(false, Ordering::Release);
                if nh.mwan3_stopped {
                    start_mwan3().await;
                    nh.mwan3_stopped = false;
                    state.push_daemon_log("dataplane: restarted mwan3 for coexist mode");
                }
                persist_native_handoff_state(&nh, &cfg, false);
                snap.supervisor_state = "coexist-observing".into();
            }
            DataplaneMode::Native => {
                native_tick = native_tick.wrapping_add(1);
                if need_orphan_fw_cleanup {
                    // Clean up any orphaned iptables/nft rules left across a crash-restart before re-applying.
                    cleanup_orphaned_native_firewall_rules(&mut snap.warnings).await;
                    need_orphan_fw_cleanup = false;
                }

                let cur_sig_pre = AppliedCfgSig::from(&cfg);
                if bearer_restart_needed(nh.last_applied_sig.as_ref(), &cur_sig_pre) {
                    state.push_daemon_log(format!(
                        "dataplane: bearer config changed (profile={}, ip_family={:?}, iface={}); restarting native bearer",
                        cfg.profile_index, cfg.ip_family, cfg.iface
                    ));
                    teardown_native_handles(&state, &mut nh, &cfg).await;
                } else {
                    if !cfg.ip_family.wants_v4() && (nh.v4_client.is_some() || nh.last_v4_ip.is_some()) {
                        if let (Some(cli), Some(hdl)) = (&nh.v4_client, nh.v4_handle.take()) {
                            let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
                        }
                        nh.v4_client = None;
                        nh.last_v4_ip = None;
                        NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                        let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                        let flush_tbl = nh.last_applied_sig.as_ref().map(|s| s.route_table).unwrap_or(cfg.route_table);
                        flush_rmnet_stale_family(flush_if, flush_tbl, Some(libc::AF_INET as u8)).await;
                    }
                    if !cfg.ip_family.wants_v6() && (nh.v6_client.is_some() || nh.last_v6_ip.is_some()) {
                        if let (Some(cli), Some(hdl)) = (&nh.v6_client, nh.v6_handle.take()) {
                            let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
                        }
                        nh.v6_client = None;
                        nh.last_v6_ip = None;
                        nh.last_v6_key = None;
                        NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                        let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                        let flush_tbl = nh.last_applied_sig.as_ref().map(|s| s.route_table).unwrap_or(cfg.route_table);
                        flush_rmnet_stale_family(flush_if, flush_tbl, Some(libc::AF_INET6 as u8)).await;
                    }
                }

                let manual_family = h.reconnect_queue.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(ref f) = manual_family {
                    let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                    let flush_tbl = nh.last_applied_sig.as_ref().map(|s| s.route_table).unwrap_or(cfg.route_table);
                    if f == "all" || f == "ipv4" {
                        if let (Some(cli), Some(hdl)) = (&nh.v4_client, nh.v4_handle.take()) {
                            let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
                        }
                        nh.v4_client = None;
                        nh.last_v4_ip = None;
                        nh.v4_backoff.reset();
                        nh.v4_next_retry_ms = 0;
                        nh.v4_last_error = None;
                        NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                    }
                    if f == "all" || f == "ipv6" {
                        if let (Some(cli), Some(hdl)) = (&nh.v6_client, nh.v6_handle.take()) {
                            let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
                        }
                        nh.v6_client = None;
                        nh.last_v6_ip = None;
                        nh.last_v6_key = None;
                        nh.v6_backoff.reset();
                        nh.v6_next_retry_ms = 0;
                        nh.v6_last_error = None;
                        NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                    }
                    let flush_fam = match f.as_str() {
                        "ipv4" => Some(libc::AF_INET as u8),
                        "ipv6" => Some(libc::AF_INET6 as u8),
                        _ => None,
                    };
                    if !is_wds_connected() {
                        NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
                    }
                    flush_rmnet_stale_family(flush_if, flush_tbl, flush_fam).await;
                    nh.netlink_backoff.reset();
                }

                NATIVE_MODE_ACTIVE.store(true, Ordering::Release);
                let vendor_procs = tokio::task::spawn_blocking(|| {
                    proc_comms_present(&["QCMAP_ConnectionManager", "netmgrd"])
                })
                .await
                .unwrap_or_else(|_| vec![false, false]);
                let (need_vendor_stop, late_vendor) =
                    should_re_stop_vendor_cm(nh.vendor_daemons_stopped, vendor_procs[0], vendor_procs[1]);
                if need_vendor_stop {
                    if late_vendor {
                        state.push_daemon_log(format!(
                            "dataplane: re-stopping late-started vendor CM daemons in native mode (qcmap={}, netmgrd={})",
                            vendor_procs[0], vendor_procs[1]
                        ));
                    }
                    stop_vendor_cm_daemons().await;
                    nh.vendor_daemons_stopped = true;
                }
                if mwan3_is_active() {
                    let was_stopped = nh.mwan3_stopped;
                    if stop_mwan3_if_active().await {
                        nh.mwan3_stopped = true;
                        state.push_daemon_log(if was_stopped {
                            "dataplane: re-stopped late-started mwan3 in native mode"
                        } else {
                            "dataplane: stopped mwan3 for native routing"
                        });
                    }
                }

                ensure_native_rmnet_link(&state, &cfg, &mut nh, &mut snap.warnings).await;
                persist_native_handoff_state(&nh, &cfg, true);

                let ps_ready = snap.nas_sys.as_ref().is_some_and(|s| s.registered);
                if !ps_ready {
                    NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
                    NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                    NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                    if !flushed_unregistered {
                        nh.v4_client = None;
                        nh.v6_client = None;
                        nh.v4_handle = None;
                        nh.v6_handle = None;
                        nh.last_v4_ip = None;
                        nh.last_v6_ip = None;
                        nh.last_v6_key = None;
                        let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                        let prev_sig = nh
                            .last_applied_sig
                            .clone()
                            .unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                        let flush_tbl = prev_sig.route_table;
                        teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, true, true, &mut snap.warnings).await;
                        if cfg.manage_dns && nh.saved_resolv.is_some() {
                            nh.applied_dns.clear();
                            if let Err(e) = restore_native_dns(&mut nh.saved_resolv).await {
                                snap.warnings.push(format!("restore native DNS: {e}"));
                            }
                        }
                        flush_rmnet_stale_state(flush_if, flush_tbl).await;
                        persist_native_handoff_state(&nh, &cfg, true);
                        flushed_unregistered = true;
                        state.push_daemon_log("dataplane: immediately flushed stale rmnet/IPA/DNS state after PS registration loss");
                    }
                    snap.supervisor_state = "native-waiting-registration".into();
                } else {
                    flushed_unregistered = false;
                    let mut v4_rt = None;
                    let mut v6_rt = None;
                    let mut v4_failed_this_tick = false;
                    let mut v6_failed_this_tick = false;
                    let mut v4_retry_delay: Option<Duration> = None;
                    let mut v6_retry_delay: Option<Duration> = None;
                    let mut netlink_err = false;
                    let mut netlink_delay: Option<Duration> = None;
                    let now_ms = crate::state::mono_ms();
                    let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                    let flush_tbl = nh.last_applied_sig.as_ref().map(|s| s.route_table).unwrap_or(cfg.route_table);

                    // 1. Poll existing live WDS clients; immediately strip stale netlink state on disconnect.
                    if cfg.ip_family.wants_v4()
                        && let Some(cli) = nh.v4_client.clone().filter(|c| c.is_alive())
                    {
                        if let Ok(st) = wds::get_pkt_srvc_status(cli.as_ref()).await {
                            snap.wds_v4.pkt_status = Some(st.clone());
                            if st.status == PktConnStatus::Connected && !st.reconfig_required {
                                match wds::get_runtime_settings(cli.as_ref()).await {
                                    Ok(rt) => {
                                        v4_rt = Some(rt.clone());
                                        snap.wds_v4.runtime = Some(rt);
                                        snap.wds_v4.handle = nh.v4_handle;
                                        snap.wds_v4.state = "connected";
                                        nh.v4_backoff.reset();
                                        nh.v4_next_retry_ms = 0;
                                        nh.v4_last_error = None;
                                        NATIVE_WDS_V4_CONNECTED.store(true, Ordering::Release);
                                    }
                                    Err(e) => {
                                        nh.v4_client = None;
                                        nh.v4_handle = None;
                                        nh.last_v4_ip = None;
                                        NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                                        let prev_sig = nh.last_applied_sig.clone().unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                                        teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, true, false, &mut snap.warnings).await;
                                        flush_rmnet_stale_family(flush_if.clone(), flush_tbl, Some(libc::AF_INET as u8)).await;
                                        v4_failed_this_tick = true;
                                        let d = nh.v4_backoff.next_delay();
                                        nh.v4_next_retry_ms = crate::state::mono_ms().saturating_add(d.as_millis() as u64);
                                        v4_retry_delay = Some(d);
                                        let msg = format!("get_runtime_settings: {e}");
                                        nh.v4_last_error = Some(msg.clone());
                                        snap.wds_v4.state = "backoff";
                                        snap.wds_v4.last_error = Some(msg);
                                    }
                                }
                            } else {
                                nh.v4_client = None;
                                nh.v4_handle = None;
                                nh.last_v4_ip = None;
                                NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                                snap.wds_v4.state = "disconnected";
                                let prev_sig = nh.last_applied_sig.clone().unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                                teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, true, false, &mut snap.warnings).await;
                                flush_rmnet_stale_family(flush_if.clone(), flush_tbl, Some(libc::AF_INET as u8)).await;
                            }
                        } else {
                            nh.v4_client = None;
                            nh.v4_handle = None;
                            nh.last_v4_ip = None;
                            NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                            snap.wds_v4.state = "disconnected";
                            let prev_sig = nh.last_applied_sig.clone().unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                            teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, true, false, &mut snap.warnings).await;
                            flush_rmnet_stale_family(flush_if.clone(), flush_tbl, Some(libc::AF_INET as u8)).await;
                        }
                    }

                    if cfg.ip_family.wants_v6()
                        && let Some(cli) = nh.v6_client.clone().filter(|c| c.is_alive())
                    {
                        if let Ok(st) = wds::get_pkt_srvc_status(cli.as_ref()).await {
                            snap.wds_v6.pkt_status = Some(st.clone());
                            if st.status == PktConnStatus::Connected && !st.reconfig_required {
                                match wds::get_runtime_settings(cli.as_ref()).await {
                                    Ok(mut rt) => {
                                        if !ipv6_bearer_changed(Some(&rt), nh.last_v6_key.as_ref())
                                            && let Some(applied_v6) = nh.last_v6_ip.as_ref()
                                        {
                                            rt.ipv6_addr = Some(applied_v6.clone());
                                        }
                                        v6_rt = Some(rt.clone());
                                        snap.wds_v6.runtime = Some(rt);
                                        snap.wds_v6.handle = nh.v6_handle;
                                        snap.wds_v6.state = "connected";
                                        nh.v6_backoff.reset();
                                        nh.v6_next_retry_ms = 0;
                                        nh.v6_last_error = None;
                                        NATIVE_WDS_V6_CONNECTED.store(true, Ordering::Release);
                                    }
                                    Err(e) => {
                                        nh.v6_client = None;
                                        nh.v6_handle = None;
                                        nh.last_v6_ip = None;
                                        nh.last_v6_key = None;
                                        NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                                        let prev_sig = nh.last_applied_sig.clone().unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                                        teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, false, true, &mut snap.warnings).await;
                                        flush_rmnet_stale_family(flush_if.clone(), flush_tbl, Some(libc::AF_INET6 as u8)).await;
                                        v6_failed_this_tick = true;
                                        let d = nh.v6_backoff.next_delay();
                                        nh.v6_next_retry_ms = crate::state::mono_ms().saturating_add(d.as_millis() as u64);
                                        v6_retry_delay = Some(d);
                                        let msg = format!("get_runtime_settings: {e}");
                                        nh.v6_last_error = Some(msg.clone());
                                        snap.wds_v6.state = "backoff";
                                        snap.wds_v6.last_error = Some(msg);
                                    }
                                }
                            } else {
                                nh.v6_client = None;
                                nh.v6_handle = None;
                                nh.last_v6_ip = None;
                                nh.last_v6_key = None;
                                NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                                snap.wds_v6.state = "disconnected";
                                let prev_sig = nh.last_applied_sig.clone().unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                                teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, false, true, &mut snap.warnings).await;
                                flush_rmnet_stale_family(flush_if.clone(), flush_tbl, Some(libc::AF_INET6 as u8)).await;
                            }
                        } else {
                            nh.v6_client = None;
                            nh.v6_handle = None;
                            nh.last_v6_ip = None;
                            nh.last_v6_key = None;
                            NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                            snap.wds_v6.state = "disconnected";
                            let prev_sig = nh.last_applied_sig.clone().unwrap_or_else(|| AppliedCfgSig::from(&cfg));
                            teardown_ipa_and_routes(&mut nh, &flush_if, &prev_sig, false, true, &mut snap.warnings).await;
                            flush_rmnet_stale_family(flush_if.clone(), flush_tbl, Some(libc::AF_INET6 as u8)).await;
                        }
                    }

                    // 2. Start missing IPv4 and IPv6 WDS sessions CONCURRENTLY (bounded to 30 s each)
                    //    so dual-stack attach never stalls back-to-back for 4 minutes.
                    let start_v4 = cfg.ip_family.wants_v4()
                        && nh.v4_client.is_none()
                        && !v4_failed_this_tick
                        && now_ms >= nh.v4_next_retry_ms;
                    let start_v6 = cfg.ip_family.wants_v6()
                        && nh.v6_client.is_none()
                        && !v6_failed_this_tick
                        && now_ms >= nh.v6_next_retry_ms;
                    if start_v4 {
                        snap.reconnect_attempts += 1;
                    }
                    if start_v6 {
                        snap.reconnect_attempts += 1;
                    }
                    let mut v4_snap_tmp = snap.wds_v4.clone();
                    let mut v6_snap_tmp = snap.wds_v6.clone();
                    let mut v4_warns = Vec::new();
                    let mut v6_warns = Vec::new();
                    let (v4_start_res, v6_start_res) = tokio::join!(
                        async {
                            if start_v4 {
                                Some(
                                    bring_up_native_family(
                                        b,
                                        &ind_tx,
                                        &cfg,
                                        4,
                                        "WDS_V4",
                                        &mut v4_snap_tmp,
                                        &mut v4_warns,
                                    )
                                    .await,
                                )
                            } else {
                                None
                            }
                        },
                        async {
                            if start_v6 {
                                Some(
                                    bring_up_native_family(
                                        b,
                                        &ind_tx,
                                        &cfg,
                                        6,
                                        "WDS_V6",
                                        &mut v6_snap_tmp,
                                        &mut v6_warns,
                                    )
                                    .await,
                                )
                            } else {
                                None
                            }
                        },
                    );
                    let after_ms = crate::state::mono_ms();
                    snap.warnings.extend(v4_warns);
                    snap.warnings.extend(v6_warns);

                    if cfg.ip_family.wants_v4() && nh.v4_client.is_none() && !v4_failed_this_tick {
                        if let Some(res) = v4_start_res {
                            snap.wds_v4 = v4_snap_tmp;
                            match res {
                                Ok((c, hdl, rt)) => {
                                    nh.v4_client = Some(c);
                                    nh.v4_handle = Some(hdl);
                                    nh.v4_backoff.reset();
                                    nh.v4_next_retry_ms = 0;
                                    nh.v4_last_error = None;
                                    NATIVE_WDS_V4_CONNECTED.store(true, Ordering::Release);
                                    v4_rt = Some(rt);
                                }
                                Err(e) => {
                                    NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                                    let d = nh.v4_backoff.next_delay();
                                    nh.v4_next_retry_ms = after_ms.saturating_add(d.as_millis() as u64);
                                    v4_retry_delay = Some(d);
                                    let msg = e.to_string();
                                    nh.v4_last_error = Some(msg.clone());
                                    snap.wds_v4.state = "backoff";
                                    snap.wds_v4.last_error = Some(msg);
                                }
                            }
                        } else {
                            NATIVE_WDS_V4_CONNECTED.store(false, Ordering::Release);
                            let rem_ms = nh.v4_next_retry_ms.saturating_sub(after_ms);
                            v4_retry_delay = Some(Duration::from_millis(rem_ms.max(1000)));
                            snap.wds_v4.state = "backoff";
                            snap.wds_v4.last_error = nh.v4_last_error.clone();
                        }
                    }

                    if cfg.ip_family.wants_v6() && nh.v6_client.is_none() && !v6_failed_this_tick {
                        if let Some(res) = v6_start_res {
                            snap.wds_v6 = v6_snap_tmp;
                            match res {
                                Ok((c, hdl, rt)) => {
                                    nh.v6_client = Some(c);
                                    nh.v6_handle = Some(hdl);
                                    nh.v6_backoff.reset();
                                    nh.v6_next_retry_ms = 0;
                                    nh.v6_last_error = None;
                                    NATIVE_WDS_V6_CONNECTED.store(true, Ordering::Release);
                                    v6_rt = Some(rt);
                                }
                                Err(e) => {
                                    NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                                    let d = nh.v6_backoff.next_delay();
                                    nh.v6_next_retry_ms = after_ms.saturating_add(d.as_millis() as u64);
                                    v6_retry_delay = Some(d);
                                    let msg = e.to_string();
                                    nh.v6_last_error = Some(msg.clone());
                                    snap.wds_v6.state = "backoff";
                                    snap.wds_v6.last_error = Some(msg);
                                }
                            }
                        } else {
                            NATIVE_WDS_V6_CONNECTED.store(false, Ordering::Release);
                            let rem_ms = nh.v6_next_retry_ms.saturating_sub(after_ms);
                            v6_retry_delay = Some(Duration::from_millis(rem_ms.max(1000)));
                            snap.wds_v6.state = "backoff";
                            snap.wds_v6.last_error = nh.v6_last_error.clone();
                        }
                    }

                    NATIVE_WDS_V4_CONNECTED.store(v4_rt.is_some(), Ordering::Release);
                    NATIVE_WDS_V6_CONNECTED.store(v6_rt.is_some(), Ordering::Release);
                    if v4_rt.is_none() && v6_rt.is_none() && cfg.manage_dns && nh.saved_resolv.is_some() {
                        nh.applied_dns.clear();
                        let _ = restore_native_dns(&mut nh.saved_resolv).await;
                        persist_native_handoff_state(&nh, &cfg, true);
                    }

                    let cur_sig = AppliedCfgSig::from(&cfg);
                    let v4_changed = v4_rt.as_ref().and_then(|r| r.ipv4_addr.clone()) != nh.last_v4_ip;
                    let v6_changed = ipv6_bearer_changed(v6_rt.as_ref(), nh.last_v6_key.as_ref());
                    let desired_mtu = resolve_dual_stack_link_mtu(
                        v4_rt.as_ref().and_then(|r| r.mtu),
                        v6_rt.as_ref().and_then(|r| r.mtu),
                    );
                    let mtu_changed = desired_mtu != nh.last_link_mtu;
                    let cfg_changed = nh.last_applied_sig.as_ref() != Some(&cur_sig);
                    let apply_v4 = cfg_changed || v4_changed;
                    let apply_v6 = cfg_changed || v6_changed;
                    if (apply_v4 || apply_v6 || mtu_changed) && (v4_rt.is_some() || v6_rt.is_some()) {
                        if cfg_changed && nh.last_applied_sig.is_some() {
                            teardown_ipa_and_dns(&mut nh, &cfg, !cfg.manage_dns, &mut snap.warnings).await;
                        } else if (apply_v4 || apply_v6)
                            && let Some(prev) = nh.last_applied_sig.as_ref().cloned()
                        {
                            let tear_iface = nh.last_resolved_iface.clone().unwrap_or_else(|| prev.iface.clone());
                            teardown_ipa_and_routes(
                                &mut nh,
                                &tear_iface,
                                &prev,
                                apply_v4,
                                apply_v6,
                                &mut snap.warnings,
                            )
                            .await;
                        }
                        match apply_native_netlink(
                            &cfg,
                            v4_rt.as_ref(),
                            v6_rt.as_ref(),
                            apply_v4,
                            apply_v6,
                            mtu_changed,
                        )
                        .await
                        {
                            Ok(applied) => {
                                let prev_v4_for_ct = nh.last_applied_v4_ip.clone();
                                let prev_v6_key_for_ct = nh.last_applied_v6_key.clone();
                                let prev_v6_ip_for_ct = nh.last_applied_v6_ip.clone();
                                snap.netlink_updates += 1;
                                let resolved_iface = applied.resolved_iface.clone();
                                nh.last_link_mtu = applied.link_mtu;
                                if apply_v4 {
                                    let new_v4 = applied.v4_ip.map(|ip| ip.to_string());
                                    nh.last_v4_ip = new_v4.clone();
                                    if new_v4.is_some() {
                                        nh.last_applied_v4_ip = new_v4;
                                    }
                                    nh.ippt_host_ip = applied.ippt_host_ip;
                                }
                                if apply_v6 {
                                    let new_v6_key = v6_rt.as_ref().and_then(ipv6_bearer_key);
                                    nh.last_v6_ip = applied.v6_addr_str.clone();
                                    nh.last_v6_key = new_v6_key.clone();
                                    if applied.v6_addr_str.is_some() {
                                        nh.last_applied_v6_ip = applied.v6_addr_str.clone();
                                    }
                                    if new_v6_key.is_some() {
                                        nh.last_applied_v6_key = new_v6_key;
                                    }
                                    nh.v6_dns_routes = applied.v6_dns;
                                }
                                nh.last_applied_sig = Some(cur_sig);
                                nh.last_resolved_iface = Some(resolved_iface.clone());

                                flush_stale_wan_conntrack_and_reload_odhcpd(
                                    prev_v4_for_ct.as_deref(),
                                    v4_changed && applied.v4_ip.is_some(),
                                    prev_v6_key_for_ct.as_ref(),
                                    prev_v6_ip_for_ct.as_deref(),
                                    v6_changed && applied.v6_addr_str.is_some(),
                                )
                                .await;

                                if cfg.kernel_tuning == KernelTuningProfile::HighThroughput {
                                    let tune_if = resolved_iface.clone();
                                    let warns = tokio::task::spawn_blocking(move || {
                                        apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some(&tune_if))
                                    })
                                    .await
                                    .unwrap_or_default();
                                    *h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()) = warns;
                                }

                                if apply_v4
                                    && cfg.ippt
                                    && let Some(mac) = cfg.ippt_mac.as_deref()
                                {
                                    let mut ipa_cfg = cfg.clone();
                                    ipa_cfg.iface = resolved_iface.clone();
                                    let args = build_ipa_ippass_enable_args(&ipa_cfg, mac);
                                    match run_ipa_cli(&args).await {
                                        Ok(true) => {
                                            nh.ipa_ippt_active = true;
                                            nh.ipa_ippt_mac = Some(mac.to_string());
                                        }
                                        Ok(false) => {
                                            snap.warnings.push("/usr/bin/ipa not found; hardware IPAv5 IPPT not programmed".into());
                                        }
                                        Err(e) => snap.warnings.push(e),
                                    }
                                    if let Some(v4_ip) = applied.v4_ip {
                                        let gw = v4_rt
                                            .as_ref()
                                            .and_then(|r| r.ipv4_gateway.as_deref())
                                            .and_then(|s| s.parse::<Ipv4Addr>().ok());
                                        match write_ippt_dnsmasq_conf(mac, v4_ip, gw).await {
                                            Ok(()) => nh.ippt_dnsmasq_active = true,
                                            Err(e) => snap.warnings.push(format!("IPPT dnsmasq config: {e}")),
                                        }
                                    }
                                } else if !cfg.ippt
                                    && (nh.ippt_dnsmasq_active
                                        || Path::new(&crate::paths::p(IPPT_DNSMASQ_CONF_PATH)).exists())
                                {
                                    if let Err(e) = remove_ippt_dnsmasq_conf().await {
                                        snap.warnings.push(e);
                                    }
                                    nh.ippt_dnsmasq_active = false;
                                }

                                if apply_v6
                                    && cfg.ipv6_prefix_sharing
                                    && let Some(v6_s) = applied.v6_addr_str.as_deref()
                                    && let Some(prefix64) = ipv6_upper64_prefix(v6_s)
                                {
                                    let args = build_ipa_v6_sharing_enable_args(&prefix64, &resolved_iface);
                                    match run_ipa_cli(&args).await {
                                        Ok(true) => nh.ipa_v6_sharing_prefix = Some(prefix64),
                                        Ok(false) => {}
                                        Err(e) => snap.warnings.push(e),
                                    }
                                }

                                if cfg.manage_dns {
                                    let dns = collect_runtime_dns(v4_rt.as_ref(), v6_rt.as_ref());
                                    if cfg_changed || dns != nh.applied_dns {
                                        match apply_native_dns(&mut nh.saved_resolv, &dns).await {
                                            Ok(true) => nh.applied_dns = dns,
                                            Ok(false) => {
                                                let _ = restore_native_dns(&mut nh.saved_resolv).await;
                                                nh.applied_dns.clear();
                                            }
                                            Err(e) => snap.warnings.push(format!("native DNS: {e}")),
                                        }
                                    }
                                }

                                let has_v4 = v4_rt.as_ref().and_then(|r| r.ipv4_addr.as_ref()).is_some();
                                let has_v6 = v6_rt.as_ref().and_then(|r| r.ipv6_addr.as_ref()).is_some();
                                // Keep the `forward` MSS clamp chain active even when `cfg.ippt == true`
                                // (only omit `postrouting masquerade` when `cfg.ippt && cfg.ippt_skip_nat`).
                                let want_masq = has_v4 && !(cfg.ippt && cfg.ippt_skip_nat);
                                if has_v4 || has_v6 {
                                    apply_native_nat(
                                        &mut nh,
                                        &resolved_iface,
                                        want_masq,
                                        applied.link_mtu,
                                        &mut snap.warnings,
                                    )
                                    .await;
                                }
                                persist_native_handoff_state(&nh, &cfg, true);
                                nh.netlink_backoff.reset();
                            }
                            Err(e) => {
                                netlink_err = true;
                                netlink_delay = Some(nh.netlink_backoff.next_delay());
                                snap.warnings.push(format!("native netlink config: {e}"));
                            }
                        }
                    } else if v4_rt.is_some() || v6_rt.is_some() {
                        nh.netlink_backoff.reset();
                        let forced_heal = FORCE_FW_HEAL.swap(false, Ordering::AcqRel);
                        // Self-heal firewall rules immediately on fw4 reload notification or ~every 60s.
                        if (forced_heal || native_tick.is_multiple_of(4))
                            && let Some(active_iface) = nh.last_resolved_iface.clone()
                        {
                            let has_v4 = v4_rt.as_ref().and_then(|r| r.ipv4_addr.as_ref()).is_some();
                            let want_masq = has_v4 && !(cfg.ippt && cfg.ippt_skip_nat);
                            let last_mtu = nh.last_link_mtu;
                            if heal_native_firewall_if_needed(
                                &mut nh,
                                &active_iface,
                                want_masq,
                                last_mtu,
                                &mut snap.warnings,
                            )
                            .await
                            {
                                state.push_daemon_log("dataplane: healed missing fw4/nft/iptables native rules");
                            }
                        }
                    }

                    let (healthy, sleep_dur, sup_state) = evaluate_native_bearer_health(
                        v4_rt.is_some(),
                        v6_rt.is_some(),
                        netlink_err,
                        v4_retry_delay,
                        v6_retry_delay,
                        netlink_delay,
                    );
                    if healthy {
                        let _ = NATIVE_CONNECTED_SINCE.compare_exchange(
                            0,
                            crate::state::mono_ms(),
                            Ordering::Release,
                            Ordering::Relaxed,
                        );
                    } else if v4_rt.is_none() && v6_rt.is_none() {
                        NATIVE_CONNECTED_SINCE.store(0, Ordering::Release);
                    }
                    next_sleep = sleep_dur;
                    snap.supervisor_state = sup_state;
                }
            }
        }

        // Self-heal drifted high-throughput sysctls (incl. late S98postboot.init cpu_gov/autosleep)
        // regardless of whether the cellular bearer is attached yet (~every 60s).
        let active_iface = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
        if cfg.kernel_tuning == KernelTuningProfile::HighThroughput && loop_tick.is_multiple_of(4) {
            let iface_chk = active_iface.clone();
            let healed = tokio::task::spawn_blocking(move || {
                if kernel_tuning_drifted(&iface_chk) {
                    Some(apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some(&iface_chk)))
                } else {
                    None
                }
            })
            .await
            .unwrap_or(None);
            if let Some(warns) = healed {
                *h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()) = warns;
                state.push_daemon_log("dataplane: healed drifted high-throughput sysctls");
            }
        }

        if cfg.sfe_fastpath && loop_tick.is_multiple_of(4) && !is_sfe_loaded() {
            snap.warnings.extend(
                reconcile_sfe_fastpath_with_guard(
                    true,
                    false,
                    cfg.preserve_ipa_offload,
                    cfg.ippt,
                )
                .await,
            );
        }

        snap.ipa_cli_present = Path::new(&crate::paths::p("/usr/bin/ipa")).exists();
        snap.sfe_loaded = is_sfe_loaded();
        snap.applied_dns = nh.applied_dns.clone();
        snap.active_ippt_mac = nh.ipa_ippt_mac.clone();
        snap.ipa_ippt_active = nh.ipa_ippt_active;
        snap.ipa_v6_sharing_prefix = nh.ipa_v6_sharing_prefix.clone();
        let tw = h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()).clone();
        snap.kernel = collect_kernel_telemetry_async(cfg.kernel_tuning, tw, Some(active_iface)).await;
        if cfg.preserve_ipa_offload && !snap.kernel.ipa_dev_present {
            snap.warnings.push("/dev/ipa device not present".into());
        }
        refresh_netlink_into(&mut snap, &cfg.iface).await;
        snap.qrtr = qrtr_telemetry_from(b.snapshot());
        let need_services = snap.qrtr.services.is_empty();
        *h.snapshot.write().await = snap;

        if h.shutdown_requested.load(Ordering::Acquire) {
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(next_sleep) => {}
            _ = h.wake.notified() => {}
            Some(ind) = ind_rx.recv() => {
                // Process first indication immediately (so WDS PDN drop strips stale rmnet state in <1 ms),
                // then debounce/coalesce any indication burst for 300 ms before running a full supervisor pass.
                apply_qmi_indication(&h, &mut nh, &cfg, ind).await;
                let burst = drain_coalesced_indications(&mut ind_rx, &h.wake, QMI_IND_DEBOUNCE_WINDOW).await;
                for extra in burst {
                    apply_qmi_indication(&h, &mut nh, &cfg, extra).await;
                }
            }
            ev = recv_bus_wakeup(bus_rx.as_mut(), Some(b.as_ref()), last_ssr_count, need_services) => {
                if let QrtrBusEvent::Ssr { node, reason } = ev {
                    let cur_ssr = b.snapshot().ssr_count;
                    if cur_ssr > last_ssr_count {
                        last_ssr_count = cur_ssr;
                        handle_modem_ssr(&state, &mut ph, &mut nh, node, last_ssr_count, &reason);
                        if cfg.mode == DataplaneMode::Native {
                            let flush_if = nh.last_resolved_iface.clone().unwrap_or_else(|| cfg.iface.clone());
                            let flush_tbl = nh.last_applied_sig.as_ref().map(|s| s.route_table).unwrap_or(cfg.route_table);
                            flush_rmnet_stale_state(flush_if, flush_tbl).await;
                        }
                        pending_phy_reenable = true;
                    }
                }
            }
        }
    }

    // Clean shutdown teardown when Native mode was active: stop WDS handles, strip stale
    // rules/addresses, restore vendor QCMAP/netmgrd, mwan3, DNS, and original pre-tuning sysctls.
    let cfg = h.config.read().await.clone();
    let was_native = cfg.mode == DataplaneMode::Native
        || NATIVE_MODE_ACTIVE.load(Ordering::Acquire)
        || nh.has_native_state()
        || nh.vendor_daemons_stopped
        || nh.mwan3_stopped;
    if was_native {
        state.push_daemon_log("dataplane: tearing down native mode cleanly on shutdown");
        teardown_native_handles(&state, &mut nh, &cfg).await;
        let iface_opt = Some(cfg.iface.clone());
        let _ = tokio::task::spawn_blocking(move || {
            apply_kernel_tuning(KernelTuningProfile::Default, iface_opt.as_deref())
        })
        .await;
        if nh.vendor_daemons_stopped || cfg.mode == DataplaneMode::Native {
            start_vendor_cm_daemons().await;
            nh.vendor_daemons_stopped = false;
        }
        if nh.mwan3_stopped {
            start_mwan3().await;
            nh.mwan3_stopped = false;
        }
        NATIVE_MODE_ACTIVE.store(false, Ordering::Release);
        clear_persisted_native_state();
    }
}

// ── REST Handlers ───────────────────────────────────────────────────────────

async fn get_status() -> Response {
    let h = hub();
    let cfg = h.config.read().await.clone();
    let mut snap = h.snapshot.read().await.clone();
    let tw = h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()).clone();
    snap.kernel = collect_kernel_telemetry_async(cfg.kernel_tuning, tw, Some(cfg.iface.clone())).await;
    snap.ipa_cli_present = Path::new(&crate::paths::p("/usr/bin/ipa")).exists();
    snap.sfe_loaded = is_sfe_loaded();
    Json(serde_json::json!({
        "status": "ok",
        "config": cfg,
        "snapshot": snap,
    }))
    .into_response()
}

pub fn validate_full_config(next: &DataplaneConfig) -> Result<(), String> {
    netlink::validate_managed_iface(next.iface.trim())?;
    if !(1..=254).contains(&next.mux_id) {
        return Err("muxId must be between 1 and 254".into());
    }
    if !(1..=16).contains(&next.ep_type) {
        return Err("epType must be between 1 and 16".into());
    }
    if !(1..=32).contains(&next.ep_iface_id) {
        return Err("epIfaceId must be between 1 and 32".into());
    }
    if !(1..=24).contains(&next.profile_index) {
        return Err("profileIndex must be between 1 and 24".into());
    }
    netlink::validate_managed_table(next.route_table)?;
    if let Some(mac) = next.ippt_mac.as_deref() {
        validate_unicast_mac(mac)?;
    }
    validate_ippt_dev_type(&next.ippt_dev_type)?;
    if next.ippt_vlan > 4094 {
        return Err("ipptVlan must be between 0 and 4094".into());
    }
    if next.mode == DataplaneMode::Native && next.ippt && next.ippt_mac.is_none() {
        return Err("ipptMac is required when enabling IP Passthrough in native mode".into());
    }
    Ok(())
}

pub async fn apply_config_from_backup(app: &AppState, mut next: DataplaneConfig) -> Result<(), String> {
    next.iface = next.iface.trim().to_string();
    if let Some(mac) = next.ippt_mac.take() {
        let m = mac.trim();
        if !m.is_empty() {
            next.ippt_mac = Some(validate_unicast_mac(m)?);
        }
    }
    next.ippt_dev_type = validate_ippt_dev_type(&next.ippt_dev_type)?;
    validate_full_config(&next)?;

    let h = hub();
    let prev = h.config.read().await.clone();
    save_config(&next).map_err(|e| format!("save dataplane config: {e}"))?;
    if next.kernel_tuning != prev.kernel_tuning || next.iface != prev.iface {
        let iface_s = next.iface.clone();
        let kt = next.kernel_tuning;
        let warns = tokio::task::spawn_blocking(move || apply_kernel_tuning(kt, Some(&iface_s)))
            .await
            .unwrap_or_default();
        *h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()) = warns;
    }
    if next.sfe_fastpath != prev.sfe_fastpath
        || (next.sfe_fastpath
            && (next.preserve_ipa_offload != prev.preserve_ipa_offload || next.ippt != prev.ippt))
    {
        let _ = reconcile_sfe_fastpath_with_guard(
            next.sfe_fastpath,
            !next.sfe_fastpath,
            next.preserve_ipa_offload,
            next.ippt,
        )
        .await;
    }
    *h.config.write().await = next.clone();
    if next.mode == DataplaneMode::Native {
        NATIVE_MODE_ACTIVE.store(true, Ordering::Relaxed);
    }
    h.wake.notify_one();
    app.push_daemon_log(format!(
        "dataplane: config restored (mode={}, iface={}, profile={}, tuning={})",
        next.mode.as_str(),
        next.iface,
        next.profile_index,
        next.kernel_tuning.as_str(),
    ));
    Ok(())
}

async fn get_profiles() -> Response {
    let h = hub();
    let snap = h.snapshot.read().await;
    Json(serde_json::json!({
        "status": "ok",
        "source": snap.profiles_source,
        "profiles": snap.profiles,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigReq {
    #[serde(default)]
    pub mode: Option<DataplaneMode>,
    #[serde(default)]
    pub iface: Option<String>,
    #[serde(default)]
    pub mux_id: Option<u8>,
    #[serde(default)]
    pub ep_type: Option<u32>,
    #[serde(default)]
    pub ep_iface_id: Option<u32>,
    #[serde(default)]
    pub profile_index: Option<u8>,
    #[serde(default)]
    pub ip_family: Option<IpFamily>,
    #[serde(default)]
    pub route_table: Option<u32>,
    #[serde(default)]
    pub ippt: Option<bool>,
    #[serde(default)]
    pub ippt_mac: Option<String>,
    #[serde(default)]
    pub ippt_dev_type: Option<String>,
    #[serde(default)]
    pub ippt_skip_nat: Option<bool>,
    #[serde(default)]
    pub ippt_vlan: Option<u16>,
    #[serde(default)]
    pub manage_dns: Option<bool>,
    #[serde(default)]
    pub ipv6_prefix_sharing: Option<bool>,
    #[serde(default)]
    pub preserve_ipa_offload: Option<bool>,
    #[serde(default)]
    pub kernel_tuning: Option<KernelTuningProfile>,
    #[serde(default)]
    pub sfe_fastpath: Option<bool>,
    #[serde(default)]
    pub confirm: Option<String>,
}

async fn post_config(
    State(ctx): State<HttpCtx>,
    Json(req): Json<ConfigReq>,
) -> Response {
    let h = hub();
    let prev = h.config.read().await.clone();
    let mut next = prev.clone();
    let iface_updated = req.iface.is_some();
    let explicit_mux = req.mux_id.is_some();

    if let Some(m) = req.mode {
        next.mode = m;
    }
    if let Some(iface) = req.iface {
        let iface = iface.trim().to_string();
        if let Err(e) = netlink::validate_managed_iface(&iface) {
            return bad(e);
        }
        next.iface = iface;
    }
    if let Some(mux) = req.mux_id {
        if !(1..=254).contains(&mux) {
            return bad("muxId must be between 1 and 254");
        }
        next.mux_id = mux;
    }
    if iface_updated && !explicit_mux {
        let links = h.snapshot.read().await.links.clone();
        if let Some(link) = netlink::resolve_rmnet_link(&links, &next.iface, next.mux_id)
            && let Some(m) = link.rmnet_mux_id
            && (1..=254).contains(&m)
        {
            next.mux_id = m as u8;
        }
    }
    if let Some(ept) = req.ep_type {
        if !(1..=16).contains(&ept) {
            return bad("epType must be between 1 and 16");
        }
        next.ep_type = ept;
    }
    if let Some(epi) = req.ep_iface_id {
        if !(1..=32).contains(&epi) {
            return bad("epIfaceId must be between 1 and 32");
        }
        next.ep_iface_id = epi;
    }
    if let Some(pidx) = req.profile_index {
        if !(1..=24).contains(&pidx) {
            return bad("profileIndex must be between 1 and 24");
        }
        next.profile_index = pidx;
    }
    if let Some(fam) = req.ip_family {
        next.ip_family = fam;
    }
    if let Some(tbl) = req.route_table {
        if let Err(e) = netlink::validate_managed_table(tbl) {
            return bad(e);
        }
        next.route_table = tbl;
    }
    if let Some(ippt) = req.ippt {
        next.ippt = ippt;
    }
    if let Some(ref mac) = req.ippt_mac {
        if mac.trim().is_empty() {
            next.ippt_mac = None;
        } else {
            match validate_unicast_mac(mac) {
                Ok(norm) => next.ippt_mac = Some(norm),
                Err(e) => return bad(e),
            }
        }
    }
    if let Some(ref dt) = req.ippt_dev_type {
        match validate_ippt_dev_type(dt) {
            Ok(norm) => next.ippt_dev_type = norm,
            Err(e) => return bad(e),
        }
    }
    if let Some(sn) = req.ippt_skip_nat {
        next.ippt_skip_nat = sn;
    }
    if let Some(vlan) = req.ippt_vlan {
        if vlan > 4094 {
            return bad("ipptVlan must be between 0 and 4094");
        }
        next.ippt_vlan = vlan;
    }
    if let Some(md) = req.manage_dns {
        next.manage_dns = md;
    }
    if let Some(v6s) = req.ipv6_prefix_sharing {
        next.ipv6_prefix_sharing = v6s;
    }
    if let Some(ipa) = req.preserve_ipa_offload {
        next.preserve_ipa_offload = ipa;
    }
    if let Some(kt) = req.kernel_tuning {
        next.kernel_tuning = kt;
    }
    if let Some(sfe) = req.sfe_fastpath {
        next.sfe_fastpath = sfe;
    }

    if next.mode == DataplaneMode::Native && next.ippt && next.ippt_mac.is_none() {
        return bad("ipptMac is required when enabling IP Passthrough in native mode");
    }

    if next.mode == DataplaneMode::Native && prev.mode != DataplaneMode::Native
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            CONFIRM_NATIVE,
            "Switching to native Rust QMI + Netlink mode stops QCMAP/netmgrd and takes direct control of the cellular data bearer while keeping IPA offload enabled.",
        )
    {
        return r;
    }

    if let Err(e) = save_config(&next) {
        return server(format!("save dataplane config: {e}"));
    }
    if next.kernel_tuning != prev.kernel_tuning || (next.iface != prev.iface && next.kernel_tuning == KernelTuningProfile::HighThroughput) {
        let iface_s = next.iface.clone();
        let kt = next.kernel_tuning;
        let warns = tokio::task::spawn_blocking(move || apply_kernel_tuning(kt, Some(&iface_s)))
            .await
            .unwrap_or_default();
        *h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()) = warns;
    }
    let sfe_warns = if next.sfe_fastpath != prev.sfe_fastpath
        || (next.sfe_fastpath
            && (next.preserve_ipa_offload != prev.preserve_ipa_offload || next.ippt != prev.ippt))
    {
        reconcile_sfe_fastpath_with_guard(
            next.sfe_fastpath,
            !next.sfe_fastpath,
            next.preserve_ipa_offload,
            next.ippt,
        )
        .await
    } else {
        Vec::new()
    };
    *h.config.write().await = next.clone();
    if next.mode == DataplaneMode::Native {
        NATIVE_MODE_ACTIVE.store(true, Ordering::Relaxed);
    }
    h.wake.notify_one();

    ctx.app.push_daemon_log(format!(
        "dataplane: config updated (mode={}, iface={}, profile={}, tuning={}, sfe={})",
        next.mode.as_str(),
        next.iface,
        next.profile_index,
        next.kernel_tuning.as_str(),
        next.sfe_fastpath,
    ));
    ctx.app.audit.event(
        "dataplane",
        "config",
        format!(
            "mode={} iface={} profile={} tuning={} sfe={}",
            next.mode.as_str(),
            next.iface,
            next.profile_index,
            next.kernel_tuning.as_str(),
            next.sfe_fastpath,
        ),
    );

    let mut snap = h.snapshot.read().await.clone();
    snap.warnings.extend(sfe_warns);
    let tw = h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()).clone();
    snap.kernel = collect_kernel_telemetry_async(next.kernel_tuning, tw, Some(next.iface.clone())).await;
    snap.ipa_cli_present = Path::new(&crate::paths::p("/usr/bin/ipa")).exists();
    snap.sfe_loaded = is_sfe_loaded();
    Json(serde_json::json!({
        "status": "ok",
        "config": next,
        "snapshot": snap,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconnectReq {
    #[serde(default)]
    pub family: Option<String>,
}

async fn post_reconnect(
    State(ctx): State<HttpCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req: ReconnectReq = match crate::vpn::parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let family = req.family.as_deref().unwrap_or("all").trim();
    if !matches!(family, "all" | "ipv4" | "ipv6") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "family must be one of: all, ipv4, ipv6",
            })),
        )
            .into_response();
    }

    let h = hub();
    *h.reconnect_queue.lock().unwrap_or_else(|e| e.into_inner()) = Some(family.to_string());
    h.wake.notify_one();
    let mode = h.config.read().await.mode;
    ctx.app.audit.event(
        "dataplane",
        "reconnect",
        format!("mode={} family={family}", mode.as_str()),
    );
    Json(serde_json::json!({
        "status": "ok",
        "mode": mode,
        "family": family,
        "triggered": true,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::ConnectInfo, http::{Method, Request, header}};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    #[test]
    fn reconnect_backoff_follows_exact_schedule() {
        let mut b = ReconnectBackoff::new();
        assert_eq!(b.next_delay(), Duration::from_secs(5));
        assert_eq!(b.next_delay(), Duration::from_secs(10));
        assert_eq!(b.next_delay(), Duration::from_secs(20));
        assert_eq!(b.next_delay(), Duration::from_secs(40));
        assert_eq!(b.next_delay(), Duration::from_secs(60));
        assert_eq!(b.next_delay(), Duration::from_secs(60));
        b.reset();
        assert_eq!(b.current_step(), 0);
        assert_eq!(b.next_delay(), Duration::from_secs(5));
    }

    #[test]
    fn parses_ipa_eth_driver_and_ioss_statistics() {
        let status = "       protocol|  instance|  pipe_hdl|                     pipe_enum|   pipe_id|     ch_id\n       RTK8125B|         0|         0|  IPA_CLIENT_RTK_ETHERNET_PROD|         8|        17\n";
        assert_eq!(parse_ipa_eth_driver(status).as_deref(), Some("RTK8125B"));
        assert_eq!(parse_ipa_eth_driver(""), None);

        let stats = "hwp_rx_packets: 1000\nhwp_tx_packets: 500\nexp_rx_packets: 50\nexp_tx_packets: 10\n";
        assert_eq!(parse_ioss_statistics(stats), (Some(1000), Some(50), Some(500), Some(10)));
    }

    #[test]
    fn kernel_tuning_is_reversible_in_sandbox() {
        let sbx = crate::paths::TestSandbox::new("dp_tuning");
        for (rel, baseline) in [
            ("/proc/sys/net/core/default_qdisc", "pfifo_fast\n"),
            ("/proc/sys/net/core/rmem_max", "229376\n"),
            ("/proc/sys/net/core/wmem_max", "229376\n"),
            ("/proc/sys/net/core/netdev_max_backlog", "1000\n"),
            ("/proc/sys/net/core/netdev_budget", "300\n"),
            ("/proc/sys/net/core/netdev_budget_usecs", "2000\n"),
            ("/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n"),
            ("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n"),
            ("/proc/sys/net/ipv4/tcp_fastopen", "1\n"),
            ("/proc/sys/net/ipv4/tcp_notsent_lowat", "4294967295\n"),
            ("/proc/sys/net/netfilter/nf_conntrack_max", "32768\n"),
            ("/proc/sys/net/netfilter/nf_conntrack_count", "25\n"),
            ("/sys/module/nf_conntrack/parameters/hashsize", "8192\n"),
            ("/sys/class/net/eth0/queues/rx-0/rps_cpus", "0\n"),
            ("/sys/class/net/eth0/queues/tx-0/xps_cpus", "0\n"),
            ("/sys/class/net/rmnet_ipa0/gro_flush_timeout", "0\n"),
            ("/sys/class/net/rmnet_ipa0/napi_defer_hard_irqs", "0\n"),
            ("/sys/class/net/rmnet_ipa0/queues/rx-0/rps_cpus", "8\n"),
            ("/sys/class/net/rmnet_ipa0/queues/rx-0/rps_flow_cnt", "0\n"),
            ("/sys/class/net/rmnet_ipa0/queues/tx-0/xps_cpus", "0\n"),
            ("/sys/class/net/rmnet_ipa0/queues/tx-1/xps_cpus", "0\n"),
            ("/sys/class/net/rmnet_ipa0/queues/tx-2/xps_cpus", "0\n"),
            ("/sys/class/net/rmnet_ipa0/queues/tx-3/xps_cpus", "0\n"),
            ("/sys/class/net/rmnet_data1/queues/rx-0/rps_cpus", "0\n"),
            ("/sys/class/net/rmnet_data1/queues/rx-0/rps_flow_cnt", "0\n"),
            ("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "schedutil\n"),
            ("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "1516800\n"),
            ("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "2208000\n"),
            ("/sys/kernel/debug/ipa/hw_type", "25\n"),
            ("/sys/kernel/debug/ipa/clk_rate", "120000000\n"),
            ("/sys/kernel/debug/ipa/enable_clock_scaling", "1\n"),
            ("/sys/kernel/debug/ipa/clock_scaling_bw_threshold_nominal_mbps", "600\n"),
            ("/sys/kernel/debug/ipa/clock_scaling_bw_threshold_turbo_mbps", "1000\n"),
            ("/sys/kernel/debug/ipa/enable_napi_chain", "1\n"),
            ("/sys/kernel/debug/ipa/eth/status", "protocol|instance\nRTK8125B|0\n"),
            ("/sys/kernel/debug/ioss/devices/eth0/statistics", "hwp_rx_packets: 1000\nexp_rx_packets: 50\nhwp_tx_packets: 500\nexp_tx_packets: 10\n"),
        ] {
            let p = sbx.root.join(rel.trim_start_matches('/'));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, baseline).unwrap();
        }
        let dev_ipa = sbx.root.join("dev/ipa");
        fs::create_dir_all(dev_ipa.parent().unwrap()).unwrap();
        fs::write(&dev_ipa, b"").unwrap();

        let w = apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some("rmnet_data1"));
        assert!(w.is_empty(), "{w:?}");
        let k = collect_kernel_telemetry(KernelTuningProfile::HighThroughput, Vec::new(), Some("rmnet_data1"));
        assert_eq!(k.default_qdisc, "fq_codel");
        assert_eq!(k.rmem_max, Some(16_777_216));
        assert_eq!(k.wmem_max, Some(16_777_216));
        assert_eq!(k.netdev_max_backlog, Some(16_384));
        assert_eq!(k.netdev_budget, Some(1_200));
        assert_eq!(k.netdev_budget_usecs, Some(8_000));
        assert_eq!(k.tcp_fastopen, Some(3));
        assert_eq!(k.tcp_notsent_lowat, Some(131_072));
        assert_eq!(k.conntrack_max, Some(65536));
        assert_eq!(k.conntrack_count, Some(25));
        assert_eq!(k.conntrack_hashsize, Some(16384));
        assert_eq!(k.cpu_governor.as_deref(), Some("performance"));
        assert_eq!(k.cpu_cur_freq_mhz, Some(1516));
        assert_eq!(k.cpu_max_freq_mhz, Some(2208));
        assert_eq!(k.rps_maps.get("eth0:rx-0/rps_cpus").map(String::as_str), Some("c"));
        assert_eq!(k.rps_maps.get("rmnet_data1:rx-0/rps_cpus").map(String::as_str), Some("c"));
        assert_eq!(k.rps_maps.get("rmnet_data1:rx-0/rps_flow_cnt").map(String::as_str), Some("4096"));
        assert_eq!(k.xps_maps.get("rmnet_ipa0:tx-0/xps_cpus").map(String::as_str), Some("4"));
        assert_eq!(k.xps_maps.get("rmnet_ipa0:tx-1/xps_cpus").map(String::as_str), Some("8"));
        assert_eq!(k.xps_maps.get("rmnet_ipa0:tx-2/xps_cpus").map(String::as_str), Some("4"));
        assert_eq!(k.xps_maps.get("rmnet_ipa0:tx-3/xps_cpus").map(String::as_str), Some("8"));
        assert_eq!(read_trimmed("/sys/class/net/rmnet_ipa0/gro_flush_timeout").as_deref(), Some("20000"));
        assert_eq!(read_trimmed("/sys/class/net/rmnet_ipa0/napi_defer_hard_irqs").as_deref(), Some("2"));
        assert_eq!(k.rps_maps.get("rmnet_ipa0:rx-0/rps_flow_cnt").map(String::as_str), Some("4096"));
        assert_eq!(k.ipa_offload.hw_type.as_deref(), Some("25"));
        assert_eq!(k.ipa_offload.clk_rate_mhz, Some(120));
        assert_eq!(k.ipa_offload.nominal_mbps, Some(100));
        assert_eq!(k.ipa_offload.turbo_mbps, Some(300));
        assert_eq!(k.ipa_offload.eth_offload_driver.as_deref(), Some("RTK8125B"));
        assert_eq!(k.ipa_offload.eth_hardware_offload_pct, Some(95));
        assert!(k.ipa_dev_present);

        let w2 = apply_kernel_tuning(KernelTuningProfile::Default, Some("rmnet_data1"));
        assert!(w2.is_empty(), "{w2:?}");
        let k2 = collect_kernel_telemetry(KernelTuningProfile::Default, Vec::new(), Some("rmnet_data1"));
        assert_eq!(k2.default_qdisc, "pfifo_fast");
        assert_eq!(k2.rmem_max, Some(229_376));
        assert_eq!(k2.netdev_max_backlog, Some(1_000));
        assert_eq!(k2.netdev_budget, Some(300));
        assert_eq!(k2.netdev_budget_usecs, Some(2_000));
        assert_eq!(k2.tcp_fastopen, Some(1));
        assert_eq!(k2.conntrack_max, Some(32768));
        assert_eq!(k2.conntrack_hashsize, Some(8192));
        assert_eq!(k2.cpu_governor.as_deref(), Some("schedutil"));
        assert_eq!(k2.rps_maps.get("eth0:rx-0/rps_cpus").map(String::as_str), Some("0"));
        assert_eq!(k2.rps_maps.get("rmnet_data1:rx-0/rps_cpus").map(String::as_str), Some("0"));
        assert_eq!(k2.xps_maps.get("rmnet_ipa0:tx-0/xps_cpus").map(String::as_str), Some("0"));
        assert_eq!(k2.rps_maps.get("rmnet_ipa0:rx-0/rps_flow_cnt").map(String::as_str), Some("0"));
        assert_eq!(k2.ipa_offload.nominal_mbps, Some(600));
        assert_eq!(k2.ipa_offload.turbo_mbps, Some(1000));
    }

    async fn call_router(
        router: &Router,
        auth_hdr: &str,
        method: Method,
        path: &str,
        ct: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "192.168.228.1")
            .header("authorization", auth_hdr);
        if let Some(c) = ct {
            b = b.header(header::CONTENT_TYPE, c);
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 228, 50], 40000))));
        let resp = router.clone().oneshot(req).await.unwrap();
        let st = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (st, json)
    }

    #[tokio::test]
    async fn dataplane_routes_enforce_validation_confirm_and_rbac() {
        let sbx = crate::paths::TestSandbox::new("dp_api");
        let www = sbx.root.join("www");
        fs::create_dir_all(&www).unwrap();
        let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
        let app = AppState::for_tests(www, auth);
        let (_, rw_tok) = app.tokens.create("ops", crate::tokens::TokenKind::Rw, None).unwrap();
        let (_, rd_tok) = app.tokens.create("mon", crate::tokens::TokenKind::Read, None).unwrap();
        let rw = format!("Bearer {rw_tok}");
        let rd = format!("Bearer {rd_tok}");

        let router = crate::http::build_router(crate::http::HttpCtx {
            app,
            proxy: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http(),
            enforce_uhttpd_loopback: true,
        });

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let (s, v) = call_router(&router, &rd, Method::GET, "/api/v1/dataplane/status", None, "").await;
                assert_eq!(s, StatusCode::OK, "{v}");
                assert_eq!(v["config"]["mode"], "coexist");
                assert!(v["snapshot"]["ipaCliPresent"].is_boolean());
                assert!(v["snapshot"]["appliedDns"].is_array());

                // `/api/v1/dataplane/profiles` is in READ_DENY (exposes carrier APN profiles)
                let (s, _) = call_router(&router, &rd, Method::GET, "/api/v1/dataplane/profiles", None, "").await;
                assert_eq!(s, StatusCode::FORBIDDEN);
                let (s, _) = call_router(&router, &rw, Method::GET, "/api/v1/dataplane/profiles", None, "").await;
                assert_eq!(s, StatusCode::OK);

                // read token cannot mutate
                let (s, _) = call_router(&router, &rd, Method::POST, "/api/v1/dataplane/reconnect", Some("application/json"), "{}").await;
                assert_eq!(s, StatusCode::FORBIDDEN);

                // native requires confirm: "NATIVE" -> 428
                let (s, v) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/config", Some("application/json"), r#"{"mode":"native"}"#).await;
                assert_eq!(s, StatusCode::PRECONDITION_REQUIRED, "{v}");
                assert_eq!(v["confirm"], CONFIRM_NATIVE);

                // protected interfaces/tables refused with 400
                let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/config", Some("application/json"), r#"{"iface":"br-lan"}"#).await;
                assert_eq!(s, StatusCode::BAD_REQUEST);
                let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/config", Some("application/json"), r#"{"routeTable":51820}"#).await;
                assert_eq!(s, StatusCode::BAD_REQUEST);
                // unknown field refused with 422/400
                let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/config", Some("application/json"), r#"{"bogus":1}"#).await;
                assert!(s.is_client_error(), "{s}");
                // invalid ipptMac / ipptDevType refused with 400
                for bad_json in [
                    r#"{"ipptMac":"not-a-mac"}"#,
                    r#"{"ipptMac":"ff:ff:ff:ff:ff:ff"}"#,
                    r#"{"ipptMac":"01:00:5e:00:00:01"}"#,
                    r#"{"ipptDevType":"wlan9"}"#,
                    r#"{"mode":"native","confirm":"NATIVE","ippt":true}"#,
                ] {
                    let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/config", Some("application/json"), bad_json).await;
                    assert_eq!(s, StatusCode::BAD_REQUEST, "{bad_json}");
                }
                let (s, v) = call_router(
                    &router,
                    &rw,
                    Method::POST,
                    "/api/v1/dataplane/config",
                    Some("application/json"),
                    r#"{"ipptMac":"AA:BB:CC:DD:EE:FF","ipptDevType":"ETH1"}"#,
                )
                .await;
                assert_eq!(s, StatusCode::OK, "{v}");
                assert_eq!(v["config"]["ipptMac"], "aa:bb:cc:dd:ee:ff");
                assert_eq!(v["config"]["ipptDevType"], "eth1");
                assert!(v["snapshot"]["ipaCliPresent"].is_boolean());
                assert!(v["snapshot"]["appliedDns"].is_array());

                // reconnect optional JSON probes: wrong CT -> 415, bad json -> 400, bad family -> 400, empty -> 200
                let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/reconnect", Some("text/plain"), "{}").await;
                assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
                let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/reconnect", Some("application/json"), "{").await;
                assert_eq!(s, StatusCode::BAD_REQUEST);
                let (s, _) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/reconnect", Some("application/json"), r#"{"family":"gre"}"#).await;
                assert_eq!(s, StatusCode::BAD_REQUEST);
                let (s, v) = call_router(&router, &rw, Method::POST, "/api/v1/dataplane/reconnect", None, "").await;
                assert_eq!(s, StatusCode::OK, "{v}");
                assert_eq!(v["triggered"], true);
            })
            .await;
    }

    #[test]
    fn bus_event_should_wake_gates_startup_services_and_forwards_ssr() {
        let added = QrtrBusEvent::ServiceAdded(ServiceEndpoint {
            service: SVC_WDS,
            name: "WDS".into(),
            version: 1,
            instance: 0,
            node: 0,
            port: 79,
        });
        let removed = QrtrBusEvent::ServiceRemoved {
            service: SVC_WDS,
            node: 0,
            port: 79,
        };
        let ssr = QrtrBusEvent::Ssr {
            node: 0,
            reason: "bye".into(),
        };
        assert!(bus_event_should_wake(&added, true));
        assert!(!bus_event_should_wake(&added, false));
        assert!(!bus_event_should_wake(&removed, true));
        assert!(!bus_event_should_wake(&removed, false));
        assert!(bus_event_should_wake(&ssr, true));
        assert!(bus_event_should_wake(&ssr, false));
    }

    #[test]
    fn validates_mac_dev_type_prefix_and_ipa_argv() {
        assert_eq!(validate_unicast_mac("AA:BB:CC:DD:EE:FF").unwrap(), "aa:bb:cc:dd:ee:ff");
        for bad in ["", "aa:bb:cc", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "zz:00:00:00:00:01"] {
            assert!(validate_unicast_mac(bad).is_err(), "{bad}");
        }

        assert_eq!(validate_ippt_dev_type("ETH0").unwrap(), "eth0");
        assert!(validate_ippt_dev_type("wlan9").is_err());

        assert_eq!(
            ipv6_upper64_prefix("2607:fb90:1234:5678::1").as_deref(),
            Some("2607:fb90:1234:5678")
        );
        assert_eq!(ipv6_upper64_prefix("2001:db8:a:b:1::2").as_deref(), Some("2001:0db8:000a:000b"));
        assert_eq!(ipv6_upper64_prefix("fe80::1"), None);
        assert_eq!(ipv6_upper64_prefix("::1"), None);

        let cfg = DataplaneConfig {
            iface: "rmnet_data1".into(),
            ippt_dev_type: "eth0".into(),
            ippt_skip_nat: true,
            ippt_vlan: 0,
            ..Default::default()
        };
        assert_eq!(
            build_ipa_ippass_enable_args(&cfg, "aa:bb:cc:dd:ee:ff"),
            vec![
                "ippass", "enable", "dev_type", "eth0", "vlan", "0", "mac", "aa:bb:cc:dd:ee:ff",
                "skip_nat", "1", "default_pdn", "1", "dev_name", "rmnet_data1"
            ]
        );
        assert_eq!(
            build_ipa_ippass_disable_args(&cfg.ippt_dev_type, cfg.ippt_vlan, &cfg.iface),
            vec!["ippass", "disable", "dev_type", "eth0", "vlan", "0", "dev_name", "rmnet_data1"]
        );
        assert_eq!(
            build_ipa_v6_sharing_enable_args("2607:fb90:1234:5678", "rmnet_data1"),
            vec![
                "idu_ipv6_config", "sharing", "ipv6_prefix", "2607:fb90:1234:5678",
                "ipv6_mask", "ffff:ffff:ffff:ffff", "pdn_name", "rmnet_data1"
            ]
        );
        assert_eq!(
            build_ipa_v6_sharing_disable_args("rmnet_data1"),
            vec!["idu_ipv6_config", "disable", "ipv6_prefix", "0", "ipv6_mask", "0", "pdn_name", "rmnet_data1"]
        );
    }

    #[tokio::test]
    async fn native_dns_apply_and_restore_roundtrip_in_sandbox() {
        let sbx = crate::paths::TestSandbox::new("dp_dns");
        let auto = sbx.root.join("tmp/resolv.conf.d/resolv.conf.auto");
        fs::create_dir_all(auto.parent().unwrap()).unwrap();
        fs::write(&auto, b"nameserver 1.1.1.1\n").unwrap();

        let v4 = WdsRuntimeSettings {
            ipv4_dns1: Some("192.0.0.30".into()),
            ..Default::default()
        };
        let v6 = WdsRuntimeSettings {
            ipv6_dns1: Some("fd00:976a::9".into()),
            ipv6_dns2: Some("fd00:976a::10".into()),
            ..Default::default()
        };
        let dns = collect_runtime_dns(Some(&v4), Some(&v6));
        assert_eq!(dns, vec!["192.0.0.30", "fd00:976a::9", "fd00:976a::10"]);

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let mut saved = None;
                let applied = apply_native_dns(&mut saved, &dns).await.unwrap();
                assert!(applied);
                let lan = sbx.root.join("tmp/resolv.conf.d/resolv.conf.lan.auto");
                let text = fs::read_to_string(&auto).unwrap();
                assert!(text.contains("nameserver 192.0.0.30\n"));
                assert!(text.contains("nameserver fd00:976a::9\n"));
                assert!(text.contains("nameserver fd00:976a::10\n"));
                assert_eq!(fs::read_to_string(&lan).unwrap(), text);

                restore_native_dns(&mut saved).await.unwrap();
                assert_eq!(fs::read_to_string(&auto).unwrap(), "nameserver 1.1.1.1\n");
                assert!(!lan.exists());
            })
            .await;
    }

    #[test]
    fn native_nat_helpers_parse_fw4_iptables_and_build_valid_nft_script() {
        let fw4_single = "chain srcnat {\n\t\toifname \"rmnet_data1\" jump srcnat_wan\n\t}\n";
        let fw4_set = "chain srcnat {\n\t\toifname { \"rmnet_data0\", \"rmnet_data1\" } jump srcnat_wan\n\t}\n";
        assert!(fw4_chain_covers_iface(fw4_single, "rmnet_data1"));
        assert!(!fw4_chain_covers_iface(fw4_single, "rmnet_data0"));
        assert!(fw4_chain_covers_iface(fw4_set, "rmnet_data0"));
        assert!(fw4_chain_covers_iface(fw4_set, "rmnet_data1"));
        assert!(!fw4_chain_covers_iface("chain srcnat {\n\t}\n", "rmnet_data1"));

        let script = build_native_nat_nft_script("rmnet_data1", true, 1500).unwrap();
        assert!(script.contains("table inet qm_native_nat"));
        assert!(script.contains("oifname \"rmnet_data1\" meta nfproto ipv4 masquerade"));
        assert!(script.contains("oifname \"rmnet_data1\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"));
        assert!(script.contains("iifname \"rmnet_data1\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size > 1460 tcp option maxseg size set 1460"));
        assert!(script.contains("iifname \"rmnet_data1\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size > 1440 tcp option maxseg size set 1440"));

        // IPPT with skip_nat=true + T-Mobile 1428 MTU: keeps symmetric v4/v6 MSS clamping active with `> {mss}` guard so smaller VPN SYNs are never clamped upward!
        let ippt_mss = build_native_nat_nft_script("rmnet_data1", false, 1428).unwrap();
        assert!(!ippt_mss.contains("masquerade"));
        assert!(ippt_mss.contains("oifname \"rmnet_data1\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size > 1388 tcp option maxseg size set 1388"));
        assert!(ippt_mss.contains("iifname \"rmnet_data1\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size > 1388 tcp option maxseg size set 1388"));
        assert!(ippt_mss.contains("oifname \"rmnet_data1\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size > 1368 tcp option maxseg size set 1368"));
        assert!(ippt_mss.contains("iifname \"rmnet_data1\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size > 1368 tcp option maxseg size set 1368"));

        assert!(build_native_nat_nft_script("eth0", true, 1500).is_err());
        assert!(build_native_nat_nft_script("br-lan", true, 1500).is_err());
        assert!(build_native_nat_nft_script("rmnet_data0\nflush ruleset", true, 1500).is_err());

        // Dual-stack WDS MTU `.min()` across reported non-zero mtu4/mtu6
        assert_eq!(resolve_dual_stack_link_mtu(Some(1428), Some(1440)), 1428);
        assert_eq!(resolve_dual_stack_link_mtu(Some(1500), Some(1420)), 1420);
        assert_eq!(resolve_dual_stack_link_mtu(Some(0), Some(1430)), 1430);
        assert_eq!(resolve_dual_stack_link_mtu(None, Some(1428)), 1428);
        assert_eq!(resolve_dual_stack_link_mtu(None, None), 1500);
        assert_eq!(resolve_dual_stack_link_mtu(Some(0), Some(0)), 1500);

        let chain_with_handles = concat!(
            "table inet fw4 {\n",
            "\tchain accept_to_wan {\n",
            "\t\toifname \"rmnet_data0\" counter packets 10 bytes 1000 accept # handle 14\n",
            "\t\toifname \"rmnet_data1\" counter packets 0 bytes 0 accept comment \"qm_native\" # handle 77\n",
            "\t\toifname \"rmnet_data2\" counter accept comment \"qm_native\" # handle 88\n",
            "\t}\n",
            "}\n",
        );
        assert_eq!(extract_qm_native_nft_handles(chain_with_handles), vec![77, 88]);

        let ipt_nat = "-A POSTROUTING -o rmnet_data10 -j MASQUERADE\n-A POSTROUTING -o rmnet_data1 -m comment --comment qm_native -j MASQUERADE\n";
        assert!(ipt_oif_covers_iface(ipt_nat, "rmnet_data1"));
        assert!(!ipt_oif_covers_iface("-A POSTROUTING -o rmnet_data10 -j MASQUERADE\n", "rmnet_data1"));

        // ipt_rules_cover_iface must require `-j TCPMSS` on both `-o` and `-i` (ignoring TTL/HL rules).
        let ttl_only = "-A FORWARD -o rmnet_data1 -j TTL --ttl-set 65\n-A FORWARD -i rmnet_data1 -j TTL --ttl-set 65\n";
        assert!(!ipt_rules_cover_iface(ttl_only, "rmnet_data1"));
        let out_only = "-A FORWARD -o rmnet_data1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1388\n";
        assert!(!ipt_rules_cover_iface(out_only, "rmnet_data1"));
        assert!(ipt_tcpmss_covers_dir(out_only, "-o", "rmnet_data1"));
        assert!(!ipt_tcpmss_covers_dir(out_only, "-i", "rmnet_data1"));
        let both_dirs = concat!(
            "-A FORWARD -o rmnet_data1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1388\n",
            "-A FORWARD -i rmnet_data1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1388\n",
        );
        assert!(ipt_rules_cover_iface(both_dirs, "rmnet_data1"));
        assert!(!ipt_rules_cover_iface(both_dirs, "rmnet_data0"));

        let mut nh = NativeHandles::new();
        assert!(!nh.has_native_state());
        nh.created_rmnet_iface = Some("rmnet_data0".into());
        assert!(nh.has_native_state());
    }

    #[test]
    fn cold_boot_vendor_cm_guard_re_stops_late_daemons_only() {
        assert_eq!(should_re_stop_vendor_cm(false, false, false), (true, false));
        assert_eq!(should_re_stop_vendor_cm(true, false, false), (false, false));
        assert_eq!(should_re_stop_vendor_cm(true, true, false), (true, true));
        assert_eq!(should_re_stop_vendor_cm(true, false, true), (true, true));
        assert_eq!(should_re_stop_vendor_cm(true, true, true), (true, true));
    }

    #[test]
    fn ipv6_bearer_key_ignores_privacy_iid_rotation_on_same_prefix() {
        let rt1 = WdsRuntimeSettings {
            ipv6_addr: Some("2607:fb91:1689:832:34d7:7469:3030:da95".into()),
            ipv6_prefix_len: Some(64),
            ..Default::default()
        };
        let rt2 = WdsRuntimeSettings {
            ipv6_addr: Some("2607:fb91:1689:832:f58d:380a:9b62:1366".into()),
            ipv6_prefix_len: Some(64),
            ..Default::default()
        };
        let k1 = ipv6_bearer_key(&rt1).unwrap();
        assert_eq!(Some(k1.clone()), ipv6_bearer_key(&rt2));
        assert!(!ipv6_bearer_changed(Some(&rt2), Some(&k1)));

        let diff_prefix = WdsRuntimeSettings {
            ipv6_addr: Some("2607:fb91:1689:999::1".into()),
            ipv6_prefix_len: Some(64),
            ..Default::default()
        };
        assert!(ipv6_bearer_changed(Some(&diff_prefix), Some(&k1)));

        let diff_plen = WdsRuntimeSettings {
            ipv6_addr: Some("2607:fb91:1689:832::1".into()),
            ipv6_prefix_len: Some(56),
            ..Default::default()
        };
        assert!(ipv6_bearer_changed(Some(&diff_plen), Some(&k1)));

        assert!(ipv6_bearer_changed(None, Some(&k1)));
        assert!(ipv6_bearer_changed(Some(&rt1), None));
        assert!(!ipv6_bearer_changed(None, None));
    }

    #[test]
    fn pins_eth0_msi_irqs_to_cpu2_3_and_gsi_to_cpu1_and_restores_on_default() {
        let sbx = crate::paths::TestSandbox::new("eth0_irqs");
        sbx.write(
            "/proc/interrupts",
            concat!(
                "           CPU0       CPU1       CPU2       CPU3\n",
                " 22:       1000          0          0          0   GICv3 102 Edge      ipcc_0\n",
                " 45:       9000          0          0          0   GICv3 210 Level     gsi\n",
                " 81:          0          0       5000          0   PCI-MSI 524288 Edge      eth0-0\n",
                " 82:          0          0       4000          0   PCI-MSI 524289 Edge      eth0-1\n",
            ),
        );
        let p45 = sbx.write("/proc/irq/45/smp_affinity_list", "0-3\n");
        let p81 = sbx.write("/proc/irq/81/smp_affinity_list", "0-3\n");
        let p82 = sbx.write("/proc/irq/82/smp_affinity_list", "0-3\n");

        let assigned = pin_eth0_irqs_to_cpu2_3();
        assert_eq!(
            assigned,
            vec![("45".into(), "1"), ("81".into(), "2"), ("82".into(), "3")]
        );
        assert_eq!(fs::read_to_string(&p45).unwrap().trim(), "1");
        assert_eq!(fs::read_to_string(&p81).unwrap().trim(), "2");
        assert_eq!(fs::read_to_string(&p82).unwrap().trim(), "3");
        assert!(!kernel_tuning_drifted("rmnet_data0"));

        // Drift detection catches IRQ affinity reset.
        fs::write(&p82, "0-3\n").unwrap();
        assert!(kernel_tuning_drifted("rmnet_data0"));

        // Restore on Default profile reverts saved IRQ affinities.
        let mut warns = Vec::new();
        restore_nic_offloads_and_irqs(&mut warns);
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(fs::read_to_string(&p45).unwrap().trim(), "0-3");
        assert_eq!(fs::read_to_string(&p81).unwrap().trim(), "0-3");
        assert_eq!(fs::read_to_string(&p82).unwrap().trim(), "0-3");
    }

    #[tokio::test]
    async fn ssr_preserves_last_applied_ips_for_v4_and_v6_conntrack_eviction() {
        let sbx = crate::paths::TestSandbox::new("dp_ssr_ct");
        let www = sbx.root.join("www");
        fs::create_dir_all(&www).unwrap();
        let app = AppState::for_tests(www, crate::auth::AuthStore::new(sbx.root.join("sessions")));
        let mut ph = ProbeHandles::default();
        let mut nh = NativeHandles::new();
        nh.last_v4_ip = Some("100.64.10.20".into());
        nh.last_applied_v4_ip = Some("100.64.10.20".into());
        nh.last_v6_ip = Some("2607:fb90:1234:5678::1".into());
        nh.last_applied_v6_ip = Some("2607:fb90:1234:5678::1".into());
        nh.last_v6_key = Some(("2607:fb90:1234:5678".into(), 64));
        nh.last_applied_v6_key = Some(("2607:fb90:1234:5678".into(), 64));

        handle_modem_ssr(&app, &mut ph, &mut nh, 0, 1, "test-ssr");
        // Live pointers cleared so netlink re-applies on reconnect...
        assert!(nh.last_v4_ip.is_none());
        assert!(nh.last_v6_ip.is_none());
        assert!(nh.last_v6_key.is_none());
        // ...while last_applied_* remain intact for conntrack eviction!
        assert_eq!(nh.last_applied_v4_ip.as_deref(), Some("100.64.10.20"));
        assert_eq!(
            nh.last_applied_v6_key,
            Some(("2607:fb90:1234:5678".into(), 64))
        );

        let args = build_conntrack_eviction_args(
            nh.last_applied_v4_ip.as_deref(),
            true,
            nh.last_applied_v6_key.as_ref(),
            nh.last_applied_v6_ip.as_deref(),
            true,
        );
        assert_eq!(
            args,
            vec![
                vec!["-D", "-q", "100.64.10.20"],
                vec!["-D", "-s", "100.64.10.20"],
                vec!["-D", "-f", "ipv6", "-s", "2607:fb90:1234:5678::/64"],
                vec!["-D", "-f", "ipv6", "-q", "2607:fb90:1234:5678::/64"],
            ]
        );
    }

    #[test]
    fn ipv6_only_carrier_in_ipv4v6_mode_is_healthy_and_ram_caps_socket_bufs() {
        let (healthy, sleep, state_str) = evaluate_native_bearer_health(
            false,
            true,
            false,
            Some(Duration::from_secs(60)),
            None,
            None,
        );
        assert!(healthy);
        assert_eq!(sleep, Duration::from_secs(15));
        assert_eq!(state_str, "native-connected");

        let (healthy_none, sleep_none, state_none) = evaluate_native_bearer_health(
            false,
            false,
            false,
            Some(Duration::from_secs(10)),
            Some(Duration::from_secs(5)),
            None,
        );
        assert!(!healthy_none);
        assert_eq!(sleep_none, Duration::from_secs(5));
        assert_eq!(state_none, "native-backoff-5s");

        assert_eq!(parse_memtotal_mib("MemTotal:       491520 kB\n"), Some(480));
        assert_eq!(socket_buf_max_bytes_for_ram(Some(480)), 8_388_608);
        assert_eq!(socket_buf_max_bytes_for_ram(Some(512)), 8_388_608);
        assert_eq!(socket_buf_max_bytes_for_ram(Some(1024)), 16_777_216);
        assert_eq!(socket_buf_max_bytes_for_ram(None), 16_777_216);

        let ethtool_k = "rx-gro-list: on\nrx-udp-gro-forwarding: off [requested off]\n";
        assert_eq!(parse_ethtool_gro_features(ethtool_k), (Some(true), Some(false)));
    }

    #[tokio::test]
    async fn ippt_dnsmasq_conf_sfe_guard_corrupt_config_and_metrics_coexist() {
        let sbx = crate::paths::TestSandbox::new("dp_ippt_sfe");
        sbx.write(DATAPLANE_CONFIG_PATH, "{corrupt json");
        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                // Corrupt dataplane.json is quarantined and returns defaults.
                let cfg = load_config();
                assert_eq!(cfg, DataplaneConfig::default());

                // IPPT dnsmasq config write & clean removal.
                write_ippt_dnsmasq_conf(
                    "AA:BB:CC:DD:EE:FF",
                    Ipv4Addr::new(100, 64, 1, 2),
                    Some(Ipv4Addr::new(100, 64, 1, 1)),
                )
                .await
                .unwrap();
                let real = sbx.root.join(IPPT_DNSMASQ_CONF_PATH.trim_start_matches('/'));
                let body = fs::read_to_string(&real).unwrap();
                assert!(body.contains("dhcp-host=aa:bb:cc:dd:ee:ff,set:cellcore_ippt,100.64.1.2,120s"));
                assert!(body.contains("dhcp-option=tag:cellcore_ippt,option:router,100.64.1.1"));
                assert!(remove_ippt_dnsmasq_conf().await.unwrap());
                assert!(!real.exists());

                // SFE mutual exclusion guard blocks loading when IPA offload or IPPT is active.
                let w_ipa = reconcile_sfe_fastpath_with_guard(true, false, true, false).await;
                assert!(w_ipa.iter().any(|w| w.contains("mutually exclusive")));
                let w_ippt = reconcile_sfe_fastpath_with_guard(true, false, false, true).await;
                assert!(w_ippt.iter().any(|w| w.contains("IP Passthrough")));

                // Monotonic native WAN uptime.
                NATIVE_CONNECTED_SINCE.store(crate::state::mono_ms(), Ordering::Relaxed);
                assert!(native_wan_uptime_secs().is_some_and(|s| s >= 1));
                NATIVE_CONNECTED_SINCE.store(0, Ordering::Relaxed);
                assert!(native_wan_uptime_secs().is_none());

                // DataplaneMetricsView reports "coexist" (never "legacy") and expanded fields.
                let mv = metrics_view().await;
                assert_ne!(mv.mode, "legacy");
                assert!(matches!(mv.mode, "coexist" | "native"));
            })
            .await;
    }

    #[tokio::test]
    async fn persisted_native_baseline_survives_crash_restart_and_restores_cleanly() {
        let sbx = crate::paths::TestSandbox::new("dp_persist_restore");
        let rmem = sbx.write("/proc/sys/net/core/rmem_max", "229376\n");
        let qdisc = sbx.write("/proc/sys/net/core/default_qdisc", "pfifo_fast\n");
        let resolv = sbx.write("/tmp/resolv.conf.d/resolv.conf.auto", "nameserver 9.9.9.9\n");
        let call_log = sbx.root.join("restore_calls.log");
        sbx.write_exec(
            "/etc/init.d/netmgrd",
            &format!("#!/bin/sh\necho \"netmgrd $*\" >> {}\nexit 0\n", call_log.display()),
        );
        sbx.write_exec(
            "/etc/init.d/mwan3",
            &format!("#!/bin/sh\necho \"mwan3 $*\" >> {}\nexit 0\n", call_log.display()),
        );

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                // 1. First tuning pass captures original pre-tuning baseline (229376, pfifo_fast) to disk.
                let _ = apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some("rmnet_data0"));
                assert_eq!(fs::read_to_string(&rmem).unwrap().trim(), "16777216");
                assert_eq!(fs::read_to_string(&qdisc).unwrap().trim(), "fq_codel");

                // 2. Simulate crash-restart: clear in-memory baseline cache and call HighThroughput AGAIN
                //    while sysctls are ALREADY tuned. Must reuse persisted original baseline (229376)!
                if let Some(lock) = BASELINE_SYSCTLS.get() {
                    lock.lock().unwrap().clear();
                }
                let _ = apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some("rmnet_data0"));
                let persisted = load_persisted_native_state().expect("persisted native state file");
                assert!(
                    persisted
                        .baseline_sysctls
                        .iter()
                        .any(|(k, v)| k == "/proc/sys/net/core/rmem_max" && v == "229376"),
                    "crash-restart must reuse pre-tuning baseline, got {:?}",
                    persisted.baseline_sysctls
                );

                // 3. Record native handoff state (vendor daemons + mwan3 stopped, resolv overwritten).
                let mut st = persisted;
                st.native_active = true;
                st.vendor_daemons_stopped = true;
                st.mwan3_stopped = true;
                st.saved_resolv = Some(vec![(
                    "/tmp/resolv.conf.d/resolv.conf.auto".into(),
                    Some(b"nameserver 9.9.9.9\n".to_vec()),
                )]);
                save_persisted_native_state(&st).unwrap();
                fs::write(&resolv, b"nameserver 192.0.0.30\n").unwrap();

                // 4. `restore_from_persisted_state()` restores sysctls, resolv.conf, netmgrd, mwan3, and removes state file.
                let actions = restore_from_persisted_state().await.unwrap();
                assert!(!actions.is_empty());
                assert_eq!(fs::read_to_string(&rmem).unwrap().trim(), "229376");
                assert_eq!(fs::read_to_string(&qdisc).unwrap().trim(), "pfifo_fast");
                assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 9.9.9.9\n");
                assert!(load_persisted_native_state().is_none());
                let calls = fs::read_to_string(&call_log).unwrap_or_default();
                assert!(calls.contains("netmgrd start"), "{calls}");
                assert!(calls.contains("mwan3 start"), "{calls}");
            })
            .await;
    }

    #[test]
    fn bearer_restart_detects_apn_profile_and_ip_family_and_parses_orphan_ipt_rules() {
        let base = DataplaneConfig::default();
        let sig_base = AppliedCfgSig::from(&base);

        let mut apn_changed = base.clone();
        apn_changed.profile_index = 2;
        assert!(bearer_restart_needed(Some(&sig_base), &AppliedCfgSig::from(&apn_changed)));

        let mut fam_changed = base.clone();
        fam_changed.ip_family = IpFamily::Ipv4;
        assert!(bearer_restart_needed(Some(&sig_base), &AppliedCfgSig::from(&fam_changed)));

        let mut dns_only = base.clone();
        dns_only.manage_dns = !base.manage_dns;
        assert!(!bearer_restart_needed(Some(&sig_base), &AppliedCfgSig::from(&dns_only)));
        assert_ne!(sig_base, AppliedCfgSig::from(&dns_only));

        let ipt_dump = concat!(
            "-P POSTROUTING ACCEPT\n",
            "-A POSTROUTING -o eth1 -j MASQUERADE\n",
            "-A POSTROUTING -o rmnet_data0 -m comment --comment \"qm_native\" -j MASQUERADE\n",
            "-A FORWARD -o rmnet_data0 -p tcp --tcp-flags SYN,RST SYN -m comment --comment qm_native -j TCPMSS --set-mss 1388\n",
        );
        let dels = extract_qm_native_ipt_delete_args(ipt_dump);
        assert_eq!(dels.len(), 2);
        assert_eq!(
            dels[0],
            vec!["-D", "POSTROUTING", "-o", "rmnet_data0", "-m", "comment", "--comment", "qm_native", "-j", "MASQUERADE"]
        );
        assert_eq!(dels[1][0], "-D");
        assert!(dels[1].contains(&"TCPMSS".to_string()));
    }

    #[tokio::test]
    async fn coalesces_qmi_indication_bursts_and_tracks_live_wds_connected_flag() {
        let (tx, mut rx) = mpsc::channel::<QmiIndication>(16);
        let wake = Notify::new();
        for i in 0..5u16 {
            tx.send(QmiIndication {
                service: SVC_NAS,
                msg_id: nas::NAS_SYS_INFO_IND,
                tlvs: vec![(0x01, vec![i as u8])],
                tag: "NAS",
            })
            .await
            .unwrap();
        }
        let batch = drain_coalesced_indications(&mut rx, &wake, Duration::from_millis(80)).await;
        assert_eq!(batch.len(), 5, "burst indications must be coalesced into one pass");

        // WDS live state tracking for ipc.rs false-positive guard.
        set_native_wds_state_for_test(true, true, false);
        assert!(is_wds_connected());
        set_native_wds_state_for_test(true, false, true);
        assert!(is_wds_connected());
        set_native_wds_state_for_test(true, false, false);
        assert!(!is_wds_connected());
        set_native_wds_state_for_test(false, false, false);
    }
}
