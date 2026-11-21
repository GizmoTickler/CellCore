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
    state::{AppState, atomic_write, save_json_atomic},
};

pub const DATAPLANE_CONFIG_PATH: &str = "/etc/cellcore/dataplane.json";
pub const CONFIRM_NATIVE: &str = "NATIVE";

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
}

static HUB: OnceLock<Arc<DataplaneHub>> = OnceLock::new();
static BASELINE_SYSCTLS: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();
static NATIVE_CONNECTED_SINCE: AtomicU64 = AtomicU64::new(0);
static NATIVE_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);
static SFE_LOADED_BY_US: AtomicBool = AtomicBool::new(false);

/// True when Qualcomm Shortcut Forwarding Engine (`shortcut_fe`) is currently loaded in the kernel.
pub fn is_sfe_loaded() -> bool {
    Path::new(&crate::paths::p("/sys/module/shortcut_fe")).exists()
        || Path::new(&crate::paths::p("/sys/sfe_ipv4")).exists()
}

/// Reconcile opt-in Qualcomm SFE software fastpath kernel modules.
pub async fn reconcile_sfe_fastpath(enable: bool, force_unload: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    let opt_bin = "/usr/sbin/data_path_opt";
    if enable {
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

/// True while `DataplaneMode::Native` is active (or stopping QCMAP/netmgrd), so `at_fwd`
/// commands backed by QCMAP (`AT+QMAP`, `+QMAPWAC`, `+QDMZ`, `+QIP6CFG`) are never written
/// to `/dev/smd11` where `atfwd-daemon` would wedge waiting for the stopped daemon.
pub fn is_native_mode() -> bool {
    NATIVE_MODE_ACTIVE.load(Ordering::Relaxed)
}

/// Seconds since the native cellular bearer became connected (`None` when not connected in native mode).
pub fn native_wan_uptime_secs() -> Option<u64> {
    let since = NATIVE_CONNECTED_SINCE.load(Ordering::Relaxed);
    (since > 0).then(|| now_secs().saturating_sub(since).max(1))
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
        })
    })
    .clone()
}

pub fn load_config() -> DataplaneConfig {
    let p = crate::paths::p(DATAPLANE_CONFIG_PATH);
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
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

pub fn apply_kernel_tuning(profile: KernelTuningProfile, active_iface: Option<&str>) -> Vec<String> {
    let baseline_lock = BASELINE_SYSCTLS.get_or_init(|| {
        let mut captured = Vec::new();
        for (rel, _) in HIGH_THROUGHPUT_SYSCTLS.iter().chain(OPTIONAL_IPA_SYSCTLS.iter()) {
            if let Some(orig) = read_trimmed(rel) {
                captured.push(((*rel).to_string(), orig));
            }
        }
        Mutex::new(captured)
    });

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

    if !dyn_entries.is_empty() {
        let mut pairs = baseline_lock.lock().unwrap_or_else(|e| e.into_inner());
        for (rel, _) in &dyn_entries {
            if !pairs.iter().any(|(k, _)| k == rel)
                && let Some(orig) = read_trimmed(rel)
            {
                pairs.push((rel.clone(), orig));
            }
        }
    }

    let mut warnings = Vec::new();
    match profile {
        KernelTuningProfile::HighThroughput => {
            for (rel, val) in HIGH_THROUGHPUT_SYSCTLS
                .iter()
                .map(|(r, v)| (*r, *v))
                .chain(dyn_entries.iter().map(|(r, v)| (r.as_str(), *v)))
            {
                let real = crate::paths::p(rel);
                if !Path::new(&real).exists() {
                    continue;
                }
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
            let pairs = baseline_lock.lock().unwrap_or_else(|e| e.into_inner()).clone();
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
        }
    }
    warnings
}

/// Enable hardware/kernel GRO forwarding offloads (`rx-gro-list`, `rx-udp-gro-forwarding`)
/// on `eth0` and the active `rmnet_data*` interface (software netdev flags that never reset
/// Realtek `r8125` + Qualcomm `ioss` hardware DMA rings), and pin `eth0-*` PCIe MSI IRQs
/// onto CPUs 2–3 via `smp_affinity_list` (isolated from `ipcc_0` on CPU 0 and `gsi/IPA` on CPU 1).
pub(crate) fn pin_eth0_irqs_to_cpu2_3() -> Vec<(String, &'static str)> {
    let mut assigned = Vec::new();
    let irqs_path = crate::paths::p("/proc/interrupts");
    let Ok(text) = fs::read_to_string(&irqs_path) else {
        return assigned;
    };
    for line in text.lines() {
        if !line.contains("eth0-") {
            continue;
        }
        if let Some((num_raw, _)) = line.split_once(':') {
            let irq = num_raw.trim();
            if !irq.is_empty() && irq.bytes().all(|b| b.is_ascii_digit()) {
                let list_path = crate::paths::p(&format!("/proc/irq/{irq}/smp_affinity_list"));
                if Path::new(&list_path).exists() {
                    let _ = fs::write(&list_path, "2-3\n");
                }
                assigned.push((irq.to_string(), "2-3"));
            }
        }
    }
    assigned
}

fn tune_nic_offloads_and_irqs(active_iface: Option<&str>) {
    let mut ifaces: Vec<&str> = vec!["eth0"];
    if let Some(iface) = active_iface
        && netlink::validate_managed_iface(iface).is_ok()
        && iface != "eth0"
    {
        ifaces.push(iface);
    }
    for iface in ifaces {
        let sys_if = crate::paths::p(&format!("/sys/class/net/{iface}"));
        if !Path::new(&sys_if).exists() {
            continue;
        }
        let _ = crate::uci::run_cmd_blocking_timeout(
            "ethtool",
            &["-K", iface, "rx-gro-list", "on", "rx-udp-gro-forwarding", "on"],
            Duration::from_secs(2),
        );
    }

    let _ = pin_eth0_irqs_to_cpu2_3();
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
    if cfg.kernel_tuning == KernelTuningProfile::HighThroughput {
        let warns = apply_kernel_tuning(KernelTuningProfile::HighThroughput, Some(&cfg.iface));
        *h.tuning_warnings.lock().unwrap_or_else(|e| e.into_inner()) = warns;
    }
    let st = state.clone();
    tokio::spawn(async move {
        if cfg.sfe_fastpath {
            let _ = reconcile_sfe_fastpath(true, false).await;
        }
        supervisor_loop(st, h).await;
    });
}

#[derive(Clone, PartialEq, Eq)]
struct AppliedCfgSig {
    iface: String,
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

#[derive(Debug, Clone, Default)]
struct NativeNatState {
    iface: String,
    link_mtu: u32,
    nft_table: bool,
    fw4_forward: bool,
    ipt_nat: bool,
    ipt_forward: bool,
    ip6t_forward: bool,
    ipt_mss_arg: Option<String>,
    ip6t_mss_arg: Option<String>,
}

struct NativeHandles {
    v4_client: Option<Arc<QrtrServiceClient>>,
    v6_client: Option<Arc<QrtrServiceClient>>,
    v4_handle: Option<u32>,
    v6_handle: Option<u32>,
    last_v4_ip: Option<String>,
    last_v6_ip: Option<String>,
    last_v6_key: Option<(String, u8)>,
    last_link_mtu: u32,
    last_applied_sig: Option<AppliedCfgSig>,
    last_resolved_iface: Option<String>,
    applied_dns: Vec<String>,
    saved_resolv: Option<SavedResolvSnapshot>,
    v6_dns_routes: Vec<Ipv6Addr>,
    ippt_host_ip: Option<Ipv4Addr>,
    ipa_ippt_active: bool,
    ipa_ippt_mac: Option<String>,
    ipa_v6_sharing_prefix: Option<String>,
    created_rmnet_iface: Option<String>,
    mwan3_stopped: bool,
    native_nat: Option<NativeNatState>,
    backoff: ReconnectBackoff,
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
            last_link_mtu: 1500,
            last_applied_sig: None,
            last_resolved_iface: None,
            applied_dns: Vec::new(),
            saved_resolv: None,
            v6_dns_routes: Vec::new(),
            ippt_host_ip: None,
            ipa_ippt_active: false,
            ipa_ippt_mac: None,
            ipa_v6_sharing_prefix: None,
            created_rmnet_iface: None,
            mwan3_stopped: false,
            native_nat: None,
            backoff: ReconnectBackoff::new(),
            vendor_daemons_stopped: false,
        }
    }

    fn has_native_state(&self) -> bool {
        self.v4_client.is_some()
            || self.v6_client.is_some()
            || self.last_applied_sig.is_some()
            || self.created_rmnet_iface.is_some()
            || self.native_nat.is_some()
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
            "add rule inet qm_native_nat forward oifname \"{iface}\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size set {mss4}\n\
             add rule inet qm_native_nat forward iifname \"{iface}\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size set {mss4}\n\
             add rule inet qm_native_nat forward oifname \"{iface}\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size set {mss6}\n\
             add rule inet qm_native_nat forward iifname \"{iface}\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size set {mss6}\n"
        ));
    } else {
        s.push_str(&format!(
            "add rule inet qm_native_nat forward oifname \"{iface}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n"
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

pub(crate) fn ipt_rules_cover_iface(rules_text: &str, iface: &str) -> bool {
    rules_text.lines().any(|line| {
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.windows(2).any(|w| w[0] == "-o" && w[1] == iface)
    })
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
            && !ipt_rules_cover_iface(&out.stdout_str(), iface)
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
            && !ipt_rules_cover_iface(&out.stdout_str(), iface)
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
            && !ipt_rules_cover_iface(&out.stdout_str(), iface)
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
            && !ipt_rules_cover_iface(&out.stdout_str(), iface)
        {
            if mtu < 1500 {
                let mss4 = (mtu - 40).to_string();
                let r_out = run(
                    ipt_bin,
                    &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss4],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
                let r_in = run(
                    ipt_bin,
                    &["-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss4],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
                if r_out.is_ok_and(|r| r.ok()) && r_in.is_ok_and(|r| r.ok()) {
                    st.ipt_mss_arg = Some(mss4);
                }
            } else {
                let r_out = run(
                    ipt_bin,
                    &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
                if r_out.is_ok_and(|r| r.ok()) {
                    st.ipt_mss_arg = Some("pmtu".into());
                }
            }
        }
        if Path::new(&crate::paths::p(ip6t_bin)).exists()
            && let Ok(out) = run(ip6t_bin, &["-t", "mangle", "-S", "FORWARD"], ExecOpts::new(5, 32 * KIB)).await
            && out.ok()
            && !ipt_rules_cover_iface(&out.stdout_str(), iface)
        {
            if mtu < 1500 {
                let mss6 = (mtu - 60).to_string();
                let r_out = run(
                    ip6t_bin,
                    &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss6],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
                let r_in = run(
                    ip6t_bin,
                    &["-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", &mss6],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
                if r_out.is_ok_and(|r| r.ok()) && r_in.is_ok_and(|r| r.ok()) {
                    st.ip6t_mss_arg = Some(mss6);
                }
            } else {
                let r_out = run(
                    ip6t_bin,
                    &["-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
                if r_out.is_ok_and(|r| r.ok()) {
                    st.ip6t_mss_arg = Some("pmtu".into());
                }
            }
        }
    }

    if st.nft_table
        || st.fw4_forward
        || st.ipt_nat
        || st.ipt_forward
        || st.ip6t_forward
        || st.ipt_mss_arg.is_some()
        || st.ip6t_mss_arg.is_some()
    {
        nh.native_nat = Some(st);
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
    if let Some(ref mss_arg) = st.ipt_mss_arg {
        if mss_arg == "pmtu" {
            let _ = run(
                ipt_bin,
                &["-t", "mangle", "-D", "FORWARD", "-o", &st.iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                ExecOpts::new(5, 16 * KIB),
            )
            .await;
        } else {
            for flag in ["-o", "-i"] {
                let _ = run(
                    ipt_bin,
                    &["-t", "mangle", "-D", "FORWARD", flag, &st.iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", mss_arg],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
            }
        }
    }
    if let Some(ref mss_arg) = st.ip6t_mss_arg {
        if mss_arg == "pmtu" {
            let _ = run(
                ip6t_bin,
                &["-t", "mangle", "-D", "FORWARD", "-o", &st.iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                ExecOpts::new(5, 16 * KIB),
            )
            .await;
        } else {
            for flag in ["-o", "-i"] {
                let _ = run(
                    ip6t_bin,
                    &["-t", "mangle", "-D", "FORWARD", flag, &st.iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", "qm_native", "-j", "TCPMSS", "--set-mss", mss_arg],
                    ExecOpts::new(5, 16 * KIB),
                )
                .await;
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
            Ok(o) if o.ok() => !ipt_rules_cover_iface(&o.stdout_str(), iface),
            _ => false,
        };
        let fwd6_missing = if Path::new(&crate::paths::p(ip6t_bin)).exists() {
            match run(ip6t_bin, &["-t", "filter", "-S", "zone_wan_dest_accept"], ExecOpts::new(5, 32 * KIB)).await {
                Ok(o) if o.ok() => !ipt_rules_cover_iface(&o.stdout_str(), iface),
                _ => false,
            }
        } else {
            false
        };
        let mss_missing = match run(ipt_bin, &["-t", "mangle", "-S", "FORWARD"], ExecOpts::new(5, 32 * KIB)).await {
            Ok(o) if o.ok() => !ipt_rules_cover_iface(&o.stdout_str(), iface),
            _ => false,
        };
        fwd_missing || fwd6_missing || mss_missing
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
    let res = tokio::task::spawn_blocking(move || {
        let links = netlink::list_links()?;
        if netlink::resolve_rmnet_link(&links, &iface, mux_id).is_some() {
            return Ok::<_, String>(None);
        }
        netlink::create_rmnet_link("rmnet_ipa0", &iface, u16::from(mux_id)).map(Some)
    })
    .await;

    match res {
        Ok(Ok(Some((link, created)))) => {
            if created {
                nh.created_rmnet_iface = Some(link.name.clone());
                if cfg.kernel_tuning == KernelTuningProfile::HighThroughput {
                    apply_iface_rps_high_throughput(&link.name);
                }
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
    NATIVE_CONNECTED_SINCE.store(0, Ordering::Relaxed);
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
    nh.last_link_mtu = 1500;
    nh.last_applied_sig = None;
    nh.last_resolved_iface = None;

    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(links) = netlink::list_links()
            && let Some(link) = links.into_iter().find(|l| l.name == iface)
        {
            let _ = netlink::del_default_routes(&iface, link.ifindex, table);
            let _ = netlink::flush_iface_addrs(&iface, link.ifindex, None);
        }
    })
    .await;

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
    let hdl = wds::start_network_interface(cli.as_ref(), &params).await?;
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
    if read_trimmed("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .is_some_and(|g| g != "performance")
    {
        return true;
    }
    if read_trimmed("/sys/power/autosleep").is_some_and(|a| a != "off") {
        return true;
    }
    if netlink::validate_managed_iface(active_iface).is_ok() {
        let rel = format!("/sys/class/net/{active_iface}/queues/rx-0/rps_cpus");
        if let Some(rps) = read_trimmed(&rel)
            && (rps == "0" || rps == "00")
        {
            return true;
        }
    }
    false
}

/// Lightweight read-only snapshot exported to `/api/v1/metrics` without
/// sending any QMI/AT commands or touching sysfs.
#[derive(Debug, Clone, Default)]
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
}

pub async fn metrics_view() -> DataplaneMetricsView {
    let h = hub();
    let mode = match h.config.read().await.mode {
        DataplaneMode::Native => "native",
        _ => "legacy",
    };
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
    NATIVE_CONNECTED_SINCE.store(0, Ordering::Relaxed);
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
}

async fn flush_stale_wan_conntrack_and_reload_odhcpd(
    prev_v4: Option<&str>,
    v4_changed: bool,
    had_prev_v6: bool,
    v6_changed: bool,
) {
    // Only flush conntrack entries bound to a *previous* WAN IPv4 address when the bearer re-IPs;
    // never run global `conntrack -F` (which drops LAN management SSH sessions!).
    if v4_changed
        && let Some(old_ip) = prev_v4
        && old_ip.parse::<Ipv4Addr>().is_ok()
    {
        for bin in ["/usr/sbin/conntrack", "/sbin/conntrack"] {
            if Path::new(&crate::paths::p(bin)).exists() {
                let _ = run(bin, &["-D", "-q", old_ip], ExecOpts::new(3, 16 * KIB)).await;
                break;
            }
        }
    }
    if had_prev_v6 && v6_changed {
        let odhcpd = "/etc/init.d/odhcpd";
        if Path::new(&crate::paths::p(odhcpd)).exists() {
            let _ = run(odhcpd, &["reload"], ExecOpts::new(5, 16 * KIB)).await;
        }
    }
}

async fn supervisor_loop(state: AppState, h: Arc<DataplaneHub>) {
    let (ind_tx, mut ind_rx) = mpsc::channel::<QmiIndication>(64);
    let mut bus: Option<Arc<QrtrBus>> = None;
    let mut bus_rx: Option<tokio::sync::broadcast::Receiver<QrtrBusEvent>> = None;
    let mut nh = NativeHandles::new();
    let mut ph = ProbeHandles::default();
    let mut native_tick: u64 = 0;
    let mut loop_tick: u64 = 0;
    let mut last_ssr_count: u64 = 0;
    let mut pending_phy_reenable = false;

    loop {
        loop_tick = loop_tick.wrapping_add(1);
        let cfg = h.config.read().await.clone();
        if bus.is_none() {
            match QrtrBus::connect() {
                Ok(b) => {
                    last_ssr_count = b.snapshot().ssr_count;
                    bus_rx = Some(b.subscribe());
                    bus = Some(b);
                    state.push_daemon_log("dataplane: AF_QIPCRTR control bus connected");
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
                NATIVE_CONNECTED_SINCE.store(0, Ordering::Relaxed);
                if nh.has_native_state() {
                    teardown_native_handles(&state, &mut nh, &cfg).await;
                }
                if nh.vendor_daemons_stopped {
                    start_vendor_cm_daemons().await;
                    nh.vendor_daemons_stopped = false;
                }
                NATIVE_MODE_ACTIVE.store(false, Ordering::Relaxed);
                if nh.mwan3_stopped {
                    start_mwan3().await;
                    nh.mwan3_stopped = false;
                    state.push_daemon_log("dataplane: restarted mwan3 for coexist mode");
                }
                snap.supervisor_state = "coexist-observing".into();
            }
            DataplaneMode::Native => {
                native_tick = native_tick.wrapping_add(1);
                let manual_family = h.reconnect_queue.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(ref f) = manual_family {
                    if f == "all" || f == "ipv4" {
                        if let (Some(cli), Some(hdl)) = (&nh.v4_client, nh.v4_handle.take()) {
                            let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
                        }
                        nh.v4_client = None;
                        nh.last_v4_ip = None;
                    }
                    if f == "all" || f == "ipv6" {
                        if let (Some(cli), Some(hdl)) = (&nh.v6_client, nh.v6_handle.take()) {
                            let _ = wds::stop_network_interface(cli.as_ref(), hdl).await;
                        }
                        nh.v6_client = None;
                        nh.last_v6_ip = None;
                        nh.last_v6_key = None;
                    }
                    nh.backoff.reset();
                }

                NATIVE_MODE_ACTIVE.store(true, Ordering::Relaxed);
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

                let ps_ready = snap.nas_sys.as_ref().is_some_and(|s| s.registered);
                if !ps_ready {
                    NATIVE_CONNECTED_SINCE.store(0, Ordering::Relaxed);
                    snap.supervisor_state = "native-waiting-registration".into();
                } else {
                    let mut v4_rt = None;
                    let mut v6_rt = None;
                    let mut had_err = false;

                    if cfg.ip_family.wants_v4() {
                        if let Some(cli) = nh.v4_client.clone().filter(|c| c.is_alive()) {
                            if let Ok(st) = wds::get_pkt_srvc_status(cli.as_ref()).await {
                                snap.wds_v4.pkt_status = Some(st.clone());
                                if st.status == PktConnStatus::Connected && !st.reconfig_required {
                                    if let Ok(rt) = wds::get_runtime_settings(cli.as_ref()).await {
                                        v4_rt = Some(rt.clone());
                                        snap.wds_v4.runtime = Some(rt);
                                        snap.wds_v4.handle = nh.v4_handle;
                                        snap.wds_v4.state = "connected";
                                    }
                                } else {
                                    nh.v4_client = None;
                                    nh.v4_handle = None;
                                    nh.last_v4_ip = None;
                                }
                            } else {
                                nh.v4_client = None;
                                nh.v4_handle = None;
                                nh.last_v4_ip = None;
                            }
                        }
                        if nh.v4_client.is_none() {
                            snap.reconnect_attempts += 1;
                            match bring_up_native_family(
                                b,
                                &ind_tx,
                                &cfg,
                                4,
                                "WDS_V4",
                                &mut snap.wds_v4,
                                &mut snap.warnings,
                            )
                            .await
                            {
                                Ok((c, hdl, rt)) => {
                                    nh.v4_client = Some(c);
                                    nh.v4_handle = Some(hdl);
                                    v4_rt = Some(rt);
                                }
                                Err(e) => {
                                    had_err = true;
                                    snap.wds_v4.state = "backoff";
                                    snap.wds_v4.last_error = Some(e.to_string());
                                }
                            }
                        }
                    }

                    if cfg.ip_family.wants_v6() {
                        if let Some(cli) = nh.v6_client.clone().filter(|c| c.is_alive()) {
                            if let Ok(st) = wds::get_pkt_srvc_status(cli.as_ref()).await {
                                snap.wds_v6.pkt_status = Some(st.clone());
                                if st.status == PktConnStatus::Connected && !st.reconfig_required {
                                    if let Ok(mut rt) = wds::get_runtime_settings(cli.as_ref()).await {
                                        if !ipv6_bearer_changed(Some(&rt), nh.last_v6_key.as_ref())
                                            && let Some(applied_v6) = nh.last_v6_ip.as_ref()
                                        {
                                            rt.ipv6_addr = Some(applied_v6.clone());
                                        }
                                        v6_rt = Some(rt.clone());
                                        snap.wds_v6.runtime = Some(rt);
                                        snap.wds_v6.handle = nh.v6_handle;
                                        snap.wds_v6.state = "connected";
                                    }
                                } else {
                                    nh.v6_client = None;
                                    nh.v6_handle = None;
                                    nh.last_v6_ip = None;
                                    nh.last_v6_key = None;
                                }
                            } else {
                                nh.v6_client = None;
                                nh.v6_handle = None;
                                nh.last_v6_ip = None;
                                nh.last_v6_key = None;
                            }
                        }
                        if nh.v6_client.is_none() {
                            snap.reconnect_attempts += 1;
                            match bring_up_native_family(
                                b,
                                &ind_tx,
                                &cfg,
                                6,
                                "WDS_V6",
                                &mut snap.wds_v6,
                                &mut snap.warnings,
                            )
                            .await
                            {
                                Ok((c, hdl, rt)) => {
                                    nh.v6_client = Some(c);
                                    nh.v6_handle = Some(hdl);
                                    v6_rt = Some(rt);
                                }
                                Err(e) => {
                                    had_err = true;
                                    snap.wds_v6.state = "backoff";
                                    snap.wds_v6.last_error = Some(e.to_string());
                                }
                            }
                        }
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
                    let apply_v4 = cfg_changed || v4_changed || mtu_changed;
                    let apply_v6 = cfg_changed || v6_changed || mtu_changed;
                    if (apply_v4 || apply_v6) && (v4_rt.is_some() || v6_rt.is_some()) {
                        if cfg_changed && nh.last_applied_sig.is_some() {
                            teardown_ipa_and_dns(&mut nh, &cfg, !cfg.manage_dns, &mut snap.warnings).await;
                        } else if let Some(prev) = nh.last_applied_sig.as_ref().cloned() {
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
                        match apply_native_netlink(&cfg, v4_rt.as_ref(), v6_rt.as_ref(), apply_v4, apply_v6).await {
                            Ok(applied) => {
                                let prev_v4_for_ct = nh.last_v4_ip.clone();
                                let had_prev_v6 = nh.last_v6_key.is_some();
                                snap.netlink_updates += 1;
                                let resolved_iface = applied.resolved_iface.clone();
                                nh.last_link_mtu = applied.link_mtu;
                                if apply_v4 {
                                    nh.last_v4_ip = applied.v4_ip.map(|ip| ip.to_string());
                                    nh.ippt_host_ip = applied.ippt_host_ip;
                                }
                                if apply_v6 {
                                    nh.last_v6_ip = applied.v6_addr_str.clone();
                                    nh.last_v6_key = v6_rt.as_ref().and_then(ipv6_bearer_key);
                                    nh.v6_dns_routes = applied.v6_dns;
                                }
                                nh.last_applied_sig = Some(cur_sig);
                                nh.last_resolved_iface = Some(resolved_iface.clone());

                                flush_stale_wan_conntrack_and_reload_odhcpd(
                                    prev_v4_for_ct.as_deref(),
                                    v4_changed,
                                    had_prev_v6,
                                    v6_changed,
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
                                nh.backoff.reset();
                            }
                            Err(e) => {
                                had_err = true;
                                snap.warnings.push(format!("native netlink config: {e}"));
                            }
                        }
                    } else if !had_err && (v4_rt.is_some() || v6_rt.is_some()) {
                        nh.backoff.reset();
                        // Self-heal firewall rules after fw4/fw3 reload (~every 60s), including IPPT MSS clamp.
                        if native_tick.is_multiple_of(4)
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

                    if !had_err && (v4_rt.is_some() || v6_rt.is_some()) {
                        let _ = NATIVE_CONNECTED_SINCE.compare_exchange(
                            0,
                            now_secs(),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    } else if v4_rt.is_none() && v6_rt.is_none() {
                        NATIVE_CONNECTED_SINCE.store(0, Ordering::Relaxed);
                    }

                    if had_err {
                        next_sleep = nh.backoff.next_delay();
                        snap.supervisor_state = format!("native-backoff-{}s", next_sleep.as_secs());
                    } else {
                        snap.supervisor_state = "native-connected".into();
                    }
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
            snap.warnings.extend(reconcile_sfe_fastpath(true, false).await);
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

        tokio::select! {
            _ = tokio::time::sleep(next_sleep) => {}
            _ = h.wake.notified() => {}
            Some(ind) = ind_rx.recv() => {
                let mut s = h.snapshot.write().await;
                s.indications_received += 1;
                s.last_indication = Some(format!("{} {:#06x} ({})", qmi::service_name(ind.service), ind.msg_id, ind.tag));
                if ind.service == SVC_NAS && ind.msg_id == nas::NAS_SYS_INFO_IND {
                    s.nas_sys = Some(nas::parse_sys_info_tlvs(&ind.tlvs));
                } else if ind.service == SVC_WDS && ind.msg_id == WDS_PKT_SRVC_STATUS_IND
                    && let Ok(ps) = wds::parse_pkt_srvc_status_tlvs(&ind.tlvs)
                    && (ps.reconfig_required || ps.status == PktConnStatus::Disconnected)
                {
                    if ind.tag == "WDS_V4" {
                        nh.v4_client = None;
                        nh.v4_handle = None;
                        nh.last_v4_ip = None;
                    } else if ind.tag == "WDS_V6" {
                        nh.v6_client = None;
                        nh.v6_handle = None;
                        nh.last_v6_ip = None;
                        nh.last_v6_key = None;
                    }
                }
            }
            ev = recv_bus_wakeup(bus_rx.as_mut(), Some(b.as_ref()), last_ssr_count, need_services) => {
                if let QrtrBusEvent::Ssr { node, reason } = ev {
                    let cur_ssr = b.snapshot().ssr_count;
                    if cur_ssr > last_ssr_count {
                        last_ssr_count = cur_ssr;
                        handle_modem_ssr(&state, &mut ph, &mut nh, node, last_ssr_count, &reason);
                        pending_phy_reenable = true;
                    }
                }
            }
        }
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
    if next.sfe_fastpath != prev.sfe_fastpath {
        let _ = reconcile_sfe_fastpath(next.sfe_fastpath, !next.sfe_fastpath).await;
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
    let sfe_warns = if next.sfe_fastpath != prev.sfe_fastpath {
        reconcile_sfe_fastpath(next.sfe_fastpath, !next.sfe_fastpath).await
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

                let (s, _) = call_router(&router, &rd, Method::GET, "/api/v1/dataplane/profiles", None, "").await;
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
        assert!(!script.contains("iifname \"rmnet_data1\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"));

        // IPPT with skip_nat=true + T-Mobile 1428 MTU: keeps symmetric v4/v6 MSS clamping active while omitting masquerade!
        let ippt_mss = build_native_nat_nft_script("rmnet_data1", false, 1428).unwrap();
        assert!(!ippt_mss.contains("masquerade"));
        assert!(ippt_mss.contains("oifname \"rmnet_data1\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size set 1388"));
        assert!(ippt_mss.contains("iifname \"rmnet_data1\" meta nfproto ipv4 tcp flags syn / syn,rst tcp option maxseg size set 1388"));
        assert!(ippt_mss.contains("oifname \"rmnet_data1\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size set 1368"));
        assert!(ippt_mss.contains("iifname \"rmnet_data1\" meta nfproto ipv6 tcp flags syn / syn,rst tcp option maxseg size set 1368"));

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

        let ipt = "-A POSTROUTING -o rmnet_data10 -j MASQUERADE\n-A POSTROUTING -o rmnet_data1 -m comment --comment qm_native -j MASQUERADE\n";
        assert!(ipt_rules_cover_iface(ipt, "rmnet_data1"));
        assert!(!ipt_rules_cover_iface("-A POSTROUTING -o rmnet_data10 -j MASQUERADE\n", "rmnet_data1"));

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
    fn pins_eth0_msi_irqs_to_cpu2_3_via_smp_affinity_list() {
        let sbx = crate::paths::TestSandbox::new("eth0_irqs");
        sbx.write(
            "/proc/interrupts",
            concat!(
                "           CPU0       CPU1       CPU2       CPU3\n",
                " 22:       1000          0          0          0   GICv3 102 Edge      ipcc_0\n",
                " 45:          0       9000          0          0   GICv3 210 Level     gsi\n",
                " 81:          0          0       5000          0   PCI-MSI 524288 Edge      eth0-0\n",
                " 82:          0          0       4000          0   PCI-MSI 524289 Edge      eth0-1\n",
            ),
        );
        let p81 = sbx.write("/proc/irq/81/smp_affinity_list", "0-3\n");
        let p82 = sbx.write("/proc/irq/82/smp_affinity_list", "0-3\n");

        let assigned = pin_eth0_irqs_to_cpu2_3();
        assert_eq!(assigned, vec![("81".into(), "2-3"), ("82".into(), "2-3")]);
        assert_eq!(fs::read_to_string(p81).unwrap().trim(), "2-3");
        assert_eq!(fs::read_to_string(p82).unwrap().trim(), "2-3");
    }
}
