//! Prometheus text exposition (format 0.0.4) built only from cached daemon
//! state: rendering a scrape never sends an AT command.
//!
//! Labels are bounded: chain (0-3), direction (rx/tx), event type and
//! suppression reason (fixed enums), sink (3), thermal sensor names and the
//! serving cell's RAT/band/PCI/ARFCN (a handful of live values; label
//! values are sanitised and length-capped).

use std::{collections::BTreeMap, fmt::Write as _, sync::atomic::Ordering};

use super::{
    events::EventKind,
    failover::Source,
    lock, notify, obs,
    usage_cycle::{self, Civil},
};
use crate::{
    smd::LATENCY_BUCKETS_MS,
    state::{
        AppState, DataUsageState, MemoryTelemetry, ModemSnapshot, PingPoint, LinkWatchRuntime, SpeedtestRun,
        SystemInternals, UptimeTelemetry,
    },
};

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const MAX_LABEL_LEN: usize = 48;
/// Realtime ping samples used for the loss ratio.
const PING_WINDOW: usize = 60;

#[derive(Debug, Clone, Default)]
pub struct AtStatsView {
    pub healthy: bool,
    pub queued: u64,
    pub commands: u64,
    pub errors: u64,
    pub timeouts: u64,
    pub preempted: u64,
    pub broken: u64,
    pub buckets: Vec<u64>,
    pub latency_count: u64,
    pub latency_sum_ms: u64,
    pub last_latency_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FailoverView {
    pub active: bool,
    pub source: Option<Source>,
    pub avg_bps: u64,
    pub baseline_bps: u64,
    pub hint_fresh: bool,
    pub episodes_total: u64,
    pub episode_secs: u64,
    pub episode_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UsageView {
    pub cycle_rx: u64,
    pub cycle_tx: u64,
    pub projected: u64,
    pub quota: Option<u64>,
    pub cycle_days: i64,
    pub days_elapsed: f64,
    pub today_rx: u64,
    pub today_tx: u64,
    pub lifetime_rx: u64,
    pub lifetime_tx: u64,
    pub standby_today: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NotifyView {
    pub sent: BTreeMap<&'static str, u64>,
    pub failed: BTreeMap<&'static str, u64>,
    pub suppressed: BTreeMap<&'static str, u64>,
    pub dropped: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MetricsInput {
    pub version: String,
    pub now: u64,
    pub modem: ModemSnapshot,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub ping: Vec<PingPoint>,
    pub memory: MemoryTelemetry,
    pub internals: SystemInternals,
    pub device_uptime: u64,
    pub session_uptime: Option<UptimeTelemetry>,
    pub quecwatch_enabled: bool,
    pub quecwatch: LinkWatchRuntime,
    pub last_speedtest: Option<SpeedtestRun>,
    pub at: AtStatsView,
    pub events: BTreeMap<EventKind, u64>,
    pub failover: FailoverView,
    pub usage: UsageView,
    pub notify: NotifyView,
    pub dataplane: crate::dataplane::DataplaneMetricsView,
    pub phy: crate::radio_tuning::PhyDiagnostics,
    pub dsp: crate::qmi::dsp::DspTelemetrySnapshot,
    pub tls_cert: crate::acme::ActiveCertInfo,
    pub cell_lock_active: bool,
    pub cell_lock_bypassed: bool,
}

pub fn usage_view(u: &DataUsageState, today: Civil, secs: u32) -> UsageView {
    let cy = usage_cycle::cycle_bounds(today, u.billing_cycle_day);
    let (rx, tx) = usage_cycle::sum_days(&u.daily, cy.start, today);
    let (trx, ttx) = usage_cycle::sum_days(&u.daily, today, today);
    let el = usage_cycle::elapsed_days(&cy, today, secs);
    UsageView {
        cycle_rx: rx,
        cycle_tx: tx,
        projected: usage_cycle::project(rx.saturating_add(tx), el, cy.days()),
        quota: u.quota_bytes,
        cycle_days: cy.days(),
        days_elapsed: el,
        today_rx: trx,
        today_tx: ttx,
        ..Default::default()
    }
}

/// Snapshot everything a scrape needs (read locks only).
pub async fn gather(state: &AppState) -> MetricsInput {
    let now = crate::auth::now_secs();
    let modem = state.modem.read().await.clone();
    let (rx_bps, tx_bps) = {
        let tr = state.traffic.read().await;
        tr.interfaces
            .iter()
            .find(|i| i.name == tr.primary_iface)
            .map(|p| (p.rx.bps, p.tx.bps))
            .unwrap_or((0, 0))
    };
    let ping: Vec<PingPoint> = {
        let rt = state.ping_realtime.read().await;
        rt.iter().rev().take(PING_WINDOW).cloned().collect()
    };
    let memory = state.memory.read().await.clone();
    let internals = state.internals.read().await.clone();
    let device_uptime = state.device_uptime.read().await.uptime_seconds;
    let session = state.session_uptime.read().await.clone();
    let session_uptime = (session.is_connected == Some(true)).then_some(session);
    let (quecwatch_enabled, has_cell_lock) = {
        let cfg = state.settings.read().await;
        (
            cfg.quecwatch_enabled,
            !cfg.cell_lock_nr5g.is_empty() || !cfg.cell_lock_lte.is_empty(),
        )
    };
    let cell_lock_bypassed = state.cell_lock_bypassed.load(Ordering::Acquire);
    let cell_lock_active = has_cell_lock && !cell_lock_bypassed;
    let quecwatch = state.quecwatch.read().await.clone();
    let last_speedtest = state.speedtest_history.read().await.iter().max_by_key(|r| r.ts).cloned();
    let usage_state = state.data_usage.read().await.clone();

    let s = state.smd.stats();
    let at = AtStatsView {
        healthy: state.smd.is_healthy(),
        queued: s.queued.load(Ordering::Relaxed),
        commands: s.commands_total.load(Ordering::Relaxed),
        errors: s.at_errors.load(Ordering::Relaxed),
        timeouts: s.timeouts.load(Ordering::Relaxed),
        preempted: s.preempted.load(Ordering::Relaxed),
        broken: s.broken.load(Ordering::Relaxed),
        buckets: s.latency_buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect(),
        latency_count: s.latency_count.load(Ordering::Relaxed),
        latency_sum_ms: s.latency_sum_ms.load(Ordering::Relaxed),
        last_latency_ms: s.last_latency_ms.load(Ordering::Relaxed),
    };

    let o = obs();
    let events = lock(&o.events).counts.clone();
    let baseline_bps = lock(&o.config).failover.baseline_bps;
    let hint_ttl = lock(&o.config).failover.hint_ttl_secs;
    let p = lock(&o.persisted).clone();
    let failover = {
        let f = lock(&o.failover);
        let mono_now = std::time::Instant::now();
        FailoverView {
            active: f.active,
            source: f.source,
            avg_bps: f.throughput.avg_bps,
            baseline_bps,
            hint_fresh: f.hint.is_some_and(|(_, at)| {
                mono_now.saturating_duration_since(at) <= std::time::Duration::from_secs(hint_ttl)
            }),
            episodes_total: p.failover_episodes,
            episode_secs: f.episode.as_ref().map(|e| now.saturating_sub(e.started_at)).unwrap_or(0),
            episode_bytes: f.episode.as_ref().map(|e| e.bytes).unwrap_or(0),
        }
    };
    let (today, secs) = usage_cycle::local_now();
    let mut usage = usage_view(&usage_state, today, secs);
    usage.lifetime_rx = p.lifetime_rx;
    usage.lifetime_tx = p.lifetime_tx;
    usage.standby_today = if p.usage.standby_day == today.ymd() { p.usage.standby_bytes } else { 0 };
    let notify = {
        let n = lock(&o.notify);
        NotifyView { sent: n.sent.clone(), failed: n.failed.clone(), suppressed: n.suppressed.clone(), dropped: n.dropped }
    };
    let dataplane = crate::dataplane::metrics_view().await;
    let phy = state.phy_diag.read().await.clone();
    let dsp = state.dsp_telemetry.read().await.clone();
    let tls_cert = state.tls_cert_info.read().await.clone();

    MetricsInput {
        version: state.version.clone(),
        now,
        modem,
        rx_bps,
        tx_bps,
        ping,
        memory,
        internals,
        device_uptime,
        session_uptime,
        quecwatch_enabled,
        quecwatch,
        last_speedtest,
        at,
        events,
        failover,
        usage,
        notify,
        dataplane,
        phy,
        dsp,
        tls_cert,
        cell_lock_active,
        cell_lock_bypassed,
    }
}

pub async fn render_state(state: &AppState) -> String {
    render(&gather(state).await)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

pub fn label_value(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars().filter(|c| !c.is_control()).take(MAX_LABEL_LEN) {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out
}

fn fmt_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

struct Prom {
    out: String,
}

impl Prom {
    fn head(&mut self, name: &str, help: &str, kind: &str) {
        let _ = writeln!(self.out, "# HELP cellcore_{name} {help}");
        let _ = writeln!(self.out, "# TYPE cellcore_{name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], v: f64) {
        self.out.push_str("cellcore_");
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (k, val)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{k}=\"{}\"", label_value(val));
            }
            self.out.push('}');
        }
        self.out.push(' ');
        self.out.push_str(&fmt_value(v));
        self.out.push('\n');
    }

    fn gauge(&mut self, name: &str, help: &str, v: f64) {
        self.head(name, help, "gauge");
        self.sample(name, &[], v);
    }

    fn counter(&mut self, name: &str, help: &str, v: f64) {
        self.head(name, help, "counter");
        self.sample(name, &[], v);
    }

    fn opt_gauge(&mut self, name: &str, help: &str, v: Option<f64>) {
        if let Some(v) = v.filter(|v| v.is_finite()) {
            self.gauge(name, help, v);
        }
    }
}

fn b(v: bool) -> f64 {
    if v { 1.0 } else { 0.0 }
}

pub const QUECWATCH_STATES: [&str; 6] = ["idle", "healthy", "degraded", "failing", "recovering", "disabled"];

pub fn render(m: &MetricsInput) -> String {
    let mut p = Prom { out: String::with_capacity(12 * 1024) };

    p.head("build_info", "Daemon version.", "gauge");
    p.sample("build_info", &[("version", &m.version)], 1.0);

    // --- radio -----------------------------------------------------------
    let modem = &m.modem;
    p.gauge(
        "snapshot_age_seconds",
        "Seconds since the cached modem snapshot was refreshed.",
        if modem.updated_at == 0 { -1.0 } else { m.now.saturating_sub(modem.updated_at) as f64 },
    );
    p.gauge("cfun", "Modem functionality level (AT+CFUN, 1 = full).", f64::from(modem.identity.cfun));
    for (name, help, vals) in [
        ("rsrp_dbm", "Per-chain RSRP (dBm).", &modem.mimo.rsrp),
        ("rsrq_db", "Per-chain RSRQ (dB).", &modem.mimo.rsrq),
        ("sinr_db", "Per-chain SINR (dB).", &modem.mimo.sinr),
    ] {
        let present: Vec<(usize, f64)> =
            vals.iter().take(4).enumerate().filter_map(|(i, v)| v.filter(|v| v.is_finite()).map(|v| (i, v))).collect();
        if !present.is_empty() {
            p.head(name, help, "gauge");
            for (i, v) in present {
                p.sample(name, &[("chain", &i.to_string())], v);
            }
        }
    }
    let registered = match modem.serving.as_ref().map(|s| s.state.to_ascii_uppercase()) {
        _ if modem.identity.cfun != 1 => 0.0,
        Some(s) if s == "NOCONN" || s == "CONNECT" => 1.0,
        _ => 0.0,
    };
    p.gauge("registered", "1 when registered on the network.", registered);
    let present_rsrp: Vec<f64> = modem
        .mimo
        .rsrp
        .iter()
        .take(4)
        .filter_map(|v| v.filter(|x| x.is_finite()))
        .collect();
    if registered == 1.0 {
        p.head(
            "antenna_chain_present",
            "1 if the receive antenna chain reports a valid RSRP reading, 0 otherwise.",
            "gauge",
        );
        for i in 0..4 {
            let ok = modem
                .mimo
                .rsrp
                .get(i)
                .and_then(|v| *v)
                .is_some_and(f64::is_finite);
            p.sample("antenna_chain_present", &[("chain", &i.to_string())], b(ok));
        }
    }
    if registered == 1.0 || !present_rsrp.is_empty() {
        p.gauge(
            "antenna_active_chains",
            "Number of active receive antenna chains reporting RSRP.",
            present_rsrp.len() as f64,
        );
    }
    if !present_rsrp.is_empty() {
        let max_r = present_rsrp.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min_r = present_rsrp.iter().copied().fold(f64::INFINITY, f64::min);
        let spread = ((max_r - min_r) * 100.0).round() / 100.0;
        p.gauge(
            "antenna_rsrp_spread_db",
            "RSRP spread (max - min, dB) across active receive antenna chains.",
            spread,
        );
    }
    if let Some(s) = modem.serving.as_ref() {
        p.head("serving_cell_info", "Serving cell identity (value is always 1).", "gauge");
        p.sample(
            "serving_cell_info",
            &[
                ("rat", &s.rat),
                ("band", &s.band),
                ("pci", &s.pci.map(|v| v.to_string()).unwrap_or_default()),
                ("arfcn", &s.arfcn.map(|v| v.to_string()).unwrap_or_default()),
                ("state", &s.state),
                ("duplex", &s.duplex_mode),
            ],
            1.0,
        );
        p.opt_gauge("serving_rsrp_dbm", "Serving cell RSRP (dBm).", s.rsrp);
        p.opt_gauge("serving_rsrq_db", "Serving cell RSRQ (dB).", s.rsrq);
        p.opt_gauge("serving_sinr_db", "Serving cell SINR (dB).", s.sinr);
        p.opt_gauge("tx_power_dbm", "UE transmit power reported for the serving cell (dBm).", s.tx_power);
        p.opt_gauge("nsa_nr5g_rsrp_dbm", "EN-DC 5G NR NSA secondary leg RSRP (dBm).", s.nsa_nr5g_rsrp);
        p.opt_gauge("nsa_nr5g_sinr_db", "EN-DC 5G NR NSA secondary leg SINR (dB).", s.nsa_nr5g_sinr);
    }
    let ca_mhz: f64 = modem.carriers.iter().filter_map(|c| c.bandwidth_mhz).sum();
    p.gauge("ca_components", "Aggregated component carriers (PCC + SCCs).", modem.carriers.len() as f64);
    p.gauge("ca_bandwidth_mhz", "Total aggregated downlink bandwidth (MHz).", ca_mhz);
    let ul_carriers_count = modem.carriers.iter().filter(|c| c.ul_configured).count();
    let scc_ul = modem
        .carriers
        .iter()
        .any(|c| c.role.eq_ignore_ascii_case("SCC") && c.ul_configured);
    p.gauge(
        "ul_ca_active",
        "1 when uplink carrier aggregation (UL CA) is active.",
        b(ul_carriers_count > 1 || scc_ul),
    );
    let ul_bw_mhz: f64 = if !modem.carriers.is_empty() {
        modem
            .carriers
            .iter()
            .filter(|c| c.ul_configured)
            .filter_map(|c| {
                if c.role.eq_ignore_ascii_case("PCC") {
                    c.ul_bandwidth_mhz
                        .or_else(|| modem.serving.as_ref().and_then(|s| s.ul_bandwidth_mhz))
                        .or(c.bandwidth_mhz)
                } else {
                    c.ul_bandwidth_mhz.or(c.bandwidth_mhz)
                }
            })
            .sum()
    } else {
        modem
            .serving
            .as_ref()
            .and_then(|s| s.ul_bandwidth_mhz)
            .unwrap_or(0.0)
    };
    p.gauge("ul_bandwidth_mhz", "Total configured uplink bandwidth (MHz).", ul_bw_mhz);
    if !modem.carriers.is_empty() {
        p.head("ca_component_bandwidth_mhz", "Bandwidth of each component carrier (MHz).", "gauge");
        for (i, c) in modem.carriers.iter().take(8).enumerate() {
            p.sample(
                "ca_component_bandwidth_mhz",
                &[("index", &i.to_string()), ("role", &c.role), ("band", &c.band)],
                c.bandwidth_mhz.unwrap_or(0.0),
            );
        }
        let has_dl_mimo = modem.carriers.iter().any(|c| c.dl_mimo_layers.is_some());
        if has_dl_mimo {
            p.head("ca_component_dl_mimo_layers", "Downlink MIMO layers reported per component carrier.", "gauge");
            for (i, c) in modem.carriers.iter().take(8).enumerate() {
                if let Some(dl) = c.dl_mimo_layers {
                    p.sample(
                        "ca_component_dl_mimo_layers",
                        &[("index", &i.to_string()), ("role", &c.role), ("band", &c.band)],
                        f64::from(dl),
                    );
                }
            }
        }
        let has_ul_mimo = modem.carriers.iter().any(|c| c.ul_mimo_layers.is_some());
        if has_ul_mimo {
            p.head("ca_component_ul_mimo_layers", "Uplink MIMO layers reported per component carrier.", "gauge");
            for (i, c) in modem.carriers.iter().take(8).enumerate() {
                if let Some(ul) = c.ul_mimo_layers {
                    p.sample(
                        "ca_component_ul_mimo_layers",
                        &[("index", &i.to_string()), ("role", &c.role), ("band", &c.band)],
                        f64::from(ul),
                    );
                }
            }
        }
    }
    let ta = &modem.time_advance;
    if ta.lte_ta.is_some() || ta.nr5g_raw.is_some() {
        p.head("timing_advance", "Timing advance in RAT-native units.", "gauge");
        if let Some(v) = ta.lte_ta {
            p.sample("timing_advance", &[("rat", "lte")], v as f64);
        }
        if let Some(v) = ta.nr5g_raw {
            p.sample("timing_advance", &[("rat", "nr")], v as f64);
        }
    }
    p.opt_gauge("timing_advance_meters", "Distance to the serving cell implied by timing advance (m).", ta.active_meters.map(|v| v as f64));
    if !modem.thermals.is_empty() {
        p.head("temperature_celsius", "Modem thermal sensors (°C).", "gauge");
        for t in modem.thermals.iter().take(24) {
            p.sample("temperature_celsius", &[("sensor", &t.sensor)], t.celsius);
        }
    }

    // --- AT channel ------------------------------------------------------
    let at = &m.at;
    p.gauge("at_channel_healthy", "1 while the AT device is open and answering.", b(at.healthy));
    p.gauge("at_queue_depth", "AT requests waiting or executing.", at.queued as f64);
    p.counter("at_commands_total", "AT commands written to the modem.", at.commands as f64);
    p.head("at_failures_total", "AT commands that did not complete normally, by kind.", "counter");
    for (k, v) in [("error", at.errors), ("timeout", at.timeouts), ("preempted", at.preempted), ("io", at.broken)] {
        p.sample("at_failures_total", &[("kind", k)], v as f64);
    }
    p.head("at_latency_seconds", "AT command round-trip latency.", "histogram");
    let mut cum = 0u64;
    for (i, le) in LATENCY_BUCKETS_MS.iter().enumerate() {
        cum += at.buckets.get(i).copied().unwrap_or(0);
        p.sample("at_latency_seconds_bucket", &[("le", &fmt_value(*le as f64 / 1000.0))], cum as f64);
    }
    p.sample("at_latency_seconds_bucket", &[("le", "+Inf")], at.latency_count as f64);
    p.sample("at_latency_seconds_sum", &[], at.latency_sum_ms as f64 / 1000.0);
    p.sample("at_latency_seconds_count", &[], at.latency_count as f64);
    p.gauge("at_last_latency_seconds", "Latency of the most recent AT command.", at.last_latency_ms as f64 / 1000.0);

    // --- traffic / usage ---------------------------------------------------
    p.head("wan_throughput_bps", "Current rmnet throughput (bit/s).", "gauge");
    p.sample("wan_throughput_bps", &[("direction", "rx")], m.rx_bps as f64);
    p.sample("wan_throughput_bps", &[("direction", "tx")], m.tx_bps as f64);
    let u = &m.usage;
    p.head("data_cycle_bytes", "Bytes used in the current billing cycle.", "gauge");
    p.sample("data_cycle_bytes", &[("direction", "rx")], u.cycle_rx as f64);
    p.sample("data_cycle_bytes", &[("direction", "tx")], u.cycle_tx as f64);
    p.gauge("data_cycle_projected_bytes", "Projected total at the end of the billing cycle.", u.projected as f64);
    p.gauge("data_cycle_days", "Length of the current billing cycle (days).", u.cycle_days as f64);
    p.gauge("data_cycle_days_elapsed", "Days into the current billing cycle.", (u.days_elapsed * 100.0).round() / 100.0);
    if let Some(q) = u.quota {
        p.gauge("data_quota_bytes", "Configured data quota per cycle.", q as f64);
        if q > 0 {
            p.gauge("data_cycle_used_ratio", "Cycle usage as a fraction of the quota.", (u.cycle_rx + u.cycle_tx) as f64 / q as f64);
        }
    }
    p.head("data_today_bytes", "Bytes used today (local date).", "gauge");
    p.sample("data_today_bytes", &[("direction", "rx")], u.today_rx as f64);
    p.sample("data_today_bytes", &[("direction", "tx")], u.today_tx as f64);
    p.head("data_lifetime_bytes", "Bytes carried since accounting began.", "counter");
    p.sample("data_lifetime_bytes", &[("direction", "rx")], u.lifetime_rx as f64);
    p.sample("data_lifetime_bytes", &[("direction", "tx")], u.lifetime_tx as f64);
    p.gauge("standby_bytes_today", "Bytes today while not carrying failover traffic.", u.standby_today as f64);

    // --- latency -----------------------------------------------------------
    if let Some(last) = m.ping.first() {
        p.gauge("ping_up", "1 if the most recent ping got a reply.", b(last.ok));
        let oks: Vec<f64> = m.ping.iter().filter(|x| x.ok).map(|x| x.latency).collect();
        p.opt_gauge("ping_latency_ms", "Most recent ping round-trip (ms).", last.ok.then_some(last.latency));
        if !oks.is_empty() {
            p.gauge("ping_latency_avg_ms", "Mean ping round-trip over the recent window (ms).", oks.iter().sum::<f64>() / oks.len() as f64);
        }
        p.gauge(
            "ping_loss_ratio",
            "Fraction of recent pings without a reply.",
            m.ping.iter().filter(|x| !x.ok).count() as f64 / m.ping.len() as f64,
        );
    }

    // --- LinkWatch / speedtest -------------------------------------------
    p.gauge("quecwatch_enabled", "1 when LinkWatch is enabled.", b(m.quecwatch_enabled));
    let qs = if m.quecwatch_enabled { m.quecwatch.status.as_str() } else { "disabled" };
    let qs = if QUECWATCH_STATES.contains(&qs) { qs } else { "idle" };
    p.head("quecwatch_state", "LinkWatch state (one-hot).", "gauge");
    for s in QUECWATCH_STATES {
        p.sample("quecwatch_state", &[("state", s)], b(s == qs));
    }
    p.gauge("quecwatch_retry", "Current LinkWatch recovery attempt.", f64::from(m.quecwatch.retry));
    p.gauge("cell_lock_active", "1 when a 4G/5G cell lock is configured and actively engaged.", b(m.cell_lock_active));
    p.gauge("cell_lock_bypassed", "1 when the dead-man's-switch has temporarily bypassed a configured cell lock.", b(m.cell_lock_bypassed));
    if let Some(st) = m.last_speedtest.as_ref() {
        p.gauge("speedtest_last_timestamp_seconds", "When the last speedtest finished (unix).", (st.ts / if st.ts > 10_000_000_000 { 1000 } else { 1 }) as f64);
        p.gauge("speedtest_last_download_mbps", "Last speedtest download (Mbit/s).", st.download_mbps);
        p.gauge("speedtest_last_upload_mbps", "Last speedtest upload (Mbit/s).", st.upload_mbps);
        p.gauge("speedtest_last_ping_ms", "Last speedtest idle latency (ms).", st.ping_ms);
        p.gauge("speedtest_last_jitter_ms", "Last speedtest jitter (ms).", st.jitter_ms);
        p.opt_gauge(
            "speedtest_dl_loaded_latency_ms",
            "Last speedtest download loaded latency IQM (ms).",
            st.dl_latency_iqm,
        );
        p.opt_gauge(
            "speedtest_ul_loaded_latency_ms",
            "Last speedtest upload loaded latency IQM (ms).",
            st.ul_latency_iqm,
        );
    }

    // --- system ------------------------------------------------------------
    let mem = &m.memory;
    if mem.total > 0 {
        p.head("memory_bytes", "System memory.", "gauge");
        p.sample("memory_bytes", &[("type", "total")], mem.total as f64);
        p.sample("memory_bytes", &[("type", "used")], mem.used as f64);
        p.sample("memory_bytes", &[("type", "available")], mem.available as f64);
    }
    let i = &m.internals;
    p.gauge("conntrack_entries", "Netfilter conntrack entries.", i.conntrack_count as f64);
    p.gauge("conntrack_max", "Netfilter conntrack table limit.", i.conntrack_max as f64);
    if i.usrdata_total_bytes > 0 {
        p.head("flash_bytes", "/usrdata flash usage.", "gauge");
        p.sample("flash_bytes", &[("type", "total")], i.usrdata_total_bytes as f64);
        p.sample("flash_bytes", &[("type", "used")], i.usrdata_used_bytes as f64);
        p.sample("flash_bytes", &[("type", "available")], i.usrdata_avail_bytes as f64);
    }
    p.gauge("device_uptime_seconds", "Modem OS uptime.", m.device_uptime as f64);
    p.gauge("wan_up", "1 when the cellular WAN interface is up.", b(m.session_uptime.is_some()));
    if let Some(s) = m.session_uptime.as_ref() {
        p.gauge("wan_session_uptime_seconds", "Current WAN session uptime.", s.uptime_seconds as f64);
        if let Some(d) = s.disconnect_count {
            p.counter("wan_disconnects_total", "WAN session drops seen by this daemon run.", f64::from(d));
        }
    }

    // --- events / failover / notifications ------------------------------
    p.head("events_total", "Events recorded since daemon start, by type.", "counter");
    for k in EventKind::ALL {
        p.sample("events_total", &[("type", k.as_str())], m.events.get(&k).copied().unwrap_or(0) as f64);
    }
    let f = &m.failover;
    p.gauge("failover_active", "1 while the modem is carrying failover (production) traffic.", b(f.active));
    p.head("failover_source", "What decided the failover state (one-hot; all 0 in standby).", "gauge");
    for (name, src) in [("hint", Source::Hint), ("throughput", Source::Throughput)] {
        p.sample("failover_source", &[("source", name)], b(f.active && f.source == Some(src)));
    }
    p.gauge("failover_hint_fresh", "1 while a Route10 role hint is fresh.", b(f.hint_fresh));
    p.gauge("failover_avg_bps", "Throughput average used for failover detection (bit/s).", f.avg_bps as f64);
    p.gauge("failover_baseline_bps", "Configured failover throughput baseline (bit/s).", f.baseline_bps as f64);
    p.counter("failover_episodes_total", "Failover episodes started.", f.episodes_total as f64);
    p.gauge("failover_episode_seconds", "Duration of the current episode (0 in standby).", f.episode_secs as f64);
    p.gauge("failover_episode_bytes", "Bytes carried in the current episode.", f.episode_bytes as f64);
    let n = &m.notify;
    p.head("notifications_sent_total", "Notifications delivered, by sink.", "counter");
    for s in notify::SINKS {
        p.sample("notifications_sent_total", &[("sink", s)], n.sent.get(s).copied().unwrap_or(0) as f64);
    }
    p.head("notifications_failed_total", "Notification deliveries that failed, by sink.", "counter");
    for s in notify::SINKS {
        p.sample("notifications_failed_total", &[("sink", s)], n.failed.get(s).copied().unwrap_or(0) as f64);
    }
    p.head("notifications_suppressed_total", "Events not notified, by reason.", "counter");
    for r in notify::Suppress::ALL {
        p.sample("notifications_suppressed_total", &[("reason", r.as_str())], n.suppressed.get(r.as_str()).copied().unwrap_or(0) as f64);
    }
    p.counter("notifications_dropped_total", "Events dropped because the notifier queue was full.", n.dropped as f64);

    // --- native dataplane -----------------------------------------------
    let dp = &m.dataplane;
    p.opt_gauge(
        "ipa_hardware_offload_pct",
        "Percentage of Ethernet packets offloaded in Qualcomm IPA hardware.",
        dp.ipa_hardware_offload_pct.map(f64::from),
    );
    p.counter(
        "qrtr_ssr_total",
        "Modem subsystem restarts (SSR) observed on the QRTR control bus.",
        dp.qrtr_ssr_total as f64,
    );
    if !dp.mode.is_empty() {
        p.head("dataplane_mode", "Active dataplane mode (one-hot: native or legacy).", "gauge");
        for mode in ["native", "legacy"] {
            p.sample("dataplane_mode", &[("mode", mode)], b(dp.mode == mode));
        }
        p.head("dataplane_wds_connected", "1 when the native QMI WDS session for the IP family is connected.", "gauge");
        p.sample("dataplane_wds_connected", &[("family", "v4")], b(dp.wds_v4_connected));
        p.sample("dataplane_wds_connected", &[("family", "v6")], b(dp.wds_v6_connected));
        p.opt_gauge("dataplane_ipa_clk_mhz", "Current Qualcomm IPA hardware offload clock rate (MHz).", dp.ipa_clk_mhz.map(|v| v as f64));
        p.gauge("dataplane_tuning_warnings", "Number of active high-throughput kernel tuning warnings.", dp.tuning_warnings as f64);
        p.counter("dataplane_indications_total", "QMI indications received by the native dataplane supervisor.", dp.indications_total as f64);
        p.counter("dataplane_netlink_updates_total", "Netlink address/route applies performed by the native dataplane.", dp.netlink_updates_total as f64);
    }

    // --- SDX75 PHY / QoS / Security telemetry ---------------------------
    let phy = &m.phy;
    if let Some(csi) = phy.nr5g_csi.as_ref() {
        p.gauge("nr5g_csi_ri", "5G NR Channel State Information Rank Indicator (RI).", f64::from(csi.ri));
        p.gauge("nr5g_csi_cqi", "5G NR Channel State Information Channel Quality Indicator (CQI).", f64::from(csi.cqi));
    }
    if let Some(tx) = phy.nr5g_tx_pwr_detail.as_ref() {
        p.head("nr5g_tx_power_dbm", "5G NR uplink transmit power by channel (dBm).", "gauge");
        p.sample("nr5g_tx_power_dbm", &[("channel", "pusch")], f64::from(tx.pusch_dbm));
        p.sample("nr5g_tx_power_dbm", &[("channel", "pucch")], f64::from(tx.pucch_dbm));
        p.sample("nr5g_tx_power_dbm", &[("channel", "max")], f64::from(tx.max_dbm));
        p.sample("nr5g_tx_power_dbm", &[("channel", "srs")], f64::from(tx.srs_dbm));
        p.gauge("nr5g_tx_headroom_db", "5G NR HPUE uplink power headroom (max - PUSCH, dB).", f64::from(tx.headroom_db));
    }
    p.opt_gauge("nr5g_pathloss_db", "5G NR RF pathloss between gNodeB and UE (dB).", phy.nr5g_pathloss_db.map(f64::from));
    if let Some(dl) = phy.nr5g_dl_mcs.as_ref() {
        p.gauge("nr5g_dl_mcs", "5G NR downlink Modulation and Coding Scheme index.", f64::from(dl.mcs));
        p.gauge("nr5g_dl_mod_order", "5G NR downlink modulation order (0=QPSK,1=16QAM,2=64QAM,3=256QAM).", f64::from(dl.mod_order));
    }
    if let Some(ul) = phy.nr5g_ul_mcs.as_ref() {
        p.gauge("nr5g_ul_mcs", "5G NR uplink Modulation and Coding Scheme index.", f64::from(ul.mcs));
        p.gauge("nr5g_ul_mod_order", "5G NR uplink modulation order (0=QPSK,1=16QAM,2=64QAM,3=256QAM).", f64::from(ul.mod_order));
    }
    p.opt_gauge("nr5g_mimo_layers", "5G NR active MIMO spatial layers.", phy.nr5g_mimo_layers.map(f64::from));
    p.opt_gauge(
        "nr5g_active_rank",
        "5G NR active spatial MIMO rank.",
        phy.nr5g_active_rank.or(phy.nr5g_mimo_layers).map(f64::from),
    );
    if let Some(beam) = phy.ssb_beams.iter().find(|b| b.is_serving).or_else(|| phy.ssb_beams.first()) {
        p.gauge("nr5g_ssb_beam_id", "Serving 5G NR Synchronization Signal Block (SSB) beam index.", f64::from(beam.beam_id));
    }
    if !phy.qos_bearers.is_empty() {
        p.head("nr5g_five_qi", "Carrier-provisioned 5G QoS Identifier (5QI) per PDU session.", "gauge");
        for q in phy.qos_bearers.iter().take(8) {
            p.sample(
                "nr5g_five_qi",
                &[("apn", &q.apn), ("qfi", &q.qfi.to_string())],
                f64::from(q.five_qi),
            );
        }
    }
    if !phy.ambr_caps.is_empty() {
        p.head("nr5g_ambr_mbps", "Carrier-provisioned Session-AMBR bandwidth cap (Mbit/s).", "gauge");
        for a in phy.ambr_caps.iter().take(8) {
            p.sample("nr5g_ambr_mbps", &[("apn", &a.apn), ("direction", "dl")], a.dl_mbps as f64);
            p.sample("nr5g_ambr_mbps", &[("apn", &a.apn), ("direction", "ul")], a.ul_mbps as f64);
        }
    }
    if let Some(sec) = phy.air_security.as_ref() {
        p.gauge(
            "air_cipher_null",
            "1 if connected on a null air-interface cipher (NEA0/EEA0); 0 when encrypted or RRC idle.",
            b(sec.null_cipher_alert),
        );
    }
    if let Some(rrc) = phy.rrc_state.as_ref() {
        p.gauge("rrc_state_code", "RRC state code (0=disconnected, 1=idle, 2=connected, 3=inactive).", f64::from(rrc.state_code));
    }

    // --- SDX75 QRTR QMI DSP telemetry (TMD thermal + SAR backoff) -------
    let dsp = &m.dsp;
    if dsp.qrtr_available {
        p.gauge("qmi_tmd_throttling", "1 when any QMI Thermal Mitigation Device is actively throttling.", b(dsp.any_throttling));
        if !dsp.tmd_devices.is_empty() {
            p.head("qmi_tmd_mitigation_level", "Current QMI TMD thermal mitigation level per DSP device.", "gauge");
            for d in dsp.tmd_devices.iter().take(24) {
                p.sample("qmi_tmd_mitigation_level", &[("device", &d.name)], f64::from(d.current_level));
            }
        }
        p.opt_gauge("qmi_sar_state", "Current QMI SAR RF transmit backoff state (0 = no backoff).", dsp.sar_rf_state.map(f64::from));
    }

    // --- TLS certificate health -----------------------------------------
    let cert = &m.tls_cert;
    if !cert.source.is_empty() {
        p.gauge("tls_cert_acme_active", "1 when HTTPS is serving an ACME-issued certificate.", b(cert.source == "acme"));
        p.opt_gauge(
            "tls_cert_days_remaining",
            "Days remaining until the active HTTPS TLS certificate expires.",
            cert.days_remaining.map(|d| d as f64),
        );
    }

    p.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{CarrierComponent, ServingCellInfo, TempSensor};

    fn sample_input() -> MetricsInput {
        let mut m = MetricsInput { version: "4.1.1".into(), now: 1000, ..Default::default() };
        m.modem.updated_at = 990;
        m.modem.identity.cfun = 1;
        m.modem.mimo.rsrp = vec![Some(-95.0), Some(-101.5), None, Some(-140.0)];
        m.modem.mimo.sinr = vec![Some(12.0)];
        m.modem.serving = Some(ServingCellInfo {
            state: "NOCONN".into(),
            rat: "NR5G-SA".into(),
            band: "n41".into(),
            pci: Some(258),
            arfcn: Some(521310),
            tx_power: Some(-3.0),
            duplex_mode: "TDD".into(),
            ..Default::default()
        });
        m.modem.carriers = vec![
            CarrierComponent { role: "PCC".into(), band: "n41".into(), bandwidth_mhz: Some(100.0), ..Default::default() },
            CarrierComponent { role: "SCC".into(), band: "n25".into(), bandwidth_mhz: Some(20.0), ..Default::default() },
        ];
        m.modem.thermals = vec![TempSensor { sensor: "modem-lte-sub6-pa1".into(), celsius: 41.5, domain: String::new() }];
        m.at = AtStatsView { healthy: true, queued: 2, commands: 10, buckets: vec![1, 2, 3, 0, 0, 0, 0, 1], latency_count: 8, latency_sum_ms: 9000, ..Default::default() };
        m.events.insert(EventKind::Handover, 3);
        m.failover = FailoverView { active: true, source: Some(Source::Hint), episodes_total: 1, ..Default::default() };
        m.ping = vec![
            PingPoint { timestamp: String::new(), ts: 0, host: String::new(), latency: 30.0, packet_loss: 0.0, ok: true },
            PingPoint { timestamp: String::new(), ts: 0, host: String::new(), latency: 0.0, packet_loss: 100.0, ok: false },
        ];
        m.usage.quota = Some(1000);
        m.usage.cycle_rx = 400;
        m.usage.cycle_tx = 100;
        m
    }

    fn line_value(text: &str, prefix: &str) -> Option<String> {
        text.lines().find(|l| l.starts_with(prefix)).and_then(|l| l.rsplit(' ').next()).map(str::to_string)
    }

    #[test]
    fn renders_core_series() {
        let t = render(&sample_input());
        assert_eq!(line_value(&t, "cellcore_rsrp_dbm{chain=\"1\"}").as_deref(), Some("-101.5"));
        assert!(!t.contains("cellcore_rsrp_dbm{chain=\"2\"}"), "missing chain omitted");
        assert!(t.contains("cellcore_serving_cell_info{rat=\"NR5G-SA\",band=\"n41\",pci=\"258\",arfcn=\"521310\",state=\"NOCONN\",duplex=\"TDD\"} 1\n"));
        assert_eq!(line_value(&t, "cellcore_registered ").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_ca_components ").as_deref(), Some("2"));
        assert_eq!(line_value(&t, "cellcore_ca_bandwidth_mhz ").as_deref(), Some("120"));
        assert_eq!(line_value(&t, "cellcore_tx_power_dbm ").as_deref(), Some("-3"));
        assert_eq!(line_value(&t, "cellcore_snapshot_age_seconds ").as_deref(), Some("10"));
        assert_eq!(line_value(&t, "cellcore_events_total{type=\"handover\"}").as_deref(), Some("3"));
        assert_eq!(line_value(&t, "cellcore_events_total{type=\"ca_change\"}").as_deref(), Some("0"), "all types always present");
        assert_eq!(line_value(&t, "cellcore_failover_active ").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_failover_source{source=\"hint\"}").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_ping_loss_ratio ").as_deref(), Some("0.5"));
        assert_eq!(line_value(&t, "cellcore_data_cycle_used_ratio ").as_deref(), Some("0.5"));
        assert_eq!(line_value(&t, "cellcore_quecwatch_state{state=\"disabled\"}").as_deref(), Some("1"));
        assert!(t.contains("cellcore_temperature_celsius{sensor=\"modem-lte-sub6-pa1\"} 41.5\n"));
    }

    #[test]
    fn histogram_is_cumulative_and_consistent() {
        let t = render(&sample_input());
        let buckets: Vec<f64> = t
            .lines()
            .filter(|l| l.starts_with("cellcore_at_latency_seconds_bucket"))
            .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(buckets, vec![1.0, 3.0, 6.0, 6.0, 6.0, 6.0, 6.0, 7.0, 8.0]);
        assert!(buckets.windows(2).all(|w| w[0] <= w[1]));
        assert!(t.contains("cellcore_at_latency_seconds_bucket{le=\"0.025\"} 1\n"));
        assert!(t.contains("cellcore_at_latency_seconds_bucket{le=\"+Inf\"} 8\n"));
        assert_eq!(line_value(&t, "cellcore_at_latency_seconds_sum").as_deref(), Some("9"));
        assert_eq!(line_value(&t, "cellcore_at_queue_depth").as_deref(), Some("2"));
    }

    #[test]
    fn exposition_is_well_formed() {
        let t = render(&sample_input());
        let mut typed = std::collections::HashSet::new();
        for line in t.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split(' ').next().unwrap();
                assert!(typed.insert(name.to_string()), "duplicate TYPE for {name}");
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let (series, value) = line.rsplit_once(' ').expect("name value");
            assert!(value == "+Inf" || value == "NaN" || value.parse::<f64>().is_ok(), "{line}");
            let name = series.split('{').next().unwrap();
            assert!(name.starts_with("cellcore_"));
            assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "{name}");
            let family = name.trim_end_matches("_bucket").trim_end_matches("_sum").trim_end_matches("_count");
            assert!(typed.contains(name) || typed.contains(family), "sample before TYPE: {name}");
        }
    }

    #[test]
    fn hostile_label_values_are_escaped_and_capped() {
        let mut m = sample_input();
        m.modem.thermals = vec![TempSensor { sensor: format!("a\"b\\c\nd{}", "x".repeat(200)), celsius: 1.0, domain: String::new() }];
        let t = render(&m);
        let line = t.lines().find(|l| l.starts_with("cellcore_temperature_celsius{")).unwrap();
        assert!(line.starts_with("cellcore_temperature_celsius{sensor=\"a\\\"b\\\\cd"), "{line}");
        assert!(line.len() < 120);
    }

    #[test]
    fn empty_state_renders_without_panicking() {
        let t = render(&MetricsInput::default());
        assert!(t.contains("cellcore_snapshot_age_seconds -1\n"));
        assert!(!t.contains("serving_cell_info{"));
        assert_eq!(line_value(&t, "cellcore_registered ").as_deref(), Some("0"));
    }

    #[test]
    fn renders_sdx75_phy_and_qmi_dsp_metrics() {
        let mut m = sample_input();
        m.phy.nr5g_tx_pwr_detail = Some(crate::radio_tuning::TxPowerDetail {
            pusch_dbm: 24,
            pucch_dbm: 18,
            max_dbm: 26,
            srs_dbm: 0,
            headroom_db: 2,
        });
        m.phy.nr5g_pathloss_db = Some(114);
        m.phy.nr5g_dl_mcs = Some(crate::radio_tuning::McsDetail {
            mcs: 28,
            mod_order: 3,
            modulation: "256QAM".into(),
        });
        m.phy.nr5g_mimo_layers = Some(4);
        m.phy.qos_bearers.push(crate::radio_tuning::QosBearerEntry {
            cid: 1,
            apn: "fast.t-mobile.com".into(),
            qfi: 1,
            five_qi: 6,
            priority_label: "Postpaid Priority (5QI 6)".into(),
        });
        m.phy.air_security = Some(crate::radio_tuning::AirSecurityInfo {
            rat: "NR5G".into(),
            cipher_id: 2,
            cipher_name: "128-NEA2 (AES-CTR)".into(),
            integrity_id: 2,
            integrity_name: "128-NIA2 (AES-CMAC)".into(),
            null_cipher_alert: false,
        });
        m.dsp.qrtr_available = true;
        m.dsp.sar_rf_state = Some(0);
        m.dsp.tmd_devices.push(crate::qmi::dsp::TmdDeviceInfo {
            name: "pa".into(),
            max_level: 3,
            current_level: 0,
            requested_level: 0,
            throttling: false,
        });

        let t = render(&m);
        assert_eq!(line_value(&t, "cellcore_nr5g_tx_power_dbm{channel=\"pusch\"}").as_deref(), Some("24"));
        assert_eq!(line_value(&t, "cellcore_nr5g_tx_headroom_db ").as_deref(), Some("2"));
        assert_eq!(line_value(&t, "cellcore_nr5g_pathloss_db ").as_deref(), Some("114"));
        assert_eq!(line_value(&t, "cellcore_nr5g_dl_mcs ").as_deref(), Some("28"));
        assert_eq!(line_value(&t, "cellcore_nr5g_mimo_layers ").as_deref(), Some("4"));
        assert_eq!(line_value(&t, "cellcore_nr5g_five_qi{apn=\"fast.t-mobile.com\",qfi=\"1\"}").as_deref(), Some("6"));
        assert_eq!(line_value(&t, "cellcore_air_cipher_null ").as_deref(), Some("0"));
        assert_eq!(line_value(&t, "cellcore_qmi_tmd_throttling ").as_deref(), Some("0"));
        assert_eq!(line_value(&t, "cellcore_qmi_tmd_mitigation_level{device=\"pa\"}").as_deref(), Some("0"));
        assert_eq!(line_value(&t, "cellcore_qmi_sar_state ").as_deref(), Some("0"));
    }

    #[test]
    fn renders_v140_antenna_ul_ca_nsa_speedtest_and_ipa_metrics() {
        let mut m = sample_input();
        // RX0=-90, RX1=-96, RX2=None, RX3=-102 -> 3 active chains, spread = 12 dB
        m.modem.mimo.rsrp = vec![Some(-90.0), Some(-96.0), None, Some(-102.0)];
        if let Some(s) = m.modem.serving.as_mut() {
            s.nsa_nr5g_rsrp = Some(-93.5);
            s.nsa_nr5g_sinr = Some(16.0);
        }
        m.modem.carriers = vec![
            CarrierComponent {
                role: "PCC".into(),
                band: "n41".into(),
                bandwidth_mhz: Some(100.0),
                ul_configured: true,
                ul_bandwidth_mhz: Some(100.0),
                ..Default::default()
            },
            CarrierComponent {
                role: "SCC".into(),
                band: "n41".into(),
                bandwidth_mhz: Some(40.0),
                ul_configured: true,
                ul_bandwidth_mhz: Some(40.0),
                ..Default::default()
            },
        ];
        m.phy.nr5g_csi = Some(crate::radio_tuning::CsiMetrics {
            mcs: 27,
            ri: 4,
            cqi: 15,
            pmi: 3,
        });
        m.phy.nr5g_active_rank = Some(4);
        m.last_speedtest = Some(SpeedtestRun {
            ts: 1_700_000_000,
            download_mbps: 820.0,
            upload_mbps: 115.0,
            ping_ms: 18.0,
            jitter_ms: 2.5,
            dl_latency_iqm: Some(31.5),
            ul_latency_iqm: Some(44.0),
            ..Default::default()
        });
        m.dataplane.mode = "native";
        m.dataplane.ipa_hardware_offload_pct = Some(98);
        m.dataplane.qrtr_ssr_total = 2;

        let t = render(&m);
        assert_eq!(line_value(&t, "cellcore_antenna_chain_present{chain=\"0\"}").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_antenna_chain_present{chain=\"1\"}").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_antenna_chain_present{chain=\"2\"}").as_deref(), Some("0"));
        assert_eq!(line_value(&t, "cellcore_antenna_chain_present{chain=\"3\"}").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_antenna_active_chains ").as_deref(), Some("3"));
        assert_eq!(line_value(&t, "cellcore_antenna_rsrp_spread_db ").as_deref(), Some("12"));
        assert_eq!(line_value(&t, "cellcore_nr5g_csi_ri ").as_deref(), Some("4"));
        assert_eq!(line_value(&t, "cellcore_nr5g_csi_cqi ").as_deref(), Some("15"));
        assert_eq!(line_value(&t, "cellcore_nr5g_active_rank ").as_deref(), Some("4"));
        assert_eq!(line_value(&t, "cellcore_ul_ca_active ").as_deref(), Some("1"));
        assert_eq!(line_value(&t, "cellcore_ul_bandwidth_mhz ").as_deref(), Some("140"));
        assert_eq!(line_value(&t, "cellcore_nsa_nr5g_rsrp_dbm ").as_deref(), Some("-93.5"));
        assert_eq!(line_value(&t, "cellcore_nsa_nr5g_sinr_db ").as_deref(), Some("16"));
        assert_eq!(line_value(&t, "cellcore_speedtest_dl_loaded_latency_ms ").as_deref(), Some("31.5"));
        assert_eq!(line_value(&t, "cellcore_speedtest_ul_loaded_latency_ms ").as_deref(), Some("44"));
        assert_eq!(line_value(&t, "cellcore_ipa_hardware_offload_pct ").as_deref(), Some("98"));
        assert_eq!(line_value(&t, "cellcore_qrtr_ssr_total ").as_deref(), Some("2"));
    }
}
