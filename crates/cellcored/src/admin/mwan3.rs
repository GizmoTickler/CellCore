//! Multi-WAN › mwan3 status (`ubus call mwan3 status`) and the config, read-only.
//! mwan3 is kept on this box for QSDK routing; editing it is deliberately not offered.

use std::{
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use axum::response::Response;
use serde::Serialize;
use serde_json::Value;

use super::{exec::{MIB, run_ok}, ok, ucicfg};

const FRESH_TTL: Duration = Duration::from_secs(10);
const STALE_TTL: Duration = Duration::from_secs(60);

static MWAN_CACHE: OnceLock<Mutex<Option<(Instant, Value)>>> = OnceLock::new();
static MWAN_REFRESHING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheAge {
    Fresh,
    Stale,
    Expired,
}

pub(crate) fn classify_age(age: Duration) -> CacheAge {
    if age < FRESH_TTL {
        CacheAge::Fresh
    } else if age < STALE_TTL {
        CacheAge::Stale
    } else {
        CacheAge::Expired
    }
}

struct RefreshReset;

impl Drop for RefreshReset {
    fn drop(&mut self) {
        MWAN_REFRESHING.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MwanIface {
    pub name: String,
    pub status: String,
    pub enabled: bool,
    pub up: bool,
    pub uptime: u64,
    pub online: u64,
    pub offline: u64,
    pub score: i64,
    pub lost: i64,
    pub track_ips: Vec<TrackIp>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrackIp {
    pub ip: String,
    pub status: String,
    pub latency: f64,
    pub packetloss: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PolicyMember {
    pub interface: String,
    pub percent: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct MwanStatus {
    pub interfaces: Vec<MwanIface>,
    /// family → policy → members
    pub policies: Vec<(String, String, Vec<PolicyMember>)>,
    pub connected: Vec<String>,
}

pub fn parse_status(json: &str) -> MwanStatus {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return MwanStatus::default();
    };
    let num = |x: &Value, k: &str| x.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mut st = MwanStatus::default();
    if let Some(Value::Object(m)) = v.get("interfaces") {
        for (name, i) in m {
            st.interfaces.push(MwanIface {
                name: name.clone(),
                status: i.get("status").and_then(Value::as_str).unwrap_or("unknown").into(),
                enabled: i.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                up: i.get("up").and_then(Value::as_bool).unwrap_or(false),
                uptime: num(i, "uptime"),
                online: num(i, "online"),
                offline: num(i, "offline"),
                score: i.get("score").and_then(Value::as_i64).unwrap_or(0),
                lost: i.get("lost").and_then(Value::as_i64).unwrap_or(0),
                track_ips: i
                    .get("track_ip")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|t| TrackIp {
                                ip: t.get("ip").and_then(Value::as_str).unwrap_or("").into(),
                                status: t.get("status").and_then(Value::as_str).unwrap_or("").into(),
                                latency: t.get("latency").and_then(Value::as_f64).unwrap_or(0.0),
                                packetloss: t.get("packetloss").and_then(Value::as_f64).unwrap_or(0.0),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
    }
    if let Some(Value::Object(fams)) = v.get("policies") {
        for (fam, pols) in fams {
            if let Value::Object(pols) = pols {
                for (pname, members) in pols {
                    let members = members
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .map(|m| PolicyMember {
                                    interface: m.get("interface").and_then(Value::as_str).unwrap_or("").into(),
                                    percent: m.get("percent").and_then(Value::as_i64).unwrap_or(0),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    st.policies.push((fam.clone(), pname.clone(), members));
                }
            }
        }
    }
    if let Some(Value::Object(c)) = v.get("connected") {
        for fam in c.values() {
            if let Some(a) = fam.as_array() {
                st.connected.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }
    }
    st
}

async fn fetch_mwan3_payload() -> Value {
    let (status_res, cfg_res) = tokio::join!(
        run_ok("ubus", &["call", "mwan3", "status"], 15, 2 * MIB),
        ucicfg::show("mwan3"),
    );
    let status = status_res.ok().map(|out| parse_status(&out));
    let config = cfg_res.unwrap_or_default();
    let policies: Vec<Value> = status
        .as_ref()
        .map(|s| {
            s.policies
                .iter()
                .map(|(fam, name, members)| serde_json::json!({ "family": fam, "name": name, "members": members }))
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({
        "available": status.is_some(),
        "interfaces": status.as_ref().map(|s| s.interfaces.clone()).unwrap_or_default(),
        "policies": policies,
        "config": config.iter().map(ucicfg::UciSection::to_json).collect::<Vec<_>>(),
    })
}

fn cache_store(v: &Value) {
    if let Ok(mut g) = MWAN_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *g = Some((Instant::now(), v.clone()));
    }
}

pub async fn get_mwan3() -> Response {
    let cached = MWAN_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|(t, v)| (classify_age(t.elapsed()), v.clone())));

    match cached {
        Some((CacheAge::Fresh, v)) => return ok(v),
        Some((CacheAge::Stale, v)) => {
            if MWAN_REFRESHING
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                tokio::spawn(async {
                    let _guard = RefreshReset;
                    let fresh = fetch_mwan3_payload().await;
                    cache_store(&fresh);
                });
            }
            return ok(v);
        }
        Some((CacheAge::Expired, _)) | None => {}
    }

    let v = fetch_mwan3_payload().await;
    cache_store(&v);
    ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_mwan3_status() {
        let st = parse_status(include_str!("fixtures/mwan3_status.json"));
        assert_eq!(st.interfaces.len(), 6);
        let wan = st.interfaces.iter().find(|i| i.name == "wan").unwrap();
        assert_eq!(wan.status, "online");
        assert!(wan.enabled && wan.up);
        assert_eq!(wan.uptime, 40697);
        assert_eq!(wan.track_ips.len(), 4);
        assert_eq!(wan.track_ips[0].status, "skipped");
        let eth = st.interfaces.iter().find(|i| i.name == "waneth").unwrap();
        assert_eq!(eth.status, "notracking");
        assert!(!eth.enabled);
        let pref = st.policies.iter().find(|(f, n, _)| f == "ipv4" && n == "backhaul_pref").unwrap();
        assert_eq!(pref.2, vec![PolicyMember { interface: "wan".into(), percent: 100 }]);
        assert!(st.connected.iter().any(|c| c == "192.168.224.0/22"));
        assert_eq!(parse_status("not json"), MwanStatus::default());
    }

    #[test]
    fn swr_cache_age_classification() {
        assert_eq!(classify_age(Duration::from_secs(0)), CacheAge::Fresh);
        assert_eq!(classify_age(Duration::from_secs(9)), CacheAge::Fresh);
        assert_eq!(classify_age(Duration::from_secs(10)), CacheAge::Stale);
        assert_eq!(classify_age(Duration::from_secs(59)), CacheAge::Stale);
        assert_eq!(classify_age(Duration::from_secs(60)), CacheAge::Expired);
    }
}
