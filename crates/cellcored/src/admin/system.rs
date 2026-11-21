//! System › hostname, timezone and NTP (uci `system`), plus time-sync status.

use axum::{Json, extract::State, response::Response};
use serde::Deserialize;

use super::{
    audit, bad, exec::{KIB, run_ok}, mutate_lock, ok, server,
    services::service_state,
    ucicfg::{self, Op, of_type},
    validate::{is_host_label, is_net_target},
};
use crate::http::HttpCtx;

const ZONEINFO: &str = include_str!("zoneinfo.tsv");
const TIME_VALID_MARKER: &str = "/var/state/dnsmasqsec";

/// Zone name (normalizing spaces and underscores, e.g. `"America/New_York"`
/// and `"America/New York"`) → `(canonical_zonename, posix_tz)` (LuCI's table).
pub fn resolve_zone(zone: &str) -> Option<(&'static str, &'static str)> {
    let trimmed = zone.trim();
    if trimmed.is_empty() {
        return None;
    }
    let norm = trimmed.replace('_', " ");
    ZONEINFO.lines().find_map(|l| {
        let (z, tz) = l.split_once('\t')?;
        (z == trimmed || z == norm || z.replace('_', " ") == norm).then_some((z, tz))
    })
}

/// Zone name → POSIX TZ string (LuCI's table, captured from the device).
pub fn tz_for_zone(zone: &str) -> Option<&'static str> {
    resolve_zone(zone).map(|(_, tz)| tz)
}

pub fn zone_names() -> Vec<&'static str> {
    ZONEINFO.lines().filter_map(|l| l.split_once('\t').map(|(z, _)| z)).collect()
}

pub async fn get_timezones() -> Response {
    ok(serde_json::json!({ "zones": zone_names() }))
}

pub async fn get_system() -> Response {
    let sections = match ucicfg::show("system").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let sys = of_type(&sections, "system").into_iter().next().cloned();
    let ntp = sections.iter().find(|s| s.stype == "timeserver").cloned();
    let local = run_ok("date", &["+%Y-%m-%d %H:%M:%S %Z"], 3, KIB).await.unwrap_or_default();
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()))
        .unwrap_or(0.0);
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ntpd = service_state("sysntpd").await;
    ok(serde_json::json!({
        "hostname": sys.as_ref().and_then(|s| s.get("hostname")).unwrap_or("OpenWrt"),
        "zonename": sys.as_ref().and_then(|s| s.get("zonename")).unwrap_or("UTC"),
        "timezone": sys.as_ref().and_then(|s| s.get("timezone")).unwrap_or("UTC0"),
        "ntp": {
            "present": ntp.is_some(),
            "enabled": ntp.as_ref().map(|n| n.flag("enabled", true)).unwrap_or(false),
            "server": ntp.as_ref().map(|n| n.flag("enable_server", false)).unwrap_or(false),
            "servers": ntp.as_ref().map(|n| n.list("server")).unwrap_or_default(),
        },
        "time": {
            "epoch": epoch,
            "local": local.trim(),
            "uptime": uptime as u64,
            "ntpdRunning": ntpd.running,
            "ntpdExitCode": ntpd.exit_code,
            "ntpdPid": ntpd.pid,
            "stratumSeen": std::path::Path::new(TIME_VALID_MARKER).exists(),
        },
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemReq {
    hostname: String,
    zonename: String,
    ntp_enabled: bool,
    #[serde(default)]
    ntp_server: bool,
    #[serde(default)]
    ntp_servers: Vec<String>,
}

pub fn validate_system(req: &SystemReq) -> Result<&'static str, String> {
    if !is_host_label(&req.hostname) {
        return Err("Hostname must be 1–63 letters, digits or hyphens (no dots, no leading/trailing hyphen)".into());
    }
    let tz = tz_for_zone(&req.zonename).ok_or_else(|| format!("Unknown timezone {}", req.zonename))?;
    if req.ntp_servers.len() > 8 {
        return Err("At most 8 NTP servers".into());
    }
    let mut seen = std::collections::HashSet::new();
    for s in &req.ntp_servers {
        if !is_net_target(s) {
            return Err(format!("Invalid NTP server: {s}"));
        }
        if !seen.insert(s.to_ascii_lowercase()) {
            return Err(format!("Duplicate NTP server: {s}"));
        }
    }
    if req.ntp_enabled && req.ntp_servers.is_empty() {
        return Err("Add at least one NTP server or turn time sync off".into());
    }
    Ok(tz)
}

pub async fn post_system(State(ctx): State<HttpCtx>, Json(req): Json<SystemReq>) -> Response {
    let tz = match validate_system(&req) {
        Ok(tz) => tz,
        Err(e) => return bad(e),
    };
    let canonical_zone = resolve_zone(&req.zonename).map(|(z, _)| z).unwrap_or(req.zonename.as_str());
    let _g = mutate_lock().await;
    let sections = match ucicfg::show("system").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let Some(sys) = of_type(&sections, "system").into_iter().next() else {
        return server("No system section in /etc/config/system");
    };
    let Some(ntp) = sections.iter().find(|s| s.stype == "timeserver") else {
        return server("No timeserver section (system.ntp) in /etc/config/system");
    };
    let old_servers = ntp.list("server");
    let ntp_changed = old_servers != req.ntp_servers
        || ntp.flag("enabled", true) != req.ntp_enabled
        || ntp.flag("enable_server", false) != req.ntp_server;
    let ops = vec![
        Op::set(&sys.id, "hostname", &req.hostname),
        Op::set(&sys.id, "zonename", canonical_zone),
        Op::set(&sys.id, "timezone", tz),
        Op::set(&ntp.id, "enabled", if req.ntp_enabled { "1" } else { "0" }),
        Op::set(&ntp.id, "enable_server", if req.ntp_server { "1" } else { "0" }),
        Op::SetList { section: ntp.id.clone(), option: "server".into(), values: req.ntp_servers.clone() },
    ];
    if let Err(e) = ucicfg::apply("system", None, ops).await {
        return server(e);
    }
    let mut notes = Vec::new();
    if let Err(e) = crate::state::atomic_write(
        std::path::Path::new("/tmp/TZ"),
        format!("{tz}\n").as_bytes(),
        0o644,
    ) {
        notes.push(format!("write /tmp/TZ: {e}"));
    }
    if let Err(e) = run_ok("/etc/init.d/system", &["reload"], 20, 16 * KIB).await {
        notes.push(format!("system reload: {e}"));
    }
    if ntp_changed
        && let Err(e) = run_ok("/etc/init.d/sysntpd", &["restart"], 20, 16 * KIB).await
    {
        notes.push(format!("sysntpd restart: {e}"));
    }
    audit(&ctx, format!("system: hostname={} zone={} ntp={} servers={}", req.hostname, canonical_zone, req.ntp_enabled, req.ntp_servers.join(",")));
    ok(serde_json::json!({ "status": "ok", "notes": notes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(h: &str, z: &str, en: bool, servers: &[&str]) -> SystemReq {
        SystemReq {
            hostname: h.into(),
            zonename: z.into(),
            ntp_enabled: en,
            ntp_server: false,
            ntp_servers: servers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn zone_table_matches_device() {
        // The device's current setting (fixture) must round-trip through the table.
        let sys = ucicfg::parse_uci_show("system", include_str!("fixtures/uci_system.txt"));
        let s = of_type(&sys, "system")[0];
        assert_eq!(tz_for_zone(s.get("zonename").unwrap()), s.get("timezone"));
        assert_eq!(tz_for_zone("UTC"), Some("UTC0"));
        assert!(tz_for_zone("Mars/Olympus").is_none());
        assert!(zone_names().len() > 400);
        let ntp = sys.iter().find(|x| x.stype == "timeserver").unwrap();
        assert_eq!(ntp.list("server").len(), 4);
    }

    #[test]
    fn validates_system_request() {
        assert_eq!(validate_system(&req("gateway-test", "America/New York", true, &["0.openwrt.pool.ntp.org", "time.cloudflare.com", "162.159.200.1"])).unwrap(), "EST5EDT,M3.2.0,M11.1.0");
        assert_eq!(validate_system(&req("gateway-test", "America/New_York", true, &["time.cloudflare.com"])).unwrap(), "EST5EDT,M3.2.0,M11.1.0");
        assert_eq!(
            resolve_zone("America/New_York"),
            Some(("America/New York", "EST5EDT,M3.2.0,M11.1.0"))
        );
        assert_eq!(
            resolve_zone("America/New York"),
            Some(("America/New York", "EST5EDT,M3.2.0,M11.1.0"))
        );
        assert!(validate_system(&req("bad.name", "UTC", false, &[])).is_err());
        assert!(validate_system(&req("-x", "UTC", false, &[])).is_err());
        assert!(validate_system(&req("ok", "Nowhere/City", false, &[])).is_err());
        assert!(validate_system(&req("ok", "UTC", true, &[])).is_err());
        assert!(validate_system(&req("ok", "UTC", true, &["-p evil"])).is_err());
        assert!(validate_system(&req("ok", "UTC", true, &["a.pool", "A.POOL"])).is_err());
        assert!(validate_system(&req("ok", "UTC", false, &[])).is_ok());
    }

    #[tokio::test]
    async fn post_system_normalizes_zonename_and_writes_tmp_tz() {
        let env = crate::paths::TestSandbox::new("system-tz");
        let uci_log = env.root.join("uci.log");
        let fixture = include_str!("fixtures/uci_system.txt");
        env.write("/uci_show.txt", fixture);
        env.write_exec(
            "/bin/uci",
            &format!(
                "#!/bin/sh\n\
                 echo \"$*\" >> {}\n\
                 if [ \"$1\" = \"-X\" ] && [ \"$2\" = \"show\" ]; then\n\
                   cat {}\n\
                 fi\n\
                 exit 0\n",
                uci_log.display(),
                env.root.join("uci_show.txt").display()
            ),
        );
        env.write_exec("/etc/init.d/system", "#!/bin/sh\nexit 0\n");
        env.write_exec("/etc/init.d/sysntpd", "#!/bin/sh\nexit 0\n");

        let ctx = HttpCtx::for_tests(&env.root);
        let r = req(
            "gateway-test",
            "America/New_York",
            true,
            &["0.openwrt.pool.ntp.org"],
        );
        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let resp = post_system(State(ctx), Json(r)).await;
                assert_eq!(resp.status(), axum::http::StatusCode::OK);
                let tmp_tz = std::fs::read_to_string(crate::paths::p("/tmp/TZ")).unwrap();
                assert_eq!(tmp_tz, "EST5EDT,M3.2.0,M11.1.0\n");
            })
            .await;

        let log = std::fs::read_to_string(&uci_log).unwrap();
        assert!(
            log.contains("set system.cfg01e48a.zonename=America/New York"),
            "expected canonical zonename in UCI log:\n{log}"
        );
        assert!(
            log.contains("set system.cfg01e48a.timezone=EST5EDT,M3.2.0,M11.1.0"),
            "expected POSIX timezone in UCI log:\n{log}"
        );
    }
}
