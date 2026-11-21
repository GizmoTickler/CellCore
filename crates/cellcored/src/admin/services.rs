//! Services › init.d scripts with enabled/running state and start/stop/restart/
//! reload/enable/disable. Platform-critical services are refused or need a typed
//! confirmation.

use std::{
    collections::HashSet,
    io::Read,
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    audit, bad, exec::{ExecOpts, KIB, MIB, run, run_ok}, forbidden, mutate_lock, ok, require_confirm, server,
    validate::is_safe_name,
};
use crate::http::HttpCtx;

const SERVICES_CACHE_TTL: Duration = Duration::from_secs(15);
const RC_LOCAL_PATH: &str = "/etc/rc.local";
const RC_LOCAL_MAX_BYTES: usize = 16 * 1024;
const SAVE_RC_LOCAL_CONFIRM: &str = "SAVE RC.LOCAL";

type ServicesCache = Mutex<Option<(Instant, Vec<RcEntry>)>>;
static SERVICES_CACHE: OnceLock<ServicesCache> = OnceLock::new();

fn invalidate_services_cache() {
    if let Ok(mut c) = SERVICES_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *c = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protection {
    /// Ordinary service.
    None,
    /// Every action except start/enable needs a typed confirmation.
    Critical,
    /// Modem/QCMAP/data-path plumbing: stop/disable refused, others confirmed.
    Locked,
    /// Never from this UI (the daemon serving the request).
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Allow,
    Confirm,
    Refuse(&'static str),
}

const BLOCKED: &[&str] = &["cellcored", "quecmanagerd"];

/// Prefixes of init scripts that keep the modem, the data path or the filesystem
/// alive on this QSDK build.
const LOCKED_PREFIXES: &[&str] = &[
    "QCMAP", "netmgrd", "ipacm", "cellular_device_manager", "mount-fix", "data", "qmi", "ql-", "ql_",
    "quectel", "qrtr", "rmtstorage", "smcinvoke", "qseecomd", "servicemanager", "ipa_fws", "binderfs",
    "partition-symlinks", "create-firmwarelinks", "ssgtzd", "qwes", "postboot", "pcie", "mhi",
    "time_serviced", "modem", "subsystem", "rproc", "usb.init", "ab-updater",
];

const LOCKED_EXACT: &[&str] = &["network", "boot", "done", "umount", "sysfixtime", "urandom_seed", "sysctl", "ubus", "procd"];

const CRITICAL_EXACT: &[&str] = &["dropbear", "firewall", "dnsmasq", "odhcpd", "mwan3", "uhttpd", "rpcd", "log", "socat", "cron", "sysntpd"];

pub fn protection_for(name: &str) -> Protection {
    if BLOCKED.contains(&name) {
        return Protection::Blocked;
    }
    if LOCKED_EXACT.contains(&name) || LOCKED_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return Protection::Locked;
    }
    // Vendor platform scripts on this build are named *.init; treat unknown ones as
    // critical rather than ordinary.
    if CRITICAL_EXACT.contains(&name) || name.ends_with(".init") || name.ends_with("_le") {
        return Protection::Critical;
    }
    Protection::None
}

pub fn gate(p: Protection, action: &str) -> Gate {
    match p {
        Protection::Blocked => Gate::Refuse("CellCore's own daemon cannot be controlled from its UI"),
        Protection::Locked => match action {
            "stop" | "disable" => Gate::Refuse("This service keeps the modem, data path or filesystem running; stopping or disabling it is blocked"),
            _ => Gate::Confirm,
        },
        Protection::Critical => match action {
            "start" | "enable" => Gate::Allow,
            _ => Gate::Confirm,
        },
        Protection::None => Gate::Allow,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RcEntry {
    pub name: String,
    pub enabled: bool,
    pub running: bool,
    pub start: Option<i64>,
    pub stop: Option<i64>,
}

/// Parse `ubus call rc list` (procd): `{ name: { start, stop, enabled, running? } }`.
pub fn parse_rc_list(json: &str) -> Vec<RcEntry> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut v: Vec<RcEntry> = map
        .into_iter()
        .map(|(name, e)| RcEntry {
            enabled: e.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            running: e.get("running").and_then(Value::as_bool).unwrap_or(false),
            start: e.get("start").and_then(Value::as_i64),
            stop: e.get("stop").and_then(Value::as_i64),
            name,
        })
        .collect();
    v.sort_by_key(|a| a.name.to_lowercase());
    v
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceState {
    pub known: bool,
    pub running: bool,
    pub pid: Option<i64>,
    pub exit_code: Option<i64>,
}

/// Parse `ubus call service list '{"name":X}'`: running if any instance runs.
pub fn parse_service_state(json: &str, name: &str) -> ServiceState {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return ServiceState::default();
    };
    let Some(svc) = v.get(name) else {
        return ServiceState::default();
    };
    let mut st = ServiceState { known: true, ..Default::default() };
    if let Some(Value::Object(inst)) = svc.get("instances") {
        for i in inst.values() {
            let running = i.get("running").and_then(Value::as_bool).unwrap_or(false);
            if running && !st.running {
                st.running = true;
                st.pid = i.get("pid").and_then(Value::as_i64);
            }
            if st.exit_code.is_none() {
                st.exit_code = i.get("exit_code").and_then(Value::as_i64);
            }
        }
    }
    st
}

/// Parse `START=<n>` and `STOP=<n>` from the top of an init.d script without spawning a shell.
pub fn parse_init_header(content: &str) -> (Option<i64>, Option<i64>) {
    let mut start = None;
    let mut stop = None;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        let parse_val = |v: &str| -> Option<i64> {
            let unquoted = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            unquoted.parse::<i64>().ok()
        };
        if start.is_none()
            && let Some(rhs) = line.strip_prefix("START=")
        {
            start = parse_val(rhs);
        } else if stop.is_none()
            && let Some(rhs) = line.strip_prefix("STOP=")
        {
            stop = parse_val(rhs);
        }
        if start.is_some() && stop.is_some() {
            break;
        }
    }
    (start, stop)
}

/// Scan `/etc/rc.d/S*` symlinks to determine which init scripts are enabled at boot.
pub fn scan_rc_enabled(rc_dir: &Path) -> HashSet<String> {
    let mut enabled = HashSet::new();
    let Ok(rd) = std::fs::read_dir(rc_dir) else {
        return enabled;
    };
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let Some(name) = fname.to_str() else {
            continue;
        };
        let Some(after_s) = name.strip_prefix('S') else {
            continue;
        };
        if !after_s.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(target) = std::fs::read_link(ent.path())
            && let Some(base) = target.file_name().and_then(|s| s.to_str())
            && is_safe_name(base, 64)
        {
            enabled.insert(base.to_string());
            continue;
        }
        let trimmed = after_s.trim_start_matches(|c: char| c.is_ascii_digit());
        if is_safe_name(trimmed, 64) {
            enabled.insert(trimmed.to_string());
        }
    }
    enabled
}

/// Parse `ubus call service list` JSON into the set of currently running service names.
pub fn parse_service_list_running(json: &str) -> HashSet<String> {
    let mut running = HashSet::new();
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(json) else {
        return running;
    };
    for (svc_name, svc) in map {
        let Some(Value::Object(insts)) = svc.get("instances") else {
            continue;
        };
        if insts
            .values()
            .any(|i| i.get("running").and_then(Value::as_bool).unwrap_or(false))
        {
            running.insert(svc_name);
        }
    }
    running
}

fn read_head_4k(path: &Path) -> String {
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::with_capacity(4096);
    let _ = f.take(4096).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

pub async fn service_state(name: &str) -> ServiceState {
    let arg = serde_json::json!({ "name": name }).to_string();
    match run_ok("ubus", &["call", "service", "list", &arg], 5, MIB).await {
        Ok(out) => parse_service_state(&out, name),
        Err(_) => ServiceState::default(),
    }
}

async fn rc_list(name: Option<&str>) -> Result<Vec<RcEntry>, String> {
    let mut args = vec!["call", "rc", "list"];
    let arg;
    if let Some(n) = name {
        arg = serde_json::json!({ "name": n }).to_string();
        args.push(&arg);
    }
    let out = run_ok("ubus", &args, 15, 2 * MIB).await?;
    Ok(parse_rc_list(&out))
}

async fn fast_service_list() -> Result<Vec<RcEntry>, String> {
    if let Ok(c) = SERVICES_CACHE.get_or_init(|| Mutex::new(None)).lock()
        && let Some((t, cached)) = c.as_ref()
        && t.elapsed() < SERVICES_CACHE_TTL
    {
        return Ok(cached.clone());
    }

    let init_dir = crate::paths::p("/etc/init.d");
    let Ok(rd) = std::fs::read_dir(&init_dir) else {
        return rc_list(None).await;
    };
    let mut entries = Vec::new();
    for e in rd.flatten() {
        if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let n = e.file_name().to_string_lossy().into_owned();
            if is_safe_name(&n, 64) {
                entries.push((n, e.path()));
            }
        }
    }

    let rc_dir = crate::paths::p("/etc/rc.d");
    let enabled_set = scan_rc_enabled(Path::new(&rc_dir));
    let running_set = run_ok("ubus", &["call", "service", "list"], 5, 2 * MIB)
        .await
        .map(|s| parse_service_list_running(&s))
        .unwrap_or_default();

    let mut list: Vec<RcEntry> = entries
        .into_iter()
        .map(|(name, path)| {
            let head = read_head_4k(&path);
            let (start, stop) = parse_init_header(&head);
            RcEntry {
                enabled: enabled_set.contains(&name),
                running: running_set.contains(&name),
                start,
                stop,
                name,
            }
        })
        .collect();
    list.sort_by_key(|a| a.name.to_lowercase());
    if let Ok(mut c) = SERVICES_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *c = Some((Instant::now(), list.clone()));
    }
    Ok(list)
}

async fn fast_service_entry(name: &str) -> Option<RcEntry> {
    let init_path = crate::paths::p(&format!("/etc/init.d/{name}"));
    if !Path::new(&init_path).is_file() {
        return None;
    }
    let st = service_state(name).await;
    let enabled = scan_rc_enabled(Path::new(&crate::paths::p("/etc/rc.d"))).contains(name);
    let (start, stop) = parse_init_header(&read_head_4k(Path::new(&init_path)));
    Some(RcEntry {
        name: name.to_string(),
        enabled,
        running: st.running,
        start,
        stop,
    })
}

pub async fn get_services() -> Response {
    let list = match fast_service_list().await {
        Ok(l) => l,
        Err(e) => return server(e),
    };
    let services: Vec<Value> = list
        .into_iter()
        .map(|e| {
            let p = protection_for(&e.name);
            let mut v = serde_json::to_value(&e).unwrap_or(Value::Null);
            if let Value::Object(m) = &mut v {
                m.insert("protection".into(), serde_json::to_value(p).unwrap_or(Value::Null));
            }
            v
        })
        .collect();
    ok(serde_json::json!({ "services": services }))
}

#[derive(Deserialize)]
pub struct ActionReq {
    name: String,
    action: String,
    #[serde(default)]
    confirm: Option<String>,
}

const ACTIONS: &[&str] = &["start", "stop", "restart", "reload", "enable", "disable"];

pub async fn post_action(State(ctx): State<HttpCtx>, Json(req): Json<ActionReq>) -> Response {
    if !is_safe_name(&req.name, 64) {
        return bad("Invalid service name");
    }
    if !ACTIONS.contains(&req.action.as_str()) {
        return bad("Unknown action");
    }
    let path = format!("/etc/init.d/{}", req.name);
    if !std::fs::metadata(crate::paths::p(&path)).map(|m| m.is_file()).unwrap_or(false) {
        return bad("No such init script");
    }
    let p = protection_for(&req.name);
    match gate(p, &req.action) {
        Gate::Refuse(why) => return forbidden(why),
        Gate::Confirm => {
            if let Err(r) = require_confirm(
                req.confirm.as_deref(),
                &req.name,
                &format!("{} is a protected service. Type its name to {} it.", req.name, req.action),
            ) {
                return r;
            }
        }
        Gate::Allow => {}
    }
    let _g = mutate_lock().await;
    let out = match run(&path, &[&req.action], ExecOpts::new(45, 64 * KIB)).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    invalidate_services_cache();
    audit(&ctx, format!("service {} {} -> {:?}", req.name, req.action, out.code));
    let state = fast_service_entry(&req.name).await;
    if !out.ok() {
        return server(format!("{} {} failed: {}", req.name, req.action, out.err_summary(&req.name)));
    }
    ok(serde_json::json!({ "status": "ok", "log": out.log(), "state": state }))
}

pub fn validate_rc_local(content: &str) -> Result<String, String> {
    if content.len() > RC_LOCAL_MAX_BYTES {
        return Err(format!("{} exceeds {RC_LOCAL_MAX_BYTES} bytes", RC_LOCAL_PATH));
    }
    if content.bytes().any(|b| b == 0) {
        return Err("NUL bytes are not allowed in rc.local".into());
    }
    let mut normalized = content.replace("\r\n", "\n");
    if !normalized.is_empty() && !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    Ok(normalized)
}

pub async fn get_rc_local() -> Response {
    let real = crate::paths::p(RC_LOCAL_PATH);
    let exists = Path::new(&real).exists();
    let content = match std::fs::File::open(&real) {
        Ok(f) => {
            let mut buf = Vec::new();
            let _ = f.take(RC_LOCAL_MAX_BYTES as u64).read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return server(format!("read {}: {e}", RC_LOCAL_PATH)),
    };
    ok(serde_json::json!({
        "path": RC_LOCAL_PATH,
        "exists": exists,
        "content": content,
        "maxBytes": RC_LOCAL_MAX_BYTES,
    }))
}

#[derive(Deserialize)]
pub struct RcLocalReq {
    content: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn put_rc_local(State(ctx): State<HttpCtx>, Json(req): Json<RcLocalReq>) -> Response {
    let normalized = match validate_rc_local(&req.content) {
        Ok(s) => s,
        Err(e) => return bad(e),
    };
    if let Err(r) = require_confirm(
        req.confirm.as_deref(),
        SAVE_RC_LOCAL_CONFIRM,
        "Commands in /etc/rc.local execute as root at boot. Type SAVE RC.LOCAL to save.",
    ) {
        return r;
    }
    let _g = mutate_lock().await;
    if let Err(e) = crate::state::atomic_write(Path::new(RC_LOCAL_PATH), normalized.as_bytes(), 0o755) {
        return server(e);
    }
    audit(&ctx, format!("saved {} ({} bytes)", RC_LOCAL_PATH, normalized.len()));
    ok(serde_json::json!({ "status": "ok", "bytes": normalized.len() }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn parses_real_rc_list() {
        let list = parse_rc_list(include_str!("fixtures/rc_list.json"));
        assert!(list.len() > 100);
        let log = list.iter().find(|e| e.name == "log").unwrap();
        assert!(log.enabled && log.running);
        assert_eq!(log.start, Some(12));
        let r = list.iter().find(|e| e.name == "r8125_ioss.init").unwrap();
        assert!(r.enabled && !r.running);
        let names: BTreeMap<_, _> = list.iter().map(|e| (e.name.as_str(), e)).collect();
        assert!(names.contains_key("dropbear"));
        assert!(names.contains_key("QCMAP_ConnectionManagerd.init"));
    }

    #[test]
    fn parses_service_state() {
        let st = parse_service_state(include_str!("fixtures/service_sysntpd.json"), "sysntpd");
        assert!(st.known);
        assert!(!st.running);
        assert_eq!(st.exit_code, Some(1));
        assert_eq!(parse_service_state("{}", "x"), ServiceState::default());
        let running = r#"{"dropbear":{"instances":{"instance1":{"running":true,"pid":9660}}}}"#;
        let st = parse_service_state(running, "dropbear");
        assert!(st.running);
        assert_eq!(st.pid, Some(9660));
    }

    #[test]
    fn protects_critical_services() {
        assert_eq!(protection_for("cellcored"), Protection::Blocked);
        for n in ["QCMAP_ConnectionManagerd.init", "netmgrd", "ipacm.init", "network", "mount-fix", "mount-fix-final", "cellular_device_manager.init", "datarmnet.init", "ql-nw-service.init", "boot"] {
            assert_eq!(protection_for(n), Protection::Locked, "{n}");
        }
        for n in ["dropbear", "firewall", "dnsmasq", "mwan3", "uhttpd", "qms.init"] {
            assert_eq!(protection_for(n), Protection::Critical, "{n}");
        }
        for n in ["miniupnpd", "avahi-daemon", "sysstat", "tftp-server"] {
            assert_eq!(protection_for(n), Protection::None, "{n}");
        }
    }

    #[test]
    fn gates_actions() {
        assert!(matches!(gate(Protection::Blocked, "restart"), Gate::Refuse(_)));
        assert!(matches!(gate(Protection::Locked, "stop"), Gate::Refuse(_)));
        assert!(matches!(gate(Protection::Locked, "disable"), Gate::Refuse(_)));
        assert_eq!(gate(Protection::Locked, "restart"), Gate::Confirm);
        assert_eq!(gate(Protection::Critical, "start"), Gate::Allow);
        assert_eq!(gate(Protection::Critical, "stop"), Gate::Confirm);
        assert_eq!(gate(Protection::None, "stop"), Gate::Allow);
    }

    #[test]
    fn parses_init_headers_rc_dir_service_list_and_validates_rc_local() {
        let script = "#!/bin/sh /etc/rc.common\n# START=99 comment\nSTART=19\nSTOP=\"50\" # trailing\nUSE_PROCD=1\n";
        assert_eq!(parse_init_header(script), (Some(19), Some(50)));
        assert_eq!(parse_init_header("#!/bin/sh\nUSE_PROCD=1\n"), (None, None));

        let sbx = crate::paths::TestSandbox::new("svc_fast");
        let rc_dir = sbx.root.join("etc/rc.d");
        std::fs::create_dir_all(&rc_dir).unwrap();
        std::fs::write(rc_dir.join("K50dropbear"), "").unwrap();
        std::fs::write(rc_dir.join("S98sysntpd"), "").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("../init.d/QCMAP_ConnectionManagerd.init", rc_dir.join("S10QCMAP_ConnectionManagerd.init")).unwrap();
        let enabled = scan_rc_enabled(&rc_dir);
        assert!(enabled.contains("sysntpd"));
        assert!(enabled.contains("QCMAP_ConnectionManagerd.init"));
        assert!(!enabled.contains("dropbear"));

        let svc_json = r#"{
            "dropbear": { "instances": { "instance1": { "running": true, "pid": 123 } } },
            "sysntpd": { "instances": { "instance1": { "running": false } } }
        }"#;
        let running = parse_service_list_running(svc_json);
        assert!(running.contains("dropbear"));
        assert!(!running.contains("sysntpd"));

        assert_eq!(validate_rc_local("echo hi\r\nexit 0").unwrap(), "echo hi\nexit 0\n");
        assert!(validate_rc_local("echo \0").is_err());
        assert!(validate_rc_local(&"a".repeat(RC_LOCAL_MAX_BYTES + 1)).is_err());
    }
}
