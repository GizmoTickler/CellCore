//! Route-level regression tests for input validation and safety (4.1.1 QA
//! findings). They drive the real router with an authenticated session; the
//! test AppState has no modem, so anything that reaches the AT queue fails
//! with 502 and every 4xx below is decided before a single AT write.

use std::{net::SocketAddr, time::Duration};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde_json::{Value, json};

use crate::{
    auth::AuthStore,
    http::{HttpCtx, build_router},
    paths::{TEST_ENV, TestEnv},
    state::AppState,
};

struct T {
    router: axum::Router,
    cookie: String,
    csrf: String,
    app: AppState,
    /// File/tool sandbox the requests run under (None: the host's paths).
    env: Option<TestEnv>,
}

async fn setup(tag: &str) -> T {
    let dir = std::env::temp_dir().join(format!("qm-val-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let auth = AuthStore::new(dir.join("sessions"));
    let app = AppState::for_tests(dir, auth.clone());
    build(app, auth, None).await
}

async fn build(app: AppState, auth: AuthStore, env: Option<TestEnv>) -> T {
    let ctx = HttpCtx {
        app: app.clone(),
        proxy: Client::builder(TokioExecutor::new()).build_http(),
        enforce_uhttpd_loopback: true,
    };
    let sess = auth.create_session().await.unwrap();
    T { router: build_router(ctx), cookie: format!("qm_session={}", sess.token), csrf: sess.csrf_token, app, env }
}

fn request(t: &T, method: Method, uri: &str, body: Body, len: Option<usize>, authed: bool) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header(header::HOST, "192.168.224.1");
    if authed {
        b = b.header(header::COOKIE, &t.cookie).header("x-qm-csrf", &t.csrf);
    }
    if let Some(n) = len {
        b = b.header(header::CONTENT_TYPE, "application/json").header(header::CONTENT_LENGTH, n);
    }
    let mut req = b.body(body).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([192, 168, 224, 50], 40000))));
    req
}

async fn send(t: &T, method: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let text = if body.is_null() { String::new() } else { body.to_string() };
    let len = (!text.is_empty()).then_some(text.len());
    let fut = tower::ServiceExt::oneshot(t.router.clone(), request(t, method, uri, Body::from(text), len, true));
    let resp = match &t.env {
        Some(env) => TEST_ENV.scope(env.clone(), fut).await,
        None => fut.await,
    }
    .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn post(t: &T, uri: &str, body: Value) -> (StatusCode, Value) {
    send(t, Method::POST, uri, body).await
}

#[tokio::test]
async fn band_lock_refuses_empty_and_unknown_bands_before_any_write() {
    let t = setup("bands").await;
    // every RAT empty: would take the backup WAN off the air
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": [], "nsaNr5gBands": [], "nr5gBands": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // mode unknown -> AUTO: every RAT must keep a band
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": [], "nr5gBands": ["41"] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // ...unless the request itself picks a mode that does not use that RAT
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": [], "nsaNr5gBands": [], "nr5gBands": ["41"], "modePref": "LTE" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "LTE-only mode with no LTE band: {v}");
    // not a 3GPP band
    for bad in [json!(["999"]), json!(["0"]), json!(["200"])] {
        let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": bad, "nsaNr5gBands": ["41"], "nr5gBands": ["41"] })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": ["41"], "modePref": "GSM" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn band_lock_write_failure_reports_what_was_applied() {
    let t = setup("bandfail").await;
    // valid request, but the modem never confirms the first write
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2", "66"], "nsaNr5gBands": ["41"], "nr5gBands": ["41"] })).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    assert_eq!(v["status"], "error");
    assert_eq!(v["failed"], "lte_band", "{v}");
    assert_eq!(v["applied"], json!([]), "{v}");
    assert_eq!(v["notApplied"], json!(["nsa_nr5g_band", "nr5g_band"]), "{v}");
    assert_eq!(v["partial"], false, "{v}");
    assert!(v["error"].as_str().unwrap().contains("nothing was changed"), "{v}");
}

#[tokio::test]
async fn mode_request_is_validated_as_a_whole() {
    let t = setup("mode").await;
    for body in [
        json!({ "modePref": "LTE", "simSlot": 9 }),
        json!({ "modePref": "LTE", "apn": "a\"b" }),
        json!({ "nr5gDisableMode": 1, "simSlot": 0 }),
        json!({ "simSlot": 1, "apn": "ok.apn", "pdpType": "PPP" }),
        json!({ "pdpType": "IP" }),
    ] {
        let (s, v) = post(&t, "/api/v1/cellular/mode", body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
    }
    // a valid request that the modem cannot confirm reports the failed step
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "simSlot": 2 })).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    assert_eq!(v["failed"], "sim_slot", "{v}");
}

#[tokio::test]
async fn cell_lock_enforces_3gpp_ranges() {
    let t = setup("lock").await;
    for body in [
        json!({ "rat": "lte", "pci": 504, "arfcn": 66786 }),
        json!({ "rat": "lte", "pci": -1, "arfcn": 66786 }),
        json!({ "rat": "lte", "pci": 1, "arfcn": -5 }),
        json!({ "rat": "lte", "pci": 1, "arfcn": 262_144 }),
        json!({ "rat": "nr5g", "pci": 1008, "arfcn": 521_310, "scs": 30, "band": 41 }),
        json!({ "rat": "nr5g", "pci": 1, "arfcn": 3_279_166, "scs": 30, "band": 41 }),
        json!({ "rat": "nr5g", "pci": 1, "arfcn": 521_310, "scs": 45, "band": 41 }),
        json!({ "rat": "nr5g", "pci": 1, "arfcn": 521_310, "scs": 30, "band": -41 }),
        json!({ "rat": "nr5g", "pci": 1, "arfcn": 521_310, "scs": 30, "band": 0 }),
    ] {
        let (s, v) = post(&t, "/api/v1/cellular/cell-lock", body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
    }
    // in range: reaches the (absent) modem
    let (s, _) = post(&t, "/api/v1/cellular/cell-lock", json!({ "rat": "nr5g", "pci": 1007, "arfcn": 3_279_165, "scs": 240, "band": 261 })).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    let (s, _) = post(&t, "/api/v1/cellular/cell-lock", json!({ "rat": "lte", "pci": 503, "arfcn": 262_143 })).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn ping_targets_cannot_inject_arguments() {
    let t = setup("ping").await;
    for host in ["-f 8.8.8.8", "-f", "8.8.8.8 -s 65000", "a b", "$(reboot)", "--help", "1.1.1.1;reboot"] {
        let (s, v) = post(&t, "/api/v1/diagnostics/latency", json!({ "host": host })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "latency {host:?}: {v}");
        let (s, v) = post(&t, "/api/v1/diagnostics/quecwatch", json!({ "enabled": false, "pingTarget": host })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "quecwatch {host:?}: {v}");
    }
    let (s, v) = post(&t, "/api/v1/speedtest/start", json!({ "serverId": -5 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn profile_delete_of_a_missing_index_is_404() {
    // A fake `uci` that knows exactly one profile (index 0): index 999 is
    // missing because the tool says so, not because uci is absent on the host.
    let (t, sbx) = setup_sandboxed("prof", None).await;
    sbx.show(PROFILE0);
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/profiles?index=999", Value::Null).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    // Valid fields + missing index -> 404
    let (s, v) = post(&t, "/api/v1/cellular/profiles", json!({ "index": 999, "name": "x", "iccid": "89012600000000000017", "apn": "a" })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    // Invalid fields or legacy/invalid networkType + missing index -> 400 (validated before index lookup)
    for body in [
        json!({ "index": 999, "name": "x", "iccid": "89012600000000000017", "apn": "a\"b" }),
        json!({ "index": 999, "name": "x", "iccid": "89012600000000000017", "apn": "a", "networkType": "WCDMA:LTE" }),
        json!({ "index": 999, "name": "x", "iccid": "89012600000000000017", "apn": "a", "networkType": "GSM" }),
        json!({ "name": "x", "iccid": "89012600000000000017", "apn": "a\"b" }),
        json!({ "name": "x\"y", "iccid": "89012600000000000017", "apn": "a" }),
        json!({ "name": "x", "iccid": "89012600000000000017", "apn": "a", "lteBands": "2;AT+CFUN=0" }),
        json!({ "name": "x", "iccid": "89012600000000000017", "apn": "a", "networkType": "GSM\"" }),
        json!({ "name": "x", "iccid": "89012600000000000017", "apn": "a", "ttl": "999" }),
        json!({ "name": "x", "iccid": "89012600000000000017", "apn": "a", "imei": "123" }),
    ] {
        let (s, v) = post(&t, "/api/v1/cellular/profiles", body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
    }
}

#[tokio::test]
async fn maintenance_validates_schedule_and_smtp_before_writing() {
    let t = setup("maint").await;
    for body in [
        json!({ "scheduledRebootEnabled": true, "scheduledRebootTime": "99:99", "scheduledRebootDays": ["sunday"] }),
        json!({ "scheduledRebootEnabled": true, "scheduledRebootTime": "04:00", "scheduledRebootDays": ["someday"] }),
        json!({ "scheduledRebootEnabled": true, "scheduledRebootTime": "4:00\n* * * * * reboot", "scheduledRebootDays": ["sunday"] }),
        json!({ "scheduledRebootEnabled": true, "scheduledRebootTime": "04:00", "scheduledRebootDays": [] }),
        // a partial SMTP set is refused instead of silently ignored
        json!({ "smtpSender": "qa@example.com", "smtpPassword": "p" }),
        json!({ "smtpSender": "qa@example.com\nhost evil.example", "smtpPassword": "p", "smtpRecipient": "ops@example.com" }),
        json!({ "smtpSender": "qa@example.com", "smtpPassword": "p\npasswordeval rm -rf /", "smtpRecipient": "ops@example.com" }),
        json!({ "smtpSender": "qa@example.com", "smtpPassword": "p", "smtpRecipient": "-oQ/tmp/x@example.com" }),
        // the schedule is not written when the SMTP part of the same request is bad
        json!({ "scheduledRebootEnabled": true, "scheduledRebootTime": "04:00", "scheduledRebootDays": ["sunday"], "smtpSender": "bad", "smtpPassword": "p", "smtpRecipient": "ops@example.com" }),
    ] {
        let (s, v) = post(&t, "/api/v1/system/maintenance", body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
    }
}

#[test]
fn smtp_addresses_cannot_become_flags_or_header_lists() {
    for bad in ["-oQ/tmp/x@example.com", "a@b,c@d", "a@b;c", "x <a@b>", "a@b\nBcc: c@d"] {
        assert!(!crate::handlers::is_plain_email(bad), "{bad:?}");
    }
    assert!(crate::handlers::is_plain_email("alerts+modem@example.com"));
}

#[tokio::test]
async fn tailscale_start_when_not_installed_is_409() {
    // the unit-test host has no /etc/init.d/tailscale (QM_ROOT is never set here)
    if std::path::Path::new("/etc/init.d/tailscale").exists() {
        return;
    }
    let t = setup("ts").await;
    let (s, v) = post(&t, "/api/v1/network/lan", json!({ "action": "tailscale_toggle", "enabled": true })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["error"].as_str().unwrap().contains("not installed"), "{v}");
}

#[tokio::test]
async fn empty_at_command_is_a_client_error() {
    let t = setup("at").await;
    for cmd in ["", "   ", "\t"] {
        let (s, v) = post(&t, "/api/v1/modem/at", json!({ "command": cmd, "confirm": true })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{cmd:?}: {v}");
    }
    let (s, v) = post(&t, "/api/v1/modem/at", json!({ "confirm": true })).await;
    assert!(s.is_client_error(), "missing command: {s} {v}");
}

/// Streams `total` bytes: the first chunk now, the rest after `pause`.
fn slow_body(total: usize, pause: Duration) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(2);
    tokio::spawn(async move {
        let first = 64 * 1024;
        let _ = tx.send(Ok(vec![0u8; first].into())).await;
        tokio::time::sleep(pause).await;
        let _ = tx.send(Ok(vec![0u8; total - first].into())).await;
    });
    Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|v| (v, rx)) }))
}

async fn send_slow(t: &T, uri: &str, total: usize, pause: Duration, authed: bool) -> (StatusCode, Value) {
    let req = request(t, Method::POST, uri, slow_body(total, pause), Some(total), authed);
    let resp = tower::ServiceExt::oneshot(t.router.clone(), req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test(start_paused = true)]
async fn archive_upload_gets_a_size_appropriate_body_deadline() {
    let t = setup("upload").await;
    // 8 MiB arriving over 20 s (~3.4 Mbit/s): longer than the generic 15 s body
    // deadline, well within a deadline sized for 8 MiB. The body is read in full
    // and judged on its content (not gzip), not cut off.
    let total = 8 * 1024 * 1024;
    let (s, v) = send_slow(&t, "/api/v1/admin/backup/inspect", total, Duration::from_secs(20), true).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], "Not a .tar.gz backup", "upload was cut off by the body deadline: {v}");
    let (s, v) = send_slow(&t, "/api/v1/admin/backup/restore?confirm=RESTORE", total, Duration::from_secs(20), true).await;
    assert_eq!(v["error"], "Not a .tar.gz backup", "{s} {v}");

    // other routes keep the generic deadline
    let (s, v) = send_slow(&t, "/api/v1/system/settings", 128 * 1024, Duration::from_secs(20), true).await;
    assert!(s.is_client_error() && v["status"] != "success", "slow body on a generic route was accepted: {s} {v}");
    // unauthenticated requests never get the longer deadline (refused before the body is read)
    let (s, _) = send_slow(&t, "/api/v1/admin/backup/inspect", total, Duration::from_secs(20), false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test(start_paused = true)]
async fn archive_upload_deadline_is_still_bounded() {
    let t = setup("upload-cap").await;
    // 1 MiB declared, but the client stalls for 10 minutes: cut off
    let (s, v) = send_slow(&t, "/api/v1/admin/backup/inspect", 1024 * 1024, Duration::from_secs(600), true).await;
    assert!(s.is_client_error(), "{s}");
    assert_ne!(v["error"], "Not a .tar.gz backup", "a stalled upload must hit the deadline: {v}");
}

// ─────────────── radio safety, profiles, cell lock (4.1.1 re-review) ───────────────

use crate::fakeat::{Fail, FakeModem, Radio};

/// Per-test sandbox: a file root and a bin dir holding a fake `uci`.
struct Sandbox {
    dir: std::path::PathBuf,
}

const PROFILE0: &str = "cellprofiles.@profile[0]=profile\n\
cellprofiles.@profile[0].name='TMO'\n\
cellprofiles.@profile[0].iccid='89012600000000000017'\n\
cellprofiles.@profile[0].apn='fast.t-mobile.com'\n";

impl Sandbox {
    fn new(tag: &str) -> (Sandbox, TestEnv) {
        let dir = std::env::temp_dir().join(format!("qm-sbx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root/etc/config")).unwrap();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let d = dir.display();
        // `uci show` answers from show.txt; show_mode makes it fail like the
        // real tool ("Entry not found" for a missing config, anything else is
        // an error). Every call is logged one per line.
        let script = format!(
            "#!/bin/sh\nD='{d}'\nprintf '%s\\n' \"$*\" >> \"$D/uci.log\"\n[ \"$1\" = -q ] && shift\n\
case \"$1\" in\n\
  show) case \"$(cat \"$D/show_mode\" 2>/dev/null)\" in\n\
          notfound) echo 'uci: Entry not found' >&2; exit 1;;\n\
          ioerror) echo 'uci: I/O error' >&2; exit 1;;\n\
        esac\n\
        cat \"$D/show.txt\" 2>/dev/null; exit 0;;\n\
  add) echo cfg0a1b2c; exit 0;;\n\
  get) exit 1;;\n\
  *) exit 0;;\n\
esac\n"
        );
        let uci = dir.join("bin/uci");
        std::fs::write(&uci, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&uci, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = TestEnv { root: Some(dir.join("root").display().to_string()), bin: Some(dir.join("bin").display().to_string()) };
        (Sandbox { dir }, env)
    }
    fn show(&self, text: &str) {
        std::fs::write(self.dir.join("show.txt"), text).unwrap();
    }
    fn show_mode(&self, mode: &str) {
        std::fs::write(self.dir.join("show_mode"), mode).unwrap();
    }
    fn uci_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("uci.log")).unwrap_or_default().lines().map(str::to_string).collect()
    }
    fn root(&self) -> std::path::PathBuf {
        self.dir.join("root")
    }
}

async fn setup_sandboxed(tag: &str, modem: Option<&FakeModem>) -> (T, Sandbox) {
    let (sbx, env) = Sandbox::new(tag);
    let www = sbx.dir.join("www");
    let _ = std::fs::create_dir_all(&www);
    let auth = AuthStore::new(sbx.dir.join("sessions"));
    let app = match modem {
        Some(m) => AppState::for_tests_with_smd(www, auth.clone(), m.client()),
        None => AppState::for_tests(www, auth.clone()),
    };
    (build(app, auth, Some(env)).await, sbx)
}

async fn setup_modem(tag: &str, radio: Radio) -> (T, FakeModem, Sandbox) {
    let m = FakeModem::new(radio);
    let (t, sbx) = setup_sandboxed(tag, Some(&m)).await;
    (t, m, sbx)
}

/// RATs a mode lets the modem use, [LTE, NR5G-NSA, NR5G-SA]. Written out
/// here from the Quectel semantics (nr5g_disable_mode 1 = SA off, 2 = NSA
/// off), not derived from the code under test.
fn allowed(mode: &str, disable: i32) -> [bool; 3] {
    match (mode, disable) {
        ("LTE", _) => [true, false, false],
        ("NR5G", 1) => [false, false, false],
        ("NR5G", _) => [false, false, true],
        (_, 1) => [true, true, false],
        (_, 2) => [true, false, true],
        _ => [true, true, true],
    }
}

fn has_bands(r: &Radio) -> [bool; 3] {
    [!r.lte.is_empty(), !r.nsa.is_empty(), !r.sa.is_empty()]
}

/// The invariant: at least one RAT the mode allows has at least one band.
fn usable(r: &Radio) -> bool {
    allowed(&r.mode, r.disable).iter().zip(has_bands(r)).any(|(a, b)| *a && b)
}

/// What the band lock enforces on top: no allowed RAT is left without bands.
fn strict_ok(r: &Radio) -> bool {
    usable(r) && allowed(&r.mode, r.disable).iter().zip(has_bands(r)).all(|(a, b)| !*a || b)
}

fn pattern(p: u8) -> (Vec<&'static str>, Vec<&'static str>, Vec<&'static str>) {
    (
        if p & 1 != 0 { vec!["2", "66"] } else { vec![] },
        if p & 2 != 0 { vec!["41"] } else { vec![] },
        if p & 4 != 0 { vec!["41", "71"] } else { vec![] },
    )
}

fn start_states() -> Vec<Radio> {
    vec![
        Radio::new("2:4:66", "41", "41:71", "AUTO", 0),
        Radio::new("2", "", "", "LTE", 0),
        Radio::new("", "", "41", "NR5G", 0),
        Radio::new("12", "71", "", "LTE:NR5G", 1),
        Radio::new("12", "", "71", "AUTO", 2),
        Radio::new("", "", "25", "NR5G", 2),
    ]
}

#[tokio::test]
async fn band_lock_invariant_holds_for_every_mode_and_band_combination() {
    let (t, m, _sbx) = setup_modem("inv-bands", Radio::new("2", "", "", "LTE", 0)).await;
    let (mut checked, mut accepted) = (0, 0);
    for start in start_states() {
        assert!(strict_ok(&start), "start state {start:?}");
        for mode in [None, Some("AUTO"), Some("LTE"), Some("NR5G"), Some("LTE:NR5G")] {
            for disable in [None, Some(0), Some(1), Some(2)] {
                for p in 0..8u8 {
                    m.reset(start.clone());
                    let (lte, nsa, sa) = pattern(p);
                    let mut body = json!({ "lteBands": lte, "nsaNr5gBands": nsa, "nr5gBands": sa });
                    if let Some(md) = mode {
                        body["modePref"] = json!(md);
                    }
                    if let Some(d) = disable {
                        body["nr5gDisableMode"] = json!(d);
                    }
                    let target = Radio::new(
                        &lte.join(":"),
                        &nsa.join(":"),
                        &sa.join(":"),
                        mode.unwrap_or(&start.mode),
                        disable.unwrap_or(start.disable),
                    );
                    let (s, v) = post(&t, "/api/v1/cellular/bands", body.clone()).await;
                    let ctx = format!("start {start:?} body {body} -> {s} {v}");
                    if strict_ok(&target) {
                        assert_eq!(s, StatusCode::OK, "valid change refused: {ctx}");
                        assert_eq!(m.radio(), target, "{ctx}");
                        for snap in m.snapshots() {
                            assert!(usable(&snap), "intermediate state has no usable RAT: {snap:?} {ctx}");
                            assert!(strict_ok(&snap), "intermediate state strands an allowed RAT: {snap:?} {ctx}");
                        }
                        accepted += 1;
                    } else {
                        assert_eq!(s, StatusCode::BAD_REQUEST, "unusable change accepted: {ctx}");
                        assert_eq!(m.writes(), Vec::<String>::new(), "refused but written: {ctx}");
                        assert_eq!(m.radio(), start, "{ctx}");
                    }
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 6 * 5 * 4 * 8);
    assert!(accepted > 100 && checked - accepted > 100, "{accepted} of {checked} accepted");
}

#[tokio::test]
async fn nr5g_only_with_sa_disabled_is_refused_everywhere() {
    let (t, m, _sbx) = setup_modem("nr5g-sa-off", Radio::new("2:66", "41", "41:71", "AUTO", 0)).await;
    // the verifiers' bypass: every list empty, NR5G-only with SA disabled
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": [], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "NR5G", "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // ...with bands on every RAT it is still a mode with no usable RAT
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": ["41"], "modePref": "NR5G", "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // network mode: refused regardless of the bands, with a plain message
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "modePref": "NR5G", "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let msg = v["error"].as_str().unwrap_or_default();
    assert!(msg.contains("NR5G") && msg.contains("SA"), "{v}");
    // half of it, with the other half already on the modem
    m.reset(Radio::new("2:66", "41", "41:71", "AUTO", 1));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "modePref": "NR5G" })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    m.reset(Radio::new("", "", "41", "NR5G", 0));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": [], "nsaNr5gBands": [], "nr5gBands": ["41"], "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(m.writes(), Vec::<String>::new());
    // a backup that carries the combination is rejected before anything is applied
    let mut b = serde_json::to_value(crate::appbackup::tests::sample()).unwrap();
    b["radio"]["modePref"] = json!("NR5G");
    b["radio"]["nr5gDisableMode"] = json!(1);
    let (s, v) = post(&t, "/api/v1/system/config-backup/apply", json!({ "bundle": b, "items": ["radio.mode"], "confirm": "RESTORE" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(m.writes(), Vec::<String>::new());
}

#[tokio::test]
async fn network_mode_invariant_holds_for_every_mode_and_band_combination() {
    let (t, m, _sbx) = setup_modem("inv-mode", Radio::new("2", "", "", "LTE", 0)).await;
    for p in 0..8u8 {
        let (lte, nsa, sa) = pattern(p);
        let lists = (lte.join(":"), nsa.join(":"), sa.join(":"));
        // the first mode under which these bands are a valid starting point
        let start = [("AUTO", 0), ("LTE:NR5G", 1), ("AUTO", 2), ("LTE", 0), ("NR5G", 0)]
            .iter()
            .map(|(md, d)| Radio::new(&lists.0, &lists.1, &lists.2, md, *d))
            .find(strict_ok)
            .unwrap_or_else(|| Radio::new(&lists.0, &lists.1, &lists.2, "AUTO", 0));
        for mode in [None, Some("AUTO"), Some("LTE"), Some("NR5G"), Some("LTE:NR5G")] {
            for disable in [None, Some(0), Some(1), Some(2)] {
                if mode.is_none() && disable.is_none() {
                    continue;
                }
                m.reset(start.clone());
                let mut body = json!({});
                if let Some(md) = mode {
                    body["modePref"] = json!(md);
                }
                if let Some(d) = disable {
                    body["nr5gDisableMode"] = json!(d);
                }
                let target = Radio { mode: mode.unwrap_or(&start.mode).to_string(), disable: disable.unwrap_or(start.disable), ..start.clone() };
                let (s, v) = post(&t, "/api/v1/cellular/mode", body.clone()).await;
                let ctx = format!("start {start:?} body {body} -> {s} {v}");
                if strict_ok(&target) {
                    assert_eq!(s, StatusCode::OK, "valid mode refused: {ctx}");
                    assert_eq!(m.radio(), target, "{ctx}");
                    if strict_ok(&start) {
                        for snap in m.snapshots() {
                            assert!(strict_ok(&snap), "intermediate state {snap:?}: {ctx}");
                        }
                    }
                } else {
                    assert_eq!(s, StatusCode::CONFLICT, "unusable mode accepted: {ctx}");
                    assert_eq!(m.writes(), Vec::<String>::new(), "{ctx}");
                }
            }
        }
    }
}

fn w(cmds: &[&str]) -> Vec<String> {
    cmds.iter().map(|c| c.to_string()).collect()
}

#[tokio::test]
async fn radio_writes_widen_first_then_mode_then_narrow() {
    let (t, m, _sbx) = setup_modem("order", Radio::new("2:4:66", "41", "41:71", "AUTO", 0)).await;
    // AUTO -> LTE-only: NR lists are cleared only once the mode no longer uses them
    // (nr5gDisableMode is already 0, so that no-op write is skipped).
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        m.writes(),
        w(&[
            "AT+QNWPREFCFG=\"lte_band\",2:66",
            "AT+QNWPREFCFG=\"mode_pref\",LTE",
            "AT+QNWPREFCFG=\"nsa_nr5g_band\",0",
            "AT+QNWPREFCFG=\"nr5g_band\",0",
        ])
    );
    assert!(m.snapshots().iter().all(strict_ok), "{:?}", m.snapshots());

    // LTE-only -> AUTO with SA disabled: the bands the new mode needs first, and
    // SA is disabled before AUTO lands (AUTO with SA still enabled would use SA
    // while it has no band). lte_band and nr5g_band already match, so skipped.
    m.reset(Radio::new("2", "", "", "LTE", 0));
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": [], "modePref": "AUTO", "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        m.writes(),
        w(&[
            "AT+QNWPREFCFG=\"nsa_nr5g_band\",41",
            "AT+QNWPREFCFG=\"nr5g_disable_mode\",1",
            "AT+QNWPREFCFG=\"mode_pref\",AUTO",
        ])
    );
    assert!(m.snapshots().iter().all(strict_ok), "{:?}", m.snapshots());

    // network mode alone, same rule: AUTO,1 (no SA band) -> LTE,0 writes the mode first
    m.reset(Radio::new("2", "41", "", "AUTO", 1));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "modePref": "LTE", "nr5gDisableMode": 0 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(m.writes(), w(&["AT+QNWPREFCFG=\"mode_pref\",LTE", "AT+QNWPREFCFG=\"nr5g_disable_mode\",0"]));
    assert!(m.snapshots().iter().all(strict_ok), "{:?}", m.snapshots());
    m.reset(Radio::new("2", "41", "", "LTE", 0));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "modePref": "AUTO", "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(m.writes(), w(&["AT+QNWPREFCFG=\"nr5g_disable_mode\",1", "AT+QNWPREFCFG=\"mode_pref\",AUTO"]));
    assert!(m.snapshots().iter().all(strict_ok), "{:?}", m.snapshots());
}

#[tokio::test]
async fn failed_radio_write_rolls_back_what_was_applied() {
    let start = Radio::new("2:4:66", "41", "41:71", "AUTO", 0);
    let (t, m, _sbx) = setup_modem("rollback", start.clone()).await;
    let lte_only = json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 });

    // modem ERROR on the mode write: 422, the LTE list already written is restored
    m.fail("\"mode_pref\",", Fail::Cme(50), Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only.clone()).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["failed"], "mode_pref", "{v}");
    assert_eq!(v["applied"], json!(["lte_band"]), "{v}");
    assert_eq!(v["notApplied"], json!(["nsa_nr5g_band", "nr5g_band"]), "{v}");
    assert_eq!(v["partial"], true, "{v}");
    assert_eq!(v["rollback"]["attempted"], true, "{v}");
    assert_eq!(v["rollback"]["ok"], true, "{v}");
    assert_eq!(v["rollback"]["restored"], json!(["lte_band"]), "{v}");
    assert!(v["error"].as_str().unwrap().contains("CME ERROR: 50"), "{v}");
    assert_eq!(
        m.writes(),
        w(&["AT+QNWPREFCFG=\"lte_band\",2:66", "AT+QNWPREFCFG=\"mode_pref\",LTE", "AT+QNWPREFCFG=\"lte_band\",2:4:66"])
    );
    assert_eq!(m.radio(), start);
    assert!(m.snapshots().iter().all(strict_ok), "{:?}", m.snapshots());

    // the line drops on the mode write: 502, rollback over the reopened line
    m.reset(start.clone());
    m.fail("\"mode_pref\",", Fail::Drop, Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only.clone()).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    assert_eq!(v["failed"], "mode_pref", "{v}");
    assert_eq!(v["rollback"]["ok"], true, "{v}");
    assert_eq!(m.radio(), start);

    // the rollback itself fails: reported, not hidden
    m.reset(start.clone());
    m.fail("\"mode_pref\",", Fail::Error, Some(1));
    m.fail("\"lte_band\",2:4:66", Fail::Error, None);
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["rollback"]["attempted"], true, "{v}");
    assert_eq!(v["rollback"]["ok"], false, "{v}");
    assert_eq!(v["rollback"]["failed"], json!(["lte_band"]), "{v}");
    assert!(v["error"].as_str().unwrap().to_ascii_lowercase().contains("rollback failed"), "{v}");

    // network settings: the mode change is undone when the SIM switch fails
    m.reset(Radio::new("2", "41", "41", "AUTO", 1));
    m.fail("AT+QUIMSLOT=", Fail::Cme(3), Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 0, "simSlot": 2 })).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["failed"], "sim_slot", "{v}");
    assert_eq!(v["applied"], json!(["nr5g_disable_mode"]), "{v}");
    assert_eq!(v["rollback"]["ok"], true, "{v}");
    assert_eq!(
        m.writes(),
        w(&["AT+QNWPREFCFG=\"nr5g_disable_mode\",0", "AT+QUIMSLOT=2", "AT+QNWPREFCFG=\"nr5g_disable_mode\",1"])
    );
    assert_eq!(m.radio().disable, 1);

    // ...and the SIM slot when the APN write fails
    m.reset(Radio::new("2", "41", "41", "AUTO", 0));
    m.fail("AT+CGDCONT=", Fail::Error, Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "simSlot": 2, "apn": "new.apn" })).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["applied"], json!(["sim_slot"]), "{v}");
    assert_eq!(v["rollback"]["restored"], json!(["sim_slot"]), "{v}");
    assert_eq!(m.with(|s| s.sim_slot), 1);
    assert_eq!(m.with(|s| s.cgdcont.1.clone()), "old.apn");
}

#[tokio::test]
async fn restore_applies_mode_and_bands_as_one_change() {
    // the device has LTE only; the backup (consistent) is LTE:NR5G with full lists
    let (t, m, _sbx) = setup_modem("restore", Radio::new("2", "", "", "LTE", 0)).await;
    let bundle = serde_json::to_value(crate::appbackup::tests::sample()).unwrap();
    let (s, v) = post(&t, "/api/v1/system/config-backup/apply", json!({ "bundle": bundle, "items": ["radio.mode", "radio.bands"], "confirm": "RESTORE" })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["results"].as_array().unwrap().iter().all(|r| r["ok"] == true), "{v}");
    assert_eq!(m.radio(), Radio::new("2:66", "41", "41:71", "LTE:NR5G", 0));
    assert!(m.snapshots().iter().all(strict_ok), "{:?}", m.snapshots());
    assert_eq!(
        m.writes(),
        w(&[
            "AT+QNWPREFCFG=\"lte_band\",2:66",
            "AT+QNWPREFCFG=\"nsa_nr5g_band\",41",
            "AT+QNWPREFCFG=\"nr5g_band\",41:71",
            "AT+QNWPREFCFG=\"mode_pref\",LTE:NR5G",
        ])
    );
    // mode alone is still checked against the bands on the device
    m.reset(Radio::new("2", "", "", "LTE", 0));
    let (s, v) = post(&t, "/api/v1/system/config-backup/apply", json!({ "bundle": bundle, "items": ["radio.mode"], "confirm": "RESTORE" })).await;
    assert_eq!(s, StatusCode::MULTI_STATUS, "{v}");
    assert_eq!(m.writes(), Vec::<String>::new());
}

#[tokio::test]
async fn band_checks_never_trust_a_stale_mode() {
    let (t, m, _sbx) = setup_modem("stale", Radio::new("2", "", "", "LTE", 0)).await;
    let lte_only = json!({ "lteBands": ["2"], "nsaNr5gBands": [], "nr5gBands": [] });
    // the daemon learns LTE-only...
    let (s, _) = send(&t, Method::GET, "/api/v1/cellular/mode", Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    // ...then cellctl / the menu / r10-modem-ctl switch the modem to AUTO over IPC
    let r = crate::ipc::dispatch_ipc(
        t.app.clone(),
        crate::ipc::IpcRequest::QuectelAt { command: "AT+QNWPREFCFG=\"mode_pref\",AUTO".into(), timeout_secs: Some(5) },
        true,
    )
    .await;
    assert!(r.ok, "{:?}", r.error);
    // an LTE-only band lock would now leave NSA/SA (used by AUTO) without bands
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(m.writes(), w(&["AT+QNWPREFCFG=\"mode_pref\",AUTO"]));

    // same, when the mode cannot be re-read: the IPC write must have dropped
    // the cached LTE-only mode, so the strictest assumption applies
    m.reset(Radio::new("2", "", "", "LTE", 0));
    let (s, _) = send(&t, Method::GET, "/api/v1/cellular/mode", Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    let r = crate::ipc::dispatch_ipc(
        t.app.clone(),
        crate::ipc::IpcRequest::QuectelAt { command: "at+qnwprefcfg=\"mode_pref\",AUTO".into(), timeout_secs: Some(5) },
        true,
    )
    .await;
    assert!(r.ok, "{:?}", r.error);
    m.fail("AT+QNWPREFCFG=\"mode_pref\"", Fail::Error, None);
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(m.radio().nsa, "");
    assert_eq!(m.writes(), w(&["at+qnwprefcfg=\"mode_pref\",AUTO"]));
}

#[tokio::test]
async fn cell_lock_reports_modem_and_persistence_failures() {
    let (t, m, sbx) = setup_modem("lockfail", Radio::new("2", "41", "41", "AUTO", 0)).await;
    let lte = json!({ "rat": "lte", "pci": 371, "arfcn": 66786, "persist": true });
    // success: locked, persisted, save_ctrl sent
    let (s, v) = post(&t, "/api/v1/cellular/cell-lock", lte.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let saved = std::fs::read_to_string(sbx.root().join("etc/cellcore/settings.json")).unwrap();
    assert!(saved.contains("1,66786,371"), "{saved}");
    assert_eq!(m.with(|s| s.save_ctrl.clone()), Some("1,0".to_string()));

    // the modem refuses save_ctrl (persisting the lock across reboots): 422
    m.fail("\"save_ctrl\",", Fail::Cme(3), Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/cell-lock", lte.clone()).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["error"].as_str().unwrap().contains("save_ctrl"), "{v}");

    // the settings file cannot be written: 500
    let qm_dir = sbx.root().join("etc/cellcore");
    std::fs::remove_dir_all(&qm_dir).unwrap();
    std::fs::write(&qm_dir, b"not a directory").unwrap();
    let (s, v) = post(&t, "/api/v1/cellular/cell-lock", lte.clone()).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    let (s, v) = post(&t, "/api/v1/cellular/cell-lock", json!({ "scheduleEnabled": true, "startTime": "01:00", "endTime": "02:00" })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    std::fs::remove_file(&qm_dir).unwrap();

    // unlock: a modem ERROR is a 422, a dropped line a 502, never success
    m.fail("\"common/4g\",0", Fail::Cme(3), Some(1));
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/cell-lock?rat=lte", Value::Null).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(m.with(|s| s.lock4g.clone()), Some("1,66786,371".to_string()), "still locked");
    assert_eq!(t.app.settings.read().await.cell_lock_lte, "1,66786,371", "the lock is still recorded");
    m.fail("\"common/5g\",0", Fail::Drop, Some(1));
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/cell-lock", Value::Null).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/cell-lock", Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(m.with(|s| (s.lock4g.clone(), s.lock5g.clone())), (None, None));
    let saved = std::fs::read_to_string(sbx.root().join("etc/cellcore/settings.json")).unwrap();
    assert!(!saved.contains("1,66786,371"), "unlock is persisted: {saved}");
}

const ICCID: &str = "89012600000000000017";

#[tokio::test]
async fn profile_names_and_network_types_accept_benign_text() {
    let (t, sbx) = setup_sandboxed("prof-text", None).await;
    sbx.show(PROFILE0);
    // (WCDMA:LTE was accepted as new input before 4.1.1 round 3; new input is
    // now the canonical set, so it moved to the refused list below and the
    // stored-verbatim check moved to a canonical combination.)
    for (name, net) in [("Mom's SIM", "LTE:NR5G"), ("Work (backup) #2 & co.", ""), ("Café ✓", "nr5g"), ("x`y", "NR5G:LTE")] {
        let (s, v) = post(&t, "/api/v1/cellular/profiles", json!({ "name": name, "iccid": ICCID, "apn": "fast.t-mobile.com", "networkType": net })).await;
        assert_eq!(s, StatusCode::OK, "{name:?} / {net:?}: {v}");
    }
    let log = sbx.uci_log();
    assert!(log.iter().any(|l| l == "set cellprofiles.cfg0a1b2c.name=Mom's SIM"), "{log:?}");
    assert!(log.iter().any(|l| l == "set cellprofiles.cfg0a1b2c.network_type=NR5G"), "known values are normalised: {log:?}");
    assert!(log.iter().any(|l| l == "set cellprofiles.cfg0a1b2c.network_type=NR5G:LTE"), "{log:?}");
    assert!(!log.iter().any(|l| l.contains("network_type=WCDMA")), "{log:?}");
    assert!(log.iter().any(|l| l == "set cellprofiles.cfg0a1b2c.network_type="), "{log:?}");
    // still refused: control characters, double quotes, backslashes, colons in
    // names; anything in a network type that is not a mode token list
    for body in [
        json!({ "name": "a\nb", "iccid": ICCID, "apn": "a" }),
        json!({ "name": "a\u{7f}b", "iccid": ICCID, "apn": "a" }),
        json!({ "name": "a\"b", "iccid": ICCID, "apn": "a" }),
        json!({ "name": "a\\b", "iccid": ICCID, "apn": "a" }),
        json!({ "name": "a:b", "iccid": ICCID, "apn": "a" }),
        json!({ "name": "x".repeat(65), "iccid": ICCID, "apn": "a" }),
        json!({ "name": "x", "iccid": ICCID, "apn": "a", "networkType": "LTE,NR5G" }),
        json!({ "name": "x", "iccid": ICCID, "apn": "a", "networkType": "LTE NR5G" }),
        json!({ "name": "x", "iccid": ICCID, "apn": "a", "networkType": "LTE;+CFUN=0" }),
        json!({ "name": "x", "iccid": ICCID, "apn": "a", "networkType": "A".repeat(33) }),
        json!({ "name": "x`y", "iccid": ICCID, "apn": "a", "networkType": "WCDMA:LTE" }),
    ] {
        let (s, v) = post(&t, "/api/v1/cellular/profiles", body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
    }
    // a stored name with an apostrophe reads back intact (uci show escapes it as '\'')
    sbx.show("cellprofiles.@profile[0]=profile\ncellprofiles.@profile[0].name='Mom'\\''s SIM'\ncellprofiles.@profile[0].iccid='89012600000000000017'\ncellprofiles.@profile[0].apn='a'\n");
    let (s, v) = send(&t, Method::GET, "/api/v1/cellular/profiles", Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["profiles"][0]["name"], "Mom's SIM", "{v}");
}

#[tokio::test]
async fn profile_bands_and_ttl_are_strict() {
    let (t, m, sbx) = setup_modem("prof-num", Radio::new("2", "41", "41", "AUTO", 0)).await;
    sbx.show(PROFILE0);
    let base = |k: &str, v: &str| {
        let mut b = json!({ "name": "x", "iccid": ICCID, "apn": "a" });
        b[k] = json!(v);
        b
    };
    for (k, v) in [
        ("lteBands", "0"),
        ("lteBands", "999"),
        ("lteBands", "0:0:000"),
        ("lteBands", "200"),
        ("lteBands", "2::66"),
        ("lteBands", "2;AT"),
        ("saNr5gBands", "0"),
        ("saNr5gBands", "300"),
        ("nsaNr5gBands", "999"),
        ("ttl", "+5"),
        ("ttl", "064"),
        ("ttl", "256"),
        ("ttl", "-1"),
        ("ttl", "1.5"),
        ("ttl", " 6 4"),
    ] {
        let (s, r) = post(&t, "/api/v1/cellular/profiles", base(k, v)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{k}={v:?}: {r}");
    }
    for (k, v, stored) in [
        ("lteBands", "2:66:71", "2:66:71"),
        ("lteBands", "2,66", "2:66"),
        ("lteBands", "", ""),
        ("saNr5gBands", "41:258", "41:258"),
        ("ttl", "0", "0"),
        ("ttl", "", "0"),
        ("ttl", "1", "1"),
        ("ttl", "65", "65"),
        ("ttl", "255", "255"),
    ] {
        let (s, r) = post(&t, "/api/v1/cellular/profiles", base(k, v)).await;
        assert_eq!(s, StatusCode::OK, "{k}={v:?}: {r}");
        let warnings = r["warnings"].as_array().cloned().unwrap_or_default();
        if v.contains(',') {
            assert!(
                warnings.iter().any(|w| w.as_str().unwrap_or_default().contains("comma")),
                "expected comma conversion warning for {k}={v:?}: {r}"
            );
        } else {
            assert!(warnings.is_empty(), "unexpected warning for {k}={v:?}: {r}");
        }
        let key = match k {
            "lteBands" => "lte_bands",
            "saNr5gBands" => "sa_nr5g_bands",
            _ => "ttl",
        };
        let prefix = format!("set cellprofiles.cfg0a1b2c.{key}=");
        let last = sbx.uci_log().into_iter().rev().find(|l| l.starts_with(&prefix));
        assert_eq!(last, Some(format!("{prefix}{stored}")), "{k}={v:?}");
    }
    // legacy "0,2,66" as new POST input is refused with 400 (band 0 invalid)
    let (s, r) = post(&t, "/api/v1/cellular/profiles", base("lteBands", "0,2,66")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    // once the modem has reported its bands, a 3GPP band it lacks is refused
    let (s, _) = send(&t, Method::GET, "/api/v1/cellular/bands", Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!m.with(|s| s.policy.0.split(':').any(|b| b == "8")));
    let (s, r) = post(&t, "/api/v1/cellular/profiles", base("lteBands", "2:8")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
}

#[tokio::test]
async fn profile_lookup_errors_are_not_reported_as_missing() {
    let (t, sbx) = setup_sandboxed("prof-err", None).await;
    sbx.show(PROFILE0);
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/profiles?index=0", Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // no cellprofiles config at all: nothing exists -> 404
    sbx.show_mode("notfound");
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/profiles?index=0", Value::Null).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    // uci fails: a server error carrying the tool's message, not 404
    sbx.show_mode("ioerror");
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/profiles?index=0", Value::Null).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert!(v["error"].as_str().unwrap().contains("I/O error"), "{v}");
    let (s, v) = post(&t, "/api/v1/cellular/profiles", json!({ "index": 0, "name": "x", "iccid": ICCID, "apn": "a" })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    let (s, v) = post(&t, "/api/v1/cellular/profiles/pause", json!({ "index": 0, "paused": true })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    // uci cannot be run at all
    std::fs::remove_file(sbx.dir.join("bin/uci")).unwrap();
    let (s, v) = send(&t, Method::DELETE, "/api/v1/cellular/profiles?index=0", Value::Null).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert!(v["error"].as_str().unwrap().contains("uci"), "{v}");
}

// ───────────── radio safety: lost replies, repair, serialization (round 3) ─────────────

const LTE_266: &str = "AT+QNWPREFCFG=\"lte_band\",2:66";
const MODE_LTE: &str = "AT+QNWPREFCFG=\"mode_pref\",LTE";
const DIS_0: &str = "AT+QNWPREFCFG=\"nr5g_disable_mode\",0";
const NSA_0: &str = "AT+QNWPREFCFG=\"nsa_nr5g_band\",0";
const SA_0: &str = "AT+QNWPREFCFG=\"nr5g_band\",0";

fn bands_json(list: &str) -> Value {
    json!(list.split(':').filter(|b| !b.is_empty()).collect::<Vec<_>>())
}

/// The `finalState` a failure response must carry for this radio.
fn radio_json(r: &Radio) -> Value {
    json!({
        "lteBands": bands_json(&r.lte),
        "nsaNr5gBands": bands_json(&r.nsa),
        "nr5gBands": bands_json(&r.sa),
        "modePref": r.mode,
        "nr5gDisableMode": r.disable,
    })
}

/// A failed radio change: never a success, and what it reports about the
/// modem is what the modem holds. `safe` must be true (every case here keeps
/// the line readable, so the daemon can always verify and repair).
fn assert_honest_and_safe(m: &FakeModem, start: &Radio, s: StatusCode, v: &Value, ctx: &str) {
    assert!(s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::BAD_GATEWAY, "a failed change must be 422/502: {ctx}");
    let fin = m.radio();
    assert_eq!(v["rollback"]["safe"], true, "{ctx}");
    assert!(usable(&fin) && strict_ok(&fin), "final radio {fin:?} breaks the invariant: {ctx}");
    assert_eq!(v["rollback"]["finalState"], radio_json(&fin), "reported final state is not the modem's: {ctx}");
    assert_eq!(v["rollback"]["ok"] == true, fin == *start, "rollback.ok must mean back at the pre-request state ({fin:?}): {ctx}");
    for snap in m.snapshots() {
        assert!(usable(&snap) && strict_ok(&snap), "intermediate state {snap:?}: {ctx}");
    }
}

#[tokio::test]
async fn lost_reply_writes_are_reconciled_from_the_modem() {
    // disable=2 so nr5g_disable_mode=0 also changes its key (all 5 radio steps run).
    let start = Radio::new("2:4:66", "41", "41:71", "AUTO", 2);
    let (t, m, _sbx) = setup_modem("lost", start.clone()).await;
    let lte_only = json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 });
    // every write of the plan is applied by the modem (reply lost or apply-then-refuse)
    // or dropped before being applied.
    for (cmd, key) in [(LTE_266, "lte_band"), (MODE_LTE, "mode_pref"), (DIS_0, "nr5g_disable_mode"), (NSA_0, "nsa_nr5g_band"), (SA_0, "nr5g_band")] {
        for (fail, want_status, want_applied) in [
            (Fail::ApplyDrop, StatusCode::BAD_GATEWAY, true),
            (Fail::Drop, StatusCode::BAD_GATEWAY, false),
            (Fail::ApplyCme(50), StatusCode::UNPROCESSABLE_ENTITY, true),
        ] {
            m.reset(start.clone());
            m.fail_exact(cmd, fail.clone(), Some(1));
            let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only.clone()).await;
            let ctx = format!("{cmd} {fail:?} -> {s} {v}");
            assert_eq!(s, want_status, "{ctx}");
            assert_eq!(v["failed"], key, "{ctx}");
            assert_eq!(v["failedWriteApplied"], want_applied, "{ctx}");
            if want_applied {
                assert_eq!(v["partial"], true, "{ctx}");
            }
            if fail == Fail::ApplyCme(50) {
                assert!(
                    v["error"].as_str().unwrap_or_default().contains("was applied even though the modem returned an error"),
                    "{ctx}"
                );
            }
            assert_eq!(m.radio(), start, "rolled back to start: {ctx}");
            assert_honest_and_safe(&m, &start, s, &v, &ctx);
        }
    }
    // sim_slot and apn: Drop (not applied), ApplyDrop (applied, reply lost), ApplyCme(50) (apply-then-refuse)
    for (cmd, key, body) in [
        ("AT+QUIMSLOT=2", "sim_slot", json!({ "simSlot": 2 })),
        ("AT+CGDCONT=1,\"IPV4V6\",\"new.apn\"", "apn", json!({ "apn": "new.apn" })),
    ] {
        for (fail, want_status, want_applied) in [
            (Fail::ApplyDrop, StatusCode::BAD_GATEWAY, true),
            (Fail::Drop, StatusCode::BAD_GATEWAY, false),
            (Fail::ApplyCme(50), StatusCode::UNPROCESSABLE_ENTITY, true),
        ] {
            m.reset(start.clone());
            m.with(|s| {
                s.sim_slot = 1;
                s.cgdcont = ("IPV4V6".into(), "old.apn".into());
            });
            m.fail_exact(cmd, fail.clone(), Some(1));
            let (s, v) = post(&t, "/api/v1/cellular/mode", body.clone()).await;
            let ctx = format!("{key} {fail:?} -> {s} {v}");
            assert_eq!(s, want_status, "{ctx}");
            assert_eq!(v["failed"], key, "{ctx}");
            assert_eq!(v["failedWriteApplied"], want_applied, "{ctx}");
            assert_eq!(v["partial"], want_applied, "{ctx}");
            assert_eq!(m.with(|s| s.sim_slot), 1, "{ctx}");
            assert_eq!(m.with(|s| s.cgdcont.clone()), ("IPV4V6".into(), "old.apn".into()), "{ctx}");
            if want_applied {
                assert_eq!(v["rollback"]["restored"], json!([key]), "{ctx}");
                assert_eq!(v["rollback"]["ok"], true, "{ctx}");
            } else {
                assert_eq!(v["rollback"]["restored"], json!([]), "{ctx}");
                assert_eq!(m.writes(), vec![cmd.to_string()], "dropped non-applied write must not trigger blind undo: {ctx}");
            }
            if fail == Fail::ApplyCme(50) {
                assert!(
                    v["error"].as_str().unwrap_or_default().contains("was applied even though the modem returned an error"),
                    "{ctx}"
                );
            }
        }
    }
    // the undo's own reply is lost (but applied): the re-read sees it, no blind retry
    m.reset(start.clone());
    m.fail_exact(MODE_LTE, Fail::Cme(50), Some(1));
    m.fail_exact("AT+QNWPREFCFG=\"lte_band\",2:4:66", Fail::ApplyDrop, Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only.clone()).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(m.radio(), start);
    assert_eq!(m.writes().iter().filter(|w| *w == "AT+QNWPREFCFG=\"lte_band\",2:4:66").count(), 1, "{:?}", m.writes());
    assert_honest_and_safe(&m, &start, s, &v, &v.to_string());
    // network mode: the mode write lands but its reply is lost; the SIM is never switched
    let start2 = Radio::new("2", "41", "41", "AUTO", 1);
    m.reset(start2.clone());
    m.fail_exact(DIS_0, Fail::ApplyDrop, Some(1));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 0, "simSlot": 2 })).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    assert_eq!(v["failedWriteApplied"], true, "{v}");
    assert_eq!(m.radio(), start2, "{v}");
    assert_eq!(m.with(|s| s.sim_slot), 1);
    assert!(!m.writes().iter().any(|w| w.starts_with("AT+QUIMSLOT=")), "{:?}", m.writes());
    assert_honest_and_safe(&m, &start2, s, &v, &v.to_string());
}

#[tokio::test]
async fn failed_undo_replans_from_the_real_state() {
    // the verifiers' case: NR5G-only on n41 -> LTE-only. Clearing nr5g_band is
    // refused, and so is putting mode_pref back; a blind reverse undo would
    // then clear lte_band and leave LTE-only mode with no LTE band.
    let start = Radio::new("", "", "41", "NR5G", 0);
    let (t, m, _sbx) = setup_modem("undo", start.clone()).await;
    let to_lte = json!({ "lteBands": ["2"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE" });
    m.fail_exact(SA_0, Fail::Cme(50), Some(1));
    m.fail_exact("AT+QNWPREFCFG=\"mode_pref\",NR5G", Fail::Cme(50), None);
    let (s, v) = post(&t, "/api/v1/cellular/bands", to_lte.clone()).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["failed"], "nr5g_band", "{v}");
    assert_eq!(v["rollback"]["ok"], false, "{v}");
    assert!(v["rollback"]["failed"].as_array().unwrap().contains(&json!("mode_pref")), "{v}");
    assert!(!m.writes().contains(&"AT+QNWPREFCFG=\"lte_band\",0".to_string()), "LTE band cleared under LTE-only: {:?}", m.writes());
    assert_eq!(m.radio(), Radio::new("2", "", "41", "LTE", 0), "{v}");
    assert_honest_and_safe(&m, &start, s, &v, &v.to_string());

    // AUTO variant: the forward plan lands AUTO with SA disabled; the undo of
    // the mode is refused after nr5g_disable_mode was already put back
    m.reset(start.clone());
    let to_auto = json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": [], "modePref": "AUTO", "nr5gDisableMode": 1 });
    m.fail_exact(SA_0, Fail::Cme(50), Some(1));
    m.fail_exact("AT+QNWPREFCFG=\"mode_pref\",NR5G", Fail::Error, None);
    let (s, v) = post(&t, "/api/v1/cellular/bands", to_auto.clone()).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["rollback"]["ok"], false, "{v}");
    assert_honest_and_safe(&m, &start, s, &v, &v.to_string());

    // the mode undo is applied but its reply is lost: the re-read sees NR5G and
    // the repair finishes (lte_band cleared only once LTE is no longer in use)
    for req in [to_lte, to_auto] {
        m.reset(start.clone());
        m.fail_exact(SA_0, Fail::Cme(50), Some(1));
        m.fail_exact("AT+QNWPREFCFG=\"mode_pref\",NR5G", Fail::ApplyDrop, Some(1));
        let (s, v) = post(&t, "/api/v1/cellular/bands", req.clone()).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(m.radio(), start, "{req} -> {v}");
        assert_eq!(v["rollback"]["ok"], true, "{v}");
        assert_honest_and_safe(&m, &start, s, &v, &v.to_string());
    }

    // the line stays dead after the failure: nothing can be verified, and the
    // response says so instead of claiming a rollback
    m.reset(Radio::new("2:4:66", "41", "41:71", "AUTO", 0));
    m.fail_exact(MODE_LTE, Fail::Cme(50), Some(1));
    m.fail_exact("AT+QNWPREFCFG=\"mode_pref\"", Fail::Delay(0), Some(1)); // the pre-read still answers
    m.fail_exact("AT+QNWPREFCFG=\"mode_pref\"", Fail::Drop, None);
    let lte_only = json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 });
    let (s, v) = post(&t, "/api/v1/cellular/bands", lte_only).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["rollback"]["safe"], false, "{v}");
    assert_eq!(v["rollback"]["ok"], false, "{v}");
    assert_eq!(v["rollback"]["finalState"], Value::Null, "{v}");
}

/// Every single-write fault on the forward plan (refused / dropped / applied
/// with the reply lost), alone and combined with every fault on the repair
/// writes that follow it: the radio always ends usable and the response
/// reports the real final state.
#[tokio::test]
async fn fault_sweep_every_write_and_undo_fault_ends_safe() {
    let cases: Vec<(Radio, Value)> = vec![
        (Radio::new("2:4:66", "41", "41:71", "AUTO", 0), json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 })),
        (Radio::new("", "", "41", "NR5G", 0), json!({ "lteBands": ["2"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE" })),
        (Radio::new("", "", "41", "NR5G", 0), json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": [], "modePref": "AUTO", "nr5gDisableMode": 1 })),
        (Radio::new("2", "", "", "LTE", 0), json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": [], "modePref": "AUTO", "nr5gDisableMode": 1 })),
        (Radio::new("2", "", "", "LTE", 0), json!({ "lteBands": [], "nsaNr5gBands": [], "nr5gBands": ["41"], "modePref": "NR5G", "nr5gDisableMode": 0 })),
        (Radio::new("12", "71", "", "LTE:NR5G", 1), json!({ "lteBands": ["12"], "nsaNr5gBands": [], "nr5gBands": ["71"], "modePref": "AUTO", "nr5gDisableMode": 2 })),
        (Radio::new("12", "", "71", "AUTO", 2), json!({ "lteBands": ["2", "66"], "nsaNr5gBands": ["41"], "nr5gBands": ["41", "71"], "modePref": "AUTO", "nr5gDisableMode": 0 })),
    ];
    let (t, m, _sbx) = setup_modem("sweep", cases[0].0.clone()).await;
    let faults = [Fail::Cme(50), Fail::ApplyCme(50), Fail::Drop, Fail::ApplyDrop];
    let (mut single, mut double) = (0, 0);
    for (start, body) in &cases {
        m.reset(start.clone());
        let (s, v) = post(&t, "/api/v1/cellular/bands", body.clone()).await;
        assert_eq!(s, StatusCode::OK, "{start:?} {body}: {v}");
        let plan = m.writes();
        assert!(plan.len() >= 3, "{plan:?}");
        for fw in &plan {
            for f in &faults {
                m.reset(start.clone());
                m.fail_exact(fw, f.clone(), Some(1));
                let (s, v) = post(&t, "/api/v1/cellular/bands", body.clone()).await;
                let ctx = format!("{start:?} {body} fault {f:?} on {fw} -> {s} {v} writes {:?}", m.writes());
                assert_honest_and_safe(&m, start, s, &v, &ctx);
                assert_eq!(m.radio(), *start, "a single fault is fully rolled back: {ctx}");
                single += 1;
                // the repair writes this fault caused, each faulted in turn
                let writes = m.writes();
                let at = writes.iter().position(|w| w == fw).unwrap();
                let mut repair: Vec<String> = writes[at + 1..].to_vec();
                repair.dedup();
                for rw in repair {
                    for (g, times) in [
                        (Fail::Cme(50), None),
                        (Fail::ApplyCme(50), Some(1)),
                        (Fail::Drop, Some(1)),
                        (Fail::ApplyDrop, Some(1)),
                    ] {
                        m.reset(start.clone());
                        m.fail_exact(fw, f.clone(), Some(1));
                        m.fail_exact(&rw, g.clone(), times);
                        let (s, v) = post(&t, "/api/v1/cellular/bands", body.clone()).await;
                        let ctx = format!("{start:?} {body} fault {f:?} on {fw}, then {g:?} on {rw} -> {s} {v} writes {:?}", m.writes());
                        assert_honest_and_safe(&m, start, s, &v, &ctx);
                        double += 1;
                    }
                }
            }
        }
    }
    assert!(single >= 80 && double >= 150, "{single} single, {double} double faults");
}

/// Commands of the log between the first and the last of `ours` (inclusive)
/// that are not in `ours`: what slipped into the middle of a change.
fn interleaved(log: &[String], ours: &[&str]) -> Vec<String> {
    let first = log.iter().position(|c| ours.contains(&c.as_str()));
    let last = log.iter().rposition(|c| ours.contains(&c.as_str()));
    match (first, last) {
        (Some(a), Some(b)) => log[a..=b].iter().filter(|c| !ours.contains(&c.as_str())).cloned().collect(),
        _ => Vec::new(),
    }
}

#[tokio::test]
async fn radio_changes_are_serialized() {
    let start = Radio::new("2:4:66", "41", "41:71", "AUTO", 0);
    let (t, m, _sbx) = setup_modem("serial", start.clone()).await;
    let lte_only = json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 });
    let a_writes = [LTE_266, MODE_LTE, NSA_0, SA_0];
    // A: AUTO -> LTE-only (slow writes). B: network mode back to AUTO, valid
    // against what it reads. Interleaved, B's AUTO lands between A's mode write
    // and A's NR clears: AUTO with no NR band.
    for delay_ms in [0u64, 40, 100, 180, 260, 400] {
        m.reset(start.clone());
        m.fail("\",", Fail::Delay(60), None);
        let a = post(&t, "/api/v1/cellular/bands", lte_only.clone());
        let b = async {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            post(&t, "/api/v1/cellular/mode", json!({ "modePref": "AUTO" })).await
        };
        let ((sa, va), (sb, vb)) = tokio::join!(a, b);
        let ctx = format!("B after {delay_ms} ms: A {sa} {va} / B {sb} {vb} / log {:?}", m.log());
        assert_eq!(sa, StatusCode::OK, "{ctx}");
        let fin = m.radio();
        assert!(strict_ok(&fin), "final {fin:?}: {ctx}");
        for snap in m.snapshots() {
            assert!(strict_ok(&snap), "intermediate {snap:?}: {ctx}");
        }
        // B planned from fresh state: before A (AUTO, a no-op, then A wins) or
        // after A (LTE-only with no NR band: AUTO is refused)
        if sb == StatusCode::OK {
            assert_eq!(fin, Radio::new("2:66", "", "", "LTE", 0), "{ctx}");
        } else {
            assert_eq!(sb, StatusCode::CONFLICT, "{ctx}");
        }
        assert_eq!(interleaved(&m.log(), &a_writes), Vec::<String>::new(), "{ctx}");
    }

    // the raw AT console (HTTP and IPC) and the cell lock wait for a radio change in progress
    for (i, who) in ["console", "ipc", "cell-lock"].into_iter().enumerate() {
        m.reset(start.clone());
        m.fail("\",", Fail::Delay(60), None);
        let a = post(&t, "/api/v1/cellular/bands", lte_only.clone());
        let b = async {
            tokio::time::sleep(Duration::from_millis(90)).await;
            match i {
                0 => {
                    let (s, v) = post(&t, "/api/v1/modem/at", json!({ "command": "AT+QNWPREFCFG=\"nr5g_band\",41", "confirm": true })).await;
                    assert_eq!(s, StatusCode::OK, "{v}");
                }
                1 => {
                    let r = crate::ipc::dispatch_ipc(
                        t.app.clone(),
                        crate::ipc::IpcRequest::QuectelAt { command: "AT+QNWPREFCFG=\"nr5g_band\",41".into(), timeout_secs: Some(5) },
                        true,
                    )
                    .await;
                    assert!(r.ok, "{:?}", r.error);
                }
                _ => {
                    let (s, v) = post(&t, "/api/v1/cellular/cell-lock", json!({ "rat": "lte", "pci": 371, "arfcn": 66786 })).await;
                    assert_eq!(s, StatusCode::OK, "{v}");
                }
            }
        };
        let ((sa, va), ()) = tokio::join!(a, b);
        assert_eq!(sa, StatusCode::OK, "{who}: {va}");
        assert_eq!(interleaved(&m.log(), &a_writes), Vec::<String>::new(), "{who} slipped into a band change: {:?}", m.log());
    }
}

#[tokio::test]
async fn network_mode_reads_any_lte_nr5g_combination() {
    let (t, m, _sbx) = setup_modem("modes", Radio::new("2:66", "41", "41:71", "NR5G:LTE", 0)).await;
    // NR5G:LTE is LTE + NR (like AUTO): disabling SA keeps LTE and NSA
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(m.radio(), Radio::new("2:66", "41", "41:71", "NR5G:LTE", 1));
    // ...and is checked as LTE + NR, not as unreadable: SA without a band is a 409
    m.reset(Radio::new("2", "41", "", "NR5G:LTE", 1));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 0 })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["error"].as_str().unwrap().contains("NR5G-SA"), "{v}");
    for weird in ["LTE:NR5G", "lte:nr5g", "NR5G:LTE", "WCDMA:LTE:NR5G", "LTE:NR5G:WCDMA"] {
        m.reset(Radio::new("2", "41", "41", weird, 0));
        let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 2 })).await;
        assert_eq!(s, StatusCode::OK, "{weird}: {v}");
        assert_eq!(m.radio().disable, 2, "{weird}");
    }
    // an LTE-only combination the modem reports (WCDMA has no band lock here)
    m.reset(Radio::new("2", "", "", "WCDMA:LTE", 0));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // truly unreadable: a partial change cannot be checked (502, nothing written)...
    m.reset(Radio::new("2:66", "41", "41:71", "GSM?", 0));
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "nr5gDisableMode": 1 })).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    assert_eq!(m.writes(), Vec::<String>::new());
    // ...but a request that names the mode proceeds on the strict assumption
    let (s, v) = post(&t, "/api/v1/cellular/mode", json!({ "modePref": "LTE", "nr5gDisableMode": 0 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(m.radio(), Radio::new("2:66", "41", "41:71", "LTE", 0));
    m.reset(Radio::new("2:66", "41", "41:71", "GSM?", 0));
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": ["41"], "nr5gBands": ["41"], "modePref": "AUTO", "nr5gDisableMode": 0 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(m.radio(), Radio::new("2", "41", "41", "AUTO", 0));
}

const LEGACY_PROFILE: &str = "cellprofiles.@profile[0]=profile\n\
cellprofiles.@profile[0].name='Legacy'\n\
cellprofiles.@profile[0].iccid='89012600000000000017'\n\
cellprofiles.@profile[0].apn='fast.t-mobile.com'\n\
cellprofiles.@profile[0].ttl='064'\n\
cellprofiles.@profile[0].lte_bands='2:0:66'\n\
cellprofiles.@profile[0].sa_nr5g_bands='0'\n\
cellprofiles.@profile[0].nsa_nr5g_bands='0,41'\n\
cellprofiles.@profile[0].network_type='WCDMA:LTE'\n";

#[tokio::test]
async fn legacy_profile_values_are_normalised_on_read() {
    let (t, sbx) = setup_sandboxed("prof-legacy", None).await;
    sbx.show(LEGACY_PROFILE);
    let (s, v) = send(&t, Method::GET, "/api/v1/cellular/profiles", Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = &v["profiles"][0];
    assert_eq!(p["ttl"], "64", "{v}");
    assert_eq!(p["lte_bands"], "2:66", "{v}");
    assert_eq!(p["sa_nr5g_bands"], "", "{v}");
    assert_eq!(p["nsa_nr5g_bands"], "41", "{v}");
    assert_eq!(p["network_type"], "WCDMA:LTE", "legacy network types are kept: {v}");
    let warnings = v["warnings"].as_array().cloned().unwrap_or_default();
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("064")), "{v}");
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("band 0")), "{v}");
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("','")), "comma-separated 0,41 warning: {v}");

    // Verify GET warnings for both "2,66" (comma only) and "0,2,66" (band 0 + comma)
    sbx.show(
        "cellprofiles.@profile[0]=profile\n\
         cellprofiles.@profile[0].name='CommaOnly'\n\
         cellprofiles.@profile[0].iccid='89012600000000000017'\n\
         cellprofiles.@profile[0].apn='a'\n\
         cellprofiles.@profile[0].lte_bands='2,66'\n\
         cellprofiles.@profile[0].nsa_nr5g_bands='0,2,66'\n",
    );
    let (s, v2) = send(&t, Method::GET, "/api/v1/cellular/profiles", Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v2}");
    assert_eq!(v2["profiles"][0]["lte_bands"], "2:66", "{v2}");
    assert_eq!(v2["profiles"][0]["nsa_nr5g_bands"], "2:66", "{v2}");
    let w2 = v2["warnings"].as_array().cloned().unwrap_or_default();
    assert!(w2.iter().any(|w| w.as_str().unwrap().contains("\"2,66\"")), "{v2}");
    assert!(w2.iter().any(|w| w.as_str().unwrap().contains("\"0,2,66\"") && w.as_str().unwrap().contains("band 0")), "{v2}");

    // Restore legacy profile for editing test below
    sbx.show(LEGACY_PROFILE);
    // editing it as read back works (the legacy network type unchanged included)
    let mut edit = json!({ "index": 0, "name": "Legacy", "iccid": ICCID, "apn": "fast.t-mobile.com" });
    for (k, f) in [("ttl", "ttl"), ("lteBands", "lte_bands"), ("saNr5gBands", "sa_nr5g_bands"), ("nsaNr5gBands", "nsa_nr5g_bands"), ("networkType", "network_type")] {
        edit[k] = p[f].clone();
    }
    let (s, r) = post(&t, "/api/v1/cellular/profiles", edit.clone()).await;
    assert_eq!(s, StatusCode::OK, "{edit}: {r}");
    let log = sbx.uci_log();
    for want in ["set cellprofiles.@profile[0].ttl=64", "set cellprofiles.@profile[0].lte_bands=2:66", "set cellprofiles.@profile[0].network_type=WCDMA:LTE"] {
        assert!(log.iter().any(|l| l == want), "{want}: {log:?}");
    }
    // the same legacy values as NEW input are still refused
    for (k, bad) in [("ttl", "064"), ("lteBands", "2:0:66"), ("lteBands", "0,2,66"), ("saNr5gBands", "0")] {
        let mut b = json!({ "name": "New", "iccid": ICCID, "apn": "a" });
        b[k] = json!(bad);
        let (s, r) = post(&t, "/api/v1/cellular/profiles", b).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{k}={bad}: {r}");
    }
    // a backup holding legacy values restores, normalised
    let mut bundle = serde_json::to_value(crate::appbackup::tests::sample()).unwrap();
    bundle["profiles"][0]["name"] = json!("Legacy");
    bundle["profiles"][0]["ttl"] = json!("064");
    bundle["profiles"][0]["lteBands"] = json!("0");
    bundle["profiles"][0]["saNr5gBands"] = json!("0,41");
    bundle["profiles"][0]["networkType"] = json!("WCDMA:LTE");
    let (s, r) = post(&t, "/api/v1/system/config-backup/apply", json!({ "bundle": bundle, "items": ["profiles"], "confirm": "RESTORE" })).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let msg = r["results"][0]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("064"), "the normalisation is reported: {r}");
    assert!(msg.contains("','"), "comma conversion is reported: {r}");
    let log = sbx.uci_log();
    for want in ["set cellprofiles.@profile[0].ttl=64", "set cellprofiles.@profile[0].lte_bands=", "set cellprofiles.@profile[0].sa_nr5g_bands=41"] {
        assert!(log.iter().rev().any(|l| l == want), "{want}: {log:?}");
    }
}

#[tokio::test]
async fn new_network_types_are_canonical() {
    let (t, sbx) = setup_sandboxed("prof-net", None).await;
    sbx.show(PROFILE0);
    for (net, stored) in [("AUTO", "AUTO"), ("lte", "LTE"), ("Nr5g", "NR5G"), ("lte:nr5g", "LTE:NR5G"), ("NR5G:LTE", "NR5G:LTE"), ("", "")] {
        let (s, v) = post(&t, "/api/v1/cellular/profiles", json!({ "name": "x", "iccid": ICCID, "apn": "a", "networkType": net })).await;
        assert_eq!(s, StatusCode::OK, "{net:?}: {v}");
        let last = sbx.uci_log().into_iter().rev().find(|l| l.starts_with("set cellprofiles.cfg0a1b2c.network_type="));
        assert_eq!(last, Some(format!("set cellprofiles.cfg0a1b2c.network_type={stored}")), "{net:?}");
    }
    for net in ["WCDMA:LTE", "GSM", "LTE:LTE", "LTE:", ":NR5G", "AUTO:LTE", "5G", "LTE1"] {
        let (s, v) = post(&t, "/api/v1/cellular/profiles", json!({ "name": "x", "iccid": ICCID, "apn": "a", "networkType": net })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{net:?}: {v}");
    }
    // editing a profile to a legacy value it does not already hold is new input
    let (s, v) = post(&t, "/api/v1/cellular/profiles", json!({ "index": 0, "name": "TMO", "iccid": ICCID, "apn": "fast.t-mobile.com", "networkType": "WCDMA:LTE" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn pure_noop_radio_and_mode_requests_emit_zero_writes() {
    let start = Radio::new("2:66", "41", "41:71", "AUTO", 0);
    let (t, m, _sbx) = setup_modem("noop", start.clone()).await;

    // Identical band lock (even with reordered band list): 0 writes
    let (s, v) = post(
        &t,
        "/api/v1/cellular/bands",
        json!({ "lteBands": ["66", "2"], "nsaNr5gBands": ["41"], "nr5gBands": ["71", "41"], "modePref": "AUTO", "nr5gDisableMode": 0 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], json!([]), "{v}");
    assert_eq!(m.writes(), Vec::<String>::new());

    // Identical mode, disable, sim_slot, and case-insensitive (pdp, apn): 0 writes
    let (s, v) = post(
        &t,
        "/api/v1/cellular/mode",
        json!({ "modePref": "AUTO", "nr5gDisableMode": 0, "simSlot": 1, "apn": "OLD.APN", "pdpType": "ipv4v6" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], json!([]), "{v}");
    assert_eq!(m.writes(), Vec::<String>::new());

    // Unknown modem mode_pref ("GSM?"): setting modePref="AUTO" is NOT a no-op and repairs it
    for endpoint in [
        ("/api/v1/cellular/bands", json!({ "lteBands": ["2", "66"], "nsaNr5gBands": ["41"], "nr5gBands": ["41", "71"], "modePref": "AUTO", "nr5gDisableMode": 0 })),
        ("/api/v1/cellular/mode", json!({ "modePref": "AUTO" })),
    ] {
        m.reset(Radio::new("2:66", "41", "41:71", "GSM?", 0));
        let (s, v) = post(&t, endpoint.0, endpoint.1).await;
        assert_eq!(s, StatusCode::OK, "{} -> {v}", endpoint.0);
        assert_eq!(v["applied"], json!(["mode_pref"]), "{v}");
        assert_eq!(m.writes(), w(&["AT+QNWPREFCFG=\"mode_pref\",AUTO"]));
        assert_eq!(m.radio().mode, "AUTO");
    }
}

#[tokio::test]
async fn r10_cfun_recovery_respects_bounded_radio_lock() {
    let start = Radio::new("2:4:66", "41", "41:71", "AUTO", 0);
    let (t, m, _sbx) = setup_modem("r10-lock", start.clone()).await;

    // 1. R10Status is completely lock-free and keeps its 19-key output while radio_lock is held
    let guard = crate::radio::lock(&t.app).await;
    let t0 = std::time::Instant::now();
    let st = crate::ipc::dispatch_ipc(t.app.clone(), crate::ipc::IpcRequest::R10Status, true).await;
    assert!(st.ok, "{:?}", st.error);
    assert!(t0.elapsed() < Duration::from_secs(2), "R10Status blocked on radio_lock");
    assert_eq!(st.output.lines().count(), 19, "{}", st.output);
    for key in [
        "wan_up=", "wan_uptime=", "l3_device=", "modem_uptime_s=", "at_token_ok=", "cfun=",
        "rsrp_dbm=", "rat=", "band=", "mode=", "lte_band=", "lte_rsrp_dbm=", "lte_rsrq_db=",
        "nr_band=", "nr_rsrp_dbm=", "nr_sinr_db=", "nr_rsrq_db=",
        "wan_v4_usable=", "wan_v6_usable=",
    ] {
        assert!(st.output.contains(key), "missing {key}: {}", st.output);
    }

    // 2. QuectelAt radio write times out cleanly if radio_lock stays held past timeout_secs
    let busy = crate::ipc::dispatch_ipc(
        t.app.clone(),
        crate::ipc::IpcRequest::QuectelAt { command: "AT+CFUN=0".into(), timeout_secs: Some(1) },
        true,
    )
    .await;
    assert!(!busy.ok);
    assert_eq!(busy.error.as_deref(), Some("AT command timed out (AT+CFUN=0): radio busy"));
    drop(guard);

    // 3. Route10 wan-restart serializes behind an in-flight radio write and forgets cached mode
    m.reset(Radio::new("2", "", "", "LTE", 0));
    let (s, _) = send(&t, Method::GET, "/api/v1/cellular/mode", Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    m.reset(start.clone());
    m.fail("\",", Fail::Delay(60), None);
    let lte_only = json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 });
    let a = post(&t, "/api/v1/cellular/bands", lte_only);
    let b = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        crate::ipc::dispatch_ipc(t.app.clone(), crate::ipc::IpcRequest::R10WanRestart, true).await
    };
    let ((sa, va), rb) = tokio::join!(a, b);
    assert_eq!(sa, StatusCode::OK, "{va}");
    assert!(rb.ok, "{:?}", rb.error);
    let a_writes = [LTE_266, MODE_LTE, NSA_0, SA_0];
    assert_eq!(interleaved(&m.log(), &a_writes), Vec::<String>::new(), "wan-restart interleaved: {:?}", m.log());
    assert!(m.log().iter().any(|c| c == "AT+CFUN=1"), "wan-restart ran CFUN=1: {:?}", m.log());
    // cached mode was forgotten by wan-restart -> fallback assumes AUTO when mode_pref read fails
    m.fail("AT+QNWPREFCFG=\"mode_pref\"", Fail::Error, None);
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": [], "nr5gBands": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "cached LTE mode should have been forgotten: {v}");

    // 4. Route10 modem-reset still proceeds if radio_lock stays held past the 5s bound
    m.reset(start);
    let held = crate::radio::lock(&t.app).await;
    let res = crate::ipc::dispatch_ipc(t.app.clone(), crate::ipc::IpcRequest::R10ModemReset, true).await;
    assert!(res.ok && !res.output.contains("in_progress"), "{res:?}");
    let log = m.log();
    assert!(log.iter().any(|c| c == "AT+CFUN=0") && log.iter().any(|c| c == "AT+CFUN=1"), "{log:?}");
    drop(held);
}

#[tokio::test]
async fn quecwatch_cfun_recovery_respects_bounded_radio_lock() {
    let start = Radio::new("2:4:66", "41", "41:71", "AUTO", 0);
    let (t, m, _sbx) = setup_modem("qw-lock", start.clone()).await;

    // 1. LinkWatch CFUN recovery serializes cleanly behind an in-flight radio write
    m.fail("\",", Fail::Delay(60), None);
    let lte_only = json!({ "lteBands": ["2", "66"], "nsaNr5gBands": [], "nr5gBands": [], "modePref": "LTE", "nr5gDisableMode": 0 });
    let mut cfg = t.app.settings.read().await.clone();
    cfg.quecwatch_connection_refresh = true;
    cfg.quecwatch_auto_sim_failover = false;

    let a = post(&t, "/api/v1/cellular/bands", lte_only);
    let b = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        crate::telemetry::trigger_quecwatch_recovery(&t.app, &cfg, 1).await
    };
    let ((sa, va), ran) = tokio::join!(a, b);
    assert_eq!(sa, StatusCode::OK, "{va}");
    assert!(ran);
    let a_writes = [LTE_266, MODE_LTE, NSA_0, SA_0];
    assert_eq!(interleaved(&m.log(), &a_writes), Vec::<String>::new(), "LinkWatch interleaved: {:?}", m.log());
    assert!(m.log().iter().any(|c| c == "AT+CFUN=0") && m.log().iter().any(|c| c == "AT+CFUN=1"), "{:?}", m.log());
    // cached mode was forgotten by LinkWatch recovery
    m.fail("AT+QNWPREFCFG=\"mode_pref\"", Fail::Error, None);
    let (s, v) = post(&t, "/api/v1/cellular/bands", json!({ "lteBands": ["2"], "nsaNr5gBands": [], "nr5gBands": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "cached LTE mode should have been forgotten: {v}");

    // 2. LinkWatch SIM failover recovery proceeds if radio_lock stays held past the 8s bound
    m.reset(start);
    cfg.quecwatch_connection_refresh = false;
    cfg.quecwatch_auto_sim_failover = true;
    let held = crate::radio::lock(&t.app).await;
    let t0 = std::time::Instant::now();
    assert!(crate::telemetry::trigger_quecwatch_recovery(&t.app, &cfg, 1).await);
    assert!(t0.elapsed() >= Duration::from_secs(8));
    assert_eq!(m.with(|s| s.sim_slot), 2, "SIM failover still ran after bounded lock wait");
    drop(held);
}

#[tokio::test]
async fn speedtest_start_rejects_malformed_unknown_and_wrong_content_type_without_spawning() {
    use std::os::unix::fs::PermissionsExt;

    let (t, sbx) = setup_sandboxed("speedtest-start-val", None).await;
    let marker = sbx.dir.join("spawned.marker");
    let bin_dir = sbx.root().join("usr/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(sbx.root().join("tmp/cellcore")).unwrap();
    std::fs::create_dir_all(sbx.root().join("etc/cellcore")).unwrap();
    let script = bin_dir.join("speedtest");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf '%s\\n' '{{\"type\":\"result\",\"ping\":{{\"latency\":10.0,\"jitter\":0.5}},\"download\":{{\"bandwidth\":12500000,\"latency\":{{\"iqm\":15.0}}}},\"upload\":{{\"bandwidth\":12500000,\"latency\":{{\"iqm\":15.0}}}},\"server\":{{\"id\":1,\"name\":\"S\",\"location\":\"C\"}}}}'\n",
            marker.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let send_raw = |ct: Option<&str>, raw: Vec<u8>| {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/speedtest/start")
            .header(header::HOST, "192.168.224.1")
            .header(header::COOKIE, &t.cookie)
            .header("x-qm-csrf", &t.csrf);
        if let Some(ct) = ct {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        let mut req = b.body(Body::from(raw)).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 224, 50], 40000))));
        let router = t.router.clone();
        let env = t.env.as_ref().unwrap().clone();
        async move {
            TEST_ENV
                .scope(env, tower::ServiceExt::oneshot(router, req))
                .await
                .unwrap()
                .status()
        }
    };

    assert_eq!(send_raw(Some("application/json"), b"{".to_vec()).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        send_raw(Some("application/json"), br#"{"command":5}"#.to_vec()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send_raw(Some("text/plain"), b"{}".to_vec()).await, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        send_raw(Some("application/json"), br#"{"serverId":-5}"#.to_vec()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send_raw(Some("application/json"), br#"{"engine":"ookla"}"#.to_vec()).await,
        StatusCode::BAD_REQUEST
    );
    assert!(!marker.exists(), "invalid POST /api/v1/speedtest/start must never spawn speedtest");
    assert!(t.app.speedtest_pid.lock().await.is_none());

    // Empty body without Content-Type starts the pure-Rust native speedtest (200)
    // and must NEVER execute an external /usr/bin/speedtest binary.
    assert_eq!(send_raw(None, Vec::new()).await, StatusCode::OK);
    assert_eq!(t.app.speedtest_live.read().await.engine.as_deref(), Some("native"));
    let _ = crate::speedtest::stop_speedtest(&t.app).await;
    assert!(!marker.exists(), "native speedtest must never exec /usr/bin/speedtest");
    assert!(t.app.speedtest_pid.lock().await.is_none());
}
