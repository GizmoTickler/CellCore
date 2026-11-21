//! Route-level tests through the real router with mocked `uci`, `ip`, `wg`,
//! `wgcf`, `curl`, `tailscale`, `opkg`, `ubus`, `fw4`, `ifup`/`ifdown` and the
//! tailscale init script. The mocks are small stateful shell scripts: `uci`
//! keeps a `uci show`-format database, `ip` keeps the rule list and the WARP
//! table so routing decisions can be asserted as state, not just as calls.
//! Nothing here talks to Cloudflare or Tailscale.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

use super::{Paths, policy, set_paths};
use crate::{
    admin::exec::BIN_OVERRIDE,
    auth::{AuthStore, now_secs},
    http::{HttpCtx, build_router},
    state::AppState,
    tokens::TokenKind,
};

static LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

const FX_WG_DUMP: &str = include_str!("fixtures/wg_dump.txt");
const FX_PROFILE: &str = include_str!("fixtures/wgcf_profile.conf");
const FX_STATUS: &str = include_str!("fixtures/wgcf_status.txt");
const FX_TS: &str = include_str!("fixtures/ts_status.json");
const FX_TS_LOGIN: &str = include_str!("fixtures/ts_status_needslogin.json");
const FX_TS_HELP: &str = include_str!("fixtures/ts_set_help.txt");
const FX_REG: &str = include_str!("fixtures/teams_reg.json");
const FX_PAGE: &str = include_str!("fixtures/warp_page.html");

const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const LICENSE: &str = "a1B2c3D4-e5F6g7H8-i9J0k1L2";
const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJ0ZWFtIjoiYWNtZSJ9.c2lnbmF0dXJlLXRlYW0tdG9rZW4";
const AUTHKEY: &str = "tskey-auth-kTEST1CNTRL-AbCdEfGhIjKlMnOpQrStUvWx";
const CLIENT_ID: &str = "0123456789abcdef0123456789abcdef.access";

const MOCKS: &[(&str, &str)] = &[
    (
        "uci",
        r#"#!/bin/sh
M=__D__; S=$M/st/uci.db; touch "$S"
echo "uci $*" >> $M/calls.log
while [ $# -gt 0 ]; do case "$1" in -q|-X) shift;; *) break;; esac; done
cmd=$1; shift
case "$cmd" in
  show|export) grep "^$1\." "$S"; exit 0;;
  changes|commit|revert) exit 0;;
  import) cat > /dev/null; exit 0;;
  get) line=$(grep "^$1=" "$S" | head -n 1); [ -z "$line" ] && exit 1; v=${line#*=}; v=${v#\'}; v=${v%\'}; echo "$v"; exit 0;;
  set) k=${1%%=*}; v=${1#*=}
       case "$k" in
         *.*.*) grep -v "^$k=" "$S" > "$S.t"; mv "$S.t" "$S"; echo "$k='$v'" >> "$S";;
         *) grep -q "^$k=" "$S" || echo "$k=$v" >> "$S";;
       esac;;
  add_list) k=${1%%=*}; v=${1#*=}; old=$(grep "^$k=" "$S" | head -n 1); grep -v "^$k=" "$S" > "$S.t"; mv "$S.t" "$S"
       if [ -n "$old" ]; then echo "$old '$v'" >> "$S"; else echo "$k='$v'" >> "$S"; fi;;
  delete) k=$1; grep -v "^$k=" "$S" | grep -v "^$k\." > "$S.t"; mv "$S.t" "$S";;
  add) n=$(wc -l < "$S"); id=$(printf 'cfg%06x' "$n"); echo "$1.$id=$2" >> "$S"; echo "$id";;
esac
exit 0
"#,
    ),
    (
        "ip",
        r#"#!/bin/sh
M=__D__; R=$M/st/rules; touch "$R"
echo "ip $*" >> $M/calls.log
[ "$1" = "-4" ] && shift
case "$1 $2" in
  "rule show") sort -n "$R"; exit 0;;
  "rule add") shift 2; [ "$1" = pref ] || exit 2; p=$2; shift 2; printf '%s:\tfrom all %s\n' "$p" "$*" >> "$R"; exit 0;;
  "rule del") awk -v p="$4:" 'BEGIN{d=0} { if (!d && $1 == p) { d=1; next } print }' "$R" > "$R.t"; mv "$R.t" "$R"; exit 0;;
  "route show") [ -s "$M/st/route_$4" ] && cat "$M/st/route_$4"; exit 0;;
  "route replace") [ -e "$M/sysnet/$5" ] || { echo "Cannot find device $5" >&2; exit 1; }; echo "default dev $5 scope link" > "$M/st/route_$7"; exit 0;;
  "route flush") : > "$M/st/route_$4"; exit 0;;
  "-o addr") echo "5: br-lan    inet 192.168.224.1/22 brd 192.168.227.255 scope global br-lan"; exit 0;;
esac
exit 0
"#,
    ),
    (
        "wg",
        r#"#!/bin/sh
M=__D__
echo "wg $*" >> $M/calls.log
case "$1" in
  genkey) echo "__PRIV__"; exit 0;;
  pubkey) cat > $M/st/pubkey_stdin; echo "zR1v3mF9KQZtqk0kQ0hKxw3Q3d6Q2wqk1zZ3m4p5r6A="; exit 0;;
esac
[ -e "$M/sysnet/$2" ] || { echo "Unable to access interface: No such device" >&2; exit 1; }
case "$3" in
  dump) cat $M/fx/wg_dump.txt;;
  latest-handshakes) if [ -s $M/st/hs ]; then cat $M/st/hs; else printf 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\t0\n'; fi;;
esac
exit 0
"#,
    ),
    (
        "wgcf",
        r#"#!/bin/sh
M=__D__
echo "wgcf $* env_license=${WGCF_LICENSE_KEY:+present}" >> $M/calls.log
cfg=""; prof=""; prev=""
for a in "$@"; do case "$prev" in --config) cfg=$a;; --profile) prof=$a;; esac; prev=$a; done
case "$1" in
  register) printf "access_token = 'tok-123-secret'\ndevice_id = 'dev-abc'\nlicense_key = 'FREEKEY0-FREEKEY0-FREEKEY0'\nprivate_key = '__PRIV__'\n" > "$cfg"; chmod 644 "$cfg";;
  update) if [ -n "$WGCF_LICENSE_KEY" ]; then sed -i "s/^license_key = .*/license_key = '$WGCF_LICENSE_KEY'/" "$cfg"; printf '%s' "$WGCF_LICENSE_KEY" > $M/st/wgcf_env_seen; fi;;
  generate) cp $M/fx/wgcf_profile.conf "$prof"; chmod 644 "$prof";;
  status) cat $M/fx/wgcf_status.txt;;
esac
exit 0
"#,
    ),
    (
        "curl",
        r#"#!/bin/sh
M=__D__
echo "curl $*" >> $M/calls.log
cat > $M/st/curl_in; cat $M/st/curl_in >> $M/st/curl_all
if grep -q 'cloudflareaccess.com/warp' $M/st/curl_in; then cat $M/fx/warp_page.html
elif grep -q 'request = "DELETE"' $M/st/curl_in; then echo '{"success":true}'
elif grep -q '/reg"' $M/st/curl_in; then cat $M/fx/teams_reg.json
fi
exit 0
"#,
    ),
    ("ubus", "#!/bin/sh\nM=__D__\necho \"ubus $*\" >> $M/calls.log\ncase \"$2\" in network.interface.*) if [ -e $M/sysnet/warp ]; then echo '{\"up\":true,\"uptime\":42}'; else echo '{\"up\":false}'; fi;; esac\nexit 0\n"),
    ("fw4", "#!/bin/sh\necho \"fw4 $*\" >> __D__/calls.log\nexit 0\n"),
    ("ifup", "#!/bin/sh\necho \"ifup $*\" >> __D__/calls.log\nmkdir -p __D__/sysnet/$1\nexit 0\n"),
    // netifd deletes the device; the kernel drops every route through it.
    ("ifdown", "#!/bin/sh\necho \"ifdown $*\" >> __D__/calls.log\nrm -rf __D__/sysnet/$1\nfor f in __D__/st/route_*; do [ -e \"$f\" ] && : > \"$f\"; done\nrm -f __D__/st/hs\nexit 0\n"),
    (
        "tailscale",
        r#"#!/bin/sh
M=__D__
echo "tailscale $*" >> $M/calls.log
case "$1" in
  status) cat $M/st/ts_status.json;;
  set) if [ "$2" = "--help" ]; then cat $M/st/ts_help >&2; exit 0; fi; grep -q fail $M/st/ts_set_fail 2>/dev/null && { echo "invalid value" >&2; exit 1; }; exit 0;;
  up) key=""; for a in "$@"; do case "$a" in --auth-key=file:*) f=${a#--auth-key=file:}; cat "$f" > $M/st/ts_key_seen; stat -c %a "$f" > $M/st/ts_key_mode; key=1;; esac; done
      if [ -n "$key" ]; then cp $M/fx/ts_status.json $M/st/ts_status.json; else cp $M/fx/ts_status_needslogin.json $M/st/ts_status.json; fi
      echo "binary built with ts_omit_ipnbus; not waiting for completion" >&2;;
  logout) cp $M/fx/ts_status_needslogin.json $M/st/ts_status.json;;
esac
exit 0
"#,
    ),
    (
        "etc__init.d__tailscale",
        "#!/bin/sh\nM=__D__\necho \"init.d/tailscale $*\" >> $M/calls.log\ncase \"$1\" in\n status) cat $M/st/ts_running 2>/dev/null || echo inactive;;\n start|restart) echo running > $M/st/ts_running;;\n stop) echo inactive > $M/st/ts_running;;\n enabled) [ -e $M/st/ts_enabled ] || exit 1;;\n enable) touch $M/st/ts_enabled;;\n disable) rm -f $M/st/ts_enabled;;\nesac\nexit 0\n",
    ),
    (
        "opkg",
        "#!/bin/sh\nM=__D__\necho \"opkg $*\" >> $M/calls.log\ncase \"$1\" in\n list-installed) [ \"$2\" = tailscale-tiny ] && echo 'tailscale-tiny - 1.104.7'; [ \"$2\" = wgcf ] && echo 'wgcf - 2.3.1';;\n update|install|upgrade) echo \"done $1 $2\";;\nesac\nexit 0\n",
    ),
];

struct Env {
    dir: PathBuf,
    router: axum::Router,
    app: AppState,
    bearer: String,
    _g: tokio::sync::MutexGuard<'static, ()>,
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Ok(mut g) = BIN_OVERRIDE.write() {
            *g = None;
        }
        set_paths(None);
        super::MODE.store(0, std::sync::atomic::Ordering::Relaxed);
        *crate::obs::lock(&super::RUNTIME) = super::Runtime::default();
        super::tailscale::forget_flags();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn setup(tag: &str) -> Env {
    let g = LOCK.lock().await;
    let dir = std::env::temp_dir().join(format!("qm-vpn-{tag}-{}-{}", std::process::id(), now_secs()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["bin", "st", "fx", "state", "run", "sysnet", "sysmod/wireguard", "procsys/net/ipv4/conf/warp", "www"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let d = dir.display().to_string();
    for (name, body) in MOCKS {
        let p = dir.join("bin").join(name);
        std::fs::write(&p, body.replace("__D__", &d).replace("__PRIV__", PRIV)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (name, body) in [
        ("wg_dump.txt", FX_WG_DUMP),
        ("wgcf_profile.conf", FX_PROFILE),
        ("wgcf_status.txt", FX_STATUS),
        ("ts_status.json", FX_TS),
        ("ts_status_needslogin.json", FX_TS_LOGIN),
        ("teams_reg.json", FX_REG),
        ("warp_page.html", FX_PAGE),
    ] {
        std::fs::write(dir.join("fx").join(name), body).unwrap();
    }
    std::fs::write(dir.join("st/ts_help"), FX_TS_HELP).unwrap();
    std::fs::write(dir.join("st/ts_status.json"), FX_TS_LOGIN).unwrap();
    // Live rules on the modem before we arrive: tailscale (mwan3 mode), mwan3, main.
    std::fs::write(
        dir.join("st/rules"),
        "0:\tfrom all lookup local\n1310:\tfrom all fwmark 0x80000/0xff0000 lookup main\n2001:\tfrom all fwmark 0x100/0x3f00 lookup 1\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n",
    )
    .unwrap();
    // The modem's own wan section, which nothing here may touch.
    std::fs::write(dir.join("st/uci.db"), "network.wan=interface\nnetwork.wan.proto='qmi'\nfirewall.lanz=zone\nfirewall.lanz.name='lan'\n").unwrap();
    *BIN_OVERRIDE.write().unwrap() = Some(dir.join("bin"));
    set_paths(Some(Paths {
        state: dir.join("state"),
        run: dir.join("run"),
        sys_net: dir.join("sysnet"),
        sys_module: dir.join("sysmod"),
        proc_sys: dir.join("procsys"),
        bin_dirs: vec![dir.join("bin")],
    }));
    let auth = AuthStore::new(dir.join("sessions"));
    let app = AppState::for_tests(dir.join("www"), auth.clone());
    let ctx = HttpCtx { app: app.clone(), proxy: Client::builder(TokioExecutor::new()).build_http(), enforce_uhttpd_loopback: true };
    let sess = auth.create_session().await.unwrap();
    Env { router: build_router(ctx), app, bearer: format!("Bearer {}", sess.token), dir, _g: g }
}

impl Env {
    async fn call_as(&self, auth: &str, method: Method, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder().method(method).uri(uri).header(header::HOST, "192.168.224.1").header("authorization", auth);
        if !body.is_empty() {
            b = b.header(header::CONTENT_TYPE, "application/json").header(header::CONTENT_LENGTH, body.len());
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([192, 168, 224, 50], 40000))));
        let resp = tower::ServiceExt::oneshot(self.router.clone(), req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    async fn call(&self, method: Method, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let b = self.bearer.clone();
        self.call_as(&b, method, uri, body).await
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join(rel)).unwrap_or_default()
    }

    fn calls(&self) -> String {
        self.read("calls.log")
    }

    fn our_rules(&self) -> Vec<(u32, String)> {
        let mut v: Vec<(u32, String)> =
            crate::vpn::parse::parse_ip_rules(&self.read("st/rules")).into_iter().filter(|(p, _)| (1400..1416).contains(p)).collect();
        v.sort();
        v
    }

    fn route(&self) -> String {
        self.read("st/route_51820")
    }

    fn handshake(&self, age: u64) {
        let t = now_secs() - age;
        std::fs::write(self.dir.join("st/hs"), format!("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\t{t}\n")).unwrap();
    }

    /// Route + summary of every audit entry, one per line (unescaped).
    fn audit_all(&self) -> String {
        let v = serde_json::to_value(self.app.audit.query(&Default::default())).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|e| format!("{} {}", e["route"].as_str().unwrap_or(""), e["summary"].as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).map(|m| m.mode() & 0o777).unwrap_or(0)
}

/// Register, license and install a consumer WARP device. Leaves the tunnel up.
async fn consumer_installed(e: &Env) {
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/register", "{}").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/install", r#"{"mtu":1280,"keepalive":25,"autostart":true}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn consumer_warp_register_license_install() {
    let e = setup("consumer").await;
    // nothing yet
    let (s, v) = e.call(Method::GET, "/api/v1/vpn/warp", "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["tools"]["wgcf"], true);
    assert_eq!(v["interface"]["installed"], false);
    assert_eq!(v["policy"]["mode"], "off");

    // register: wgcf register + generate, secrets 0600
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/register", "{}").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["needsInstall"], true);
    let acct = e.dir.join("state/wgcf-account.toml");
    assert_eq!(mode_of(&acct), 0o600, "wgcf wrote 0644; forced to 0600");
    assert_eq!(mode_of(&e.dir.join("state/wgcf-profile.conf")), 0o600);
    assert_eq!(mode_of(&e.dir.join("state")), 0o700);
    assert!(e.calls().contains("wgcf register --accept-tos --config"));
    // a second registration needs the typed confirmation
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/register", "{}").await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(v["confirm"], "REPLACE WARP ACCOUNT");

    // license: format checked, key via environment only
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/license", r#"{"licenseKey":"nope"}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/license", &format!(r#"{{"licenseKey":"{LICENSE}"}}"#)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["licenseSet"], true);
    assert_eq!(e.read("st/wgcf_env_seen"), LICENSE, "wgcf received the key through WGCF_LICENSE_KEY");
    assert!(e.calls().contains("wgcf update --config") && e.calls().contains("env_license=present"));
    assert!(!e.calls().contains(LICENSE), "license never in argv");

    // install: native proto wireguard, no ROOter, main table untouched
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/install", r#"{"mtu":1200}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/install", r#"{"mtu":1280,"keepalive":25,"endpoint":"162.159.192.1:2408"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let db = e.read("st/uci.db");
    for want in [
        "network.warp=interface",
        "network.warp.proto='wireguard'",
        "network.warp.addresses='172.16.0.2/32'",
        "network.warp.mtu='1280'",
        "network.warp.fwmark='0x1000000'",
        "network.warp_peer=wireguard_warp",
        "network.warp_peer.route_allowed_ips='0'",
        "network.warp_peer.allowed_ips='0.0.0.0/0'",
        "network.warp_peer.endpoint_host='162.159.192.1'",
        "network.warp_peer.endpoint_port='2408'",
        "network.warp_peer.persistent_keepalive='25'",
        "firewall.warp_zone=zone",
        "firewall.warp_zone.masq='1'",
        "firewall.warp_zone.mtu_fix='1'",
        "firewall.warp_zone.input='REJECT'",
        "firewall.warp_fwd.src='lan'",
        "network.wan.proto='qmi'",
    ] {
        assert!(db.contains(want), "missing {want} in\n{db}");
    }
    assert!(!db.contains("wireguard_WARP") && !db.contains("go-wireguard"), "no ROOter sections");
    let calls = e.calls();
    assert!(calls.contains("ubus call network reload") && calls.contains("fw4 reload") && calls.contains("ifup warp"), "{calls}");
    assert!(!calls.contains("uci set network.wan"), "wan untouched");
    assert!(!calls.lines().any(|l| l.starts_with("ip") && l.contains("route") && !l.contains("table")), "main table untouched: {calls}");

    // status: live tunnel numbers, never the private key / tokens / license
    e.handshake(30);
    let (s, v) = e.call(Method::GET, "/api/v1/vpn/warp", "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["interface"]["up"], true);
    assert_eq!(v["interface"]["endpoint"], "162.159.192.1:2408");
    assert_eq!(v["interface"]["rxBytes"], 1_048_576);
    assert_eq!(v["account"]["consumer"]["licenseSet"], true);
    let all = v.to_string();
    for secret in [PRIV, LICENSE, "tok-123-secret", "SECRETPRIVATEKEY"] {
        assert!(!all.contains(secret), "{secret} leaked: {all}");
    }

    // account details from wgcf status
    let (s, v) = e.call(Method::GET, "/api/v1/vpn/warp/account", "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"]["accountType"], "limited");
    assert_eq!(v["status"]["devices"].as_array().unwrap().len(), 2);

    // down/up
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/connection", r#"{"action":"down"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!e.dir.join("sysnet/warp").exists());
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/connection", r#"{"action":"sideways"}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // audit: every mutation recorded, no secret in it
    let a = e.audit_all();
    for r in ["/api/v1/vpn/warp/register", "/api/v1/vpn/warp/license", "/api/v1/vpn/warp/install", "/api/v1/vpn/warp/connection"] {
        assert!(a.contains(r), "{r} not audited");
    }
    assert!(!a.contains(LICENSE) && !a.contains(PRIV), "{a}");
    assert!(a.contains("licenseKey=<redacted>"), "{a}");
}

#[tokio::test]
async fn policy_modes_and_failback_never_blackhole() {
    let e = setup("policy").await;
    // policy needs an installed interface
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"modem"}"#).await;
    assert_eq!(s, StatusCode::CONFLICT);
    consumer_installed(&e).await;
    assert!(e.dir.join("sysnet/warp").exists());

    // (a) modem-only, no handshake yet: rules in place, route held back
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"modem"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let plan = policy::Plan { mode: policy::Mode::Modem, pref: 1400, table: 51820, lan_dev: "br-lan".into() };
    let mut want = plan.rules();
    want.sort();
    assert_eq!(e.our_rules(), want);
    assert!(e.route().is_empty(), "no handshake yet: nothing steered into the tunnel");
    assert_eq!(v["usable"], false);
    // foreign rules survive
    let rules = e.read("st/rules");
    for keep in ["1310:", "2001:", "32766:"] {
        assert!(rules.contains(keep), "{keep} removed:\n{rules}");
    }

    // handshake arrives -> route installed, rp_filter loosened on the tunnel only
    e.handshake(5);
    assert_eq!(super::warp::tick(now_secs()).await, policy::RouteAction::Install);
    assert_eq!(e.route().trim(), "default dev warp scope link");
    assert_eq!(e.read("procsys/net/ipv4/conf/warp/rp_filter"), "2");
    assert_eq!(super::warp::tick(now_secs()).await, policy::RouteAction::Keep, "steady state: no churn");

    // peer goes silent while the device stays up -> fail back to cellular
    e.handshake(policy::STALE_SECS + 20);
    assert_eq!(super::warp::tick(now_secs()).await, policy::RouteAction::Withdraw);
    assert!(e.route().trim().is_empty(), "table empty: lookups fall through to the cellular path");
    assert_eq!(e.our_rules(), want, "rules stay; with an empty table they only fall through");
    let (_, v) = e.call(Method::GET, "/api/v1/vpn/warp", "").await;
    assert_eq!(v["policy"]["failingBack"], true);
    assert_eq!(v["policy"]["failbacks"], 1);
    assert!(v["warnings"].to_string().contains("fail-back"));
    let (_, ev) = e.call(Method::GET, "/api/v1/events?type=vpn", "").await;
    assert!(ev.to_string().contains("falls back to the cellular path"), "{ev}");

    // a slightly-fresh handshake is not enough to return (hysteresis) ...
    e.handshake(policy::FRESH_SECS + 10);
    assert_eq!(super::warp::tick(now_secs()).await, policy::RouteAction::Keep);
    assert!(e.route().trim().is_empty());
    // ... a fresh one is
    e.handshake(3);
    assert_eq!(super::warp::tick(now_secs()).await, policy::RouteAction::Install);

    // (b) LAN: typed confirmation with the plain warning
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"lan"}"#).await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED, "{v}");
    assert_eq!(v["confirm"], "ROUTE LAN VIA WARP");
    let w = v["error"].as_str().unwrap();
    assert!(w.contains("latency") && w.contains("egress IP") && w.contains("CGNAT") && w.contains("falls back"), "{w}");
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"lan","confirm":"ROUTE LAN VIA WARP"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(e.our_rules().contains(&(1411, "from all iif br-lan lookup 51820".to_string())));
    assert_eq!(e.route().trim(), "default dev warp scope link");

    // tunnel interface torn down while in (b): the kernel drops the route with
    // the device, the monitor agrees, LAN traffic falls through to cellular
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/connection", r#"{"action":"down"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert!(e.route().trim().is_empty());
    assert!(!super::runtime().usable);
    let (_, v) = e.call(Method::GET, "/api/v1/vpn/warp", "").await;
    assert_eq!(v["policy"]["failingBack"], true);
    // ... and comes back on its own once the tunnel handshakes again
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/connection", r#"{"action":"up"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert!(e.route().trim().is_empty(), "a fresh device has no handshake yet: still on cellular");
    e.handshake(2);
    assert_eq!(super::warp::tick(now_secs()).await, policy::RouteAction::Install);

    // a Tailscale exit node cannot be set while WARP routes LAN traffic
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"exitNode":"nas01","confirm":"USE EXIT NODE"}"#).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");

    // off: our block and the route go away, nothing else changes
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"off"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert!(e.our_rules().is_empty());
    assert!(e.route().trim().is_empty());
    let rules = e.read("st/rules");
    assert_eq!(crate::vpn::parse::parse_ip_rules(&rules).len(), 5, "{rules}");
    assert_eq!(crate::vpn::bypass_mark(), None, "probes unmarked again");

    // the WAN side was never touched by any of this
    let calls = e.calls();
    assert!(!calls.lines().any(|l| l.contains("network.wan") || (l.starts_with("ip") && l.contains("route") && !l.contains("table"))), "{calls}");
    assert!(!calls.lines().any(|l| l.contains("unreachable") || l.contains("blackhole")), "no kill switch");
}

#[tokio::test]
async fn monitor_reasserts_rules_and_marks_probes() {
    let e = setup("reassert").await;
    consumer_installed(&e).await;
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"modem"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(crate::vpn::bypass_mark(), Some(policy::BYPASS_MARK));
    // someone flushes our rules (e.g. a manual `ip rule flush`)
    std::fs::write(e.dir.join("st/rules"), "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n").unwrap();
    let d = super::warp::reconcile_rules(&super::load_state()).await.unwrap();
    assert!(!d.add.is_empty());
    assert_eq!(e.our_rules().len(), policy::EXCLUDE_V4.len() + 3);
    let d = super::warp::reconcile_rules(&super::load_state()).await.unwrap();
    assert!(d.is_empty(), "idempotent");
}

#[tokio::test]
async fn zero_trust_enrollment_with_team_and_service_tokens() {
    let e = setup("teams").await;
    for bad in [
        r#"{"team":"acme"}"#,
        r#"{"team":"acme.example.com","teamToken":"x"}"#,
        r#"{"team":"acme","teamToken":"https://evil.example/?token=aaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        r#"{"team":"acme","clientId":"abc","clientSecret":"def"}"#,
    ] {
        let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/teams", bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let body = format!(r#"{{"team":"acme","teamToken":"com.cloudflare.warp://acme.cloudflareaccess.com/auth?token={JWT}"}}"#);
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/teams", &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["teams"]["accountType"], "team");
    assert_eq!(v["teams"]["endpoint"], "162.159.193.5:2408");
    assert!(v["warnings"].to_string().contains("reserved bytes"));
    // the token went to curl on stdin, not argv; the public key from wg pubkey
    let curl_in = e.read("st/curl_in");
    assert!(curl_in.contains(&format!("CF-Access-Jwt-Assertion: {JWT}")), "{curl_in}");
    assert!(curl_in.contains("zR1v3mF9KQZtqk0kQ0hKxw3Q3d6Q2wqk1zZ3m4p5r6A="));
    assert_eq!(e.read("st/pubkey_stdin").trim(), PRIV, "private key piped to wg pubkey, not argv");
    let calls = e.calls();
    assert!(!calls.contains(JWT) && !calls.contains(PRIV), "{calls}");
    // secrets at rest: 0600
    let sf = e.dir.join("state/warp.json");
    assert_eq!(mode_of(&sf), 0o600);
    let stored = e.read("state/warp.json");
    assert!(stored.contains("DEVICE-API-TOKEN") && stored.contains(PRIV));
    // status never shows them
    let (_, v) = e.call(Method::GET, "/api/v1/vpn/warp", "").await;
    let all = v.to_string();
    assert_eq!(v["account"]["kind"], "teams");
    for secret in [PRIV, JWT, "DEVICE-API-TOKEN"] {
        assert!(!all.contains(secret), "{secret} leaked");
    }
    // install builds the peer from the enrollment
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/install", "{}").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let db = e.read("st/uci.db");
    assert!(db.contains("network.warp.addresses='172.16.0.7/32'") && db.contains("network.warp_peer.endpoint_host='162.159.193.5'"), "{db}");

    // replacing needs the typed confirmation; the service-token path fetches
    // the enrollment token from the team's /warp page first
    let secret = "ab".repeat(32);
    let sbody = format!(r#"{{"team":"acme","clientId":"{CLIENT_ID}","clientSecret":"{secret}"}}"#);
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/teams", &sbody).await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED, "{v}");
    let sbody = format!(r#"{{"team":"acme","clientId":"{CLIENT_ID}","clientSecret":"{secret}","confirm":"REPLACE WARP ACCOUNT"}}"#);
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/teams", &sbody).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let all_in = e.read("st/curl_all");
    assert!(all_in.contains("https://acme.cloudflareaccess.com/warp") && all_in.contains(&format!("CF-Access-Client-Secret: {secret}")));
    assert!(all_in.contains("CF-Access-Jwt-Assertion: eyJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoid2FycCJ9.c2VydmljZS10b2tlbi1zaWc"));
    assert!(!e.calls().contains(&secret));

    // audit keeps none of it
    let a = e.audit_all();
    for s in [JWT, secret.as_str(), CLIENT_ID, PRIV] {
        assert!(!a.contains(s), "{s} in audit: {a}");
    }
    assert!(a.contains("team=\"acme\""), "{a}");

    // remove: typed confirmation, then interface, zone and enrollment go
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/remove", r#"{"deleteAccount":true}"#).await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED, "{v}");
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/remove", r#"{"deleteAccount":true,"confirm":"REMOVE WARP"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let db = e.read("st/uci.db");
    assert!(!db.contains("network.warp") && !db.contains("firewall.warp"), "{db}");
    assert!(db.contains("network.wan.proto='qmi'"));
    assert!(e.read("st/curl_in").contains("request = \"DELETE\""), "unenrolled at Cloudflare");
    assert!(!e.read("state/warp.json").contains(PRIV));
}

#[tokio::test]
async fn tailscale_full_manager() {
    let e = setup("ts").await;
    let (s, v) = e.call(Method::GET, "/api/v1/vpn/tailscale", "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["package"]["name"], "tailscale-tiny");
    assert_eq!(v["service"]["running"], false);
    assert_eq!(v["capabilities"]["tiny"], true);
    assert_eq!(v["capabilities"]["unsupported"].as_array().unwrap().len(), 0);
    assert_eq!(v["lanCidr"], "192.168.224.0/22");

    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/service", r#"{"action":"start"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/service", r#"{"action":"enable"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["enabledAtBoot"], true);
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/service", r#"{"action":"rm -rf"}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // interactive login: the auth URL is shown to sessions and rw tokens only
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/login", "{}").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["authUrl"], "https://login.tailscale.com/a/1a2b3c4d5e6f");
    let (_, rd) = e.app.tokens.create("mon", TokenKind::Read, None).unwrap();
    let (_, rw) = e.app.tokens.create("ops", TokenKind::Rw, None).unwrap();
    let (s, v) = e.call_as(&format!("Bearer {rd}"), Method::GET, "/api/v1/vpn/tailscale", "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"]["backendState"], "NeedsLogin");
    assert!(!v.to_string().contains("login.tailscale.com"), "read token sees no login link");
    let (_, v) = e.call_as(&format!("Bearer {rw}"), Method::GET, "/api/v1/vpn/tailscale", "").await;
    assert_eq!(v["status"]["authUrl"], "https://login.tailscale.com/a/1a2b3c4d5e6f");

    // auth key: validated, handed over as file: (0600, deleted afterwards)
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/login", r#"{"authKey":"tskey-client-k1-abcdefghijklmnop"}"#).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "tiny build has no OAuth client support");
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/login", r#"{"authKey":"hunter2"}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/login", &format!(r#"{{"authKey":"{AUTHKEY}"}}"#)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["backendState"], "Running");
    assert_eq!(e.read("st/ts_key_seen"), AUTHKEY);
    assert_eq!(e.read("st/ts_key_mode").trim(), "600");
    assert!(!e.dir.join("run/ts-authkey").exists(), "key file removed");
    assert!(!e.calls().contains(AUTHKEY), "auth key never in argv");
    assert!(e.calls().contains("tailscale up --reset --auth-key=file:"));

    // status with peers
    let (_, v) = e.call(Method::GET, "/api/v1/vpn/tailscale", "").await;
    assert_eq!(v["status"]["selfNode"]["hostName"], "mgateway1");
    assert_eq!(v["status"]["tailnet"], "example.github");
    assert_eq!(v["status"]["peers"].as_array().unwrap().len(), 3);

    // settings: CIDR validation, subnet routes default to the modem LAN
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"advertiseRoutes":["192.168.224.1/22"]}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"].as_str().unwrap().contains("192.168.224.0/22"));
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"advertiseRoutes":["192.168.224.0/22"],"acceptRoutes":true,"ssh":true,"hostname":"mgateway1"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(e.calls().contains("tailscale set --hostname=mgateway1 --accept-routes=true --advertise-routes=192.168.224.0/22 --ssh=true"), "{}", e.calls());
    let db = e.read("st/uci.db");
    assert!(db.contains("tailscale.settings.advertise_routes='192.168.224.0/22'") && db.contains("tailscale.settings.ssh='1'"), "{db}");

    // exit node: typed confirmation with the backup-WAN warning
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"exitNode":"nas01"}"#).await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(v["confirm"], "USE EXIT NODE");
    assert!(v["error"].as_str().unwrap().contains("backup WAN"));
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"exitNode":"nas01","confirm":"USE EXIT NODE"}"#).await;
    assert_eq!(s, StatusCode::OK);
    assert!(e.calls().contains("tailscale set --exit-node=nas01 --exit-node-allow-lan-access=true"));
    // WARP (b) is refused while an exit node is configured
    consumer_installed(&e).await;
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/warp/policy", r#"{"mode":"lan","confirm":"ROUTE LAN VIA WARP"}"#).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // shields up confirmation
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"shieldsUp":true}"#).await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(v["confirm"], "SHIELDS UP");

    // a tailscale refusal leaves the mirror unchanged
    std::fs::write(e.dir.join("st/ts_set_fail"), "fail").unwrap();
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"acceptRoutes":false}"#).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    std::fs::remove_file(e.dir.join("st/ts_set_fail")).unwrap();

    // a build without a flag is detected, not silently ignored
    std::fs::write(e.dir.join("st/ts_help"), FX_TS_HELP.replace("--ssh", "--sxh")).unwrap();
    super::tailscale::forget_flags();
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/settings", r#"{"ssh":false}"#).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["error"].as_str().unwrap().contains("--ssh"));
    let (_, v) = e.call(Method::GET, "/api/v1/vpn/tailscale", "").await;
    assert_eq!(v["capabilities"]["unsupported"], serde_json::json!(["ssh"]));

    // logout needs the typed confirmation
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/logout", "{}").await;
    assert_eq!(s, StatusCode::PRECONDITION_REQUIRED);
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/tailscale/logout", r#"{"confirm":"LOG OUT TAILSCALE"}"#).await;
    assert_eq!(s, StatusCode::OK);

    let a = e.audit_all();
    assert!(!a.contains(AUTHKEY) && a.contains("authKey=<redacted>"), "{a}");
    assert!(a.contains("exitNode=\"nas01\""), "{a}");
}

#[tokio::test]
async fn package_jobs_run_detached() {
    let e = setup("pkg").await;
    let (s, _) = e.call(Method::POST, "/api/v1/vpn/packages", r#"{"package":"busybox","action":"install"}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/packages", r#"{"package":"tailscale-tiny","action":"upgrade"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut done = None;
    for _ in 0..50 {
        if let Some(j) = super::pkg::read_job().filter(|j| j.state != "running") {
            done = Some(j);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let j = done.expect("job finished");
    assert_eq!(j.state, "succeeded", "{j:?} {}", e.read("run/pkg-job.log"));
    assert_eq!(j.installed_after.as_deref(), Some("1.104.7"));
    assert!(e.calls().contains("opkg update") && e.calls().contains("opkg upgrade tailscale-tiny"));
    let (s, v) = e.call(Method::GET, "/api/v1/vpn/packages", "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["packages"][0]["installed"], "1.104.7");
}

#[tokio::test]
async fn read_tokens_see_status_never_secrets_or_mutations() {
    let e = setup("tokens").await;
    consumer_installed(&e).await;
    let (_, rd) = e.app.tokens.create("mon", TokenKind::Read, None).unwrap();
    let h = format!("Bearer {rd}");
    for p in ["/api/v1/vpn/warp", "/api/v1/vpn/tailscale", "/api/v1/vpn/packages", "/api/v1/vpn/warp/account"] {
        let (s, v) = e.call_as(&h, Method::GET, p, "").await;
        assert_eq!(s, StatusCode::OK, "{p}: {v}");
        let t = v.to_string();
        assert!(!t.contains(PRIV) && !t.contains("tok-123-secret") && !t.contains("FREEKEY0"), "{p}: {t}");
    }
    for p in [
        "/api/v1/vpn/warp/register",
        "/api/v1/vpn/warp/license",
        "/api/v1/vpn/warp/teams",
        "/api/v1/vpn/warp/install",
        "/api/v1/vpn/warp/connection",
        "/api/v1/vpn/warp/policy",
        "/api/v1/vpn/warp/remove",
        "/api/v1/vpn/tailscale/service",
        "/api/v1/vpn/tailscale/login",
        "/api/v1/vpn/tailscale/logout",
        "/api/v1/vpn/tailscale/settings",
        "/api/v1/vpn/packages",
    ] {
        let (s, _) = e.call_as(&h, Method::POST, p, "{}").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    }
}

#[tokio::test]
async fn optional_json_vpn_routes_reject_malformed_unknown_and_wrong_content_type() {
    let e = setup("optjson").await;
    for path in ["/api/v1/vpn/warp/register", "/api/v1/vpn/tailscale/login"] {
        for (ct, raw, want) in [
            ("application/json", "{", StatusCode::BAD_REQUEST),
            ("application/json", r#"{"command":5}"#, StatusCode::BAD_REQUEST),
            ("text/plain", "{}", StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ] {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::HOST, "192.168.224.1")
                .header("authorization", &e.bearer)
                .header(header::CONTENT_TYPE, ct)
                .body(Body::from(raw.to_string()))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([192, 168, 224, 50], 40000))));
            let resp = tower::ServiceExt::oneshot(e.router.clone(), req).await.unwrap();
            assert_eq!(resp.status(), want, "{path} {ct} {raw}");
        }
    }
    let calls = e.calls();
    assert!(!calls.contains("wgcf"), "must not spawn wgcf on invalid JSON: {calls}");
    assert!(!calls.contains("tailscale "), "must not run tailscale up on invalid JSON: {calls}");
}

#[tokio::test]
async fn tailscale_service_stop_waits_for_async_procd_exit() {
    let e = setup("ts_settle").await;
    std::fs::write(e.dir.join("st/ts_running"), "running\n").unwrap();
    let init_mock = e.dir.join("bin/etc__init.d__tailscale");
    std::fs::write(
        &init_mock,
        format!(
            "#!/bin/sh\nM={}\ncase \"$1\" in\n  stop) echo 1 > $M/st/ts_stopping;;\n  status) if [ -f $M/st/ts_stopping ]; then rm -f $M/st/ts_stopping; echo running; else echo inactive; fi;;\n  enabled) exit 0;;\nesac\nexit 0\n",
            e.dir.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&init_mock, std::fs::Permissions::from_mode(0o755));
    }
    let (s, v) = e.call(Method::POST, "/api/v1/vpn/tailscale/service", r#"{"action":"stop"}"#).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["running"], false);
}
