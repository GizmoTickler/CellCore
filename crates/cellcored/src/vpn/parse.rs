//! Pure parsers for the outputs the VPN module reads. Nothing here returns a
//! private key, access token or license: those fields are either skipped or
//! reduced to "present".

use serde::Serialize;

// ── wgcf ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgcfDevice {
    pub id: String,
    pub current: bool,
    pub kind: String,
    pub model: String,
    pub name: String,
    pub active: bool,
    pub created: String,
    pub activated: String,
    pub role: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgcfStatus {
    pub account_id: String,
    pub account_type: String,
    pub premium_data: String,
    pub quota: String,
    pub role: String,
    pub devices: Vec<WgcfDevice>,
}

/// Parse `wgcf status` (wgcf 2.x `PrintAccountDetails`): `Key : value`
/// blocks under "Account" and "Devices" banners. Log lines (timestamps) and
/// banners are ignored.
pub fn parse_wgcf_status(text: &str) -> Option<WgcfStatus> {
    let mut st = WgcfStatus::default();
    let mut section = "";
    let mut dev: Option<WgcfDevice> = None;
    let mut saw_account = false;
    for raw in text.lines() {
        let line = raw.trim();
        match line {
            "Account" => {
                section = "account";
                continue;
            }
            "Devices" => {
                section = "devices";
                continue;
            }
            _ => {}
        }
        if line.is_empty() || line.starts_with("===") {
            continue;
        }
        let Some((k, v)) = line.split_once(" : ") else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match section {
            "account" => {
                saw_account = true;
                match k {
                    "Id" => st.account_id = v.to_string(),
                    "Account type" => st.account_type = v.to_string(),
                    "Premium data" => st.premium_data = v.to_string(),
                    "Quota" => st.quota = v.to_string(),
                    "Role" => st.role = v.to_string(),
                    _ => {}
                }
            }
            "devices" => {
                if k == "Id" {
                    if let Some(d) = dev.take() {
                        st.devices.push(d);
                    }
                    let current = v.ends_with("(current)");
                    dev = Some(WgcfDevice {
                        id: v.trim_end_matches("(current)").trim().to_string(),
                        current,
                        ..Default::default()
                    });
                    continue;
                }
                let Some(d) = dev.as_mut() else { continue };
                match k {
                    "Type" => d.kind = v.to_string(),
                    "Model" => d.model = v.to_string(),
                    "Name" => d.name = v.to_string(),
                    "Active" => d.active = v == "true",
                    "Created" => d.created = v.to_string(),
                    "Activated" => d.activated = v.to_string(),
                    "Role" => d.role = v.to_string(),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if let Some(d) = dev.take() {
        st.devices.push(d);
    }
    saw_account.then_some(st)
}

/// What the wgcf account file tells us, minus the secrets themselves.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WgcfAccount {
    pub device_id: String,
    pub has_access_token: bool,
    pub has_private_key: bool,
    /// The bound license, kept in memory only to compare; never serialized.
    pub license_key: String,
}

/// Parse `wgcf-account.toml` (flat `key = 'value'` / `key = "value"`).
pub fn parse_wgcf_account(text: &str) -> WgcfAccount {
    let mut a = WgcfAccount::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
        match k.trim() {
            "device_id" => a.device_id = v,
            "access_token" => a.has_access_token = !v.is_empty(),
            "private_key" => a.has_private_key = !v.is_empty(),
            "license_key" => a.license_key = v,
            _ => {}
        }
    }
    a
}

/// A WireGuard client profile (`wgcf generate` output or one we built).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WgProfile {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub mtu: Option<u16>,
    pub peer_public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<u16>,
}

impl WgProfile {
    pub fn v4_address(&self) -> Option<&str> {
        self.addresses.iter().map(String::as_str).find(|a| !a.contains(':'))
    }
}

/// Parse a wg-quick style INI profile.
pub fn parse_wg_profile(text: &str) -> Result<WgProfile, String> {
    let mut p = WgProfile::default();
    let mut sect = String::new();
    let list = |v: &str| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            sect = line.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (sect.as_str(), k.as_str()) {
            ("interface", "privatekey") => p.private_key = v.to_string(),
            ("interface", "address") => p.addresses = list(v),
            ("interface", "mtu") => p.mtu = v.parse().ok(),
            ("peer", "publickey") => p.peer_public_key = v.to_string(),
            ("peer", "endpoint") => p.endpoint = v.to_string(),
            ("peer", "allowedips") => p.allowed_ips = list(v),
            ("peer", "persistentkeepalive") => p.keepalive = v.parse().ok(),
            _ => {}
        }
    }
    if !super::validate::is_wg_key(&p.private_key) || !super::validate::is_wg_key(&p.peer_public_key) {
        return Err("profile has no valid key pair".into());
    }
    if p.v4_address().is_none() {
        return Err("profile has no IPv4 address".into());
    }
    if super::validate::endpoint(&p.endpoint).is_none() {
        return Err("profile has no valid endpoint".into());
    }
    Ok(p)
}

// ── wg ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub keepalive: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WgDump {
    pub public_key: String,
    pub listen_port: u16,
    pub fwmark: Option<String>,
    pub peers: Vec<WgPeer>,
}

/// Parse `wg show <if> dump`. The first line carries the interface's
/// private key: it is read past and never stored.
pub fn parse_wg_dump(text: &str) -> Option<WgDump> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first: Vec<&str> = lines.next()?.split('\t').collect();
    if first.len() < 4 {
        return None;
    }
    let mut d = WgDump {
        public_key: first[1].to_string(),
        listen_port: first[2].parse().unwrap_or(0),
        fwmark: (first[3] != "off").then(|| first[3].to_string()),
        peers: Vec::new(),
    };
    for l in lines {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 8 {
            continue;
        }
        d.peers.push(WgPeer {
            public_key: f[0].to_string(),
            endpoint: (f[2] != "(none)").then(|| f[2].to_string()),
            allowed_ips: if f[3] == "(none)" { Vec::new() } else { f[3].split(',').map(str::to_string).collect() },
            latest_handshake: f[4].parse().unwrap_or(0),
            rx_bytes: f[5].parse().unwrap_or(0),
            tx_bytes: f[6].parse().unwrap_or(0),
            keepalive: f[7].parse().ok(),
        });
    }
    Some(d)
}

/// Parse `wg show <if> latest-handshakes`: newest handshake epoch (0 = never).
pub fn parse_latest_handshake(text: &str) -> Option<u64> {
    text.lines().filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).max()
}

// ── ip rule ─────────────────────────────────────────────────────────────────

/// `ip -4 rule show` → (pref, selector/action text with single spaces).
pub fn parse_ip_rules(text: &str) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|l| {
            let (p, rest) = l.split_once(':')?;
            let pref = p.trim().parse::<u32>().ok()?;
            Some((pref, rest.split_whitespace().collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

/// `ip -4 -o addr show dev X` → first "a.b.c.d/nn".
pub fn parse_ip_addr_cidr(text: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "inet"
            && let Some(cidr) = it.next()
            && let Some((a, p)) = cidr.split_once('/')
        {
            return Some((a.parse().ok()?, p.parse().ok()?));
        }
    }
    None
}

// ── tailscale ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsPeer {
    pub host_name: String,
    pub dns_name: String,
    pub os: String,
    pub ips: Vec<String>,
    pub online: bool,
    pub active: bool,
    pub last_seen: Option<String>,
    pub exit_node_option: bool,
    pub exit_node: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsStatus {
    pub backend_state: String,
    pub version: String,
    /// Login link while `NeedsLogin`; withheld from read-only tokens by the handler.
    pub auth_url: Option<String>,
    pub tailnet: Option<String>,
    pub magic_dns_suffix: Option<String>,
    pub health: Vec<String>,
    pub self_node: Option<TsPeer>,
    pub peers: Vec<TsPeer>,
    pub exit_node_in_use: Option<String>,
}

fn s(v: &serde_json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn ts_peer(v: &serde_json::Value) -> TsPeer {
    let last_seen = v
        .get("LastSeen")
        .and_then(|x| x.as_str())
        .filter(|t| !t.is_empty() && !t.starts_with("0001-01-01"))
        .map(str::to_string);
    TsPeer {
        host_name: s(v, "HostName"),
        dns_name: s(v, "DNSName").trim_end_matches('.').to_string(),
        os: s(v, "OS"),
        ips: v
            .get("TailscaleIPs")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        online: v.get("Online").and_then(|x| x.as_bool()).unwrap_or(false),
        active: v.get("Active").and_then(|x| x.as_bool()).unwrap_or(false),
        last_seen,
        exit_node_option: v.get("ExitNodeOption").and_then(|x| x.as_bool()).unwrap_or(false),
        exit_node: v.get("ExitNode").and_then(|x| x.as_bool()).unwrap_or(false),
        rx_bytes: v.get("RxBytes").and_then(|x| x.as_u64()).unwrap_or(0),
        tx_bytes: v.get("TxBytes").and_then(|x| x.as_u64()).unwrap_or(0),
    }
}

/// Parse `tailscale status --json`.
pub fn parse_ts_status(text: &str) -> Result<TsStatus, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("tailscale status: {e}"))?;
    let mut peers: Vec<TsPeer> = v
        .get("Peer")
        .and_then(|p| p.as_object())
        .map(|m| m.values().map(ts_peer).collect())
        .unwrap_or_default();
    peers.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.host_name.to_ascii_lowercase().cmp(&b.host_name.to_ascii_lowercase())));
    let exit = peers.iter().find(|p| p.exit_node).map(|p| if p.dns_name.is_empty() { p.host_name.clone() } else { p.dns_name.clone() });
    let tailnet = v.get("CurrentTailnet").filter(|t| !t.is_null());
    Ok(TsStatus {
        backend_state: s(&v, "BackendState"),
        version: s(&v, "Version").split('-').next().unwrap_or("").to_string(),
        auth_url: v.get("AuthURL").and_then(|x| x.as_str()).filter(|u| u.starts_with("https://")).map(str::to_string),
        tailnet: tailnet.map(|t| s(t, "Name")).filter(|n| !n.is_empty()),
        magic_dns_suffix: tailnet.map(|t| s(t, "MagicDNSSuffix")).filter(|n| !n.is_empty()),
        health: v
            .get("Health")
            .and_then(|h| h.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        self_node: v.get("Self").filter(|x| x.is_object()).map(ts_peer),
        peers,
        exit_node_in_use: exit,
    })
}

/// Flag names offered by `tailscale <sub> --help` (ffcli prints
/// `  --accept-routes, --accept-routes=false` style lines to stderr).
pub fn parse_help_flags(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in text.split(|c: char| c.is_whitespace() || c == ',') {
        let Some(name) = tok.strip_prefix("--") else { continue };
        let name: String = name.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        if name.len() > 1 && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WGCF_STATUS: &str = include_str!("fixtures/wgcf_status.txt");
    const WG_DUMP: &str = include_str!("fixtures/wg_dump.txt");
    const TS_STATUS: &str = include_str!("fixtures/ts_status.json");
    const TS_STATUS_LOGIN: &str = include_str!("fixtures/ts_status_needslogin.json");
    const TS_SET_HELP: &str = include_str!("fixtures/ts_set_help.txt");
    const PROFILE: &str = include_str!("fixtures/wgcf_profile.conf");

    #[test]
    fn wgcf_status_account_and_devices() {
        let st = parse_wgcf_status(WGCF_STATUS).unwrap();
        assert_eq!(st.account_type, "limited");
        assert_eq!(st.premium_data, "24 GB");
        assert_eq!(st.quota, "24 GB");
        assert_eq!(st.role, "child");
        assert_eq!(st.devices.len(), 2);
        assert!(st.devices[0].current);
        assert_eq!(st.devices[0].id, "0f2b6e1c-7a0e-4f0e-9a7e-2d6c8b1e5a11");
        assert_eq!(st.devices[0].model, "PC");
        assert!(st.devices[0].active);
        assert!(!st.devices[1].current);
        assert_eq!(st.devices[1].name, "Pixel");
        assert!(!st.devices[1].active);
        assert!(parse_wgcf_status("2026/11/18 no account detected, register one first").is_none());
        // free account: no premium data line values beyond 0
        let free = "Account\nId           : abc\nAccount type : free\nPremium data : 0 B\nQuota        : 0 B\nRole         : N/A\n\nDevices\n";
        let f = parse_wgcf_status(free).unwrap();
        assert_eq!(f.account_type, "free");
        assert!(f.devices.is_empty());
    }

    #[test]
    fn wgcf_account_never_exposes_secrets() {
        let t = "access_token = 'aaaa-bbbb'\ndevice_id = 'dev-1'\nlicense_key = 'a1B2c3D4-e5F6g7H8-i9J0k1L2'\nprivate_key = 'cGs='\n";
        let a = parse_wgcf_account(t);
        assert_eq!(a.device_id, "dev-1");
        assert!(a.has_access_token && a.has_private_key);
        assert_eq!(a.license_key, "a1B2c3D4-e5F6g7H8-i9J0k1L2");
        let a2 = parse_wgcf_account("device_id = \"x\"\naccess_token = \"\"\n");
        assert!(!a2.has_access_token && !a2.has_private_key);
    }

    #[test]
    fn wg_profile_round_trip() {
        let p = parse_wg_profile(PROFILE).unwrap();
        assert_eq!(p.addresses, vec!["172.16.0.2/32", "2606:4700:110:8a36:df92:102a:9602:fa18/128"]);
        assert_eq!(p.v4_address(), Some("172.16.0.2/32"));
        assert_eq!(p.mtu, Some(1280));
        assert_eq!(p.endpoint, "engage.cloudflareclient.com:2408");
        assert_eq!(p.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(p.peer_public_key, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");
        assert!(parse_wg_profile("[Interface]\nPrivateKey = x\n").is_err());
        let no_ep = PROFILE.replace("Endpoint = engage.cloudflareclient.com:2408", "");
        assert!(parse_wg_profile(&no_ep).is_err());
    }

    #[test]
    fn wg_dump_skips_private_key() {
        let d = parse_wg_dump(WG_DUMP).unwrap();
        assert_eq!(d.public_key, "zR1v3mF9KQZtqk0kQ0hKxw3Q3d6Q2wqk1zZ3m4p5r6A=");
        assert_eq!(d.listen_port, 51820);
        assert_eq!(d.fwmark.as_deref(), Some("0x1000000"));
        assert_eq!(d.peers.len(), 1);
        let p = &d.peers[0];
        assert_eq!(p.endpoint.as_deref(), Some("162.159.192.1:2408"));
        assert_eq!(p.latest_handshake, 1_763_450_000);
        assert_eq!(p.rx_bytes, 1_048_576);
        assert_eq!(p.tx_bytes, 524_288);
        assert_eq!(p.keepalive, Some(25));
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("SECRETPRIVATEKEY"), "{json}");
        // fresh interface: no peers, no handshake
        let bare = "SECRETPRIVATEKEY0000000000000000000000000000=\tpub=\t0\toff\n";
        let b = parse_wg_dump(bare).unwrap();
        assert!(b.peers.is_empty() && b.fwmark.is_none());
        assert!(parse_wg_dump("").is_none());
        assert_eq!(parse_latest_handshake("k1=\t0\nk2=\t1763450000\n"), Some(1_763_450_000));
        assert_eq!(parse_latest_handshake("k1=\t0\n"), Some(0));
        assert_eq!(parse_latest_handshake(""), None);
    }

    #[test]
    fn ip_rule_and_addr() {
        let r = parse_ip_rules("0:\tfrom all lookup local\n1310:\tfrom all fwmark 0x80000/0xff0000 lookup main\n1410:\tfrom all iif lo lookup 51820 \n32766:\tfrom all lookup main\n");
        assert_eq!(r.len(), 4);
        assert_eq!(r[2], (1410, "from all iif lo lookup 51820".to_string()));
        assert_eq!(
            parse_ip_addr_cidr("5: br-lan    inet 192.168.224.1/22 brd 192.168.227.255 scope global br-lan\\       valid_lft forever"),
            Some(("192.168.224.1".parse().unwrap(), 22))
        );
        assert_eq!(parse_ip_addr_cidr(""), None);
    }

    #[test]
    fn tailscale_status_running() {
        let st = parse_ts_status(TS_STATUS).unwrap();
        assert_eq!(st.backend_state, "Running");
        assert_eq!(st.version, "1.104.7");
        assert_eq!(st.tailnet.as_deref(), Some("example.github"));
        assert_eq!(st.health, vec!["Some peers are advertising routes but --accept-routes is false"]);
        let me = st.self_node.as_ref().unwrap();
        assert_eq!(me.host_name, "mgateway1");
        assert_eq!(me.ips, vec!["100.101.102.103", "fd7a:115c:a1e0::1"]);
        assert_eq!(st.peers.len(), 3);
        assert_eq!(st.peers[0].host_name, "laptop", "online first, then by name");
        let nas = st.peers.iter().find(|p| p.host_name == "nas01").unwrap();
        assert!(nas.exit_node_option && nas.online);
        let phone = st.peers.iter().find(|p| p.host_name == "phone").unwrap();
        assert!(!phone.online);
        assert_eq!(phone.last_seen.as_deref(), Some("2026-11-17T21:04:11Z"));
        assert!(st.peers.iter().find(|p| p.host_name == "laptop").unwrap().last_seen.is_none(), "zero time is no time");
        assert!(st.auth_url.is_none());
        assert!(st.exit_node_in_use.is_none());
    }

    #[test]
    fn tailscale_status_needs_login() {
        let st = parse_ts_status(TS_STATUS_LOGIN).unwrap();
        assert_eq!(st.backend_state, "NeedsLogin");
        assert_eq!(st.auth_url.as_deref(), Some("https://login.tailscale.com/a/1a2b3c4d5e6f"));
        assert!(st.peers.is_empty());
        assert!(st.tailnet.is_none());
        assert!(parse_ts_status("not json").is_err());
        let evil = r#"{"BackendState":"NeedsLogin","AuthURL":"javascript:alert(1)"}"#;
        assert!(parse_ts_status(evil).unwrap().auth_url.is_none(), "only https links reach the UI");
    }

    #[test]
    fn tailscale_help_flags() {
        let f = parse_help_flags(TS_SET_HELP);
        for want in ["accept-routes", "advertise-exit-node", "advertise-routes", "exit-node", "hostname", "shields-up", "ssh", "exit-node-allow-lan-access"] {
            assert!(f.iter().any(|x| x == want), "missing {want}: {f:?}");
        }
        assert!(!f.iter().any(|x| x == "webclient"), "tiny build omits the web client");
        assert!(!f.iter().any(|x| x == "accept-routes=false"));
    }
}
