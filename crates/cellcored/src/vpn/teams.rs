//! Cloudflare Zero Trust (Teams) enrollment as a WireGuard device.
//!
//! Cloudflare documents two enrollment inputs for headless devices: the
//! team token printed on `https://<team>.cloudflareaccess.com/warp` after
//! login (`warp-cli registration token "com.cloudflare.warp://…?token=…"`)
//! and an Access service token (`auth_client_id` / `auth_client_secret` in
//! `mdm.xml`). The official client that consumes them is not built for
//! musl/OpenWrt, so this module performs the same registration call the
//! client makes against the (undocumented) client API, exactly as the
//! community tools do (wgcf-teams, warp.sh, usque), and turns the result into
//! a kernel WireGuard peer.
//!
//! Everything that depends on that undocumented API lives in this file:
//! [`API_BASE`], [`CLIENT_HEADERS`], [`registration_body`] and
//! [`parse_registration`]. docs/WARP.md lists what breaks if it changes.
//!
//! Secrets (team token, service token, device API token) only travel in a
//! curl config fed on stdin, never in argv or the environment.

use serde::{Deserialize, Serialize};

pub const API_BASE: &str = "https://api.cloudflareclient.com/v0a2483";
pub const CLIENT_HEADERS: &[(&str, &str)] = &[
    ("User-Agent", "1.1.1.1/6.81"),
    ("CF-Client-Version", "a-6.81-2410012252.0"),
    ("Accept", "application/json; charset=UTF-8"),
];
/// The port the client uses when the API returns `:0` endpoints.
pub const DEFAULT_PORT: u16 = 2408;

/// Escape a value for a double-quoted curl config string.
pub fn curl_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' | '\r' | '\t' => o.push(' '),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn base_config(url: &str, timeout: u64) -> String {
    let mut c = format!("url = {}\nsilent\nshow-error\nmax-time = {timeout}\nproto = \"=https\"\n", curl_str(url));
    for (k, v) in CLIENT_HEADERS {
        c.push_str(&format!("header = {}\n", curl_str(&format!("{k}: {v}"))));
    }
    c
}

pub fn registration_body(public_key: &str, name: &str, tos: &str) -> serde_json::Value {
    serde_json::json!({
        "key": public_key,
        "install_id": "",
        "fcm_token": "",
        "tos": tos,
        "model": "CellCore",
        "serial_number": "",
        "name": name,
        "type": "Linux",
        "locale": "en_US",
    })
}

/// curl config for `POST /reg` with the team token as the Access assertion.
pub fn registration_config(team_token: &str, body: &serde_json::Value) -> String {
    let mut c = base_config(&format!("{API_BASE}/reg"), 30);
    c.push_str("request = \"POST\"\n");
    c.push_str("header = \"Content-Type: application/json\"\n");
    c.push_str(&format!("header = {}\n", curl_str(&format!("CF-Access-Jwt-Assertion: {team_token}"))));
    c.push_str(&format!("data = {}\n", curl_str(&body.to_string())));
    c
}

/// curl config for `GET /reg/<id>` (refresh peers/addresses).
pub fn refresh_config(device_id: &str, device_token: &str) -> String {
    let mut c = base_config(&format!("{API_BASE}/reg/{device_id}"), 30);
    c.push_str(&format!("header = {}\n", curl_str(&format!("Authorization: Bearer {device_token}"))));
    c
}

/// curl config for `DELETE /reg/<id>` (unenroll).
pub fn delete_config(device_id: &str, device_token: &str) -> String {
    let mut c = refresh_config(device_id, device_token);
    c.push_str("request = \"DELETE\"\n");
    c
}

/// curl config that presents an Access service token to the team's /warp
/// page, which answers with the same success page a browser login shows.
pub fn service_token_config(team: &str, client_id: &str, client_secret: &str) -> String {
    let mut c = format!(
        "url = {}\nsilent\nshow-error\nmax-time = 30\nproto = \"=https\"\n",
        curl_str(&format!("https://{team}.cloudflareaccess.com/warp"))
    );
    c.push_str(&format!("header = {}\n", curl_str(&format!("CF-Access-Client-Id: {client_id}"))));
    c.push_str(&format!("header = {}\n", curl_str(&format!("CF-Access-Client-Secret: {client_secret}"))));
    c
}

/// Extract the enrollment token from the /warp success page
/// (`<meta http-equiv="refresh" content="0;url=com.cloudflare.warp://…?token=…">`).
pub fn token_from_success_page(html: &str) -> Option<String> {
    let i = html.find("com.cloudflare.warp://")?;
    let rest = &html[i..];
    let end = rest.find(['"', '\'', '<', ' ']).unwrap_or(rest.len());
    super::validate::team_token(&rest[..end])
}

/// What we keep about an enrolled Zero Trust device (0600 on disk).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TeamsDevice {
    pub team: String,
    pub device_id: String,
    /// Device API token (secret): refresh/unenroll only.
    pub device_token: String,
    pub account_type: String,
    pub organization: String,
    pub peer_public_key: String,
    pub endpoint_host: String,
    pub endpoint_v4: String,
    pub address_v4: String,
    pub address_v6: String,
    /// Reserved bytes Cloudflare asks clients to put in WireGuard headers.
    /// The kernel module cannot send them; kept for diagnostics.
    pub client_id: String,
    pub tunnel_protocol: String,
    pub enrolled_at: u64,
}

impl TeamsDevice {
    /// Endpoint for the WireGuard peer: the anycast IPv4 from the API with
    /// the client port (the API reports `:0`), else the hostname.
    pub fn endpoint(&self) -> (String, u16) {
        if let Some((h, _)) = self.endpoint_v4.rsplit_once(':')
            && h.parse::<std::net::Ipv4Addr>().is_ok()
        {
            return (h.to_string(), DEFAULT_PORT);
        }
        match super::validate::endpoint(&self.endpoint_host) {
            Some((h, p)) => (h, p),
            None => ("engage.cloudflareclient.com".into(), DEFAULT_PORT),
        }
    }

    /// Public view: no device token.
    pub fn public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "team": self.team,
            "deviceId": self.device_id,
            "accountType": self.account_type,
            "organization": self.organization,
            "peerPublicKey": self.peer_public_key,
            "endpoint": format!("{}:{}", self.endpoint().0, self.endpoint().1),
            "addressV4": self.address_v4,
            "tunnelProtocol": self.tunnel_protocol,
            "enrolledAt": self.enrolled_at,
        })
    }
}

fn js(v: &serde_json::Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(*p) {
            Some(x) => cur = x,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or("").to_string()
}

/// Parse the `/reg` (or `/reg/<id>`) response.
pub fn parse_registration(text: &str, team: &str) -> Result<TeamsDevice, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|_| "Cloudflare returned something that is not JSON".to_string())?;
    if let Some(errs) = v.get("errors").and_then(|e| e.as_array()).filter(|a| !a.is_empty()) {
        let msg: Vec<String> = errs.iter().filter_map(|e| e.get("message").and_then(|m| m.as_str()).map(str::to_string)).collect();
        return Err(format!("Cloudflare refused the enrollment: {}", msg.join("; ")));
    }
    let peer = v.pointer("/config/peers/0").cloned().unwrap_or_default();
    let d = TeamsDevice {
        team: team.to_string(),
        device_id: js(&v, &["id"]),
        device_token: js(&v, &["token"]),
        account_type: js(&v, &["account", "account_type"]),
        organization: js(&v, &["account", "organization"]),
        peer_public_key: js(&peer, &["public_key"]),
        endpoint_host: js(&peer, &["endpoint", "host"]),
        endpoint_v4: js(&peer, &["endpoint", "v4"]),
        address_v4: js(&v, &["config", "interface", "addresses", "v4"]),
        address_v6: js(&v, &["config", "interface", "addresses", "v6"]),
        client_id: js(&v, &["config", "client_id"]),
        tunnel_protocol: js(&v, &["policy", "tunnel_protocol"]),
        enrolled_at: crate::auth::now_secs(),
    };
    if d.device_id.is_empty() {
        return Err("Cloudflare's answer has no device id".into());
    }
    if !super::validate::is_wg_key(&d.peer_public_key) {
        return Err("Cloudflare's answer has no WireGuard peer (is the device profile set to MASQUE? see docs/WARP.md)".into());
    }
    if d.address_v4.parse::<std::net::Ipv4Addr>().is_err() {
        return Err("Cloudflare's answer has no IPv4 tunnel address".into());
    }
    if d.account_type != "team" {
        return Err(format!("Enrollment returned a '{}' account, not a Zero Trust device", d.account_type));
    }
    Ok(d)
}

/// RFC 3339 UTC timestamp for the `tos` field.
pub fn rfc3339_now() -> String {
    crate::obs::notify::rfc3339(crate::auth::now_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG: &str = include_str!("fixtures/teams_reg.json");
    const PAGE: &str = include_str!("fixtures/warp_page.html");
    const PUB: &str = "zR1v3mF9KQZtqk0kQ0hKxw3Q3d6Q2wqk1zZ3m4p5r6A=";

    #[test]
    fn parses_a_wireguard_team_registration() {
        let d = parse_registration(REG, "acme").unwrap();
        assert_eq!(d.device_id, "t.1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b");
        assert_eq!(d.account_type, "team");
        assert_eq!(d.organization, "acme");
        assert_eq!(d.address_v4, "172.16.0.7");
        assert_eq!(d.client_id, "AbCd");
        assert_eq!(d.endpoint(), ("162.159.193.5".to_string(), 2408));
        let pubj = d.public_json().to_string();
        assert!(!pubj.contains("DEVICE-API-TOKEN"), "{pubj}");
        assert!(pubj.contains("162.159.193.5:2408"));
    }

    #[test]
    fn rejects_unusable_registrations() {
        assert!(parse_registration("<html>", "acme").is_err());
        let e = parse_registration(r#"{"success":false,"errors":[{"code":1001,"message":"Invalid token"}]}"#, "acme").unwrap_err();
        assert!(e.contains("Invalid token"), "{e}");
        let consumer = REG.replace("\"team\"", "\"free\"");
        assert!(parse_registration(&consumer, "acme").unwrap_err().contains("free"));
        let masque = REG.replace("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "");
        assert!(parse_registration(&masque, "acme").unwrap_err().contains("MASQUE"));
        // hostname endpoint when the API omits v4
        let host_only = REG.replace("\"v4\": \"162.159.193.5:0\", ", "");
        assert_eq!(parse_registration(&host_only, "acme").unwrap().endpoint(), ("engage.cloudflareclient.com".into(), 2408));
    }

    #[test]
    fn secrets_only_in_the_stdin_config() {
        let body = registration_body(PUB, "mgateway1", "2026-11-18T00:00:00Z");
        assert_eq!(body["key"], PUB);
        assert_eq!(body["type"], "Linux");
        let c = registration_config("eyJ.tok.sig\"\nurl = https://evil", &body);
        assert!(c.contains("CF-Access-Jwt-Assertion: eyJ.tok.sig\\\" url = https://evil\""), "{c}");
        assert_eq!(c.lines().filter(|l| l.starts_with("url")).count(), 1, "no line injection: {c}");
        assert!(c.contains(&format!("url = \"{API_BASE}/reg\"")));
        assert!(c.contains("proto = \"=https\""));
        let r = refresh_config("t.abc", "DEVTOKEN");
        assert!(r.contains("/reg/t.abc\"") && r.contains("Authorization: Bearer DEVTOKEN"));
        assert!(delete_config("t.abc", "X").contains("request = \"DELETE\""));
        let s = service_token_config("acme", "id.access", "sec");
        assert!(s.contains("https://acme.cloudflareaccess.com/warp"));
        assert!(s.contains("CF-Access-Client-Id: id.access") && s.contains("CF-Access-Client-Secret: sec"));
    }

    #[test]
    fn success_page_token() {
        assert_eq!(
            token_from_success_page(PAGE).as_deref(),
            Some("eyJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoid2FycCJ9.c2VydmljZS10b2tlbi1zaWc")
        );
        assert!(token_from_success_page("<html>Forbidden</html>").is_none());
        assert!(token_from_success_page("com.cloudflare.warp://x/auth?token=bad token").is_none());
    }
}
