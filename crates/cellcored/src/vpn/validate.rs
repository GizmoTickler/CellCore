//! Validators for every VPN input that reaches an argv slot, a UCI value, a
//! curl config line or a file. Secrets are checked for shape only and never
//! echoed back in error messages.

use std::net::Ipv4Addr;

use crate::admin::validate::{is_host_label, is_hostname, parse_ip, parse_ipv4};

/// Standard base64 of exactly 32 bytes (WireGuard public/private key): 44
/// chars, the last one `=`, and the 43rd restricted to the values that keep
/// the unused low bits zero.
pub fn is_wg_key(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 44 || b[43] != b'=' {
        return false;
    }
    let b64 = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    if !b[..43].iter().all(|&c| b64(c)) {
        return false;
    }
    // 43rd char encodes 4 meaningful bits + 2 zero bits.
    matches!(b[42], b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y' | b'c' | b'g' | b'k' | b'o' | b's' | b'w' | b'0' | b'4' | b'8')
}

/// WARP+ license key as shown in the 1.1.1.1 app: three groups of eight
/// alphanumerics separated by '-' (`xxxxxxxx-xxxxxxxx-xxxxxxxx`).
pub fn is_warp_license(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3 && parts.iter().all(|p| p.len() == 8 && p.bytes().all(|c| c.is_ascii_alphanumeric()))
}

/// Zero Trust team name (the `<team>` of `<team>.cloudflareaccess.com`).
/// Accepts the bare name or the full team domain; returns the bare name.
pub fn team_name(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches("https://").trim_end_matches('/').to_ascii_lowercase();
    let t = t.strip_suffix(".cloudflareaccess.com").unwrap_or(&t).to_string();
    (is_host_label(&t) && t.len() <= 63).then_some(t)
}

/// Service token Client ID: `<32 hex>.access`.
pub fn is_access_client_id(s: &str) -> bool {
    s.strip_suffix(".access").is_some_and(|h| h.len() == 32 && h.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Service token Client Secret: 64 hex.
pub fn is_access_client_secret(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// The enrollment token printed on `https://<team>.cloudflareaccess.com/warp`
/// after login. Accepts the full `com.cloudflare.warp://…/auth?token=X` URL
/// (Cloudflare's documented fallback format) or the bare token; returns the
/// token. JWT charset only, bounded length.
pub fn team_token(input: &str) -> Option<String> {
    let s = input.trim();
    let tok = match s.find("token=") {
        Some(i) if s.starts_with("com.cloudflare.warp://") => &s[i + 6..],
        Some(_) => return None,
        None => s,
    };
    let tok = tok.split('&').next().unwrap_or("");
    let ok = (20..=8192).contains(&tok.len()) && tok.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'));
    ok.then(|| tok.to_string())
}

/// Tailscale pre-auth key: `tskey-…`, URL-safe charset.
pub fn is_ts_authkey(s: &str) -> bool {
    s.starts_with("tskey-")
        && (20..=256).contains(&s.len())
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

/// OAuth client secrets need the `oauthkey` feature tailscale-tiny omits.
pub fn is_ts_oauth_secret(s: &str) -> bool {
    s.starts_with("tskey-client-")
}

/// Canonical IPv4 network in CIDR form (host bits zero, explicit prefix).
/// Tailscale refuses non-canonical prefixes, so they are rejected here with
/// the canonical form suggested.
pub fn canonical_v4_cidr(s: &str) -> Result<String, String> {
    let (a, p) = s.trim().split_once('/').ok_or_else(|| format!("{s} needs a /prefix (for example 192.168.1.0/24)"))?;
    let ip = parse_ipv4(a).ok_or_else(|| format!("{s} is not an IPv4 network"))?;
    if p.is_empty() || p.starts_with('+') || p.len() > 2 {
        return Err(format!("{s} has an invalid prefix"));
    }
    let n: u8 = p.parse().map_err(|_| format!("{s} has an invalid prefix"))?;
    if n > 32 {
        return Err(format!("{s} has an invalid prefix"));
    }
    if n == 0 {
        return Err("0.0.0.0/0 is not a subnet route; use \"act as exit node\" instead".into());
    }
    let net = network_of(ip, n);
    if net != ip {
        return Err(format!("{s} has host bits set; did you mean {net}/{n}?"));
    }
    Ok(format!("{net}/{n}"))
}

pub fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = u32::MAX << (32 - u32::from(prefix.min(32)));
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Exit node selector: a tailnet IP, a node name or a MagicDNS name.
pub fn is_exit_node(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && !s.starts_with('-') && (parse_ip(s).is_some() || is_hostname(s))
}

/// Tailscale hostname override: one DNS label.
pub fn is_ts_hostname(s: &str) -> bool {
    is_host_label(s) && s.len() <= 63
}

/// WARP endpoint override: `host:port` or `ipv4:port`.
pub fn endpoint(s: &str) -> Option<(String, u16)> {
    let (h, p) = s.trim().rsplit_once(':')?;
    let port = crate::admin::validate::parse_port(p)?;
    (parse_ipv4(h).is_some() || is_hostname(h)).then(|| (h.to_string(), port))
}

/// Linux interface name usable in `ip rule iif`.
pub fn is_ifname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && !s.starts_with('-') && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

    #[test]
    fn wireguard_keys() {
        assert!(is_wg_key(PUB));
        assert!(is_wg_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        assert!(!is_wg_key(&PUB[..43]), "short");
        assert!(!is_wg_key(&format!("{}A", &PUB[..43])), "no padding");
        assert!(!is_wg_key("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyB="), "non-zero tail bits");
        assert!(!is_wg_key("bmXOC-F1FxEMF9dyiK2H5_1SUtzH0JuVo51h2wPfgyo="), "url-safe alphabet");
        assert!(!is_wg_key("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgy'="));
        assert!(!is_wg_key(""));
    }

    #[test]
    fn warp_license_keys() {
        assert!(is_warp_license("a1B2c3D4-e5F6g7H8-i9J0k1L2"));
        assert!(!is_warp_license("a1B2c3D4-e5F6g7H8"));
        assert!(!is_warp_license("a1B2c3D4-e5F6g7H8-i9J0k1L"));
        assert!(!is_warp_license("a1B2c3D4-e5F6g7H8-i9J0k1L2-"));
        assert!(!is_warp_license("a1B2c3D4_e5F6g7H8_i9J0k1L2"));
        assert!(!is_warp_license("a1B2c3D4-e5F6g7H8-i9J0k1L'"));
        assert!(!is_warp_license(PUB), "a WireGuard key is not a license");
    }

    #[test]
    fn zero_trust_inputs() {
        assert_eq!(team_name("acme").as_deref(), Some("acme"));
        assert_eq!(team_name("https://Acme.cloudflareaccess.com/").as_deref(), Some("acme"));
        assert_eq!(team_name("acme-corp.cloudflareaccess.com").as_deref(), Some("acme-corp"));
        for bad in ["", "-x", "a.b", "a b", "acme;reboot", "acme.example.com"] {
            assert!(team_name(bad).is_none(), "{bad:?}");
        }
        assert!(is_access_client_id("0123456789abcdef0123456789abcdef.access"));
        assert!(!is_access_client_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_access_client_id("0123456789abcdef0123456789abcdeg.access"));
        assert!(is_access_client_secret(&"ab12".repeat(16)));
        assert!(!is_access_client_secret(&"ab12".repeat(15)));
        assert!(!is_access_client_secret(&format!("{}z", "a".repeat(63))));
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXZhbHVl";
        assert_eq!(team_token(jwt).as_deref(), Some(jwt));
        let url = format!("com.cloudflare.warp://acme.cloudflareaccess.com/auth?token={jwt}");
        assert_eq!(team_token(&url).as_deref(), Some(jwt));
        assert!(team_token("https://evil.example/?token=abcdefghijklmnopqrstuvwxyz").is_none());
        assert!(team_token("short").is_none());
        assert!(team_token(&format!("{jwt}\"; rm -rf /")).is_none());
        assert!(team_token(&format!("{jwt}\nheader = x")).is_none(), "no curl config injection");
    }

    #[test]
    fn tailscale_inputs() {
        assert!(is_ts_authkey("tskey-auth-kAbCdEf1CNTRL-0123456789abcdefABCDEF"));
        assert!(!is_ts_authkey("tskey-"));
        assert!(!is_ts_authkey("auth-kAbCdEf1CNTRL-0123456789abcdef"));
        assert!(!is_ts_authkey("tskey-auth-abc def ghi jkl mno"));
        assert!(is_ts_oauth_secret("tskey-client-k123-abc"));
        assert!(is_ts_hostname("mgateway1"));
        assert!(!is_ts_hostname("m.gateway"));
        assert!(!is_ts_hostname("-x"));
        assert!(is_exit_node("100.64.0.7"));
        assert!(is_exit_node("fd7a:115c:a1e0::7"));
        assert!(is_exit_node("nas01"));
        assert!(is_exit_node("nas01.tail1234.ts.net"));
        assert!(!is_exit_node("--exit-node-allow-lan-access"));
        assert!(!is_exit_node("a b"));
    }

    #[test]
    fn cidrs_are_canonical() {
        assert_eq!(canonical_v4_cidr("192.168.224.0/22").unwrap(), "192.168.224.0/22");
        assert_eq!(canonical_v4_cidr(" 10.0.0.0/8 ").unwrap(), "10.0.0.0/8");
        let e = canonical_v4_cidr("192.168.224.1/22").unwrap_err();
        assert!(e.contains("192.168.224.0/22"), "{e}");
        assert!(canonical_v4_cidr("192.168.224.0").is_err());
        assert!(canonical_v4_cidr("192.168.224.0/33").is_err());
        assert!(canonical_v4_cidr("192.168.224.0/+2").is_err());
        assert!(canonical_v4_cidr("0.0.0.0/0").is_err());
        assert!(canonical_v4_cidr("010.0.0.0/8").is_err());
        assert!(canonical_v4_cidr("2001:db8::/32").is_err());
        assert_eq!(network_of("192.168.227.200".parse().unwrap(), 22), "192.168.224.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn endpoints_and_ifnames() {
        assert_eq!(endpoint("engage.cloudflareclient.com:2408"), Some(("engage.cloudflareclient.com".into(), 2408)));
        assert_eq!(endpoint("162.159.192.1:500"), Some(("162.159.192.1".into(), 500)));
        assert!(endpoint("162.159.192.1").is_none());
        assert!(endpoint("x:0").is_none());
        assert!(endpoint("-x:1").is_none());
        assert!(is_ifname("br-lan"));
        assert!(!is_ifname("br lan"));
        assert!(!is_ifname("averyveryverylongif"));
    }
}
