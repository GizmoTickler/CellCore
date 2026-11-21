//! Observability settings (`/etc/cellcore/observability.json`, 0600: it
//! holds sink credentials) and the validators for every user-supplied URL
//! and header. Secrets are write-only: [`ObsConfig::public_view`] never
//! returns them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::events::EventKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct FailoverConfig {
    /// Infer "carrying traffic" from rmnet throughput when no fresh hint.
    pub throughput_detect: bool,
    /// Average rx+tx (bit/s) that counts as production traffic.
    pub baseline_bps: u64,
    /// The average must stay at or above the baseline this long to go active.
    pub sustain_secs: u64,
    /// ... and below half the baseline this long to go back to standby.
    pub release_secs: u64,
    /// A `r10-modem-ctl role` hint wins for this long after it was sent.
    pub hint_ttl_secs: u64,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            throughput_detect: true,
            baseline_bps: 2_000_000,
            sustain_secs: 60,
            release_secs: 300,
            hint_ttl_secs: 180,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct UsageAlertConfig {
    /// Raise events at 50/80/95/100 % of the quota.
    pub thresholds_enabled: bool,
    /// Bytes per local day while not in failover above which a "standby
    /// leak" is raised; 0 disables.
    pub standby_floor_bytes: u64,
}

impl Default for UsageAlertConfig {
    fn default() -> Self {
        Self {
            thresholds_enabled: true,
            standby_floor_bytes: 200 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct QuietHours {
    pub enabled: bool,
    pub start: String,
    pub end: String,
    /// Critical events still go out during quiet hours.
    pub allow_critical: bool,
}

impl Default for QuietHours {
    fn default() -> Self {
        Self {
            enabled: false,
            start: "22:00".into(),
            end: "07:00".into(),
            allow_critical: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct EmailSink {
    /// Uses `/etc/msmtprc` and the recipient set under Maintenance › Alerts.
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    #[default]
    Json,
    Alertmanager,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct WebhookSink {
    pub enabled: bool,
    pub url: String,
    pub format: WebhookFormat,
    /// Values are secrets (e.g. an Authorization header).
    pub headers: Vec<Header>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct NtfySink {
    pub enabled: bool,
    /// Full topic URL, e.g. https://ntfy.sh/my-topic
    pub url: String,
    /// Optional access token (secret).
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SmsForward {
    pub enabled: bool,
    pub interval_secs: u64,
}

impl Default for SmsForward {
    fn default() -> Self {
        Self { enabled: false, interval_secs: 300 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct NotifyConfig {
    pub enabled: bool,
    /// Per event type; a type missing here uses [`EventKind::notify_default`].
    pub kinds: BTreeMap<String, bool>,
    /// The same event (type + title) is sent at most once per window.
    pub dedupe_secs: u64,
    /// At most this many notifications per rolling hour.
    pub rate_per_hour: u32,
    pub quiet: QuietHours,
    pub email: EmailSink,
    pub webhook: WebhookSink,
    pub ntfy: NtfySink,
    pub sms_forward: SmsForward,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kinds: BTreeMap::new(),
            dedupe_secs: 900,
            rate_per_hour: 12,
            quiet: QuietHours::default(),
            email: EmailSink::default(),
            webhook: WebhookSink::default(),
            ntfy: NtfySink::default(),
            sms_forward: SmsForward::default(),
        }
    }
}

impl NotifyConfig {
    pub fn kind_enabled(&self, kind: EventKind) -> bool {
        self.kinds.get(kind.as_str()).copied().unwrap_or_else(|| kind.notify_default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ObsConfig {
    pub failover: FailoverConfig,
    pub usage: UsageAlertConfig,
    pub notify: NotifyConfig,
}

impl ObsConfig {
    /// What the API returns: secrets replaced by "is set" flags.
    pub fn public_view(&self) -> serde_json::Value {
        let n = &self.notify;
        let kinds: BTreeMap<&str, bool> = EventKind::ALL.iter().map(|k| (k.as_str(), n.kind_enabled(*k))).collect();
        serde_json::json!({
            "failover": self.failover,
            "usage": self.usage,
            "notify": {
                "enabled": n.enabled,
                "kinds": kinds,
                "dedupeSecs": n.dedupe_secs,
                "ratePerHour": n.rate_per_hour,
                "quiet": n.quiet,
                "email": n.email,
                "webhook": {
                    "enabled": n.webhook.enabled,
                    "url": n.webhook.url,
                    "format": n.webhook.format,
                    "headers": n.webhook.headers.iter().map(|h| serde_json::json!({
                        "name": h.name,
                        "valueSet": !h.value.is_empty(),
                    })).collect::<Vec<_>>(),
                },
                "ntfy": {
                    "enabled": n.ntfy.enabled,
                    "url": n.ntfy.url,
                    "tokenSet": !n.ntfy.token.is_empty(),
                },
                "smsForward": n.sms_forward,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

pub const MAX_URL_LEN: usize = 512;
pub const MAX_HEADERS: usize = 8;
pub const MAX_HEADER_VALUE_LEN: usize = 1024;
pub const MAX_TOKEN_LEN: usize = 512;

/// Headers the sink sets itself or that would change request framing.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "expect",
    "te",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
];

/// An http(s) URL with a plain host (DNS name or IP literal), optional port
/// and a conservative path/query character set. No userinfo, no fragment,
/// no whitespace, quotes, backslashes or control characters: the value ends
/// up in a curl config line and must not be able to escape its quotes.
pub fn validate_url(raw: &str) -> Result<String, String> {
    let url = raw.trim();
    if url.is_empty() {
        return Err("URL is required".into());
    }
    if url.len() > MAX_URL_LEN {
        return Err(format!("URL is longer than {MAX_URL_LEN} characters"));
    }
    let (scheme, rest) = url.split_once("://").ok_or("URL must start with http:// or https://")?;
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return Err("Only http:// and https:// URLs are allowed".into());
    }
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("URL has no host".into());
    }
    if authority.contains('@') {
        return Err("Credentials in the URL are not allowed; use a header or token".into());
    }
    let (host, port) = split_host_port(authority)?;
    let host_ok = if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        v6.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        crate::admin::validate::parse_ipv4(host).is_some() || crate::admin::validate::is_hostname(host)
    };
    if !host_ok {
        return Err("URL host is not a valid host name or IP address".into());
    }
    if let Some(p) = port
        && !(!p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n)))
    {
        return Err("URL port must be 1-65535".into());
    }
    let path_ok = path.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b"-._~/%!$&'()*+,;=:@?".contains(&b)
    });
    if !path_ok {
        return Err("URL path contains characters that are not allowed".into());
    }
    Ok(format!("{}://{authority}{path}", scheme.to_ascii_lowercase()))
}

fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), String> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or("Unclosed IPv6 literal in URL")?;
        let host = &authority[..=end];
        let rest = &authority[end + 1..];
        return match rest.strip_prefix(':') {
            Some(p) => Ok((host, Some(p))),
            None if rest.is_empty() => Ok((host, None)),
            None => Err("Malformed URL authority".into()),
        };
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((h, Some(p))),
        None => Ok((authority, None)),
    }
}

/// RFC 7230 token, limited to [A-Za-z0-9-] for sanity; reserved names refused.
pub fn validate_header_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 64 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || n.starts_with('-') {
        return Err(format!("Invalid header name {n:?}"));
    }
    if RESERVED_HEADERS.contains(&n.to_ascii_lowercase().as_str()) {
        return Err(format!("Header {n} is set by CellCore and cannot be overridden"));
    }
    Ok(n.to_string())
}

/// Printable ASCII only: no CR/LF (header injection), quotes or backslashes
/// (curl config quoting).
pub fn validate_header_value(value: &str) -> Result<String, String> {
    if value.len() > MAX_HEADER_VALUE_LEN {
        return Err("Header value is too long".into());
    }
    if !value.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\') {
        return Err("Header values may only contain printable ASCII without quotes or backslashes".into());
    }
    Ok(value.trim().to_string())
}

pub fn validate_token(token: &str) -> Result<String, String> {
    let t = token.trim();
    if t.len() > MAX_TOKEN_LEN || !t.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\') {
        return Err("Token may only contain printable ASCII without spaces, quotes or backslashes".into());
    }
    Ok(t.to_string())
}

pub fn validate_hhmm(s: &str) -> Result<String, String> {
    crate::profiles::parse_hhmm(s)
        .map(|m| format!("{:02}:{:02}", m / 60, m % 60))
        .ok_or_else(|| format!("Invalid time {s:?}; use HH:MM"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_urls() {
        for (u, want) in [
            ("https://ntfy.sh/my-topic", "https://ntfy.sh/my-topic"),
            ("HTTPS://ntfy.sh/a_b", "https://ntfy.sh/a_b"),
            ("http://192.168.120.10:9093/api/v2/alerts", "http://192.168.120.10:9093/api/v2/alerts"),
            ("https://hooks.example.com/x?token=abc&b=1", "https://hooks.example.com/x?token=abc&b=1"),
            ("https://[fd00::1]:8443/hook", "https://[fd00::1]:8443/hook"),
            ("http://alertmanager.local", "http://alertmanager.local"),
            ("  https://ntfy.sh/t  ", "https://ntfy.sh/t"),
        ] {
            assert_eq!(validate_url(u).as_deref(), Ok(want), "{u}");
        }
    }

    #[test]
    fn rejects_dangerous_urls() {
        for u in [
            "",
            "ftp://x/y",
            "file:///etc/shadow",
            "gopher://h/",
            "https://",
            "https://user:pw@host/",
            "https://host/a b",
            "https://host/\"x",
            "https://host/a\\b",
            "https://host/a\nb",
            "https://host/a\r\nHost: evil",
            "https://host:0/",
            "https://host:70000/",
            "https://host:abc/",
            "https://-host/",
            "https://ho_st/",
            "https://[zz::1]/",
            "https://host/#frag",
            "https://host/`id`",
            "https://host/$(reboot)<",
            "//host/x",
        ] {
            assert!(validate_url(u).is_err(), "accepted {u:?}");
        }
        assert!(validate_url(&format!("https://h/{}", "a".repeat(600))).is_err());
    }

    #[test]
    fn header_validation() {
        assert_eq!(validate_header_name("Authorization").as_deref(), Ok("Authorization"));
        assert_eq!(validate_header_name("X-Api-Key").as_deref(), Ok("X-Api-Key"));
        for bad in ["", "Bad Name", "X:Y", "Host", "content-length", "Content-Type", "-x", "a\nb", &"x".repeat(65)] {
            assert!(validate_header_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_header_value("Bearer abc.def").is_ok());
        for bad in ["a\r\nX-Evil: 1", "quote\"", "back\\slash", "tab\tvalue", "é"] {
            assert!(validate_header_value(bad).is_err(), "{bad:?}");
        }
        assert!(validate_token("tk_abcDEF123").is_ok());
        assert!(validate_token("has space").is_err());
        assert!(validate_token("q\"").is_err());
    }

    #[test]
    fn public_view_never_contains_secrets() {
        let mut c = ObsConfig::default();
        c.notify.ntfy.token = "SECRET-TOKEN".into();
        c.notify.webhook.headers.push(Header { name: "Authorization".into(), value: "Bearer SECRET-H".into() });
        let text = c.public_view().to_string();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(text.contains("\"tokenSet\":true"));
        assert!(text.contains("\"valueSet\":true"));
    }

    #[test]
    fn hhmm() {
        assert_eq!(validate_hhmm("7:05").as_deref(), Ok("07:05"));
        assert!(validate_hhmm("24:00").is_err());
    }
}
