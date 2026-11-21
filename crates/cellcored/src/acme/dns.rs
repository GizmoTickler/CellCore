//! Native DNS-01 challenge solvers for CellCore's ACME client.
//!
//! Zero external shell scripts or binaries required: uses `curl` over HTTPS (for
//! REST DNS APIs) and pure-Rust UDP/TCP wire framing + HMAC-SHA256 TSIG (for
//! RFC 2136 dynamic DNS such as Knot DNS / BIND).

use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::admin::exec::{ExecOpts, run};

const API_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsProvider {
    #[default]
    Cloudflare,
    Route53,
    Digitalocean,
    Hetzner,
    Porkbun,
    Duckdns,
    Desec,
    Rfc2136,
    Webhook,
}

impl DnsProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Route53 => "route53",
            Self::Digitalocean => "digitalocean",
            Self::Hetzner => "hetzner",
            Self::Porkbun => "porkbun",
            Self::Duckdns => "duckdns",
            Self::Desec => "desec",
            Self::Rfc2136 => "rfc2136",
            Self::Webhook => "webhook",
        }
    }
}

/// Opaque handle returned by `present` so `cleanup` can delete the exact TXT record.
#[derive(Debug, Clone)]
pub struct DnsRecordHandle {
    pub provider: DnsProvider,
    pub fqdn: String,
    pub domain: String,
    pub value: String,
    pub zone_id: Option<String>,
    pub record_id: Option<String>,
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

fn curl_escape(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 2);
    out.push('"');
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn https_req(
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut cfg = format!(
        "url = {}\nrequest = {}\nsilent\nshow-error\nmax-time = {API_TIMEOUT_SECS}\nproto = \"=https\"\nwrite-out = \"\\n%{{http_code}}\"\n",
        curl_escape(url),
        curl_escape(method),
    );
    for (k, v) in headers {
        cfg.push_str(&format!("header = {}\n", curl_escape(&format!("{k}: {v}"))));
    }
    if let Some(b) = body {
        cfg.push_str(&format!("data-raw = {}\n", curl_escape(b)));
    }
    let out = run(
        "curl",
        &["-q", "-K", "-"],
        ExecOpts::new(API_TIMEOUT_SECS + 3, 256 * 1024).stdin(cfg.into_bytes()),
    )
    .await?;
    if !out.ok() {
        return Err(out.err_summary("dns-api"));
    }
    let raw = out.stdout_str();
    let (resp_body, code_str) = raw.rsplit_once('\n').unwrap_or(("", raw.trim()));
    let code: u16 = code_str.trim().parse().unwrap_or(0);
    Ok((code, resp_body.to_string()))
}

/// Candidate parent zones for a domain, longest first (e.g. `a.b.example.com` -> `["a.b.example.com", "b.example.com", "example.com"]`).
pub fn candidate_zones(domain: &str) -> Vec<String> {
    let d = domain.trim().trim_start_matches("*.").trim_end_matches('.');
    let labels: Vec<&str> = d.split('.').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    for i in 0..labels.len().saturating_sub(1) {
        out.push(labels[i..].join("."));
    }
    out
}

fn relative_subname(fqdn: &str, zone: &str) -> String {
    let f = fqdn.trim_end_matches('.');
    let z = zone.trim_end_matches('.');
    if f.eq_ignore_ascii_case(z) {
        "@".into()
    } else if let Some(prefix) = f.strip_suffix(&format!(".{z}")) {
        prefix.to_string()
    } else {
        f.to_string()
    }
}

fn require_cred<'a>(creds: &'a HashMap<String, String>, key: &str, provider: &str) -> Result<&'a str, String> {
    creds
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("DNS provider '{provider}' requires credential '{key}'"))
}

pub async fn present_txt(
    provider: DnsProvider,
    creds: &HashMap<String, String>,
    domain: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let clean_domain = domain.trim().trim_start_matches("*.").trim_end_matches('.').to_string();
    let fqdn = format!("_acme-challenge.{clean_domain}");
    match provider {
        DnsProvider::Cloudflare => cf_present(creds, &clean_domain, &fqdn, txt_value).await,
        DnsProvider::Route53 => r53_change(creds, &clean_domain, &fqdn, txt_value, "UPSERT").await,
        DnsProvider::Digitalocean => do_present(creds, &clean_domain, &fqdn, txt_value).await,
        DnsProvider::Hetzner => hetzner_present(creds, &clean_domain, &fqdn, txt_value).await,
        DnsProvider::Porkbun => porkbun_present(creds, &clean_domain, &fqdn, txt_value).await,
        DnsProvider::Duckdns => duckdns_present(creds, &clean_domain, &fqdn, txt_value).await,
        DnsProvider::Desec => desec_present(creds, &clean_domain, &fqdn, txt_value).await,
        DnsProvider::Rfc2136 => rfc2136_update(creds, &clean_domain, &fqdn, txt_value, false).await,
        DnsProvider::Webhook => webhook_call(creds, &clean_domain, &fqdn, txt_value, "present").await,
    }
}

pub async fn cleanup_txt(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    match h.provider {
        DnsProvider::Cloudflare => cf_cleanup(creds, h).await,
        DnsProvider::Route53 => r53_change(creds, &h.domain, &h.fqdn, &h.value, "DELETE").await.map(|_| ()),
        DnsProvider::Digitalocean => do_cleanup(creds, h).await,
        DnsProvider::Hetzner => hetzner_cleanup(creds, h).await,
        DnsProvider::Porkbun => porkbun_cleanup(creds, h).await,
        DnsProvider::Duckdns => duckdns_cleanup(creds, h).await,
        DnsProvider::Desec => desec_cleanup(creds, h).await,
        DnsProvider::Rfc2136 => rfc2136_update(creds, &h.domain, &h.fqdn, &h.value, true).await.map(|_| ()),
        DnsProvider::Webhook => webhook_call(creds, &h.domain, &h.fqdn, &h.value, "cleanup").await.map(|_| ()),
    }
}

// ---------------------------------------------------------------------------
// 1. Cloudflare DNS API v4
// ---------------------------------------------------------------------------

async fn cf_resolve_zone(token: &str, creds: &HashMap<String, String>, domain: &str) -> Result<String, String> {
    if let Some(zid) = creds.get("zoneId").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        return Ok(zid.to_string());
    }
    let hdrs = [("Authorization", format!("Bearer {token}"))];
    for zone in candidate_zones(domain) {
        let url = format!("https://api.cloudflare.com/client/v4/zones?name={zone}&status=active");
        let (code, body) = https_req("GET", &url, &hdrs, None).await?;
        if code == 200
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(id) = v
                .get("result")
                .and_then(|r| r.as_array())
                .and_then(|a| a.first())
                .and_then(|z| z.get("id"))
                .and_then(|x| x.as_str())
        {
            return Ok(id.to_string());
        }
    }
    Err(format!("Cloudflare: could not find active zone for {domain}"))
}

async fn cf_present(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let token = require_cred(creds, "apiToken", "cloudflare")?;
    let zone_id = cf_resolve_zone(token, creds, domain).await?;
    let payload = serde_json::json!({
        "type": "TXT",
        "name": fqdn,
        "content": txt_value,
        "ttl": 120
    })
    .to_string();
    let hdrs = [
        ("Authorization", format!("Bearer {token}")),
        ("Content-Type", "application/json".into()),
    ];
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
    let (code, body) = https_req("POST", &url, &hdrs, Some(&payload)).await?;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    if !(200..300).contains(&code) || v.get("success").and_then(|b| b.as_bool()) != Some(true) {
        return Err(format!("Cloudflare TXT create failed (HTTP {code}): {body}"));
    }
    let rec_id = v
        .get("result")
        .and_then(|r| r.get("id"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    Ok(DnsRecordHandle {
        provider: DnsProvider::Cloudflare,
        fqdn: fqdn.into(),
        domain: domain.into(),
        value: txt_value.into(),
        zone_id: Some(zone_id),
        record_id: rec_id,
    })
}

async fn cf_cleanup(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    let token = require_cred(creds, "apiToken", "cloudflare")?;
    let (Some(zone_id), Some(rec_id)) = (&h.zone_id, &h.record_id) else {
        return Ok(());
    };
    let hdrs = [("Authorization", format!("Bearer {token}"))];
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}");
    let _ = https_req("DELETE", &url, &hdrs, None).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. AWS Route 53 (pure-Rust SigV4)
// ---------------------------------------------------------------------------

fn utc_amz_timestamps() -> (String, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = now.div_euclid(86400);
    let secs = now.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    (
        format!("{y:04}{m:02}{d:02}"),
        format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
    )
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m, d)
}

#[allow(clippy::too_many_arguments)]
pub fn aws_sigv4_headers(
    access_key: &str,
    secret_key: &str,
    method: &str,
    canonical_uri: &str,
    host: &str,
    region: &str,
    service: &str,
    payload: &str,
    date_stamp: &str,
    amz_date: &str,
) -> Vec<(&'static str, String)> {
    let payload_hash = hex::encode(Sha256::digest(payload.as_bytes()));
    let canonical_headers = format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_req = format!("{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let cred_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{cred_scope}\n{}",
        hex::encode(Sha256::digest(canonical_req.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{cred_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    vec![
        ("Authorization", auth),
        ("x-amz-date", amz_date.to_string()),
        ("x-amz-content-sha256", payload_hash),
        ("Content-Type", "application/xml".into()),
    ]
}

async fn r53_change(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
    action: &str,
) -> Result<DnsRecordHandle, String> {
    let access_key = require_cred(creds, "accessKeyId", "route53")?;
    let secret_key = require_cred(creds, "secretAccessKey", "route53")?;
    let zone_id = require_cred(creds, "hostedZoneId", "route53")?
        .trim_start_matches("/hostedzone/");
    let canonical_uri = format!("/2013-04-01/hostedzone/{zone_id}/rrset/");
    let host = "route53.amazonaws.com";
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>{fqdn}.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"{txt_value}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#
    );
    let (date_stamp, amz_date) = utc_amz_timestamps();
    let hdrs = aws_sigv4_headers(
        access_key,
        secret_key,
        "POST",
        &canonical_uri,
        host,
        "us-east-1",
        "route53",
        &xml,
        &date_stamp,
        &amz_date,
    );
    let url = format!("https://{host}{canonical_uri}");
    let (code, body) = https_req("POST", &url, &hdrs, Some(&xml)).await?;
    if !(200..300).contains(&code) {
        return Err(format!("Route53 {action} failed (HTTP {code}): {body}"));
    }
    Ok(DnsRecordHandle {
        provider: DnsProvider::Route53,
        fqdn: fqdn.into(),
        domain: domain.into(),
        value: txt_value.into(),
        zone_id: Some(zone_id.into()),
        record_id: None,
    })
}

// ---------------------------------------------------------------------------
// 3. DigitalOcean DNS API v2
// ---------------------------------------------------------------------------

async fn do_present(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let token = require_cred(creds, "apiToken", "digitalocean")?;
    let hdrs = [
        ("Authorization", format!("Bearer {token}")),
        ("Content-Type", "application/json".into()),
    ];
    for zone in candidate_zones(domain) {
        let url = format!("https://api.digitalocean.com/v2/domains/{zone}/records");
        let name = relative_subname(fqdn, &zone);
        let payload = serde_json::json!({
            "type": "TXT",
            "name": name,
            "data": txt_value,
            "ttl": 60
        })
        .to_string();
        let (code, body) = https_req("POST", &url, &hdrs, Some(&payload)).await?;
        if (200..300).contains(&code) {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let rec_id = v
                .get("domain_record")
                .and_then(|r| r.get("id"))
                .and_then(|x| x.as_u64())
                .map(|n| n.to_string());
            return Ok(DnsRecordHandle {
                provider: DnsProvider::Digitalocean,
                fqdn: fqdn.into(),
                domain: domain.into(),
                value: txt_value.into(),
                zone_id: Some(zone),
                record_id: rec_id,
            });
        }
    }
    Err(format!("DigitalOcean: failed to create TXT record for {domain}"))
}

async fn do_cleanup(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    let token = require_cred(creds, "apiToken", "digitalocean")?;
    let (Some(zone), Some(rec_id)) = (&h.zone_id, &h.record_id) else {
        return Ok(());
    };
    let hdrs = [("Authorization", format!("Bearer {token}"))];
    let url = format!("https://api.digitalocean.com/v2/domains/{zone}/records/{rec_id}");
    let _ = https_req("DELETE", &url, &hdrs, None).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Hetzner DNS API
// ---------------------------------------------------------------------------

async fn hetzner_present(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let token = require_cred(creds, "apiToken", "hetzner")?;
    let hdrs = [
        ("Auth-API-Token", token.to_string()),
        ("Content-Type", "application/json".into()),
    ];
    let mut found_zone: Option<(String, String)> = None;
    for zone in candidate_zones(domain) {
        let url = format!("https://dns.hetzner.com/api/v1/zones?name={zone}");
        let (code, body) = https_req("GET", &url, &hdrs, None).await?;
        if code == 200
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(id) = v
                .get("zones")
                .and_then(|z| z.as_array())
                .and_then(|a| a.first())
                .and_then(|z| z.get("id"))
                .and_then(|x| x.as_str())
        {
            found_zone = Some((id.to_string(), zone));
            break;
        }
    }
    let (zone_id, zone_name) = found_zone.ok_or_else(|| format!("Hetzner: zone not found for {domain}"))?;
    let payload = serde_json::json!({
        "zone_id": zone_id,
        "type": "TXT",
        "name": relative_subname(fqdn, &zone_name),
        "value": txt_value,
        "ttl": 60
    })
    .to_string();
    let (code, body) = https_req("POST", "https://dns.hetzner.com/api/v1/records", &hdrs, Some(&payload)).await?;
    if !(200..300).contains(&code) {
        return Err(format!("Hetzner TXT create failed (HTTP {code}): {body}"));
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let rec_id = v
        .get("record")
        .and_then(|r| r.get("id"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    Ok(DnsRecordHandle {
        provider: DnsProvider::Hetzner,
        fqdn: fqdn.into(),
        domain: domain.into(),
        value: txt_value.into(),
        zone_id: Some(zone_id),
        record_id: rec_id,
    })
}

async fn hetzner_cleanup(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    let token = require_cred(creds, "apiToken", "hetzner")?;
    let Some(rec_id) = &h.record_id else { return Ok(()) };
    let hdrs = [("Auth-API-Token", token.to_string())];
    let url = format!("https://dns.hetzner.com/api/v1/records/{rec_id}");
    let _ = https_req("DELETE", &url, &hdrs, None).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Porkbun API v3
// ---------------------------------------------------------------------------

async fn porkbun_present(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let api_key = require_cred(creds, "apiKey", "porkbun")?;
    let secret = require_cred(creds, "secretApiKey", "porkbun")?;
    let hdrs = [("Content-Type", "application/json".into())];
    for zone in candidate_zones(domain) {
        let url = format!("https://api.porkbun.com/api/json/v3/dns/create/{zone}");
        let payload = serde_json::json!({
            "apikey": api_key,
            "secretapikey": secret,
            "name": relative_subname(fqdn, &zone),
            "type": "TXT",
            "content": txt_value,
            "ttl": "600"
        })
        .to_string();
        let (code, body) = https_req("POST", &url, &hdrs, Some(&payload)).await?;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        if code == 200 && v.get("status").and_then(|s| s.as_str()) == Some("SUCCESS") {
            let rec_id = v.get("id").and_then(|x| x.as_u64()).map(|n| n.to_string())
                .or_else(|| v.get("id").and_then(|x| x.as_str()).map(str::to_string));
            return Ok(DnsRecordHandle {
                provider: DnsProvider::Porkbun,
                fqdn: fqdn.into(),
                domain: domain.into(),
                value: txt_value.into(),
                zone_id: Some(zone),
                record_id: rec_id,
            });
        }
    }
    Err(format!("Porkbun: failed to create TXT record for {domain}"))
}

async fn porkbun_cleanup(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    let api_key = require_cred(creds, "apiKey", "porkbun")?;
    let secret = require_cred(creds, "secretApiKey", "porkbun")?;
    let (Some(zone), Some(rec_id)) = (&h.zone_id, &h.record_id) else {
        return Ok(());
    };
    let hdrs = [("Content-Type", "application/json".into())];
    let payload = serde_json::json!({ "apikey": api_key, "secretapikey": secret }).to_string();
    let url = format!("https://api.porkbun.com/api/json/v3/dns/delete/{zone}/{rec_id}");
    let _ = https_req("POST", &url, &hdrs, Some(&payload)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. DuckDNS
// ---------------------------------------------------------------------------

async fn duckdns_present(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let token = require_cred(creds, "token", "duckdns")?;
    let sub = domain.trim_end_matches(".duckdns.org");
    let url = format!("https://www.duckdns.org/update?domains={sub}&token={token}&txt={txt_value}");
    let (code, body) = https_req("GET", &url, &[], None).await?;
    if code != 200 || body.trim() != "OK" {
        return Err(format!("DuckDNS TXT update failed (HTTP {code}): {body}"));
    }
    Ok(DnsRecordHandle {
        provider: DnsProvider::Duckdns,
        fqdn: fqdn.into(),
        domain: domain.into(),
        value: txt_value.into(),
        zone_id: Some(sub.into()),
        record_id: None,
    })
}

async fn duckdns_cleanup(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    let token = require_cred(creds, "token", "duckdns")?;
    let sub = h.zone_id.as_deref().unwrap_or(h.domain.trim_end_matches(".duckdns.org"));
    let url = format!("https://www.duckdns.org/update?domains={sub}&token={token}&txt=&clear=true");
    let _ = https_req("GET", &url, &[], None).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 7. deSEC
// ---------------------------------------------------------------------------

async fn desec_present(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> Result<DnsRecordHandle, String> {
    let token = require_cred(creds, "apiToken", "desec")?;
    let hdrs = [
        ("Authorization", format!("Token {token}")),
        ("Content-Type", "application/json".into()),
    ];
    for zone in candidate_zones(domain) {
        let sub = relative_subname(fqdn, &zone);
        let url = format!("https://desec.io/api/v1/domains/{zone}/rrsets/");
        let payload = serde_json::json!({
            "subname": sub,
            "type": "TXT",
            "ttl": 3600,
            "records": [format!("\"{txt_value}\"")]
        })
        .to_string();
        let (code, body) = https_req("POST", &url, &hdrs, Some(&payload)).await?;
        if (200..300).contains(&code) {
            return Ok(DnsRecordHandle {
                provider: DnsProvider::Desec,
                fqdn: fqdn.into(),
                domain: domain.into(),
                value: txt_value.into(),
                zone_id: Some(zone),
                record_id: Some(sub),
            });
        }
        if code == 400 && body.contains("already exists") {
            let patch_url = format!("https://desec.io/api/v1/domains/{zone}/rrsets/{sub}/TXT/");
            let patch_body = serde_json::json!({ "records": [format!("\"{txt_value}\"")] }).to_string();
            let (pc, _) = https_req("PATCH", &patch_url, &hdrs, Some(&patch_body)).await?;
            if (200..300).contains(&pc) {
                return Ok(DnsRecordHandle {
                    provider: DnsProvider::Desec,
                    fqdn: fqdn.into(),
                    domain: domain.into(),
                    value: txt_value.into(),
                    zone_id: Some(zone),
                    record_id: Some(sub),
                });
            }
        }
    }
    Err(format!("deSEC: failed to set TXT record for {domain}"))
}

async fn desec_cleanup(creds: &HashMap<String, String>, h: &DnsRecordHandle) -> Result<(), String> {
    let token = require_cred(creds, "apiToken", "desec")?;
    let (Some(zone), Some(sub)) = (&h.zone_id, &h.record_id) else {
        return Ok(());
    };
    let hdrs = [("Authorization", format!("Token {token}"))];
    let url = format!("https://desec.io/api/v1/domains/{zone}/rrsets/{sub}/TXT/");
    let _ = https_req("DELETE", &url, &hdrs, None).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. RFC 2136 Dynamic DNS with HMAC-SHA256 TSIG (Knot DNS / BIND / PowerDNS)
// ---------------------------------------------------------------------------

pub fn encode_dns_name(name: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return Ok(out);
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS label in '{name}'"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

pub fn decode_base64_std(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in clean.bytes() {
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return Err("invalid base64 character".into()),
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn build_rfc2136_packet(
    tx_id: u16,
    zone: &str,
    fqdn: &str,
    txt_value: &str,
    delete: bool,
    tsig_key_name: Option<&str>,
    tsig_secret: Option<&[u8]>,
    now_secs: u64,
) -> Result<Vec<u8>, String> {
    let mut pkt = Vec::with_capacity(256);
    // Header: ID, Flags (OPCODE=5 UPDATE -> 0x2800), ZOCOUNT=1, PRCOUNT=0, UPCOUNT=1, ADCOUNT=0 (updated if TSIG)
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x2800u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());

    // Zone section: ZNAME, ZTYPE=SOA(6), ZCLASS=IN(1)
    pkt.extend_from_slice(&encode_dns_name(zone)?);
    pkt.extend_from_slice(&6u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());

    // Update section: NAME, TYPE=TXT(16)
    pkt.extend_from_slice(&encode_dns_name(fqdn)?);
    pkt.extend_from_slice(&16u16.to_be_bytes());
    if delete {
        // Delete RRset: CLASS=ANY(255), TTL=0, RDLENGTH=0
        pkt.extend_from_slice(&255u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
    } else {
        // Add TXT RR: CLASS=IN(1), TTL=60, RDATA=<len><txt>
        let tb = txt_value.as_bytes();
        if tb.len() > 255 {
            return Err("TXT value exceeds 255 bytes".into());
        }
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&60u32.to_be_bytes());
        pkt.extend_from_slice(&((tb.len() + 1) as u16).to_be_bytes());
        pkt.push(tb.len() as u8);
        pkt.extend_from_slice(tb);
    }

    if let (Some(key_name), Some(secret)) = (tsig_key_name, tsig_secret) {
        let alg_wire = encode_dns_name("hmac-sha256")?;
        let key_wire = encode_dns_name(key_name)?;
        // RFC 2845 TSIG digest input = original message (ADCOUNT=0) + TSIG variables
        let mut to_sign = pkt.clone();
        to_sign.extend_from_slice(&key_wire);
        to_sign.extend_from_slice(&255u16.to_be_bytes()); // CLASS=ANY
        to_sign.extend_from_slice(&0u32.to_be_bytes()); // TTL=0
        to_sign.extend_from_slice(&alg_wire);
        // 48-bit time signed
        let t_hi = ((now_secs >> 32) & 0xffff) as u16;
        let t_lo = (now_secs & 0xffff_ffff) as u32;
        to_sign.extend_from_slice(&t_hi.to_be_bytes());
        to_sign.extend_from_slice(&t_lo.to_be_bytes());
        to_sign.extend_from_slice(&300u16.to_be_bytes()); // fudge 300s
        to_sign.extend_from_slice(&0u16.to_be_bytes()); // error=0
        to_sign.extend_from_slice(&0u16.to_be_bytes()); // other_len=0

        let mac = hmac_sha256(secret, &to_sign);

        // Build TSIG RDATA
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&alg_wire);
        rdata.extend_from_slice(&t_hi.to_be_bytes());
        rdata.extend_from_slice(&t_lo.to_be_bytes());
        rdata.extend_from_slice(&300u16.to_be_bytes());
        rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&tx_id.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());

        // Set ADCOUNT=1 and append TSIG RR (TYPE=250, CLASS=ANY(255), TTL=0)
        pkt[10..12].copy_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&key_wire);
        pkt.extend_from_slice(&250u16.to_be_bytes());
        pkt.extend_from_slice(&255u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rdata);
    }

    Ok(pkt)
}

async fn rfc2136_update(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
    delete: bool,
) -> Result<DnsRecordHandle, String> {
    let server = require_cred(creds, "server", "rfc2136")?.to_string();
    let zone = creds
        .get("zone")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| candidate_zones(domain).last().cloned())
        .ok_or_else(|| format!("RFC 2136: unable to determine zone for {domain}"))?;
    let key_name = creds
        .get("tsigKeyName")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let key_secret = match creds.get("tsigSecret").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(b64) => Some(decode_base64_std(b64)?),
        None => None,
    };

    let mut id_bytes = [0u8; 2];
    let _ = getrandom::getrandom(&mut id_bytes);
    let tx_id = u16::from_be_bytes(id_bytes);
    let now = crate::auth::now_secs();
    let pkt = build_rfc2136_packet(
        tx_id,
        &zone,
        fqdn,
        txt_value,
        delete,
        key_name.as_deref(),
        key_secret.as_deref(),
        now,
    )?;

    let target = if server.contains(':') {
        server.clone()
    } else {
        format!("{server}:53")
    };
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let addr: SocketAddr = target
            .to_socket_addrs()
            .map_err(|e| format!("resolve RFC2136 server '{target}': {e}"))?
            .next()
            .ok_or_else(|| format!("no address for RFC2136 server '{target}'"))?;
        let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("udp bind: {e}"))?;
        sock.set_read_timeout(Some(Duration::from_secs(8))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(8))).ok();
        sock.send_to(&pkt, addr).map_err(|e| format!("udp send: {e}"))?;
        let mut resp = [0u8; 512];
        let n = sock.recv(&mut resp).map_err(|e| format!("udp recv from {target}: {e}"))?;
        if n < 12 {
            return Err("short RFC2136 DNS response".into());
        }
        let rcode = resp[3] & 0x0f;
        if rcode != 0 {
            return Err(format!("RFC2136 server returned DNS RCODE {rcode}"));
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("rfc2136 task join: {e}"))??;

    Ok(DnsRecordHandle {
        provider: DnsProvider::Rfc2136,
        fqdn: fqdn.into(),
        domain: domain.into(),
        value: txt_value.into(),
        zone_id: Some(zone),
        record_id: None,
    })
}

// ---------------------------------------------------------------------------
// 9. Generic HTTPS Webhook
// ---------------------------------------------------------------------------

async fn webhook_call(
    creds: &HashMap<String, String>,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
    action: &str,
) -> Result<DnsRecordHandle, String> {
    let url = require_cred(creds, "url", "webhook")?;
    if !url.starts_with("https://") {
        return Err("Webhook DNS URL must use https://".into());
    }
    let mut hdrs = vec![("Content-Type", "application/json".into())];
    if let Some(tok) = creds.get("bearerToken").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        hdrs.push(("Authorization", format!("Bearer {tok}")));
    }
    let payload = serde_json::json!({
        "action": action,
        "domain": domain,
        "fqdn": fqdn,
        "value": txt_value
    })
    .to_string();
    let (code, body) = https_req("POST", url, &hdrs, Some(&payload)).await?;
    if !(200..300).contains(&code) {
        return Err(format!("Webhook DNS {action} failed (HTTP {code}): {body}"));
    }
    Ok(DnsRecordHandle {
        provider: DnsProvider::Webhook,
        fqdn: fqdn.into(),
        domain: domain.into(),
        value: txt_value.into(),
        zone_id: None,
        record_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_zones_handles_wildcard_and_subdomains() {
        assert_eq!(
            candidate_zones("*.modem1.example.test"),
            vec!["modem1.example.test", "example.test"]
        );
        assert_eq!(
            relative_subname("_acme-challenge.modem1.example.test", "example.test"),
            "_acme-challenge.mgateway1"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_vector() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn aws_sigv4_produces_well_formed_auth_header() {
        let hdrs = aws_sigv4_headers(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "POST",
            "/2013-04-01/hostedzone/Z123/rrset/",
            "route53.amazonaws.com",
            "us-east-1",
            "route53",
            "<xml/>",
            "20261121",
            "20261121T120000Z",
        );
        let auth = &hdrs[0].1;
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261121/us-east-1/route53/aws4_request"));
        assert!(auth.contains("Signature="));
    }

    #[test]
    fn rfc2136_packet_with_tsig_sets_opcode_update_and_adcount() {
        let pkt = build_rfc2136_packet(
            0x1234,
            "example.test",
            "_acme-challenge.modem1.example.test",
            "test-digest-value",
            false,
            Some("acme-key."),
            Some(b"supersecretkey"),
            1_795_227_000,
        )
        .unwrap();
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
        assert_eq!(&pkt[2..4], &[0x28, 0x00]); // OPCODE=UPDATE
        assert_eq!(&pkt[10..12], &[0x00, 0x01]); // ADCOUNT=1 (TSIG)
        assert!(pkt.len() > 90);
    }
}
