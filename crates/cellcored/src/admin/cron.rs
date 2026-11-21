//! Scheduled tasks › root crontab editor (busybox crond syntax).
//!
//! Saved through `crontab -` (stdin, no shell), then `/etc/init.d/cron reload`,
//! exactly as LuCI does.

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    audit, exec::{ExecOpts, KIB, run, run_ok}, mutate_lock, ok, server,
    services::service_state,
};
use crate::http::HttpCtx;

const CRONTAB_PATH: &str = "/etc/crontabs/root";
const MAX_BYTES: usize = 32 * 1024;
const MAX_LINE: usize = 1000;
const MAX_JOBS: usize = 100;

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
/// Environment assignments busybox crond understands.
const ENV_VARS: [&str; 4] = ["SHELL", "PATH", "HOME", "MAILTO"];

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CronLine {
    pub line: usize,
    /// blank | comment | env | job | invalid
    pub kind: &'static str,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub error: Option<String>,
}

fn field_value(tok: &str, min: u32, max: u32, names: Option<&[&str]>) -> Result<u32, String> {
    if let Some(names) = names
        && let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(tok))
    {
        // Month names are 1-based, day names 0-based.
        return Ok(i as u32 + min);
    }
    if tok.is_empty() || tok.len() > 2 || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{tok:?} is not a number"));
    }
    let v: u32 = tok.parse().map_err(|_| format!("{tok:?} is not a number"))?;
    if v < min || v > max {
        return Err(format!("{v} is outside {min}–{max}"));
    }
    Ok(v)
}

/// Validate one schedule field: `*`, `*/n`, `a`, `a-b`, `a-b/n`, comma lists.
pub fn validate_field(field: &str, min: u32, max: u32, names: Option<&[&str]>) -> Result<(), String> {
    if field.is_empty() {
        return Err("empty field".into());
    }
    for item in field.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((r, s)) => (r, Some(s)),
            None => (item, None),
        };
        if let Some(s) = step {
            let n = field_value(s, 1, max.max(1), None).map_err(|e| format!("step {e}"))?;
            if n == 0 {
                return Err("step must be ≥ 1".into());
            }
        }
        if range == "*" {
            continue;
        }
        match range.split_once('-') {
            Some((a, b)) => {
                let a = field_value(a, min, max, names)?;
                let b = field_value(b, min, max, names)?;
                if a > b {
                    return Err(format!("range {a}-{b} is reversed"));
                }
            }
            None => {
                field_value(range, min, max, names)?;
                if step.is_some() {
                    return Err("a step needs * or a range".into());
                }
            }
        }
    }
    Ok(())
}

pub fn parse_cron_line(raw: &str, n: usize) -> CronLine {
    let mut cl = CronLine { line: n, kind: "blank", schedule: None, command: None, error: None };
    let line = raw.trim();
    if line.is_empty() {
        return cl;
    }
    if line.starts_with('#') {
        cl.kind = "comment";
        return cl;
    }
    let invalid = |mut cl: CronLine, e: String| {
        cl.kind = "invalid";
        cl.error = Some(e);
        cl
    };
    if raw.len() > MAX_LINE {
        return invalid(cl, format!("line is longer than {MAX_LINE} characters"));
    }
    if raw.chars().any(|c| c.is_control() && c != '\t') {
        return invalid(cl, "control characters are not allowed".into());
    }
    if let Some((name, _)) = line.split_once('=')
        && !name.contains(char::is_whitespace)
        && name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    {
        if ENV_VARS.contains(&name) {
            cl.kind = "env";
            return cl;
        }
        return invalid(cl, format!("busybox crond only supports {} assignments", ENV_VARS.join(", ")));
    }
    if line.starts_with('@') {
        return invalid(cl, "@reboot/@daily shortcuts are not supported by this crond; use the five-field form".into());
    }
    let mut fields = Vec::with_capacity(5);
    let mut rest = line;
    for _ in 0..5 {
        let r = rest.trim_start();
        let end = r.find(char::is_whitespace).unwrap_or(r.len());
        if end == 0 {
            break;
        }
        fields.push(&r[..end]);
        rest = &r[end..];
    }
    let command = rest.trim();
    if fields.len() < 5 || command.is_empty() {
        return invalid(cl, "expected: minute hour day month weekday command".into());
    }
    let checks: [(&str, u32, u32, Option<&[&str]>); 5] = [
        ("minute", 0, 59, None),
        ("hour", 0, 23, None),
        ("day of month", 1, 31, None),
        ("month", 1, 12, Some(&MONTHS)),
        ("day of week", 0, 7, Some(&DAYS)),
    ];
    for (f, (label, min, max, names)) in fields.iter().zip(checks) {
        if let Err(e) = validate_field(f, min, max, names) {
            return invalid(cl, format!("{label}: {e}"));
        }
    }
    cl.kind = "job";
    cl.schedule = Some(fields.join(" "));
    cl.command = Some(command.to_string());
    cl
}

pub fn validate_crontab(text: &str) -> Result<Vec<CronLine>, Vec<CronLine>> {
    let lines: Vec<CronLine> = text.lines().enumerate().map(|(i, l)| parse_cron_line(l, i + 1)).collect();
    let mut bad: Vec<CronLine> = lines.iter().filter(|l| l.kind == "invalid").cloned().collect();
    if text.len() > MAX_BYTES {
        bad.insert(0, CronLine { line: 0, kind: "invalid", schedule: None, command: None, error: Some(format!("crontab is larger than {} KiB", MAX_BYTES / 1024)) });
    }
    if lines.iter().filter(|l| l.kind == "job").count() > MAX_JOBS {
        bad.insert(0, CronLine { line: 0, kind: "invalid", schedule: None, command: None, error: Some(format!("more than {MAX_JOBS} jobs")) });
    }
    if bad.is_empty() { Ok(lines) } else { Err(bad) }
}

pub async fn get_cron() -> Response {
    let content = std::fs::read(CRONTAB_PATH)
        .map(|b| String::from_utf8_lossy(&b[..b.len().min(MAX_BYTES * 2)]).into_owned())
        .unwrap_or_default();
    let lines: Vec<CronLine> = content.lines().enumerate().map(|(i, l)| parse_cron_line(l, i + 1)).collect();
    let svc = service_state("cron").await;
    ok(serde_json::json!({
        "content": content,
        "lines": lines,
        "cronRunning": svc.running,
        "cronEnabled": std::path::Path::new("/etc/rc.d").read_dir().map(|rd| rd.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with('S') && n.ends_with("cron") && n.len() == "S00cron".len()
        })).unwrap_or(false),
    }))
}

#[derive(Deserialize)]
pub struct CronReq {
    content: String,
}

fn invalid_resp(bad: Vec<CronLine>) -> Response {
    let first = bad.first().and_then(|l| l.error.clone()).unwrap_or_default();
    let line = bad.first().map(|l| l.line).unwrap_or(0);
    let msg = if line > 0 { format!("Line {line}: {first}") } else { first };
    (
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "status": "error", "error": msg, "lines": bad })),
    )
        .into_response()
}

pub async fn post_validate(Json(req): Json<CronReq>) -> Response {
    match validate_crontab(&req.content) {
        Ok(lines) => ok(serde_json::json!({ "valid": true, "lines": lines })),
        Err(bad) => ok(serde_json::json!({ "valid": false, "lines": bad })),
    }
}

pub async fn put_cron(State(ctx): State<HttpCtx>, Json(req): Json<CronReq>) -> Response {
    let lines = match validate_crontab(&req.content) {
        Ok(l) => l,
        Err(bad) => return invalid_resp(bad),
    };
    let mut content = req.content.replace("\r\n", "\n");
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    let _g = mutate_lock().await;
    let out = match run("crontab", &["-"], ExecOpts::new(10, 16 * KIB).stdin(content.into_bytes())).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    if !out.ok() {
        return server(out.err_summary("crontab"));
    }
    let reload = run_ok("/etc/init.d/cron", &["reload"], 15, 16 * KIB).await.err();
    let jobs = lines.iter().filter(|l| l.kind == "job").count();
    audit(&ctx, format!("crontab saved ({jobs} jobs)"));
    ok(serde_json::json!({ "status": "ok", "jobs": jobs, "note": reload }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_lines() {
        for l in [
            "*/5 * * * * /usr/bin/check.sh",
            "0 4 * * 1-5 /sbin/reboot",
            "30 2 1,15 * * logger hi there",
            "0 0 * jan,jul sun echo x",
            "0-30/10 8-18 * * mon-fri echo y > /tmp/x 2>&1",
            "0 3 * * 7 echo sunday",
            "\t15\t*\t*\t*\t*\tdate",
        ] {
            let c = parse_cron_line(l, 1);
            assert_eq!(c.kind, "job", "{l}: {:?}", c.error);
        }
        let c = parse_cron_line("*/5 * * * * /usr/bin/check.sh --flag", 3);
        assert_eq!(c.schedule.as_deref(), Some("*/5 * * * *"));
        assert_eq!(c.command.as_deref(), Some("/usr/bin/check.sh --flag"));
        assert_eq!(parse_cron_line("# note", 1).kind, "comment");
        assert_eq!(parse_cron_line("   ", 1).kind, "blank");
        assert_eq!(parse_cron_line("PATH=/usr/sbin:/usr/bin", 1).kind, "env");
    }

    #[test]
    fn rejects_invalid_lines() {
        for l in [
            "60 * * * * x",
            "* 24 * * * x",
            "* * 0 * * x",
            "* * * 13 * x",
            "* * * * 8 x",
            "* * * * *",
            "5-1 * * * * x",
            "*/0 * * * * x",
            "5/2 * * * * x",
            "@reboot /bin/x",
            "FOO=bar",
            "a b c d e f",
            "1,,2 * * * * x",
            "* * * foo * x",
        ] {
            assert_eq!(parse_cron_line(l, 1).kind, "invalid", "{l} should be invalid");
        }
        assert_eq!(parse_cron_line(&format!("* * * * * {}", "x".repeat(1200)), 1).kind, "invalid");
    }

    #[test]
    fn validates_whole_crontab() {
        assert!(validate_crontab("").is_ok());
        assert!(validate_crontab("# c\n0 4 * * * /sbin/reboot\n").is_ok());
        let err = validate_crontab("0 4 * * * ok\n99 * * * * bad\n").unwrap_err();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].line, 2);
        let many: String = (0..101).map(|_| "* * * * * x\n").collect();
        assert!(validate_crontab(&many).is_err());
    }
}
