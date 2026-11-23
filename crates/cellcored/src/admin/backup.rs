//! Backup › download the standard OpenWrt config backup (`sysupgrade -b -`) and
//! restore one (`sysupgrade -r -`). Archives are inspected first: only relative
//! paths under etc/ are accepted. No firmware flashing.

use std::{sync::OnceLock, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, MutexGuard};

use super::{
    audit, bad, exec::{ExecOpts, ExecOut, MIB, run, run_ok}, mutate_lock, ok, require_confirm, server,
};
use crate::http::HttpCtx;

pub const MAX_ARCHIVE: usize = 32 * MIB;
pub const MAX_ARCHIVE_ENTRIES: usize = 5000;
pub const BACKUP_SCOPE: &str = "sysupgrade (/etc config files listed by sysupgrade -l; runtime state outside /etc is excluded)";

static SYSUPGRADE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

async fn sysupgrade_lock() -> MutexGuard<'static, ()> {
    SYSUPGRADE_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Owner-maintained files that a restore would overwrite; surfaced as warnings.
const SENSITIVE: &[&str] = &["etc/shadow", "etc/passwd", "etc/dropbear/", "etc/nftables.d/", "etc/firewall.user", "etc/config/qcmap", "etc/config/network", "etc/config/firewall"];

pub fn is_gzip(b: &[u8]) -> bool {
    b.len() > 18 && b[0] == 0x1f && b[1] == 0x8b
}

pub fn sha256_hex(b: &[u8]) -> String {
    let digest = Sha256::digest(b);
    hex::encode(digest)
}

fn validate_archive_path(raw: &str) -> Result<String, String> {
    let e = raw.trim();
    if e.is_empty() {
        return Err("empty path in archive".into());
    }
    if e.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        return Err(format!("control character in archive path: {e:?}"));
    }
    let mut p = e;
    while let Some(stripped) = p.strip_prefix("./") {
        p = stripped;
    }
    if p.starts_with('/') {
        return Err(format!("absolute path in archive: {e}"));
    }
    if p.split('/').any(|c| c == "..") {
        return Err(format!("path traversal in archive: {e}"));
    }
    if !(p == "etc" || p == "etc/" || p.starts_with("etc/")) {
        return Err(format!("unexpected path outside etc/: {e}"));
    }
    Ok(p.to_string())
}

/// Verify that a symlink or hardlink target resolves strictly inside `/etc`
/// without ever escaping `/etc` via `..` traversal.
fn validate_link_target(entry_path: &str, target: &str, is_hardlink: bool) -> Result<(), String> {
    let t = target.trim();
    if t.is_empty() {
        return Err(format!("empty link target for archive entry: {entry_path}"));
    }
    if t.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        return Err(format!("control character in link target for {entry_path}"));
    }

    let mut stack: Vec<&str> = Vec::new();
    let started_inside_etc = if t.starts_with('/') || is_hardlink {
        false
    } else {
        // Symlink target is relative to the parent directory of `entry_path`.
        let trimmed = entry_path.trim_end_matches('/');
        let comps: Vec<&str> = trimmed.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() > 1 {
            stack.extend_from_slice(&comps[..comps.len() - 1]);
        }
        stack.first().copied() == Some("etc")
    };

    let mut clean = t;
    if is_hardlink {
        while let Some(stripped) = clean.strip_prefix("./") {
            clean = stripped;
        }
        if clean.starts_with('/') {
            return Err(format!("absolute hardlink target in archive: {entry_path} -> {t}"));
        }
    }

    for comp in clean.split('/') {
        match comp {
            "" | "." => continue,
            ".." => {
                if is_hardlink {
                    return Err(format!("hardlink traversal in archive: {entry_path} -> {t}"));
                }
                if stack.pop().is_none() {
                    return Err(format!("link target escapes root: {entry_path} -> {t}"));
                }
                if started_inside_etc && stack.first().copied() != Some("etc") {
                    return Err(format!("link target escapes etc/: {entry_path} -> {t}"));
                }
            }
            seg => {
                stack.push(seg);
            }
        }
    }

    if stack.first().copied() != Some("etc") {
        return Err(format!("link target points outside etc/: {entry_path} -> {t}"));
    }
    Ok(())
}

/// Validate plain `tar -tz` output: every entry must be a relative path under
/// `etc/` with no `..` component, capped at [`MAX_ARCHIVE_ENTRIES`].
#[cfg(test)]
pub fn check_entries(listing: &str) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    for raw in listing.lines() {
        let e = raw.trim();
        if e.is_empty() {
            continue;
        }
        if v.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(format!("archive exceeds maximum of {MAX_ARCHIVE_ENTRIES} entries"));
        }
        v.push(validate_archive_path(e)?);
    }
    if v.is_empty() {
        return Err("archive is empty".into());
    }
    Ok(v)
}

/// Parse one line of `tar -tvzf` output (GNU tar or BusyBox tar) into
/// `(file_type_char, entry_and_link_tail)`. Rejects special files (device nodes,
/// FIFOs, sockets) and malformed metadata lines fail-closed.
fn parse_tar_verbose_line(line: &str) -> Result<(char, &str), String> {
    let trimmed = line.trim_end_matches('\r');
    let first_ws = trimmed
        .find([' ', '\t'])
        .ok_or_else(|| format!("malformed tar listing line: {trimmed}"))?;
    let mode = &trimmed[..first_ws];
    let ftype = mode
        .chars()
        .next()
        .ok_or_else(|| format!("missing mode in tar listing line: {trimmed}"))?;
    if mode.len() < 10 {
        return Err(format!("invalid tar mode field '{mode}' in listing: {trimmed}"));
    }
    if matches!(ftype, 'b' | 'c' | 'p' | 's' | 'D') {
        return Err(format!("disallowed special file type '{ftype}' in archive: {trimmed}"));
    }
    if !matches!(ftype, '-' | 'd' | 'l' | 'h') {
        return Err(format!("unsupported tar entry type '{ftype}' in archive: {trimmed}"));
    }

    // Consume 5 whitespace-separated fields: mode, owner/group, size, YYYY-MM-DD, HH:MM[:SS].
    let mut rest = trimmed;
    let mut fields = [""; 5];
    for slot in &mut fields {
        rest = rest.trim_start_matches([' ', '\t']);
        let end = rest
            .find([' ', '\t'])
            .ok_or_else(|| format!("malformed tar listing line: {trimmed}"))?;
        *slot = &rest[..end];
        rest = &rest[end..];
    }
    let date = fields[3];
    let time = fields[4];
    if date.len() != 10
        || date.as_bytes()[4] != b'-'
        || date.as_bytes()[7] != b'-'
        || !time.contains(':')
    {
        return Err(format!("unexpected tar metadata format in listing: {trimmed}"));
    }
    let name_part = rest.trim_start_matches([' ', '\t']);
    if name_part.is_empty() {
        return Err(format!("missing archive path in tar listing: {trimmed}"));
    }
    Ok((ftype, name_part))
}

/// Validate `tar -tvzf` verbose output: enforces [`MAX_ARCHIVE_ENTRIES`],
/// rejects device nodes/FIFOs/sockets, validates every path under `etc/`, and
/// ensures symlinks/hardlinks resolve strictly inside `/etc`.
pub fn check_verbose_entries(listing: &str) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    for raw in listing.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        if v.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(format!("archive exceeds maximum of {MAX_ARCHIVE_ENTRIES} entries"));
        }
        let (ftype, tail) = parse_tar_verbose_line(raw)?;
        let norm = match ftype {
            '-' | 'd' => validate_archive_path(tail)?,
            'l' => {
                let (name, target) = tail
                    .split_once(" -> ")
                    .ok_or_else(|| format!("malformed symlink entry in archive: {tail}"))?;
                if target.contains(" -> ") {
                    return Err(format!("ambiguous symlink entry in archive: {tail}"));
                }
                let p = validate_archive_path(name)?;
                validate_link_target(&p, target, false)?;
                p
            }
            'h' => {
                let (name, target) = tail
                    .split_once(" link to ")
                    .ok_or_else(|| format!("malformed hardlink entry in archive: {tail}"))?;
                if target.contains(" link to ") {
                    return Err(format!("ambiguous hardlink entry in archive: {tail}"));
                }
                let p = validate_archive_path(name)?;
                validate_link_target(&p, target, true)?;
                p
            }
            other => return Err(format!("unsupported tar entry type '{other}' in archive")),
        };
        v.push(norm);
    }
    if v.is_empty() {
        return Err("archive is empty".into());
    }
    Ok(v)
}

/// Fail-closed validation of `tar -tvzf` execution output. Any stdout truncation
/// is immediately rejected so trailing disallowed entries can never slip past.
pub fn check_tar_output(out: &ExecOut) -> Result<Vec<String>, String> {
    if out.truncated {
        return Err("Archive listing exceeded inspection limit (truncated); refusing restore".into());
    }
    if !out.ok() {
        return Err(format!("Archive is unreadable: {}", out.err_summary("tar")));
    }
    check_verbose_entries(&out.stdout_str())
}

pub fn sensitive_entries(entries: &[String]) -> Vec<String> {
    entries.iter().filter(|e| SENSITIVE.iter().any(|s| e.starts_with(s))).cloned().collect()
}

pub fn luci_installed() -> bool {
    std::path::Path::new(&crate::paths::p("/www/cgi-bin/luci")).exists()
        || std::path::Path::new(&crate::paths::p("/usr/lib/lua/luci")).exists()
}

pub async fn get_backup() -> Response {
    let _sg = sysupgrade_lock().await;
    match run_ok("sysupgrade", &["-l"], 30, 2 * MIB).await {
        Ok(out) => {
            let files: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
            let includes_cellcore = files.iter().any(|f| f.starts_with("/etc/cellcore/"));
            let installed = luci_installed();
            let proxy_enabled = crate::http::luci_proxy_enabled();
            ok(serde_json::json!({
                "files": files,
                "count": files.len(),
                "scope": BACKUP_SCOPE,
                "includesCellcoreState": includes_cellcore,
                "luciAvailable": installed && proxy_enabled,
                "luciInstalled": installed,
                "luciProxyEnabled": proxy_enabled,
            }))
        }
        Err(e) => server(e),
    }
}

async fn run_sysupgrade_backup() -> Result<ExecOut, String> {
    run("sysupgrade", &["-b", "-"], ExecOpts::new(120, MAX_ARCHIVE)).await
}

fn backup_archive_err(res: Result<ExecOut, String>) -> (StatusCode, String) {
    match res {
        Ok(o) if o.truncated => (StatusCode::INTERNAL_SERVER_ERROR, "backup larger than 32 MiB".into()),
        Ok(o) => (StatusCode::SERVICE_UNAVAILABLE, o.err_summary("sysupgrade -b")),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

pub async fn get_download(State(ctx): State<HttpCtx>) -> Response {
    let out = {
        let _sg = sysupgrade_lock().await;
        match run_sysupgrade_backup().await {
            Ok(o) if o.ok() && !o.truncated && is_gzip(&o.stdout) => Ok(o),
            Ok(o) if o.truncated => Err((StatusCode::INTERNAL_SERVER_ERROR, "backup larger than 32 MiB".into())),
            _ => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                match run_sysupgrade_backup().await {
                    Ok(o) if o.ok() && !o.truncated && is_gzip(&o.stdout) => Ok(o),
                    other => Err(backup_archive_err(other)),
                }
            }
        }
    };
    let out = match out {
        Ok(o) => o,
        Err((status, msg)) => return super::fail(status, msg),
    };
    let host = crate::uci::uci_get("system.@system[0].hostname").await.unwrap_or_else(|| "gateway".into());
    let host: String = host.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(40).collect();
    let date = run_ok("date", &["+%Y-%m-%d"], 3, 64).await.unwrap_or_default();
    let fname = format!("backup-{host}-{}.tar.gz", date.trim());
    let digest = sha256_hex(&out.stdout);
    audit(&ctx, format!("config backup downloaded ({} bytes, sha256={digest})", out.stdout.len()));
    let mut resp = Body::from(out.stdout).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&digest) {
        h.insert(HeaderName::from_static("x-backup-sha256"), v);
    }
    h.insert(
        HeaderName::from_static("x-backup-scope"),
        HeaderValue::from_static("sysupgrade-etc"),
    );
    resp
}

async fn inspect(body: &Bytes) -> Result<Vec<String>, String> {
    if !is_gzip(body) {
        return Err("Not a .tar.gz backup".into());
    }
    let out = run("tar", &["-tvzf", "-"], ExecOpts::new(30, 2 * MIB).stdin(body.to_vec())).await?;
    check_tar_output(&out)
}

pub async fn post_inspect(body: Bytes) -> Response {
    match inspect(&body).await {
        Ok(entries) => {
            let includes_cellcore = entries.iter().any(|e| e.starts_with("etc/cellcore/"));
            ok(serde_json::json!({
                "entries": entries.len(),
                "files": entries.iter().filter(|e| !e.ends_with('/')).take(500).collect::<Vec<_>>(),
                "sensitive": sensitive_entries(&entries),
                "bytes": body.len(),
                "sha256": sha256_hex(&body),
                "scope": BACKUP_SCOPE,
                "includesCellcoreState": includes_cellcore,
            }))
        }
        Err(e) => bad(e),
    }
}

#[derive(Deserialize)]
pub struct ConfirmQ {
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_restore(State(ctx): State<HttpCtx>, Query(q): Query<ConfirmQ>, body: Bytes) -> Response {
    if let Err(r) = require_confirm(
        q.confirm.as_deref(),
        "RESTORE",
        "Restoring replaces /etc with the archive (passwords, SSH keys, firewall, QCMAP and network config). Type RESTORE to continue.",
    ) {
        return r;
    }
    let entries = match inspect(&body).await {
        Ok(e) => e,
        Err(e) => return bad(e),
    };
    let digest = sha256_hex(&body);
    let _g = mutate_lock().await;
    let _sg = sysupgrade_lock().await;
    let out = match run("sysupgrade", &["-r", "-"], ExecOpts::new(120, 256 * 1024).stdin(body.to_vec())).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    audit(&ctx, format!("config backup restored ({} entries, sha256={digest}) -> {:?}", entries.len(), out.code));
    if !out.ok() {
        return server(out.err_summary("sysupgrade -r"));
    }
    ok(serde_json::json!({
        "status": "ok",
        "entries": entries.len(),
        "sha256": digest,
        "rebootRequired": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_archive_entries() {
        let good = "etc/\netc/config/\netc/config/system\n./etc/dropbear/authorized_keys\netc/shadow\n";
        let e = check_entries(good).unwrap();
        assert_eq!(e.len(), 5);
        let s = sensitive_entries(&e);
        assert!(s.contains(&"etc/shadow".to_string()));
        assert!(s.contains(&"etc/dropbear/authorized_keys".to_string()));
        assert!(!s.contains(&"etc/config/system".to_string()));
        assert!(check_entries("/etc/passwd\n").is_err());
        assert!(check_entries("etc/../root/.ssh/authorized_keys\n").is_err());
        assert!(check_entries("usr/bin/evil\n").is_err());
        assert!(check_entries("etcetera/x\n").is_err());
        assert!(check_entries("").is_err());
    }

    #[test]
    fn real_backup_list_is_restorable_shape() {
        // `sysupgrade -l` lists absolute paths; the tarball stores them relative.
        let listing: String = include_str!("fixtures/sysupgrade_list.txt")
            .lines()
            .map(|l| format!("{}\n", l.trim_start_matches('/')))
            .collect();
        let e = check_entries(&listing).unwrap();
        assert!(e.len() > 100);
        let s = sensitive_entries(&e);
        assert!(s.iter().any(|x| x.starts_with("etc/nftables.d/")));
        assert!(s.contains(&"etc/shadow".to_string()));
    }

    #[test]
    fn gzip_magic() {
        assert!(is_gzip(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_gzip(b"PK\x03\x04................"));
    }

    #[tokio::test]
    async fn download_retries_once_and_succeeds() {
        let env = crate::paths::TestSandbox::new("backup-retry-ok");
        let count_file = env.root.join("calls");
        env.write_exec("/bin/uci", "#!/bin/sh\necho 'gateway'\n");
        env.write_exec("/bin/date", "#!/bin/sh\necho '2026-11-18'\n");
        env.write_exec(
            "/bin/sysupgrade",
            &format!(
                "#!/bin/sh\n\
                 n=$(cat {cf} 2>/dev/null || echo 0)\n\
                 n=$((n + 1))\n\
                 echo \"$n\" > {cf}\n\
                 if [ \"$n\" -eq 1 ]; then\n\
                   echo 'tar: /tmp/sysupgrade.conffiles: race' >&2\n\
                   exit 1\n\
                 fi\n\
                 printf '\\037\\213\\010\\000\\000\\000\\000\\000\\000\\003\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000'\n",
                cf = count_file.display()
            ),
        );
        let ctx = HttpCtx::for_tests(&env.root);

        let resp = crate::paths::TEST_ENV
            .scope(env.env(), get_download(State(ctx)))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/gzip");
        let sha_hdr = resp.headers().get("x-backup-sha256").unwrap().to_str().unwrap().to_string();
        assert_eq!(resp.headers().get("x-backup-scope").unwrap(), "sysupgrade-etc");
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(is_gzip(&body));
        assert_eq!(sha_hdr, sha256_hex(&body));
        assert_eq!(std::fs::read_to_string(&count_file).unwrap().trim(), "2");
    }

    fn append_tar_entry(buf: &mut Vec<u8>, name: &str, typeflag: u8, linkname: &str, data: &[u8]) {
        let mut hdr = [0u8; 512];
        let nb = name.as_bytes();
        assert!(nb.len() <= 100);
        hdr[..nb.len()].copy_from_slice(nb);
        hdr[100..108].copy_from_slice(b"0000644\0");
        hdr[108..116].copy_from_slice(b"0000000\0");
        hdr[116..124].copy_from_slice(b"0000000\0");
        let sz = format!("{:011o}\0", data.len());
        hdr[124..136].copy_from_slice(sz.as_bytes());
        hdr[136..148].copy_from_slice(b"14700000000\0");
        hdr[148..156].copy_from_slice(b"        ");
        hdr[156] = typeflag;
        let lb = linkname.as_bytes();
        assert!(lb.len() <= 100);
        hdr[157..157 + lb.len()].copy_from_slice(lb);
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        let cksum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
        let ck = format!("{cksum:06o}\0 ");
        hdr[148..156].copy_from_slice(ck.as_bytes());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(data);
        let rem = data.len() % 512;
        if rem != 0 {
            buf.resize(buf.len() + (512 - rem), 0);
        }
    }

    fn gzip_tar(mut tar_buf: Vec<u8>) -> Bytes {
        use std::io::Write;
        tar_buf.resize(tar_buf.len() + 1024, 0);
        let mut child = std::process::Command::new("gzip")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn gzip");
        child.stdin.take().unwrap().write_all(&tar_buf).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        Bytes::from(out.stdout)
    }

    #[test]
    fn rejects_truncated_tar_output_fail_closed() {
        let out = ExecOut {
            code: Some(0),
            stdout: b"-rw-r--r-- root/root 10 2026-11-23 12:00 etc/config/system\n".to_vec(),
            stderr: String::new(),
            truncated: true,
            timed_out: false,
        };
        let err = check_tar_output(&out).unwrap_err();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn enforces_max_entry_count_and_validates_verbose_types() {
        // Entry count cap in both check_entries and check_verbose_entries
        let too_many: String = (0..=MAX_ARCHIVE_ENTRIES).map(|i| format!("etc/f{i}\n")).collect();
        assert!(check_entries(&too_many).unwrap_err().contains("maximum"));
        let too_many_v: String = (0..=MAX_ARCHIVE_ENTRIES)
            .map(|i| format!("-rw-r--r-- 0/0 0 2026-11-23 12:00:00 etc/f{i}\n"))
            .collect();
        assert!(check_verbose_entries(&too_many_v).unwrap_err().contains("maximum"));

        // Safe regular file + dir + internal symlinks + internal hardlink
        let ok_v = "\
drwxr-xr-x 0/0         0 2026-11-23 12:00:00 etc/rc.d/\n\
-rw-r--r-- root/root  12 2026-11-23 12:00 etc/init.d/cellcored\n\
lrwxrwxrwx 0/0         0 2026-11-23 12:00:00 etc/rc.d/S95cellcored -> ../init.d/cellcored\n\
lrwxrwxrwx 0/0         0 2026-11-23 12:00:00 etc/rc.d/S96abs -> /etc/init.d/cellcored\n\
hrw-r--r-- 0/0         0 2026-11-23 12:00:00 etc/hard link to etc/init.d/cellcored\n";
        assert_eq!(check_verbose_entries(ok_v).unwrap().len(), 5);

        // Disallowed symlinks / hardlinks / device nodes / FIFOs
        for bad_line in [
            "lrwxrwxrwx 0/0 0 2026-11-23 12:00:00 etc/evil -> /usr/sbin/cellcored\n",
            "lrwxrwxrwx 0/0 0 2026-11-23 12:00:00 etc/rc.d/evil -> ../../usr/sbin/cellcored\n",
            "lrwxrwxrwx 0/0 0 2026-11-23 12:00:00 etc/evil -> /etc/../usr/sbin/cellcored\n",
            "hrw-r--r-- 0/0 0 2026-11-23 12:00:00 etc/evil link to usr/sbin/cellcored\n",
            "hrw-r--r-- 0/0 0 2026-11-23 12:00:00 etc/evil link to /etc/shadow\n",
            "crw-rw-rw- 0/0 1, 3 2026-11-23 12:00:00 etc/null\n",
            "brw-rw---- 0/0 8, 0 2026-11-23 12:00:00 etc/sda\n",
            "prw-r--r-- 0/0 0 2026-11-23 12:00:00 etc/fifo\n",
        ] {
            assert!(check_verbose_entries(bad_line).is_err(), "must reject: {bad_line}");
        }
    }

    #[tokio::test]
    async fn inspect_rejects_padded_archive_with_trailing_disallowed_entry() {
        // Build a real .tar.gz with >2 MiB of verbose tar listing output (26,000 valid etc/
        // entries) followed by a trailing disallowed `usr/sbin/cellcored` entry.
        let mut tar = Vec::with_capacity(26_005 * 512);
        for i in 0..26_000u32 {
            let name = format!("etc/pad/entry_padding_long_name_{i:06}");
            append_tar_entry(&mut tar, &name, b'0', "", b"");
        }
        append_tar_entry(&mut tar, "usr/sbin/cellcored", b'0', "", b"pwn");
        let gz = gzip_tar(tar);

        let err = inspect(&gz).await.unwrap_err();
        assert!(
            err.contains("truncated") || err.contains("maximum") || err.contains("outside etc/"),
            "padded archive with trailing disallowed file must be rejected: {err}"
        );
    }

    #[tokio::test]
    async fn inspect_rejects_symlink_escape_and_returns_sha256_on_valid_archive() {
        let mut bad_tar = Vec::new();
        append_tar_entry(&mut bad_tar, "etc/config/system", b'0', "", b"ok");
        append_tar_entry(&mut bad_tar, "etc/escape", b'2', "../../usr/sbin/cellcored", b"");
        let bad_gz = gzip_tar(bad_tar);
        assert!(inspect(&bad_gz).await.is_err());

        let mut good_tar = Vec::new();
        append_tar_entry(&mut good_tar, "etc/config/system", b'0', "", b"ok");
        append_tar_entry(&mut good_tar, "etc/cellcore/settings.json", b'0', "", b"{}");
        append_tar_entry(&mut good_tar, "etc/rc.d/S95cellcored", b'2', "../init.d/cellcored", b"");
        let good_gz = gzip_tar(good_tar);
        let expected_sha = sha256_hex(&good_gz);

        let resp = post_inspect(good_gz).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["entries"], 3);
        assert_eq!(v["sha256"], expected_sha);
        assert_eq!(v["includesCellcoreState"], true);
        assert!(v["scope"].as_str().unwrap().contains("sysupgrade"));
    }

    #[tokio::test]
    async fn download_returns_503_with_tool_error_after_retry() {
        let env = crate::paths::TestSandbox::new("backup-retry-503");
        let count_file = env.root.join("calls");
        env.write_exec(
            "/bin/sysupgrade",
            &format!(
                "#!/bin/sh\n\
                 n=$(cat {cf} 2>/dev/null || echo 0)\n\
                 n=$((n + 1))\n\
                 echo \"$n\" > {cf}\n\
                 echo 'tar: /tmp/sysupgrade.conffiles: No such file or directory' >&2\n\
                 exit 1\n",
                cf = count_file.display()
            ),
        );
        let ctx = HttpCtx::for_tests(&env.root);

        let resp = crate::paths::TEST_ENV
            .scope(env.env(), get_download(State(ctx)))
            .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "error");
        let err = v["error"].as_str().unwrap();
        assert!(err.contains("sysupgrade -b"), "{err}");
        assert!(err.contains("sysupgrade.conffiles"), "{err}");
        assert_eq!(std::fs::read_to_string(&count_file).unwrap().trim(), "2");
    }
}
