use std::{path::Path, process::Stdio, time::Duration};

use tokio::process::Command;

pub async fn run_cmd(prog: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut cmd = Command::new(crate::paths::program(prog));
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // On timeout the future is dropped: kill (and reap) the child instead
        // of leaving it running/holding pipes.
        .kill_on_drop(true);
    let child = cmd.spawn().map_err(|e| format!("spawn {prog}: {e}"))?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| format!("{prog} timed out after {}s", timeout.as_secs()))?
        .map_err(|e| format!("{prog} wait error: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        let msg = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        Err(format!(
            "{prog} exited {:?}: {msg}",
            output.status.code()
        ))
    }
}

/// Blocking variant with a hard deadline: the child is killed and reaped
/// when it overruns (used by the CLI, which must finish inside Route10's
/// 25 s SSH budget).
pub fn run_cmd_blocking_timeout(prog: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    use std::io::Read;
    let mut child = std::process::Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("exec {prog}: {e}"))?;
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        if let Some(s) = stdout.as_mut() {
            let _ = s.read_to_end(&mut out);
        }
        out
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("wait {prog}: {e}")),
        }
    };
    let out = String::from_utf8_lossy(&reader.join().unwrap_or_default()).to_string();
    match status {
        None => Err(format!("{prog} timed out after {}ms", timeout.as_millis())),
        Some(st) if st.success() => Ok(out),
        Some(st) => Err(format!("{prog} exited {:?}", st.code())),
    }
}

pub fn run_cmd_blocking(prog: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(crate::paths::program(prog))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("exec {prog}: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        })
    }
}

pub async fn uci_get(path: &str) -> Option<String> {
    run_cmd("uci", &["-q", "get", path], Duration::from_secs(3))
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn uci_get_blocking(path: &str) -> Option<String> {
    run_cmd_blocking("uci", &["-q", "get", path])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn uci_show(target: &str) -> String {
    run_cmd("uci", &["-q", "show", target], Duration::from_secs(3))
        .await
        .unwrap_or_default()
}

/// `uci show` that tells a missing config (uci: "Entry not found" -> empty)
/// apart from a failure (spawn error, timeout, parse/I-O error -> Err).
pub async fn uci_show_checked(target: &str) -> Result<String, String> {
    match run_cmd("uci", &["show", target], Duration::from_secs(3)).await {
        Ok(out) => Ok(out),
        Err(e) if e.contains("Entry not found") => Ok(String::new()),
        Err(e) => Err(e),
    }
}

pub async fn uci_set(path: &str, value: &str) -> Result<(), String> {
    let arg = format!("{path}={value}");
    run_cmd("uci", &["set", &arg], Duration::from_secs(3)).await?;
    Ok(())
}

pub async fn uci_add_section(config: &str, section_type: &str) -> Result<String, String> {
    let out = run_cmd("uci", &["add", config, section_type], Duration::from_secs(3)).await?;
    Ok(out.trim().to_string())
}

#[allow(dead_code)]
pub async fn uci_add_list(path: &str, value: &str) -> Result<(), String> {
    let arg = format!("{path}={value}");
    run_cmd("uci", &["add_list", &arg], Duration::from_secs(3)).await?;
    Ok(())
}

pub async fn uci_delete(path: &str) {
    let _ = run_cmd("uci", &["-q", "delete", path], Duration::from_secs(3)).await;
}

pub async fn uci_commit(config: &str) -> Result<(), String> {
    run_cmd("uci", &["commit", config], Duration::from_secs(3)).await?;
    Ok(())
}

pub async fn ensure_uci_config_file(config: &str) {
    let path = crate::paths::p(&format!("/etc/config/{config}"));
    if !Path::new(&path).exists() {
        let _ = crate::state::atomic_write(Path::new(&path), b"", 0o644);
    }
}

pub fn is_valid_uci_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn detect_wan_rmnet_ifaces_blocking() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = std::fs::read_dir(crate::paths::p("/sys/class/net")) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("rmnet_data") {
                ifaces.push(name);
            }
        }
    }
    ifaces.sort();
    if ifaces.is_empty() {
        ifaces.push("rmnet_data0".into());
    }
    ifaces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid_running(pid: i32) -> bool {
        // A zombie (state Z) is not running; a reaped process has no entry.
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => {
                let after = stat.rsplit(')').next().unwrap_or("");
                !after.trim_start().starts_with('Z')
            }
            Err(_) => false,
        }
    }

    #[tokio::test]
    async fn run_cmd_kills_child_on_timeout() {
        let dir = std::env::temp_dir().join(format!("qm-runcmd-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let pidfile = dir.join("pid");
        let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
        let res = run_cmd("sh", &["-c", &script], Duration::from_millis(300)).await;
        assert!(res.unwrap_err().contains("timed out"));
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let mut gone = false;
        for _ in 0..50 {
            if !pid_running(pid) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(gone, "child {pid} still running after run_cmd timeout");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocking_timeout_variant_kills_child() {
        let t0 = std::time::Instant::now();
        let res = run_cmd_blocking_timeout("sleep", &["30"], Duration::from_millis(200));
        assert!(res.unwrap_err().contains("timed out"));
        assert!(t0.elapsed() < Duration::from_secs(3));
        assert_eq!(run_cmd_blocking_timeout("echo", &["hi"], Duration::from_secs(2)).unwrap(), "hi\n");
    }
}
