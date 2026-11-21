//! Bounded, argv-only process execution for the admin API.
//!
//! Every command runs without a shell, with a hard wall-clock timeout (the child
//! is killed when it expires) and a cap on how much stdout/stderr is retained.
//! Output beyond the cap is drained and discarded so the child never blocks on a
//! full pipe.

use std::{
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

pub const KIB: usize = 1024;
pub const MIB: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ExecOpts {
    pub timeout: Duration,
    pub max_stdout: usize,
    pub max_stderr: usize,
    pub stdin: Option<Vec<u8>>,
    /// Extra environment for the child (secrets that must not appear in argv).
    pub env: Vec<(String, String)>,
}

impl ExecOpts {
    pub fn new(timeout_secs: u64, max_stdout: usize) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            max_stdout,
            max_stderr: 64 * KIB,
            stdin: None,
            env: Vec::new(),
        }
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn stdin(mut self, data: Vec<u8>) -> Self {
        self.stdin = Some(data);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExecOut {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

impl ExecOut {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.code == Some(0)
    }

    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Combined, human-readable log: stdout then stderr, trimmed.
    pub fn log(&self) -> String {
        let mut s = self.stdout_str();
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&self.stderr);
        }
        if self.timed_out {
            s.push_str("\n[timed out; process killed]");
        }
        if self.truncated {
            s.push_str("\n[output truncated]");
        }
        s.trim().to_string()
    }

    /// Short error description for API responses.
    pub fn err_summary(&self, prog: &str) -> String {
        if self.timed_out {
            return format!("{prog} timed out");
        }
        let msg = if self.stderr.trim().is_empty() {
            self.stdout_str()
        } else {
            self.stderr.clone()
        };
        let msg = tail_chars(msg.trim(), 600);
        format!("{prog} exited {}: {msg}", self.code.map(|c| c.to_string()).unwrap_or_else(|| "by signal".into()))
    }
}

pub fn tail_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        s.to_string()
    } else {
        s.chars().skip(count - n).collect()
    }
}

struct Capture {
    buf: Vec<u8>,
    truncated: bool,
}

fn spawn_reader<R>(mut r: R, cap: usize) -> (Arc<Mutex<Capture>>, tokio::task::JoinHandle<()>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let shared = Arc::new(Mutex::new(Capture { buf: Vec::new(), truncated: false }));
    let s2 = Arc::clone(&shared);
    let h = tokio::spawn(async move {
        let mut chunk = vec![0u8; 16 * KIB];
        loop {
            match r.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Ok(mut c) = s2.lock() else { break };
                    let room = cap.saturating_sub(c.buf.len());
                    if room >= n {
                        c.buf.extend_from_slice(&chunk[..n]);
                    } else {
                        c.buf.extend_from_slice(&chunk[..room]);
                        c.truncated = true;
                    }
                }
            }
        }
    });
    (shared, h)
}

fn take_capture(c: &Arc<Mutex<Capture>>) -> (Vec<u8>, bool) {
    match c.lock() {
        Ok(mut g) => (std::mem::take(&mut g.buf), g.truncated),
        Err(_) => (Vec::new(), false),
    }
}

/// Test-only program override: when set, `run("uci", ..)` executes
/// `<dir>/uci` if that file exists (absolute paths map to `<dir>/_etc__init.d__x`
/// style names), so route-level tests drive mocked binaries. Never set outside
/// tests; production resolves programs through PATH as before.
#[cfg(test)]
pub static BIN_OVERRIDE: std::sync::RwLock<Option<std::path::PathBuf>> = std::sync::RwLock::new(None);

#[cfg(test)]
pub fn mock_name(prog: &str) -> String {
    prog.trim_start_matches('/').replace('/', "__")
}

fn resolve(prog: &str) -> std::ffi::OsString {
    #[cfg(test)]
    if let Ok(g) = BIN_OVERRIDE.read()
        && let Some(dir) = g.as_ref()
    {
        let p = dir.join(mock_name(prog));
        if p.is_file() {
            return p.into_os_string();
        }
    }
    crate::paths::program(prog).into()
}

/// Run `prog args…` with no shell. Errors only when the process cannot be spawned;
/// a non-zero exit or a timeout is reported through [`ExecOut`].
pub async fn run(prog: &str, args: &[&str], opts: ExecOpts) -> Result<ExecOut, String> {
    let mut cmd = Command::new(resolve(prog));
    cmd.envs(opts.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    cmd.args(args)
        .stdin(if opts.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("spawn {prog}: {e}"))?;

    if let (Some(data), Some(mut si)) = (opts.stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = si.write_all(&data).await;
            let _ = si.shutdown().await;
        });
    }
    let (out_cap, out_h) = match child.stdout.take() {
        Some(so) => {
            let (c, h) = spawn_reader(so, opts.max_stdout);
            (Some(c), Some(h))
        }
        None => (None, None),
    };
    let (err_cap, err_h) = match child.stderr.take() {
        Some(se) => {
            let (c, h) = spawn_reader(se, opts.max_stderr);
            (Some(c), Some(h))
        }
        None => (None, None),
    };

    let mut res = ExecOut::default();
    match tokio::time::timeout(opts.timeout, child.wait()).await {
        Ok(Ok(st)) => res.code = st.code(),
        Ok(Err(e)) => return Err(format!("wait {prog}: {e}")),
        Err(_) => {
            res.timed_out = true;
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        }
    }
    // Background daemons forked by init scripts may keep our pipes open; give the
    // readers a short grace period, then take whatever was captured.
    for h in [out_h, err_h].into_iter().flatten() {
        let abort = h.abort_handle();
        if tokio::time::timeout(Duration::from_millis(1500), h).await.is_err() {
            abort.abort();
        }
    }
    if let Some(c) = out_cap {
        let (b, t) = take_capture(&c);
        res.stdout = b;
        res.truncated |= t;
    }
    if let Some(c) = err_cap {
        let (b, _) = take_capture(&c);
        res.stderr = String::from_utf8_lossy(&b).into_owned();
    }
    Ok(res)
}

/// Run and require exit 0; returns stdout as a string.
pub async fn run_ok(prog: &str, args: &[&str], timeout_secs: u64, max_stdout: usize) -> Result<String, String> {
    let out = run(prog, args, ExecOpts::new(timeout_secs, max_stdout)).await?;
    if out.ok() {
        Ok(out.stdout_str())
    } else {
        Err(out.err_summary(prog))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_and_bounds_output() {
        let out = run("sh", &["-c", "yes x | head -c 100000"], ExecOpts::new(5, 1000)).await.unwrap();
        assert!(out.ok());
        assert_eq!(out.stdout.len(), 1000);
        assert!(out.truncated);
    }

    #[tokio::test]
    async fn kills_on_timeout() {
        let t0 = std::time::Instant::now();
        let out = run("sleep", &["30"], ExecOpts::new(1, 100)).await.unwrap();
        assert!(out.timed_out);
        assert!(!out.ok());
        assert!(t0.elapsed() < Duration::from_secs(6));
    }

    #[tokio::test]
    async fn feeds_stdin_without_shell() {
        let out = run("cat", &[], ExecOpts::new(5, 1000).stdin(b"a; rm -rf /\n".to_vec())).await.unwrap();
        assert_eq!(out.stdout_str(), "a; rm -rf /\n");
    }

    #[tokio::test]
    async fn reports_nonzero_exit() {
        let out = run("sh", &["-c", "echo boom >&2; exit 3"], ExecOpts::new(5, 1000)).await.unwrap();
        assert_eq!(out.code, Some(3));
        assert!(out.err_summary("sh").contains("boom"));
    }
}
