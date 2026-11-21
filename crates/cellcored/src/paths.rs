//! Test seam and production path passthrough.
//!
//! In release builds, `p` and `program` are zero-overhead passthroughs and only
//! `QM_SMD_DEVICE` / `QM_IPC_SOCKET` are read from the environment. Under
//! `#[cfg(test)]`, `TEST_ENV` (task-local for async tests) and `TestSandbox`
//! (thread-local + temp root/bin directory) isolate filesystem and tool paths
//! without process-wide environment mutations.

use std::env;

#[cfg(test)]
fn root() -> Option<&'static str> {
    static ROOT: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        env::var("QM_ROOT")
            .ok()
            .map(|r| r.trim_end_matches('/').to_string())
            .filter(|r| !r.is_empty())
    })
    .as_deref()
}

/// Per-test filesystem / tool sandbox. Route tests scope their own root and
/// tool directory via [`TEST_ENV`] (`tokio::task_local!`) or [`TestSandbox`]
/// so parallel tests never contend on process-wide env vars: absolute paths map
/// under `root`, and bare program names resolve to `{bin}/{prog}`.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct TestEnv {
    pub root: Option<String>,
    pub bin: Option<String>,
}

#[cfg(test)]
tokio::task_local! {
    pub static TEST_ENV: TestEnv;
}

#[cfg(test)]
thread_local! {
    static TEST_LOCAL: std::cell::RefCell<Option<TestEnv>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_env() -> Option<TestEnv> {
    TEST_ENV
        .try_with(Clone::clone)
        .ok()
        .or_else(|| TEST_LOCAL.with(|cell| cell.borrow().clone()))
}

/// The program to spawn for `prog`: `{bin}/{prog}` under a test sandbox, else `p(prog)`.
pub fn program(prog: &str) -> String {
    #[cfg(test)]
    if let Some(TestEnv { bin: Some(bin), .. }) = test_env()
        && !prog.contains('/')
    {
        return format!("{}/{prog}", bin.trim_end_matches('/'));
    }
    p(prog)
}

/// Map an absolute production path under the active test root (if any).
pub fn p(path: &str) -> String {
    #[cfg(test)]
    {
        if let Some(TestEnv { root: Some(r), .. }) = test_env() {
            let r = r.trim_end_matches('/');
            if path.starts_with('/') && !path.starts_with(&format!("{r}/")) {
                return format!("{r}{path}");
            }
            return path.to_string();
        }
        match root() {
            Some(r) if path.starts_with('/') && !path.starts_with(&format!("{r}/")) => format!("{r}{path}"),
            _ => path.to_string(),
        }
    }
    #[cfg(not(test))]
    {
        path.to_string()
    }
}

pub fn smd_device() -> String {
    env::var("QM_SMD_DEVICE").unwrap_or_else(|_| p(crate::smd::DEFAULT_SMD_DEVICE))
}

pub fn ipc_socket() -> String {
    env::var("QM_IPC_SOCKET").unwrap_or_else(|_| p(crate::ipc::IPC_SOCKET_PATH))
}

#[cfg(test)]
#[allow(dead_code)]
pub fn luci_upstream() -> String {
    env::var("QM_LUCI_UPSTREAM").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}

/// Isolated temporary root + `/bin` directory cleaned up on drop.
///
/// Sets the thread-local fallback for synchronous `#[test]` cases and exposes
/// [`TestSandbox::env`] so async `#[tokio::test]` cases can run inside
/// `TEST_ENV.scope(sbx.env(), async { ... })` with zero mutex contention.
#[cfg(test)]
pub struct TestSandbox {
    pub root: std::path::PathBuf,
    root_str: String,
    bin_str: String,
    prev_local: Option<TestEnv>,
}

#[cfg(test)]
impl TestSandbox {
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("qm-test-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("bin")).expect("create TestSandbox root");
        let root_str = root.to_string_lossy().trim_end_matches('/').to_string();
        let bin_str = root.join("bin").to_string_lossy().trim_end_matches('/').to_string();
        let env_val = TestEnv {
            root: Some(root_str.clone()),
            bin: Some(bin_str.clone()),
        };
        let prev_local = TEST_LOCAL.with(|cell| cell.borrow_mut().replace(env_val));
        Self {
            root,
            root_str,
            bin_str,
            prev_local,
        }
    }

    pub fn env(&self) -> TestEnv {
        TestEnv {
            root: Some(self.root_str.clone()),
            bin: Some(self.bin_str.clone()),
        }
    }

    pub fn write(&self, path: &str, contents: impl AsRef<[u8]>) -> std::path::PathBuf {
        let target = self.root.join(path.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs in TestSandbox");
        }
        std::fs::write(&target, contents).expect("write file in TestSandbox");
        target
    }

    pub fn write_exec(&self, path: &str, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let target = self.write(path, script);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755 in TestSandbox");
        target
    }
}

#[cfg(test)]
impl Drop for TestSandbox {
    fn drop(&mut self) {
        let prev = self.prev_local.take();
        TEST_LOCAL.with(|cell| {
            *cell.borrow_mut() = prev;
        });
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_without_root() {
        if env::var_os("QM_ROOT").is_none() {
            assert_eq!(p("/etc/shadow"), "/etc/shadow");
            assert_eq!(p("uci"), "uci");
            assert_eq!(smd_device(), "/dev/smd11");
            assert_eq!(ipc_socket(), "/var/run/cellcored.sock");
            assert_eq!(luci_upstream(), "127.0.0.1:8080");
        }
    }
}

#[cfg(test)]
mod sandbox_tests {
    use super::*;

    #[tokio::test]
    async fn test_env_maps_paths_and_tools_for_its_task_only() {
        let env = TestEnv { root: Some("/tmp/qm-sbx".into()), bin: Some("/tmp/qm-sbx/bin".into()) };
        TEST_ENV
            .scope(env, async {
                assert_eq!(p("/etc/config/cellprofiles"), "/tmp/qm-sbx/etc/config/cellprofiles");
                assert_eq!(p("/tmp/qm-sbx/x"), "/tmp/qm-sbx/x");
                assert_eq!(program("uci"), "/tmp/qm-sbx/bin/uci");
                assert_eq!(program("/sbin/reboot"), "/tmp/qm-sbx/sbin/reboot");
            })
            .await;
        if env::var_os("QM_ROOT").is_none() {
            assert_eq!(p("/etc/config/cellprofiles"), "/etc/config/cellprofiles");
            assert_eq!(program("uci"), "uci");
        }
    }
}
