use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::uci::{detect_wan_rmnet_ifaces_blocking, run_cmd_blocking, uci_get_blocking};

pub const USB_DISABLED_MARKER: &str = "/etc/cellcore/usb_gadget_disabled";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileReport {
    pub timestamp: u64,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
    pub pcie_aspm: String,
    pub autosleep: String,
    pub conntrack_hashsize: u64,
    pub conntrack_max: u64,
    pub usb_udc: String,
}

pub fn run_boot_reconcile(enforce_uhttpd_loopback: bool) -> ReconcileReport {
    let mut actions = Vec::new();
    let mut warnings = Vec::new();

    // 1. PCIe ASPM policy -> performance (prevents RTL8125 TX watchdog timeouts)
    let aspm_path_s = crate::paths::p("/sys/module/pcie_aspm/parameters/policy");
    let aspm_path = Path::new(&aspm_path_s);
    let mut pcie_aspm = String::new();
    if aspm_path.exists() {
        let cur = fs::read_to_string(aspm_path).unwrap_or_default();
        if !cur.contains("[performance]") {
            if let Err(e) = fs::write(aspm_path, "performance\n") {
                warnings.push(format!("pcie_aspm write failed: {e}"));
            } else {
                actions.push("Set PCIe ASPM policy=performance".into());
            }
        }
        pcie_aspm = fs::read_to_string(aspm_path)
            .unwrap_or_default()
            .trim()
            .to_string();
    }

    // 2. Disable kernel autosleep on mains-powered CPE
    let autosleep_path_s = crate::paths::p("/sys/power/autosleep");
    let autosleep_path = Path::new(&autosleep_path_s);
    let mut autosleep = String::new();
    if autosleep_path.exists() {
        let cur = fs::read_to_string(autosleep_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        if cur != "off" {
            if let Err(e) = fs::write(autosleep_path, "off\n") {
                warnings.push(format!("autosleep write failed: {e}"));
            } else {
                actions.push(format!("Disabled kernel autosleep (was {cur})"));
            }
        }
        autosleep = fs::read_to_string(autosleep_path)
            .unwrap_or_default()
            .trim()
            .to_string();
    }

    // 2b. Disable Qualcomm crash-dump xbl_ramdump trap & ensure MSS remoteproc SSR recovery
    let dload_path_s = crate::paths::p("/sys/module/qcom_dload_mode/parameters/download_mode");
    let dload_path = Path::new(&dload_path_s);
    if dload_path.exists()
        && fs::read_to_string(dload_path).unwrap_or_default().trim() == "1"
    {
        if let Err(e) = fs::write(dload_path, "0") {
            warnings.push(format!("qcom_dload_mode write failed: {e}"));
        } else {
            actions.push("Disabled Qualcomm xbl_ramdump download_mode (1 -> 0)".into());
        }
    }

    let rproc_path_s = crate::paths::p("/sys/class/remoteproc/remoteproc0/recovery");
    let rproc_path = Path::new(&rproc_path_s);
    if rproc_path.exists()
        && fs::read_to_string(rproc_path).unwrap_or_default().trim() == "disabled"
    {
        if let Err(e) = fs::write(rproc_path, "enabled") {
            warnings.push(format!("remoteproc0 recovery write failed: {e}"));
        } else {
            actions.push("Enabled MSS remoteproc0 SSR recovery".into());
        }
    }

    // 3. Conntrack hashsize / limits & SIP ALG suppression
    let hash_path_s = crate::paths::p("/sys/module/nf_conntrack/parameters/hashsize");
    let hash_path = Path::new(&hash_path_s);
    let mut conntrack_hashsize = fs::read_to_string(hash_path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if conntrack_hashsize > 0 && conntrack_hashsize < 16384 && hash_path.exists() {
        if fs::write(hash_path, "16384\n").is_ok() {
            actions.push(format!("Raised nf_conntrack hashsize {conntrack_hashsize} -> 16384"));
            conntrack_hashsize = 16384;
        } else {
            warnings.push("Failed to raise nf_conntrack hashsize".into());
        }
    }

    raise_sysctl_at_least(
        "/proc/sys/net/netfilter/nf_conntrack_max",
        32768,
        "nf_conntrack_max",
        &mut actions,
    );
    set_sysctl_if_different(
        "/proc/sys/net/netfilter/nf_conntrack_helper",
        "0",
        "nf_conntrack_helper",
        &mut actions,
    );
    set_sysctl_if_different(
        "/proc/sys/net/netfilter/nf_conntrack_disable_sip_alg",
        "1",
        "nf_conntrack_disable_sip_alg",
        &mut actions,
    );
    set_sysctl_if_different(
        "/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream",
        "180",
        "nf_conntrack_udp_timeout_stream",
        &mut actions,
    );
    for (p, v, lbl) in [
        (
            "/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal",
            "1",
            "nf_conntrack_tcp_be_liberal",
        ),
        (
            "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
            "7200",
            "nf_conntrack_tcp_timeout_established",
        ),
        (
            "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait",
            "30",
            "nf_conntrack_tcp_timeout_fin_wait",
        ),
        (
            "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait",
            "30",
            "nf_conntrack_tcp_timeout_time_wait",
        ),
    ] {
        set_sysctl_if_different(p, v, lbl, &mut actions);
    }
    // Security baseline sysctls (loose reverse-path filter + anti-redirect/source-route)
    for (p, v, lbl) in [
        ("/proc/sys/net/ipv4/conf/all/rp_filter", "2", "rp_filter"),
        ("/proc/sys/net/ipv4/conf/default/rp_filter", "2", "default.rp_filter"),
        ("/proc/sys/net/ipv4/conf/all/accept_source_route", "0", "accept_source_route"),
        ("/proc/sys/net/ipv6/conf/all/accept_source_route", "0", "ipv6.accept_source_route"),
        ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0", "accept_redirects"),
        ("/proc/sys/net/ipv6/conf/all/accept_redirects", "0", "ipv6.accept_redirects"),
    ] {
        set_sysctl_if_different(p, v, lbl, &mut actions);
    }
    let conntrack_max = fs::read_to_string(crate::paths::p("/proc/sys/net/netfilter/nf_conntrack_max"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    // 4. QCMAP mobileap_cfg.xml SIP ALG off
    reconcile_mobileap_xml(&mut actions, &mut warnings);

    // 5. Idempotent guards on Qualcomm /etc/data/{ippt.sh,lanUtils.sh,lan_config.sh} + QCMAP log_config
    reconcile_qualcomm_scripts(&mut actions, &mut warnings);

    // 6. Disable unused noisy vendor services (preserving mwan3!)
    disable_unused_services(&mut actions);

    // 7. Bind USB ConfigFS gadget g1 when adb is excluded and not user-disabled
    let usb_udc = ensure_usb_gadget_bound(&mut actions, &mut warnings);

    // 8. Re-apply Ethernet link speed limit, TTL/HL, and MTU if persisted
    reapply_network_policies(&mut actions, &mut warnings);

    // 9. Enforce uhttpd loopback-only LuCI listener when cellcored owns :443
    if enforce_uhttpd_loopback {
        ensure_uhttpd_loopback(&mut actions, &mut warnings);
    }

    // 9b. Auto-restore any unconfirmed firewall commit-confirm rollback left across a crash/reboot
    crate::admin::firewall::restore_pending_rollback_blocking(&mut actions, &mut warnings);

    // 9c. Prune legacy QuecManager keep_alive_worker.sh entries from /etc/crontabs/root
    prune_legacy_crontabs(&mut actions, &mut warnings);

    // 10. Purge legacy CGI/LuCI leftovers if present
    for stale in [
        "/etc/opkg/keys/6262698f038d1226",
        "/usr/lib/lua/luci/controller/modem/atc.lua",
    ] {
        let mapped = crate::paths::p(stale);
        let p = Path::new(&mapped);
        if p.exists() && fs::remove_file(p).is_ok() {
            actions.push(format!("Removed stale file {stale}"));
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ReconcileReport {
        timestamp,
        actions,
        warnings,
        pcie_aspm,
        autosleep,
        conntrack_hashsize,
        conntrack_max,
        usb_udc,
    }
}

fn set_sysctl_if_different(proc_path: &str, target: &str, label: &str, actions: &mut Vec<String>) {
    let mapped = crate::paths::p(proc_path);
    let p = Path::new(&mapped);
    if !p.exists() {
        return;
    }
    let cur = fs::read_to_string(p).unwrap_or_default().trim().to_string();
    if cur != target && fs::write(p, format!("{target}\n")).is_ok() {
        actions.push(format!("Set {label}={target} (was {cur})"));
    }
}

fn raise_sysctl_at_least(proc_path: &str, floor: u64, label: &str, actions: &mut Vec<String>) {
    let mapped = crate::paths::p(proc_path);
    let p = Path::new(&mapped);
    if !p.exists() {
        return;
    }
    let cur_raw = fs::read_to_string(p).unwrap_or_default();
    let cur = cur_raw.trim().parse::<u64>().unwrap_or(0);
    if cur < floor && fs::write(p, format!("{floor}\n")).is_ok() {
        actions.push(format!("Raised {label}={floor} (was {cur})"));
    }
}

fn backup_once(src_path: &str) {
    let bak_root_s = crate::paths::p("/root/backups/quecmanager");
    let bak_root = Path::new(&bak_root_s);
    let rel = src_path.trim_start_matches('/');
    let bak_path = bak_root.join(format!("{rel}.orig.bak"));
    if bak_path.exists() {
        return;
    }
    if let Some(parent) = bak_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    // Written once and then trusted forever: never leave a torn copy behind.
    if let Ok(orig) = fs::read(crate::paths::p(src_path)) {
        let _ = crate::state::atomic_write(&bak_path, &orig, 0o600);
    }
}

fn write_atomic(path: &str, contents: &str, mode: u32) -> Result<(), String> {
    crate::state::atomic_write(Path::new(path), contents.as_bytes(), mode)
}

fn reconcile_mobileap_xml(actions: &mut Vec<String>, warnings: &mut Vec<String>) {
    let xml_path = "/etc/data/mobileap_cfg.xml";
    let Ok(text) = fs::read_to_string(crate::paths::p(xml_path)) else {
        return;
    };
    if text.contains("<EnableSIPAlg>1</EnableSIPAlg>") {
        backup_once(xml_path);
        let updated = text.replace("<EnableSIPAlg>1</EnableSIPAlg>", "<EnableSIPAlg>0</EnableSIPAlg>");
        match write_atomic(xml_path, &updated, 0o644) {
            Ok(()) => actions.push("Set EnableSIPAlg=0 in /etc/data/mobileap_cfg.xml".into()),
            Err(e) => warnings.push(e),
        }
    }
}

fn reconcile_qualcomm_scripts(actions: &mut Vec<String>, warnings: &mut Vec<String>) {
    // 1. /etc/data/ippt.sh guard against empty profile_idx syslog storm
    let ippt_path = "/etc/data/ippt.sh";
    if let Ok(ippt) = fs::read_to_string(crate::paths::p(ippt_path))
        && let Some(patched) = patch_ippt_text(&ippt)
        && patched != ippt
    {
        backup_once(ippt_path);
        if validate_sh_syntax(&patched) {
            match write_atomic(ippt_path, &patched, 0o755) {
                Ok(()) => actions.push("Patched /etc/data/ippt.sh empty profile_idx guard".into()),
                Err(e) => warnings.push(e),
            }
        }
    }

    // 2. /etc/data/lanUtils.sh merge (.ttl/.mtu/.custom) + sourced CLI guard
    let lu_path = "/etc/data/lanUtils.sh";
    if let Ok(lu) = fs::read_to_string(crate::paths::p(lu_path)) {
        let mut updated = lu.clone();
        let mut changed = false;
        if !updated.contains("local custom_firewall_file=/etc/firewall.user.custom") {
            let candidate = patch_lanutils_merge(&updated);
            if candidate != updated {
                updated = candidate;
                changed = true;
            }
        }
        if !updated.contains("sdxpinn-patch: guard lanUtils sourced dispatch") {
            let candidate = guard_sourced_case(&updated, "lanUtils.sh", "sdxpinn-patch: guard lanUtils sourced dispatch");
            if candidate != updated {
                updated = candidate;
                changed = true;
            }
        }
        if changed && validate_sh_syntax(&updated) {
            backup_once(lu_path);
            match write_atomic(lu_path, &updated, 0o755) {
                Ok(()) => {
                    actions.push("Patched /etc/data/lanUtils.sh".into());
                    let _ = Command::new(crate::paths::p("/bin/sh"))
                        .args(["-c", &format!(". {} && util_combine_iptable_rules", crate::paths::p(lu_path))])
                        .output();
                }
                Err(e) => warnings.push(e),
            }
        }
    }

    // 3. /etc/data/lan_config.sh sourced CLI guard
    let lc_path = "/etc/data/lan_config.sh";
    if let Ok(lc) = fs::read_to_string(crate::paths::p(lc_path))
        && !lc.contains("sdxpinn-patch: guard lan_config sourced dispatch")
    {
        let updated = guard_sourced_case(
            &lc,
            "lan_config.sh",
            "sdxpinn-patch: guard lan_config sourced dispatch",
        );
        if updated != lc && validate_sh_syntax(&updated) {
            backup_once(lc_path);
            match write_atomic(lc_path, &updated, 0o755) {
                Ok(()) => actions.push("Patched /etc/data/lan_config.sh sourced guard".into()),
                Err(e) => warnings.push(e),
            }
        }
    }

    // 4. QCMAP log level suppression (avoid excessive syslog flood)
    if let Some(level) = uci_get_blocking("ql_cust_config.@qcmap_configs[0].log_config")
        && (level == "5" || level == "6")
    {
        let _ = run_cmd_blocking("uci", &["set", "ql_cust_config.@qcmap_configs[0].log_config=2"]);
        let _ = run_cmd_blocking("uci", &["commit", "ql_cust_config"]);
        actions.push(format!("Quiet QCMAP log_config=2 (was {level})"));
    }
}

fn validate_sh_syntax(script: &str) -> bool {
    use std::io::Write;
    let dir_s = crate::paths::p(crate::state::TMP_QM_DIR);
    let dir = Path::new(&dir_s);
    let _ = fs::create_dir_all(dir);
    let seq = std::time::SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = dir.join(format!(".shcheck.{}.{seq}", std::process::id()));
    let ok = match crate::state::create_private_tmp(&tmp, 0o600) {
        Ok(mut f) => {
            f.write_all(script.as_bytes()).is_ok()
                && Command::new(crate::paths::p("/bin/sh"))
                    .arg("-n")
                    .arg(&tmp)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
        }
        Err(_) => false,
    };
    let _ = fs::remove_file(&tmp);
    ok
}

const IPPT_ANCHOR: &str = "ippt_enabled=$(uci get qcmap_lan.@profile[$profile_idx].ippt_enable)";

/// Patch /etc/data/ippt.sh. Returns `None` when there is nothing to do:
/// already patched, or the vendor anchor is absent (unknown script version —
/// never touch it then). Line endings of untouched lines are preserved, so
/// re-running on the output is a no-op.
pub fn patch_ippt_text(orig: &str) -> Option<String> {
    if orig.contains("sdxpinn-patch: guard empty profile_idx") {
        return None;
    }
    let mut in_ql_scan = false;
    let mut anchor_found = false;
    for line in orig.lines() {
        if line.starts_with("function ql_update_ippt_dhcp_host()") {
            in_ql_scan = true;
        }
        if in_ql_scan && line.contains(IPPT_ANCHOR) {
            anchor_found = true;
            break;
        }
    }
    if !anchor_found {
        return None;
    }
    let has_empty_case = orig.lines().any(|l| l.trim() == "\"\")");

    let mut out = String::with_capacity(orig.len() + 512);
    let mut in_ql = false;
    let mut skip_if = 0u8;
    for raw in orig.split_inclusive('\n') {
        let line = raw.trim_end_matches(['\n', '\r']);
        if line.starts_with("function ql_update_ippt_dhcp_host()") {
            in_ql = true;
        }
        if in_ql && line.contains("ql_update_ippt_dhcp_host") && line.contains("mac_addr") && skip_if == 0 {
            continue;
        }
        if in_ql && line.contains(IPPT_ANCHOR) {
            for l in [
                "\t# sdxpinn-patch: guard empty profile_idx when IPPT is disabled",
                "\t[ -n \"$profile_idx\" ] || return 0",
                "\tippt_enabled=$(uci -q get qcmap_lan.@profile[$profile_idx].ippt_enable)",
                "\tadap_ippt_mode=$(uci -q get qcmap_lan.@profile[$profile_idx].adap_ippt_mode)",
                "\tif [ \"${adap_ippt_mode:-0}\" -eq 0 ] || [ \"${ippt_enabled:-0}\" -eq 0 ]; then",
                "\t\treturn 0",
                "\tfi",
                "\tlog $(basename \"$0\") \"ql_update_ippt_dhcp_host\" $LINENO \"vlan:${vlan_id}; MAC: ${mac_addr}\"",
            ] {
                out.push_str(l);
                out.push('\n');
            }
            skip_if = 1;
            continue;
        }
        if skip_if == 1 && line.contains("adap_ippt_mode=") {
            continue;
        }
        if skip_if == 1 && line.contains("if [ $adap_ippt_mode -eq 0 ]") {
            skip_if = 2;
            continue;
        }
        if skip_if == 2 {
            if line.trim() == "fi" {
                skip_if = 0;
            }
            continue;
        }
        if in_ql && line.trim() == "esac" {
            in_ql = false;
        }
        if line.trim() == "*)" {
            in_ql = false;
            if !has_empty_case {
                out.push_str("\t\"\")\n\t\t;;\n");
            }
        }
        out.push_str(raw);
    }
    Some(out)
}

fn patch_lanutils_merge(orig: &str) -> String {
    let need_ttl_var = !orig.contains("local ttl_firewall_file=/etc/firewall.user.ttl");
    let need_mtu_var = !orig.contains("local mtu_firewall_file=/etc/firewall.user.mtu");
    let need_custom_var = !orig.contains("local custom_firewall_file=/etc/firewall.user.custom");
    let need_ttl_merge = !orig.contains("cat $ttl_firewall_file >> $firewall_file");
    let need_mtu_merge = !orig.contains("cat $mtu_firewall_file >> $firewall_file");
    let need_custom_merge = !orig.contains("cat $custom_firewall_file >> $firewall_file");

    let mut out = Vec::new();
    let mut done_vars = false;
    let mut done_merges = false;
    for line in orig.lines() {
        let trimmed = line.trim_start();
        if !done_vars && trimmed.starts_with("local firewall_file_to_write=") {
            if need_ttl_var {
                out.push("  local ttl_firewall_file=/etc/firewall.user.ttl");
            }
            if need_mtu_var {
                out.push("  local mtu_firewall_file=/etc/firewall.user.mtu");
            }
            if need_custom_var {
                out.push("  local custom_firewall_file=/etc/firewall.user.custom");
            }
            done_vars = true;
        }
        if !done_merges && trimmed.starts_with("mv $firewall_file $firewall_file_to_write") {
            if need_ttl_merge {
                out.push("  if [ -f \"$ttl_firewall_file\" ]; then");
                out.push("    cat $ttl_firewall_file >> $firewall_file");
                out.push("  fi");
            }
            if need_mtu_merge {
                out.push("  if [ -f \"$mtu_firewall_file\" ]; then");
                out.push("    cat $mtu_firewall_file >> $firewall_file");
                out.push("  fi");
            }
            if need_custom_merge {
                out.push("  if [ -f \"$custom_firewall_file\" ]; then");
                out.push("    cat $custom_firewall_file >> $firewall_file");
                out.push("  fi");
            }
            done_merges = true;
        }
        out.push(line);
    }
    format!("{}\n", out.join("\n"))
}

fn guard_sourced_case(orig: &str, script_name: &str, marker: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut in_case = false;
    let mut added_empty = false;
    for line in orig.lines() {
        if !in_case && line.trim_end() == "case $1 in" {
            out.push(format!("# {marker}"));
            out.push(format!("if [ \"${{0##*/}}\" = \"{script_name}\" ]; then"));
            in_case = true;
        }
        if in_case && !added_empty && line.trim() == "*)" {
            out.push("\t\"\")".into());
            out.push("\t\t;;".into());
            added_empty = true;
        }
        out.push(line.to_string());
        if in_case && line.trim_end() == "esac" {
            out.push("fi".into());
            in_case = false;
        }
    }
    format!("{}\n", out.join("\n"))
}

fn disable_unused_services(actions: &mut Vec<String>) {
    // Preserve mwan3! Only disable noisy/unused vendor daemons.
    let svcs = [
        "quectel-voice-server.init",
        "quectel-slic-daemon.init",
        "start_quectel_slic_daemon",
        "emergencyalert_daemon",
        "miniupnpd",
        "csd_server.init",
        "agm_server.init",
        "init_audio.init",
        "first-boot",
        "ttyd",
        "adbd.init",
        "openvpn",
    ];
    for svc in svcs {
        let init_path = crate::paths::p(&format!("/etc/init.d/{svc}"));
        let enabled = fs::read_dir(crate::paths::p("/etc/rc.d"))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.contains(svc.trim_end_matches(".init"))
            });
        if enabled && Path::new(&init_path).exists() {
            let _ = Command::new(&init_path).arg("stop").output();
            let _ = Command::new(&init_path).arg("disable").output();
            actions.push(format!("Disabled unused service {svc}"));
        }
    }
}

pub fn current_usb_gadget_udc() -> (String, String, bool) {
    let udc_s = crate::paths::p("/sys/kernel/config/usb_gadget/g1/UDC");
    let udc_path = Path::new(&udc_s);
    let current = fs::read_to_string(udc_path)
        .unwrap_or_default()
        .trim()
        .to_string();
    let controller = fs::read_dir(crate::paths::p("/sys/class/udc"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .next()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .unwrap_or_default();
    let adb_present = fs::read_dir(crate::paths::p("/sys/kernel/config/usb_gadget/g1/configs/c.1"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            e.file_name().to_string_lossy().contains("ffs.adb")
                || fs::read_link(e.path())
                    .ok()
                    .is_some_and(|t| t.to_string_lossy().contains("ffs.adb"))
        });
    (current, controller, adb_present)
}

fn adbd_is_running() -> bool {
    let Ok(entries) = fs::read_dir(crate::paths::p("/proc")) else {
        return false;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let ns = name.to_string_lossy();
        if !ns.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = fs::read_to_string(ent.path().join("comm"))
            && comm.trim() == "adbd"
        {
            return true;
        }
    }
    false
}

/// Remove dangling `f* -> .../ffs.adb` symlinks from `usb_gadget/g1/configs/c.1` when `adbd`
/// is disabled so Qualcomm ConfigFS `UDC` bind (`gsi.ecm` + `cser.dun` AT ports) succeeds
/// without exposing ADB.
fn unlink_dangling_ffs_adb() -> bool {
    if adbd_is_running() {
        return false;
    }
    let cfg_dir = crate::paths::p("/sys/kernel/config/usb_gadget/g1/configs/c.1");
    let Ok(entries) = fs::read_dir(&cfg_dir) else {
        return false;
    };
    let mut removed = false;
    for ent in entries.flatten() {
        let p = ent.path();
        let is_adb_link = ent.file_name().to_string_lossy().contains("ffs.adb")
            || fs::read_link(&p)
                .ok()
                .is_some_and(|t| t.to_string_lossy().contains("ffs.adb"));
        if is_adb_link && fs::remove_file(&p).is_ok() {
            removed = true;
        }
    }
    removed
}

pub fn set_usb_gadget_enabled(enable: bool) -> Result<String, String> {
    let udc_s = crate::paths::p("/sys/kernel/config/usb_gadget/g1/UDC");
    let udc_path = Path::new(&udc_s);
    if !udc_path.exists() {
        return Err("USB ConfigFS g1 gadget not present".into());
    }
    let _ = fs::create_dir_all(crate::paths::p("/etc/cellcore"));
    if enable {
        let _ = unlink_dangling_ffs_adb();
        let (current, controller, adb_present) = current_usb_gadget_udc();
        if adb_present {
            return Err("Refusing to bind USB gadget while active ffs.adb is present".into());
        }
        if controller.is_empty() {
            return Err("No USB UDC controller found in /sys/class/udc".into());
        }
        let _ = fs::remove_file(crate::paths::p(USB_DISABLED_MARKER));
        if current != controller {
            fs::write(udc_path, format!("{controller}\n"))
                .map_err(|e| format!("Failed to bind USB UDC: {e}"))?;
        }
        Ok(controller)
    } else {
        let (current, _, _) = current_usb_gadget_udc();
        crate::state::atomic_write(Path::new(USB_DISABLED_MARKER), b"disabled\n", 0o644)
            .map_err(|e| format!("Failed to record USB marker: {e}"))?;
        if !current.is_empty() {
            fs::write(udc_path, "\n").map_err(|e| format!("Failed to unbind USB UDC: {e}"))?;
        }
        Ok(String::new())
    }
}

fn ensure_usb_gadget_bound(actions: &mut Vec<String>, warnings: &mut Vec<String>) -> String {
    if Path::new(&crate::paths::p(USB_DISABLED_MARKER)).exists() {
        return current_usb_gadget_udc().0;
    }
    if unlink_dangling_ffs_adb() {
        actions.push("Unlinked dangling ffs.adb symlink from usb_gadget/g1/configs/c.1".into());
    }
    let (cur, ctrl, adb_present) = current_usb_gadget_udc();
    if !cur.is_empty() || ctrl.is_empty() || adb_present {
        return cur;
    }
    let udc_s = crate::paths::p("/sys/kernel/config/usb_gadget/g1/UDC");
    let udc_path = Path::new(&udc_s);
    if udc_path.exists() {
        match fs::write(udc_path, format!("{ctrl}\n")) {
            Ok(()) => {
                actions.push(format!("Bound USB ConfigFS g1 to {ctrl}"));
                return ctrl;
            }
            Err(e) => warnings.push(format!("USB UDC bind failed: {e}")),
        }
    }
    cur
}

pub fn build_mtu_firewall_script(ifaces: &[String], mtu_val: u32) -> String {
    let mut out = String::new();
    for iface in ifaces {
        let trimmed = iface.trim();
        if !trimmed.starts_with("rmnet_data") && !trimmed.starts_with("wwan") {
            continue;
        }
        if !trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) {
            continue;
        }
        out.push_str(&format!("ip link set {trimmed} mtu {mtu_val}\n"));
        if (1280..1500).contains(&mtu_val) {
            let mss4 = mtu_val - 40;
            let mss6 = mtu_val - 60;
            out.push_str(&format!(
                "iptables -t mangle -C FORWARD -o {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss4} 2>/dev/null || iptables -t mangle -A FORWARD -o {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss4}\n"
            ));
            out.push_str(&format!(
                "iptables -t mangle -C FORWARD -i {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss4} 2>/dev/null || iptables -t mangle -A FORWARD -i {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss4}\n"
            ));
            out.push_str(&format!(
                "ip6tables -t mangle -C FORWARD -o {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss6} 2>/dev/null || ip6tables -t mangle -A FORWARD -o {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss6}\n"
            ));
            out.push_str(&format!(
                "ip6tables -t mangle -C FORWARD -i {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss6} 2>/dev/null || ip6tables -t mangle -A FORWARD -i {trimmed} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss6}\n"
            ));
        }
    }
    out
}

fn reapply_network_policies(actions: &mut Vec<String>, warnings: &mut Vec<String>) {
    // Ethernet PHY speed limit
    if let Some(limit) = uci_get_blocking("cellcore.eth_link.speed_limit")
        && limit != "auto"
    {
        let adv = match limit.as_str() {
            "10" => Some("0x003"),
            "100" => Some("0x00f"),
            "1000" => Some("0x02f"),
            _ => None,
        };
        if let Some(hex_adv) = adv {
            if let Ok(eth_info) = run_cmd_blocking("ethtool", &["eth0"])
                && let Err(reason) = crate::handlers::check_partner_speed_limit(&eth_info, &limit)
            {
                warnings.push(format!("Skipped eth0 speed limit {limit}M: {reason}"));
            } else if run_cmd_blocking("ethtool", &["-s", "eth0", "advertise", hex_adv, "autoneg", "on"])
                .is_ok()
            {
                let _ = run_cmd_blocking("ethtool", &["-r", "eth0"]);
                actions.push(format!("Applied eth0 speed limit {limit}M"));
            } else {
                warnings.push(format!("Failed to apply eth0 limit {limit}M"));
            }
        }
    }

    // TTL / HL (verify both IPv4 --ttl-set and IPv6 --hl-set)
    let ttl_s = crate::paths::p("/etc/firewall.user.ttl");
    let ttl_file = Path::new(&ttl_s);
    if ttl_file.exists() {
        let ttl_content = fs::read_to_string(ttl_file).unwrap_or_default();
        let cur4 = run_cmd_blocking("iptables", &["-t", "mangle", "-S", "POSTROUTING"]).unwrap_or_default();
        let need_v4 = !cur4.contains("--ttl-set");
        let need_v6 = if ttl_content.contains("--hl-set") || ttl_content.contains("ip6tables") {
            let cur6 = run_cmd_blocking("ip6tables", &["-t", "mangle", "-S", "POSTROUTING"]).unwrap_or_default();
            !cur6.contains("--hl-set")
        } else {
            false
        };
        if need_v4 || need_v6 {
            let _ = Command::new("sh").arg(ttl_file).output();
            actions.push("Re-applied /etc/firewall.user.ttl rules".into());
        }
    }

    // MTU + symmetric TCPMSS clamping (verify script & live rules match active rmnet_data* ifaces)
    let mtu_s = crate::paths::p("/etc/firewall.user.mtu");
    let mtu_file = Path::new(&mtu_s);
    if let Ok(content) = fs::read_to_string(mtu_file)
        && let Some(mtu_val) = content
            .split_whitespace()
            .skip_while(|&w| w != "mtu")
            .nth(1)
            .and_then(|v| v.parse::<u32>().ok())
        && (1280..=1500).contains(&mtu_val)
    {
        let m_str = mtu_val.to_string();
        let mut ifaces = detect_wan_rmnet_ifaces_blocking();
        for line in content.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() >= 5 && toks[0] == "ip" && toks[1] == "link" && toks[2] == "set" {
                let cand = toks[3].to_string();
                if (cand.starts_with("rmnet_data") || cand.starts_with("wwan"))
                    && !ifaces.contains(&cand)
                {
                    ifaces.push(cand);
                }
            }
        }
        for iface in &ifaces {
            let _ = run_cmd_blocking("ip", &["link", "set", iface, "mtu", &m_str]);
        }
        if mtu_val < 1500 && !ifaces.is_empty() {
            let desired = build_mtu_firewall_script(&ifaces, mtu_val);
            if !desired.is_empty() && !mtu_script_covers_ifaces(&content, &ifaces) {
                let _ = write_atomic("/etc/firewall.user.mtu", &desired, 0o644);
            }
            let _ = Command::new("sh").arg(mtu_file).output();
        }
        actions.push(format!("Verified WAN MTU={m_str}"));
    }
}

pub(crate) fn mtu_script_covers_ifaces(content: &str, ifaces: &[String]) -> bool {
    if ifaces.is_empty() {
        return true;
    }
    ifaces.iter().all(|iface| {
        let has_rule = |bin: &str, dir: &str| {
            content.lines().any(|line| {
                line.contains(bin)
                    && line.contains(&format!("{dir} {iface} "))
                    && line.contains("TCPMSS")
            })
        };
        has_rule("iptables", "-o")
            && has_rule("iptables", "-i")
            && has_rule("ip6tables", "-o")
            && has_rule("ip6tables", "-i")
    })
}

const LEGACY_KEEP_ALIVE_CRON_MARKER: &str = "/www/cgi-bin/quecmanager/experimental/keep_alive_worker.sh";

pub(crate) fn prune_legacy_crontabs(actions: &mut Vec<String>, warnings: &mut Vec<String>) {
    let cron_path = "/etc/crontabs/root";
    let mapped = crate::paths::p(cron_path);
    let Ok(orig) = fs::read_to_string(&mapped) else {
        return;
    };
    if !orig.contains(LEGACY_KEEP_ALIVE_CRON_MARKER) {
        return;
    }
    let kept: Vec<&str> = orig
        .lines()
        .filter(|line| !line.contains(LEGACY_KEEP_ALIVE_CRON_MARKER))
        .collect();
    let mut updated = kept.join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
    match write_atomic(cron_path, &updated, 0o600) {
        Ok(()) => {
            actions.push("Pruned legacy keep_alive_worker.sh entry from /etc/crontabs/root".into());
            let cron_init = crate::paths::p("/etc/init.d/cron");
            if Path::new(&cron_init).exists() {
                let _ = Command::new(&cron_init).arg("reload").output();
            }
        }
        Err(e) => warnings.push(format!("prune {cron_path}: {e}")),
    }
}

pub fn ensure_uhttpd_loopback(actions: &mut Vec<String>, warnings: &mut Vec<String>) {
    if !Path::new(&crate::paths::p("/etc/init.d/uhttpd")).exists()
        && !Path::new(&crate::paths::p("/etc/config/uhttpd")).exists()
    {
        return;
    }
    let http = uci_get_blocking("uhttpd.main.listen_http").unwrap_or_default();
    let https = uci_get_blocking("uhttpd.main.listen_https").unwrap_or_default();
    let redir = uci_get_blocking("uhttpd.main.redirect_https").unwrap_or_default();

    if http.trim() == "127.0.0.1:8080" && https.trim().is_empty() && redir.trim() == "0" {
        return;
    }

    let cmds = [
        &["set", "uhttpd.main.redirect_https=0"][..],
        &["-q", "delete", "uhttpd.main.listen_https"][..],
        &["-q", "delete", "uhttpd.main.listen_http"][..],
        &["add_list", "uhttpd.main.listen_http=127.0.0.1:8080"][..],
        &["commit", "uhttpd"][..],
    ];
    for args in cmds {
        if let Err(e) = run_cmd_blocking("uci", args)
            && !args.contains(&"delete")
        {
            warnings.push(format!("uci {}: {e}", args.join(" ")));
            return;
        }
    }
    if Path::new(&crate::paths::p("/etc/init.d/uhttpd")).exists() {
        let _ = run_cmd_blocking("/etc/init.d/uhttpd", &["restart"]);
    }
    actions.push("Rebound uhttpd (LuCI-only) to 127.0.0.1:8080".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPPT_VENDOR: &str = "#!/bin/sh\nfunction ql_update_ippt_dhcp_host()\n{\n\tlocal mac_addr=$1\n\tql_update_ippt_dhcp_host mac_addr dbg\n\tippt_enabled=$(uci get qcmap_lan.@profile[$profile_idx].ippt_enable)\n\tadap_ippt_mode=$(uci get qcmap_lan.@profile[$profile_idx].adap_ippt_mode)\n\tif [ $adap_ippt_mode -eq 0 ]; then\n\t\treturn\n\tfi\n\techo done\n}\n\ncase $1 in\n\tupdate)\n\t\tql_update_ippt_dhcp_host $2\n\t\t;;\n\t*)\n\t\techo usage\n\t\t;;\nesac\n";

    #[test]
    fn ippt_patch_is_idempotent() {
        let once = patch_ippt_text(IPPT_VENDOR).expect("anchor present");
        assert!(once.contains("sdxpinn-patch: guard empty profile_idx"));
        assert_eq!(once.matches("\t\"\")\n").count(), 1);
        assert!(once.contains("[ -n \"$profile_idx\" ] || return 0"));
        // second reconcile: nothing to do
        assert_eq!(patch_ippt_text(&once), None);
    }

    #[test]
    fn ippt_without_anchor_is_left_alone() {
        // Unknown vendor version: on the old code this inserted another
        // `"") ;;` before every `*)` on every reconcile.
        let unknown = "#!/bin/sh\ncase $1 in\n\tstart)\n\t\t;;\n\t*)\n\t\t;;\nesac";
        assert_eq!(patch_ippt_text(unknown), None);
        let crlf = "#!/bin/sh\r\ncase $1 in\r\n\t*)\r\n\t\t;;\r\nesac\r\n";
        assert_eq!(patch_ippt_text(crlf), None);
    }

    #[test]
    fn ippt_patch_preserves_line_endings_and_existing_empty_case() {
        let with_empty = IPPT_VENDOR.replace("\t*)\n", "\t\"\")\n\t\t;;\n\t*)\n");
        let p = patch_ippt_text(&with_empty).unwrap();
        assert_eq!(p.matches("\"\")").count(), 1, "existing empty case must not be duplicated");
        let no_trailing_nl = IPPT_VENDOR.trim_end_matches('\n');
        let p2 = patch_ippt_text(no_trailing_nl).unwrap();
        assert!(p2.ends_with("esac"), "no newline normalisation of untouched lines");
    }

    #[test]
    fn usb_gadget_skips_redundant_udc_writes() {
        use std::os::unix::fs::PermissionsExt;
        let env = crate::paths::TestSandbox::new("usb-udc");
        env.write("/sys/class/udc/a600000.dwc3/uevent", "");
        let udc = env.write("/sys/kernel/config/usb_gadget/g1/UDC", "");
        // Make UDC read-only to prove disabling an already-unbound gadget does NOT write "\n" (avoids ENODEV)
        std::fs::set_permissions(&udc, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(set_usb_gadget_enabled(false).unwrap(), "");
        assert!(Path::new(&crate::paths::p(USB_DISABLED_MARKER)).exists());

        // Enabling when UDC already equals controller removes marker without writing UDC
        std::fs::set_permissions(&udc, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&udc, "a600000.dwc3\n").unwrap();
        std::fs::set_permissions(&udc, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(set_usb_gadget_enabled(true).unwrap(), "a600000.dwc3");
        assert!(!Path::new(&crate::paths::p(USB_DISABLED_MARKER)).exists());

        // Cleanup writable permissions so TempDir removal succeeds cleanly
        std::fs::set_permissions(&udc, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn usb_gadget_detects_active_adbd_and_unlinks_dangling_ffs_adb() {
        let env = crate::paths::TestSandbox::new("usb-adb-symlink");
        env.write("/sys/class/udc/a600000.dwc3/uevent", "");
        env.write("/sys/kernel/config/usb_gadget/g1/UDC", "");
        env.write("/sys/kernel/config/usb_gadget/g1/functions/ffs.adb/.keep", "");
        let adbd_comm = env.write("/proc/4242/comm", "adbd\n");
        let cfg = env.root.join("sys/kernel/config/usb_gadget/g1/configs/c.1");
        std::fs::create_dir_all(&cfg).unwrap();
        std::os::unix::fs::symlink(
            "../../../../usb_gadget/g1/functions/ffs.adb",
            cfg.join("f5"),
        )
        .unwrap();

        let (_, _, adb) = current_usb_gadget_udc();
        assert!(adb, "symlink target containing ffs.adb must be detected");
        // While adbd is running, binding UDC is refused to avoid exposing ADB.
        let err = set_usb_gadget_enabled(true).unwrap_err();
        assert!(err.contains("ffs.adb"), "{err}");

        // Once adbd is disabled/stopped, dangling f5 -> ffs.adb is unlinked so UDC binds cleanly.
        std::fs::remove_file(adbd_comm).unwrap();
        assert_eq!(set_usb_gadget_enabled(true).unwrap(), "a600000.dwc3");
        assert!(!cfg.join("f5").exists());
    }

    #[test]
    fn reconcile_skips_unadvertised_eth_speed_limit() {
        let env = crate::paths::TestSandbox::new("reconcile-eth");
        let calls = env.root.join("ethtool.log");
        env.write(
            "/sc01.txt",
            "Settings for eth0:\n\tLink partner advertised link modes:  100baseT/Full\n\t                                     1000baseT/Full\n",
        );
        env.write_exec(
            "/bin/uci",
            "#!/bin/sh\nif [ \"$1\" = \"-q\" ] && [ \"$2\" = \"get\" ] && [ \"$3\" = \"cellcore.eth_link.speed_limit\" ]; then\n  echo \"10\"\nfi\nexit 0\n",
        );
        env.write_exec(
            "/bin/ethtool",
            &format!(
                "#!/bin/sh\necho \"$*\" >> {log}\nif [ \"$1\" = \"eth0\" ]; then cat {sc01}; fi\nexit 0\n",
                log = calls.display(),
                sc01 = env.root.join("sc01.txt").display()
            ),
        );

        let mut actions = Vec::new();
        let mut warnings = Vec::new();
        reapply_network_policies(&mut actions, &mut warnings);
        assert!(warnings.iter().any(|w| w.contains("Skipped eth0 speed limit 10M")), "{warnings:?}");
        assert!(actions.is_empty(), "{actions:?}");
        assert_eq!(std::fs::read_to_string(&calls).unwrap().trim(), "eth0");
    }

    #[test]
    fn raise_sysctl_at_least_does_not_downgrade_higher_value() {
        let env = crate::paths::TestSandbox::new("reconcile-conntrack");
        let p_max = env.write("/proc/sys/net/netfilter/nf_conntrack_max", "65536\n");
        let p_hash = env.write("/sys/module/nf_conntrack/parameters/hashsize", "8192\n");
        let p_lib = env.write("/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal", "0\n");
        let p_est = env.write("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", "432000\n");
        let p_fin = env.write("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait", "120\n");
        let p_tw = env.write("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait", "120\n");
        let rep = run_boot_reconcile(false);
        assert_eq!(std::fs::read_to_string(&p_max).unwrap().trim(), "65536");
        assert_eq!(std::fs::read_to_string(&p_hash).unwrap().trim(), "16384");
        assert_eq!(std::fs::read_to_string(&p_lib).unwrap().trim(), "1");
        assert_eq!(std::fs::read_to_string(&p_est).unwrap().trim(), "7200");
        assert_eq!(std::fs::read_to_string(&p_fin).unwrap().trim(), "30");
        assert_eq!(std::fs::read_to_string(&p_tw).unwrap().trim(), "30");
        assert_eq!(rep.conntrack_max, 65536);
        assert_eq!(rep.conntrack_hashsize, 16384);
    }

    #[test]
    fn mtu_firewall_helper_emits_symmetric_v4_v6_tcpmss_clamping() {
        let script = build_mtu_firewall_script(&["rmnet_data0".into()], 1420);
        assert!(script.starts_with("ip link set rmnet_data0 mtu 1420\n"));
        assert!(script.contains("-o rmnet_data0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380"));
        assert!(script.contains("-i rmnet_data0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380"));
        assert!(script.contains("ip6tables -t mangle"));
        assert!(script.contains("-o rmnet_data0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360"));
        assert!(script.contains("-i rmnet_data0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360"));

        let s1500 = build_mtu_firewall_script(&["rmnet_data0".into()], 1500);
        assert_eq!(s1500, "ip link set rmnet_data0 mtu 1500\n");
        assert!(build_mtu_firewall_script(&["br-lan".into(), "eth0".into()], 1420).is_empty());
    }

    #[test]
    fn reconcile_disables_qcom_dload_mode_and_enables_remoteproc_recovery() {
        let env = crate::paths::TestSandbox::new("reconcile-dload-rproc");
        let p_dload = env.write("/sys/module/qcom_dload_mode/parameters/download_mode", "1\n");
        let p_rproc = env.write("/sys/class/remoteproc/remoteproc0/recovery", "disabled\n");

        let rep1 = run_boot_reconcile(false);
        assert_eq!(std::fs::read_to_string(&p_dload).unwrap().trim(), "0");
        assert_eq!(std::fs::read_to_string(&p_rproc).unwrap().trim(), "enabled");
        assert!(
            rep1.actions
                .iter()
                .any(|a| a == "Disabled Qualcomm xbl_ramdump download_mode (1 -> 0)"),
            "{:?}",
            rep1.actions
        );
        assert!(
            rep1.actions
                .iter()
                .any(|a| a == "Enabled MSS remoteproc0 SSR recovery"),
            "{:?}",
            rep1.actions
        );

        let rep2 = run_boot_reconcile(false);
        assert!(
            !rep2
                .actions
                .iter()
                .any(|a| a.contains("xbl_ramdump") || a.contains("remoteproc0")),
            "second run must be idempotent: {:?}",
            rep2.actions
        );
    }

    #[test]
    fn reconcile_verifies_ipv6_hl_mtu_iface_coverage_and_prunes_legacy_cron() {
        let env = crate::paths::TestSandbox::new("reconcile-v160");
        let sh_log = env.root.join("ttl-run.log");
        env.write(
            "/etc/firewall.user.ttl",
            format!(
                "#!/bin/sh\necho applied >> {}\n# ip6tables -t mangle -A POSTROUTING -o rmnet+ -j HL --hl-set 65\n",
                sh_log.display()
            ),
        );
        // iptables already has --ttl-set, but ip6tables is missing --hl-set -> must re-apply!
        env.write_exec(
            "/bin/iptables",
            "#!/bin/sh\necho '-A POSTROUTING -o rmnet+ -j TTL --ttl-set 65'\nexit 0\n",
        );
        env.write_exec("/bin/ip6tables", "#!/bin/sh\necho '-P POSTROUTING ACCEPT'\nexit 0\n");

        env.write(
            "/etc/crontabs/root",
            "*/5 * * * * /usr/sbin/other_job\n* * * * * /www/cgi-bin/quecmanager/experimental/keep_alive_worker.sh\n",
        );

        let mut actions = Vec::new();
        let mut warnings = Vec::new();
        crate::paths::TEST_ENV.sync_scope(env.env(), || {
            reapply_network_policies(&mut actions, &mut warnings);
            prune_legacy_crontabs(&mut actions, &mut warnings);
        });
        assert!(actions.iter().any(|a| a.contains("firewall.user.ttl")), "{actions:?}");
        assert!(sh_log.exists(), "missing IPv6 --hl-set must trigger re-applying firewall.user.ttl");

        let cron_after = fs::read_to_string(env.root.join("etc/crontabs/root")).unwrap();
        assert!(cron_after.contains("/usr/sbin/other_job"));
        assert!(!cron_after.contains("keep_alive_worker.sh"));
        assert!(actions.iter().any(|a| a.contains("keep_alive_worker.sh")));

        let s0 = build_mtu_firewall_script(&["rmnet_data0".into()], 1428);
        assert!(mtu_script_covers_ifaces(&s0, &["rmnet_data0".into()]));
        assert!(!mtu_script_covers_ifaces(&s0, &["rmnet_data0".into(), "rmnet_data1".into()]));
        assert!(!mtu_script_covers_ifaces(&s0, &["rmnet_data1".into()]));
    }
}
