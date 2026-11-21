# CellCore 4.2.0 Native Rust Data Plane

CellCore 4.2.0 adds a clean-room Rust `AF_QIPCRTR` QMI + `RTNETLINK` data-plane supervisor inside `cellcored` ([`dataplane.rs`](../crates/cellcored/src/dataplane.rs), [`netlink.rs`](../crates/cellcored/src/netlink.rs), [`qmi/`](../crates/cellcored/src/qmi/mod.rs)) paired with the **Network › Data Plane** UI (`#/network/dataplane`, [`DataPlaneView.tsx`](../src/pages/network/DataPlaneView.tsx)).

## Control Modes

| Mode | Behaviour | Vendor Daemons (`QCMAP` / `netmgrd`) |
|---|---|---|
| `coexist` (boot default) | Opens read-only `AF_QIPCRTR` QMI clients (`DMS`, `NAS`, `UIM`, `WDA`, `WDS`) and observes kernel links, addresses, and routes via `RTNETLINK`. | Untouched — vendor connection manager retains bearer control. |
| `native` (opt-in, `confirm: "NATIVE"`) | Stops vendor CM init scripts and pauses active `/etc/init.d/mwan3`, keeps `/dev/ipa` and `ipacm` active, creates the configured `rmnet_data*` child link on `rmnet_ipa0` via `RTNETLINK` if absent (re-applying High-Throughput RPS and cleaning up daemon-created links before returning to `coexist`), binds QMI WDS MUX ports, starts dual-stack IPv4/IPv6 bearers with `5s -> 10s -> 20s -> 40s -> 60s` backoff and QRTR SSR recovery, and programs links/routes directly over `RTNETLINK`. | Stopped on entry; `netmgrd`, `QCMAP`, and any paused `mwan3` are restarted automatically when switching back to `coexist`. |

`qrtr.rs` auto-detects the modem DSP QRTR node from advertised core QMI services (`WDS`, `DMS`, `NAS`, `UIM`, `WDA`) across firmware layouts (such as node `0` on `R01A04` and node `3` on `R02A02`), with `QM_QRTR_MODEM_NODE` available as an explicit environment override.

## Native Bearer, Carrier & IPAv5 Integration

- **Hardware IPAv5 & IOSS telemetry**: reads `/sys/kernel/debug/ipa/*` (`hw_type`, `clk_rate`, `enable_clock_scaling`, `clock_scaling_bw_threshold_nominal_mbps`, `clock_scaling_bw_threshold_turbo_mbps`, `enable_napi_chain`, `eth/status`) and `/sys/kernel/debug/ioss/devices/eth0/statistics` (`hwp_rx_packets`, `exp_rx_packets`, `hwp_tx_packets`, `exp_tx_packets`).
- **Dual-stack & DSP 464XLAT**: On carriers where the SDX75 DSP runs 464XLAT internally (for example T-Mobile over `rmnet_data*`), QMI WDS provides both IPv4 CLAT parameters and native IPv6 `/64` parameters without a Linux `nat46` kernel module.
- **`rmnet` child links & MUX auto-resolution**: When `netmgrd` stops in `native` mode, `netlink::create_rmnet_link` creates missing `rmnet_data*` child interfaces on `rmnet_ipa0` via `RTM_NEWLINK` (`IFLA_LINK` + nested `rmnet` `IFLA_RMNET_MUX_ID`), and `delete_rmnet_link` (`RTM_DELLINK`) removes only daemon-created links prior to `netmgrd` restart. `resolve_rmnet_link` matches `iface` or non-zero `rmnet_mux_id`; `apply_native_netlink` sets the link up at the max family MTU and installs IPv4/IPv6 default routes with locked `RTA_METRICS` (`RTAX_LOCK` bit `1 << 2` + `RTAX_MTU` for MTUs in `576..=9216`).
- **Reversible runtime NAT & forward handling**: When `!cfg.ippt` and an active bearer comes up, `apply_native_nat` installs an isolated `table inet qm_native_nat` (IPv4 masquerade on `oifname "<iface>"`) plus `comment "qm_native"` accept rule in `inet fw4 accept_to_wan` if `fw4` does not already cover `<iface>` (falling back to `-m comment --comment qm_native` `iptables` rules on `fw3` boards), and `teardown_native_nat` removes them on IPPT toggle, reconfiguration, or return to `coexist`.
- **`r10-modem-ctl` & session uptime fallback**: When `netifd` `wan`/`wan_v6` are down in `native` mode, `ipc.rs`, `cli.rs`, and `telemetry.rs` inspect live `RTNETLINK` links and addresses (`detect_active_rmnet_wan_live`) and report `wan_up=1` with `l3_device` and native uptime whenever an `UP + LOWER_UP` `rmnet_data*` interface carries a non-link-local IPv4 or IPv6 address; `r10-modem-ctl` `wan-restart` / `modem-reset` also call `trigger_native_reconnect_if_active()` in `native` mode.
- **QMI DNS handoff & IPv6 DNS host routes**: When `manageDns` is `true` in `native` mode, runtime WDS IPv4/IPv6 DNS servers are written to `/tmp/resolv.conf.d/resolv.conf.auto` and `/tmp/resolv.conf.d/resolv.conf.lan.auto` (`0o644` via crash-safe `state::atomic_write`) followed by `/etc/init.d/dnsmasq reload`, and `/128` host routes (metric `1024`) are added for IPv6 DNS resolvers on the cellular interface. Teardown or `manageDns: false` restores prior resolv snapshots.
- **Hardware IPAv5 IP Passthrough & IPv6 prefix sharing** (via `/usr/bin/ipa` when present):
  - `ippt: true` (requires a valid unicast `ipptMac` in `native` mode): programs `ipa ippass enable dev_type <eth0|eth1|usb|any> vlan <id> mac <mac> skip_nat <0|1> default_pdn 1 dev_name <iface>` and installs a `/32` `RT_SCOPE_LINK` passthrough host route on `br-lan`.
  - `ipv6PrefixSharing: true`: derives the global/ULA `/64` prefix and programs `ipa idu_ipv6_config sharing ipv6_prefix <prefix64> ipv6_mask ffff:ffff:ffff:ffff pdn_name <iface>`.
  - Mode exit, IP change, or config change tears down previous IPA rules, host routes, and managed DNS cleanly before re-applying.

## Reversible High-Throughput Kernel Profile

Selecting `kernelTuning: "high-throughput"` captures the current values once into `BASELINE_SYSCTLS` and applies `HIGH_THROUGHPUT_SYSCTLS` (skipping sysfs nodes not present on a board):

| Parameter / Queue | Value |
|---|---|
| `/proc/sys/net/core/default_qdisc` | `fq_codel` |
| `/proc/sys/net/core/rmem_max`, `wmem_max` | `16777216` (16 MiB) |
| `/proc/sys/net/ipv4/tcp_rmem`, `tcp_wmem` | `4096 131072 16777216`, `4096 65536 16777216` |
| `/proc/sys/net/core/netdev_max_backlog`, `netdev_budget` | `16384`, `1200` |
| `/proc/sys/net/ipv4/tcp_slow_start_after_idle`, `tcp_mtu_probing`, `tcp_fastopen` | `0`, `1`, `3` |
| `/proc/sys/net/core/rps_sock_flow_entries`, `/proc/sys/net/netfilter/nf_conntrack_max` | `32768`, `65536` |
| `eth0` queues (`rx-0/rps_cpus`, `rx-0/rps_flow_cnt`, `tx-0/xps_cpus`) | `e`, `4096`, `c` |
| `rmnet_ipa0` queues (`rx-0..3/rps_*`, `tx-0..3/xps_cpus`) | RPS `e` / `4096`, XPS `1` / `2` / `4` / `8` |
| `rmnet_data0` queues (`rx-0/rps_cpus`, `rx-0/rps_flow_cnt`) | `e`, `4096` |
| `/sys/devices/system/cpu/cpu0..cpu3/cpufreq/scaling_governor` | `performance` |

Switching back to `kernelTuning: "default"` restores every captured baseline value. Config persists atomically (`0o600` via `save_json_atomic`) at `/etc/cellcore/dataplane.json`.

## Safety Guards & Validation

- **Protected interfaces** (`netlink::validate_managed_iface`): only `rmnet_data*` or `wwan*` are allowed; `lo`, `eth0`, `br-lan`, and `rmnet_ipa0` are rejected.
- **Protected routing tables** (`netlink::validate_managed_table`): `0`, `255` (`TABLE_LOCAL`), and `51820` (`TABLE_WARP`) are rejected.
- **Passthrough bridge allowlist** (`netlink::validate_passthrough_bridge`): only `br-lan` or `br-lan<digits>`.
- **Input validation**: strict `deny_unknown_fields` JSON schema, unicast non-zero/non-broadcast MAC check (`validate_unicast_mac`), `ipptDevType` allowlist (`eth0`, `eth1`, `usb`, `any`), `ipptVlan <= 4094`, `epType` `1..=16`, `muxId` `1..=254`, and `profileIndex` `1..=24`. Changing `iface` automatically syncs `muxId` from the resolved `NetlinkLink` unless `muxId` is explicitly supplied in the request.

## HTTP API

| Endpoint | Method | Auth / RBAC | Notes |
|---|---|---|---|
| `/api/v1/dataplane/status` | `GET` | Read or RW | Returns `config` and live `snapshot` (QRTR, WDS v4/v6, Netlink links/addrs/routes, kernel telemetry, IPA/IOSS offload, `ipaCliPresent`, `appliedDns`, `ipaIpptActive`, `ipaV6SharingPrefix`). |
| `/api/v1/dataplane/profiles` | `GET` | Read or RW | Returns sanitized 3GPP WDS profiles read over QRTR (no raw password field). |
| `/api/v1/dataplane/config` | `POST` | RW (`403` for Read token) + `X-QM-CSRF` for cookies | Updates mode, bearer, IPPT, DNS, IPv6 sharing, and `kernelTuning`. Switching `coexist -> native` requires `confirm: "NATIVE"` (`428` otherwise). |
| `/api/v1/dataplane/reconnect` | `POST` | RW (`403` for Read token) + `X-QM-CSRF` for cookies | Optional JSON body (`{ "family": "all" \| "ipv4" \| "ipv6" }`); wakes supervisor immediately. |
