# CellCore Signed Feed (`feed/`) Provenance & Security Notes

This directory hosts the `usign`-signed `opkg` package feed (`CellCore-repo`) for Quectel RM55x / SDX75 (`sdxpinn` / `aarch64_cortex-a53`) gateways.

## Feed Signing Key

- **Public key file:** `feed/usign.pub`
- **Key ID:** `14647e6bee9674ba`
- **Public key:** `RWQUZH5r7pZ0ulLC3JfaotxtUoYnUmTrN5IzN8RmZXI1xGURn1z+EKfl`

Verify the feed index and any package before installation:

```sh
usign -V -m feed/Packages -x feed/Packages.sig -p feed/usign.pub
sha256sum feed/<package>.ipk
```

---

## Bundled Third-Party Packages

None of the third-party `.ipk` archives below are installed automatically by `sdxpinn-cellcore`. They are optional packages kept in the signed feed only for operators who explicitly opt in.

### 1. `ookla-speedtest` (v1.2.0) — **Optional**

| Field | Value |
| --- | --- |
| Filename | `ookla-speedtest_1.2.0_aarch64_cortex-a53.ipk` |
| Architecture | `aarch64_cortex-a53` |
| Size | 1,075,696 bytes |
| SHA-256 | `ebe16686e6cf4e0753679d0bbb6e7010e37df61d58690a22c0f421002dfdda82` |
| MD5 | `b26e1909599f73cab40ea0281c5a6283` |
| Upstream / Origin | Ookla Speedtest CLI (`https://www.speedtest.net/apps/cli`), proprietary prebuilt `aarch64` binary packaged as an OpenWrt `.ipk` (`/usr/bin/speedtest`) |
| License | Proprietary (Ookla EULA) |

**Security & Dependency Note:**
- Removed from `sdxpinn-cellcore`'s `Depends:` list in v1.8.0 so it is **strictly optional** and no longer installed by default.
- The proprietary v1.2.0 binary statically links legacy **mbed TLS 3.1.0**.
- CellCore ships a built-in native Rust Cloudflare speedtest engine (using up-to-date TLS) as the default speedtest backend, and gracefully detects `/usr/bin/speedtest` at runtime only if an operator explicitly installs `ookla-speedtest`.

### 2. `tailscale-tiny` (v1.104.7) — **Optional**

| Field | Value |
| --- | --- |
| Filename | `tailscale-tiny_1.104.7_aarch64_cortex-a53.ipk` |
| Architecture | `aarch64_cortex-a53` |
| Size | 7,687,602 bytes |
| SHA-256 | `8b513f2395c60e104063d115468645cab2cf2ef83afe1248f6e84e66cf3ebd70` |
| MD5 | `ca8f5a9664c8f06020090c5d8e8d498a` |
| Upstream / Origin | `feeds/packages/net/tailscale` (`tiny-tailscale` stripped combined static binary with 25 features kept, packaged by Cameron Thompson `iamromulan@github`) |
| License | BSD-3-Clause |
| Depends | `ca-bundle`, `kmod-tun` |

**Notes:**
- Installed only when explicitly requested by the operator (via the Network › Tailscale UI or `opkg install tailscale-tiny`).
- Ships `/usr/sbin/tailscaled`, `/usr/bin/tailscale`, `/etc/init.d/tailscale`, `/etc/config/tailscale`, and `/lib/upgrade/keep.d/tailscaled`.

### 3. `wgcf` (v2.3.1) — **Optional**

| Field | Value |
| --- | --- |
| Filename | `wgcf_2.3.1_aarch64_generic.ipk` |
| Architecture | `aarch64_generic` |
| Size | 5,187,850 bytes |
| SHA-256 | `4d519459b278a1d5e1f0262c678b585ce776fb1e87d7e95929486c7724653a67` |
| MD5 | `9b6255f130699886d9dc60aefca28001` |
| Upstream / Origin | `https://github.com/ViRb3/wgcf/releases` (v2.3.1, unofficial Cloudflare WARP CLI, packaged as `/usr/bin/wgcf`) |
| License | MIT |
| Depends | `libc` |

**Notes:**
- Installed only when explicitly requested by the operator (via the Network › WARP UI or `opkg install wgcf`).

---

## Removed Packages

### `kmod-wireguard` (v1) — **Removed in v1.8.0**

- Former filename: `kmod-wireguard_1_sdxpinn.ipk` (789 bytes, SHA-256 `fc2f24bfdaf9245ca2809d7a2b20a4bc9a789ab08a835ea54ed84fabfaafd1ac`).
- Reason for removal: Broken placeholder stub that depended on the obsolete `sdxpinn-patch` package and only created an empty `/tmp/kmod-wireguard.reg` marker. WireGuard is compiled directly into the SDX75 kernel, so no stub kernel-module IPK is needed.
