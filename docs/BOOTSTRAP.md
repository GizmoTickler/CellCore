# Bootstrapping a Brand-New RM551E-GL (SDX75) From Scratch

This guide takes a **factory-new or freshly flashed Quectel RM551E-GL / SDX75** modem to a fully provisioned **CellCore** appliance — using only clean-room, cryptographically verified CellCore tooling (zero third-party rootfs patch scripts), with **preflight safety checks**, **dry-run validation**, and **1-command reversible rollback** back to stock factory firmware.

> **Need to flash firmware over USB first?** See [FLASHING.md](./FLASHING.md) for the clean-room USB flash + EFS backup/restore workflow (`scripts/flash-modem.sh`) and Zero-USB A/B flashing (`cellctl firmware-flash`) on `R02A02+` modems.

---

## Why a Bootstrap Step Is Needed

Out of the box, Qualcomm/Quectel SDX75 firmware boots with:
1. **Read-only root filesystem (`ubi0:rootfs` at `/`):** `opkg` cannot install packages to `/usr/sbin` or `/www`.
2. **Large writable `/usrdata` partition (~260 MiB):** Designed to hold persistent user data.
3. **No custom `opkg` architecture (`sdxpinn`), `usign` public key, or `CellCore-repo` feed.**

CellCore solves this cleanly using its built-in Rust **`cellcored overlay`** subcommand (`libc::mount` + `SYS_pivot_root` — no third-party shell scripts):
- At early boot (`START=03`), `/usrdata/bin/cellcored overlay pivot` mounts a Linux `overlayfs` (`lowerdir=/`, `upperdir=/usrdata/cellcore-rootfs`, `workdir=/usrdata/cellcore-rootfs-work`) and pivots `/` cleanly while preserving the untouched factory `ubi0:rootfs` read-only at `/real_rootfs`.
- At late boot (`START=13`), `/usrdata/bin/cellcored overlay remount-rw` ensures `/` and `/etc/rc.d` stay read-write before `cellcored` starts.
- Because factory `ubi0:rootfs` stays untouched (except two tiny init scripts that `--revert` cleanly removes), the entire bootstrap is **100% reversible**.

---

## Cryptographic Verification Guarantees

Before writing anything to the modem, `bootstrap.sh` enforces:
1. **`usign` signature verification** on `feed/Packages.sig` against the pinned CellCore public key (`14647e6bee9674ba`).
2. **Double SHA-256 verification** on `sdxpinn-cellcore_*.ipk` — checked locally against the signed `Packages` stanza, then re-verified on the modem after push before running `opkg install`.
3. **Fail-closed `--config-bundle` inspection** — rejects absolute paths (`/etc/...`), path traversal (`..`), symlinks, hardlinks, device nodes, FIFOs, and any path outside the strict allowlist (`etc/config/`, `etc/cellcore/`, `etc/ssl/acme/`, `etc/dropbear/authorized_keys`, `etc/rc.local`, `etc/crontabs/`), plus remote SHA-256 verification before extraction.
4. **SSH MITM protection** — uses `StrictHostKeyChecking=accept-new` in `--ssh` mode.

---

## Prerequisites

- **Hardware:** RM551E-GL in an M.2-to-USB/Ethernet carrier board connected to your workstation via USB (for initial ADB) or Ethernet (if SSH is already enabled).
- **Tools on your workstation:** `adb` (Android Platform Tools) or `ssh`, `curl`, `tar`, `python3`, and `usign` (Linux x86_64 also uses the SHA-256-verified bundled `scripts/feed/usign_x64`).
- **Unlocking ADB on a stock modem (if `adb devices` is empty):**
  1. Connect over the USB AT serial port (e.g., `/dev/ttyUSB2`) at `115200 8N1`.
  2. Query the challenge key (`AT+QADBKEY?`), unlock ADB (`AT+QADBKEY="<key>"`), enable ADB in USB composition (`AT+QCFG="usbcfg",0x2C7C,0x0125,1,1,1,1,1,1,1`), and reboot (`AT+CFUN=1,1`).
  3. Confirm root shell: `adb devices` lists the modem as `device`, and `adb shell id` prints `uid=0(root)`.

---

## Step 1 — Dry-Run Preflight (Zero Changes Written)

Clone CellCore and run a non-destructive dry-run. `--dry-run` validates all local inputs (`--config-bundle`, `--lan-ip`, `--hostname`, `--mbn`, `--lan-gw-ip`, `--root-shadow`), verifies `Packages.sig` + `.ipk` SHA-256, and prints the exact planned steps (connecting to inspect mounts/space if a modem is attached, or running offline validation if not):

```bash
git clone https://github.com/GizmoTickler/CellCore.git
cd CellCore

# Over USB ADB (factory-fresh modem):
./bootstrap.sh --adb --auto-overlay --dry-run

# Or over SSH (if SSH is already reachable):
./bootstrap.sh --ssh root@192.168.225.1 --dry-run
```

Confirm you see `arch=aarch64`, `uid=0`, and at least **32 MiB** free on `/usrdata` (stock modems typically have ~240–260 MiB free).

---

## Step 2 — Run the Clean-Room Bootstrap

### Basic Factory Bootstrap

```bash
# Over USB ADB (pivots clean-room overlay on factory RO rootfs & installs SSH key):
./bootstrap.sh --adb --auto-overlay --ssh-key ~/.ssh/id_ed25519.pub

# Over SSH on an already-writable rootfs:
./bootstrap.sh --ssh root@192.168.225.1 --ssh-key ~/.ssh/id_ed25519.pub
```

### Full Zero-Touch Provisioning (All Composable Flags)

```bash
# Prepare a 0600 file containing a single $6$ / $5$ / $y$ shadow hash:
#   openssl passwd -6 > ./root.shadow && chmod 0600 ./root.shadow

./bootstrap.sh --adb \
  --auto-overlay \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --hostname modem0 \
  --lan-ip 192.168.224.1/24 \
  --at-baseline \
  --mbn Commercial-TMO \
  --lan-gw-ip 192.168.224.1 \
  --config-bundle ./modem-config-bundle.tar.gz \
  --root-shadow ./root.shadow \
  --lockdown
```

### Flag Reference

| Flag | Description |
| --- | --- |
| `--adb` / `--adb-serial <id>` | Connect over USB ADB (optionally selecting a specific serial). |
| `--ssh <user@host>` | Connect over SSH (`StrictHostKeyChecking=accept-new`). |
| `--auto-overlay` / `--stage-overlay-helper` | Opt-in early-boot `/usrdata` overlay pivot when `/` is factory read-only. |
| `--ipk <path>` | Push and install a local `sdxpinn-cellcore` `.ipk` (useful for air-gapped benches). |
| `--ssh-key <path>` | Install SSH public key idempotently into `/etc/dropbear/authorized_keys` (`0600`). |
| `--config-bundle <tar.gz>` | Locally validate allowlisted `/etc` tar.gz, verify SHA-256 on modem, extract to `/`, fix secret permissions (`0600`/`0700`), and restart `cellcored`. |
| `--lan-ip <ip[/prefix]>` | Set UCI `network.lan.ipaddr` (and `network.lan.netmask` converted from `/prefix`, e.g. `/24` → `255.255.255.0`, `/22` → `255.255.252.0`). Reloads network in `--adb` mode; warns and defers to reboot in `--ssh` mode if IP changes so SSH never wedges mid-run. |
| `--hostname <name>` | Validate RFC-1123 hostname and commit UCI `system.@system[0].hostname`. |
| `--at-baseline` | Apply SDX75 Ethernet/5G baseline AT commands via `cellctl at` (fallback `/dev/smd7`): `AT+QCFG="pcie/mode",1` and `AT+QMAPWAC=1`. |
| `--mbn <name>` | With `--at-baseline`: disables MBN AutoSel (`AT+QMBNCFG="AutoSel",0`) and selects `<name>`. |
| `--lan-gw-ip <ip>` | With `--at-baseline`: configures QMAP LAN IP (`AT+QMAP="LANIP",<start>,<end>,<gw>`). |
| `--root-shadow <file>` | Read a single `$5$`/`$6$`/`$y$` crypt hash from a `0600` file, update `/etc/shadow` atomically without echoing to stdout or `ps`, and immediately remove the temp file. |
| `--lockdown` | Opt-in final step (runs strictly last; never drops ADB mid-run): requires non-empty `/etc/dropbear/authorized_keys`, disables Dropbear password auth (leaving `Interface` unset so LAN/loopback works), disables `ttyd`, and disables `adbd.init`. |
| `--dry-run` | Validate all flags, bundles, hashes, and signatures locally and print the execution plan without modifying the modem. |
| `--revert [--purge]` | Stage reversible rollback to stock factory `ubi0:rootfs`. |

---

## Step 3 — First Login & Verification

1. Open **`https://<lan-ip>/`** (default `https://192.168.225.1/`).
   - **Initial TLS certificate:** If no ACME certificate exists yet, `bootstrap.sh` / `cellcored` generates an **ECDSA P-256 self-signed certificate** at `/etc/cellcore/tls/{cert,key}.pem`.
   - **ACME certificate bundle:** Including `etc/ssl/acme/fullchain.pem` + `etc/ssl/acme/privkey.pem` inside `--config-bundle` applies the trusted cert immediately (`privkey.pem` set to `0600`) and restarts `cellcored`.
2. Verify on the modem:

```sh
cellctl overlay status
cellctl verify
cellctl upgrade --check
```

---

## Reversible Rollback (Return to 100% Stock Factory Rootfs)

Because factory `ubi0:rootfs` stays read-only and untouched at `/real_rootfs`, you can undo the entire bootstrap cleanly at any time:

```bash
# Disable overlay hooks & restore factory opkg config (keeps /usrdata/cellcore-rootfs intact):
./bootstrap.sh --adb --revert

# Full factory clean (also deletes /usrdata/cellcore-rootfs and /usrdata/bin/cellcored):
./bootstrap.sh --adb --revert --purge
```

Or directly on the modem:

```sh
cellctl overlay revert --yes --purge
reboot
```

---

## Troubleshooting

- **Overlay did not activate after reboot:** Inspect `/tmp/cellcore-overlay.log` and run `/usrdata/bin/cellcored overlay status`.
- **Low `/usrdata` space (`< 32 MiB`):** Clean old logs/files under `/usrdata` and re-run `./bootstrap.sh`.
- **Offline / air-gapped install:** Pass `--ipk ./feed/sdxpinn-cellcore_<version>_sdxpinn.ipk` to install over USB ADB or SSH without WAN connectivity.
- **`--lockdown` refused:** Ensure you pass `--ssh-key` (or include `etc/dropbear/authorized_keys` in `--config-bundle`) so key-based SSH is guaranteed before disabling password authentication.
