# Bootstrapping a Brand-New RM551E-GL (SDX75) From Scratch

This guide takes a **factory-new Quectel RM551E-GL / SDX75** modem out of the box to a fully running **CellCore** appliance — using only clean-room CellCore tooling, with **preflight safety checks**, **dry-run support**, and **1-command reversible rollback** back to stock factory firmware.

---

## Why a Bootstrap Step Is Needed

Out of the box, Qualcomm/Quectel SDX75 firmware boots with:
1. **Read-only root filesystem (`ubi0:rootfs` at `/`):** `opkg` cannot install packages to `/usr/sbin` or `/www`.
2. **Large writable `/usrdata` partition (~260 MiB):** Designed to hold persistent user data.
3. **No custom `opkg` architecture (`sdxpinn`), signing key, or `CellCore-repo` feed.**

CellCore solves this cleanly using its built-in Rust **`cellcored overlay`** subcommand (`libc::mount` + `SYS_pivot_root` — no third-party shell scripts):
- At early boot (`START=03`), `/usrdata/bin/cellcored overlay pivot` mounts a Linux `overlayfs` (`lowerdir=/`, `upperdir=/usrdata/cellcore-rootfs`, `workdir=/usrdata/cellcore-rootfs-work`) and pivots `/` cleanly while preserving the untouched factory `ubi0:rootfs` read-only at `/real_rootfs`.
- At late boot (`START=13`), `/usrdata/bin/cellcored overlay remount-rw` ensures `/` and `/etc/rc.d` stay read-write before `cellcored` starts at `START=14`.
- Because factory `ubi0:rootfs` is never modified (except two tiny init scripts that `revert` cleanly removes), the entire bootstrap is **100% reversible**.

---

## Prerequisites

- **Hardware:** RM551E-GL in an M.2-to-USB/Ethernet carrier board connected to your computer via USB (for initial ADB) or Ethernet (if SSH is already enabled).
- **Tools on your workstation:** `adb` (Android Platform Tools) or `ssh`, `curl`, and `tar`.
- **Unlocking ADB on a stock modem (if `adb devices` is empty):**
  1. Connect over the USB AT serial port (e.g., `/dev/ttyUSB2` or Windows COM port) at `115200 8N1`.
  2. Query the challenge key: `AT+QADBKEY?` and unlock ADB with your Quectel ADB response key (`AT+QADBKEY="<key>"`), then enable ADB in USB composition: `AT+QCFG="usbcfg",0x2C7C,0x0125,1,1,1,1,1,1,1` (or carrier-appropriate PID) and reboot (`AT+CFUN=1,1`).
  3. Confirm root shell: `adb devices` should list your modem as `device`, and `adb shell id` should print `uid=0(root)`.

---

## Step 1 — Dry-Run Preflight (Zero Changes Written)

Clone CellCore on your workstation and run a non-destructive preflight check:

```bash
git clone https://github.com/GizmoTickler/CellCore.git
cd CellCore

# Over USB ADB (factory-fresh modem):
./bootstrap.sh --adb --dry-run

# Or over SSH (if SSH is already reachable):
./bootstrap.sh --ssh root@192.168.225.1 --dry-run
```

Confirm you see `arch=aarch64`, `uid=0`, and at least **32 MiB** free on `/usrdata` (stock modems typically have ~240–260 MiB free).

---

## Step 2 — Run the Clean-Room Bootstrap

```bash
# Over USB ADB (recommended for brand-new modems; optionally installs your SSH key):
./bootstrap.sh --adb --ssh-key ~/.ssh/id_ed25519.pub

# Or over SSH:
./bootstrap.sh --ssh root@192.168.225.1 --ssh-key ~/.ssh/id_ed25519.pub
```

### What `bootstrap.sh` Does Automatically
1. **Backs up factory config** (`/etc/opkg.conf` & `/etc/opkg/customfeeds.conf`) to `/usrdata/cellcore-factory-backup/`.
2. **Stages static `cellcored`** (`aarch64-unknown-linux-musl`) to `/usrdata/bin/cellcored` (used before overlay mount at `START=03`).
3. **Installs reversible overlay hooks** (`S03cellcore-overlay` & `S13cellcore-overlay-rw`) if `/` is still read-only, reboots once, waits for reconnect, and verifies `root_writable=1`. *(Skipped automatically if a writable overlay is already active.)*
4. **Configures `opkg` & SSH:** Adds `arch sdxpinn 100`, installs CellCore's `usign` public key (`14647e6bee9674ba`), points `/etc/opkg/customfeeds.conf` to `CellCore-repo`, enables Dropbear SSH, and installs your `--ssh-key`.
5. **Installs & verifies `sdxpinn-cellcore`:** Runs `opkg update && opkg install sdxpinn-cellcore` and verifies `cellctl verify --expect-wan 0`.

---

## Step 3 — First Login & Setup

1. Open **`https://<lan-ip>/`** (default `https://192.168.225.1/`).
2. Set a strong root password if still on factory defaults (`System → Security & Units`, or `passwd` over SSH).
3. Configure your carrier APN / SIM profile (`Radio → Profiles & MBN`).
4. *(Optional)* Switch to the pure-Rust QRTR/QMI data plane under **`Network → Data Plane`**, configure your Home location & tower pin under **`Radio → Antenna Aim`**, and mint a read-only Bearer token under **`System → Security & Units`** for Prometheus `/api/v1/metrics`.

---

## Verification Commands (On the Modem)

```sh
# Check overlay state, backing partition, and free space
cellctl overlay status
cellctl overlay status --json

# Verify daemon health, HTTP/2 TLS, AT actor, and WAN bearer
cellctl verify

# Check signed feed updates
cellctl upgrade --check
```

---

## Reversible Rollback (Return to 100% Stock Factory Rootfs)

Because factory `ubi0:rootfs` stays read-only and untouched at `/real_rootfs`, you can undo the entire bootstrap cleanly at any time:

```bash
# Disable overlay hooks & restore factory opkg config (keeps /usrdata/cellcore-rootfs intact in case you re-enable):
./bootstrap.sh --adb --revert

# Full factory clean (also deletes /usrdata/cellcore-rootfs and /usrdata/bin/cellcored):
./bootstrap.sh --adb --revert --purge
```

Or directly on the modem over SSH/ADB:

```sh
cellctl overlay revert --yes --purge
reboot
```

After one reboot, the modem boots cleanly back into its untouched factory `ubi0:rootfs`.

---

## Troubleshooting

- **Overlay did not activate after reboot:** Inspect `/tmp/cellcore-overlay.log` and run `/usrdata/bin/cellcored overlay status`.
- **Low `/usrdata` space (`< 32 MiB`):** Clean old logs or files under `/usrdata` and re-run `./bootstrap.sh`.
- **Offline / air-gapped install (no internet on the modem yet):** Pass `--ipk ./feed/sdxpinn-cellcore_1.0.0-1_sdxpinn.ipk` to `./bootstrap.sh` to push and install the `.ipk` directly over USB/SSH without needing WAN connectivity first!
