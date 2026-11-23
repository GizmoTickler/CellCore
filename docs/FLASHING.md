# Flashing Quectel RM551E-GL (SDX75) Firmware — Clean-Room Guide

CellCore owns the entire firmware lifecycle end-to-end with **zero third-party rootfs patch scripts**:

1. **USB Bench Flasher (`scripts/flash-modem.sh`):** Full Linux (x86_64 & ARM64) and macOS CLI for firmware verification, fail-closed EFS backup & NV 550 IMEI validation, single- or two-stage QFirehose flashing, EFS restore, and automatic `bootstrap.sh` provisioning.
2. **Zero-USB A/B OTA Flashing (`cellctl firmware-flash`):** For modems already running an A/B dual-slot firmware (`R02A02+`, with `system_b` and `boot_b` partitions), you can flash firmware updates directly on-device over SSH/UI without a USB bench cable — see `cellctl firmware-flash --help` once `R02A02+` is installed.

---

## Safety Guarantees Built Into `scripts/flash-modem.sh`

- **Fail-closed firmware verification (`verify-firmware`):** Tests zip container integrity (`unzip -tq`), parses Quectel `md5.txt` (including Windows `\` paths and CRLF endings), streams and verifies the MD5 of **every** listed file, and inspects `rawprogram_nand_*.xml` to classify `factory` vs `update`, partition count, `c_project_name`, and A/B dual-slot support.
- **Fail-closed EFS/IMEI protection (`inspect-xqcn` + `backup`):** Never executes `QFirehose` without a verified `>= 1 MiB` `.xqcn` backup (plus `.tar` backup and `SHA256SUMS`, stored `0700`/`0600`) whose Qualcomm **NV 550** 9-byte BCD IMEI passes Luhn checksum validation and matches `--expected-imei` (when supplied).
- **Masked IMEI output by default:** Displays `•••••••••••1481` unless `--show-imei` is explicitly passed so logs stay safe to share.
- **Zero third-party provisioning scripts:** After flashing and restoring EFS, `flash-modem.sh` invokes CellCore's own signed [`bootstrap.sh`](../bootstrap.sh) (`--adb --auto-overlay --at-baseline ...`).

---

## Step 1 — Check Your Bench Workstation (`doctor`)

```bash
./scripts/flash-modem.sh doctor
```

`doctor` checks:
- Host binaries: `adb`, `QFirehose`/`qfirehose`, `qfenix`, `unzip`, `md5sum`/`md5`, `sha256sum`/`shasum`, `python3`, and `usign` (or SHA-256-verified bundled `scripts/feed/usign_x64`).
- USB devices: Quectel normal/ADB/DIAG mode (`2c7c:*`) and Qualcomm EDL 9008 mode (`05c6:9008`).
- Conflicting host services: warns if `ModemManager` is active (pass `--stop-mm` to stop it automatically) and reports `qcserial` driver status (unbound automatically before `qfenix`/`QFirehose`).

---

## Step 2 — Verify Firmware Packages Offline (`verify-firmware`)

Before plugging in a modem, verify every file MD5 and inspect the partition table:

```bash
./scripts/flash-modem.sh verify-firmware ./RM551EGL00AAR02A02M8G.zip
```

Example output:
```text
firmware_ok=1 verified_files=42 image_type=update c_project_name=RM551EGL00AAR02A02M8G partitions=58 ab_dual_slot=1 rawprogram=rawprogram_nand_p4K_b256K_update.xml
```

- `image_type=factory`: contains `cefs.mbn` or `rawprogram_nand_*_factory.xml` (used for Stage-1 repartitioning with `-e`).
- `ab_dual_slot=1`: firmware includes both `system_b` and `boot_b` slots (supports Zero-USB A/B updates via `cellctl firmware-flash` after flashing).

---

## Step 3 — Capture & Inspect EFS Backups (`backup` & `inspect-xqcn`)

Capture standalone `.xqcn` + `.tar` + `SHA256SUMS` backups (permissions forced to `0700` dir / `0600` files):

```bash
./scripts/flash-modem.sh backup --out ~/modem-backups/modem0 --stop-mm
```

Inspect any existing `.xqcn` (or binary `.qcn`) backup offline:

```bash
# Masked IMEI output (default):
./scripts/flash-modem.sh inspect-xqcn ~/modem-backups/modem0/efs_20261123T000000Z.xqcn

# Verify against an expected IMEI (fail-closed if wrong modem's backup):
./scripts/flash-modem.sh inspect-xqcn ~/modem-backups/modem0/efs_20261123T000000Z.xqcn \
  --expected-imei 352099001761481

# Reveal full IMEI explicitly on a trusted terminal:
./scripts/flash-modem.sh inspect-xqcn ~/modem-backups/modem0/efs_20261123T000000Z.xqcn --show-imei
```

---

## Step 4 — Dry-Run & Execute Full USB Flash + Provisioning (`flash`)

### Scenario A: Two-Stage Partition Migration (e.g. 37-partition `R01` → 58-partition A/B `R02A02`)

Always preview with `--dry-run` first (validates both zips, existing XQCN if supplied, IMEI Luhn, and all `bootstrap.sh` flags + `--config-bundle` without touching USB):

```bash
./scripts/flash-modem.sh flash \
  --factory-zip ./RM551EGL00AAR02A01M8G_factory.zip \
  --firmware ./RM551EGL00AAR02A02M8G_update.zip \
  --backup-dir ~/modem-backups/modem0 \
  --expected-imei 352099001761481 \
  --stop-mm \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --hostname modem0 \
  --lan-ip 192.168.224.1/24 \
  --mbn Commercial-TMO \
  --lan-gw-ip 192.168.224.1 \
  --config-bundle ./modem0-bundle.tar.gz \
  --root-shadow ./root.shadow \
  --lockdown \
  --dry-run
```

Remove `--dry-run` when ready. The exact execution sequence is:
1. Verify Stage-1 `--factory-zip` and Stage-2 `--firmware` MD5 checksums.
2. Capture (or re-verify `--existing-xqcn`) a `>= 1 MiB` `.xqcn` + `.tar` backup with valid NV 550 Luhn IMEI matching `--expected-imei`.
3. Unpack zips into an auto-cleaned `mktemp -d`, stop `ModemManager` (if `--stop-mm`), and unbind `qcserial`.
4. **Stage 1:** `QFirehose -e -f <factory_update_dir>` → wait up to 90s for modem boot & USB re-enumeration.
5. **Stage 2:** `QFirehose -f <target_update_dir>` → wait up to 90s for modem boot & USB re-enumeration.
6. Re-verify `.xqcn` against `--expected-imei`, run `qfenix efsrestore`, send `AT+CFUN=1,1`, wait for re-enumeration, and verify live `AT+CGSN` matches!
7. *(Optional)* Apply `--set-imei <15-digits>` (`AT+EGMR=1,7` + `AT+CFUN=1,1`) if explicitly requested.
8. Run `./bootstrap.sh --adb --auto-overlay --at-baseline ...` with all passthrough flags so the modem finishes 100% provisioned with signed CellCore.

### Scenario B: Single-Stage USB Flash (Same Partition Layout)

```bash
./scripts/flash-modem.sh flash \
  --firmware ./RM551EGL00AAR02A02M8G_update.zip \
  --backup-dir ~/modem-backups/modem0 \
  --stop-mm \
  --ssh-key ~/.ssh/id_ed25519.pub
```

Add `--erase` if you explicitly want `QFirehose -e` on a single-stage flash, or `--skip-bootstrap` to stop right after EFS restore + IMEI verification.

---

## Zero-USB A/B Flashing (`R02A02+` Modems)

Once a modem is running an A/B dual-slot firmware (`ab_dual_slot=1`, such as `R02A02+`) with CellCore installed, future firmware updates do **not** require a USB bench cable or EDL/QFirehose. Use CellCore's on-device A/B flasher (`cellctl firmware-flash`) over SSH or the Web UI to stream and verify images directly to the inactive slot (`boot_b` / `system_b`) with automatic rollback safety.

---

## Running the Automated Test Suite

Verify all flasher & bootstrapper validators offline without needing a modem attached:

```bash
./scripts/tests/test-flash-and-bootstrap.sh
```
