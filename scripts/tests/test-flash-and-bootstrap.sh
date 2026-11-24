#!/usr/bin/env bash
# Automated test suite for CellCore USB flasher (scripts/flash-modem.sh) and
# enhanced clean-room bootstrapper (bootstrap.sh).
#
# Uses strictly synthetic test fixtures (Luhn-valid test IMEI 352099001761481,
# synthetic firmware zip, synthetic config bundles) — touches no real USB hardware.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FLASH="$ROOT/scripts/flash-modem.sh"
BOOTSTRAP="$ROOT/bootstrap.sh"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1" >&2
}

assert_cmd_ok() {
  local name="$1"
  shift
  local out=""
  if out=$("$@" 2>&1); then
    pass "$name"
    LAST_OUT="$out"
  else
    fail "$name (unexpected non-zero exit)"
    printf '  output: %s\n' "$out" >&2
    LAST_OUT="$out"
  fi
}

assert_cmd_fail() {
  local name="$1"
  shift
  local out=""
  if out=$("$@" 2>&1); then
    fail "$name (expected non-zero exit, got 0)"
    printf '  output: %s\n' "$out" >&2
    LAST_OUT="$out"
  else
    pass "$name"
    LAST_OUT="$out"
  fi
}

assert_contains() {
  local name="$1"
  local haystack="$2"
  local needle="$3"
  if printf '%s' "$haystack" | grep -qF -- "$needle"; then
    pass "$name"
  else
    fail "$name (missing expected substring: ${needle})"
    printf '  actual: %s\n' "$haystack" >&2
  fi
}

assert_not_contains() {
  local name="$1"
  local haystack="$2"
  local needle="$3"
  if printf '%s' "$haystack" | grep -qF -- "$needle"; then
    fail "$name (unexpected substring present: ${needle})"
  else
    pass "$name"
  fi
}

echo "=== CellCore Flash & Bootstrap Automated Tests ==="

# ---------------------------------------------------------------------------
# 1. Bash syntax checks & doctor smoke test
# ---------------------------------------------------------------------------
assert_cmd_ok "bash -n bootstrap.sh" bash -n "$BOOTSTRAP"
assert_cmd_ok "bash -n scripts/flash-modem.sh" bash -n "$FLASH"
assert_cmd_ok "flash-modem.sh doctor runs cleanly" "$FLASH" doctor

# ---------------------------------------------------------------------------
# 2. Synthetic XQCN fixtures & inspect-xqcn tests
#    Test IMEI: 352099001761481 (Luhn valid)
#    Qualcomm NV 550 BCD bytes: 08 3A 25 90 09 10 67 41 18
#    Bad Luhn IMEI: 352099001761482 -> last byte 0x28 instead of 0x18
# ---------------------------------------------------------------------------
python3 - "$TMP_DIR" <<'PYEOF'
import os, sys

tmp = sys.argv[1]

def write_xml_xqcn(path: str, nv550_hex: str, target_size: int):
    header = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<QCN>\n'
        '  <NvItem id="550" name="NV_UE_IMEI_I">' + nv550_hex + '</NvItem>\n'
        '  <NvItem id="1000" name="NV_SYNTH_PAD">'
    ).encode("utf-8")
    footer = b"</NvItem>\n</QCN>\n"
    pad_len = max(0, target_size - len(header) - len(footer))
    with open(path, "wb") as f:
        f.write(header)
        if pad_len:
            f.write(b"00 " * (pad_len // 3) + b"0" * (pad_len % 3))
        f.write(footer)

# Valid >= 1 MiB XML XQCN (352099001761481)
write_xml_xqcn(os.path.join(tmp, "valid.xqcn"), "08 3A 25 90 09 10 67 41 18", 1052672)

# Valid decimal comma-separated XML XQCN with --min-bytes test
write_xml_xqcn(os.path.join(tmp, "valid_dec_small.xqcn"), "8,58,37,144,9,16,103,65,24", 4096)

# Corrupt Luhn >= 1 MiB XML XQCN (352099001761482)
write_xml_xqcn(os.path.join(tmp, "bad_luhn.xqcn"), "08 3A 25 90 09 10 67 41 28", 1052672)

# Undersized XML XQCN (valid IMEI, but < 1 MiB)
write_xml_xqcn(os.path.join(tmp, "undersized.xqcn"), "08 3A 25 90 09 10 67 41 18", 2048)

# Synthetic OLE2/binary QCN (>= 1 MiB) containing NV 550 record
bin_path = os.path.join(tmp, "valid_bin.qcn")
ole_hdr = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
nv550_rec = b"\x26\x02\x00\x00" + bytes.fromhex("083A25900910674118")
with open(bin_path, "wb") as f:
    f.write(ole_hdr)
    f.write(nv550_rec)
    f.write(b"\x00" * (1052672 - len(ole_hdr) - len(nv550_rec)))

# Synthetic QPST/qfenix XML Storage NV_ITEM_ARRAY XQCN (>= 1 MiB)
import struct
rec0 = struct.pack("<HHHH", 136, 1, 0, 0) + b"\x00" * 128
rec550 = struct.pack("<HHHH", 136, 1, 550, 0) + bytes.fromhex("083A25900910674118") + b"\x00" * 119
hex_arr = " ".join(f"{b:02X}" for b in (rec0 + rec550))
qpst_hdr = (
    '<?xml version="1.0" encoding="Windows-1252" ?>\n'
    "<Storage Name='test.xqcn'><Storage Name='NV_NUMBERED_ITEMS'>"
    f"<Stream Length='272' Name='NV_ITEM_ARRAY' Value='{hex_arr}'/>"
    "<Stream Name='PAD' Value='"
).encode("utf-8")
qpst_ftr = b"'/></Storage></Storage>\n"
qpst_pad = max(0, 1052672 - len(qpst_hdr) - len(qpst_ftr))
with open(os.path.join(tmp, "valid_qpst.xqcn"), "wb") as f:
    f.write(qpst_hdr)
    f.write(b"00 " * (qpst_pad // 3) + b"0" * (qpst_pad % 3))
    f.write(qpst_ftr)
PYEOF

assert_cmd_ok "inspect-xqcn valid >=1MiB XML XQCN" "$FLASH" inspect-xqcn "$TMP_DIR/valid.xqcn"
assert_contains "inspect-xqcn masks IMEI by default" "$LAST_OUT" "imei=•••••••••••1481"
assert_not_contains "inspect-xqcn does not leak full IMEI by default" "$LAST_OUT" "352099001761481"
assert_contains "inspect-xqcn reports valid=1 luhn_ok=1" "$LAST_OUT" "valid=1 luhn_ok=1"

assert_cmd_ok "inspect-xqcn --show-imei prints full IMEI" "$FLASH" inspect-xqcn "$TMP_DIR/valid.xqcn" --show-imei
assert_contains "inspect-xqcn --show-imei contains full IMEI" "$LAST_OUT" "imei=352099001761481"

assert_cmd_ok "inspect-xqcn --expected-imei matches" "$FLASH" inspect-xqcn "$TMP_DIR/valid.xqcn" --expected-imei 352099001761481
assert_cmd_fail "inspect-xqcn --expected-imei rejects mismatch" "$FLASH" inspect-xqcn "$TMP_DIR/valid.xqcn" --expected-imei 490154203237518

assert_cmd_ok "inspect-xqcn handles decimal CSV with --min-bytes" "$FLASH" inspect-xqcn "$TMP_DIR/valid_dec_small.xqcn" --min-bytes 1024
assert_cmd_ok "inspect-xqcn handles OLE2 binary QCN" "$FLASH" inspect-xqcn "$TMP_DIR/valid_bin.qcn"
assert_contains "inspect-xqcn binary QCN detects ole2-qcn" "$LAST_OUT" "format=ole2-qcn"
assert_cmd_ok "inspect-xqcn handles QPST/qfenix NV_ITEM_ARRAY XQCN" "$FLASH" inspect-xqcn "$TMP_DIR/valid_qpst.xqcn"
assert_contains "inspect-xqcn QPST NV_ITEM_ARRAY decodes masked IMEI" "$LAST_OUT" "imei=•••••••••••1481"

assert_cmd_fail "inspect-xqcn rejects corrupt Luhn IMEI" "$FLASH" inspect-xqcn "$TMP_DIR/bad_luhn.xqcn"
assert_cmd_fail "inspect-xqcn rejects undersized (<1 MiB) XQCN" "$FLASH" inspect-xqcn "$TMP_DIR/undersized.xqcn"

# ---------------------------------------------------------------------------
# 3. Synthetic Quectel firmware zip & verify-firmware tests
# ---------------------------------------------------------------------------
python3 - "$TMP_DIR" <<'PYEOF'
import hashlib, os, sys, zipfile

tmp = sys.argv[1]

def build_fw_zip(zip_path: str, is_factory: bool, tamper: bool = False):
    rp_name = "rawprogram_nand_p4K_b256K_factory.xml" if is_factory else "rawprogram_nand_p4K_b256K_update.xml"
    cefs_entry = '  <program label="0:efs2" filename="cefs.mbn" />\n' if is_factory else ""
    rp_xml = (
        '<?xml version="1.0" ?>\n'
        '<data>\n'
        '  <program label="0:sbl" filename="sbl1.mbn" />\n'
        '  <program label="0:boot" filename="boot.img" />\n'
        '  <program label="0:boot_b" filename="boot.img" />\n'
        '  <program label="0:system" filename="rootfs.ubi" />\n'
        '  <program label="0:system_b" filename="rootfs.ubi" />\n'
        + cefs_entry +
        '</data>\n'
    ).encode("utf-8")
    contents_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<contents>\n'
        '  <c_project_name>RM551EGL00AAR02A02M8G</c_project_name>\n'
        '</contents>\n'
    ).encode("utf-8")

    files = {
        f"update/firehose/{rp_name}": rp_xml,
        "update/sbl1.mbn": b"SYNTH_SBL_PAYLOAD_12345",
        "update/boot.img": b"SYNTH_BOOT_PAYLOAD_67890",
        "update/rootfs.ubi": b"SYNTH_ROOTFS_PAYLOAD_ABCDE",
        "contents.xml": contents_xml,
    }
    if is_factory:
        files["update/cefs.mbn"] = b"SYNTH_CEFS_PAYLOAD"

    # Build Windows-style md5.txt with Quectel VERSION/FILE:START/FILE:END + backslashes + CRLF
    md5_lines = ["VERSION:1.0\r\n", "FILE:START\r\n"]
    for rel, data in files.items():
        digest = hashlib.md5(data).hexdigest().upper()
        win_rel = "\\" + rel.replace("/", "\\")
        md5_lines.append(f"FILE:{win_rel}:{digest}\r\n")
    md5_lines.append("FILE:END\r\n")
    md5_bytes = "".join(md5_lines).encode("utf-8")

    if tamper:
        files["update/boot.img"] = b"TAMPERED_BOOT_PAYLOAD"

    prefix = "RM551EGL00AAR02A02M8G/"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(prefix + "md5.txt", md5_bytes)
        for rel, data in files.items():
            zf.writestr(prefix + rel, data)

build_fw_zip(os.path.join(tmp, "fw_update_ok.zip"), is_factory=False, tamper=False)
build_fw_zip(os.path.join(tmp, "fw_factory_ok.zip"), is_factory=True, tamper=False)
build_fw_zip(os.path.join(tmp, "fw_tampered.zip"), is_factory=False, tamper=True)

# Multi-rawprogram zip: verify deterministic preference for p4k_b256k over p2k_b128k
with zipfile.ZipFile(os.path.join(tmp, "fw_update_ok.zip"), "r") as zin, \
     zipfile.ZipFile(os.path.join(tmp, "fw_multi_rp.zip"), "w", compression=zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        zout.writestr(item, zin.read(item.filename))
    zout.writestr(
        "RM551EGL00AAR02A02M8G/update/firehose/rawprogram_nand_p2K_b128K_update.xml",
        b'<?xml version="1.0" ?><data><program label="0:boot" filename="boot.img" /></data>\n',
    )
PYEOF

assert_cmd_ok "verify-firmware passes valid update zip (Windows \\ + CRLF)" "$FLASH" verify-firmware "$TMP_DIR/fw_update_ok.zip"
assert_contains "verify-firmware detects update image_type" "$LAST_OUT" "image_type=update"
assert_contains "verify-firmware detects A/B dual-slot" "$LAST_OUT" "ab_dual_slot=1"
assert_contains "verify-firmware extracts c_project_name" "$LAST_OUT" "c_project_name=RM551EGL00AAR02A02M8G"
assert_contains "verify-firmware counts partitions" "$LAST_OUT" "partitions=5"

assert_cmd_ok "verify-firmware deterministically prefers p4k_b256k rawprogram" "$FLASH" verify-firmware "$TMP_DIR/fw_multi_rp.zip"
assert_contains "verify-firmware chose p4K_b256K over p2K_b128K" "$LAST_OUT" "rawprogram=rawprogram_nand_p4K_b256K_update.xml"

assert_cmd_ok "verify-firmware passes valid factory zip" "$FLASH" verify-firmware "$TMP_DIR/fw_factory_ok.zip"
assert_contains "verify-firmware detects factory image_type" "$LAST_OUT" "image_type=factory"

assert_cmd_fail "verify-firmware rejects tampered file MD5" "$FLASH" verify-firmware "$TMP_DIR/fw_tampered.zip"

# ---------------------------------------------------------------------------
# 4. Synthetic config bundles + bootstrap.sh security rejection tests
# ---------------------------------------------------------------------------
python3 - "$TMP_DIR" <<'PYEOF'
import io, os, sys, tarfile

tmp = sys.argv[1]

def make_tar(path, entries):
    with tarfile.open(path, "w:gz") as tf:
        for kind, name, payload in entries:
            ti = tarfile.TarInfo(name=name)
            if kind == "file":
                data = payload.encode("utf-8")
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            elif kind == "lnk":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tf.addfile(ti)

# Valid bundle (all allowlisted paths)
make_tar(os.path.join(tmp, "bundle_valid.tar.gz"), [
    ("dir", "etc", ""),
    ("dir", "etc/config", ""),
    ("file", "etc/config/network", "config interface 'lan'\n"),
    ("file", "etc/cellcore/settings.json", '{"hostname":"modem0"}\n'),
    ("file", "etc/ssl/acme/fullchain.pem", "-----BEGIN CERTIFICATE-----\n"),
    ("file", "etc/dropbear/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@example.com\n"),
    ("file", "etc/rc.local", "#!/bin/sh\nexit 0\n"),
    ("file", "etc/crontabs/root", "0 3 * * * /bin/true\n"),
])

# Malicious bundle 1: path traversal ../etc/passwd
make_tar(os.path.join(tmp, "bundle_traversal.tar.gz"), [
    ("file", "../etc/passwd", "root:x:0:0:root:/root:/bin/ash\n"),
])

# Malicious bundle 2: nested traversal etc/config/../../etc/passwd
make_tar(os.path.join(tmp, "bundle_nested_traversal.tar.gz"), [
    ("file", "etc/config/../../etc/passwd", "evil\n"),
])

# Malicious bundle 3: absolute path /etc/shadow
make_tar(os.path.join(tmp, "bundle_abs.tar.gz"), [
    ("file", "/etc/shadow", "root:*:0:0:99999:7:::\n"),
])

# Malicious bundle 4: symlink
make_tar(os.path.join(tmp, "bundle_symlink.tar.gz"), [
    ("sym", "etc/config/evil", "/etc/shadow"),
])

# Malicious bundle 5: hardlink
make_tar(os.path.join(tmp, "bundle_hardlink.tar.gz"), [
    ("file", "etc/config/network", "ok\n"),
    ("lnk", "etc/config/hard", "etc/config/network"),
])

# Malicious bundle 6: disallowed path usr/sbin/cellcored
make_tar(os.path.join(tmp, "bundle_disallowed.tar.gz"), [
    ("file", "usr/sbin/cellcored", "trojan\n"),
])
PYEOF

# Create synthetic 0600 root shadow file + 0644 bad-perm shadow file + dummy ssh key + dummy ipk
printf '%s\n' '$6$testsalt01234567$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./abcdefghijklmno' > "$TMP_DIR/root.shadow"
chmod 0600 "$TMP_DIR/root.shadow"

cp "$TMP_DIR/root.shadow" "$TMP_DIR/root_badperm.shadow"
chmod 0644 "$TMP_DIR/root_badperm.shadow"

printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyExample000000000000000000000000000000 operator@example.com' > "$TMP_DIR/test_id.pub"
printf 'synthetic-ipk-bytes' > "$TMP_DIR/dummy.ipk"

assert_cmd_fail "bootstrap.sh rejects ../etc/passwd traversal bundle" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --config-bundle "$TMP_DIR/bundle_traversal.tar.gz" --dry-run

assert_cmd_fail "bootstrap.sh rejects nested etc/config/../../etc/passwd bundle" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --config-bundle "$TMP_DIR/bundle_nested_traversal.tar.gz" --dry-run

assert_cmd_fail "bootstrap.sh rejects absolute /etc/shadow bundle" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --config-bundle "$TMP_DIR/bundle_abs.tar.gz" --dry-run

assert_cmd_fail "bootstrap.sh rejects symlink inside bundle" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --config-bundle "$TMP_DIR/bundle_symlink.tar.gz" --dry-run

assert_cmd_fail "bootstrap.sh rejects hardlink inside bundle" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --config-bundle "$TMP_DIR/bundle_hardlink.tar.gz" --dry-run

assert_cmd_fail "bootstrap.sh rejects disallowed path usr/sbin/cellcored" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --config-bundle "$TMP_DIR/bundle_disallowed.tar.gz" --dry-run

assert_cmd_fail "bootstrap.sh rejects non-0600 --root-shadow file" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --root-shadow "$TMP_DIR/root_badperm.shadow" --dry-run

assert_cmd_fail "bootstrap.sh rejects invalid RFC-1123 --hostname" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --hostname "-invalid_host" --dry-run

assert_cmd_fail "bootstrap.sh rejects invalid --lan-ip prefix" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --lan-ip "192.168.224.1/33" --dry-run

assert_cmd_fail "bootstrap.sh rejects shell metacharacters in --mbn" \
  "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --mbn 'Commercial-TMO;reboot' --dry-run

assert_cmd_fail "bootstrap.sh rejects single quotes / shell injection in CELLCORE_FEED_URL" \
  env CELLCORE_FEED_URL="https://example.com/feed';reboot;'" "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --dry-run

assert_cmd_fail "bootstrap.sh rejects whitespace in CELLCORE_FEED_URL" \
  env CELLCORE_FEED_URL="https://example.com/feed with spaces" "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --dry-run

assert_cmd_fail "bootstrap.sh rejects command substitution in CELLCORE_FEED_URL" \
  env CELLCORE_FEED_URL='https://example.com/$(id)' "$BOOTSTRAP" --adb --ipk "$TMP_DIR/dummy.ipk" --dry-run

assert_cmd_ok "bootstrap.sh accepts valid bundle + all flags in --dry-run" \
  "$BOOTSTRAP" --adb --auto-overlay --ipk "$TMP_DIR/dummy.ipk" \
    --ssh-key "$TMP_DIR/test_id.pub" \
    --config-bundle "$TMP_DIR/bundle_valid.tar.gz" \
    --lan-ip "192.168.224.1/22" \
    --hostname "modem0" \
    --at-baseline --mbn "Commercial-TMO" --lan-gw-ip "192.168.224.1" \
    --root-shadow "$TMP_DIR/root.shadow" \
    --lockdown --dry-run
assert_contains "bootstrap.sh dry-run converts /22 to 255.255.252.0" "$LAST_OUT" "netmask 255.255.252.0"
assert_contains "bootstrap.sh dry-run plans MBN select" "$LAST_OUT" 'AT+QMBNCFG="Select","Commercial-TMO"'
assert_contains "bootstrap.sh dry-run plans QMAP LANIP" "$LAST_OUT" 'AT+QMAP="LANIP",192.168.224.100,192.168.224.200,192.168.224.1'
assert_not_contains "bootstrap.sh dry-run never echoes root shadow hash" "$LAST_OUT" '$6$testsalt'

# ---------------------------------------------------------------------------
# 5. End-to-end flash --dry-run tests
# ---------------------------------------------------------------------------
assert_cmd_ok "flash --dry-run end-to-end (factory + target + XQCN + bundle + all flags)" \
  "$FLASH" flash \
    --factory-zip "$TMP_DIR/fw_factory_ok.zip" \
    --firmware "$TMP_DIR/fw_update_ok.zip" \
    --backup-dir "$TMP_DIR/backups" \
    --existing-xqcn "$TMP_DIR/valid.xqcn" \
    --expected-imei 352099001761481 \
    --ssh-key "$TMP_DIR/test_id.pub" \
    --lan-ip "192.168.224.1/24" \
    --hostname "modem0" \
    --mbn "Commercial-TMO" \
    --lan-gw-ip "192.168.224.1" \
    --config-bundle "$TMP_DIR/bundle_valid.tar.gz" \
    --root-shadow "$TMP_DIR/root.shadow" \
    --ipk "$TMP_DIR/dummy.ipk" \
    --lockdown \
    --dry-run
assert_contains "flash --dry-run prints Stage-1 factory plan" "$LAST_OUT" "Stage-1 factory"
assert_contains "flash --dry-run prints Stage-2 target plan" "$LAST_OUT" "Stage-2 target"
assert_contains "flash --dry-run prints EFS restore plan" "$LAST_OUT" "EFS restore"
assert_contains "flash --dry-run prints bootstrap.sh plan" "$LAST_OUT" "bootstrap.sh"

assert_cmd_fail "flash --dry-run rejects tampered firmware zip" \
  "$FLASH" flash \
    --firmware "$TMP_DIR/fw_tampered.zip" \
    --backup-dir "$TMP_DIR/backups" \
    --existing-xqcn "$TMP_DIR/valid.xqcn" \
    --skip-bootstrap --dry-run

assert_cmd_fail "flash --dry-run rejects bad Luhn --set-imei" \
  "$FLASH" flash \
    --firmware "$TMP_DIR/fw_update_ok.zip" \
    --backup-dir "$TMP_DIR/backups" \
    --existing-xqcn "$TMP_DIR/valid.xqcn" \
    --set-imei 352099001761482 \
    --skip-bootstrap --dry-run

assert_cmd_fail "flash --dry-run rejects malicious --config-bundle" \
  "$FLASH" flash \
    --firmware "$TMP_DIR/fw_update_ok.zip" \
    --backup-dir "$TMP_DIR/backups" \
    --existing-xqcn "$TMP_DIR/valid.xqcn" \
    --config-bundle "$TMP_DIR/bundle_traversal.tar.gz" \
    --ipk "$TMP_DIR/dummy.ipk" \
    --dry-run

echo ""
echo "============================================================"
echo " Test Summary: passed=${PASS_COUNT}, failed=${FAIL_COUNT}"
echo "============================================================"
[ "$FAIL_COUNT" -eq 0 ]
