#!/usr/bin/env bash
# CellCore Clean-Room USB Firmware Flasher & Provisioner (Zero third-party scripts)
#
# Complete USB bench flashing + EFS backup/restore + CellCore provisioning CLI for
# Quectel RM551E-GL / SDX75 modems on Linux (x86_64 / ARM64) and macOS.
#
# Subcommands:
#   doctor
#   inspect-xqcn <file.xqcn> [--min-bytes <N>] [--show-imei] [--expected-imei <15-digits>]
#   verify-firmware <zip-or-dir>
#   backup --out <dir> [--qfenix <path>] [--adb-serial <id>] [--stop-mm]
#   flash --firmware <zip-or-dir> --backup-dir <dir> [options...]
#
# Run `./scripts/flash-modem.sh <subcommand> --help` for subcommand details.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXPECTED_USIGN_X64_SHA="961aacc9dc143c3e14bd04732e7917ff2801c2b705131ba9416c38e1022bf169"
MIN_XQCN_BYTES_DEFAULT=1048576

usage() {
  cat <<'EOF'
CellCore USB Firmware Flasher & Provisioner (RM551E-GL / SDX75)

Usage:
  scripts/flash-modem.sh doctor [--qfirehose <path>] [--qfenix <path>]
  scripts/flash-modem.sh inspect-xqcn <file.xqcn> [--min-bytes <N>] [--show-imei] [--expected-imei <15-digits>]
  scripts/flash-modem.sh verify-firmware <zip-or-dir>
  scripts/flash-modem.sh backup --out <dir> [--qfenix <path>] [--adb-serial <id>] [--stop-mm]
  scripts/flash-modem.sh flash --firmware <zip-or-dir> --backup-dir <dir> [options]

Flash options:
  --firmware <zip-or-dir>     Target firmware zip or unpacked dir (required)
  --factory-zip <zip-or-dir>  Optional Stage-1 factory repartition zip (flashed with QFirehose -e)
  --backup-dir <dir>          Directory for mandatory pre-flash .xqcn + .tar backups (required)
  --existing-xqcn <path>      Use a previously captured .xqcn (still verified >= 1 MiB & NV 550 Luhn)
  --erase                     Pass -e to QFirehose for single-stage --firmware (automatic for --factory-zip)
  --expected-imei <15-digits> Fail-closed guard: abort restore if XQCN NV 550 IMEI does not match
  --set-imei <15-digits>      Luhn-validated AT+EGMR=1,7 override after EFS restore (opt-in)
  --qfirehose <path>          Path to QFirehose binary
  --qfenix <path>             Path to qfenix binary
  --adb-serial <id>           Target a specific ADB device serial
  --stop-mm                   Stop ModemManager before DIAG/Firehose operations
  --skip-bootstrap            Skip running bootstrap.sh after flashing and EFS restore
  --ssh-key <path>            Passthrough to bootstrap.sh --ssh-key
  --lan-ip <ip[/prefix]>      Passthrough to bootstrap.sh --lan-ip
  --hostname <name>           Passthrough to bootstrap.sh --hostname
  --mbn <name>                Passthrough to bootstrap.sh --mbn
  --lan-gw-ip <ip>            Passthrough to bootstrap.sh --lan-gw-ip
  --config-bundle <tar.gz>    Passthrough to bootstrap.sh --config-bundle
  --root-shadow <file>        Passthrough to bootstrap.sh --root-shadow
  --ipk <path>                Passthrough to bootstrap.sh --ipk
  --lockdown                  Passthrough to bootstrap.sh --lockdown
  --dry-run                   Verify firmware, XQCN, IMEI, and bootstrap inputs; print plan without touching USB
EOF
  exit 1
}

# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  else
    echo "ERROR: neither sha256sum nor shasum found locally" >&2
    return 1
  fi
}

find_bin() {
  local explicit="${1:-}"
  shift || true
  if [ -n "$explicit" ]; then
    if [ -x "$explicit" ]; then
      echo "$explicit"
      return 0
    fi
    return 1
  fi
  local candidate
  for candidate in "$@"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

run_privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

validate_imei_luhn() {
  local imei="$1"
  local label="${2:-IMEI}"
  python3 - "$imei" "$label" <<'PYEOF'
import sys

imei, label = sys.argv[1], sys.argv[2]
if len(imei) != 15 or not imei.isdigit():
    sys.stderr.write(f"ERROR: {label} must be exactly 15 decimal digits\n")
    sys.exit(1)

total = 0
for idx, ch in enumerate(reversed(imei)):
    d = int(ch)
    if idx % 2 == 1:
        d *= 2
        if d > 9:
            d -= 9
    total += d
if total % 10 != 0:
    sys.stderr.write(f"ERROR: {label} failed Luhn checksum verification\n")
    sys.exit(1)
PYEOF
}

mask_imei() {
  local imei="$1"
  printf '•••••••••••%s' "${imei: -4}"
}

adb_cmd() {
  local serial="${1:-}"
  shift || true
  if [ -n "$serial" ]; then
    adb -s "$serial" "$@"
  else
    adb "$@"
  fi
}

stop_modem_manager_if_requested() {
  local stop_mm="${1:-0}"
  if [ "$stop_mm" -ne 1 ]; then
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ModemManager 2>/dev/null; then
    echo "==> Stopping ModemManager..."
    run_privileged systemctl stop ModemManager
  elif pgrep -x ModemManager >/dev/null 2>&1; then
    echo "==> Stopping ModemManager process..."
    run_privileged pkill -x ModemManager || true
  fi
}

detach_qcserial() {
  if [ "$(uname -s)" != "Linux" ]; then
    return 0
  fi
  local driver_dir="/sys/bus/usb/drivers/qcserial"
  if [ -d "$driver_dir" ]; then
    local dev
    for dev in "$driver_dir"/*:*; do
      [ -e "$dev" ] || continue
      local bname
      bname=$(basename "$dev")
      echo "==> Unbinding qcserial from USB interface ${bname}..."
      printf '%s' "$bname" | run_privileged tee "${driver_dir}/unbind" >/dev/null || true
    done
  fi
}

query_live_imei_adb() {
  local serial="${1:-}"
  command -v adb >/dev/null 2>&1 || return 1
  adb_cmd "$serial" get-state 2>/dev/null | grep -qx "device" || return 1
  local raw
  raw=$(adb_cmd "$serial" shell '
    if command -v cellctl >/dev/null 2>&1; then
      cellctl at AT+CGSN 2>/dev/null || cellctl at AT+EGMR=0,7 2>/dev/null || true
    elif [ -c /dev/smd7 ]; then
      (
        exec 3<>/dev/smd7
        printf "AT+CGSN\r\n" >&3
        timeout 3 cat <&3 2>/dev/null || head -n 6 <&3 2>/dev/null || true
      ) 2>/dev/null || true
    fi
  ' 2>/dev/null || true)
  local imei
  imei=$(printf '%s\n' "$raw" | grep -oE '[0-9]{15}' | head -n 1 || true)
  if [ -n "$imei" ]; then
    printf '%s\n' "$imei"
    return 0
  fi
  return 1
}

send_at_adb_or_serial() {
  local serial="$1"
  local at_cmd="$2"
  local escaped
  escaped=$(printf '%s' "$at_cmd" | sed "s/'/'\\\\''/g")
  if command -v adb >/dev/null 2>&1 && adb_cmd "$serial" get-state 2>/dev/null | grep -qx "device"; then
    adb_cmd "$serial" shell "
      if command -v cellctl >/dev/null 2>&1; then
        cellctl at '${escaped}'
      elif [ -c /dev/smd7 ]; then
        printf '%s\r\n' '${escaped}' > /dev/smd7
        sleep 1
      else
        echo 'ERROR: neither cellctl nor /dev/smd7 available' >&2
        exit 1
      fi
    "
    return 0
  fi
  # Fallback to host USB AT serial port (typically /dev/ttyUSB2 on Linux)
  local port
  for port in /dev/ttyUSB2 /dev/ttyUSB3 /dev/cu.usbserial*; do
    if [ -c "$port" ]; then
      echo "==> Sending AT command via serial port ${port}..."
      printf '%s\r\n' "$at_cmd" | run_privileged tee "$port" >/dev/null
      sleep 1
      return 0
    fi
  done
  echo "ERROR: cannot send AT command (no ADB device and no USB AT serial port found)" >&2
  return 1
}

wait_for_modem_reenum() {
  local serial="${1:-}"
  local label="${2:-modem}"
  local timeout_secs="${3:-90}"
  echo "==> Waiting for ${label} boot & USB re-enumeration (up to ${timeout_secs}s)..."
  local elapsed=0
  # Give the modem a moment to reset/disconnect before polling
  sleep 6
  elapsed=6
  while [ "$elapsed" -lt "$timeout_secs" ]; do
    if command -v adb >/dev/null 2>&1 && adb_cmd "$serial" get-state 2>/dev/null | grep -qx "device"; then
      if adb_cmd "$serial" shell "echo ready" 2>/dev/null | grep -q "ready"; then
        echo ""
        echo "==> ${label} is back online via ADB (${elapsed}s)."
        return 0
      fi
    elif command -v lsusb >/dev/null 2>&1 && lsusb 2>/dev/null | grep -qi "2c7c:"; then
      # Quectel normal USB PID is present; keep waiting briefly if ADB is still coming up
      if [ "$elapsed" -ge 30 ]; then
        echo ""
        echo "==> ${label} re-enumerated on USB (2c7c:) at ${elapsed}s."
        return 0
      fi
    fi
    printf '.'
    sleep 3
    elapsed=$((elapsed + 3))
  done
  echo ""
  echo "ERROR: timed out after ${timeout_secs}s waiting for ${label} to re-enumerate." >&2
  return 1
}

# ---------------------------------------------------------------------------
# Subcommand 1: doctor
# ---------------------------------------------------------------------------

cmd_doctor() {
  local qfirehose_arg="${QFIREHOSE_BIN:-}"
  local qfenix_arg="${QFENIX_BIN:-}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --qfirehose) qfirehose_arg="${2:?missing path}"; shift 2 ;;
      --qfenix) qfenix_arg="${2:?missing path}"; shift 2 ;;
      -h|--help) usage ;;
      *) echo "Unknown option for doctor: $1" >&2; usage ;;
    esac
  done

  echo "=== CellCore USB Flasher Doctor ($(uname -s) $(uname -m)) ==="
  echo ""
  echo "-- Host Tools --"

  local path_out ver_out

  check_tool() {
    local label="$1"
    shift
    local found=""
    found=$(find_bin "" "$@" 2>/dev/null || true)
    if [ -n "$found" ]; then
      local v=""
      case "$label" in
        adb) v=$("$found" version 2>/dev/null | head -n 1 || true) ;;
        python3) v=$("$found" --version 2>&1 | head -n 1 || true) ;;
        unzip) v=$("$found" -v 2>/dev/null | head -n 1 || true) ;;
        md5sum|sha256sum) v=$("$found" --version 2>/dev/null | head -n 1 || true) ;;
        shasum) v=$("$found" --version 2>/dev/null | head -n 1 || true) ;;
        *) v="present" ;;
      esac
      printf '  [OK]   %-14s %s (%s)\n' "$label" "$found" "${v:-present}"
    else
      printf '  [MISS] %-14s not found in PATH\n' "$label"
    fi
  }

  check_tool "adb" adb
  if path_out=$(find_bin "$qfirehose_arg" QFirehose qfirehose 2>/dev/null); then
    printf '  [OK]   %-14s %s\n' "QFirehose" "$path_out"
  else
    printf '  [MISS] %-14s not found (pass --qfirehose <path> or install QFirehose)\n' "QFirehose"
  fi
  if path_out=$(find_bin "$qfenix_arg" qfenix 2>/dev/null); then
    printf '  [OK]   %-14s %s\n' "qfenix" "$path_out"
  else
    printf '  [MISS] %-14s not found (pass --qfenix <path> or install qfenix)\n' "qfenix"
  fi
  check_tool "unzip" unzip
  if command -v md5sum >/dev/null 2>&1; then
    check_tool "md5sum" md5sum
  else
    check_tool "md5" md5
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    check_tool "sha256sum" sha256sum
  else
    check_tool "shasum" shasum
  fi
  check_tool "python3" python3

  if command -v usign >/dev/null 2>&1; then
    printf '  [OK]   %-14s %s\n' "usign" "$(command -v usign)"
  elif [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ] && [ -x "$ROOT/scripts/feed/usign_x64" ]; then
    local got_sha
    got_sha=$(sha256_of "$ROOT/scripts/feed/usign_x64")
    if [ "$got_sha" = "$EXPECTED_USIGN_X64_SHA" ]; then
      printf '  [OK]   %-14s %s (bundled, sha256 verified)\n' "usign" "$ROOT/scripts/feed/usign_x64"
    else
      printf '  [FAIL] %-14s %s (SHA-256 mismatch!)\n' "usign" "$ROOT/scripts/feed/usign_x64"
    fi
  else
    printf '  [MISS] %-14s not found in PATH\n' "usign"
  fi

  echo ""
  echo "-- USB Devices & Kernel State --"
  if command -v lsusb >/dev/null 2>&1; then
    local usb_matches
    usb_matches=$(lsusb 2>/dev/null | grep -iE '2c7c:|05c6:9008' || true)
    if [ -n "$usb_matches" ]; then
      printf '%s\n' "$usb_matches" | while IFS= read -r line; do
        if printf '%s' "$line" | grep -qi '05c6:9008'; then
          echo "  [EDL]  $line"
        else
          echo "  [USB]  $line"
        fi
      done
    else
      echo "  [INFO] No Quectel (2c7c:*) or Qualcomm EDL (05c6:9008) USB devices detected."
    fi
  elif [ "$(uname -s)" = "Darwin" ] && command -v system_profiler >/dev/null 2>&1; then
    local mac_usb
    mac_usb=$(system_profiler SPUSBDataType 2>/dev/null | grep -iE 'Quectel|0x2c7c|0x05c6|9008' || true)
    if [ -n "$mac_usb" ]; then
      printf '%s\n' "$mac_usb" | sed 's/^/  [USB]  /'
    else
      echo "  [INFO] No Quectel or Qualcomm EDL USB devices detected."
    fi
  else
    echo "  [INFO] lsusb unavailable on this host."
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ModemManager 2>/dev/null; then
    echo "  [WARN] ModemManager is ACTIVE — pass --stop-mm (or stop ModemManager) before qfenix/QFirehose!"
  elif pgrep -x ModemManager >/dev/null 2>&1; then
    echo "  [WARN] ModemManager process is RUNNING — pass --stop-mm before qfenix/QFirehose!"
  else
    echo "  [OK]   ModemManager is not active."
  fi

  if [ "$(uname -s)" = "Linux" ]; then
    if [ -d /sys/module/qcserial ] || (command -v lsmod >/dev/null 2>&1 && lsmod | grep -qw qcserial); then
      local bound_count=0
      if [ -d /sys/bus/usb/drivers/qcserial ]; then
        bound_count=$(find /sys/bus/usb/drivers/qcserial -maxdepth 1 -name '*:*' 2>/dev/null | wc -l | tr -d ' ')
      fi
      echo "  [INFO] qcserial kernel module is loaded (bound interfaces: ${bound_count}; flash/backup unbinds automatically)."
    else
      echo "  [OK]   qcserial kernel module is not loaded."
    fi
  fi
}

# ---------------------------------------------------------------------------
# Subcommand 2: inspect-xqcn
# ---------------------------------------------------------------------------

cmd_inspect_xqcn() {
  local xqcn_file=""
  local min_bytes="$MIN_XQCN_BYTES_DEFAULT"
  local show_imei=0
  local expected_imei=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --min-bytes) min_bytes="${2:?missing byte count}"; shift 2 ;;
      --show-imei) show_imei=1; shift ;;
      --expected-imei) expected_imei="${2:?missing expected IMEI}"; shift 2 ;;
      -h|--help) usage ;;
      -*) echo "Unknown option for inspect-xqcn: $1" >&2; usage ;;
      *)
        if [ -z "$xqcn_file" ]; then
          xqcn_file="$1"
          shift
        else
          echo "Unexpected argument: $1" >&2
          usage
        fi
        ;;
    esac
  done

  [ -n "$xqcn_file" ] || { echo "ERROR: inspect-xqcn requires <file.xqcn>" >&2; usage; }
  command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required for inspect-xqcn" >&2; exit 1; }

  python3 - "$xqcn_file" "$min_bytes" "$show_imei" "$expected_imei" <<'PYEOF'
import hashlib
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET

xqcn_path = sys.argv[1]
min_bytes = int(sys.argv[2])
show_imei = sys.argv[3] == "1"
expected_imei = sys.argv[4]

def luhn_valid(digits: str) -> bool:
    if len(digits) != 15 or not digits.isdigit():
        return False
    total = 0
    for idx, ch in enumerate(reversed(digits)):
        d = int(ch)
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (total % 10) == 0

def decode_nv550_bcd(raw_bytes: bytes):
    if len(raw_bytes) < 9:
        return None
    b = raw_bytes[:9]
    if b[0] != 0x08:
        return None
    if (b[1] & 0x0F) != 0x0A:
        return None
    digits = []
    d1 = (b[1] >> 4) & 0x0F
    if d1 > 9:
        return None
    digits.append(str(d1))
    for byte in b[2:9]:
        lo = byte & 0x0F
        hi = (byte >> 4) & 0x0F
        if lo > 9 or hi > 9:
            return None
        digits.append(str(lo))
        digits.append(str(hi))
    return "".join(digits)

def parse_nv_payload_text(text: str):
    if not text:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    # Contiguous hex string (e.g. 083A25900910674118)
    compact = re.sub(r"\s+", "", cleaned)
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{18,}", compact) and "," not in cleaned and " " not in cleaned:
        hex_str = compact[2:] if compact.lower().startswith("0x") else compact
        if len(hex_str) % 2 == 0:
            try:
                return bytes.fromhex(hex_str)
            except ValueError:
                pass
    tokens = [t for t in re.split(r"[\s,;]+", cleaned) if t]
    if len(tokens) < 9:
        return None
    # Distinguish hex tokens vs decimal tokens
    has_hex_marker = any(
        t.lower().startswith("0x") or re.search(r"[a-fA-F]", t)
        for t in tokens[:9]
    )
    out = bytearray()
    for t in tokens[:9]:
        try:
            val = int(t, 16) if has_hex_marker else int(t, 10)
        except ValueError:
            return None
        if val < 0 or val > 255:
            return None
        out.append(val)
    return bytes(out)

def extract_nv550_from_qpst_nv_array(raw: bytes):
    """Parse Qualcomm QPST/qfenix NV_ITEM_ARRAY stream: [u16 len][u16 type][u16 nv_id][u16 idx][128B data]."""
    off = 0
    while off + 17 <= len(raw):
        rec_len, _rec_type, nv_id, _idx = struct.unpack_from("<HHHH", raw, off)
        if rec_len < 17 or off + rec_len > len(raw):
            break
        if nv_id == 550:
            return raw[off + 8 : off + 17]
        off += rec_len
    return None

def extract_nv550_from_xml(data: bytes):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower()
        # QPST / qfenix XML-encoded compound storage: <Stream Name='NV_ITEM_ARRAY' Value='88 00 01 00 ...'/>
        if tag == "stream":
            name_attr = None
            val_attr = None
            for k, v in elem.attrib.items():
                kl = k.lower()
                if kl == "name":
                    name_attr = v.strip()
                elif kl == "value":
                    val_attr = v
            if name_attr and name_attr.upper() == "NV_ITEM_ARRAY" and val_attr:
                try:
                    raw = bytes.fromhex(val_attr)
                except ValueError:
                    raw = None
                if raw:
                    found = extract_nv550_from_qpst_nv_array(raw)
                    if found is not None:
                        return found
            continue
        if tag not in ("nvitem", "nv_item", "item"):
            continue
        item_id = None
        for k, v in elem.attrib.items():
            if k.lower() in ("id", "item_id", "nvid"):
                item_id = v.strip()
                break
        if item_id != "550":
            continue
        # Candidate text locations: element text, value attribute, or child text
        candidates = []
        if elem.text and elem.text.strip():
            candidates.append(elem.text)
        for k, v in elem.attrib.items():
            if k.lower() in ("value", "data", "hex"):
                candidates.append(v)
        for child in elem:
            if child.text and child.text.strip():
                candidates.append(child.text)
        for cand in candidates:
            parsed = parse_nv_payload_text(cand)
            if parsed is not None:
                return parsed
    return None

def extract_nv550_from_xml_regex(data: bytes):
    # Fallback for XML with minor quirks or non-UTF8 comments
    text = data.decode("latin1", errors="ignore")
    for m in re.finditer(
        r"<(?:NvItem|NVItem|nv_item)\b[^>]*\bid\s*=\s*['\"]550['\"][^>]*>(.*?)</(?:NvItem|NVItem|nv_item)>",
        text,
        re.IGNORECASE | re.DOTALL,
    ):
        inner = re.sub(r"<[^>]+>", " ", m.group(1))
        parsed = parse_nv_payload_text(inner)
        if parsed is not None:
            return parsed
    return None

def extract_nv550_from_binary_qcn(data: bytes):
    # Binary / OLE2 QCN record pattern: uint16 LE 550 (0x26, 0x02) followed closely by 9-byte BCD IMEI
    needle = b"\x26\x02"
    pos = 0
    best = None
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        pos = idx + 1
        # Common offsets after NV ID in QCN records: 2, 4, 6 bytes (index/length fields)
        for offset in (2, 4, 6, 8):
            start = idx + offset
            if start + 9 <= len(data):
                cand = data[start:start + 9]
                imei = decode_nv550_bcd(cand)
                if imei is not None:
                    if luhn_valid(imei):
                        return cand
                    if best is None:
                        best = cand
    return best

if not os.path.isfile(xqcn_path):
    sys.stderr.write(f"ERROR: XQCN file not found: {xqcn_path}\n")
    sys.exit(1)

size_bytes = os.path.getsize(xqcn_path)
with open(xqcn_path, "rb") as f:
    raw = f.read()
sha256 = hashlib.sha256(raw).hexdigest()

if size_bytes < min_bytes:
    sys.stderr.write(
        f"ERROR: XQCN file too small ({size_bytes} bytes < minimum {min_bytes} bytes); "
        f"refusing truncated/uncalibrated backup!\n"
    )
    print(f"file={xqcn_path} size_bytes={size_bytes} sha256={sha256} valid=0 luhn_ok=0")
    sys.exit(1)

nv550_bytes = None
fmt = "unknown"
stripped = raw.lstrip()
if stripped.startswith(b"<") or b"<NvItem" in raw[:65536] or b"<NVItem" in raw[:65536]:
    fmt = "xml-xqcn"
    nv550_bytes = extract_nv550_from_xml(raw)
    if nv550_bytes is None:
        nv550_bytes = extract_nv550_from_xml_regex(raw)
elif raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
    fmt = "ole2-qcn"
    nv550_bytes = extract_nv550_from_binary_qcn(raw)
else:
    fmt = "binary-qcn"
    nv550_bytes = extract_nv550_from_xml_regex(raw) or extract_nv550_from_binary_qcn(raw)

if nv550_bytes is None:
    sys.stderr.write(f"ERROR: NV item 550 (IMEI) not found in {xqcn_path} (format={fmt})\n")
    print(f"file={xqcn_path} format={fmt} size_bytes={size_bytes} sha256={sha256} valid=0 luhn_ok=0")
    sys.exit(1)

imei = decode_nv550_bcd(nv550_bytes)
if imei is None:
    sys.stderr.write(
        f"ERROR: NV item 550 in {xqcn_path} has invalid Qualcomm BCD framing "
        f"(bytes={nv550_bytes[:9].hex()})\n"
    )
    print(f"file={xqcn_path} format={fmt} size_bytes={size_bytes} sha256={sha256} valid=0 luhn_ok=0")
    sys.exit(1)

luhn_ok = luhn_valid(imei)
display_imei = imei if show_imei else ("•••••••••••" + imei[-4:])
valid_flag = 1 if luhn_ok else 0

print(
    f"imei={display_imei} format={fmt} size_bytes={size_bytes} "
    f"sha256={sha256} valid={valid_flag} luhn_ok={1 if luhn_ok else 0}"
)

if not luhn_ok:
    sys.stderr.write(f"ERROR: NV 550 IMEI ({display_imei}) failed Luhn checksum verification!\n")
    sys.exit(1)

if expected_imei:
    if not luhn_valid(expected_imei):
        sys.stderr.write("ERROR: --expected-imei itself is not a valid 15-digit Luhn IMEI\n")
        sys.exit(1)
    if imei != expected_imei:
        sys.stderr.write(
            f"ERROR: XQCN NV 550 IMEI (•••••••••••{imei[-4:]}) does NOT match "
            f"--expected-imei (•••••••••••{expected_imei[-4:]})!\n"
        )
        sys.exit(1)
PYEOF
}

# ---------------------------------------------------------------------------
# Subcommand 3: verify-firmware
# ---------------------------------------------------------------------------

cmd_verify_firmware() {
  local target=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage ;;
      -*) echo "Unknown option for verify-firmware: $1" >&2; usage ;;
      *)
        if [ -z "$target" ]; then
          target="$1"
          shift
        else
          echo "Unexpected argument: $1" >&2
          usage
        fi
        ;;
    esac
  done

  [ -n "$target" ] || { echo "ERROR: verify-firmware requires <zip-or-dir>" >&2; usage; }
  [ -e "$target" ] || { echo "ERROR: firmware path not found: ${target}" >&2; exit 1; }
  command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required for verify-firmware" >&2; exit 1; }

  # Run unzip -tq if verifying a zip file and unzip is available
  if [ -f "$target" ] && command -v unzip >/dev/null 2>&1; then
    unzip -tq "$target" >/dev/null || {
      echo "ERROR: zip integrity test (unzip -tq) FAILED for ${target}" >&2
      exit 1
    }
  fi

  python3 - "$target" <<'PYEOF'
import hashlib
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile

target = sys.argv[1]

def fail(msg):
    sys.stderr.write(f"ERROR: verify-firmware failed: {msg}\n")
    sys.exit(1)

def parse_md5_txt(raw_bytes: bytes):
    text = raw_bytes.decode("utf-8", errors="replace")
    entries = []
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Quectel format: FILE:\update\firehose\foo.xml:0123456789abcdef0123456789abcdef
        m = re.match(r"^FILE:(.+):([0-9a-fA-F]{32})$", line, re.IGNORECASE)
        if m:
            rel = m.group(1).strip().replace("\\", "/").lstrip("/")
            digest = m.group(2).lower()
            entries.append((rel, digest))
            continue
        # Standard md5sum format: <32-hex>  <path>
        m2 = re.match(r"^([0-9a-fA-F]{32})\s+\*?(.+)$", line)
        if m2:
            digest = m2.group(1).lower()
            rel = m2.group(2).strip().replace("\\", "/").lstrip("/")
            entries.append((rel, digest))
            continue
        # Ignore known Quectel header/footer lines such as VERSION:1.0, FILE:START, FILE:END, TOTAL:...
        if re.match(r"^(FILE:(START|END)|TOTAL|VERSION|TIME|DATE|PROJECT|C_PROJECT_NAME)\b", line, re.IGNORECASE):
            continue
        fail(f"unrecognized line {lineno} in md5.txt: {line!r}")
    if not entries:
        fail("md5.txt contains no file checksum entries")
    return entries

def extract_project_name_from_xml_bytes(xml_bytes: bytes):
    try:
        text = xml_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = re.search(r"<c_project_name>\s*([^<\s]+)\s*</c_project_name>", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m2 = re.search(r'c_project_name\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
    if m2:
        return m2.group(1).strip()
    return None

def analyze_rawprogram(xml_name: str, xml_bytes: bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        fail(f"malformed rawprogram XML ({xml_name}): {exc}")
    programs = [e for e in root.iter() if e.tag.split("}")[-1].lower() == "program"]
    labels = set()
    filenames = set()
    for p in programs:
        lbl = (p.attrib.get("label") or "").strip().lower()
        fn = (p.attrib.get("filename") or "").strip().lower()
        if lbl:
            labels.add(lbl)
            labels.add(re.sub(r"^\d+:", "", lbl))
        if fn:
            filenames.add(fn)
    is_factory = (
        xml_name.lower().endswith("_factory.xml")
        or "cefs.mbn" in filenames
        or any(fn.endswith("/cefs.mbn") for fn in filenames)
    )
    ab_dual_slot = ("system_b" in labels) and ("boot_b" in labels)
    return {
        "image_type": "factory" if is_factory else "update",
        "partitions": len(programs),
        "ab_dual_slot": 1 if ab_dual_slot else 0,
    }

def md5_stream(fileobj) -> str:
    h = hashlib.md5()
    while True:
        chunk = fileobj.read(65536)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest().lower()

c_project_name = None
rawprogram_name = None
rawprogram_bytes = None
verified_count = 0

if os.path.isfile(target):
    try:
        zf = zipfile.ZipFile(target, "r")
    except zipfile.BadZipFile as exc:
        fail(f"not a valid zip file ({exc})")
    with zf:
        bad = zf.testzip()
        if bad is not None:
            fail(f"corrupt zip member: {bad}")
        names = [n for n in zf.namelist() if not n.endswith("/")]
        norm_map = {}
        lower_map = {}
        for n in names:
            norm = n.replace("\\", "/").lstrip("/")
            norm_map[norm] = n
            lower_map[norm.lower()] = n

        md5_candidates = [n for n in names if os.path.basename(n.replace("\\", "/")).lower() == "md5.txt"]
        if not md5_candidates:
            fail("md5.txt not found inside firmware zip")
        # Pick shallowest md5.txt
        md5_member = sorted(md5_candidates, key=lambda s: s.count("/"))[0]
        md5_norm = md5_member.replace("\\", "/").lstrip("/")
        base_prefix = os.path.dirname(md5_norm)

        entries = parse_md5_txt(zf.read(md5_member))
        for rel, expected_md5 in entries:
            cand = f"{base_prefix}/{rel}".lstrip("/") if base_prefix else rel
            actual_member = (
                norm_map.get(cand)
                or norm_map.get(rel)
                or lower_map.get(cand.lower())
                or lower_map.get(rel.lower())
            )
            if actual_member is None:
                fail(f"file listed in md5.txt is missing from zip: {rel}")
            with zf.open(actual_member, "r") as fh:
                got_md5 = md5_stream(fh)
            if got_md5 != expected_md5:
                fail(f"MD5 mismatch for {rel}: expected {expected_md5}, got {got_md5}")
            verified_count += 1

        # Locate rawprogram_nand_*.xml deterministically (sorted, preferring p4k_b256k)
        rp_candidates = [
            n for n in names
            if re.match(r"^rawprogram_nand_.*\.xml$", os.path.basename(n.replace("\\", "/")), re.IGNORECASE)
        ]
        if not rp_candidates:
            fail("rawprogram_nand_*.xml not found in firmware zip")
        rp_sorted = sorted(rp_candidates)
        rp_member = next(
            (c for c in rp_sorted if "p4k_b256k" in os.path.basename(c.replace("\\", "/")).lower()),
            rp_sorted[0],
        )
        rawprogram_name = os.path.basename(rp_member.replace("\\", "/"))
        rawprogram_bytes = zf.read(rp_member)

        # Look for c_project_name in contents.xml or other small xml/txt files
        for n in names:
            bn = os.path.basename(n.replace("\\", "/")).lower()
            if bn in ("contents.xml", "build_info.txt", "version.txt") or bn.endswith(".xml"):
                info = zf.getinfo(n)
                if info.file_size <= 2 * 1024 * 1024:
                    found = extract_project_name_from_xml_bytes(zf.read(n))
                    if found:
                        c_project_name = found
                        break
        if not c_project_name and base_prefix:
            c_project_name = base_prefix.split("/")[0]
elif os.path.isdir(target):
    all_files = []
    for root_dir, _dirs, files in os.walk(target):
        for fn in files:
            full = os.path.join(root_dir, fn)
            rel = os.path.relpath(full, target).replace("\\", "/")
            all_files.append((rel, full))
    norm_map = {rel: full for rel, full in all_files}
    lower_map = {rel.lower(): full for rel, full in all_files}

    md5_candidates = [(rel, full) for rel, full in all_files if os.path.basename(rel).lower() == "md5.txt"]
    if not md5_candidates:
        fail("md5.txt not found inside firmware directory")
    md5_rel, md5_full = sorted(md5_candidates, key=lambda x: x[0].count("/"))[0]
    base_prefix = os.path.dirname(md5_rel)

    with open(md5_full, "rb") as f:
        entries = parse_md5_txt(f.read())

    for rel, expected_md5 in entries:
        cand = f"{base_prefix}/{rel}".lstrip("/") if base_prefix else rel
        actual_full = (
            norm_map.get(cand)
            or norm_map.get(rel)
            or lower_map.get(cand.lower())
            or lower_map.get(rel.lower())
        )
        if actual_full is None:
            fail(f"file listed in md5.txt is missing from directory: {rel}")
        with open(actual_full, "rb") as fh:
            got_md5 = md5_stream(fh)
        if got_md5 != expected_md5:
            fail(f"MD5 mismatch for {rel}: expected {expected_md5}, got {got_md5}")
        verified_count += 1

    rp_candidates = [
        (rel, full) for rel, full in all_files
        if re.match(r"^rawprogram_nand_.*\.xml$", os.path.basename(rel), re.IGNORECASE)
    ]
    if not rp_candidates:
        fail("rawprogram_nand_*.xml not found in firmware directory")
    rp_sorted = sorted(rp_candidates, key=lambda x: x[0])
    rp_rel, rp_full = next(
        (pair for pair in rp_sorted if "p4k_b256k" in os.path.basename(pair[0]).lower()),
        rp_sorted[0],
    )
    rawprogram_name = os.path.basename(rp_rel)
    with open(rp_full, "rb") as f:
        rawprogram_bytes = f.read()

    for rel, full in all_files:
        bn = os.path.basename(rel).lower()
        if bn in ("contents.xml", "build_info.txt", "version.txt") or bn.endswith(".xml"):
            if os.path.getsize(full) <= 2 * 1024 * 1024:
                with open(full, "rb") as f:
                    found = extract_project_name_from_xml_bytes(f.read())
                if found:
                    c_project_name = found
                    break
    if not c_project_name:
        c_project_name = os.path.basename(os.path.abspath(target))
else:
    fail(f"unsupported path type: {target}")

analysis = analyze_rawprogram(rawprogram_name, rawprogram_bytes)
c_project_name = c_project_name or "unknown"

print(
    f"firmware_ok=1 verified_files={verified_count} "
    f"image_type={analysis['image_type']} c_project_name={c_project_name} "
    f"partitions={analysis['partitions']} ab_dual_slot={analysis['ab_dual_slot']} "
    f"rawprogram={rawprogram_name}"
)
PYEOF
}

# ---------------------------------------------------------------------------
# Subcommand 4: backup
# ---------------------------------------------------------------------------

cmd_backup() {
  local out_dir=""
  local qfenix_arg="${QFENIX_BIN:-}"
  local adb_serial=""
  local stop_mm=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out_dir="${2:?missing output directory}"; shift 2 ;;
      --qfenix) qfenix_arg="${2:?missing qfenix path}"; shift 2 ;;
      --adb-serial) adb_serial="${2:?missing adb serial}"; shift 2 ;;
      --stop-mm) stop_mm=1; shift ;;
      -h|--help) usage ;;
      *) echo "Unknown option for backup: $1" >&2; usage ;;
    esac
  done

  [ -n "$out_dir" ] || { echo "ERROR: backup requires --out <dir>" >&2; usage; }

  local qfenix_bin
  qfenix_bin=$(find_bin "$qfenix_arg" qfenix) || {
    echo "ERROR: qfenix binary not found (install qfenix or pass --qfenix <path>)" >&2
    exit 1
  }

  umask 077
  mkdir -p "$out_dir"
  chmod 0700 "$out_dir"

  # Query live IMEI via ADB before detaching drivers (best-effort)
  local live_imei=""
  if live_imei=$(query_live_imei_adb "$adb_serial" 2>/dev/null); then
    echo "==> Live IMEI read via ADB: $(mask_imei "$live_imei")"
  else
    echo "==> Note: ADB live IMEI read unavailable; will validate NV 550 Luhn from captured XQCN."
  fi

  stop_modem_manager_if_requested "$stop_mm"
  detach_qcserial

  local stamp xqcn_out tar_out
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  xqcn_out="${out_dir}/efs_${stamp}.xqcn"
  tar_out="${out_dir}/efs_${stamp}.tar"

  echo "==> Capturing EFS XQCN backup -> ${xqcn_out}..."
  run_privileged "$qfenix_bin" efsbackup "$xqcn_out"
  if [ "$(id -u)" -ne 0 ]; then
    run_privileged chown "$(id -u):$(id -g)" "$xqcn_out" 2>/dev/null || true
  fi
  chmod 0600 "$xqcn_out"

  echo "==> Capturing EFS TAR backup -> ${tar_out}..."
  run_privileged "$qfenix_bin" efsbackup "$tar_out"
  if [ "$(id -u)" -ne 0 ]; then
    run_privileged chown "$(id -u):$(id -g)" "$tar_out" 2>/dev/null || true
  fi
  chmod 0600 "$tar_out"

  [ -s "$tar_out" ] || { echo "ERROR: captured EFS .tar backup is missing or empty: ${tar_out}" >&2; exit 1; }

  echo "==> Verifying captured XQCN backup (>= 1 MiB, NV 550 IMEI, Luhn)..."
  if [ -n "$live_imei" ]; then
    cmd_inspect_xqcn "$xqcn_out" --expected-imei "$live_imei"
  else
    cmd_inspect_xqcn "$xqcn_out"
  fi

  echo "==> Writing ${out_dir}/SHA256SUMS..."
  local sum_file="${out_dir}/SHA256SUMS"
  (
    umask 077
    cd "$out_dir"
    printf '%s  %s\n' "$(sha256_of "$(basename "$xqcn_out")")" "$(basename "$xqcn_out")"
    printf '%s  %s\n' "$(sha256_of "$(basename "$tar_out")")" "$(basename "$tar_out")"
  ) > "$sum_file"
  chmod 0600 "$sum_file"

  LAST_BACKUP_XQCN="$xqcn_out"
  echo "==> Backup complete & verified:"
  echo "    XQCN : ${xqcn_out}"
  echo "    TAR  : ${tar_out}"
  echo "    SUMS : ${sum_file}"
}

# ---------------------------------------------------------------------------
# Subcommand 5: flash
# ---------------------------------------------------------------------------

unpack_firmware_to_update_dir() {
  local src="$1"
  local dest="$2"
  mkdir -p "$dest"
  if [ -f "$src" ]; then
    unzip -q "$src" -d "$dest"
  else
    cp -a "$src"/. "$dest"/
  fi
  # Locate directory containing firehose/rawprogram_nand_*.xml deterministically (sorted, preferring p4k_b256k)
  local rp_list rp_file
  rp_list=$(find "$dest" -type f -iname 'rawprogram_nand_*.xml' | LC_ALL=C sort)
  rp_file=$(printf '%s\n' "$rp_list" | grep -i 'p4k_b256k' | head -n 1 || true)
  if [ -z "$rp_file" ]; then
    rp_file=$(printf '%s\n' "$rp_list" | head -n 1 || true)
  fi
  if [ -z "$rp_file" ]; then
    echo "ERROR: could not locate rawprogram_nand_*.xml after unpacking ${src}" >&2
    return 1
  fi
  local rp_dir parent_dir
  rp_dir=$(dirname "$rp_file")
  parent_dir=$(dirname "$rp_dir")
  if [ "$(basename "$rp_dir")" = "firehose" ]; then
    echo "$parent_dir"
  else
    echo "$rp_dir"
  fi
}

cmd_flash() {
  local firmware=""
  local factory_zip=""
  local backup_dir=""
  local existing_xqcn=""
  local erase_target=0
  local expected_imei=""
  local set_imei=""
  local qfirehose_arg="${QFIREHOSE_BIN:-}"
  local qfenix_arg="${QFENIX_BIN:-}"
  local adb_serial=""
  local stop_mm=0
  local dry_run=0

  # Bootstrap passthrough flags
  local skip_bootstrap=0
  local ssh_key=""
  local lan_ip=""
  local hostname_val=""
  local mbn_name=""
  local lan_gw_ip=""
  local config_bundle=""
  local root_shadow=""
  local local_ipk=""
  local lockdown=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --firmware) firmware="${2:?missing --firmware path}"; shift 2 ;;
      --factory-zip) factory_zip="${2:?missing --factory-zip path}"; shift 2 ;;
      --backup-dir) backup_dir="${2:?missing --backup-dir path}"; shift 2 ;;
      --existing-xqcn) existing_xqcn="${2:?missing --existing-xqcn path}"; shift 2 ;;
      --erase) erase_target=1; shift ;;
      --expected-imei) expected_imei="${2:?missing --expected-imei}"; shift 2 ;;
      --set-imei) set_imei="${2:?missing --set-imei}"; shift 2 ;;
      --qfirehose) qfirehose_arg="${2:?missing --qfirehose path}"; shift 2 ;;
      --qfenix) qfenix_arg="${2:?missing --qfenix path}"; shift 2 ;;
      --adb-serial) adb_serial="${2:?missing --adb-serial}"; shift 2 ;;
      --stop-mm) stop_mm=1; shift ;;
      --skip-bootstrap) skip_bootstrap=1; shift ;;
      --ssh-key) ssh_key="${2:?missing --ssh-key}"; shift 2 ;;
      --lan-ip) lan_ip="${2:?missing --lan-ip}"; shift 2 ;;
      --hostname) hostname_val="${2:?missing --hostname}"; shift 2 ;;
      --mbn) mbn_name="${2:?missing --mbn}"; shift 2 ;;
      --lan-gw-ip) lan_gw_ip="${2:?missing --lan-gw-ip}"; shift 2 ;;
      --config-bundle) config_bundle="${2:?missing --config-bundle}"; shift 2 ;;
      --root-shadow) root_shadow="${2:?missing --root-shadow}"; shift 2 ;;
      --ipk) local_ipk="${2:?missing --ipk}"; shift 2 ;;
      --lockdown) lockdown=1; shift ;;
      --dry-run) dry_run=1; shift ;;
      -h|--help) usage ;;
      *) echo "Unknown option for flash: $1" >&2; usage ;;
    esac
  done

  [ -n "$firmware" ] || { echo "ERROR: flash requires --firmware <zip-or-dir>" >&2; usage; }
  [ -n "$backup_dir" ] || { echo "ERROR: flash requires --backup-dir <dir>" >&2; usage; }

  echo "=== CellCore SDX75 USB Flasher (dry_run=${dry_run}) ==="

  # 1. Fail-closed verification of firmware zip(s)
  local factory_info="" target_info=""
  if [ -n "$factory_zip" ]; then
    echo "==> Verifying Stage-1 factory firmware: ${factory_zip}"
    factory_info=$(cmd_verify_firmware "$factory_zip")
    echo "    ${factory_info}"
  fi
  echo "==> Verifying target firmware: ${firmware}"
  target_info=$(cmd_verify_firmware "$firmware")
  echo "    ${target_info}"

  # 2. Validate IMEI guards (Luhn)
  if [ -n "$expected_imei" ]; then
    validate_imei_luhn "$expected_imei" "--expected-imei"
    echo "==> IMEI guard active: $(mask_imei "$expected_imei") (Luhn OK)"
  fi
  if [ -n "$set_imei" ]; then
    validate_imei_luhn "$set_imei" "--set-imei"
    echo "==> Post-restore IMEI override requested: $(mask_imei "$set_imei") (Luhn OK)"
  fi

  # 3. Validate existing XQCN if supplied
  local xqcn_info=""
  if [ -n "$existing_xqcn" ]; then
    echo "==> Verifying existing XQCN backup: ${existing_xqcn}"
    if [ -n "$expected_imei" ]; then
      xqcn_info=$(cmd_inspect_xqcn "$existing_xqcn" --expected-imei "$expected_imei")
    else
      xqcn_info=$(cmd_inspect_xqcn "$existing_xqcn")
    fi
    echo "    ${xqcn_info}"
  fi

  # 4. Build bootstrap passthrough argument list & validate via bootstrap.sh --dry-run
  local bs_args=(--adb --auto-overlay --at-baseline)
  [ -n "$adb_serial" ] && bs_args=(--adb-serial "$adb_serial" --auto-overlay --at-baseline)
  [ -n "$ssh_key" ] && bs_args+=(--ssh-key "$ssh_key")
  [ -n "$lan_ip" ] && bs_args+=(--lan-ip "$lan_ip")
  [ -n "$hostname_val" ] && bs_args+=(--hostname "$hostname_val")
  [ -n "$mbn_name" ] && bs_args+=(--mbn "$mbn_name")
  [ -n "$lan_gw_ip" ] && bs_args+=(--lan-gw-ip "$lan_gw_ip")
  [ -n "$config_bundle" ] && bs_args+=(--config-bundle "$config_bundle")
  [ -n "$root_shadow" ] && bs_args+=(--root-shadow "$root_shadow")
  [ -n "$local_ipk" ] && bs_args+=(--ipk "$local_ipk")
  [ "$lockdown" -eq 1 ] && bs_args+=(--lockdown)

  if [ "$skip_bootstrap" -ne 1 ]; then
    echo "==> Pre-validating bootstrap.sh arguments & config bundle..."
    "$ROOT/bootstrap.sh" "${bs_args[@]}" --dry-run >/dev/null
    echo "    bootstrap.sh dry-run validation passed."
  fi

  if [ "$dry_run" -eq 1 ]; then
    echo ""
    echo "[dry-run] Planned USB flash & provisioning sequence:"
    echo "  1. Backup / XQCN      : $([ -n "$existing_xqcn" ] && printf 'using verified %s' "$existing_xqcn" || printf 'capture fresh .xqcn + .tar into %s (>= 1 MiB + NV 550 Luhn)' "$backup_dir")"
    if [ -n "$factory_zip" ]; then
      echo "  2. Stage-1 factory    : QFirehose -e -f <unpacked:${factory_zip}> -> wait 90s re-enum"
      echo "  3. Stage-2 target     : QFirehose $([ "$erase_target" -eq 1 ] && echo '-e ')-f <unpacked:${firmware}> -> wait 90s re-enum"
    else
      echo "  2. Firmware flash     : QFirehose $([ "$erase_target" -eq 1 ] && echo '-e ')-f <unpacked:${firmware}> -> wait 90s re-enum"
    fi
    echo "  4. EFS restore        : qfenix efsrestore <verified.xqcn> -> AT+CFUN=1,1 -> wait re-enum -> verify live AT+CGSN"
    if [ -n "$set_imei" ]; then
      echo "  5. Explicit IMEI set  : AT+EGMR=1,7,\"$(mask_imei "$set_imei")\" -> AT+CFUN=1,1 -> verify live AT+CGSN"
    fi
    if [ "$skip_bootstrap" -eq 1 ]; then
      echo "  6. Bootstrap          : skipped (--skip-bootstrap)"
    else
      echo "  6. Bootstrap          : ${ROOT}/bootstrap.sh ${bs_args[*]}"
    fi
    echo "[dry-run] All pre-flight checks passed. No USB/modem operations were executed."
    exit 0
  fi

  # 5. Live flash: locate required host flash binaries
  local qfirehose_bin qfenix_bin
  qfirehose_bin=$(find_bin "$qfirehose_arg" QFirehose qfirehose) || {
    echo "ERROR: QFirehose binary not found (pass --qfirehose <path>)" >&2
    exit 1
  }
  qfenix_bin=$(find_bin "$qfenix_arg" qfenix) || {
    echo "ERROR: qfenix binary not found (pass --qfenix <path>)" >&2
    exit 1
  }

  # 6. Mandatory EFS backup (NEVER run QFirehose without a verified >= 1 MiB XQCN!)
  local xqcn_to_restore=""
  if [ -n "$existing_xqcn" ]; then
    xqcn_to_restore="$existing_xqcn"
  else
    echo "==> Capturing mandatory pre-flash EFS backup into ${backup_dir}..."
    local bk_args=(--out "$backup_dir" --qfenix "$qfenix_bin")
    [ -n "$adb_serial" ] && bk_args+=(--adb-serial "$adb_serial")
    [ "$stop_mm" -eq 1 ] && bk_args+=(--stop-mm)
    LAST_BACKUP_XQCN=""
    cmd_backup "${bk_args[@]}"
    xqcn_to_restore="$LAST_BACKUP_XQCN"
    [ -n "$xqcn_to_restore" ] && [ -f "$xqcn_to_restore" ] || { echo "ERROR: failed to locate captured .xqcn from backup in ${backup_dir}" >&2; exit 1; }
  fi

  # Re-verify XQCN NV 550 IMEI and capture its full IMEI internally for post-restore check
  local restored_expected_imei
  if [ -n "$expected_imei" ]; then
    restored_expected_imei=$(cmd_inspect_xqcn "$xqcn_to_restore" --show-imei --expected-imei "$expected_imei" | sed -n 's/^imei=\([0-9]\{15\}\).*/\1/p')
  else
    restored_expected_imei=$(cmd_inspect_xqcn "$xqcn_to_restore" --show-imei | sed -n 's/^imei=\([0-9]\{15\}\).*/\1/p')
  fi
  [ -n "$restored_expected_imei" ] || { echo "ERROR: failed to verify XQCN NV 550 IMEI before flashing" >&2; exit 1; }

  # 7. Unpack firmware into secure temp dir (cleaned via trap)
  local tmp_flash
  tmp_flash=$(mktemp -d)
  trap 'rm -rf "$tmp_flash"' EXIT

  local factory_update_dir="" target_update_dir=""
  if [ -n "$factory_zip" ]; then
    echo "==> Unpacking Stage-1 factory firmware..."
    factory_update_dir=$(unpack_firmware_to_update_dir "$factory_zip" "${tmp_flash}/factory")
  fi
  echo "==> Unpacking target firmware..."
  target_update_dir=$(unpack_firmware_to_update_dir "$firmware" "${tmp_flash}/target")

  stop_modem_manager_if_requested "$stop_mm"
  detach_qcserial

  # 8. Stage-1 factory repartition flash (if --factory-zip)
  if [ -n "$factory_update_dir" ]; then
    echo "==> [Stage 1] Flashing factory repartition image with QFirehose -e..."
    run_privileged "$qfirehose_bin" -e -f "$factory_update_dir"
    wait_for_modem_reenum "$adb_serial" "Stage-1 factory modem" 90
    detach_qcserial
  fi

  # 9. Stage-2 (or single-stage) target firmware flash
  echo "==> [Stage 2] Flashing target firmware with QFirehose$([ "$erase_target" -eq 1 ] && echo ' -e')..."
  if [ "$erase_target" -eq 1 ]; then
    run_privileged "$qfirehose_bin" -e -f "$target_update_dir"
  else
    run_privileged "$qfirehose_bin" -f "$target_update_dir"
  fi
  wait_for_modem_reenum "$adb_serial" "target firmware modem" 90

  # 10. Restore EFS XQCN and verify live IMEI
  echo "==> Re-verifying XQCN before EFS restore..."
  cmd_inspect_xqcn "$xqcn_to_restore" --expected-imei "$restored_expected_imei"
  detach_qcserial
  echo "==> Restoring EFS calibration & NV items via qfenix efsrestore..."
  run_privileged "$qfenix_bin" efsrestore "$xqcn_to_restore"

  echo "==> Rebooting modem radio/OS via AT+CFUN=1,1..."
  send_at_adb_or_serial "$adb_serial" "AT+CFUN=1,1"
  wait_for_modem_reenum "$adb_serial" "post-restore modem" 90

  local live_post_imei
  live_post_imei=$(query_live_imei_adb "$adb_serial" || true)
  if [ -n "$live_post_imei" ]; then
    if [ "$live_post_imei" != "$restored_expected_imei" ]; then
      echo "ERROR: post-restore live IMEI ($(mask_imei "$live_post_imei")) does NOT match restored XQCN ($(mask_imei "$restored_expected_imei"))!" >&2
      exit 1
    fi
    echo "==> Live IMEI verified after EFS restore: $(mask_imei "$live_post_imei")"
  else
    echo "WARNING: could not verify live AT+CGSN via ADB after EFS restore; confirm IMEI before field deployment." >&2
  fi

  # 11. Explicit opt-in --set-imei override
  if [ -n "$set_imei" ]; then
    echo "==> Applying explicit --set-imei ($(mask_imei "$set_imei"))..."
    send_at_adb_or_serial "$adb_serial" "AT+EGMR=1,7,\"${set_imei}\""
    send_at_adb_or_serial "$adb_serial" "AT+CFUN=1,1"
    wait_for_modem_reenum "$adb_serial" "post-IMEI-set modem" 90
    local after_set_imei
    after_set_imei=$(query_live_imei_adb "$adb_serial" || true)
    if [ -n "$after_set_imei" ] && [ "$after_set_imei" != "$set_imei" ]; then
      echo "ERROR: live IMEI ($(mask_imei "$after_set_imei")) does not match --set-imei ($(mask_imei "$set_imei"))!" >&2
      exit 1
    fi
  fi

  # 12. Full CellCore provisioning via bootstrap.sh (zero third-party scripts)
  if [ "$skip_bootstrap" -ne 1 ]; then
    echo "==> Running CellCore bootstrap.sh provisioning..."
    "$ROOT/bootstrap.sh" "${bs_args[@]}"
  else
    echo "==> Skipping bootstrap.sh (--skip-bootstrap)."
  fi

  echo ""
  echo "============================================================"
  echo " CellCore USB flash & provisioning complete!"
  echo "============================================================"
}

# ---------------------------------------------------------------------------
# Entrypoint dispatch
# ---------------------------------------------------------------------------

[ $# -ge 1 ] || usage
SUBCMD="$1"
shift

case "$SUBCMD" in
  doctor) cmd_doctor "$@" ;;
  inspect-xqcn) cmd_inspect_xqcn "$@" ;;
  verify-firmware) cmd_verify_firmware "$@" ;;
  backup) cmd_backup "$@" ;;
  flash) cmd_flash "$@" ;;
  -h|--help|help) usage ;;
  *) echo "Unknown subcommand: ${SUBCMD}" >&2; usage ;;
esac
