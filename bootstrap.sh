#!/usr/bin/env bash
# CellCore Factory-Modem Bootstrapper (Clean-Room, Verified, Reversible)
#
# Takes an out-of-the-box Quectel RM551E-GL / SDX75 modem over USB ADB or SSH,
# configures the usign-verified CellCore opkg feed (with option check_signature),
# optionally pivots the clean-room cellcored overlay, installs SSH keys / UCI
# network / hostname / AT baseline / validated config bundle / root shadow hash,
# verifies Packages.sig + package SHA-256, and installs + verifies sdxpinn-cellcore.
#
# Usage:
#   ./bootstrap.sh --adb [--auto-overlay] [--ssh-key ~/.ssh/id_ed25519.pub] [--dry-run]
#   ./bootstrap.sh --ssh root@192.168.225.1 [--ssh-key ~/.ssh/id_ed25519.pub] [--dry-run]
#   ./bootstrap.sh --adb --auto-overlay --lan-ip 192.168.224.1/24 --hostname modem0 \
#     --at-baseline --mbn Commercial-TMO --config-bundle ./bundle.tar.gz \
#     --root-shadow ./root.shadow --lockdown
#   ./bootstrap.sh --adb --revert [--purge]
#   ./bootstrap.sh --ssh root@192.168.225.1 --revert [--purge]
#
# Options:
#   --adb                       Use USB ADB transport
#   --adb-serial <id>           Use USB ADB transport for a specific device serial
#   --ssh <user@host>           Use SSH transport (StrictHostKeyChecking=accept-new)
#   --ssh-key <path>            Install SSH public key into /etc/dropbear/authorized_keys
#   --ipk <path>                Install a local sdxpinn-cellcore .ipk instead of fetching feed
#   --stage-overlay-helper      Opt-in early-boot /usrdata overlay helper for factory RO rootfs
#   --auto-overlay              Alias for --stage-overlay-helper
#   --config-bundle <tar.gz>    Validated config bundle (allowlisted /etc paths only, SHA-256 checked)
#   --lan-ip <ip[/prefix]>      Set UCI network.lan.ipaddr (and netmask if /prefix given)
#   --hostname <name>           Set UCI system.@system[0].hostname (RFC-1123 validated)
#   --at-baseline               Apply SDX75 Ethernet/5G baseline AT commands (pcie/mode, QMAPWAC)
#   --mbn <name>                With --at-baseline: disable MBN AutoSel and select <name>
#   --lan-gw-ip <ip>            With --at-baseline: configure AT+QMAP="LANIP" gateway
#   --root-shadow <file>        Apply root shadow hash from a 0600 file without echoing to stdout/ps
#   --lockdown                  Final opt-in hardening (requires non-empty authorized_keys)
#   --dry-run                   Validate inputs locally and preview planned steps without changes
#   --revert [--purge]          Reversible rollback to stock factory rootfs
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED_NAME="CellCore-repo"
FEED_URL="${CELLCORE_FEED_URL:-https://raw.githubusercontent.com/GizmoTickler/CellCore/main/feed}"
PUBKEY_ID="14647e6bee9674ba"
PUBKEY_CONTENT="untrusted comment: CellCore SDXPINN opkg feed
RWQUZH5r7pZ0ulLC3JfaotxtUoYnUmTrN5IzN8RmZXI1xGURn1z+EKfl"
EXPECTED_USIGN_X64_SHA="961aacc9dc143c3e14bd04732e7917ff2801c2b705131ba9416c38e1022bf169"

MODE=""
SSH_TARGET=""
ADB_SERIAL=""
SSH_PUBKEY=""
LOCAL_IPK=""
STAGE_OVERLAY_HELPER=0
CONFIG_BUNDLE=""
LAN_IP_SPEC=""
LAN_IP=""
LAN_PREFIX=""
LAN_NETMASK=""
HOSTNAME_VAL=""
AT_BASELINE=0
MBN_NAME=""
LAN_GW_IP=""
ROOT_SHADOW_FILE=""
LOCKDOWN=0
DRY_RUN=0
REVERT=0
PURGE=0

usage() {
  sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --adb) MODE="adb"; shift ;;
    --adb-serial) MODE="adb"; ADB_SERIAL="${2:?missing serial}"; shift 2 ;;
    --ssh) MODE="ssh"; SSH_TARGET="${2:?missing user@host}"; shift 2 ;;
    --ssh-key) SSH_PUBKEY="${2:?missing pubkey path}"; shift 2 ;;
    --ipk) LOCAL_IPK="${2:?missing ipk path}"; shift 2 ;;
    --stage-overlay-helper|--auto-overlay) STAGE_OVERLAY_HELPER=1; shift ;;
    --config-bundle) CONFIG_BUNDLE="${2:?missing config bundle path}"; shift 2 ;;
    --lan-ip) LAN_IP_SPEC="${2:?missing LAN IP}"; shift 2 ;;
    --hostname) HOSTNAME_VAL="${2:?missing hostname}"; shift 2 ;;
    --at-baseline) AT_BASELINE=1; shift ;;
    --mbn) MBN_NAME="${2:?missing MBN profile name}"; shift 2 ;;
    --lan-gw-ip) LAN_GW_IP="${2:?missing LAN gateway IP}"; shift 2 ;;
    --root-shadow) ROOT_SHADOW_FILE="${2:?missing root shadow file}"; shift 2 ;;
    --lockdown) LOCKDOWN=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --revert) REVERT=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

[ -n "$MODE" ] || { echo "ERROR: specify --adb or --ssh <user@host>" >&2; usage; }

# ---------------------------------------------------------------------------
# Local fail-closed validators (run BEFORE touching USB/SSH/modem)
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

validate_ipv4() {
  local ip="$1"
  local label="${2:-IPv4 address}"
  if ! printf '%s' "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    echo "ERROR: invalid ${label}: ${ip}" >&2
    return 1
  fi
  local IFS='.'
  local o1 o2 o3 o4
  read -r o1 o2 o3 o4 <<< "$ip"
  local o
  for o in "$o1" "$o2" "$o3" "$o4"; do
    # Reject leading zeros (e.g. 010) to avoid octal ambiguity
    if [ "${#o}" -gt 1 ] && [ "${o#0}" != "$o" ]; then
      echo "ERROR: invalid ${label} (leading zero in octet): ${ip}" >&2
      return 1
    fi
    if [ "$o" -lt 0 ] || [ "$o" -gt 255 ]; then
      echo "ERROR: invalid ${label} (octet out of range): ${ip}" >&2
      return 1
    fi
  done
  if [ "$ip" = "0.0.0.0" ] || [ "$ip" = "255.255.255.255" ]; then
    echo "ERROR: invalid ${label} (reserved address): ${ip}" >&2
    return 1
  fi
}

prefix_to_netmask() {
  local p="$1"
  local mask=$(( 0xffffffff ^ ((1 << (32 - p)) - 1) ))
  printf '%d.%d.%d.%d\n' \
    $(( (mask >> 24) & 255 )) \
    $(( (mask >> 16) & 255 )) \
    $(( (mask >> 8) & 255 )) \
    $(( mask & 255 ))
}

validate_lan_ip_spec() {
  local spec="$1"
  if [[ "$spec" == */* ]]; then
    LAN_IP="${spec%%/*}"
    LAN_PREFIX="${spec#*/}"
    if [[ "$LAN_PREFIX" == */* ]] || ! printf '%s' "$LAN_PREFIX" | grep -qE '^[0-9]{1,2}$'; then
      echo "ERROR: invalid --lan-ip prefix: ${spec}" >&2
      return 1
    fi
    if [ "$LAN_PREFIX" -lt 1 ] || [ "$LAN_PREFIX" -gt 32 ]; then
      echo "ERROR: invalid --lan-ip prefix length (must be 1..32): ${spec}" >&2
      return 1
    fi
    validate_ipv4 "$LAN_IP" "--lan-ip"
    LAN_NETMASK="$(prefix_to_netmask "$LAN_PREFIX")"
  else
    LAN_IP="$spec"
    LAN_PREFIX=""
    LAN_NETMASK=""
    validate_ipv4 "$LAN_IP" "--lan-ip"
  fi
}

validate_hostname() {
  local h="$1"
  if ! printf '%s' "$h" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'; then
    echo "ERROR: invalid RFC-1123 --hostname: ${h}" >&2
    return 1
  fi
}

validate_mbn() {
  local m="$1"
  if ! printf '%s' "$m" | grep -qE '^[A-Za-z0-9._-]+$'; then
    echo "ERROR: invalid --mbn profile name (allowed: A-Za-z0-9._-): ${m}" >&2
    return 1
  fi
}

validate_feed_url() {
  local url="$1"
  if [ -z "$url" ] || [ "${#url}" -gt 512 ]; then
    echo "ERROR: invalid CELLCORE_FEED_URL (empty or too long)" >&2
    return 1
  fi
  # Reject single quotes, whitespace, control characters, and shell metacharacters
  if printf '%s' "$url" | LC_ALL=C grep -qE "[[:space:][:cntrl:]'\"\`\$;\|&<>()\\\\{}\*\?]"; then
    echo "ERROR: invalid CELLCORE_FEED_URL (contains forbidden quotes, whitespace, or shell metacharacters): ${url}" >&2
    return 1
  fi
  if ! printf '%s' "$url" | grep -qE '^https?://[A-Za-z0-9._~:/@%+-]+$'; then
    echo "ERROR: invalid CELLCORE_FEED_URL (must be a clean http(s):// URL): ${url}" >&2
    return 1
  fi
}

validate_config_bundle() {
  local bundle="$1"
  if [ ! -f "$bundle" ]; then
    echo "ERROR: --config-bundle file not found: ${bundle}" >&2
    return 1
  fi
  command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required to safely validate --config-bundle" >&2
    return 1
  }
  python3 - "$bundle" <<'PYEOF'
import sys, tarfile

bundle_path = sys.argv[1]
ALLOWED_DIR_PREFIXES = (
    "etc/config/",
    "etc/cellcore/",
    "etc/ssl/acme/",
    "etc/crontabs/",
)
ALLOWED_EXACT_FILES = {
    "etc/dropbear/authorized_keys",
    "etc/rc.local",
}
ALLOWED_ANCESTOR_DIRS = {
    "etc",
    "etc/config",
    "etc/cellcore",
    "etc/ssl",
    "etc/ssl/acme",
    "etc/dropbear",
    "etc/crontabs",
}
MAX_ENTRIES = 512

def fail(msg):
    sys.stderr.write(f"ERROR: --config-bundle validation failed: {msg}\n")
    sys.exit(1)

try:
    tf = tarfile.open(bundle_path, mode="r:gz")
except Exception as exc:
    fail(f"cannot open gzip tar archive ({exc})")

with tf:
    members = tf.getmembers()
    if len(members) > MAX_ENTRIES:
        fail(f"archive exceeds maximum entry count ({len(members)} > {MAX_ENTRIES})")
    reg_count = 0
    for m in members:
        raw = m.name
        if not raw or "\x00" in raw or "\n" in raw or "\r" in raw:
            fail(f"illegal control character or empty name in archive entry: {raw!r}")
        if raw.startswith("/") or raw.startswith("\\"):
            fail(f"absolute path not allowed: {raw!r}")
        if "\\" in raw:
            fail(f"backslash path separator not allowed: {raw!r}")
        parts = raw.split("/")
        if ".." in parts:
            fail(f"path traversal ('..') not allowed: {raw!r}")
        if m.issym() or m.islnk():
            fail(f"symlinks and hardlinks are not allowed: {raw!r}")
        if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
            fail(f"device nodes and FIFOs are not allowed: {raw!r}")
        if not (m.isreg() or m.isdir()):
            fail(f"unsupported archive entry type ({m.type!r}): {raw!r}")

        norm = raw
        while norm.startswith("./"):
            norm = norm[2:]
        norm_no_trail = norm.rstrip("/")

        if norm_no_trail in ("", "."):
            if not m.isdir():
                fail(f"invalid non-directory root entry: {raw!r}")
            continue

        if m.isdir():
            if norm_no_trail in ALLOWED_ANCESTOR_DIRS or any(
                norm_no_trail.startswith(p) for p in ALLOWED_DIR_PREFIXES
            ):
                continue
            fail(f"disallowed directory outside allowlist: {raw!r}")

        # Regular file
        if norm_no_trail in ALLOWED_EXACT_FILES:
            reg_count += 1
            continue
        if any(
            norm_no_trail.startswith(p) and len(norm_no_trail) > len(p)
            for p in ALLOWED_DIR_PREFIXES
        ):
            reg_count += 1
            continue
        fail(f"disallowed file path outside allowlist: {raw!r}")

    if reg_count == 0:
        fail("archive contains no regular files inside the allowed paths")
PYEOF
}

validate_root_shadow() {
  local sfile="$1"
  if [ ! -f "$sfile" ]; then
    echo "ERROR: --root-shadow file not found: ${sfile}" >&2
    return 1
  fi
  if [ -L "$sfile" ]; then
    echo "ERROR: --root-shadow file must not be a symlink: ${sfile}" >&2
    return 1
  fi
  local mode=""
  if stat -c '%a' "$sfile" >/dev/null 2>&1; then
    mode=$(stat -c '%a' "$sfile")
  elif stat -f '%Lp' "$sfile" >/dev/null 2>&1; then
    mode=$(stat -f '%Lp' "$sfile")
  else
    echo "ERROR: unable to inspect permissions on --root-shadow file" >&2
    return 1
  fi
  if [ "$mode" != "600" ]; then
    echo "ERROR: --root-shadow file must have mode 0600 (got 0${mode}); run 'chmod 0600 ${sfile}'" >&2
    return 1
  fi
  local line_count
  line_count=$(grep -cv '^[[:space:]]*$' "$sfile" || true)
  if [ "$line_count" -ne 1 ]; then
    echo "ERROR: --root-shadow file must contain exactly 1 non-empty shadow hash line (got ${line_count})" >&2
    return 1
  fi
  local hash_val
  hash_val=$(grep -v '^[[:space:]]*$' "$sfile" | tr -d '\r\n')
  if ! printf '%s' "$hash_val" | grep -qE '^\$(5|6|y)\$[A-Za-z0-9./$=+_-]+$'; then
    echo "ERROR: --root-shadow line must be a valid \$5\$, \$6\$, or \$y\$ crypt hash with no whitespace or colons" >&2
    return 1
  fi
}

derive_qmap_lanip_range() {
  local gw="$1"
  local IFS='.'
  local o1 o2 o3 o4
  read -r o1 o2 o3 o4 <<< "$gw"
  if [ "$o4" -ge 100 ] && [ "$o4" -le 200 ]; then
    printf '%s.%s.%s.20,%s.%s.%s.99,%s\n' "$o1" "$o2" "$o3" "$o1" "$o2" "$o3" "$gw"
  else
    printf '%s.%s.%s.100,%s.%s.%s.200,%s\n' "$o1" "$o2" "$o3" "$o1" "$o2" "$o3" "$gw"
  fi
}

# Run all local validations immediately (even in --dry-run and before touching USB/SSH)
validate_feed_url "$FEED_URL"
if [ -n "$SSH_PUBKEY" ] && [ ! -f "$SSH_PUBKEY" ]; then
  echo "ERROR: SSH public key not found: $SSH_PUBKEY" >&2
  exit 1
fi
if [ -n "$LOCAL_IPK" ] && [ ! -f "$LOCAL_IPK" ]; then
  echo "ERROR: local .ipk not found: $LOCAL_IPK" >&2
  exit 1
fi
if [ -n "$CONFIG_BUNDLE" ]; then
  validate_config_bundle "$CONFIG_BUNDLE"
fi
if [ -n "$LAN_IP_SPEC" ]; then
  validate_lan_ip_spec "$LAN_IP_SPEC"
fi
if [ -n "$HOSTNAME_VAL" ]; then
  validate_hostname "$HOSTNAME_VAL"
fi
if [ -n "$MBN_NAME" ]; then
  validate_mbn "$MBN_NAME"
fi
if [ -n "$LAN_GW_IP" ]; then
  validate_ipv4 "$LAN_GW_IP" "--lan-gw-ip"
fi
if [ -n "$ROOT_SHADOW_FILE" ]; then
  validate_root_shadow "$ROOT_SHADOW_FILE"
fi

# Transport wrappers (ADB or SSH; StrictHostKeyChecking=accept-new prevents MITM on known hosts)
adb_cmd() {
  if [ -n "$ADB_SERIAL" ]; then
    adb -s "$ADB_SERIAL" "$@"
  else
    adb "$@"
  fi
}

run_remote() {
  local script="$1"
  if [ "$MODE" = "adb" ]; then
    adb_cmd shell "$script"
  else
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "$SSH_TARGET" "$script"
  fi
}

push_file() {
  local local_path="$1"
  local remote_path="$2"
  if [ "$MODE" = "adb" ]; then
    adb_cmd push "$local_path" "$remote_path" >/dev/null
  else
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 "$SSH_TARGET" "cat > '$remote_path'" < "$local_path"
  fi
}

# Send an AT command via cellctl (preferred when cellcored owns /dev/smd7) or /dev/smd7 directly
send_remote_at() {
  local cmd="$1"
  local escaped_cmd
  escaped_cmd=$(printf '%s' "$cmd" | sed "s/'/'\\\\''/g")
  run_remote "
    if command -v cellctl >/dev/null 2>&1; then
      cellctl at '${escaped_cmd}'
    elif [ -c /dev/smd7 ]; then
      printf '%s\r\n' '${escaped_cmd}' > /dev/smd7
      sleep 1
    else
      echo 'ERROR: neither cellctl nor /dev/smd7 available for AT command' >&2
      exit 1
    fi
  "
}

wait_for_device() {
  echo "==> Waiting for modem to come back online (up to 90s)..."
  local i=0
  while [ "$i" -lt 45 ]; do
    sleep 2
    i=$((i + 1))
    if [ "$MODE" = "adb" ]; then
      if adb_cmd get-state 2>/dev/null | grep -qx "device"; then
        if run_remote "echo ready" 2>/dev/null | grep -q "ready"; then
          return 0
        fi
      fi
    else
      if run_remote "echo ready" 2>/dev/null | grep -q "ready"; then
        return 0
      fi
    fi
  done
  echo "ERROR: timed out waiting for modem to reconnect after reboot." >&2
  return 1
}

TMP_WORK=$(mktemp -d)
trap 'rm -rf "$TMP_WORK"' EXIT

resolve_usign() {
  if command -v usign >/dev/null 2>&1; then
    command -v usign
    return 0
  fi
  local bundled="$ROOT/scripts/feed/usign_x64"
  if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ] && [ -x "$bundled" ]; then
    local got
    got=$(sha256_of "$bundled")
    if [ "$got" != "$EXPECTED_USIGN_X64_SHA" ]; then
      echo "ERROR: bundled scripts/feed/usign_x64 SHA-256 mismatch!" >&2
      return 1
    fi
    echo "$bundled"
    return 0
  fi
  echo "ERROR: usign binary not found (install usign to verify feed/Packages.sig)" >&2
  return 1
}

resolve_pubkey_file() {
  local out="$TMP_WORK/usign.pub"
  if [ -f "$ROOT/feed/usign.pub" ]; then
    cp -f "$ROOT/feed/usign.pub" "$out"
  else
    printf '%s\n' "$PUBKEY_CONTENT" > "$out"
  fi
  echo "$out"
}

# Verify feed/Packages.sig against feed/usign.pub AND verify the .ipk SHA-256
# against the signed Packages stanza before touching any device binary or opkg install.
resolve_verified_feed_ipk() {
  local usign_bin pub_file pkgs_file sig_file ipk_path
  usign_bin=$(resolve_usign)
  pub_file=$(resolve_pubkey_file)
  pkgs_file="$TMP_WORK/Packages"
  sig_file="$TMP_WORK/Packages.sig"

  if [ -f "$ROOT/feed/Packages" ] && [ -f "$ROOT/feed/Packages.sig" ] && [ -z "${CELLCORE_FEED_URL:-}" ]; then
    echo "==> Verifying local feed/Packages.sig with usign..." >&2
    cp -f "$ROOT/feed/Packages" "$pkgs_file"
    cp -f "$ROOT/feed/Packages.sig" "$sig_file"
  else
    echo "==> Downloading and verifying ${FEED_URL}/Packages + Packages.sig..." >&2
    curl -fsSL "${FEED_URL}/Packages" -o "$pkgs_file"
    curl -fsSL "${FEED_URL}/Packages.sig" -o "$sig_file"
  fi

  "$usign_bin" -V -m "$pkgs_file" -x "$sig_file" -p "$pub_file" >/dev/null || {
    echo "ERROR: Packages.sig signature verification FAILED against ${pub_file}; aborting!" >&2
    return 1
  }

  local pkg_file expected_sha
  pkg_file=$(awk '/^Package: sdxpinn-cellcore$/{f=1; next} f && /^Package:/{exit} f && /^Filename:/{print $2; exit}' "$pkgs_file")
  expected_sha=$(awk '/^Package: sdxpinn-cellcore$/{f=1; next} f && /^Package:/{exit} f && /^SHA256sum:/{print tolower($2); exit}' "$pkgs_file")

  if [ -z "$pkg_file" ] || [[ "$pkg_file" == */* ]] || [[ "$pkg_file" == *..* ]]; then
    echo "ERROR: invalid or missing Filename for sdxpinn-cellcore in signed Packages" >&2
    return 1
  fi
  if ! printf '%s' "$expected_sha" | grep -qE '^[0-9a-f]{64}$'; then
    echo "ERROR: invalid or missing SHA256sum for sdxpinn-cellcore in signed Packages" >&2
    return 1
  fi

  if [ -f "$ROOT/feed/$pkg_file" ] && [ -z "${CELLCORE_FEED_URL:-}" ]; then
    ipk_path="$ROOT/feed/$pkg_file"
  else
    ipk_path="$TMP_WORK/$pkg_file"
    echo "==> Downloading ${pkg_file} from ${FEED_URL}..." >&2
    curl -fsSL "${FEED_URL}/${pkg_file}" -o "$ipk_path"
  fi

  local actual_sha
  actual_sha=$(sha256_of "$ipk_path")
  if [ "$actual_sha" != "$expected_sha" ]; then
    echo "ERROR: SHA-256 mismatch for ${pkg_file}!" >&2
    echo "  expected: ${expected_sha}" >&2
    echo "  actual  : ${actual_sha}" >&2
    return 1
  fi
  echo "==> Verified ${pkg_file} (usign OK, sha256=${actual_sha})" >&2
  echo "$ipk_path"
}

extract_verified_cellcored_from_ipk() {
  local ipk="$1"
  mkdir -p "$TMP_WORK/extract"
  tar -xzf "$ipk" -C "$TMP_WORK/extract" ./data.tar.gz 2>/dev/null || tar -xzf "$ipk" -C "$TMP_WORK/extract" data.tar.gz
  tar -xzf "$TMP_WORK/extract/"*data.tar.gz -C "$TMP_WORK/extract" ./usr/sbin/cellcored 2>/dev/null || \
    tar -xzf "$TMP_WORK/extract/"*data.tar.gz -C "$TMP_WORK/extract" usr/sbin/cellcored
  chmod 0755 "$TMP_WORK/extract/usr/sbin/cellcored"
  echo "$TMP_WORK/extract/usr/sbin/cellcored"
}

print_dry_run_plan() {
  local verified_ipk="$1"
  echo ""
  echo "[dry-run] Planned execution steps:"
  echo "  1. Transport          : ${MODE}$([ "$MODE" = "ssh" ] && printf ' (%s)' "$SSH_TARGET" || true)$([ -n "$ADB_SERIAL" ] && printf ' (serial=%s)' "$ADB_SERIAL" || true)"
  echo "  2. Package            : ${verified_ipk} (sha256=$(sha256_of "$verified_ipk"))"
  echo "  3. Overlay pivot      : $([ "$STAGE_OVERLAY_HELPER" -eq 1 ] && echo 'enabled (--auto-overlay / --stage-overlay-helper if RO rootfs)' || echo 'disabled (requires already-writable rootfs)')"
  echo "  4. opkg feed          : ${FEED_NAME} (${FEED_URL}, usign key ${PUBKEY_ID}, option check_signature)"
  if [ -n "$CONFIG_BUNDLE" ]; then
    echo "  5. Config bundle      : ${CONFIG_BUNDLE} (validated OK, sha256=$(sha256_of "$CONFIG_BUNDLE")) -> extract to /, fix perms, restart cellcored"
  fi
  if [ -n "$SSH_PUBKEY" ]; then
    echo "  6. SSH public key     : ${SSH_PUBKEY} -> /etc/dropbear/authorized_keys (0600)"
  fi
  if [ -n "$HOSTNAME_VAL" ]; then
    echo "  7. Hostname           : ${HOSTNAME_VAL} (UCI system.@system[0].hostname)"
  fi
  if [ -n "$LAN_IP" ]; then
    echo "  8. LAN IP             : ${LAN_IP}$([ -n "$LAN_NETMASK" ] && printf ' / netmask %s' "$LAN_NETMASK" || true) ($([ "$MODE" = "adb" ] && echo 'reload network' || echo 'commit UCI only; applies on reboot in SSH mode'))"
  fi
  if [ -n "$ROOT_SHADOW_FILE" ]; then
    echo "  9. Root shadow hash   : ${ROOT_SHADOW_FILE} (mode 0600 validated; atomic /etc/shadow update, never echoed)"
  fi
  if [ "$AT_BASELINE" -eq 1 ]; then
    echo " 10. AT baseline        : AT+QCFG=\"pcie/mode\",1; AT+QMAPWAC=1"
    if [ -n "$MBN_NAME" ]; then
      echo "     - MBN select       : AT+QMBNCFG=\"AutoSel\",0; AT+QMBNCFG=\"Select\",\"${MBN_NAME}\""
    fi
    if [ -n "$LAN_GW_IP" ]; then
      echo "     - QMAP LANIP       : AT+QMAP=\"LANIP\",$(derive_qmap_lanip_range "$LAN_GW_IP")"
    fi
  elif [ -n "$MBN_NAME" ] || [ -n "$LAN_GW_IP" ]; then
    echo " 10. AT baseline        : NOTE --mbn/--lan-gw-ip require --at-baseline to be applied"
  fi
  echo " 11. Health check       : cellctl verify --expect-wan 0 && cellctl overlay status"
  if [ "$LOCKDOWN" -eq 1 ]; then
    echo " 12. Lockdown (final)   : verify non-empty authorized_keys; disable Dropbear password auth; disable ttyd & adbd.init"
  fi
  echo "[dry-run] Preflight & validation complete. No changes were written to the modem."
}

echo "=== CellCore SDX75 Bootstrapper (mode=${MODE}, dry_run=${DRY_RUN}, revert=${REVERT}) ==="

# Handle dry-run cleanly (connects if device is present, or runs offline validation if no device attached)
if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$REVERT" -eq 1 ]; then
    echo "[dry-run] Would restore factory /etc/opkg.conf & customfeeds.conf, remove cellcore-overlay hooks (purge=${PURGE}), and reboot."
    exit 0
  fi

  DEVICE_ONLINE=0
  if [ "$MODE" = "adb" ]; then
    if command -v adb >/dev/null 2>&1 && adb_cmd get-state 2>/dev/null | grep -qx "device"; then
      DEVICE_ONLINE=1
    fi
  else
    if run_remote "echo ready" 2>/dev/null | grep -q "ready"; then
      DEVICE_ONLINE=1
    fi
  fi

  if [ "$DEVICE_ONLINE" -eq 1 ]; then
    ARCH=$(run_remote "uname -m" | tr -d '\r\n')
    UID_VAL=$(run_remote "id -u" | tr -d '\r\n')
    echo "==> Connected: arch=${ARCH}, uid=${UID_VAL}"
    [ "$ARCH" = "aarch64" ] || { echo "ERROR: expected aarch64 SDX75 modem, got ${ARCH}" >&2; exit 1; }
    [ "$UID_VAL" = "0" ] || { echo "ERROR: root shell required (uid=0, got ${UID_VAL})" >&2; exit 1; }
    echo "==> Running preflight mount & space check..."
    run_remote "cat /proc/mounts | grep -E ' (/|/real_rootfs|/usrdata|/etc|/overlay) ' || true; df -h / /usrdata 2>/dev/null || true"
  else
    echo "[dry-run] No live modem connected on ${MODE}; performing full offline validation & plan preview."
  fi

  VERIFIED_IPK=""
  if [ -n "$LOCAL_IPK" ]; then
    echo "==> Using operator-supplied local package: ${LOCAL_IPK} (sha256=$(sha256_of "$LOCAL_IPK"))"
    VERIFIED_IPK="$LOCAL_IPK"
  else
    VERIFIED_IPK=$(resolve_verified_feed_ipk)
  fi

  print_dry_run_plan "$VERIFIED_IPK"
  exit 0
fi

# 1. Verify connectivity and architecture
if [ "$MODE" = "adb" ]; then
  command -v adb >/dev/null 2>&1 || { echo "ERROR: adb not found in PATH" >&2; exit 1; }
  adb_cmd get-state | grep -qx "device" || { echo "ERROR: no ADB device ready (run 'adb devices')" >&2; exit 1; }
fi

ARCH=$(run_remote "uname -m" | tr -d '\r\n')
UID_VAL=$(run_remote "id -u" | tr -d '\r\n')
echo "==> Connected: arch=${ARCH}, uid=${UID_VAL}"
[ "$ARCH" = "aarch64" ] || { echo "ERROR: expected aarch64 SDX75 modem, got ${ARCH}" >&2; exit 1; }
[ "$UID_VAL" = "0" ] || { echo "ERROR: root shell required (uid=0, got ${UID_VAL})" >&2; exit 1; }

# Handle clean reversible rollback mode
if [ "$REVERT" -eq 1 ]; then
  echo "==> Reverting CellCore bootstrap (purge=${PURGE})..."
  PURGE_FLAG=""
  [ "$PURGE" -eq 1 ] && PURGE_FLAG="--purge"
  run_remote "
    set -e
    if [ -f /usrdata/cellcore-factory-backup/opkg.conf ]; then
      cp -p /usrdata/cellcore-factory-backup/opkg.conf /etc/opkg.conf 2>/dev/null || true
    fi
    if [ -f /usrdata/cellcore-factory-backup/customfeeds.conf ]; then
      cp -p /usrdata/cellcore-factory-backup/customfeeds.conf /etc/opkg/customfeeds.conf 2>/dev/null || true
    fi
    if [ -x /usr/sbin/cellcored ]; then
      /usr/sbin/cellcored overlay revert --yes ${PURGE_FLAG}
    elif [ -x /usrdata/bin/cellcored ]; then
      /usrdata/bin/cellcored overlay revert --yes ${PURGE_FLAG}
    else
      echo 'ERROR: cellcored binary not found on device' >&2
      exit 1
    fi
    if [ '${PURGE}' = '1' ]; then
      rm -rf /usrdata/bin/cellcored
    fi
    sync
  "
  echo "==> Revert staged cleanly! Reboot the modem ('reboot') to return to 100% stock factory rootfs."
  exit 0
fi

# 2. Resolve and cryptographically verify the target .ipk before touching the modem
VERIFIED_IPK=""
if [ -n "$LOCAL_IPK" ]; then
  echo "==> Using operator-supplied local package: ${LOCAL_IPK} (sha256=$(sha256_of "$LOCAL_IPK"))"
  VERIFIED_IPK="$LOCAL_IPK"
else
  VERIFIED_IPK=$(resolve_verified_feed_ipk)
fi

# 3. Inspect mount layout & backup factory opkg config (no unmanaged binary staged by default)
echo "==> Running preflight mount & space check..."
run_remote "
  mkdir -p /usrdata/cellcore-factory-backup
  [ -f /usrdata/cellcore-factory-backup/opkg.conf ] || cp -p /etc/opkg.conf /usrdata/cellcore-factory-backup/opkg.conf 2>/dev/null || true
  [ -f /usrdata/cellcore-factory-backup/customfeeds.conf ] || cp -p /etc/opkg/customfeeds.conf /usrdata/cellcore-factory-backup/customfeeds.conf 2>/dev/null || true
"

ROOT_RW=$(run_remote "if touch /etc/.cellcore_rw_probe 2>/dev/null; then rm -f /etc/.cellcore_rw_probe; echo 1; else echo 0; fi" | tr -d '\r\n')

# 4. Early-boot overlay pivot (strictly opt-in via --stage-overlay-helper / --auto-overlay
#    for factory read-only rootfs; never stages an unmanaged /usrdata/bin shadow binary on
#    already-writable systems).
if [ "$ROOT_RW" != "1" ]; then
  if [ "$STAGE_OVERLAY_HELPER" -ne 1 ]; then
    echo "ERROR: root filesystem is read-only (factory stock rootfs)." >&2
    echo "       To keep /usr/sbin/cellcored managed strictly by opkg, staging an early-boot" >&2
    echo "       overlay helper under /usrdata/bin is disabled by default." >&2
    echo "       Re-run with --auto-overlay (or --stage-overlay-helper) to pivot the verified overlay on this factory modem." >&2
    exit 1
  fi
  CELLCORED_BIN=$(extract_verified_cellcored_from_ipk "$VERIFIED_IPK")
  echo "==> Staging usign+SHA-256 verified early-boot overlay helper -> /usrdata/bin/cellcored"
  run_remote "mkdir -p /usrdata/bin"
  push_file "$CELLCORED_BIN" "/usrdata/bin/cellcored"
  run_remote "chmod 0755 /usrdata/bin/cellcored"

  OVERLAY_STATUS=$(run_remote "/usrdata/bin/cellcored overlay status")
  echo "$OVERLAY_STATUS"
  SAFE_PIVOT=$(echo "$OVERLAY_STATUS" | sed -n 's/.*safe_to_pivot=\([01]\).*/\1/p')
  [ "$SAFE_PIVOT" = "1" ] || { echo "ERROR: modem is not safe to pivot; see overlay status above." >&2; exit 1; }

  echo "==> Installing clean-room reversible overlay hooks (S03 + S13) on base rootfs..."
  run_remote "
    set -e
    /usrdata/bin/cellcored overlay pivot --dry-run
    mount -o remount,rw /
    cat > /etc/init.d/cellcore-overlay <<'INIT03'
#!/bin/sh /etc/rc.common
START=03
start() {
    [ -x /usrdata/bin/cellcored ] && /usrdata/bin/cellcored overlay pivot
}
INIT03
    cat > /etc/init.d/cellcore-overlay-rw <<'INIT13'
#!/bin/sh /etc/rc.common
START=13
start() {
    [ -x /usrdata/bin/cellcored ] && /usrdata/bin/cellcored overlay remount-rw
}
INIT13
    chmod 0755 /etc/init.d/cellcore-overlay /etc/init.d/cellcore-overlay-rw
    ln -sf ../init.d/cellcore-overlay /etc/rc.d/S03cellcore-overlay
    ln -sf ../init.d/cellcore-overlay-rw /etc/rc.d/S13cellcore-overlay-rw
    sync
    mount -o remount,ro / || true
    reboot
  "
  wait_for_device
  echo "==> Post-reboot overlay verification:"
  POST_STATUS=$(run_remote "/usrdata/bin/cellcored overlay status")
  echo "$POST_STATUS"
  echo "$POST_STATUS" | grep -q "root_writable=1" || {
    echo "ERROR: root filesystem is still read-only after reboot. Check /tmp/cellcore-overlay.log." >&2
    exit 1
  }
else
  echo "==> Writable rootfs already active — installing cleanly via opkg (no /usrdata/bin shadow binary)."
fi

# 5. Configure opkg architectures, option check_signature, usign public key, CellCore-repo feed, and Dropbear SSH
echo "==> Configuring opkg (option check_signature, arch sdxpinn, usign key ${PUBKEY_ID}, ${FEED_NAME})..."
run_remote "
  set -e
  mkdir -p /etc/opkg /etc/opkg/keys
  touch /etc/opkg.conf /etc/opkg/customfeeds.conf

  # Enforce opkg signature verification
  TMP_CONF=\$(mktemp)
  grep -vE '^[[:space:]]*option[[:space:]]+check_signature([[:space:]]|$)' /etc/opkg.conf > \"\$TMP_CONF\" || true
  echo 'option check_signature' >> \"\$TMP_CONF\"
  mv -f \"\$TMP_CONF\" /etc/opkg.conf

  grep -qE '^arch[[:space:]]+sdxpinn[[:space:]]' /etc/opkg.conf || echo 'arch sdxpinn 100' >> /etc/opkg.conf
  grep -qE '^arch[[:space:]]+aarch64_cortex-a53[[:space:]]' /etc/opkg.conf || echo 'arch aarch64_cortex-a53 50' >> /etc/opkg.conf

  cat > /etc/opkg/keys/${PUBKEY_ID} <<'KEYEOF'
${PUBKEY_CONTENT}
KEYEOF

  TMP_F=\$(mktemp)
  grep -v '^src/gz[[:space:]]\+${FEED_NAME}[[:space:]]' /etc/opkg/customfeeds.conf > \"\$TMP_F\" || true
  printf 'src/gz %s %s\n' '${FEED_NAME}' '${FEED_URL}' >> \"\$TMP_F\"
  mv -f \"\$TMP_F\" /etc/opkg/customfeeds.conf

  if [ -x /etc/init.d/dropbear ]; then
    /etc/init.d/dropbear enable 2>/dev/null || true
    /etc/init.d/dropbear start 2>/dev/null || true
  fi
"

# 6. Ensure a TLS cert exists before starting cellcored (ACME -> CellCore self-signed ECDSA -> uhttpd)
echo "==> Verifying TLS certificate for :443..."
run_remote "
  if [ ! -f /etc/ssl/acme/fullchain.pem ] && [ ! -f /etc/cellcore/tls/cert.pem ] && [ ! -f /etc/uhttpd.crt ]; then
    if command -v openssl >/dev/null 2>&1; then
      LAN_IP_CUR=\$(uci -q get network.lan.ipaddr || echo 192.168.225.1)
      HOST_CUR=\$(uci -q get system.@system[0].hostname || hostname || echo cellcore)
      mkdir -p /etc/cellcore/tls
      chmod 0700 /etc/cellcore/tls
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -days 3650 \
        -keyout /etc/cellcore/tls/key.pem \
        -out /etc/cellcore/tls/cert.pem \
        -subj \"/CN=\${HOST_CUR}\" \
        -addext \"subjectAltName=DNS:\${HOST_CUR},DNS:cellcore.local,IP:\${LAN_IP_CUR},IP:127.0.0.1\" 2>/dev/null || \
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -days 3650 \
        -keyout /etc/cellcore/tls/key.pem \
        -out /etc/cellcore/tls/cert.pem \
        -subj \"/CN=\${HOST_CUR}\"
      chmod 0600 /etc/cellcore/tls/key.pem
      chmod 0644 /etc/cellcore/tls/cert.pem
      echo 'Generated self-signed ECDSA P-256 cert at /etc/cellcore/tls/cert.pem'
    fi
  fi
"

# 7. Push and install the verified .ipk via opkg (with remote SHA-256 re-check before install)
EXPECTED_IPK_SHA=$(sha256_of "$VERIFIED_IPK")
echo "==> Installing verified package $(basename "$VERIFIED_IPK") via opkg..."
push_file "$VERIFIED_IPK" "/tmp/sdxpinn-cellcore.ipk"
run_remote "
  set -e
  REMOTE_SHA=\$(sha256sum /tmp/sdxpinn-cellcore.ipk | awk '{print \$1}' | tr 'A-Z' 'a-z')
  if [ \"\$REMOTE_SHA\" != '${EXPECTED_IPK_SHA}' ]; then
    echo \"ERROR: remote SHA-256 mismatch after push (expected ${EXPECTED_IPK_SHA}, got \$REMOTE_SHA)\" >&2
    rm -f /tmp/sdxpinn-cellcore.ipk
    exit 1
  fi
  opkg update || true
  opkg install /tmp/sdxpinn-cellcore.ipk
"

echo "==> Staging verified rescue package -> /etc/cellcore-rescue/cellcore.ipk..."
run_remote "
  mkdir -p /etc/cellcore-rescue
  if [ -f /tmp/sdxpinn-cellcore.ipk ]; then
    cp -f /tmp/sdxpinn-cellcore.ipk /etc/cellcore-rescue/cellcore.ipk.tmp && \
      mv -f /etc/cellcore-rescue/cellcore.ipk.tmp /etc/cellcore-rescue/cellcore.ipk
    rm -f /tmp/sdxpinn-cellcore.ipk
  fi
"

# 8. Optional validated config bundle (remote SHA-256 verified before extract)
if [ -n "$CONFIG_BUNDLE" ]; then
  BUNDLE_SHA=$(sha256_of "$CONFIG_BUNDLE")
  echo "==> Pushing and applying verified config bundle $(basename "$CONFIG_BUNDLE") (sha256=${BUNDLE_SHA})..."
  push_file "$CONFIG_BUNDLE" "/tmp/cellcore-config-bundle.tar.gz"
  run_remote "
    set -e
    REMOTE_SHA=\$(sha256sum /tmp/cellcore-config-bundle.tar.gz | awk '{print \$1}' | tr 'A-Z' 'a-z')
    if [ \"\$REMOTE_SHA\" != '${BUNDLE_SHA}' ]; then
      echo \"ERROR: config bundle remote SHA-256 mismatch (expected ${BUNDLE_SHA}, got \$REMOTE_SHA)\" >&2
      rm -f /tmp/cellcore-config-bundle.tar.gz
      exit 1
    fi
    tar -xzf /tmp/cellcore-config-bundle.tar.gz -C /
    rm -f /tmp/cellcore-config-bundle.tar.gz
    [ -f /etc/dropbear/authorized_keys ] && chmod 0600 /etc/dropbear/authorized_keys
    [ -f /etc/ssl/acme/privkey.pem ] && chmod 0600 /etc/ssl/acme/privkey.pem
    [ -d /etc/cellcore ] && chmod 0700 /etc/cellcore
    if [ -x /etc/init.d/cellcored ]; then
      /etc/init.d/cellcored restart
    fi
  "
fi

# 9. Optional SSH public key (appended idempotently after config bundle so it is never clobbered)
if [ -n "$SSH_PUBKEY" ]; then
  echo "==> Installing SSH authorized key from ${SSH_PUBKEY}..."
  push_file "$SSH_PUBKEY" "/tmp/cellcore-ssh.pub"
  run_remote "
    set -e
    mkdir -p /etc/dropbear
    touch /etc/dropbear/authorized_keys
    chmod 0600 /etc/dropbear/authorized_keys
    PUB_LINE=\$(cat /tmp/cellcore-ssh.pub)
    rm -f /tmp/cellcore-ssh.pub
    grep -qxF \"\$PUB_LINE\" /etc/dropbear/authorized_keys || printf '%s\n' \"\$PUB_LINE\" >> /etc/dropbear/authorized_keys
  "
fi

# 10. Optional hostname
if [ -n "$HOSTNAME_VAL" ]; then
  echo "==> Setting hostname to ${HOSTNAME_VAL}..."
  run_remote "
    set -e
    uci set system.@system[0].hostname='${HOSTNAME_VAL}'
    uci commit system
    printf '%s\n' '${HOSTNAME_VAL}' > /proc/sys/kernel/hostname 2>/dev/null || true
  "
fi

# 11. Optional LAN IP / netmask
if [ -n "$LAN_IP" ]; then
  echo "==> Configuring UCI network.lan.ipaddr=${LAN_IP}$([ -n "$LAN_NETMASK" ] && printf ' netmask=%s' "$LAN_NETMASK" || true)..."
  CUR_LAN_IP=$(run_remote "uci -q get network.lan.ipaddr || true" | tr -d '\r\n')
  run_remote "
    set -e
    uci set network.lan.ipaddr='${LAN_IP}'
    $([ -n "$LAN_NETMASK" ] && printf "uci set network.lan.netmask='%s'" "$LAN_NETMASK" || true)
    uci commit network
  "
  if [ "$MODE" = "adb" ]; then
    echo "==> Reloading network over ADB..."
    run_remote "
      if [ -x /etc/init.d/network ]; then
        /etc/init.d/network reload || true
      fi
      sleep 2
      if [ -x /etc/init.d/cellcored ]; then
        /etc/init.d/cellcored restart || true
      fi
    "
  elif [ "$CUR_LAN_IP" != "$LAN_IP" ]; then
    echo "WARNING: LAN IP changed from '${CUR_LAN_IP:-unset}' to '${LAN_IP}' while connected over SSH." >&2
    echo "         Skipping live network reload to avoid dropping your SSH session." >&2
    echo "         Reboot the modem (or run '/etc/init.d/network reload') to apply the new LAN IP." >&2
  fi
fi

# 12. Optional root shadow password hash (never echoed to stdout/stderr or command-line args)
if [ -n "$ROOT_SHADOW_FILE" ]; then
  echo "==> Updating root password hash in /etc/shadow..."
  SHADOW_CLEAN="$TMP_WORK/root.shadow"
  (umask 077; grep -v '^[[:space:]]*$' "$ROOT_SHADOW_FILE" | tr -d '\r\n' > "$SHADOW_CLEAN")
  run_remote "umask 077; rm -f /tmp/.cellcore-shadow-hash; touch /tmp/.cellcore-shadow-hash; chmod 0600 /tmp/.cellcore-shadow-hash"
  push_file "$SHADOW_CLEAN" "/tmp/.cellcore-shadow-hash"
  rm -f "$SHADOW_CLEAN"
  run_remote "
    set -e
    trap 'rm -f /tmp/.cellcore-shadow-hash /etc/shadow.cellcore.tmp' EXIT
    chmod 0600 /tmp/.cellcore-shadow-hash
    awk -F: 'BEGIN { OFS=\":\"; if ((getline h < \"/tmp/.cellcore-shadow-hash\") <= 0 || h == \"\") exit 1; close(\"/tmp/.cellcore-shadow-hash\") }
      \$1 == \"root\" { \$2 = h; found = 1 }
      { print }
      END { if (!found) exit 2 }' /etc/shadow > /etc/shadow.cellcore.tmp
    chmod 0600 /etc/shadow.cellcore.tmp
    mv -f /etc/shadow.cellcore.tmp /etc/shadow
    rm -f /tmp/.cellcore-shadow-hash
  "
fi

# 13. Optional SDX75 Ethernet/5G AT baseline
if [ "$AT_BASELINE" -eq 1 ]; then
  echo "==> Applying SDX75 Ethernet/5G baseline AT commands..."
  send_remote_at 'AT+QCFG="pcie/mode",1'
  send_remote_at 'AT+QMAPWAC=1'
  if [ -n "$MBN_NAME" ]; then
    echo "==> Selecting MBN profile: ${MBN_NAME}..."
    send_remote_at 'AT+QMBNCFG="AutoSel",0'
    send_remote_at "AT+QMBNCFG=\"Select\",\"${MBN_NAME}\""
  fi
  if [ -n "$LAN_GW_IP" ]; then
    LANIP_RANGE=$(derive_qmap_lanip_range "$LAN_GW_IP")
    echo "==> Configuring QMAP LANIP (${LANIP_RANGE})..."
    send_remote_at "AT+QMAP=\"LANIP\",${LANIP_RANGE}"
  fi
elif [ -n "$MBN_NAME" ] || [ -n "$LAN_GW_IP" ]; then
  echo "WARNING: --mbn / --lan-gw-ip were specified without --at-baseline; skipping AT commands." >&2
fi

# 14. Final health verification
echo "==> Verifying CellCore daemon..."
sleep 2
run_remote "cellctl verify --expect-wan 0 && cellctl overlay status"

# 15. Optional final lockdown (runs strictly at the very end; never drops ADB mid-run)
if [ "$LOCKDOWN" -eq 1 ]; then
  echo "==> Applying final opt-in lockdown (key-only SSH, disabling ttyd & adbd.init)..."
  run_remote "
    set -e
    if [ ! -s /etc/dropbear/authorized_keys ] || ! grep -qE '^[[:space:]]*(ssh-|ecdsa-|sk-)' /etc/dropbear/authorized_keys; then
      echo 'ERROR: refusing --lockdown because /etc/dropbear/authorized_keys is missing or has no SSH public keys!' >&2
      exit 1
    fi
    chmod 0600 /etc/dropbear/authorized_keys
    if uci -q show dropbear >/dev/null 2>&1; then
      for sec in \$(uci -q show dropbear | sed -n 's/^dropbear\.\([^.=]*\)=dropbear$/\1/p'); do
        uci set \"dropbear.\${sec}.PasswordAuth=off\"
        uci set \"dropbear.\${sec}.RootPasswordAuth=off\"
      done
      uci commit dropbear
      if [ -x /etc/init.d/dropbear ]; then
        /etc/init.d/dropbear restart || true
      fi
    fi
    if [ -x /etc/init.d/ttyd ]; then
      /etc/init.d/ttyd disable 2>/dev/null || true
      /etc/init.d/ttyd stop 2>/dev/null || true
    fi
    if [ -x /etc/init.d/adbd.init ]; then
      /etc/init.d/adbd.init disable 2>/dev/null || true
    fi
    sync
  "
fi

FINAL_LAN_IP=$(run_remote "uci -q get network.lan.ipaddr || echo 192.168.225.1" | tr -d '\r\n')
echo ""
echo "============================================================"
echo " CellCore bootstrap complete!"
echo " Web UI : https://${FINAL_LAN_IP}/"
echo " SSH    : ssh root@${FINAL_LAN_IP}"
echo " Revert : ./bootstrap.sh --${MODE} $([ "$MODE" = "ssh" ] && echo "$SSH_TARGET") --revert [--purge]"
echo "============================================================"
