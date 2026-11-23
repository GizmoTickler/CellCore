#!/usr/bin/env bash
# CellCore Factory-Modem Bootstrapper (Clean-Room, Verified, Reversible)
#
# Takes an out-of-the-box Quectel RM551E-GL / SDX75 modem over USB ADB or SSH,
# configures the usign-verified CellCore opkg feed (with option check_signature),
# optionally installs your SSH public key, verifies Packages.sig + package SHA-256,
# and installs + verifies sdxpinn-cellcore cleanly via opkg.
#
# Usage:
#   ./bootstrap.sh --adb [--ssh-key ~/.ssh/id_ed25519.pub] [--dry-run]
#   ./bootstrap.sh --ssh root@192.168.225.1 [--ssh-key ~/.ssh/id_ed25519.pub] [--dry-run]
#   ./bootstrap.sh --adb --stage-overlay-helper   # opt-in early-boot /usrdata overlay helper for factory RO rootfs
#   ./bootstrap.sh --adb --revert [--purge]
#   ./bootstrap.sh --ssh root@192.168.225.1 --revert [--purge]
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
DRY_RUN=0
REVERT=0
PURGE=0

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --adb) MODE="adb"; shift ;;
    --adb-serial) MODE="adb"; ADB_SERIAL="${2:?missing serial}"; shift 2 ;;
    --ssh) MODE="ssh"; SSH_TARGET="${2:?missing user@host}"; shift 2 ;;
    --ssh-key) SSH_PUBKEY="${2:?missing pubkey path}"; shift 2 ;;
    --ipk) LOCAL_IPK="${2:?missing ipk path}"; shift 2 ;;
    --stage-overlay-helper) STAGE_OVERLAY_HELPER=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --revert) REVERT=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

[ -n "$MODE" ] || { echo "ERROR: specify --adb or --ssh <user@host>" >&2; usage; }

if [ -n "$SSH_PUBKEY" ] && [ ! -f "$SSH_PUBKEY" ]; then
  echo "ERROR: SSH public key not found: $SSH_PUBKEY" >&2
  exit 1
fi

if [ -n "$LOCAL_IPK" ] && [ ! -f "$LOCAL_IPK" ]; then
  echo "ERROR: local .ipk not found: $LOCAL_IPK" >&2
  exit 1
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

echo "=== CellCore SDX75 Bootstrapper (mode=${MODE}, dry_run=${DRY_RUN}, revert=${REVERT}) ==="

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
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] Would restore factory /etc/opkg.conf & customfeeds.conf, remove cellcore-overlay hooks, and reboot."
    exit 0
  fi
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
if [ "$DRY_RUN" -eq 1 ]; then
  run_remote "cat /proc/mounts | grep -E ' (/|/real_rootfs|/usrdata|/etc|/overlay) ' || true; df -h / /usrdata 2>/dev/null || true"
  echo "[dry-run] Verified package: ${VERIFIED_IPK}"
  echo "[dry-run] Preflight complete. No changes were written to the modem."
  exit 0
fi

run_remote "
  mkdir -p /usrdata/cellcore-factory-backup
  [ -f /usrdata/cellcore-factory-backup/opkg.conf ] || cp -p /etc/opkg.conf /usrdata/cellcore-factory-backup/opkg.conf 2>/dev/null || true
  [ -f /usrdata/cellcore-factory-backup/customfeeds.conf ] || cp -p /etc/opkg/customfeeds.conf /usrdata/cellcore-factory-backup/customfeeds.conf 2>/dev/null || true
"

ROOT_RW=$(run_remote "if touch /etc/.cellcore_rw_probe 2>/dev/null; then rm -f /etc/.cellcore_rw_probe; echo 1; else echo 0; fi" | tr -d '\r\n')

# 4. Early-boot overlay pivot (strictly opt-in via --stage-overlay-helper for factory read-only rootfs;
#    never stages an unmanaged /usrdata/bin shadow binary on already-writable systems).
if [ "$ROOT_RW" != "1" ]; then
  if [ "$STAGE_OVERLAY_HELPER" -ne 1 ]; then
    echo "ERROR: root filesystem is read-only (factory stock rootfs)." >&2
    echo "       To keep /usr/sbin/cellcored managed strictly by opkg, staging an early-boot" >&2
    echo "       overlay helper under /usrdata/bin is disabled by default." >&2
    echo "       Re-run with --stage-overlay-helper to pivot the verified overlay on this factory modem." >&2
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

# 6. Ensure a TLS cert exists before starting cellcored (ACME -> CellCore self-signed ECDSA -> uhttpd)
echo "==> Verifying TLS certificate for :443..."
run_remote "
  if [ ! -f /etc/ssl/acme/fullchain.pem ] && [ ! -f /etc/cellcore/tls/cert.pem ] && [ ! -f /etc/uhttpd.crt ]; then
    if command -v openssl >/dev/null 2>&1; then
      LAN_IP=\$(uci -q get network.lan.ipaddr || echo 192.168.225.1)
      HOST=\$(uci -q get system.@system[0].hostname || hostname || echo cellcore)
      mkdir -p /etc/cellcore/tls
      chmod 0700 /etc/cellcore/tls
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -days 3650 \
        -keyout /etc/cellcore/tls/key.pem \
        -out /etc/cellcore/tls/cert.pem \
        -subj \"/CN=\${HOST}\" \
        -addext \"subjectAltName=DNS:\${HOST},DNS:cellcore.local,IP:\${LAN_IP},IP:127.0.0.1\" 2>/dev/null || \
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -days 3650 \
        -keyout /etc/cellcore/tls/key.pem \
        -out /etc/cellcore/tls/cert.pem \
        -subj \"/CN=\${HOST}\"
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

# 8. Final health verification & rescue .ipk staging (from the already-verified package)
echo "==> Verifying CellCore daemon..."
sleep 2
run_remote "cellctl verify --expect-wan 0 && cellctl overlay status"
echo "==> Staging verified rescue package -> /etc/cellcore-rescue/cellcore.ipk..."
run_remote "
  mkdir -p /etc/cellcore-rescue
  if [ -f /tmp/sdxpinn-cellcore.ipk ]; then
    cp -f /tmp/sdxpinn-cellcore.ipk /etc/cellcore-rescue/cellcore.ipk.tmp && \
      mv -f /etc/cellcore-rescue/cellcore.ipk.tmp /etc/cellcore-rescue/cellcore.ipk
    rm -f /tmp/sdxpinn-cellcore.ipk
  fi
"

LAN_IP=$(run_remote "uci -q get network.lan.ipaddr || echo 192.168.225.1" | tr -d '\r\n')
echo ""
echo "============================================================"
echo " CellCore bootstrap complete!"
echo " Web UI : https://${LAN_IP}/"
echo " SSH    : ssh root@${LAN_IP}"
echo " Revert : ./bootstrap.sh --${MODE} $([ "$MODE" = "ssh" ] && echo "$SSH_TARGET") --revert [--purge]"
echo "============================================================"
