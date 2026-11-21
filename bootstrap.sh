#!/usr/bin/env bash
# CellCore Factory-Modem Bootstrapper (Clean-Room, Reliable, Robust, Reversible)
#
# Takes a brand-new out-of-the-box Quectel RM551E-GL / SDX75 modem over USB ADB or SSH,
# enables a clean-room Rust-backed writable rootfs overlay on /usrdata (fully reversible),
# configures the signed CellCore opkg feed, optionally installs your SSH public key,
# and installs + verifies sdxpinn-cellcore.
#
# Usage:
#   ./bootstrap.sh --adb [--ssh-key ~/.ssh/id_ed25519.pub] [--dry-run]
#   ./bootstrap.sh --ssh root@192.168.225.1 [--ssh-key ~/.ssh/id_ed25519.pub] [--dry-run]
#   ./bootstrap.sh --adb --revert [--purge]
#   ./bootstrap.sh --ssh root@192.168.225.1 --revert [--purge]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED_NAME="CellCore-repo"
FEED_URL="${CELLCORE_FEED_URL:-https://raw.githubusercontent.com/GizmoTickler/CellCore/main/feed}"
PUBKEY_ID="14647e6bee9674ba"
PUBKEY_CONTENT="untrusted comment: CellCore SDXPINN opkg feed
RWQUZH5r7pZ0ulLC3JfaotxtUoYnUmTrN5IzN8RmZXI1xGURn1z+EKfl"

MODE=""
SSH_TARGET=""
ADB_SERIAL=""
SSH_PUBKEY=""
LOCAL_IPK=""
DRY_RUN=0
REVERT=0
PURGE=0

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --adb) MODE="adb"; shift ;;
    --adb-serial) MODE="adb"; ADB_SERIAL="${2:?missing serial}"; shift 2 ;;
    --ssh) MODE="ssh"; SSH_TARGET="${2:?missing user@host}"; shift 2 ;;
    --ssh-key) SSH_PUBKEY="${2:?missing pubkey path}"; shift 2 ;;
    --ipk) LOCAL_IPK="${2:?missing ipk path}"; shift 2 ;;
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

# Transport wrappers (ADB or SSH)
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
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_TARGET" "$script"
  fi
}

push_file() {
  local local_path="$1"
  local remote_path="$2"
  if [ "$MODE" = "adb" ]; then
    adb_cmd push "$local_path" "$remote_path" >/dev/null
  else
    ssh -o StrictHostKeyChecking=no "$SSH_TARGET" "cat > '$remote_path'" < "$local_path"
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

# Locate or extract static cellcored binary for early-boot overlay staging
TMP_WORK=$(mktemp -d)
trap 'rm -rf "$TMP_WORK"' EXIT

resolve_cellcored_bin() {
  if [ -x "$ROOT/target/aarch64-unknown-linux-musl/release/cellcored" ]; then
    echo "$ROOT/target/aarch64-unknown-linux-musl/release/cellcored"
    return 0
  fi
  local ipk="$LOCAL_IPK"
  if [ -z "$ipk" ]; then
    ipk=$(ls -t "$ROOT"/feed/sdxpinn-cellcore_*_sdxpinn.ipk 2>/dev/null | head -n 1 || true)
  fi
  if [ -z "$ipk" ]; then
    echo "==> Fetching latest sdxpinn-cellcore .ipk from ${FEED_URL}..." >&2
    local pkg_file
    pkg_file=$(curl -fsSL "${FEED_URL}/Packages" | awk '/^Package: sdxpinn-cellcore$/{f=1} f && /^Filename:/{print $2; exit}')
    [ -n "$pkg_file" ] || { echo "ERROR: could not resolve sdxpinn-cellcore filename from feed" >&2; return 1; }
    ipk="$TMP_WORK/$pkg_file"
    curl -fsSL "${FEED_URL}/${pkg_file}" -o "$ipk"
  fi
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

# 2. Stage static cellcored onto writable /usrdata/bin/cellcored (needed before overlay pivot at S03)
CELLCORED_BIN=$(resolve_cellcored_bin)
echo "==> Staging static cellcored binary -> /usrdata/bin/cellcored"
if [ "$DRY_RUN" -eq 0 ]; then
  run_remote "mkdir -p /usrdata/bin /usrdata/cellcore-factory-backup"
  push_file "$CELLCORED_BIN" "/usrdata/bin/cellcored"
  run_remote "chmod 0755 /usrdata/bin/cellcored"
else
  echo "[dry-run] Would push ${CELLCORED_BIN} -> /usrdata/bin/cellcored"
fi

# 3. Inspect mount layout & backup factory opkg config
echo "==> Running preflight mount & space check..."
if [ "$DRY_RUN" -eq 1 ]; then
  run_remote "cat /proc/mounts | grep -E ' (/|/real_rootfs|/usrdata|/etc|/overlay) ' || true; df -h / /usrdata 2>/dev/null || true"
  echo "[dry-run] Preflight complete. No changes were written to the modem."
  exit 0
fi

run_remote "
  [ -f /usrdata/cellcore-factory-backup/opkg.conf ] || cp -p /etc/opkg.conf /usrdata/cellcore-factory-backup/opkg.conf 2>/dev/null || true
  [ -f /usrdata/cellcore-factory-backup/customfeeds.conf ] || cp -p /etc/opkg/customfeeds.conf /usrdata/cellcore-factory-backup/customfeeds.conf 2>/dev/null || true
"

OVERLAY_STATUS=$(run_remote "/usrdata/bin/cellcored overlay status")
echo "$OVERLAY_STATUS"

PIVOTED=$(echo "$OVERLAY_STATUS" | sed -n 's/.*pivoted=\([01]\).*/\1/p')
ROOT_RW=$(echo "$OVERLAY_STATUS" | sed -n 's/.*root_writable=\([01]\).*/\1/p')
SAFE_PIVOT=$(echo "$OVERLAY_STATUS" | sed -n 's/.*safe_to_pivot=\([01]\).*/\1/p')

# 4. Install reversible early-boot overlay init scripts if rootfs is still stock read-only
if [ "$PIVOTED" != "1" ] && [ "$ROOT_RW" != "1" ]; then
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
  echo "==> Writable rootfs already active — skipping overlay pivot reboot."
fi

# 5. Configure opkg architectures, usign public key, CellCore-repo feed, and Dropbear SSH
echo "==> Configuring opkg (arch sdxpinn, usign key ${PUBKEY_ID}, ${FEED_NAME})..."
run_remote "
  set -e
  mkdir -p /etc/opkg /etc/opkg/keys
  touch /etc/opkg.conf /etc/opkg/customfeeds.conf

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
  PUB_LINE=$(cat "$SSH_PUBKEY")
  run_remote "
    mkdir -p /etc/dropbear
    touch /etc/dropbear/authorized_keys
    chmod 0600 /etc/dropbear/authorized_keys
    grep -qxF '${PUB_LINE}' /etc/dropbear/authorized_keys || printf '%s\n' '${PUB_LINE}' >> /etc/dropbear/authorized_keys
  "
fi

# 6. Install sdxpinn-cellcore (from local --ipk if given, else from signed CellCore-repo feed)
if [ -n "$LOCAL_IPK" ]; then
  echo "==> Installing local package ${LOCAL_IPK}..."
  push_file "$LOCAL_IPK" "/tmp/sdxpinn-cellcore.ipk"
  run_remote "opkg update || true; opkg install /tmp/sdxpinn-cellcore.ipk && rm -f /tmp/sdxpinn-cellcore.ipk"
else
  echo "==> Installing sdxpinn-cellcore from signed ${FEED_NAME}..."
  run_remote "opkg update && opkg install sdxpinn-cellcore"
fi

# 7. Final health verification
echo "==> Verifying CellCore daemon..."
sleep 2
run_remote "cellctl verify --expect-wan 0 && cellctl overlay status"
LAN_IP=$(run_remote "uci -q get network.lan.ipaddr || echo 192.168.225.1" | tr -d '\r\n')
echo ""
echo "============================================================"
echo " CellCore bootstrap complete!"
echo " Web UI : https://${LAN_IP}/"
echo " SSH    : ssh root@${LAN_IP}"
echo " Revert : ./bootstrap.sh --${MODE} $([ "$MODE" = "ssh" ] && echo "$SSH_TARGET") --revert [--purge]"
echo "============================================================"
