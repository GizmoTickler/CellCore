#!/bin/sh
# CellCore one-liner installer / feed bootstrapper for Quectel SDX75 (sdxpinn) OpenWrt modems.
set -eu

FEED_NAME="CellCore-repo"
FEED_URL="${CELLCORE_FEED_URL:-https://raw.githubusercontent.com/GizmoTickler/CellCore/main/feed}"
CUSTOM_FEEDS="/etc/opkg/customfeeds.conf"
KEY_DIR="/etc/opkg/keys"
PUBKEY_ID="14647e6bee9674ba"

echo "=== CellCore SDX75 Installer ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root on the modem." >&2
    exit 1
fi

if ! touch /etc/.cellcore_rw_test 2>/dev/null; then
    echo "Error: root filesystem is read-only. Enable a writable overlay first, then re-run." >&2
    exit 1
fi
rm -f /etc/.cellcore_rw_test

mkdir -p /etc/opkg "$KEY_DIR"
touch "$CUSTOM_FEEDS"

# Install CellCore usign public key if missing
if [ ! -f "${KEY_DIR}/${PUBKEY_ID}" ]; then
    cat > "${KEY_DIR}/${PUBKEY_ID}" <<'EOF'
untrusted comment: CellCore SDXPINN opkg feed
RWQUZH5r7pZ0ulLC3JfaotxtUoYnUmTrN5IzN8RmZXI1xGURn1z+EKfl
EOF
    echo "Installed CellCore signing public key (${PUBKEY_ID})."
fi

# Ensure CellCore-repo feed entry points to FEED_URL
TMP_FEEDS=$(mktemp)
grep -v "^src/gz[[:space:]]\+${FEED_NAME}[[:space:]]" "$CUSTOM_FEEDS" > "$TMP_FEEDS" || true
printf 'src/gz %s %s\n' "$FEED_NAME" "$FEED_URL" >> "$TMP_FEEDS"
mv -f "$TMP_FEEDS" "$CUSTOM_FEEDS"

echo "Updating opkg package list..."
opkg update

echo "Installing sdxpinn-cellcore..."
opkg install sdxpinn-cellcore

echo "Verifying CellCore daemon..."
cellctl verify --expect-wan 0 || true
echo "Done! Open https://$(uci -q get network.lan.ipaddr || echo 192.168.225.1)/"
