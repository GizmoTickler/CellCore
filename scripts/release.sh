#!/usr/bin/env bash
# Single-command CellCore build, test, cross-compile, package, feed-sign, and optional deploy.
# Usage: ./scripts/release.sh <version> [--skip-rust] [--deploy]
set -euo pipefail

export PATH="$HOME/.cargo/bin:$HOME/.local/share/mise/shims:/usr/local/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <pkg-version> [--skip-rust] [--deploy]" >&2
  echo "Example: $0 1.0.0-1" >&2
  exit 1
fi
shift

SKIP_RUST=0
DEPLOY=0
for arg in "$@"; do
  case "$arg" in
    --skip-rust) SKIP_RUST=1 ;;
    --deploy) DEPLOY=1 ;;
    *) echo "Unknown flag: $arg" >&2; exit 1 ;;
  esac
done

PKG_DIR="$ROOT/packaging/sdxpinn-cellcore"
USIGN="$ROOT/scripts/feed/usign_x64"
EXPECTED_USIGN_SHA="961aacc9dc143c3e14bd04732e7917ff2801c2b705131ba9416c38e1022bf169"

if [ "$(sha256sum "$USIGN" | awk '{print $1}')" != "$EXPECTED_USIGN_SHA" ]; then
  echo "ERROR: usign_x64 sha256 mismatch!" >&2
  exit 1
fi

if [ "$SKIP_RUST" -eq 0 ]; then
  echo "==> [1/6] Running Rust tests & clippy..."
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings

  echo "==> [2/6] Cross-compiling static aarch64-unknown-linux-musl release binary..."
  cargo build --release --target aarch64-unknown-linux-musl -p cellcored
fi

echo "==> [3/6] Building React 19 + TypeScript frontend..."
npm run build

echo "==> [4/6] Staging packaging tree for sdxpinn-cellcore ${VERSION}..."
rm -rf "$PKG_DIR/root"
mkdir -p "$PKG_DIR/root/www" "$PKG_DIR/root/etc/init.d" "$PKG_DIR/root/usr/sbin" "$PKG_DIR/root/usr/bin"
cp -a "$ROOT/dist/." "$PKG_DIR/root/www/"
mv -f "$PKG_DIR/root/www/index.html" "$PKG_DIR/root/www/login.html"
cp -f "$ROOT/target/aarch64-unknown-linux-musl/release/cellcored" "$PKG_DIR/root/usr/sbin/cellcored"
chmod 0755 "$PKG_DIR/root/usr/sbin/cellcored"
cp -f "$ROOT/scripts/etc/init.d/cellcored" "$PKG_DIR/root/etc/init.d/cellcored"
chmod 0755 "$PKG_DIR/root/etc/init.d/cellcored"
ln -sf cellcored "$PKG_DIR/root/usr/sbin/r10-modem-ctl"
ln -sf cellcored "$PKG_DIR/root/usr/sbin/modem-ctl"
ln -sf ../sbin/cellcored "$PKG_DIR/root/usr/bin/cellctl"
ln -sf ../sbin/cellcored "$PKG_DIR/root/usr/bin/quecctl"
ln -sf ../sbin/cellcored "$PKG_DIR/root/usr/bin/menu"

sed -i "s/^Version:.*/Version: ${VERSION}/" "$PKG_DIR/CONTROL/control"

echo "==> [5/6] Packing .ipk and updating signed feed/..."
TMPDIR=$(mktemp -d)
KEYFILE=$(mktemp)
trap 'shred -u "$KEYFILE" 2>/dev/null || rm -f "$KEYFILE"; rm -rf "$TMPDIR"' EXIT

python3 "$ROOT/scripts/feed/build_ipk.py" "$PKG_DIR" --out "$TMPDIR"
python3 "$ROOT/scripts/feed/build_feed.py" "$ROOT/feed" "$TMPDIR/sdxpinn-cellcore_${VERSION}_sdxpinn.ipk"

chmod 600 "$KEYFILE"
op read "op://Infrastructure/SDXPINN-opkg-usign/credential" > "$KEYFILE"
"$USIGN" -S -m "$ROOT/feed/Packages" -s "$KEYFILE" -x "$ROOT/feed/Packages.sig"
"$USIGN" -V -m "$ROOT/feed/Packages" -x "$ROOT/feed/Packages.sig" -p "$ROOT/feed/usign.pub"

echo "==> [6/6] Package & signed feed ready: feed/sdxpinn-cellcore_${VERSION}_sdxpinn.ipk"

if [ "$DEPLOY" -eq 1 ]; then
  echo "==> Deploying staged rollout: mgateway0 (QA) -> mgateway1 (prod)..."
  ssh -o StrictHostKeyChecking=no root@192.168.228.1 'cellctl upgrade --check && cellctl upgrade --yes && cellctl verify'
  ssh -o StrictHostKeyChecking=no root@192.168.224.1 'cellctl upgrade --check && cellctl upgrade --yes && cellctl verify --expect-wan 1'
fi
