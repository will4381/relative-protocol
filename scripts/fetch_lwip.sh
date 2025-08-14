#!/usr/bin/env bash
set -euo pipefail

LWIP_REPO="https://github.com/lwip-tcpip/lwip"
LWIP_COMMIT="STABLE-2_2_0_RELEASE"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="$ROOT_DIR/third_party/lwip"
SRC_DIR="$DEST_DIR/lwip-src"

mkdir -p "$SRC_DIR"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "Fetching lwIP $LWIP_COMMIT..."
curl -sSL "$LWIP_REPO/archive/$LWIP_COMMIT.tar.gz" -o "$tmpdir/lwip.tar.gz"
tar -xzf "$tmpdir/lwip.tar.gz" -C "$tmpdir"
src_root="$(find "$tmpdir" -maxdepth 1 -type d -name 'lwip-*' | head -n1)"

mkdir -p "$SRC_DIR/src/api" "$SRC_DIR/src/core" "$SRC_DIR/src/core/ipv4" "$SRC_DIR/src/core/ipv6" "$SRC_DIR/src/netif" "$SRC_DIR/src/include"
rsync -a "$src_root/src/api/"  "$SRC_DIR/src/api/"
rsync -a "$src_root/src/core/" "$SRC_DIR/src/core/"
rsync -a "$src_root/src/netif/" "$SRC_DIR/src/netif/"
rsync -a "$src_root/src/include/" "$SRC_DIR/src/include/"

echo "$LWIP_REPO @ $LWIP_COMMIT" > "$DEST_DIR/VERSION.txt"
echo "lwIP fetched into $SRC_DIR"
echo "Provide port sources under third_party/lwip/port/relative/ before building."


