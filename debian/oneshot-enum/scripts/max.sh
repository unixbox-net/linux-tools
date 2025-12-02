#!/usr/bin/env bash
# max.sh — build & run oneshot-enum with Linux-first defaults (host net, raw scans)
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target> [extra oneshot-enum flags]"
  exit 1
fi

TARGET="$1"; shift || true
IMG="${IMG:-oneshot-enum}"

echo "[*] Building scanner image: $IMG"
docker build -t "$IMG" ./scanner

OUT_DIR="$(pwd)/out"
ACTIONS_DIR="$OUT_DIR/actions"
CACHE_DIR="$(pwd)/.cache"
mkdir -p "$OUT_DIR" "$ACTIONS_DIR" "$CACHE_DIR"

echo "[*] Running oneshot-enum against: $TARGET"
docker run --rm \
  --network=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e XDG_CACHE_HOME=/tmp/.cache \
  -v "$OUT_DIR:/out" \
  -v "$CACHE_DIR:/tmp/.cache" \
  "$IMG" \
  --full "$TARGET" \
  --out /out/out.json \
  --report-html /out/report.html \
  --actions-out /out/actions \
  --assume-yes --automate \
  "$@"

echo
echo "Done. See: out/out.json and out/report.html"
echo "Artifacts: out/actions/<host>/..."
