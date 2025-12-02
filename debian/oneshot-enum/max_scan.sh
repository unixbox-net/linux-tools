#!/usr/bin/env bash
# max.sh — build & run oneshot-enum in "max" mode by default (Linux-first)
# - Defaults to Linux: host networking + raw caps for fast/accurate nmap scans
# - Scans all TCP ports by default, higher concurrency, automations on
# - Works on macOS/Windows too (host networking auto-omitted there)
# - Optional knobs are included but commented with specific labels

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target> [extra oneshot-enum flags]"
  exit 1
fi

TARGET="$1"; shift || true

# -----------------------------
# Image / build knobs (Linux default pulls latest base)
# -----------------------------
IMG="${IMG:-oneshot-enum}"
BUILD_ARGS=()
BUILD_ARGS+=(--pull)               # [DEFAULT ON] pull latest base image each build
#BUILD_ARGS+=(--no-cache)          # [OPTIONAL] force clean rebuild
#BUILD_ARGS+=(--build-arg NUCLEI_VERSION=v3.3.9)  # [OPTIONAL] pin nuclei version

echo "[*] Building image: $IMG"
docker build "${BUILD_ARGS[@]:-}" -t "$IMG" .

# -----------------------------
# OS-aware networking (Linux default = host)
# -----------------------------
OS="$(uname -s || echo '')"
RUN_OPTS=()
if [[ "$OS" == Linux* ]]; then
  RUN_OPTS+=(--network=host)       # [DEFAULT ON LINUX] fast/accurate local scans
fi

HOST_PWD="$PWD"

# -----------------------------
# Output & cache locations
# -----------------------------
OUT_DIR="$HOST_PWD/out"
ACTIONS_DIR="$OUT_DIR/actions"
CACHE_DIR="$HOST_PWD/.cache"        # persisted tool cache (nuclei/httpx/etc.)

mkdir -p "$OUT_DIR" "$ACTIONS_DIR" "$CACHE_DIR"

# -----------------------------
# Container privileges / mounts (Linux defaults to max scanning)
# -----------------------------
RUN_OPTS+=(--cap-add=NET_RAW --cap-add=NET_ADMIN)   # [DEFAULT ON LINUX] raw sockets/SYN
RUN_OPTS+=(-e XDG_CACHE_HOME=/tmp/.cache -v "$CACHE_DIR:/tmp/.cache")  # persist caches

# Wordlists (SecLists) — uncomment if you have it locally:
#RUN_OPTS+=(-v "$HOST_PWD/SecLists:/opt/SecLists:ro")  # [OPTIONAL] mount SecLists

# Nuclei templates override — uncomment if you keep your own:
#RUN_OPTS+=(-e NUCLEI_TEMPLATES=/opt/nuclei-templates)
#RUN_OPTS+=(-v "$HOST_PWD/nuclei-templates:/opt/nuclei-templates:ro")

# Passive intel keys — uncomment/provide env as needed:
#RUN_OPTS+=(-e SHODAN_API_KEY="$SHODAN_API_KEY")
#RUN_OPTS+=(-e CENSYS_API_ID="$CENSYS_API_ID" -e CENSYS_API_SECRET="$CENSYS_API_SECRET")
#RUN_OPTS+=(-e VT_API_KEY="$VT_API_KEY")

# Route tools through a proxy (Burp/mitmproxy) — optional:
#RUN_OPTS+=(-e HTTP_PROXY=http://127.0.0.1:8080 -e HTTPS_PROXY=http://127.0.0.1:8080)

# Resource knobs (raise if your host is beefy)
RUN_OPTS+=(--cpus="4" --memory="8g" --ulimit nofile=1048576:1048576)

# -----------------------------
# Oneshot-enum flags
# -----------------------------
EXTRA_FLAGS=()

# Custom rules (only add if you actually placed one at out/rules.yaml)
if [[ -f "$OUT_DIR/rules.yaml" ]]; then
  EXTRA_FLAGS+=(--rules /out/rules.yaml)
fi

# *** MAX DEFAULTS ***
EXTRA_FLAGS+=(--ports "1-65535")     # [DEFAULT MAX] scan all TCP ports (can be slow)
EXTRA_FLAGS+=(--concurrency 128)     # [DEFAULT MAX] bump worker count
EXTRA_FLAGS+=(--timeout 15)          # [DEFAULT MAX-ish] longer per-op timeout

# Alternative presets you can switch to:
#EXTRA_FLAGS=(--ports "popular" --concurrency 64 --timeout 10)   # [OPTIONAL] faster

# Control follow-up actions parallelism:
#EXTRA_FLAGS+=(--actions-par 8)       # [OPTIONAL] more parallel post-scan actions

# Debug shell instead of running the tool:
#DEBUG_SHELL=1

# -----------------------------
# Run
# -----------------------------
if [[ "${DEBUG_SHELL:-0}" == "1" ]]; then
  echo "[*] Launching debug shell inside container..."
  exec docker run --rm -it \
    "${RUN_OPTS[@]}" \
    -v "$OUT_DIR:/out" \
    "$IMG" /bin/bash
fi

echo "[*] Running oneshot-enum (MAX) against: $TARGET"
docker run --rm \
  "${RUN_OPTS[@]}" \
  -v "$OUT_DIR:/out" \
  "$IMG" \
  --full "$TARGET" \
  --out /out/out.json \
  --report-html /out/report.html \
  --actions-out /out/actions \
  --assume-yes --automate \
  "${EXTRA_FLAGS[@]}" \
  "$@"

echo
echo "Done. See: out/out.json  and  out/report.html"
echo "Artifacts: out/actions/<host>/..."
