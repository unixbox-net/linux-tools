#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-/out/loghog}"
SRC_DIR="/var/lib/docker/containers"
PROJECT_NAME="${PROJECT_NAME:-oneshot-enum}"
DUR="${DURATION_SEC:-60}"

mkdir -p "$OUT_DIR"

echo "[loghog] collecting json-file logs for compose project: ${PROJECT_NAME}"
echo "[loghog] source: ${SRC_DIR}"

# Find container dirs that belong to this compose project by inspecting config.v2.json
mapfile -t CONTAINER_DIRS < <(
  grep -Rl "\"com.docker.compose.project\":\"${PROJECT_NAME}\"" \
    "${SRC_DIR}"/*/config.v2.json 2>/dev/null \
  | xargs -r -n1 dirname \
  | sort -u
)

TS="$(date -u +%Y%m%d-%H%M%S)"
TMP="/tmp/loghog-${TS}"
mkdir -p "${TMP}"

if ((${#CONTAINER_DIRS[@]} == 0)); then
  echo "[loghog] no container logs found for project '${PROJECT_NAME}' under ${SRC_DIR}" | tee "${OUT_DIR}/info.txt"
  touch "${OUT_DIR}/empty"
  exit 0
fi

# Copy each container's json log with a friendlier name
for d in "${CONTAINER_DIRS[@]}"; do
  cid="$(basename "$d")"
  name="$(jq -r '.Name' "$d/config.v2.json" 2>/dev/null | sed 's#^/##' || true)"
  log="${d}/${cid}-json.log"
  if [ -s "$log" ]; then
    dest="${name:-$cid}.json.log"
    echo "[loghog] adding ${dest}"
    cp -a "$log" "${TMP}/${dest}"
  fi
done

# Pack logs into a tarball artifact
ARCHIVE="${OUT_DIR}/docker-logs-${TS}.tgz"
tar -C "${TMP}" -czf "${ARCHIVE}" .
echo "[loghog] wrote ${ARCHIVE}"

# Stay alive briefly (symmetry with other one-shot jobs) then exit
sleep 1
exit 0

