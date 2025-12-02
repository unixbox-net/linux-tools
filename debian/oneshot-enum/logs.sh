#!/usr/bin/env bash
# collect-all-docker-logs.sh
# Collects logs for ALL Docker containers + useful context, and tars the result.
# Usage: ./collect-all-docker-logs.sh [OUTPUT_DIR]

set -Eeuo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${1:-out/docker-logs-$TS}"

mkdir -p "$OUT"/{containers,host,compose,host-logfiles}

echo "==> Output dir: $OUT"

run() { echo "+ $*"; "$@"; }

# --- Host & Docker context
( run docker version ) > "$OUT/host/docker-version.txt" 2>&1 || true
( run docker info ) > "$OUT/host/docker-info.txt" 2>&1 || true
uname -a > "$OUT/host/uname.txt" 2>&1 || true
( command -v lsb_release >/dev/null && lsb_release -a ) > "$OUT/host/lsb-release.txt" 2>&1 || true
date -u +"%F %T UTC" > "$OUT/host/timestamp.txt"

run docker ps -a > "$OUT/host/ps-a.txt" 2>&1 || true
run docker images > "$OUT/host/images.txt" 2>&1 || true
run docker network ls > "$OUT/host/networks.txt" 2>&1 || true
run docker volume ls > "$OUT/host/volumes.txt" 2>&1 || true

# --- Per-container logs
mapfile -t IDS < <(docker ps -aq || true)
echo "==> Found ${#IDS[@]} containers"
for id in "${IDS[@]}"; do
  name="$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##' || echo "$id")"
  base="$OUT/containers/${name}-${id}"
  echo "==> Collecting $name ($id)"

  # stdout/stderr logs
  docker logs --timestamps --details "$id" > "${base}.log" 2>&1 || true

  # metadata + snapshot of processes (if running)
  docker inspect "$id" > "${base}.inspect.json" 2>&1 || true
  docker top "$id" -eo pid,ppid,tty,time,cmd > "${base}.top.txt" 2>&1 || true

  # log driver & host log path, copy json-file if readable
  drv="$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' "$id" 2>/dev/null || echo 'unknown')"
  echo "$drv" > "${base}.logdriver.txt" || true

  path="$(docker inspect -f '{{.LogPath}}' "$id" 2>/dev/null || echo '')"
  echo "$path" > "${base}.logpath.txt" || true
  if [[ -n "$path" && -r "$path" ]]; then
    cp -a "$path" "$OUT/host-logfiles/$(basename "${base}").json" 2>/dev/null || true
  elif [[ -n "$path" ]]; then
    echo "(not readable: $path — try sudo)" >> "${base}.logpath.txt"
  fi
done

# --- Compose context (only if a compose file is present in cwd)
if [[ -f docker-compose.yml || -f docker-compose.yaml || -f compose.yml || -f compose.yaml ]]; then
  run docker compose ps -a > "$OUT/compose/compose-ps.txt" 2>&1 || true
  run docker compose config > "$OUT/compose/compose-config.yaml" 2>&1 || true
  run docker compose logs -t --no-color --tail=all > "$OUT/compose/compose-all.log" 2>&1 || true
fi

# --- Daemon logs (systemd-based hosts)
if command -v journalctl >/dev/null 2>&1; then
  sudo journalctl -u docker --since 24h > "$OUT/host/dockerd-24h.log" 2>&1 || true
  sudo journalctl -u containerd --since 24h > "$OUT/host/containerd-24h.log" 2>&1 || true
fi

# --- Docker events (last 24h)
if command -v timeout >/dev/null 2>&1; then
  timeout 5s docker events --since 24h --until now > "$OUT/host/docker-events-24h.log" 2>&1 || true
else
  docker events --since 24h --until now > "$OUT/host/docker-events-24h.log" 2>&1 &
  sleep 5; kill $! 2>/dev/null || true
fi

# --- Pack everything
tar czf "$OUT.tgz" -C "$OUT" .
echo
echo "Logs written to: $OUT"
echo "Archive created: $OUT.tgz"

