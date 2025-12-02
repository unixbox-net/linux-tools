#!/usr/bin/env bash
set -euo pipefail

PROJECT="oneshot-enum"
TARGET_ARG="${1:-}"
ACTION="${2:-}"

if [[ -z "${TARGET_ARG}" ]]; then
  echo "Usage: TARGET=<ip-or-host> $0 <ip-or-host> [--deep-clean]"
  exit 1
fi

export TARGET="${TARGET_ARG}"

echo "==> Preparing host directories (fresh ./out and ./reports)"
rm -rf ./out ./reports
mkdir -p ./out ./reports

echo "==> chmod +x on all .sh (recursive)"
find . -type f -name "*.sh" -print0 | xargs -0 chmod +x || true

echo "==> Tearing down existing stack (project: ${PROJECT})"
docker compose down -v --remove-orphans || true

if [[ "${ACTION}" == "--deep-clean" ]]; then
  echo "==> Deep clean: removing project images (oneshot-*)"
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | grep -E '^oneshot-enum' | awk '{print $1}' | xargs -r docker rmi -f || true
fi

echo "==> Building images"
docker compose build --no-cache --pull

echo "==> Starting core (postgres, minio, minio-init)"
docker compose up -d postgres minio
# wait for minio-init to finish idempotently
docker compose up --no-deps minio-init
echo "OK"

echo "==> Starting observers (socketsnoop + loghog)"
docker compose up -d socketsnoop loghog || true

echo "==> Running scanner against ${TARGET}"
docker compose run --rm -e TARGET="${TARGET}" oneshot-scanner

echo "==> URL list and screenshots"
docker compose run --rm urlgen python /app/urlgen.py

if [ -s out/urls.txt ]; then
  docker compose run --rm webshot bash -lc 'mkdir -p /out/shots && gowitness file -f /out/urls.txt -P /out/shots --threads 4 --timeout 10'
else
  echo "[urlgen] no URLs produced; skipping webshot"
fi

echo "==> Ingesting artifacts to Postgres + MinIO"
docker compose run --rm oneshot-ingestor || true

echo "==> Generating consolidated HTML report"
docker compose run --rm oneshot-reporter || true

echo "Done."
echo "  OUT: $(pwd)/out"
echo "  REPORTS: $(pwd)/reports"

