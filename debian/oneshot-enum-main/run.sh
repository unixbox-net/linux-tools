#!/usr/bin/env bash
set -euo pipefail
IMAGE=${IMAGE:-oneshot-enum}

docker build -t "$IMAGE" .
mkdir -p out
docker run --rm \
  -e AD_DOMAIN -e AD_USER -e AD_PASS -e KRB5CCNAME -e AD_ENUM_SAFE -e ALLOW_ROAST -e ALLOW_BRUTE \
  -v "$PWD/out:/work/out" "$IMAGE" \
  --full "${1:-example.com}" \
  --out /work/out/out.json \
  --report-html /work/out/report.html \
  --assume-yes --automate

echo "Artifacts in ./out"

