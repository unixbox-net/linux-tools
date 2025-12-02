#!/usr/bin/env bash
set -euo pipefail

: "${DURATION_SEC:=60}"

mkdir -p /out/bpf

# Try eBPF capture; if it fails, leave a breadcrumb and run the fallback
if python3 /app/socketsnoop.py \
    --out /out/bpf/socketsnoop.jsonl \
    --duration "${DURATION_SEC}" \
  2> /out/bpf/error.log
then
  echo "[socketsnoop] captured OK"
else
  echo 'ebpf failed' > /out/bpf/unsupported.txt
  # best-effort fallback so the dir isn't empty
  ss -Htanp > /out/bpf/ss.txt || true
  echo "[socketsnoop] fallback ss.txt written"
fi

