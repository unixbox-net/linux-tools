#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-./bpf/vmlinux.h}"

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool not found. Install it (Debian/Ubuntu): apt-get install -y bpftool" >&2
  exit 1
fi

VMLINUX_BTF="/sys/kernel/btf/vmlinux"
if [[ ! -r "${VMLINUX_BTF}" ]]; then
  echo "Missing ${VMLINUX_BTF}. Your kernel may not expose BTF." >&2
  echo "Hint: install a kernel with CONFIG_DEBUG_INFO_BTF=y, or generate vmlinux BTF another way." >&2
  exit 1
fi

mkdir -p "$(dirname "${OUT}")"
echo "[gen-vmlinuxh] Generating ${OUT} from ${VMLINUX_BTF}"
bpftool btf dump file "${VMLINUX_BTF}" format c > "${OUT}"
echo "[gen-vmlinuxh] Done"
