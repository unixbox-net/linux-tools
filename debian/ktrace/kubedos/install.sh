#!/usr/bin/env bash
set -euo pipefail

# Minimal installer for OS images (e.g., kubedos)
# Copies binary to /usr/local/bin and installs a systemd template service.

BIN_SRC="${1:-./dist/ktrace}"
BIN_DST="/usr/local/bin/ktrace"
UNIT_DST="/etc/systemd/system/ktrace-snapshot@.service"

if [[ ! -x "${BIN_SRC}" ]]; then
  echo "Binary not found/executable at ${BIN_SRC}" >&2
  exit 1
fi

install -m 0755 "${BIN_SRC}" "${BIN_DST}"
install -m 0644 "./kubedos/systemd/ktrace-snapshot@.service" "${UNIT_DST}"

echo "Installed:"
echo "  ${BIN_DST}"
echo "  ${UNIT_DST}"
echo
echo "Example run:"
echo "  systemctl start ktrace-snapshot@60.service"
