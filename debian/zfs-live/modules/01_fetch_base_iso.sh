#!/usr/bin/env bash
# 01_fetch_base_iso.sh - verify (and optionally checksum) the base Debian live ISO

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 01_fetch_base_iso: Verifying base live ISO ==="

  require_cmd sha256sum

  # Ensure the base ISO path is set and exists
  if [[ -z "${ZFS_BASE_ISO_PATH:-}" ]]; then
    die "ZFS_BASE_ISO_PATH is not set (see zfs-live/env.sh)"
  fi

  if [[ ! -f "$ZFS_BASE_ISO_PATH" ]]; then
    die "Base ISO not found at ZFS_BASE_ISO_PATH: $ZFS_BASE_ISO_PATH"
  fi

  info "Base ISO found at: $ZFS_BASE_ISO_PATH"

  # Optional checksum verification
  if [[ -n "${ZFS_BASE_ISO_SHA256:-}" ]]; then
    info "Verifying SHA256 checksum for base ISO"
    local actual
    actual="$(sha256sum "$ZFS_BASE_ISO_PATH" | awk '{print $1}')"
    if [[ "$actual" != "$ZFS_BASE_ISO_SHA256" ]]; then
      die "SHA256 mismatch for $ZFS_BASE_ISO_PATH:
  expected: $ZFS_BASE_ISO_SHA256
  actual:   $actual"
    fi
    info "SHA256 checksum OK for $ZFS_BASE_ISO_PATH"
  else
    warn "ZFS_BASE_ISO_SHA256 not set; skipping checksum verification."
  fi

  info "01_fetch_base_iso: base ISO verification complete."
}

main "$@"

