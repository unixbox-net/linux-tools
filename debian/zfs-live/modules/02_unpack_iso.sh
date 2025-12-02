#!/usr/bin/env bash
# 02_unpack_iso.sh - extract base Debian live ISO into the ISO work directory

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 02_unpack_iso: Extracting base live ISO ==="

  require_cmd xorriso

  die_if_missing "$ZFS_BASE_ISO_PATH" "base live ISO"
  info "Using base ISO: $ZFS_BASE_ISO_PATH"

  # Clean ISO work dir but keep parent structure intact
  if [[ -d "$ZFS_ISO_WORK_DIR" ]]; then
    info "Clearing ISO work directory: $ZFS_ISO_WORK_DIR"
    rm -rf "${ZFS_ISO_WORK_DIR:?}/"*
  else
    mkdir -p "$ZFS_ISO_WORK_DIR"
  fi

  info "Extracting ISO with xorriso into $ZFS_ISO_WORK_DIR"
  run xorriso -osirrox on \
    -indev "$ZFS_BASE_ISO_PATH" \
    -extract / "$ZFS_ISO_WORK_DIR"

  # Verify live filesystem image exists
  if [[ ! -f "$ZFS_SQUASHFS_IMAGE" ]]; then
    die "Could not find filesystem.squashfs at expected path: $ZFS_SQUASHFS_IMAGE"
  fi

  info "Found SquashFS image at: $ZFS_SQUASHFS_IMAGE"
  info "02_unpack_iso: ISO extraction complete."
}

main "$@"

