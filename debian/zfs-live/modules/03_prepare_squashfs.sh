#!/usr/bin/env bash
# 03_prepare_squashfs.sh - unsquash live filesystem for customization

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 03_prepare_squashfs: Unsquashing live filesystem ==="

  require_cmd unsquashfs

  die_if_missing "$ZFS_SQUASHFS_IMAGE" "live SquashFS image"

  # Clean SquashFS work dir but keep parent
  if [[ -d "$ZFS_SQUASHFS_WORK_DIR" ]]; then
    info "Clearing SquashFS work directory: $ZFS_SQUASHFS_WORK_DIR"
    rm -rf "${ZFS_SQUASHFS_WORK_DIR:?}/"*
  else
    mkdir -p "$ZFS_SQUASHFS_WORK_DIR"
  fi

  info "Unsquashing $ZFS_SQUASHFS_IMAGE into $ZFS_SQUASHFS_WORK_DIR"

  # unsquashfs needs to run with a working dir that can see the paths sanely
  ( cd "$ZFS_BUILD_DIR" && \
    run unsquashfs -d "$ZFS_SQUASHFS_WORK_DIR" "$ZFS_SQUASHFS_IMAGE" )

  info "03_prepare_squashfs: live filesystem unsquashed successfully."
}

main "$@"

