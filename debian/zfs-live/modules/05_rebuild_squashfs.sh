#!/usr/bin/env bash
# 05_rebuild_squashfs.sh - rebuild live filesystem.squashfs after customization

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 05_rebuild_squashfs: Rebuilding live SquashFS image ==="

  require_cmd mksquashfs

  die_if_missing "$ZFS_SQUASHFS_WORK_DIR" "SquashFS work directory"
  die_if_missing "$ZFS_ISO_WORK_DIR" "ISO work directory"

  # Sanity: ensure the original squashfs existed
  if [[ ! -f "$ZFS_SQUASHFS_IMAGE" ]]; then
    warn "Original SquashFS image $ZFS_SQUASHFS_IMAGE not found; assuming it was removed earlier and will be recreated."
  else
    info "Removing old SquashFS image: $ZFS_SQUASHFS_IMAGE"
    rm -f "$ZFS_SQUASHFS_IMAGE"
  fi

  info "Packing new SquashFS from: $ZFS_SQUASHFS_WORK_DIR"
  # mksquashfs must run with workdir at the root of the tree
  (
    cd "$ZFS_SQUASHFS_WORK_DIR"
    run mksquashfs . "$ZFS_SQUASHFS_IMAGE" -comp xz -Xbcj x86 -noappend
  )

  if [[ ! -f "$ZFS_SQUASHFS_IMAGE" ]]; then
    die "Failed to create new SquashFS at $ZFS_SQUASHFS_IMAGE"
  fi

  info "New SquashFS image created at: $ZFS_SQUASHFS_IMAGE"
  info "05_rebuild_squashfs: SquashFS rebuild complete."
}

main "$@"

