#!/usr/bin/env bash
# 00_clean_build.sh - fully reset ZFS live installer build state

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 00_clean_build: Cleaning previous ZFS live build state ==="

  # 1) Unmount anything under the build directory (live/target mounts, etc.)
  cleanup_mounts_under "$ZFS_BUILD_DIR"

  # 2) Remove the entire build tree, including logs, iso/, squashfs-root/, output/
  info "Removing build directory: $ZFS_BUILD_DIR"
  rm -rf "$ZFS_BUILD_DIR"

  # 3) Recreate base directories using the env-provided paths
  info "Recreating build directories"
  mkdir -p \
    "$ZFS_BUILD_DIR" \
    "$ZFS_ISO_WORK_DIR" \
    "$ZFS_SQUASHFS_WORK_DIR" \
    "$ZFS_OUTPUT_DIR" \
    "$ZFS_LOG_DIR"

  # 4) Remove any leftover local QEMU disk image (it will be recreated by 07_test_qemu.sh)
  if [[ -n "${ZFS_QEMU_DISK_IMG:-}" && -f "$ZFS_QEMU_DISK_IMG" ]]; then
    info "Removing leftover QEMU test disk: $ZFS_QEMU_DISK_IMG"
    rm -f "$ZFS_QEMU_DISK_IMG"
  fi

  info "00_clean_build: build environment reset complete."
}

main "$@"

