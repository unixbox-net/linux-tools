#!/usr/bin/env bash
# 07_test_qemu.sh - optional QEMU smoke test for ZFS live ISO

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 07_test_qemu: QEMU smoke test ==="

  if [[ "${ZFS_QEMU_SKIP:-0}" != "0" ]]; then
    info "ZFS_QEMU_SKIP=${ZFS_QEMU_SKIP}; skipping QEMU smoke test."
    return 0
  fi

  require_cmd qemu-system-x86_64 qemu-img

  local iso="$ZFS_OUTPUT_ISO_PATH"
  die_if_missing "$iso" "built ZFS live ISO"

  # Ensure test disk exists
  if [[ ! -f "$ZFS_QEMU_DISK_IMG" ]]; then
    info "Creating QEMU test disk: $ZFS_QEMU_DISK_IMG (${ZFS_QEMU_DISK_SIZE_GB}G)"
    run qemu-img create -f qcow2 "$ZFS_QEMU_DISK_IMG" "${ZFS_QEMU_DISK_SIZE_GB}G"
  else
    info "Using existing QEMU test disk: $ZFS_QEMU_DISK_IMG"
  fi

  info "Booting QEMU with:"
  info "  ISO : $iso"
  info "  Disk: $ZFS_QEMU_DISK_IMG"
  info ""
  info "Tip: Select the '${ZFS_BOOT_MENU_LABEL}' entry in the boot menu to trigger ZFS autoinstall."

  # Use curses display so you can see boot without GTK
  run qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 \
    -cpu host \
    -drive file="$iso",media=cdrom \
    -drive file="$ZFS_QEMU_DISK_IMG",format=qcow2,if=virtio \
    -boot d \
    -serial mon:stdio \
    -display curses

  info "07_test_qemu: QEMU session ended."
}

main "$@"

