#!/usr/bin/env bash
# 08_proxmox_deploy.sh - upload ZFS live ISO to Proxmox and create SecureBoot+TPM VM

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDRY_ROOT="$(cd "$ZFS_LIVE_ROOT/.." && pwd)"

# zfs-live helpers
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

# Proxmox helpers (pmx, pmx_deploy, wait_poweroff, boot_from_disk, etc.)
# shellcheck source=/dev/null
source "$FOUNDRY_ROOT/cluster/lib/proxmox.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 08_proxmox_deploy: Deploying ZFS live ISO onto Proxmox ==="

  require_cmd ssh scp

  : "${PROXMOX_HOST:?PROXMOX_HOST must be set (see cluster/env.sh)}"

  die_if_missing "$ZFS_OUTPUT_ISO_PATH" "built ZFS live ISO"

  info "Using Proxmox host           : $PROXMOX_HOST"
  info "ISO storage                  : ${ZFS_ISO_STORAGE}"
  info "VM storage                   : ${ZFS_VM_STORAGE}"
  info "Test VM ID                   : ${ZFS_TEST_VM_ID}"
  info "Test VM name/FQDN            : ${ZFS_TEST_VM_FQDN}"
  info "Test VM memory / cores       : ${ZFS_TEST_VM_MEM_MB} MB / ${ZFS_TEST_VM_CORES}"
  info "Test VM disk size            : ${ZFS_TEST_VM_DISK_GB} GB"
  info "ZFS root disk inside VM      : ${ZFS_TEST_VM_ROOT_DISK}"

  # Note: ZFS_TEST_VM_ROOT_DISK should match what we pass in kernel cmdline via
  # zfs-disk= in the boot menu (06_rebuild_iso.sh). For Proxmox VirtIO, this is
  # typically /dev/vda. The menu currently uses ZFS_ROOT_DISK; set that to
  # /dev/vda in env.sh for Proxmox-created VMs.

  # Call pmx_deploy from cluster/lib/proxmox.sh
  pmx_deploy \
    "$ZFS_TEST_VM_ID" \
    "$ZFS_TEST_VM_NAME" \
    "$ZFS_OUTPUT_ISO_PATH" \
    "$ZFS_TEST_VM_MEM_MB" \
    "$ZFS_TEST_VM_CORES" \
    "$ZFS_TEST_VM_DISK_GB"

  info "Proxmox VM $ZFS_TEST_VM_ID created and started with ZFS live ISO attached."
  info "You can now open the Proxmox console for VM $ZFS_TEST_VM_ID and select:"
  info "    ${ZFS_BOOT_MENU_LABEL}"
  info "to trigger the ZFS-on-root autoinstall."
}

main "$@"

