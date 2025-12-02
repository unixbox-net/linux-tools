#!/usr/bin/env bash
# zfs-live/env.sh - Environment for Debian 13 ZFS-on-root live installer builder

set -euo pipefail

# -----------------------------------------------------------------------------
# Repo roots
# -----------------------------------------------------------------------------
ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FOUNDRY_ROOT="$(cd "$ZFS_LIVE_ROOT/.." && pwd)"

# Optionally source cluster/env.sh so we can reuse PROXMOX_HOST, ISO_STORAGE, VM_STORAGE, DOMAIN, etc.
if [[ -f "$FOUNDRY_ROOT/cluster/env.sh" ]]; then
  # shellcheck source=/dev/null
  source "$FOUNDRY_ROOT/cluster/env.sh"
fi

# -----------------------------------------------------------------------------
# Debian live ISO selection
# -----------------------------------------------------------------------------
ZFS_DEBIAN_CODENAME="${ZFS_DEBIAN_CODENAME:-trixie}"

# Base Debian *live* ISO path (already downloaded).
ZFS_BASE_ISO_PATH="${ZFS_BASE_ISO_PATH:-/root/debian-live-13.2.0-amd64-standard.iso}"

# Optional checksum for safety. Leave empty to skip verification.
ZFS_BASE_ISO_SHA256="${ZFS_BASE_ISO_SHA256:-}"

# -----------------------------------------------------------------------------
# Build directories – **moved out of the git repo** to /root/builds/zfs-live
# -----------------------------------------------------------------------------
ZFS_BUILD_DIR="${ZFS_BUILD_DIR:-/root/builds/zfs-live}"
ZFS_ISO_WORK_DIR="${ZFS_ISO_WORK_DIR:-$ZFS_BUILD_DIR/iso}"
ZFS_SQUASHFS_WORK_DIR="${ZFS_SQUASHFS_WORK_DIR:-$ZFS_BUILD_DIR/squashfs-root}"
ZFS_OUTPUT_DIR="${ZFS_OUTPUT_DIR:-$ZFS_BUILD_DIR/output}"
ZFS_LOG_DIR="${ZFS_LOG_DIR:-$ZFS_BUILD_DIR/logs}"

mkdir -p "$ZFS_BUILD_DIR" "$ZFS_ISO_WORK_DIR" "$ZFS_SQUASHFS_WORK_DIR" "$ZFS_OUTPUT_DIR" "$ZFS_LOG_DIR"

# Paths inside ISO
ZFS_LIVE_DIR="${ZFS_LIVE_DIR:-$ZFS_ISO_WORK_DIR/live}"
ZFS_SQUASHFS_IMAGE="${ZFS_SQUASHFS_IMAGE:-$ZFS_LIVE_DIR/filesystem.squashfs}"

# Output ISO name
ZFS_OUTPUT_ISO_NAME="${ZFS_OUTPUT_ISO_NAME:-debian-13-zfs-live-amd64.iso}"
ZFS_OUTPUT_ISO_PATH="${ZFS_OUTPUT_DIR}/${ZFS_OUTPUT_ISO_NAME}"

# -----------------------------------------------------------------------------
# ZFS-on-root layout
# -----------------------------------------------------------------------------
# Default install target disk inside VM/bare metal.
ZFS_ROOT_DISK="${ZFS_ROOT_DISK:-/dev/sda}"

# Optional extra data disks (future).
ZFS_DATA_DISKS="${ZFS_DATA_DISKS:-}"

ZFS_POOL_NAME="${ZFS_POOL_NAME:-rpool}"

ZFS_ROOT_DATASET_PREFIX="${ZFS_ROOT_DATASET_PREFIX:-ROOT}"
ZFS_ROOT_DATASET_NAME="${ZFS_ROOT_DATASET_NAME:-${ZFS_ROOT_DATASET_PREFIX}/${ZFS_DEBIAN_CODENAME}}"

# Default hostname / user / timezone / password (can be overridden via kernel cmdline).
ZFS_DEFAULT_HOSTNAME="${ZFS_DEFAULT_HOSTNAME:-debian-zfs}"
ZFS_DEFAULT_USERNAME="${ZFS_DEFAULT_USERNAME:-debian}"
ZFS_DEFAULT_PASSWORD="${ZFS_DEFAULT_PASSWORD:-debian}"
ZFS_DEFAULT_TIMEZONE="${ZFS_DEFAULT_TIMEZONE:-Etc/UTC}"

ZFS_DEBIAN_SUITE="${ZFS_DEBIAN_SUITE:-$ZFS_DEBIAN_CODENAME}"
ZFS_DEBOOTSTRAP_MIRROR="${ZFS_DEBOOTSTRAP_MIRROR:-http://deb.debian.org/debian}"

# -----------------------------------------------------------------------------
# Darksite / offline APT repo (optional)
# -----------------------------------------------------------------------------
ZFS_DARKSITE_DIR="${ZFS_DARKSITE_DIR:-$ZFS_BUILD_DIR/darksite}"

# Whether the **target install** should wire /opt/darksite into APT.
ZFS_USE_DARKSITE_IN_TARGET="${ZFS_USE_DARKSITE_IN_TARGET:-false}"

# Whether the **live environment** should have the darksite bind-mounted in.
# Used by 04_inject_zfs_autoinstall.sh
ZFS_USE_DARKSITE_IN_LIVE="${ZFS_USE_DARKSITE_IN_LIVE:-false}"

# -----------------------------------------------------------------------------
# Auto-install boot menu behaviour
# -----------------------------------------------------------------------------
ZFS_BOOT_MENU_LABEL="${ZFS_BOOT_MENU_LABEL:-Auto ZFS Install (DESTROYS DISK)}"

ZFS_KERNEL_FLAG_ENABLE="${ZFS_KERNEL_FLAG_ENABLE:-zfs-auto-install=1}"
ZFS_KERNEL_FLAG_DISK_PARAM="${ZFS_KERNEL_FLAG_DISK_PARAM:-zfs-disk}"
ZFS_KERNEL_FLAG_DATA_PARAM="${ZFS_KERNEL_FLAG_DATA_PARAM:-zfs-data-disks}"

ZFS_ADD_SERIAL_CONSOLE="${ZFS_ADD_SERIAL_CONSOLE:-true}"

# -----------------------------------------------------------------------------
# Proxmox integration
# -----------------------------------------------------------------------------
ZFS_ISO_STORAGE="${ZFS_ISO_STORAGE:-${ISO_STORAGE:-local}}"
ZFS_VM_STORAGE="${ZFS_VM_STORAGE:-${VM_STORAGE:-local-zfs}}"

ZFS_TEST_VM_ID="${ZFS_TEST_VM_ID:-13000}"
ZFS_TEST_VM_NAME="${ZFS_TEST_VM_NAME:-debian13-zfs}"
ZFS_TEST_VM_FQDN="${ZFS_TEST_VM_FQDN:-${ZFS_TEST_VM_NAME}.${DOMAIN:-unixbox.net}-${ZFS_TEST_VM_ID}}"

ZFS_TEST_VM_MEM_MB="${ZFS_TEST_VM_MEM_MB:-4096}"
ZFS_TEST_VM_CORES="${ZFS_TEST_VM_CORES:-4}"
ZFS_TEST_VM_DISK_GB="${ZFS_TEST_VM_DISK_GB:-40}"

ZFS_TEST_VM_ROOT_DISK="${ZFS_TEST_VM_ROOT_DISK:-/dev/vda}"

# -----------------------------------------------------------------------------
# Local QEMU smoke test settings
# -----------------------------------------------------------------------------
ZFS_QEMU_SKIP="${ZFS_QEMU_SKIP:-0}"
ZFS_QEMU_DISK_IMG="${ZFS_QEMU_DISK_IMG:-$ZFS_BUILD_DIR/test-disk.img}"
ZFS_QEMU_DISK_SIZE_GB="${ZFS_QEMU_DISK_SIZE_GB:-40}"

# -----------------------------------------------------------------------------
# Helper: environment summary
# -----------------------------------------------------------------------------
zfs_live_env_summary() {
  cat <<EOF
[zfs-live] Environment summary
  ZFS_DEBIAN_CODENAME         = $ZFS_DEBIAN_CODENAME
  ZFS_BASE_ISO_PATH           = $ZFS_BASE_ISO_PATH
  ZFS_OUTPUT_ISO_PATH         = $ZFS_OUTPUT_ISO_PATH

  ZFS_ROOT_DISK               = $ZFS_ROOT_DISK
  ZFS_DATA_DISKS              = $ZFS_DATA_DISKS
  ZFS_POOL_NAME               = $ZFS_POOL_NAME
  ZFS_ROOT_DATASET_NAME       = $ZFS_ROOT_DATASET_NAME

  ZFS_DEFAULT_HOSTNAME        = $ZFS_DEFAULT_HOSTNAME
  ZFS_DEFAULT_USERNAME        = $ZFS_DEFAULT_USERNAME
  ZFS_DEFAULT_TIMEZONE        = $ZFS_DEFAULT_TIMEZONE

  ZFS_DEBOOTSTRAP_MIRROR      = $ZFS_DEBOOTSTRAP_MIRROR
  ZFS_DARKSITE_DIR            = $ZFS_DARKSITE_DIR
  ZFS_USE_DARKSITE_IN_TARGET  = $ZFS_USE_DARKSITE_IN_TARGET
  ZFS_USE_DARKSITE_IN_LIVE    = $ZFS_USE_DARKSITE_IN_LIVE

  PROXMOX_HOST                = ${PROXMOX_HOST:-<unset>}
  ZFS_ISO_STORAGE             = $ZFS_ISO_STORAGE
  ZFS_VM_STORAGE              = $ZFS_VM_STORAGE
  ZFS_TEST_VM_ID              = $ZFS_TEST_VM_ID
  ZFS_TEST_VM_FQDN            = $ZFS_TEST_VM_FQDN
EOF
}

