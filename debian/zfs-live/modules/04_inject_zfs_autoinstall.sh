#!/usr/bin/env bash
# 04_inject_zfs_autoinstall.sh - add live-config ZFS autoinstall hook + darksite repo

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

main() {
  info "=== 04_inject_zfs_autoinstall: Injecting live-config hook ==="

  die_if_missing "$ZFS_SQUASHFS_WORK_DIR" "SquashFS work directory"

  # ---------------------------------------------------------------------------
  # 1) Install live-config script: /lib/live/config/9999-zfs-autoinstall
  # ---------------------------------------------------------------------------
  local lc_dir="$ZFS_SQUASHFS_WORK_DIR/lib/live/config"
  local src_script="$ZFS_LIVE_ROOT/autoinstall/9999-zfs-autoinstall"
  local dst_script="$lc_dir/9999-zfs-autoinstall"

  die_if_missing "$src_script" "source ZFS autoinstall script (zfs-live/autoinstall/9999-zfs-autoinstall)"

  info "Creating live-config directory: $lc_dir"
  mkdir -p "$lc_dir"

  info "Copying ZFS autoinstall live-config script:"
  info "  from: $src_script"
  info "  to  : $dst_script"

  install -m 0755 "$src_script" "$dst_script"

  # ---------------------------------------------------------------------------
  # 2) Optional: copy darksite repo into the live filesystem at /opt/darksite
  # ---------------------------------------------------------------------------
  if [[ -n "${ZFS_DARKSITE_DIR:-}" && -d "$ZFS_DARKSITE_DIR" ]]; then
    local target_darksite="$ZFS_SQUASHFS_WORK_DIR/opt/darksite"
    info "Copying darksite APT repo into image:"
    info "  from: $ZFS_DARKSITE_DIR"
    info "  to  : $target_darksite"
    mkdir -p "$target_darksite"
    # rsync if present, else fallback to cp -a
    if command -v rsync >/dev/null 2>&1; then
      run rsync -a "$ZFS_DARKSITE_DIR"/ "$target_darksite"/
    else
      run cp -a "$ZFS_DARKSITE_DIR"/. "$target_darksite"/
    fi
  else
    info "No darksite repo directory configured or found; skipping darksite injection."
  fi

  info "04_inject_zfs_autoinstall: live-config ZFS hook injected successfully."
}

main "$@"

