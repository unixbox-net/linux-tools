#!/usr/bin/env bash
# 06_rebuild_iso.sh - rebuild the final ZFS live ISO from the modified ISO tree
#
# - Patches isolinux + GRUB configs so there is a short timeout and
#   the default entry includes the ZFS auto-install kernel flags.
# - Rebuilds a hybrid BIOS/UEFI ISO with xorriso.

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

patch_isolinux_and_grub() {
  info "Patching bootloader configs for auto-boot + ZFS flags"

  local isolinux_main="$ZFS_ISO_WORK_DIR/isolinux/isolinux.cfg"
  local isolinux_live="$ZFS_ISO_WORK_DIR/isolinux/live.cfg"
  local grub_cfg="$ZFS_ISO_WORK_DIR/boot/grub/grub.cfg"

  # Build the kernel flags we want to inject
  local auto_flags="${ZFS_KERNEL_FLAG_ENABLE} ${ZFS_KERNEL_FLAG_DISK_PARAM}=${ZFS_ROOT_DISK}"

  if [[ -n "${ZFS_DATA_DISKS:-}" ]]; then
    # Convert "/dev/sdb /dev/sdc" -> "/dev/sdb,/dev/sdc"
    local data_csv="${ZFS_DATA_DISKS// /,}"
    auto_flags+=" ${ZFS_KERNEL_FLAG_DATA_PARAM}=${data_csv}"
  fi

  if [[ "${ZFS_ADD_SERIAL_CONSOLE}" == "true" ]]; then
    auto_flags+=" console=ttyS0,115200n8"
  fi

  info "Using auto kernel flags: ${auto_flags}"

  # ------------------------------ BIOS / isolinux -----------------------------
  if [[ -f "$isolinux_main" ]]; then
    info "Patching isolinux main config: $isolinux_main"

    # Ensure a short timeout (in deciseconds)
    if grep -q '^timeout ' "$isolinux_main"; then
      sed -i 's/^timeout .*/timeout 20/' "$isolinux_main"
    else
      echo 'timeout 20' >>"$isolinux_main"
    fi
  else
    warn "isolinux main config not found at $isolinux_main (BIOS boot may still work with defaults)"
  fi

  if [[ -f "$isolinux_live" ]]; then
    info "Patching isolinux live config: $isolinux_live"

    if grep -q 'zfs-auto-install' "$isolinux_live"; then
      info "isolinux live.cfg already has zfs-auto-install flags; leaving as-is."
    else
      # Append our flags to the first 'append' line (the default live entry).
      # This makes the default menu entry perform the auto-install.
      sed -i '0,/^ *append /s//& '"$auto_flags"'/' "$isolinux_live" || \
        warn "Failed to inject ZFS flags into $isolinux_live (check manually)."
    fi
  else
    warn "isolinux live config not found at $isolinux_live"
  fi

  # ------------------------------ UEFI / GRUB --------------------------------
  if [[ -f "$grub_cfg" ]]; then
    info "Patching GRUB config: $grub_cfg"

    # Ensure short timeout
    if grep -q '^set timeout=' "$grub_cfg"; then
      sed -i 's/^set timeout=.*/set timeout=2/' "$grub_cfg"
    else
      sed -i '1iset timeout=2' "$grub_cfg"
    fi

    # Inject auto flags into the first "linux ... boot=live" line (default entry).
    if grep -q 'zfs-auto-install' "$grub_cfg"; then
      info "GRUB cfg already has zfs-auto-install flags; leaving as-is."
    else
      sed -i '0,/^[[:space:]]*linux[[:space:]]\+.*boot=live/s//& '"$auto_flags"'/' "$grub_cfg" || \
        warn "Failed to inject ZFS flags into $grub_cfg (check manually)."
    fi
  else
    warn "GRUB config not found at $grub_cfg"
  fi
}

main() {
  info "=== 06_rebuild_iso: Rebuilding ZFS live ISO ==="

  require_cmd xorriso

  die_if_missing "$ZFS_ISO_WORK_DIR" "ISO work directory"
  die_if_missing "$ZFS_SQUASHFS_IMAGE" "rebuilt SquashFS image"

  # Make sure the boot configs are patched before we repack.
  patch_isolinux_and_grub

  local out_iso="$ZFS_OUTPUT_ISO_PATH"
  mkdir -p "$(dirname "$out_iso")"

  # Optional isohybrid MBR from original ISO
  local mbr_bin="isolinux/isohdpfx.bin"
  local mbr_opts=()
  if [[ -f "$ZFS_ISO_WORK_DIR/$mbr_bin" ]]; then
    mbr_opts=(
      -isohybrid-mbr "$mbr_bin"
      -partition_offset 16
      -isohybrid-gpt-basdat
    )
  else
    warn "MBR bootstrap $mbr_bin not found; building ISO without -isohybrid-mbr/-gpt-basdat options."
  fi

  (
    cd "$ZFS_ISO_WORK_DIR"

    run xorriso -as mkisofs \
      -r -J -joliet-long -cache-inodes \
      -V "Debian ${ZFS_DEBIAN_CODENAME:-trixie} ZFS live amd64" \
      -A "Debian ${ZFS_DEBIAN_CODENAME:-trixie} ZFS live amd64" \
      "${mbr_opts[@]}" \
      -b isolinux/isolinux.bin \
         -c isolinux/boot.cat \
         -no-emul-boot \
         -boot-load-size 4 \
         -boot-info-table \
      -eltorito-alt-boot \
         -e boot/grub/efi.img \
         -no-emul-boot \
      -o "$out_iso" \
      .
  )

  [[ -f "$out_iso" ]] || die "ISO build failed: $out_iso not created"
  info "06_rebuild_iso: ISO created at $out_iso"
}

main "$@"

