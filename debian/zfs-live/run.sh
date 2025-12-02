#!/usr/bin/env bash
# zfs-live/run.sh - orchestrate Debian 13 ZFS live installer build

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$ZFS_LIVE_ROOT/utils.sh"

zfs_setup_err_trap "$(basename "$0")"

MODULE_DIR="$ZFS_LIVE_ROOT/modules"

usage() {
  cat <<EOF
Usage: $0 [module ...]

If no module is given, all modules in $MODULE_DIR are run in numeric order.

Examples:
  $0                         # run all modules
  $0 00                      # run module with prefix "00_"
  $0 00 01 02                # run specific modules by prefix
  $0 04_inject_zfs_autoinstall.sh   # run a specific module file
EOF
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  zfs_live_header
  zfs_live_env_summary

  local modules=()

  if [[ $# -gt 0 ]]; then
    # User specified modules
    local m file
    for m in "$@"; do
      if [[ "$m" =~ ^[0-9][0-9]$ ]]; then
        # Prefix form: "00" → resolve to "00_*.sh"
        file="$(cd "$MODULE_DIR" && ls -1 "${m}"_*.sh 2>/dev/null | head -n1 || true)"
        if [[ -z "$file" ]]; then
          die "No module found for prefix: $m"
        fi
        modules+=("$MODULE_DIR/$file")
      else
        # Assume it is a file name (with or without path)
        if [[ -f "$MODULE_DIR/$m" ]]; then
          modules+=("$MODULE_DIR/$m")
        elif [[ -f "$m" ]]; then
          modules+=("$m")
        else
          die "Module not found: $m"
        fi
      fi
    done
  else
    # No modules specified: run all in order
    mapfile -t modules < <(cd "$MODULE_DIR" && ls -1 [0-9][0-9]_*.sh 2>/dev/null | sort)
    if [[ ${#modules[@]} -eq 0 ]]; then
      die "No modules found in $MODULE_DIR"
    fi
    local i
    for i in "${!modules[@]}"; do
      modules[$i]="$MODULE_DIR/${modules[$i]}"
    done
  fi

  info "Module execution order:"
  local mod
  for mod in "${modules[@]}"; do
    info "  - $(basename "$mod")"
  done

  for mod in "${modules[@]}"; do
    if [[ ! -x "$mod" ]]; then
      die "Module not executable: $mod"
    fi
    info "=== Running module: $mod ==="
    "$mod"
  done

  info "All requested modules completed successfully."
}

main "$@"

