#!/usr/bin/env bash
# zfs-live/utils.sh - shared helpers for Debian 13 ZFS live installer build

set -euo pipefail

ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FOUNDRY_ROOT="$(cd "$ZFS_LIVE_ROOT/.." && pwd)"

# -----------------------------------------------------------------------------
# Try to reuse cluster/lib/logging.sh (preferred) or fall back to local logger
# -----------------------------------------------------------------------------

if [[ -f "$FOUNDRY_ROOT/cluster/lib/logging.sh" ]]; then
  # shellcheck source=/dev/null
  source "$FOUNDRY_ROOT/cluster/lib/logging.sh"
  HAVE_CLUSTER_LOGGING=1
else
  HAVE_CLUSTER_LOGGING=0

  log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(date -Is)" "$level" "$*" >&2
  }

  info() { log "INFO" "$@"; }
  warn() { log "WARN" "$@"; }
  err()  { log "ERROR" "$@"; }

  die() {
    err "$@"
    exit 1
  }

  require_cmd() {
    if [[ $# -eq 0 ]]; then
      die "require_cmd: no command names provided"
    fi
    local cmd missing=0
    for cmd in "$@"; do
      if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Required command not found in PATH: $cmd"
        missing=1
      fi
    done
    (( missing == 0 )) || die "One or more required commands are missing"
  }

  run() {
    info "Running: $*"
    "$@"
  }

  setup_err_trap() {
    local script_name="${1:-${BASH_SOURCE[1]:-unknown}}"
    # shellcheck disable=SC2064
    trap "die \"Script ${script_name} failed at line \$LINENO\"" ERR
  }
fi

# -----------------------------------------------------------------------------
# Source zfs-live/env.sh to get all ZFS_* paths/knobs
# -----------------------------------------------------------------------------
if [[ -f "$ZFS_LIVE_ROOT/env.sh" ]]; then
  # shellcheck source=/dev/null
  source "$ZFS_LIVE_ROOT/env.sh"
else
  die "zfs-live/utils.sh: env.sh not found at $ZFS_LIVE_ROOT/env.sh"
fi

# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------

die_if_missing() {
  # Usage: die_if_missing "/some/path" "human description"
  local path="$1" desc="$2"
  if [[ ! -e "$path" ]]; then
    die "Missing ${desc}: $path"
  fi
}

cleanup_mounts_under() {
  # Usage: cleanup_mounts_under "$ZFS_BUILD_DIR"
  # Unmount any mounts with a mountpoint under the given directory, deepest first.
  local root="$1"
  [[ -d "$root" ]] || return 0

  local m escaped
  escaped="$(printf '%s' "$root" | sed 's/[.[\*^$(){}+?\\/]/\\&/g')"

  info "Checking for mounts under $root to unmount"
  awk '{print $2}' /proc/mounts | grep "^$escaped" | sort -r | while read -r m; do
    if [[ -n "$m" && "$m" != "/" ]]; then
      info "Unmounting $m"
      umount -lf "$m" 2>/dev/null || warn "Failed to unmount $m (may already be gone)"
    fi
  done
}

zfs_live_header() {
  info "=== Debian ${ZFS_DEBIAN_CODENAME} ZFS live installer build ==="
  info "Base live ISO : $ZFS_BASE_ISO_PATH"
  info "Output ISO    : $ZFS_OUTPUT_ISO_PATH"
  info "Build dir     : $ZFS_BUILD_DIR"
}

# Convenience alias so modules can just call setup_err_trap without thinking
zfs_setup_err_trap() {
  local script_name="${1:-$(basename "${BASH_SOURCE[1]:-unknown}")}"
  setup_err_trap "$script_name"
}

