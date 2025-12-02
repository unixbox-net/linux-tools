#!/usr/bin/env bash
# cluster/lib/logging.sh - logging and basic error helpers for foundryBot

set -euo pipefail

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
# All logs go to stderr so stdout can be reserved for machine-readable output
# (JSON, IDs, etc.) if we ever need that.

log() {
  # Usage: log "INFO" "message..."
  local level="$1"; shift
  printf '[%s] [%s] %s\n' "$(date -Is)" "$level" "$*" >&2
}

info() {
  # Usage: info "message..."
  log "INFO" "$@"
}

warn() {
  # Usage: warn "message..."
  log "WARN" "$@"
}

err() {
  # Usage: err "message..."
  log "ERROR" "$@"
}

die() {
  # Usage: die "message..."
  err "$@"
  exit 1
}

# -----------------------------------------------------------------------------
# Command sanity
# -----------------------------------------------------------------------------

require_cmd() {
  # Usage: require_cmd cmd1 cmd2 ...
  # Fails fast if any of the given commands are missing.
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

  if [[ $missing -ne 0 ]]; then
    die "One or more required commands are missing"
  fi
}

# -----------------------------------------------------------------------------
# Safe runner
# -----------------------------------------------------------------------------

run() {
  # Usage: run some_command args...
  # Logs the command before running it.
  info "Running: $*"
  "$@"
}

# -----------------------------------------------------------------------------
# Standard trap helper (optional, used by modules/run scripts)
# -----------------------------------------------------------------------------

setup_err_trap() {
  # Usage: setup_err_trap "script-name"
  local script_name="${1:-${BASH_SOURCE[1]:-unknown}}"
  # shellcheck disable=SC2064
  trap "die \"Script ${script_name} failed at line \$LINENO\"" ERR
}

