#!/usr/bin/env bash
# cluster/lib/enroll_keys.sh - enrollment SSH keypair management

set -euo pipefail

# This library expects:
#   - cluster/env.sh to have set:
#       ENROLL_KEY_NAME
#       ENROLL_KEY_DIR
#       ENROLL_KEY_PRIV
#       ENROLL_KEY_PUB
#   - cluster/lib/logging.sh for log/die/require_cmd

FOUNDRY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=/dev/null
source "$FOUNDRY_ROOT/cluster/lib/logging.sh"

# Optionally source env if not already done by caller
if [[ -z "${ENROLL_KEY_DIR:-}" || -z "${ENROLL_KEY_NAME:-}" ]]; then
  if [[ -f "$FOUNDRY_ROOT/cluster/env.sh" ]]; then
    # shellcheck source=/dev/null
    source "$FOUNDRY_ROOT/cluster/env.sh"
  else
    die "cluster/lib/enroll_keys.sh: ENROLL_KEY_* not set and cluster/env.sh not found"
  fi
fi

setup_err_trap "$(basename "${BASH_SOURCE[0]}")"

# ---------------------------------------------------------------------------
# ensure_enroll_keypair
# ---------------------------------------------------------------------------
# This is the exact behaviour from your original deploy.sh:
# - If either private or public key is missing → generate a fresh ed25519 pair.
# - Otherwise → log that we are reusing the existing keypair.

ensure_enroll_keypair() {
  require_cmd ssh-keygen

  mkdir -p "$ENROLL_KEY_DIR"

  if [[ ! -f "$ENROLL_KEY_PRIV" || ! -f "$ENROLL_KEY_PUB" ]]; then
    info "Generating cluster enrollment SSH keypair in $ENROLL_KEY_DIR"
    ssh-keygen \
      -t ed25519 \
      -N "" \
      -f "$ENROLL_KEY_PRIV" \
      -C "enroll@cluster" \
      >/dev/null
  else
    info "Using existing cluster enrollment keypair in $ENROLL_KEY_DIR"
  fi
}

