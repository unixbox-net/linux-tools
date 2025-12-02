#!/usr/bin/env bash
# cluster/lib/ssh.sh - SSH + SCP helpers (build host → Proxmox / remote)

set -euo pipefail

# This file expects PROXMOX_HOST etc. to come from cluster/env.sh
# but is generic enough to be reused for other hosts too.

# -----------------------------------------------------------------------------
# SSH options
# -----------------------------------------------------------------------------
# - Quiet, no hostkey prompts
# - Short timeout
# - No permanent known_hosts pollution
SSH_OPTS="-q \
  -o LogLevel=ERROR \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o GlobalKnownHostsFile=/dev/null \
  -o CheckHostIP=no \
  -o ConnectTimeout=6 \
  -o BatchMode=yes"

# -----------------------------------------------------------------------------
# SSH wrappers
# -----------------------------------------------------------------------------

# sssh: run remote SSH command with hardened defaults
#   Usage: sssh root@host "qm list"
sssh() {
  ssh $SSH_OPTS "$@"
}

# sscp: copy files with the same hardened options
#   Usage: sscp local.iso root@host:/var/lib/vz/template/iso/
sscp() {
  scp -q $SSH_OPTS "$@"
}

