#!/usr/bin/env bash
# cluster/lib/proxmox.sh - Proxmox helper functions for foundryBot

set -euo pipefail

FOUNDRY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=/dev/null
source "$FOUNDRY_ROOT/cluster/lib/logging.sh"
# shellcheck source=/dev/null
source "$FOUNDRY_ROOT/cluster/lib/ssh.sh"

# Optionally source env (for PROXMOX_HOST, ISO_STORAGE, VM_STORAGE, DOMAIN)
if [[ -z "${PROXMOX_HOST:-}" ]] && [[ -f "$FOUNDRY_ROOT/cluster/env.sh" ]]; then
  # shellcheck source=/dev/null
  source "$FOUNDRY_ROOT/cluster/env.sh"
fi

# -----------------------------------------------------------------------------
# Core Proxmox SSH wrapper
# -----------------------------------------------------------------------------

# pmx: run a command on the Proxmox host as root
#   Usage: pmx "qm list"
pmx() {
  : "${PROXMOX_HOST:?PROXMOX_HOST must be set (see cluster/env.sh)}"
  sssh "root@${PROXMOX_HOST}" "$@"
}

# -----------------------------------------------------------------------------
# VM state helpers
# -----------------------------------------------------------------------------

# pmx_vm_state: get VM state (running, stopped, paused, unknown)
pmx_vm_state() {
  local vmid="$1"
  local state
  # qm status <vmid> returns "status: <STATE>"
  state="$(pmx "qm status $vmid 2>/dev/null" | awk '{print tolower($2)}' || true)"
  if [[ -z "$state" ]]; then
    echo "unknown"
  else
    echo "$state"
  fi
}

# pmx_wait_for_state: poll until VM reaches desired state or timeout
pmx_wait_for_state() {
  local vmid="$1"
  local want="$2"
  local timeout="${3:-2400}"  # default 40 minutes
  local start now state

  start="$(date +%s)"
  info "Waiting for VM $vmid to be '$want' ..."

  while :; do
    state="$(pmx_vm_state "$vmid")"
    if [[ "$state" == "$want" ]]; then
      info "VM $vmid is now $state"
      return 0
    fi

    now="$(date +%s)"
    if (( now - start > timeout )); then
      err "Timeout: VM $vmid did not reach state '$want' (current=$state)"
      return 1
    fi

    sleep 5
  done
}

# pmx_wait_qga: wait for QEMU Guest Agent to be responsive
pmx_wait_qga() {
  local vmid="$1"
  local timeout="${2:-1200}"  # default 20 minutes
  local start now

  info "Waiting for QEMU Guest Agent on VM $vmid ..."
  start="$(date +%s)"

  while :; do
    if pmx "qm agent $vmid ping >/dev/null 2>&1 || qm guest ping $vmid >/dev/null 2>&1"; then
      info "QGA ready on VM $vmid"
      return 0
    fi

    now="$(date +%s)"
    if (( now - start > timeout )); then
      err "Timeout waiting for QGA on VM $vmid"
      return 1
    fi

    sleep 3
  done
}

# -----------------------------------------------------------------------------
# Guest agent helpers (JSON / non-JSON handling)
# -----------------------------------------------------------------------------

# pmx_qga_has_json: detect if qm guest exec supports --output-format json
pmx_qga_has_json() {
  if [[ "${PMX_QGA_JSON:-}" == "yes" || "${PMX_QGA_JSON:-}" == "no" ]]; then
    echo "$PMX_QGA_JSON"
    return
  fi
  PMX_QGA_JSON="$(
    pmx "qm guest exec -h 2>&1 | grep -q -- '--output-format' && echo yes || echo no" \
      | tr -d '\r'
  )"
  echo "$PMX_QGA_JSON"
}

# pmx_guest_exec: fire-and-forget guest command via QGA
pmx_guest_exec() {
  local vmid="$1"; shift
  pmx "qm guest exec $vmid -- $* >/dev/null 2>&1 || true"
}

# pmx_guest_cat: cat a file inside the guest via QGA, handling JSON/no-JSON
pmx_guest_cat() {
  local vmid="$1" path="$2"
  local has_json raw pid status outb64 outplain outjson

  has_json="$(pmx_qga_has_json)"

  if [[ "$has_json" == "yes" ]]; then
    # Newer qm guest exec with --output-format json and separate exec-status
    raw="$(pmx "qm guest exec $vmid --output-format json -- /bin/cat '$path' 2>/dev/null || true")"
    pid="$(printf '%s\n' "$raw" | sed -n 's/.*\"pid\"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p')"
    [[ -n "$pid" ]] || return 2

    while :; do
      status="$(pmx "qm guest exec-status $vmid $pid --output-format json 2>/dev/null || true" || true)"
      if printf '%s' "$status" | grep -Eq '"exited"[[:space:]]*:[[:space:]]*(true|1)'; then
        outb64="$(printf '%s' "$status" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
        if [[ -n "$outb64" ]]; then
          printf '%s' "$outb64" | base64 -d 2>/dev/null || printf '%b' "${outb64//\\n/$'\n'}"
        else
          outplain="$(printf '%s' "$status" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
          printf '%b' "${outplain//\\n/$'\n'}"
        fi
        break
      fi
      sleep 1
    done
  else
    # Older qm guest exec: output is JSON-ish on stdout
    outjson="$(pmx "qm guest exec $vmid -- /bin/cat '$path' 2>/dev/null || true")"
    outb64="$(printf '%s\n' "$outjson" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
    if [[ -n "$outb64" ]]; then
      printf '%b' "${outb64//\\n/$'\n'}"
    else
      outplain="$(printf '%s\n' "$outjson" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
      [[ -n "$outplain" ]] || return 3
      printf '%b' "${outplain//\\n/$'\n'}"
    fi
  fi
}

# -----------------------------------------------------------------------------
# ISO upload + VM creation
# -----------------------------------------------------------------------------

# pmx_upload_iso: scp ISO to Proxmox and wait until pvesm sees it
pmx_upload_iso() {
  local iso_file="$1" iso_base
  iso_base="$(basename "$iso_file")"

  info "Uploading ISO to Proxmox: $iso_base"
  sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base" || {
    warn "ISO upload failed once, retrying: $iso_base"
    sleep 2
    sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base"
  }

  # Wait for pvesm to list it on the target ISO storage
  if [[ -n "${ISO_STORAGE:-}" ]]; then
    local i
    for i in {1..30}; do
      if pmx "pvesm list ${ISO_STORAGE}" | awk 'NR>1 {print $2}' | grep -qx "$iso_base"; then
        info "ISO ${iso_base} is now visible in storage ${ISO_STORAGE}"
        break
      fi
      sleep 1
    done
  else
    warn "ISO_STORAGE is not set; skipping pvesm visibility check for ${iso_base}"
  fi

  echo "$iso_base"
}

# pmx_deploy: create a VM with Secure Boot + TPM2 and boot from installer ISO
#   vmid     - VM ID
#   vmname   - short name (we append .${DOMAIN}-${vmid} inside)
#   iso_file - local ISO path
#   mem      - memory in MB
#   cores    - CPU cores
#   disk_gb  - disk size in GB (scsi0 on VM_STORAGE)
pmx_deploy() {
  local vmid="$1" vmname="$2" iso_file="$3" mem="$4" cores="$5" disk_gb="$6"
  local iso_base fqdn

  : "${VM_STORAGE:?VM_STORAGE must be set}"
  : "${ISO_STORAGE:?ISO_STORAGE must be set}"
  : "${DOMAIN:-unixbox.net}"

  fqdn="${vmname}.${DOMAIN}-${vmid}"

  info "Uploading ISO for VM $vmid ($fqdn)"
  iso_base="$(pmx_upload_iso "$iso_file")"

  pmx \
    VMID="$vmid" VMNAME="$fqdn" FINAL_ISO="$iso_base" \
    VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" \
    DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail

# Destroy any existing VM with this ID
qm destroy "$VMID" --purge >/dev/null 2>&1 || true

# Create VM with Secure Boot + TPM2
qm create "$VMID" \
  --name "$VMNAME" \
  --memory "$MEMORY_MB" --cores "$CORES" \
  --cpu host \
  --sockets 1 \
  --machine q35 \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} \
  --serial0 socket \
  --ostype l26 \
  --agent enabled=1,fstrim_cloned_disks=1

# UEFI firmware + Secure Boot keys (OVMF)
qm set "$VMID" --bios ovmf
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=1

# TPM 2.0 state
qm set "$VMID" --tpmstate ${VM_STORAGE}:1,version=v2.0,size=4M

# Attach installer ISO (with retries)
for i in {1..10}; do
  if qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom 2>/dev/null; then
    break
  fi
  sleep 1
done

# Ensure ISO is actually attached
if ! qm config "$VMID" | grep -q '^ide2:.*media=cdrom'; then
  echo "[X] failed to attach ISO ${FINAL_ISO} from ${ISO_STORAGE}" >&2
  exit 1
fi

# Boot from CD first
qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}

# -----------------------------------------------------------------------------
# Convenience wrappers
# -----------------------------------------------------------------------------

# wait_poweroff: wait until VM stops
wait_poweroff() {
  local vmid="$1"
  local timeout="${2:-2400}"
  pmx_wait_for_state "$vmid" "stopped" "$timeout"
}

# boot_from_disk: after install, remove ISO and boot from scsi0
boot_from_disk() {
  local vmid="$1"

  info "Switching VM $vmid to boot from disk"
  pmx "qm set $vmid --delete ide2; qm set $vmid --boot order=scsi0; qm start $vmid"
  pmx_wait_for_state "$vmid" "running" 600
}

