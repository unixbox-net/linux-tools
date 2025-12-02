#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Logging / error helpers
# =============================================================================

log()  { echo "[INFO]  $(date '+%F %T') - $*"; }
warn() { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err()  { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()  { err "$*"; exit 1; }

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found in PATH: $cmd"
}

# =============================================================================
# SSH helpers (build host → Proxmox / remote)
# =============================================================================

SSH_OPTS="-q \
  -o LogLevel=ERROR \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o GlobalKnownHostsFile=/dev/null \
  -o CheckHostIP=no \
  -o ConnectTimeout=6 \
  -o BatchMode=yes"

sssh() { ssh $SSH_OPTS "$@"; }
sscp() { scp -q $SSH_OPTS "$@"; }

# =============================================================================
# Preseed / installer behaviour
# =============================================================================
# These shape how the Debian installer runs inside the VM.

# PRESEED_LOCALE: system locale (POSIX-style).
#   Common: en_US.UTF-8, en_GB.UTF-8, fr_CA.UTF-8, de_DE.UTF-8
PRESEED_LOCALE="${PRESEED_LOCALE:-en_US.UTF-8}"

# PRESEED_KEYMAP: console keymap.
#   Examples: us, uk, de, fr, ca, se, ...
PRESEED_KEYMAP="${PRESEED_KEYMAP:-us}"

# PRESEED_TIMEZONE: system timezone (tzdata name).
#   Examples: America/Vancouver, UTC, Europe/Berlin, America/New_York
PRESEED_TIMEZONE="${PRESEED_TIMEZONE:-America/Vancouver}"

# PRESEED_MIRROR_COUNTRY: Debian mirror country selector.
#   "manual" = use PRESEED_MIRROR_HOST/PRESEED_MIRROR_DIR directly.
#   Otherwise: two-letter country code (e.g. CA, US, DE).
PRESEED_MIRROR_COUNTRY="${PRESEED_MIRROR_COUNTRY:-manual}"

# PRESEED_MIRROR_HOST: Debian HTTP mirror host.
#   Examples: deb.debian.org, ftp.ca.debian.org, mirror.local.lan
PRESEED_MIRROR_HOST="${PRESEED_MIRROR_HOST:-deb.debian.org}"

# PRESEED_MIRROR_DIR: Debian mirror directory path (typically /debian).
PRESEED_MIRROR_DIR="${PRESEED_MIRROR_DIR:-/debian}"

# PRESEED_HTTP_PROXY: HTTP proxy for installer.
#   Empty = no proxy. Example: http://10.0.0.10:3128
PRESEED_HTTP_PROXY="${PRESEED_HTTP_PROXY:-}"

# PRESEED_ROOT_PASSWORD: root password used by preseed.
#   Strongly recommended to override via env/secret.
PRESEED_ROOT_PASSWORD="${PRESEED_ROOT_PASSWORD:-root}"

# PRESEED_BOOTDEV: install target disk inside the VM.
#   Examples: /dev/sda, /dev/vda, /dev/nvme0n1
PRESEED_BOOTDEV="${PRESEED_BOOTDEV:-/dev/sda}"

# PRESEED_EXTRA_PKGS: space-separated list of extra packages installed at install time.
#   Example: "openssh-server curl vim"
PRESEED_EXTRA_PKGS="${PRESEED_EXTRA_PKGS:-openssh-server}"

# =============================================================================
# High-level deployment mode / target
# =============================================================================

# TARGET: what this script should do.
#   Typical values (depends on which functions you wire in):
#     proxmox-all        - full Proxmox flow (build ISO + master + minions)
#     proxmox-cluster    - build & deploy master + core minions
#     proxmox-k8s-ha     - build HA K8s layout on Proxmox
#     image-only         - build role ISOs only
#     export-base-image  - export master disk from Proxmox to qcow2
#     vmdk-export        - convert BASE_DISK_IMAGE → VMDK
#     aws-ami            - import BASE_DISK_IMAGE into AWS as AMI
#     aws-run            - launch EC2 instances from AMI
#     firecracker-bundle - emit Firecracker rootfs/kernel/initrd + helpers
#     firecracker        - run Firecracker microVMs
#     packer-scaffold    - emit Packer QEMU template
TARGET="${TARGET:-proxmox-all}"

# DOMAIN: base DNS domain for all VMs.
DOMAIN="${DOMAIN:-unixbox.net}"

# INPUT: logical Proxmox target selector (maps to PROXMOX_HOST).
INPUT="${INPUT:-1}"

case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *)        die "Unknown INPUT=$INPUT (expected 1|fiend, 2|dragon, 3|lion)" ;;
esac

# =============================================================================
# ISO source / Proxmox storage IDs
# =============================================================================

# ISO_ORIG: source Debian ISO used to build custom images.
#   Typical: netinst or DVD ISO path on the build host.
# ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-netinst.iso}"
ISO_ORIG="${ISO_ORIG:-/root/debian-live-13.2.0-amd64-standard.iso}"

# ISO_STORAGE: Proxmox storage ID for ISO upload.
#   Examples: local, local-zfs, iso-store
ISO_STORAGE="${ISO_STORAGE:-local}"

# VM_STORAGE: Proxmox storage ID for VM disks.
#   Examples: local-zfs, ssd-zfs, ceph-data
VM_STORAGE="${VM_STORAGE:-local-zfs}"

# =============================================================================
# Master hub VM (control plane / hub)
# =============================================================================

# MASTER_ID: Proxmox VMID for master node.
MASTER_ID="${MASTER_ID:-1000}"

# MASTER_NAME: VM name in Proxmox.
MASTER_NAME="${MASTER_NAME:-master}"

# MASTER_LAN: master LAN IP (IPv4) on your Proxmox bridge.
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

# NETMASK: LAN netmask (e.g. 255.255.255.0 for /24).
NETMASK="${NETMASK:-255.255.255.0}"

# GATEWAY: default gateway on LAN for master/minions.
GATEWAY="${GATEWAY:-10.100.10.1}"

# NAMESERVER: space-separated list of DNS servers inside guests.
#   Example: "10.100.10.2 10.100.10.3 1.1.1.1"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

# =============================================================================
# Core minion VMs (classic 4-node layout)
# =============================================================================
# prom / graf / k8s / storage – these are the "core" non-K8s nodes.

PROM_ID="${PROM_ID:-1001}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.223}"
GRAF_ID="${GRAF_ID:-1002}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.222}"
K8S_ID="${K8S_ID:-1003}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.221}"
STOR_ID="${STOR_ID:-1004}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.220}"

# =============================================================================
# WireGuard hub addresses (planes / fabrics)
# =============================================================================
# WG0–WG3 live on the master; minions/K8s nodes get /32s carved out of them.
#
# Suggested mapping:
#   wg0 = bootstrap / access
#   wg1 = control / telemetry
#   wg2 = data (K8s, app traffic)
#   wg3 = storage / backup

WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"

# WG_ALLOWED_CIDR: comma-separated CIDRs allowed via WireGuard.
#   Default covers all four 10.77–10.80 /16 networks.
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# =============================================================================
# Per-minion WireGuard /32s (PROM / GRAF / K8S / STOR)
# =============================================================================

# Static /32s per role per fabric. Change only if you want a different scheme.
PROM_WG0="${PROM_WG0:-10.77.0.2/32}"; PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; PROM_WG2="${PROM_WG2:-10.79.0.2/32}"; PROM_WG3="${PROM_WG3:-10.80.0.2/32}"
GRAF_WG0="${GRAF_WG0:-10.77.0.3/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; GRAF_WG2="${GRAF_WG2:-10.79.0.3/32}"; GRAF_WG3="${GRAF_WG3:-10.80.0.3/32}"
K8S_WG0="${K8S_WG0:-10.77.0.4/32}";  K8S_WG1="${K8S_WG1:-10.78.0.4/32}";  K8S_WG2="${K8S_WG2:-10.79.0.4/32}";  K8S_WG3="${K8S_WG3:-10.80.0.4/32}"
STOR_WG0="${STOR_WG0:-10.77.0.5/32}"; STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; STOR_WG2="${STOR_WG2:-10.79.0.5/32}"; STOR_WG3="${STOR_WG3:-10.80.0.5/32}"

# =============================================================================
# Extended K8s HA layout VMs
# =============================================================================
# IDs/IPs assume a contiguous /24; adjust to match your LAN.

K8SLB1_ID="${K8SLB1_ID:-1005}"; K8SLB1_NAME="${K8SLB1_NAME:-k8s-lb1}"; K8SLB1_IP="${K8SLB1_IP:-10.100.10.213}"
K8SLB2_ID="${K8SLB2_ID:-1006}"; K8SLB2_NAME="${K8SLB2_NAME:-k8s-lb2}"; K8SLB2_IP="${K8SLB2_IP:-10.100.10.212}"

K8SCP1_ID="${K8SCP1_ID:-1007}"; K8SCP1_NAME="${K8SCP1_NAME:-k8s-cp1}"; K8SCP1_IP="${K8SCP1_IP:-10.100.10.219}"
K8SCP2_ID="${K8SCP2_ID:-1008}"; K8SCP2_NAME="${K8SCP2_NAME:-k8s-cp2}"; K8SCP2_IP="${K8SCP2_IP:-10.100.10.218}"
K8SCP3_ID="${K8SCP3_ID:-1009}"; K8SCP3_NAME="${K8SCP3_NAME:-k8s-cp3}"; K8SCP3_IP="${K8SCP3_IP:-10.100.10.217}"

K8SW1_ID="${K8SW1_ID:-1010}"; K8SW1_NAME="${K8SW1_NAME:-k8s-w1}"; K8SW1_IP="${K8SW1_IP:-10.100.10.216}"
K8SW2_ID="${K8SW2_ID:-1011}"; K8SW2_NAME="${K8SW2_NAME:-k8s-w2}"; K8SW2_IP="${K8SW2_IP:-10.100.10.215}"
K8SW3_ID="${K8SW3_ID:-1012}"; K8SW3_NAME="${K8SW3_NAME:-k8s-w3}"; K8SW3_IP="${K8SW3_IP:-10.100.10.214}"

# =============================================================================
# Per-node K8s WG /32s (extended layout)
# =============================================================================
# Mostly "don't touch" unless you want a different addressing plan.

K8SLB1_WG0="${K8SLB1_WG0:-10.77.0.101/32}"; K8SLB1_WG1="${K8SLB1_WG1:-10.78.0.101/32}"; K8SLB1_WG2="${K8SLB1_WG2:-10.79.0.101/32}"; K8SLB1_WG3="${K8SLB1_WG3:-10.80.0.101/32}"
K8SLB2_WG0="${K8SLB2_WG0:-10.77.0.102/32}"; K8SLB2_WG1="${K8SLB2_WG1:-10.78.0.102/32}"; K8SLB2_WG2="${K8SLB2_WG2:-10.79.0.102/32}"; K8SLB2_WG3="${K8SLB2_WG3:-10.80.0.102/32}"

K8SCP1_WG0="${K8SCP1_WG0:-10.77.0.110/32}"; K8SCP1_WG1="${K8SCP1_WG1:-10.78.0.110/32}"; K8SCP1_WG2="${K8SCP1_WG2:-10.79.0.110/32}"; K8SCP1_WG3="${K8SCP1_WG3:-10.80.0.110/32}"
K8SCP2_WG0="${K8SCP2_WG0:-10.77.0.111/32}"; K8SCP2_WG1="${K8SCP2_WG1:-10.78.0.111/32}"; K8SCP2_WG2="${K8SCP2_WG2:-10.79.0.111/32}"; K8SCP2_WG3="${K8SCP2_WG3:-10.80.0.111/32}"
K8SCP3_WG0="${K8SCP3_WG0:-10.77.0.112/32}"; K8SCP3_WG1="${K8SCP3_WG1:-10.78.0.112/32}"; K8SCP3_WG2="${K8SCP3_WG2:-10.79.0.112/32}"; K8SCP3_WG3="${K8SCP3_WG3:-10.80.0.112/32}"

K8SW1_WG0="${K8SW1_WG0:-10.77.0.120/32}"; K8SW1_WG1="${K8SW1_WG1:-10.78.0.120/32}"; K8SW1_WG2="${K8SW1_WG2:-10.79.0.120/32}"; K8SW1_WG3="${K8SW1_WG3:-10.80.0.120/32}"
K8SW2_WG0="${K8SW2_WG0:-10.77.0.121/32}"; K8SW2_WG1="${K8SW2_WG1:-10.78.0.121/32}"; K8SW2_WG2="${K8SW2_WG2:-10.79.0.121/32}"; K8SW2_WG3="${K8SW2_WG3:-10.80.0.121/32}"
K8SW3_WG0="${K8SW3_WG0:-10.77.0.122/32}"; K8SW3_WG1="${K8SW3_WG1:-10.78.0.122/32}"; K8SW3_WG2="${K8SW3_WG2:-10.79.0.122/32}"; K8SW3_WG3="${K8SW3_WG3:-10.80.0.122/32}"

# =============================================================================
# VM sizing (resources per role)
# =============================================================================
# Memory in MB, cores as vCPUs, disk in GB.

MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-4}";  MASTER_DISK_GB="${MASTER_DISK_GB:-40}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-32}"

K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

K8S_LB_MEM="${K8S_LB_MEM:-2048}"; K8S_LB_CORES="${K8S_LB_CORES:-2}";  K8S_LB_DISK_GB="${K8S_LB_DISK_GB:-16}"
K8S_CP_MEM="${K8S_CP_MEM:-8192}"; K8S_CP_CORES="${K8S_CP_CORES:-4}";  K8S_CP_DISK_GB="${K8S_CP_DISK_GB:-50}"
K8S_WK_MEM="${K8S_WK_MEM:-8192}"; K8S_WK_CORES="${K8S_WK_CORES:-4}";  K8S_WK_DISK_GB="${K8S_WK_DISK_GB:-60}"

# =============================================================================
# Admin / auth / GUI
# =============================================================================

# ADMIN_USER: primary admin account created in the guest.
ADMIN_USER="${ADMIN_USER:-todd}"

# ADMIN_PUBKEY_FILE: path to an SSH public key file.
#   If set and readable, content overrides SSH_PUBKEY.
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-}"

# SSH_PUBKEY: SSH public key string to authorize for ADMIN_USER.
SSH_PUBKEY="${SSH_PUBKEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgqdaF+C41xwLS41+dOTnpsrDTPkAwo4Zejn4tb0lOt todd@onyx.unixbox.net}"

# ALLOW_ADMIN_PASSWORD: whether password SSH auth is enabled for ADMIN_USER.
#   yes = enable password login (LAN-scoped by your firewall rules)
#   no  = key-only SSH auth
# Backward compat: ALLOW_TODD_PASSWORD also respected.
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-${ALLOW_TODD_PASSWORD:-no}}"

# GUI_PROFILE: what kind of GUI to install (if any).
#   server  = no full desktop; server-friendly bits only
#   gnome   = full GNOME desktop
#   minimal = minimal X/Wayland stack (implementation-specific)
GUI_PROFILE="${GUI_PROFILE:-server}"

# INSTALL_ANSIBLE: whether to install Ansible on master (yes|no).
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"

# INSTALL_SEMAPHORE: whether to install Semaphore (Ansible UI) on master.
#   yes - force install
#   try - attempt install; ignore failures
#   no  - skip
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-no}"

TMUX_CONF="${TMUX_CONF:-/etc/skel/.tmux.conf}"


# =============================================================================
# Build artifacts / disk image paths
# =============================================================================

# BUILD_ROOT: base directory on the build server for all outputs.
BUILD_ROOT="${BUILD_ROOT:-/root/builds}"
mkdir -p "$BUILD_ROOT"

# BASE_DISK_IMAGE: exported “golden” VM disk (qcow2 or raw).
#   Used as input for vmdk-export, aws-ami, etc.
BASE_DISK_IMAGE="${BASE_DISK_IMAGE:-$BUILD_ROOT/base-root.qcow2}"

# BASE_RAW_IMAGE: optional explicit raw image path (for tools needing raw).
BASE_RAW_IMAGE="${BASE_RAW_IMAGE:-$BUILD_ROOT/base-root.raw}"

# BASE_VMDK_IMAGE: default VMDK path (ESXi).
BASE_VMDK_IMAGE="${BASE_VMDK_IMAGE:-$BUILD_ROOT/base-root.vmdk}"

# =============================================================================
# AWS image bake / EC2 run
# =============================================================================

# AWS_REGION: AWS region (e.g. us-east-1, us-west-2, ca-central-1)
AWS_REGION="${AWS_REGION:-us-east-1}"

# AWS_PROFILE: AWS CLI profile to use (from ~/.aws/credentials).
AWS_PROFILE="${AWS_PROFILE:-default}"

# AWS_S3_BUCKET: S3 bucket used during AMI import.
AWS_S3_BUCKET="${AWS_S3_BUCKET:-foundrybot-images}"

# AWS_IMPORT_ROLE: IAM role for VM import (typically 'vmimport').
AWS_IMPORT_ROLE="${AWS_IMPORT_ROLE:-vmimport}"

# AWS_ARCH: AMI architecture (x86_64 | arm64).
AWS_ARCH="${AWS_ARCH:-x86_64}"

# AWS_INSTANCE_TYPE: EC2 instance type for builds / runs.
AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t3.micro}"

# AWS_ASSOC_PUBLIC_IP: whether to associate public IP on run (true|false).
AWS_ASSOC_PUBLIC_IP="${AWS_ASSOC_PUBLIC_IP:-true}"

# AWS_KEY_NAME: Name of EC2 KeyPair to inject.
AWS_KEY_NAME="${AWS_KEY_NAME:-clusterkey}"

# AWS_SECURITY_GROUP_ID: Security Group ID for run (required for aws-run).
AWS_SECURITY_GROUP_ID="${AWS_SECURITY_GROUP_ID:-}"

# AWS_SUBNET_ID: Subnet ID where instances will be launched.
AWS_SUBNET_ID="${AWS_SUBNET_ID:-}"

# AWS_VPC_ID: VPC ID (optional; some flows infer from subnet).
AWS_VPC_ID="${AWS_VPC_ID:-}"

# AWS_AMI_ID: The AMI ID to run (required for aws-run).
AWS_AMI_ID="${AWS_AMI_ID:-}"

# AWS_TAG_STACK: Base tag value for "Stack" or similar.
AWS_TAG_STACK="${AWS_TAG_STACK:-foundrybot}"

# AWS_RUN_ROLE: logical role name for instances launched by aws-run.
#   Examples: master, k8s, generic, worker
AWS_RUN_ROLE="${AWS_RUN_ROLE:-generic}"

# AWS_RUN_COUNT: number of instances to launch in aws-run.
AWS_RUN_COUNT="${AWS_RUN_COUNT:-1}"

# =============================================================================
# Firecracker microVM parameters
# =============================================================================

# FC_IMG_SIZE_MB: rootfs size when creating Firecracker images.
FC_IMG_SIZE_MB="${FC_IMG_SIZE_MB:-2048}"

# FC_VCPUS / FC_MEM_MB: default Firecracker vCPU count and RAM in MB.
FC_VCPUS="${FC_VCPUS:-2}"
FC_MEM_MB="${FC_MEM_MB:-2048}"

# FC_ROOTFS_IMG / FC_KERNEL / FC_INITRD: paths to Firecracker artifacts.
FC_ROOTFS_IMG="${FC_ROOTFS_IMG:-$BUILD_ROOT/firecracker/rootfs.ext4}"
FC_KERNEL="${FC_KERNEL:-$BUILD_ROOT/firecracker/vmlinux}"
FC_INITRD="${FC_INITRD:-$BUILD_ROOT/firecracker/initrd.img}"

# FC_WORKDIR: directory holding Firecracker configs/run scripts.
FC_WORKDIR="${FC_WORKDIR:-$BUILD_ROOT/firecracker}"

# =============================================================================
# Packer output paths
# =============================================================================

# PACKER_OUT_DIR: where Packer templates live.
PACKER_OUT_DIR="${PACKER_OUT_DIR:-$BUILD_ROOT/packer}"

# PACKER_TEMPLATE: path to generated QEMU Packer template.
PACKER_TEMPLATE="${PACKER_TEMPLATE:-$PACKER_OUT_DIR/foundrybot-qemu.json}"

# =============================================================================
# ESXi / VMDK export
# =============================================================================

# VMDK_OUTPUT: target VMDK path when exporting BASE_DISK_IMAGE.
VMDK_OUTPUT="${VMDK_OUTPUT:-$BASE_VMDK_IMAGE}"

# =============================================================================
# Enrollment SSH keypair (for WireGuard / cluster enrollment)
# =============================================================================

# ENROLL_KEY_NAME: filename stem for enroll SSH keypair.
ENROLL_KEY_NAME="${ENROLL_KEY_NAME:-enroll_ed25519}"

# ENROLL_KEY_DIR: directory to store enrollment keys under BUILD_ROOT.
ENROLL_KEY_DIR="$BUILD_ROOT/keys"

# ENROLL_KEY_PRIV / ENROLL_KEY_PUB: private/public key paths.
ENROLL_KEY_PRIV="$ENROLL_KEY_DIR/${ENROLL_KEY_NAME}"
ENROLL_KEY_PUB="$ENROLL_KEY_DIR/${ENROLL_KEY_NAME}.pub"

ensure_enroll_keypair() {
  mkdir -p "$ENROLL_KEY_DIR"
  if [[ ! -f "$ENROLL_KEY_PRIV" || ! -f "$ENROLL_KEY_PUB" ]]; then
    log "Generating cluster enrollment SSH keypair in $ENROLL_KEY_DIR"
    ssh-keygen -t ed25519 -N "" -f "$ENROLL_KEY_PRIV" -C "enroll@cluster" >/dev/null
  else
    log "Using existing cluster enrollment keypair in $ENROLL_KEY_DIR"
  fi
}

# =============================================================================
# Tool sanity checks
# =============================================================================

require_cmd xorriso || true
command -v xorriso >/dev/null || { err "xorriso not installed (needed for ISO build)"; }

SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }

log() { echo "[INFO]  $(date '+%F %T') - $*"; }
warn(){ echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err() { echo "[ERROR] $(date '+%F %T') - $*"; }
die(){ err "$*"; exit 1; }

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found in PATH: $cmd"
}

command -v xorriso >/dev/null || { err "xorriso not installed (needed for ISO build)"; }

# =============================================================================
# PROXMOX HELPERS
# =============================================================================

pmx() { sssh root@"$PROXMOX_HOST" "$@"; }

pmx_vm_state() { pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }

pmx_wait_for_state() {
  local vmid="$1" want="$2" timeout="${3:-2400}" start state
  start=$(date +%s)
  log "Waiting for VM $vmid to be $want ..."
  while :; do
    state="$(pmx_vm_state "$vmid")"
    [[ "$state" == "$want" ]] && { log "VM $vmid is $state"; return 0; }
    (( $(date +%s) - start > timeout )) && { err "Timeout: VM $vmid not $want (state=$state)"; return 1; }
    sleep 5
  done
}

pmx_wait_qga() {
  local vmid="$1" timeout="${2:-1200}" start; start=$(date +%s)
  log "Waiting for QEMU Guest Agent on VM $vmid ..."
  while :; do
    if pmx "qm agent $vmid ping >/dev/null 2>&1 || qm guest ping $vmid >/dev/null 2>&1"; then
      log "QGA ready on VM $vmid"; return 0
    fi
    (( $(date +%s) - start > timeout )) && { err "Timeout waiting for QGA on VM $vmid"; return 1; }
    sleep 3
  done
}

pmx_qga_has_json() {
  if [[ "${PMX_QGA_JSON:-}" == "yes" || "${PMX_QGA_JSON:-}" == "no" ]]; then
    echo "$PMX_QGA_JSON"; return
  fi
  PMX_QGA_JSON="$( pmx "qm guest exec -h 2>&1 | grep -q -- '--output-format' && echo yes || echo no" | tr -d '\r' )"
  echo "$PMX_QGA_JSON"
}

pmx_guest_exec() {
  local vmid="$1"; shift
  pmx "qm guest exec $vmid -- $* >/dev/null 2>&1 || true"
}

pmx_guest_cat() {
  local vmid="$1" path="$2"
  local has_json raw pid status outb64 outplain outjson

  has_json="$(pmx_qga_has_json)"

  if [[ "$has_json" == "yes" ]]; then
    raw="$(pmx "qm guest exec $vmid --output-format json -- /bin/cat '$path' 2>/dev/null || true")"
    pid="$(printf '%s\n' "$raw" | sed -n 's/.*\"pid\"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p')"
    [[ -n "$pid" ]] || return 2
    while :; do
      status="$(pmx "qm guest exec-status $vmid $pid --output-format json 2>/dev/null || true")" || true
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

pmx_upload_iso() {
  local iso_file="$1" iso_base
  iso_base="$(basename "$iso_file")"
  sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base" || {
    log "ISO upload retry: $iso_base"; sleep 2
    sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base"
  }
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${iso_base}\" && exit 0; sleep 1; done; exit 1" \
    || warn "pvesm list didn't show ${iso_base} yet—will still try to attach"
  echo "$iso_base"
}

pmx_deploy() {
  local vmid="$1" vmname="$2" iso_file="$3" mem="$4" cores="$5" disk_gb="$6"
  local iso_base
  log "Uploading ISO to Proxmox: $(basename "$iso_file")"
  iso_base="$(pmx_upload_iso "$iso_file")"
  pmx \
    VMID="$vmid" VMNAME="${vmname}.${DOMAIN}-$vmid" FINAL_ISO="$iso_base" \
    VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" \
    DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
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

# UEFI firmware + Secure Boot keys
qm set "$VMID" --bios ovmf
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=1

# TPM 2.0 state
qm set "$VMID" --tpmstate ${VM_STORAGE}:1,version=v2.0,size=4M

# Attach installer ISO
for i in {1..10}; do
  if qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom 2>/dev/null; then
    break
  fi
  sleep 1
done

if ! qm config "$VMID" | grep -q '^ide2:.*media=cdrom'; then
  echo "[X] failed to attach ISO ${FINAL_ISO} from ${ISO_STORAGE}" >&2
  exit 1
fi

qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}

wait_poweroff() { pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }

boot_from_disk() {
  local vmid="$1"
  pmx "qm set $vmid --delete ide2; qm set $vmid --boot order=scsi0; qm start $vmid"
  pmx_wait_for_state "$vmid" "running" 600
}

seed_tmux_conf() {
  : "${ADMIN_USER:=todd}"
  : "${TMUX_CONF:=/etc/skel/.tmux.conf}"

  log "Writing tmux config to ${TMUX_CONF}"
  install -d -m0755 "$(dirname "$TMUX_CONF")"

  cat >"$TMUX_CONF" <<'EOF'
set -g mouse on
set -g history-limit 100000
setw -g mode-keys vi
bind -n C-Space copy-mode
EOF

  # Copy to root and admin user if they exist
  if id root >/dev/null 2>&1; then
    cp -f "$TMUX_CONF" /root/.tmux.conf
  fi
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    cp -f "$TMUX_CONF" "/home/${ADMIN_USER}/.tmux.conf"
    chown "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.tmux.conf"
  fi
}

# =============================================================================
# ISO BUILDER
# =============================================================================

mk_iso() {
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"

  local build="$BUILD_ROOT/$name"
  local mnt="$build/mnt"
  local cust="$build/custom"
  local dark="$cust/darksite"

  rm -rf "$build" 2>/dev/null || true
  mkdir -p "$mnt" "$cust" "$dark"

  (
    set -euo pipefail
    trap 'umount -f "$mnt" 2>/dev/null || true' EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    cp -a "$mnt/"* "$cust/"
    cp -a "$mnt/.disk" "$cust/" 2>/dev/null || true
  )

  # Darksite payload
  install -m0755 "$postinstall_src" "$dark/postinstall.sh"

  cat > "$dark/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (One-time)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/root/darksite/postinstall.sh
ConditionPathExists=!/root/.bootstrap_done

[Service]
Type=oneshot
Environment=SHELL=/bin/bash
ExecStart=/bin/bash -lc '/root/darksite/postinstall.sh'
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  # Seed env
  {
    echo "DOMAIN=${DOMAIN}"
    echo "MASTER_LAN=${MASTER_LAN}"
    echo "WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}"
    echo "GUI_PROFILE=${GUI_PROFILE}"
    echo "WG0_PORT=${WG0_PORT}"
    echo "WG1_PORT=${WG1_PORT}"
    echo "WG2_PORT=${WG2_PORT}"
    echo "WG3_PORT=${WG3_PORT}"
    echo "ALLOW_ADMIN_PASSWORD=${ALLOW_ADMIN_PASSWORD}"
    echo "ADMIN_USER=${ADMIN_USER}"
    echo "INSTALL_ANSIBLE=${INSTALL_ANSIBLE}"
    echo "INSTALL_SEMAPHORE=${INSTALL_SEMAPHORE}"
  } > "$dark/99-provision.conf"

  # Admin authorized key
  local auth_seed="$dark/authorized_keys.${ADMIN_USER}"
  if [[ -n "${SSH_PUBKEY:-}" ]]; then
    printf '%s\n' "$SSH_PUBKEY" > "$auth_seed"
  elif [[ -n "${ADMIN_PUBKEY_FILE:-}" && -r "$ADMIN_PUBKEY_FILE" ]]; then
    cat "$ADMIN_PUBKEY_FILE" > "$auth_seed"
  else
    : > "$auth_seed"
  fi
  chmod 0644 "$auth_seed"

  # Bake in enrollment keypair if present
  if [[ -f "$ENROLL_KEY_PRIV" && -f "$ENROLL_KEY_PUB" ]]; then
    install -m0600 "$ENROLL_KEY_PRIV" "$dark/enroll_ed25519"
    install -m0644 "$ENROLL_KEY_PUB"  "$dark/enroll_ed25519.pub"
  fi
  # Preseed (DHCP vs static)
  local NETBLOCK
  if [[ -z "${static_ip}" ]]; then
    NETBLOCK="d-i netcfg/choose_interface select auto
d-i netcfg/disable_dhcp boolean false
d-i netcfg/get_hostname string ${name}
d-i netcfg/get_domain string ${DOMAIN}"
  else
    NETBLOCK="d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string ${name}
d-i netcfg/get_domain string ${DOMAIN}
d-i netcfg/disable_dhcp boolean true
d-i netcfg/get_ipaddress string ${static_ip}
d-i netcfg/get_netmask string ${NETMASK}
d-i netcfg/get_gateway string ${GATEWAY}
d-i netcfg/get_nameservers string ${NAMESERVER}"
  fi

  cat > "$cust/preseed.cfg" <<EOF
d-i debian-installer/locale string ${PRESEED_LOCALE}
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select ${PRESEED_KEYMAP}
$NETBLOCK
d-i mirror/country string ${PRESEED_MIRROR_COUNTRY}
d-i mirror/http/hostname string ${PRESEED_MIRROR_HOST}
d-i mirror/http/directory string ${PRESEED_MIRROR_DIR}
d-i mirror/http/proxy string ${PRESEED_HTTP_PROXY}
d-i passwd/root-login boolean true
d-i passwd/root-password password ${PRESEED_ROOT_PASSWORD}
d-i passwd/root-password-again password ${PRESEED_ROOT_PASSWORD}
d-i passwd/make-user boolean false
d-i time/zone string ${PRESEED_TIMEZONE}
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true
d-i partman-auto/method string lvm
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman/choose_partition select finish
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto-lvm/guided_size string max
d-i pkgsel/run_tasksel boolean false
d-i pkgsel/include string ${PRESEED_EXTRA_PKGS}
d-i pkgsel/upgrade select none
d-i pkgsel/ignore-recommends boolean true
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string ${PRESEED_BOOTDEV}
d-i preseed/late_command string \
  mkdir -p /target/root/darksite ; \
  cp -a /cdrom/darksite/* /target/root/darksite/ ; \
  in-target chmod +x /root/darksite/postinstall.sh ; \
  in-target cp /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service ; \
  in-target mkdir -p /etc/environment.d ; \
  in-target cp /root/darksite/99-provision.conf /etc/environment.d/99-provision.conf ; \
  in-target chmod 0644 /etc/environment.d/99-provision.conf ; \
  in-target systemctl daemon-reload ; \
  in-target systemctl enable bootstrap.service ; \
  in-target /bin/systemctl --no-block poweroff || true
d-i cdrom-detect/eject boolean true
d-i finish-install/reboot_in_progress note
d-i finish-install/exit-installer boolean true
d-i debian-installer/exit/poweroff boolean true
EOF

  # --- Bootloader patching (BIOS + UEFI) -------------------------------------
  local KARGS="auto=true priority=critical vga=788 preseed/file=/cdrom/preseed.cfg ---"

  # BIOS isolinux menu: add an "auto" preseed entry and make it default
  if [[ -f "$cust/isolinux/txt.cfg" ]]; then
    cat >>"$cust/isolinux/txt.cfg" <<EOF
label auto
  menu label ^auto (preseed)
  kernel /install.amd/vmlinuz
  append initrd=/install.amd/initrd.gz $KARGS
EOF
    sed -i 's/^default .*/default auto/' "$cust/isolinux/isolinux.cfg" || true
  fi

  # Patch *all* GRUB configs that might be used (BIOS + UEFI), and
  # force them to auto-boot entry 0 with a short timeout.
  local cfg
  for cfg in \
    "$cust/boot/grub/grub.cfg" \
    "$cust/boot/grub/x86_64-efi/grub.cfg" \
    "$cust/EFI/boot/grub.cfg"
  do
    [[ -f "$cfg" ]] || continue

    # Ensure default=0
    if grep -q '^set[[:space:]]\+default=' "$cfg"; then
      sed -i 's/^set[[:space:]]\+default.*/set default="0"/' "$cfg" || true
    else
      sed -i '1i set default="0"' "$cfg" || true
    fi

    # Ensure short timeout (1 second)
    if grep -q '^set[[:space:]]\+timeout=' "$cfg"; then
      sed -i 's/^set[[:space:]]\+timeout.*/set timeout=1/' "$cfg" || true
    else
      sed -i '1i set timeout=1' "$cfg" || true
    fi

    # Inject KARGS right after the kernel path
    sed -i "s#^\([[:space:]]*linux[[:space:]]\+\S\+\)#\1 $KARGS#g" "$cfg" || true
  done

  # --- EFI image detection ----------------------------------------------------
  local efi_img=""
  if [[ -f "$cust/boot/grub/efi.img" ]]; then
    efi_img="boot/grub/efi.img"
  elif [[ -f "$cust/efi.img" ]]; then
    efi_img="efi.img"
  fi

  # --- Final ISO (BIOS+UEFI hybrid if possible, else UEFI-only) --------------
  if [[ -f "$cust/isolinux/isolinux.bin" && -f "$cust/isolinux/boot.cat" && -f /usr/share/syslinux/isohdpfx.bin ]]; then
    log "Repacking ISO (BIOS+UEFI hybrid) -> $iso_out"

    if [[ -n "$efi_img" ]]; then
      xorriso -as mkisofs \
        -o "$iso_out" \
        -r -J -joliet-long -l \
        -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot \
        -e "$efi_img" \
        -no-emul-boot -isohybrid-gpt-basdat \
        "$cust"
    else
      xorriso -as mkisofs \
        -o "$iso_out" \
        -r -J -joliet-long -l \
        -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        "$cust"
    fi
  else
    log "No isolinux BIOS bits found; building UEFI-only ISO"
    if [[ -z "$efi_img" ]]; then
      die "EFI image not found in ISO tree - cannot build bootable ISO"
    fi

    xorriso -as mkisofs \
      -o "$iso_out" \
      -r -J -joliet-long -l \
      -eltorito-alt-boot \
      -e "$efi_img" \
      -no-emul-boot -isohybrid-gpt-basdat \
      "$cust"
  fi
}

# =============================================================================
# MASTER POSTINSTALL
# =============================================================================

emit_postinstall_master() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/postinstall-master.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

# Load seed environment if present (from mk_iso)
if [ -r /etc/environment.d/99-provision.conf ]; then
  # shellcheck disable=SC2046
  export $(grep -E '^[A-Z0-9_]+=' /etc/environment.d/99-provision.conf | xargs -d'\n' || true)
fi

# ---------- Defaults (if not seeded) ----------
DOMAIN="${DOMAIN:-unixbox.net}"

MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"

WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

ADMIN_USER="${ADMIN_USER:-todd}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-yes}"   # yes|try|no

HUB_NAME="${HUB_NAME:-master}"

# ---------- Helpers ----------
ensure_base() {
  log "Configuring APT & base system packages"
  export DEBIAN_FRONTEND=noninteractive

  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF

  for i in 1 2 3; do
    if apt-get update -y; then break; fi
    sleep $((i*3))
  done

  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq xxd unzip tar \
    iproute2 iputils-ping net-tools \
    nftables wireguard-tools \
    python3-venv python3-pip python3-bpfcc python3-psutil \
    libbpfcc llvm libclang-cpp* \
    chrony rsyslog qemu-guest-agent vim || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true

  # Use python3 -m pip so we don’t care about pip vs pip3 name
  if command -v python3 >/dev/null; then
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    python3 -m pip install dnspython requests cryptography pyOpenSSL || true
  fi

  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true

  cat >/etc/sysctl.d/99-master.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF

  sysctl --system || true
}

ensure_users(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"

  mk(){ local u="$1" k="$2";
    id -u "$u" &>/dev/null || useradd -m -s /bin/bash "$u";
    install -d -m700 -o "$u" -g "$u" "/home/$u/.ssh";
    touch "/home/$u/.ssh/authorized_keys"; chmod 600 "/home/$u/.ssh/authorized_keys"
    chown -R "$u:$u" "/home/$u/.ssh"
    [[ -n "$k" ]] && grep -qxF "$k" "/home/$u/.ssh/authorized_keys" || {
      [[ -n "$k" ]] && printf '%s\n' "$k" >> "/home/$u/.ssh/authorized_keys"
    }
    install -d -m755 /etc/sudoers.d
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$u" >"/etc/sudoers.d/90-$u"
    chmod 0440 "/etc/sudoers.d/90-$u"
  }

  mk "$ADMIN_USER" "$PUB"

  # ansible service user
  id -u ansible &>/dev/null || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || \
    runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys
  chmod 600 /home/ansible/.ssh/authorized_keys

  # Allow the cluster enrollment key to log in as ADMIN_USER
  local ENROLL_PUB_SRC="/root/darksite/enroll_ed25519.pub"
  if [[ -s "$ENROLL_PUB_SRC" ]]; then
    local ENROLL_PUB
    ENROLL_PUB="$(head -n1 "$ENROLL_PUB_SRC")"
    if ! grep -qxF "$ENROLL_PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys"; then
      printf '%s\n' "$ENROLL_PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"
    fi
  fi

  # Backplane is wg1
  local BACKPLANE_IF="wg1"
  local BACKPLANE_IP="${WG1_IP%/*}"

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress ${MASTER_LAN}
ListenAddress ${BACKPLANE_IP}
AllowUsers ${ADMIN_USER} ansible
EOF

  cat >/etc/ssh/sshd_config.d/99-hard.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

  if [ "${ALLOW_ADMIN_PASSWORD}" = "yes" ]; then
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi

  install -d -m755 /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  (sshd -t && systemctl daemon-reload && systemctl restart ssh) || true
}

wg_setup_planes() {
  log "Configuring WireGuard planes (wg0 reserved, wg1/wg2/wg3 active)"

  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077

  # Generate keys once per interface if missing
  local ifn
  for ifn in wg0 wg1 wg2 wg3; do
    [ -f "/etc/wireguard/${ifn}.key" ] || wg genkey | tee "/etc/wireguard/${ifn}.key" | wg pubkey >"/etc/wireguard/${ifn}.pub"
  done

  # wg0: reserved, NOT started (future use / extra plane)
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${WG0_IP}
PrivateKey = $(cat /etc/wireguard/wg0.key)
ListenPort = ${WG0_PORT}
MTU        = 1420
EOF

  # wg1: Ansible / SSH plane
  cat >/etc/wireguard/wg1.conf <<EOF
[Interface]
Address    = ${WG1_IP}
PrivateKey = $(cat /etc/wireguard/wg1.key)
ListenPort = ${WG1_PORT}
MTU        = 1420
EOF

  # wg2: Metrics plane
  cat >/etc/wireguard/wg2.conf <<EOF
[Interface]
Address    = ${WG2_IP}
PrivateKey = $(cat /etc/wireguard/wg2.key)
ListenPort = ${WG2_PORT}
MTU        = 1420
EOF

  # wg3: K8s backend plane
  cat >/etc/wireguard/wg3.conf <<EOF
[Interface]
Address    = ${WG3_IP}
PrivateKey = $(cat /etc/wireguard/wg3.key)
ListenPort = ${WG3_PORT}
MTU        = 1420
EOF

  chmod 600 /etc/wireguard/*.conf
  umask "$_old_umask"

  systemctl daemon-reload || true
  systemctl enable --now wg-quick@wg1 || true
  systemctl enable --now wg-quick@wg2 || true
  systemctl enable --now wg-quick@wg3 || true
  # NOTE: wg0 is intentionally NOT enabled
}

nft_firewall() {
  # Try to detect the primary LAN interface (fallback to ens18 if we can't)
  local lan_if
  lan_if="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')" || true
  : "${lan_if:=ens18}"

  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Basic sanity
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept

    # SSH + RDP
    tcp dport 22 accept
    tcp dport 3389 accept

    # WireGuard ports
    udp dport { ${WG0_PORT}, ${WG1_PORT}, ${WG2_PORT}, ${WG3_PORT} } accept

    # Allow traffic arriving over the WG planes
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept

    # Allow WG planes to reach the LAN, and replies back
    iifname "wg1" oifname "${lan_if}" accept
    iifname "wg2" oifname "${lan_if}" accept
    iifname "wg3" oifname "${lan_if}" accept

    iifname "${lan_if}" oifname "wg1" accept
    iifname "${lan_if}" oifname "wg2" accept
    iifname "${lan_if}" oifname "wg3" accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;

    # Masquerade anything leaving via the LAN interface
    oifname "${lan_if}" masquerade
  }
}
EOF

  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

helper_tools() {
  log "Installing wg-add-peer, wg-enrollment, register-minion helpers"

  # wg-add-peer: generic, used for wg1/wg2/wg3 (wg0 if ever needed)
  cat >/usr/local/sbin/wg-add-peer <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFN="${3:-wg1}"
PUB="${1:-}"
ADDR="${2:-}"
FLAG="/srv/wg/ENROLL_ENABLED"

if [[ ! -f "$FLAG" ]]; then
  echo "[X] enrollment closed" >&2
  exit 2
fi
if [[ -z "$PUB" || -z "$ADDR" ]]; then
  echo "usage: wg-add-peer <pubkey> <ip/cidr> [ifname]" >&2
  exit 1
fi

if wg show "$IFN" peers 2>/dev/null | grep -qx "$PUB"; then
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR"
else
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR" persistent-keepalive 25
fi

CONF="/etc/wireguard/${IFN}.conf"
if ! grep -q "$PUB" "$CONF"; then
  printf "\n[Peer]\nPublicKey  = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n" "$PUB" "$ADDR" >> "$CONF"
fi

systemctl reload "wg-quick@${IFN}" 2>/dev/null || true

# TODO: XDP/eBPF hook:
#  - update an eBPF map with peer->plane info here for fast dataplane decisions.

echo "[+] added $PUB $ADDR on $IFN"
EOF
  chmod 0755 /usr/local/sbin/wg-add-peer

  # wg-enrollment: toggle ENROLL_ENABLED flag
  cat >/usr/local/sbin/wg-enrollment <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FLAG="/srv/wg/ENROLL_ENABLED"
case "${1:-}" in
  on)  : >"$FLAG"; echo "enrollment enabled";;
  off) rm -f "$FLAG"; echo "enrollment disabled";;
  *)   echo "usage: wg-enrollment on|off" >&2; exit 1;;
esac
EOF
  chmod 0755 /usr/local/sbin/wg-enrollment

  # register-minion:
  cat >/usr/local/sbin/register-minion <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

GROUP="${1:-}"
HOST="${2:-}"
IP="${3:-}"        # metrics (wg2) IP, port 9100

if [[ -z "$GROUP" || -z "$HOST" || -z "$IP" ]]; then
  echo "usage: $0 <group> <hostname> <metrics-ip>" >&2
  exit 2
fi

ANS_HOSTS="/etc/ansible/hosts"
PROM_DIR="/etc/prometheus/targets.d"
PROM_TGT="${PROM_DIR}/${GROUP}.json"

mkdir -p "$(dirname "$ANS_HOSTS")" "$PROM_DIR"
touch "$ANS_HOSTS"

# Ansible inventory: we use IP as ansible_host for now.
if ! grep -q "^\[${GROUP}\]" "$ANS_HOSTS"; then
  printf "\n[%s]\n" "$GROUP" >> "$ANS_HOSTS"
fi
sed -i "/^${HOST}\b/d" "$ANS_HOSTS"
printf "%s ansible_host=%s\n" "$HOST" "$IP" >> "$ANS_HOSTS"

# Prometheus file_sd target for node_exporter (fixed port 9100)
if [[ ! -s "$PROM_TGT" ]]; then
  echo '[]' > "$PROM_TGT"
fi

tmp="$(mktemp)"
jq --arg target "${IP}:9100" '
  map(select(.targets|index($target)|not)) + [{"targets":[$target]}]
' "$PROM_TGT" > "$tmp" && mv "$tmp" "$PROM_TGT"

if pidof prometheus >/dev/null 2>&1; then
  pkill -HUP prometheus || systemctl reload prometheus || true
fi

echo "[OK] Registered ${HOST} (${IP}) in group ${GROUP}"
EOF
  chmod 0755 /usr/local/sbin/register-minion
}

# -----------------------------------------------------------------------------
salt_master_stack() {
  log "Installing and configuring Salt master on LAN"

  install -d -m0755 /etc/apt/keyrings

  # Salt Broadcom repo
  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public \
    -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp \
    >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.gpg || true

  cat >/etc/apt/sources.list.d/salt.sources <<'EOF'
Types: deb
URIs: https://packages.broadcom.com/artifactory/saltproject-deb
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/salt-archive-keyring.pgp
EOF

  cat >/etc/apt/preferences.d/salt-pin-1001 <<'EOF'
Package: salt-*
Pin: version 3006.*
Pin-Priority: 1001
EOF

  apt-get update -y || true
  apt-get install -y --no-install-recommends salt-master salt-api salt-common || true

  cat >/etc/salt/master.d/network.conf <<EOF
interface: ${MASTER_LAN}
ipv6: False
publish_port: 4505
ret_port: 4506
EOF

  # For now we keep salt-api without TLS to simplify; harden later.
  cat >/etc/salt/master.d/api.conf <<EOF
rest_cherrypy:
  host: ${MASTER_LAN}
  port: 8000
  disable_ssl: True
EOF

  cat >/etc/salt/master.d/bootstrap-autoaccept.conf <<'EOF'
auto_accept: True
EOF

  cat >/etc/salt/master.d/roots.conf <<'EOF'
file_roots:
  base:
    - /srv/salt

pillar_roots:
  base:
    - /srv/pillar
EOF

  install -d -m0755 /etc/systemd/system/salt-master.service.d
  cat >/etc/systemd/system/salt-master.service.d/wg-order.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF

  systemctl daemon-reload
  systemctl enable --now salt-master salt-api || true
}

# -----------------------------------------------------------------------------
pillars_and_states_seed() {
  log "Seeding minimal /srv/pillar and /srv/salt skeleton"

  # ---------------------------------------------------------------------------
  # Ensure directory skeleton exists *before* any redirections
  # ---------------------------------------------------------------------------
  install -d -m0755 /srv/pillar
  install -d -m0755 /srv/salt
  install -d -m0755 /srv/salt/common
  install -d -m0755 /srv/salt/roles

  # ---------------------------------------------------------------------------
  # Normalise cluster layout variables (protect against set -u)
  # ---------------------------------------------------------------------------
  : "${DOMAIN:=unixbox.net}"
  : "${MASTER_LAN:=10.100.10.224}"

  : "${K8SLB1_NAME:=k8s-lb1}"
  : "${K8SLB1_IP:=10.100.10.213}"
  : "${K8SLB2_NAME:=k8s-lb2}"
  : "${K8SLB2_IP:=10.100.10.212}"

  : "${K8SCP1_NAME:=k8s-cp1}"
  : "${K8SCP1_IP:=10.100.10.219}"
  : "${K8SCP2_NAME:=k8s-cp2}"
  : "${K8SCP2_IP:=10.100.10.218}"
  : "${K8SCP3_NAME:=k8s-cp3}"
  : "${K8SCP3_IP:=10.100.10.217}"

  : "${K8SW1_NAME:=k8s-w1}"
  : "${K8SW1_IP:=10.100.10.216}"
  : "${K8SW2_NAME:=k8s-w2}"
  : "${K8SW2_IP:=10.100.10.215}"
  : "${K8SW3_NAME:=k8s-w3}"
  : "${K8SW3_IP:=10.100.10.214}"

  # ---------------------------------------------------------------------------
  # Pillar: top.sls
  # ---------------------------------------------------------------------------
  cat >/srv/pillar/top.sls <<'EOF'
base:
  '*':
    - cluster
EOF

  # ---------------------------------------------------------------------------
  # Pillar: cluster layout (domain, master, and full K8s node map)
  # ---------------------------------------------------------------------------
  cat >/srv/pillar/cluster.sls <<EOF
cluster:
  domain: ${DOMAIN}

  master:
    id: master
    lan_ip: ${MASTER_LAN}
    wg:
      wg1: ${WG1_IP}

  k8s:
    # VIP / primary LB address for API (you can change this to an actual VIP later)
    api_vip: ${K8SLB1_IP}

    lbs:
      - name: ${K8SLB1_NAME}
        ip: ${K8SLB1_IP}
      - name: ${K8SLB2_NAME}
        ip: ${K8SLB2_IP}

    control_planes:
      - name: ${K8SCP1_NAME}
        ip: ${K8SCP1_IP}
      - name: ${K8SCP2_NAME}
        ip: ${K8SCP2_IP}
      - name: ${K8SCP3_NAME}
        ip: ${K8SCP3_IP}

    workers:
      - name: ${K8SW1_NAME}
        ip: ${K8SW1_IP}
      - name: ${K8SW2_NAME}
        ip: ${K8SW2_IP}
      - name: ${K8SW3_NAME}
        ip: ${K8SW3_IP}

    # Defaults for kubeadm / CNI; your post-install (apply.py) can read/override these.
    version_minor: "v1.34"
    pod_subnet: "10.244.0.0/16"
    service_subnet: "10.96.0.0/12"
EOF

  log "Seeding /srv/pillar and /srv/salt tree"

  # ---------------------------------------------------------------------------
  # /srv/salt/top.sls → role-based mapping
  # ---------------------------------------------------------------------------
  cat >/srv/salt/top.sls <<'EOF'
base:
  'role:graf':
    - match: grain
    - roles.grafana

  'role:prometheus':
    - match: grain
    - roles.prometheus

  'role:storage':
    - match: grain
    - roles.storage

  # Optional K8s admin/jumphost
  'role:k8s':
    - match: grain
    - roles.k8s_admin

  # HAProxy API load balancers
  'role:k8s-lb':
    - match: grain
    - roles.k8s_lb

  # Kubernetes control plane nodes
  'role:k8s-cp':
    - match: grain
    - roles.k8s_control_plane
    - roles.k8s_flannel

  # Kubernetes workers
  'role:k8s-worker':
    - match: grain
    - roles.k8s_worker
EOF

  # ---------------------------------------------------------------------------
  # common/baseline.sls (basic tools)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/common/baseline.sls <<'EOF'
common-baseline:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - vim-tiny
      - jq
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_admin.sls  (K8s toolbox/jumphost)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_admin.sls <<'EOF'
# Kubernetes admin / toolbox node for Debian 13

{% set k8s = pillar.get('cluster', {}).get('k8s', {}) %}
{% set k8s_minor = k8s.get('version_minor', 'v1.34') %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

k8s-admin-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
      - jq
      - git

k8s-admin-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-admin-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-admin-keyrings-dir
      - pkg: k8s-admin-prereqs

k8s-admin-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/kubernetes.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] {{ k8s_repo_url }} /
    - require:
      - cmd: k8s-admin-apt-keyring

# Helm repo
k8s-admin-helm-keyring:
  cmd.run:
    - name: >
        curl -fsSL https://baltocdn.com/helm/signing.asc
        | gpg --dearmor -o /etc/apt/keyrings/helm.gpg
    - creates: /etc/apt/keyrings/helm.gpg
    - require:
      - pkg: k8s-admin-prereqs

k8s-admin-helm-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/helm-stable-debian.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main
    - require:
      - cmd: k8s-admin-helm-keyring

k8s-admin-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-admin-apt-repo
      - file: k8s-admin-helm-repo

k8s-admin-tools:
  pkg.installed:
    - pkgs:
      - kubectl
      - helm
    - require:
      - cmd: k8s-admin-apt-update
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_control_plane.sls  (K8s control-plane prerequisites)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_control_plane.sls <<'EOF'
# Kubernetes control-plane node role for Debian 13

{% set k8s = pillar.get('cluster', {}).get('k8s', {}) %}
{% set k8s_minor = k8s.get('version_minor', 'v1.34') %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

# APT prerequisites
k8s-cp-prereqs:
  pkg.installed:
    - pkgs:
      - apt-transport-https
      - ca-certificates
      - curl
      - gpg
      - gnupg
      - lsb-release

# Disable swap
k8s-cp-swapoff-fstab:
  file.replace:
    - name: /etc/fstab
    - pattern: '^\S+\s+\S+\s+swap\s+\S+'
    - repl: '# \0'
    - flags:
      - MULTILINE
    - append_if_not_found: False

k8s-cp-swapoff-runtime:
  cmd.run:
    - name: swapoff -a
    - require:
      - file: k8s-cp-swapoff-fstab

# Kernel modules
k8s-cp-modules-load-config:
  file.managed:
    - name: /etc/modules-load.d/k8s.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        overlay
        br_netfilter

k8s-cp-modules-load-now:
  cmd.run:
    - name: |
        modprobe overlay || true
        modprobe br_netfilter || true
    - onchanges:
      - file: k8s-cp-modules-load-config

# Sysctl
k8s-cp-sysctl-config:
  file.managed:
    - name: /etc/sysctl.d/99-kubernetes.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        net.bridge.bridge-nf-call-iptables  = 1
        net.bridge.bridge-nf-call-ip6tables = 1
        net.ipv4.ip_forward                 = 1

k8s-cp-sysctl-apply:
  cmd.run:
    - name: sysctl --system
    - onchanges:
      - file: k8s-cp-sysctl-config

# Kubernetes repo
k8s-cp-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-cp-apt-keyring-deps:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
    - require:
      - pkg: k8s-cp-prereqs

k8s-cp-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-cp-keyrings-dir
      - pkg: k8s-cp-apt-keyring-deps

k8s-cp-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/kubernetes.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] {{ k8s_repo_url }} /
    - require:
      - cmd: k8s-cp-apt-keyring

k8s-cp-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-cp-apt-repo

# containerd
k8s-cp-containerd-pkg:
  pkg.installed:
    - name: containerd
    - require:
      - cmd: k8s-cp-apt-update

k8s-cp-containerd-config-default:
  cmd.run:
    - name: "containerd config default > /etc/containerd/config.toml"
    - creates: /etc/containerd/config.toml
    - require:
      - pkg: k8s-cp-containerd-pkg

k8s-cp-containerd-systemdcgroup:
  file.replace:
    - name: /etc/containerd/config.toml
    - pattern: 'SystemdCgroup = false'
    - repl: 'SystemdCgroup = true'
    - require:
      - cmd: k8s-cp-containerd-config-default

k8s-cp-containerd-service:
  service.running:
    - name: containerd
    - enable: True
    - require:
      - file: k8s-cp-containerd-systemdcgroup

# Kubernetes packages
k8s-cp-packages:
  pkg.installed:
    - pkgs:
      - kubelet
      - kubeadm
      - kubectl
    - require:
      - cmd: k8s-cp-apt-update
      - pkg: k8s-cp-containerd-pkg

k8s-cp-packages-hold:
  cmd.run:
    - name: apt-mark hold kubelet kubeadm kubectl
    - unless: dpkg -l | awk '/kubelet|kubeadm|kubectl/ && /hold/ {found=1} END {exit !found}'
    - require:
      - pkg: k8s-cp-packages

k8s-cp-kubelet-service:
  service.running:
    - name: kubelet
    - enable: True
    - require:
      - pkg: k8s-cp-packages
      - service: k8s-cp-containerd-service
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_worker.sls  (K8s worker prerequisites)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_worker.sls <<'EOF'
# Kubernetes worker node role for Debian 13

{% set k8s = pillar.get('cluster', {}).get('k8s', {}) %}
{% set k8s_minor = k8s.get('version_minor', 'v1.34') %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

k8s-worker-prereqs:
  pkg.installed:
    - pkgs:
      - apt-transport-https
      - ca-certificates
      - curl
      - gpg
      - gnupg
      - lsb-release

k8s-swapoff-fstab:
  file.replace:
    - name: /etc/fstab
    - pattern: '^\S+\s+\S+\s+swap\s+\S+'
    - repl: '# \0'
    - flags:
      - MULTILINE
    - append_if_not_found: False

k8s-swapoff-runtime:
  cmd.run:
    - name: swapoff -a
    - require:
      - file: k8s-swapoff-fstab

k8s-modules-load-config:
  file.managed:
    - name: /etc/modules-load.d/k8s.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        overlay
        br_netfilter

k8s-modules-load-now:
  cmd.run:
    - name: |
        modprobe overlay || true
        modprobe br_netfilter || true
    - onchanges:
      - file: k8s-modules-load-config

k8s-sysctl-config:
  file.managed:
    - name: /etc/sysctl.d/99-kubernetes.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        net.bridge.bridge-nf-call-iptables  = 1
        net.bridge.bridge-nf-call-ip6tables = 1
        net.ipv4.ip_forward                 = 1

k8s-sysctl-apply:
  cmd.run:
    - name: sysctl --system
    - onchanges:
      - file: k8s-sysctl-config

k8s-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-apt-keyring-deps:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
    - require:
      - pkg: k8s-worker-prereqs

k8s-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-keyrings-dir
      - pkg: k8s-apt-keyring-deps

k8s-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/kubernetes.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] {{ k8s_repo_url }} /
    - require:
      - cmd: k8s-apt-keyring

k8s-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-apt-repo

k8s-containerd-pkg:
  pkg.installed:
    - name: containerd
    - require:
      - cmd: k8s-apt-update

k8s-containerd-config-default:
  cmd.run:
    - name: "containerd config default > /etc/containerd/config.toml"
    - creates: /etc/containerd/config.toml
    - require:
      - pkg: k8s-containerd-pkg

k8s-containerd-systemdcgroup:
  file.replace:
    - name: /etc/containerd/config.toml
    - pattern: 'SystemdCgroup = false'
    - repl: 'SystemdCgroup = true'
    - require:
      - cmd: k8s-containerd-config-default

k8s-containerd-service:
  service.running:
    - name: containerd
    - enable: True
    - require:
      - pkg: k8s-containerd-pkg
      - file: k8s-containerd-systemdcgroup

k8s-worker-packages:
  pkg.installed:
    - pkgs:
      - kubelet
      - kubeadm
      - kubectl
    - require:
      - cmd: k8s-apt-update
      - pkg: k8s-containerd-pkg

k8s-worker-packages-hold:
  cmd.run:
    - name: apt-mark hold kubelet kubeadm kubectl
    - unless: dpkg -l | awk '/kubelet|kubeadm|kubectl/ && /hold/ {found=1} END {exit !found}'
    - require:
      - pkg: k8s-worker-packages

k8s-kubelet-service:
  service.running:
    - name: kubelet
    - enable: True
    - require:
      - pkg: k8s-worker-packages
      - service: k8s-containerd-service
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_lb.sls  (HAProxy for K8s API – pillar-driven)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_lb.sls <<'EOF'
# Kubernetes API load balancer (HAProxy) for Debian 13

{% set cluster = pillar.get('cluster', {}) %}
{% set domain = cluster.get('domain', 'cluster.local') %}
{% set k8s = cluster.get('k8s', {}) %}
{% set control_planes = k8s.get('control_planes', []) %}

k8s-lb-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl

k8s-lb-haproxy-pkg:
  pkg.installed:
    - name: haproxy
    - require:
      - pkg: k8s-lb-prereqs

k8s-lb-haproxy-config:
  file.managed:
    - name: /etc/haproxy/haproxy.cfg
    - mode: '0644'
    - user: root
    - group: root
    - require:
      - pkg: k8s-lb-haproxy-pkg
    - contents: |
        global
          log /dev/log  local0
          log /dev/log  local1 notice
          daemon
          maxconn 4096

        defaults
          log     global
          mode    tcp
          option  tcplog
          option  dontlognull
          retries 3
          timeout connect 5s
          timeout client  300s
          timeout server  300s

        frontend k8s_api
          bind *:6443
          default_backend k8s_api_backend

        backend k8s_api_backend
          balance roundrobin
          option tcp-check
          default-server inter 10s fall 3 rise 2
{% for cp in control_planes %}
          server {{ cp.name }} {{ cp.ip }}:6443 check
{% endfor %}
  # If control_planes is empty, backend will be empty until pillar is updated.

k8s-lb-haproxy-service:
  service.running:
    - name: haproxy
    - enable: True
    - require:
      - file: k8s-lb-haproxy-config
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_flannel.sls (CNI from upstream manifest)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_flannel.sls <<'EOF'
# Flannel CNI deployment for Kubernetes

k8s-flannel-apply:
  cmd.run:
    - name: |
        export KUBECONFIG=/etc/kubernetes/admin.conf
        kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
    - onlyif: test -f /etc/kubernetes/admin.conf
    - unless: |
        export KUBECONFIG=/etc/kubernetes/admin.conf
        kubectl get daemonset -n kube-flannel kube-flannel -o jsonpath='{.status.numberReady}' 2>/dev/null \
          | grep -Eq '^[1-9]'
EOF
}

ansible_stack() {
  if [ "${INSTALL_ANSIBLE}" != "yes" ]; then
    log "INSTALL_ANSIBLE != yes; skipping Ansible stack"
    return 0
  fi

  log "Installing Ansible and base config"
  apt-get install -y --no-install-recommends ansible || true

  install -d -m0755 /etc/ansible

  cat >/etc/ansible/ansible.cfg <<EOF
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
forks = 50
timeout = 30
remote_user = ansible
# We'll use WireGuard plane (wg1) IPs for ansible_host where possible.
EOF

  touch /etc/ansible/hosts
}

semaphore_stack() {
  if [ "${INSTALL_SEMAPHORE}" = "no" ]; then
    log "INSTALL_SEMAPHORE=no; skipping Semaphore"
    return 0
  fi

  log "Installing Semaphore (Ansible UI) - best effort"

  local WG1_ADDR
  WG1_ADDR="$(echo "$WG1_IP" | cut -d/ -f1)"

  install -d -m755 /etc/semaphore

  if curl -fsSL -o /usr/local/bin/semaphore \
      https://github.com/ansible-semaphore/semaphore/releases/latest/download/semaphore_linux_amd64; then
    chmod +x /usr/local/bin/semaphore

    cat >/etc/systemd/system/semaphore.service <<EOF
[Unit]
Description=Ansible Semaphore
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target

[Service]
ExecStart=/usr/local/bin/semaphore server --listen ${WG1_ADDR}:3000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now semaphore || true
  else
    log "WARNING: Failed to fetch Semaphore binary; skipping UI."
  fi
}

hub_seed() {
  log "Seeding /srv/wg/hub.env with master WireGuard metadata"

  mkdir -p /srv/wg

  # Read master public keys (created in wg_setup_planes)
  local wg0_pub wg1_pub wg2_pub wg3_pub
  [ -r /etc/wireguard/wg0.pub ] && wg0_pub="$(cat /etc/wireguard/wg0.pub)" || wg0_pub=""
  [ -r /etc/wireguard/wg1.pub ] && wg1_pub="$(cat /etc/wireguard/wg1.pub)" || wg1_pub=""
  [ -r /etc/wireguard/wg2.pub ] && wg2_pub="$(cat /etc/wireguard/wg2.pub)" || wg2_pub=""
  [ -r /etc/wireguard/wg3.pub ] && wg3_pub="$(cat /etc/wireguard/wg3.pub)" || wg3_pub=""

  cat >/srv/wg/hub.env <<EOF
# Master WireGuard Hub metadata – AUTOGENERATED
HUB_NAME=${HUB_NAME}

# This is the IP that minions should use as endpoint for the hub:
HUB_LAN=${MASTER_LAN}
HUB_LAN_GW=10.100.10.1

# High-level WG plane nets
HUB_WG1_NET=10.78.0.0/16    # control/SSH plane
HUB_WG2_NET=10.79.0.0/16    # metrics/prom/graf plane
HUB_WG3_NET=10.80.0.0/16    # k8s/backplane

# Master interface addresses (same values as wg_setup_planes)
WG0_IP=${WG0_IP}
WG1_IP=${WG1_IP}
WG2_IP=${WG2_IP}
WG3_IP=${WG3_IP}

# Master listen ports
WG0_PORT=${WG0_PORT}
WG1_PORT=${WG1_PORT}
WG2_PORT=${WG2_PORT}
WG3_PORT=${WG3_PORT}

# Global allowed CIDR across planes
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}

# Master public keys
WG0_PUB=${wg0_pub}
WG1_PUB=${wg1_pub}
WG2_PUB=${wg2_pub}
WG3_PUB=${wg3_pub}
EOF

  chmod 0644 /srv/wg/hub.env

  mkdir -p /srv/wg/peers
  cat >/srv/wg/README.md <<'EOF'
This directory holds WireGuard hub configuration and enrolled peers.

  * hub.env   – top-level metadata about this hub (IPs, ports, pubkeys)
  * peers/    – per-peer JSON/YAML/whatever we decide later

EOF
}

configure_salt_master_network() {
  echo "[*] Configuring Salt master bind addresses..."

  install -d -m 0755 /etc/salt/master.d

  cat >/etc/salt/master.d/network.conf <<'EOF'
# Bind Salt master on all IPv4 addresses so it’s reachable via:
#  - Public IP
#  - 10.100.x LAN
#  - 10.78.x WireGuard control plane
interface: 0.0.0.0
ipv6: False

# Standard Salt ports
publish_port: 4505
ret_port: 4506
EOF

  systemctl enable --now salt-master salt-api || true
}

configure_nftables_master() {
  echo "[*] Writing /etc/nftables.conf for master..."

  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Allow established/related
    ct state established,related accept

    # Loopback
    iifname "lo" accept

    # Basic ICMP
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    #################################################################
    # SSH (public, LAN, and over WireGuard)
    #################################################################
    tcp dport 22 accept

    #################################################################
    # Salt master (publisher 4505, return 4506)
    # Accessible via:
    #  - public IP
    #  - LAN (10.100.10.0/24)
    #  - WG control plane (10.78.0.0/16)
    #
    # If you want to tighten this later, you can add ip saddr filters.
    #################################################################
    tcp dport { 4505, 4506 } accept

    #################################################################
    # WireGuard UDP ports
    #################################################################
    udp dport { 51820, 51821, 51822, 51823 } accept

    #################################################################
    # Allow all traffic arriving from the WG planes
    # (wg0 = VPN, wg1 = control, wg2 = metrics, wg3 = backup, etc.)
    #################################################################
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept

    #################################################################
    # Default-drop everything else
    #################################################################
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    # Allow forwarding between WG planes and LAN if desired.
    # You can refine this later with explicit rules.
    ct state established,related accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

  chmod 600 /etc/nftables.conf

  # Enable + apply
  systemctl enable nftables || true
  nft -f /etc/nftables.conf
}

# -----------------------------------------------------------------------------
write_bashrc() {
  log "Writing clean .bashrc for all users (via /etc/skel)..."

  local BASHRC=/etc/skel/.bashrc

  cat > "$BASHRC" <<'EOF'
# ~/.bashrc - foundryBot cluster console

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# -------------------------------------------------------------------
# History, shell options, basic prompt
# -------------------------------------------------------------------
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT='%F %T '
HISTCONTROL=ignoredups:erasedups

shopt -s histappend
shopt -s checkwinsize
shopt -s cdspell

# Basic prompt (will be overridden below with colorized variant)
PS1='\u@\h:\w\$ '

# -------------------------------------------------------------------
# Banner
# -------------------------------------------------------------------
fb_banner() {
  cat << 'FBBANNER'
   ___                           __                  ______          __
 /'___\                         /\ \                /\     \        /\ \__
/\ \__/  ___   __  __    ___    \_\ \  _ __   __  __\ \ \L\ \    ___\ \ ,_\
\ \ ,__\/ __`\/\ \/\ \ /' _ `\  /'_` \/\`'__\/\ \/\ \\ \  _ <'  / __`\ \ \/
 \ \ \_/\ \L\ \ \ \_\ \/\ \/\ \/\ \L\ \ \ \/ \ \ \_\ \\ \ \L\ \/\ \L\ \ \ \_
  \ \_\\ \____/\ \____/\ \_\ \_\ \___,_\ \_\  \/`____ \\ \____/\ \____/\ \__\
   \/_/ \/___/  \/___/  \/_/\/_/\/__,_ /\/_/   `/___/> \\/___/  \/___/  \/__/
                                                  /\___/
                                                  \/__/
           secure cluster deploy & control

FBBANNER
}

# Only show once per interactive session
if [ -z "$FBNOBANNER" ]; then
  fb_banner
  export FBNOBANNER=1
fi

# -------------------------------------------------------------------
# Colorized prompt (root vs non-root)
# -------------------------------------------------------------------
if [ "$EUID" -eq 0 ]; then
  PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
else
  PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi

# -------------------------------------------------------------------
# Bash completion
# -------------------------------------------------------------------
if [ -f /etc/bash_completion ]; then
  # shellcheck source=/etc/bash_completion
  . /etc/bash_completion
fi

# -------------------------------------------------------------------
# Basic quality-of-life aliases
# -------------------------------------------------------------------
alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'

alias ls='ls --color=auto'
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias e='${EDITOR:-vim}'
alias vi='vim'

# Net & disk helpers
alias ports='ss -tuln'
alias df='df -h'
alias du='du -h'
alias tk='tmux kill-server'

# -------------------------------------------------------------------
# Salt cluster helper commands
# -------------------------------------------------------------------

# Wide minion list as a table
slist() {
  salt --static --no-color --out=json --out-indent=-1 "*" \
    grains.item host os osrelease ipv4 num_cpus mem_total roles \
  | jq -r '
      to_entries[]
      | .key as $id
      | .value as $v
      | ($v.ipv4 // []
         | map(select(. != "127.0.0.1" and . != "0.0.0.0"))
         | join("  ")) as $ips
      | [
          $id,
          $v.host,
          ($v.os + " " + $v.osrelease),
          $ips,
          $v.num_cpus,
          $v.mem_total,
          ($v.roles // "")
        ]
      | @tsv
    ' \
  | sort -k1,1
}

sping()      { salt "*" test.ping; }
ssall()      { salt "*" cmd.run 'ss -tnlp || netstat -tnlp'; }
skservices() { salt "*" service.status kubelet containerd; }
sdfall()     { salt "*" cmd.run 'df -hT --exclude-type=tmpfs --exclude-type=devtmpfs'; }
stop5()      { salt "*" cmd.run 'ps aux --sort=-%cpu | head -n 5'; }
smem5()      { salt "*" cmd.run 'ps aux --sort=-%mem | head -n 5'; }

skvers() {
  echo "== kubelet versions =="
  salt "*" cmd.run 'kubelet --version 2>/dev/null || echo no-kubelet'
  echo
  echo "== kubectl client versions =="
  salt "*" cmd.run 'kubectl version --client --short 2>/dev/null || echo no-kubectl'
}

# "World" apply helpers – tweak state names to your liking
fb_world() {
  echo "Applying 'world' state to all minions..."
  salt "*" state.apply world
}

fb_k8s_cluster() {
  echo "Applying 'k8s.cluster' to role:k8s_cp and role:k8s_worker..."
  salt -C 'G@role:k8s_cp or G@role:k8s_worker' state.apply k8s.cluster
}
# -------------------------------------------------------------------
# Kubernetes helper commands (Salt-powered via role:k8s_cp)
# -------------------------------------------------------------------

# Core cluster info
skcls()   { salt -G "role:k8s_cp" cmd.run 'kubectl cluster-info'; }
sknodes() { salt -G "role:k8s_cp" cmd.run 'kubectl get nodes -o wide'; }
skpods()  { salt -G "role:k8s_cp" cmd.run 'kubectl get pods -A -o wide'; }
sksys()   { salt -G "role:k8s_cp" cmd.run 'kubectl get pods -n kube-system -o wide'; }
sksvc()   { salt -G "role:k8s_cp" cmd.run 'kubectl get svc -A -o wide'; }
sking()   { salt -G "role:k8s_cp" cmd.run 'kubectl get ingress -A -o wide'; }
skapi()   { salt -G "role:k8s_cp" cmd.run 'kubectl api-resources | column -t'; }

# Health & metrics
skready() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get nodes -o json | jq -r ".items[] | [.metadata.name, (.status.conditions[] | select(.type==\"Ready\").status)] | @tsv"'
}

sktop() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl top nodes 2>/dev/null || echo metrics-server-not-installed'
}

sktopp() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl top pods -A --use-protocol-buffers 2>/dev/null || echo metrics-server-not-installed'
}

skevents() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get events -A --sort-by=.lastTimestamp | tail -n 40'
}

skdescribe() {
  if [ -z "$1" ]; then
    echo "Usage: skdescribe <pod> [namespace]"
    return 1
  fi
  local pod="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl describe pod $pod -n $ns"
}

# Workload inventory
skdeploy() { salt -G "role:k8s_cp" cmd.run 'kubectl get deploy -A -o wide'; }
skrs()     { salt -G "role:k8s_cp" cmd.run 'kubectl get rs -A -o wide'; }
sksts()    { salt -G "role:k8s_cp" cmd.run 'kubectl get statefulset -A -o wide'; }
skdaemon() { salt -G "role:k8s_cp" cmd.run 'kubectl get daemonset -A -o wide'; }

# Labels & annotations
sklabel() {
  if [ $# -lt 2 ]; then
    echo "Usage: sklabel <key>=<value> <pod> [namespace]"
    return 1
  fi
  local kv="$1"
  local pod="$2"
  local ns="${3:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl label pod $pod -n $ns $kv --overwrite"
}

skannot() {
  if [ $# -lt 2 ]; then
    echo "Usage: skannot <key>=<value> <pod> [namespace]"
    return 1
  fi
  local kv="$1"
  local pod="$2"
  local ns="${3:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl annotate pod $pod -n $ns $kv --overwrite"
}

# Networking
sknetpol() { 
  salt -G "role:k8s_cp" cmd.run 'kubectl get networkpolicies -A -o wide'
}

skcni() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get pods -n kube-flannel -o wide 2>/dev/null || kubectl get pods -n kube-system | grep -i cni'
}

sksvcips() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get svc -A -o json | jq -r ".items[]|[.metadata.namespace,.metadata.name,.spec.clusterIP]|@tsv"'
}

skdns() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide 2>/dev/null || kubectl get pods -n kube-system | grep -i coredns'
}

# Logs
sklog() {
  if [ -z "$1" ]; then
    echo "Usage: sklog <pod> [namespace]"
    return 1
  fi
  local pod="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl logs $pod -n $ns --tail=200"
}

sklogf() {
  if [ -z "$1" ]; then
    echo "Usage: sklogf <pod> [namespace]"
    return 1
  fi
  local pod="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl logs $pod -n $ns -f"
}

sklogs_ns() {
  local ns="${1:-default}"
  salt -G "role:k8s_cp" cmd.run \
    "kubectl get pods -n $ns -o json \
      | jq -r '.items[].metadata.name' \
      | xargs -I {} kubectl logs {} -n $ns --tail=40"
}

# Container runtime & node diag
skcri()   { salt -G "role:k8s_cp" cmd.run 'crictl ps -a 2>/dev/null || echo no-cri-tools'; }
skdmesg() { salt "*" cmd.run 'dmesg | tail -n 25'; }
skoom()   { salt "*" cmd.run 'journalctl -k -g OOM -n 20 --no-pager'; }

# Rollouts & node lifecycle
skroll() {
  if [ -z "$1" ]; then
    echo "Usage: skroll <deployment> [namespace]"
    return 1
  fi
  local deploy="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl rollout restart deploy/$deploy -n $ns"
}

skundo() {
  if [ -z "$1" ]; then
    echo "Usage: skundo <deployment> [namespace]"
    return 1
  fi
  local deploy="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl rollout undo deploy/$deploy -n $ns"
}

skdrain() {
  if [ -z "$1" ]; then
    echo "Usage: skdrain <node>"
    return 1
  fi
  local node="$1"
  salt -G "role:k8s_cp" cmd.run "kubectl drain $node --ignore-daemonsets --force --delete-emptydir-data"
}

skuncordon() {
  if [ -z "$1" ]; then
    echo "Usage: skuncordon <node>"
    return 1
  fi
  local node="$1"
  salt -G "role:k8s_cp" cmd.run "kubectl uncordon $node"
}

skcordon() {
  if [ -z "$1" ]; then
    echo "Usage: skcordon <node>"
    return 1
  fi
  local node="$1"
  salt -G "role:k8s_cp" cmd.run "kubectl cordon $node"
}

# Security / certs / RBAC
skrbac() { 
  salt -G "role:k8s_cp" cmd.run 'kubectl get roles,rolebindings -A -o wide'
}

sksa() {
  salt -G "role:k8s_cp" cmd.run 'kubectl get sa -A -o wide'
}

skcerts() {
  salt -G "role:k8s_cp" cmd.run \
    'for i in /etc/kubernetes/pki/*.crt; do echo "== $(basename "$i") =="; openssl x509 -in "$i" -text -noout | head -n 10; echo; done'
}

# Show-offs
skpodsmap() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get pods -A -o json | jq -r ".items[] | [.metadata.namespace,.metadata.name,.status.podIP,(.spec.containers|length),.spec.nodeName] | @tsv"'
}

sktopcpu() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl top pod -A 2>/dev/null | sort -k3 -r | head -n 15'
}

# -------------------------------------------------------------------
# Helper: print cheat sheet of all the good stuff
# -------------------------------------------------------------------
shl() {
  printf "%s\n" \
"Salt / cluster helper commands:" \
"  slist         - List all minions in a wide table (id, host, OS, IPs, CPU, RAM, roles)." \
"  sping         - Ping all minions via Salt (test.ping)." \
"  ssall         - Show listening TCP sockets on all minions (ss/netstat)." \
"  skservices    - Check kubelet and containerd service status on all minions." \
"  skvers        - Show kubelet and kubectl versions on all minions." \
"  sdfall        - Show disk usage (df -hT, no tmpfs/devtmpfs) on all minions." \
"  stop5         - Top 5 CPU-hungry processes on each minion." \
"  smem5         - Top 5 memory-hungry processes on each minion." \
"  fb_world      - Apply top-level 'world' Salt state to all minions." \
"  fb_k8s_cluster- Apply 'k8s.cluster' state to CP + workers." \
"" \
"Kubernetes cluster helpers (via role:k8s_cp):" \
"  skcls         - Show cluster-info." \
"  sknodes       - List nodes (wide)." \
"  skpods        - List all pods (all namespaces, wide)." \
"  sksys         - Show kube-system pods." \
"  sksvc         - List all services." \
"  sking         - List all ingresses." \
"  skapi         - Show API resources." \
"  skready       - Show node Ready status." \
"  sktop         - Node CPU/mem usage (if metrics-server installed)." \
"  sktopp        - Pod CPU/mem usage (if metrics-server installed)." \
"  skevents      - Tail the last cluster events." \
"  skdeploy      - List deployments (all namespaces)." \
"  sksts         - List StatefulSets." \
"  skdaemon      - List DaemonSets." \
"  sknetpol      - List NetworkPolicies." \
"  sksvcips      - Map svc -> ClusterIP." \
"  skdns         - Show cluster DNS pods." \
"  sklog         - Show logs for a pod: sklog <pod> [ns]." \
"  sklogf        - Follow logs for a pod: sklogf <pod> [ns]." \
"  sklogs_ns     - Tail logs for all pods in a namespace." \
"  skroll        - Restart a deployment: skroll <deploy> [ns]." \
"  skundo        - Rollback a deployment: skundo <deploy> [ns]." \
"  skdrain       - Drain a node." \
"  skcordon      - Cordon a node." \
"  skuncordon    - Uncordon a node." \
"  skrbac        - List Roles and RoleBindings." \
"  sksa          - List ServiceAccounts." \
"  skcerts       - Dump brief info about control-plane certs." \
"  skpodsmap     - Pretty map of pods (ns, name, IP, containers, node)." \
"  sktopcpu      - Top 15 CPU-hungry pods." \
"" \
"Other:" \
"  cp/mv/rm      - Interactive (prompt before overwrite/delete)." \
"  ll/la/l       - ls variants." \
"  e, vi         - Open \$EDITOR (vim by default)." \
""
}

# -------------------------------------------------------------------
# Auto-activate BCC virtualenv (if present)
# -------------------------------------------------------------------
VENV_DIR="/root/bccenv"
if [ -d "$VENV_DIR" ] && [ -n "$PS1" ]; then
  if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$VENV_DIR" ]; then
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
  fi
fi

# -------------------------------------------------------------------
# Friendly login line
# -------------------------------------------------------------------
echo "Welcome $USER — connected to $(hostname) on $(date)"
echo "Type 'shl' for the foundryBot helper command list."
EOF
}

# -----------------------------------------------------------------------------
write_tmux_conf() {
  log "Writing tmux.conf to /etc/skel and root"
  apt-get install -y tmux

  local TMUX_CONF="/etc/skel/.tmux.conf"

  cat > "$TMUX_CONF" <<'EOF'
# ~/.tmux.conf — Airline-style theme
set -g mouse on
setw -g mode-keys vi
set -g history-limit 10000
set -g default-terminal "screen-256color"
set-option -ga terminal-overrides ",xterm-256color:Tc"
set-option -g status on
set-option -g status-interval 5
set-option -g status-justify centre
set-option -g status-bg colour236
set-option -g status-fg colour250
set-option -g status-style bold
set-option -g status-left-length 60
set-option -g status-left "#[fg=colour0,bg=colour83] #S #[fg=colour83,bg=colour55,nobold,nounderscore,noitalics]"
set-option -g status-right-length 120
set-option -g status-right "#[fg=colour55,bg=colour236]#[fg=colour250,bg=colour55] %Y-%m-%d  %H:%M #[fg=colour236,bg=colour55]#[fg=colour0,bg=colour236] #H "
set-window-option -g window-status-current-style "fg=colour0,bg=colour83,bold"
set-window-option -g window-status-current-format " #I:#W "
set-window-option -g window-status-style "fg=colour250,bg=colour236"
set-window-option -g window-status-format " #I:#W "
set-option -g pane-border-style "fg=colour238"
set-option -g pane-active-border-style "fg=colour83"
set-option -g message-style "bg=colour55,fg=colour250"
set-option -g message-command-style "bg=colour55,fg=colour250"
set-window-option -g bell-action none
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
bind r source-file ~/.tmux.conf \; display-message "Reloaded!"
bind-key -T copy-mode-vi 'v' send -X begin-selection
bind-key -T copy-mode-vi 'y' send -X copy-selection-and-cancel
EOF

  log ".tmux.conf written to /etc/skel/.tmux.conf"

  # Also set for root:
  cp "$TMUX_CONF" /root/.tmux.conf
  log ".tmux.conf copied to /root/.tmux.conf"
}

# Backwards-compat wrapper (if anything else ever calls this name)
seed_tmux_conf() {
  write_tmux_conf
}

# -----------------------------------------------------------------------------
setup_vim_config() {
  log "Writing standard Vim config..."
  apt-get install -y \
    vim \
    git \
    vim-airline \
    vim-airline-themes \
    vim-ctrlp \
    vim-fugitive \
    vim-gitgutter \
    vim-tabular

  local VIMRC=/etc/skel/.vimrc
  mkdir -p /etc/skel/.vim/autoload/airline/themes

  cat > "$VIMRC" <<'EOF'
syntax on
filetype plugin indent on
set nocompatible
set tabstop=2 shiftwidth=2 expandtab
set autoindent smartindent
set background=dark
set ruler
set showcmd
set cursorline
set wildmenu
set incsearch
set hlsearch
set laststatus=2
set clipboard=unnamedplus
set showmatch
set backspace=indent,eol,start
set ignorecase
set smartcase
set scrolloff=5
set wildmode=longest,list,full
set splitbelow
set splitright
highlight ColorColumn ctermbg=darkgrey guibg=grey
highlight ExtraWhitespace ctermbg=red guibg=red
match ExtraWhitespace /\s\+$/
let g:airline_powerline_fonts = 1
let g:airline_theme = 'custom'
let g:airline#extensions#tabline#enabled = 1
let g:airline_section_z = '%l:%c'
let g:ctrlp_map = '<c-p>'
let g:ctrlp_cmd = 'CtrlP'
nmap <leader>gs :Gstatus<CR>
nmap <leader>gd :Gdiff<CR>
nmap <leader>gc :Gcommit<CR>
nmap <leader>gb :Gblame<CR>
let g:gitgutter_enabled = 1
autocmd FileType python,yaml setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType javascript,typescript,json setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType sh,bash,zsh setlocal tabstop=2 shiftwidth=2 expandtab
nnoremap <leader>w :w<CR>
nnoremap <leader>q :q<CR>
nnoremap <leader>tw :%s/\s\+$//e<CR>
if &term =~ 'xterm'
  let &t_SI = "\e[6 q"
  let &t_EI = "\e[2 q"
endif
EOF

  chmod 644 /etc/skel/.vimrc
  cat > /etc/skel/.vim/autoload/airline/themes/custom.vim <<'EOF'
let g:airline#themes#custom#palette = {}
let s:N1 = [ '#000000' , '#00ff5f' , 0 , 83 ]
let s:N2 = [ '#ffffff' , '#5f00af' , 255 , 55 ]
let s:N3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:I1 = [ '#000000' , '#5fd7ff' , 0 , 81 ]
let s:I2 = [ '#ffffff' , '#5f00d7' , 255 , 56 ]
let s:I3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:V1 = [ '#000000' , '#af5fff' , 0 , 135 ]
let s:V2 = [ '#ffffff' , '#8700af' , 255 , 91 ]
let s:V3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:R1 = [ '#000000' , '#ff5f00' , 0 , 202 ]
let s:R2 = [ '#ffffff' , '#d75f00' , 255 , 166 ]
let s:R3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:IA = [ '#aaaaaa' , '#1c1c1c' , 250 , 234 ]
let g:airline#themes#custom#palette.normal = airline#themes#generate_color_map(s:N1, s:N2, s:N3)
let g:airline#themes#custom#palette.insert = airline#themes#generate_color_map(s:I1, s:I2, s:I3)
let g:airline#themes#custom#palette.visual = airline#themes#generate_color_map(s:V1, s:V2, s:V3)
let g:airline#themes#custom#palette.replace = airline#themes#generate_color_map(s:R1, s:R2, s:R3)
let g:airline#themes#custom#palette.inactive = airline#themes#generate_color_map(s:IA, s:IA, s:IA)
EOF

  mkdir -p /root/.vim/autoload/airline/themes
  cp /etc/skel/.vimrc /root/.vimrc
  chmod 644 /root/.vimrc
  cp /etc/skel/.vim/autoload/airline/themes/custom.vim /root/.vim/autoload/airline/themes/custom.vim
  chmod 644 /root/.vim/autoload/airline/themes/custom.vim
}

# -----------------------------------------------------------------------------
setup_python_env() {
  log "Setting up Python for BCC scripts..."

  # System packages only — no pip bcc!
  apt-get install -y python3-psutil python3-bpfcc

  # Create a virtualenv that sees system site-packages
  local VENV_DIR="/root/bccenv"
  python3 -m venv --system-site-packages "$VENV_DIR"

  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install cryptography pyOpenSSL numba pytest
  deactivate

  log "System Python has psutil + bpfcc. Venv created at $VENV_DIR with system site-packages."

  # Auto-activate for root
  local ROOT_BASHRC="/root/.bashrc"
  if ! grep -q "$VENV_DIR" "$ROOT_BASHRC"; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv"
      echo "source \"$VENV_DIR/bin/activate\""
    } >> "$ROOT_BASHRC"
  fi

  # Auto-activate for future users
  local SKEL_BASHRC="/etc/skel/.bashrc"
  if ! grep -q "$VENV_DIR" "$SKEL_BASHRC"; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv if available"
      echo "[ -d \"$VENV_DIR\" ] && source \"$VENV_DIR/bin/activate\""
    } >> "$SKEL_BASHRC"
  fi

  log "Virtualenv activation added to root and skel .bashrc"
}

# -----------------------------------------------------------------------------
sync_skel_to_existing_users() {
  log "Syncing skel configs to existing users (root + baked)..."

  local files=".bashrc .vimrc .tmux.conf"
  local homes="/root"
  homes+=" $(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)"

  for home in $homes; do
    for f in $files; do
      if [ -f "/etc/skel/$f" ]; then
        cp -f "/etc/skel/$f" "$home/$f"
      fi
    done
  done
}

main_master() {
  log "BEGIN postinstall (master control hub)"

  ensure_base
  ensure_users
  wg_setup_planes
  nft_firewall
  hub_seed
  helper_tools
  salt_master_stack
  pillars_and_states_seed
  ansible_stack
  semaphore_stack
  configure_salt_master_network
  configure_nftables_master
  write_bashrc
  write_tmux_conf
  setup_vim_config
  setup_python_env
  sync_skel_to_existing_users

  # Clean up unnecessary services
  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Master hub ready."

  # Mark bootstrap as done for this VM
  touch /root/.bootstrap_done
  sync || true

  # Disable bootstrap.service so it won't be wanted on next boot
  systemctl disable bootstrap.service 2>/dev/null || true
  systemctl daemon-reload || true

  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}

main_master
EOS
}

# =============================================================================
# MINION POSTINSTALL
# =============================================================================

emit_postinstall_minion() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/postinstall-minion.log"
exec > >(tee -a "$LOG") 2>&1
exec 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

# ---------------------------------------------------------------------------
# Load seed environment if present (from mk_iso / darksite baking)
# ---------------------------------------------------------------------------
if [ -r /etc/environment.d/99-provision.conf ]; then
  # shellcheck disable=SC2046
  export $(grep -E '^[A-Z0-9_]+=' /etc/environment.d/99-provision.conf | xargs -d'\n' || true)
fi

# ---------------------------------------------------------------------------
# Defaults (safe for set -u; all variables we might touch get a default)
# ---------------------------------------------------------------------------
DOMAIN="${DOMAIN:-unixbox.net}"

ADMIN_USER="${ADMIN_USER:-todd}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"

ROLE="${ROLE:-generic}"          # e.g. k8s-cp, k8s-worker, graf, prometheus, storage, k8s-lb, k8s

# Salt master location (minion will point here)
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"
SALT_MASTER_IP="${SALT_MASTER_IP:-$MASTER_LAN}"

# WireGuard / hub metadata (minion side)
# If mk_iso seeds these per-node, they will override; otherwise, safe defaults.
WG0_IP="${WG0_IP:-10.77.0.2/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.2/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.2/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.2/16}"; WG3_PORT="${WG3_PORT:-51823}"

WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# Hub metadata (parsed from hub.env if present)
HUB_ENV="${HUB_ENV:-/root/darksite/hub.env}"
[ -r /srv/wg/hub.env ] && HUB_ENV="/srv/wg/hub.env"

# ---------------------------------------------------------------------------
# Base system
# ---------------------------------------------------------------------------
ensure_base_minion() {
  log "Configuring APT & base system packages (minion)"

  export DEBIAN_FRONTEND=noninteractive

  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF

  for i in 1 2 3; do
    if apt-get update -y; then break; fi
    sleep $((i*3))
  done

  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq xxd unzip tar \
    iproute2 iputils-ping net-tools \
    nftables wireguard-tools \
    python3-venv python3-pip python3-bpfcc python3-psutil \
    chrony rsyslog qemu-guest-agent vim \
    salt-minion prometheus-node-exporter || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true

  if command -v python3 >/dev/null; then
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    python3 -m pip install dnspython requests cryptography pyOpenSSL || true
  fi

  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true

  cat >/etc/sysctl.d/99-minion.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF

  sysctl --system || true
}

# ---------------------------------------------------------------------------
# Users & SSH hardening (mirrors master’s behaviour)
# ---------------------------------------------------------------------------
ensure_users_minion() {
  log "Ensuring ${ADMIN_USER} + ansible users exist"

  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""
  [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"

  mkuser() {
    local u="$1" k="$2"
    id -u "$u" &>/dev/null || useradd -m -s /bin/bash "$u"
    install -d -m700 -o "$u" -g "$u" "/home/$u/.ssh"
    touch "/home/$u/.ssh/authorized_keys"
    chmod 600 "/home/$u/.ssh/authorized_keys"
    chown -R "$u:$u" "/home/$u/.ssh"

    if [[ -n "$k" ]] && ! grep -qxF "$k" "/home/$u/.ssh/authorized_keys"; then
      printf '%s\n' "$k" >> "/home/$u/.ssh/authorized_keys"
    fi

    install -d -m755 /etc/sudoers.d
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$u" >"/etc/sudoers.d/90-$u"
    chmod 0440 "/etc/sudoers.d/90-$u"
  }

  mkuser "$ADMIN_USER" "$PUB"

  # ansible service user
  id -u ansible &>/dev/null || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || \
    runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys
  chmod 600 /home/ansible/.ssh/authorized_keys

  # Allow cluster enrollment key to log in as ADMIN_USER (same as master)
  local ENROLL_PUB_SRC="/root/darksite/enroll_ed25519.pub"
  if [[ -s "$ENROLL_PUB_SRC" ]]; then
    local ENROLL_PUB
    ENROLL_PUB="$(head -n1 "$ENROLL_PUB_SRC")"
    if ! grep -qxF "$ENROLL_PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys"; then
      printf '%s\n' "$ENROLL_PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"
    fi
  fi

  # Backplane corresponds to wg1
  local BACKPLANE_IF="wg1"
  local BACKPLANE_IP="${WG1_IP%/*}"

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress 0.0.0.0
ListenAddress ${BACKPLANE_IP}
AllowUsers ${ADMIN_USER} ansible
EOF

  cat >/etc/ssh/sshd_config.d/99-hard.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

  if [ "${ALLOW_ADMIN_PASSWORD}" = "yes" ]; then
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
Match User ${ADMIN_USER} Address 10.0.0.0/8
    PasswordAuthentication yes
EOF
  fi

  install -d -m755 /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  (sshd -t && systemctl daemon-reload && systemctl restart ssh) || true
}

# ---------------------------------------------------------------------------
# Parse hub.env (if present) to get master pubkeys + endpoints
# ---------------------------------------------------------------------------
parse_hub_env() {
  log "Parsing hub.env (if present) for WireGuard metadata"
  HUB_WG1_NET=""
  HUB_WG2_NET=""
  HUB_WG3_NET=""
  HUB_LAN=""
  HUB_WG1_PUB=""
  HUB_WG2_PUB=""
  HUB_WG3_PUB=""
  HUB_WG0_PUB=""
  HUB_WG0_PORT=""
  HUB_WG1_PORT=""
  HUB_WG2_PORT=""
  HUB_WG3_PORT=""

  if [[ -r "$HUB_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$HUB_ENV" || true

    HUB_LAN="${HUB_LAN:-$MASTER_LAN}"
    HUB_WG1_NET="${HUB_WG1_NET:-10.78.0.0/16}"
    HUB_WG2_NET="${HUB_WG2_NET:-10.79.0.0/16}"
    HUB_WG3_NET="${HUB_WG3_NET:-10.80.0.0/16}"

    HUB_WG0_PUB="${WG0_PUB:-}"
    HUB_WG1_PUB="${WG1_PUB:-}"
    HUB_WG2_PUB="${WG2_PUB:-}"
    HUB_WG3_PUB="${WG3_PUB:-}"

    HUB_WG0_PORT="${WG0_PORT:-$WG0_PORT}"
    HUB_WG1_PORT="${WG1_PORT:-$WG1_PORT}"
    HUB_WG2_PORT="${WG2_PORT:-$WG2_PORT}"
    HUB_WG3_PORT="${WG3_PORT:-$WG3_PORT}"
  else
    log "NOTE: $HUB_ENV not found; WireGuard peers will not be auto-populated"
  fi
}

# ---------------------------------------------------------------------------
# WireGuard setup (minion side)
# ---------------------------------------------------------------------------
wg_minion_setup() {
  log "Configuring WireGuard planes on minion"

  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077

  # Local keypair per interface (wg0–wg3)
  local ifn
  for ifn in wg0 wg1 wg2 wg3; do
    [ -f "/etc/wireguard/${ifn}.key" ] || wg genkey | tee "/etc/wireguard/${ifn}.key" | wg pubkey >"/etc/wireguard/${ifn}.pub"
  done

  parse_hub_env

  # Helper: build peer section if we have data
  build_peer_block() {
    local pub="$1" ip="$2" port="$3"
    if [[ -n "$pub" && -n "$ip" && -n "$port" ]]; then
      cat <<EOF
[Peer]
PublicKey = ${pub}
Endpoint  = ${ip}:${port}
AllowedIPs = ${WG_ALLOWED_CIDR}
PersistentKeepalive = 25
EOF
    else
      echo "# Peer info not available; run wg-set-peer manually."
    fi
  }

  # wg1: control / SSH plane
  {
    echo "[Interface]"
    echo "Address    = ${WG1_IP}"
    echo "PrivateKey = $(cat /etc/wireguard/wg1.key)"
    echo "ListenPort = ${WG1_PORT}"
    echo "MTU        = 1420"
    echo
    build_peer_block "${HUB_WG1_PUB:-}" "${HUB_LAN:-$MASTER_LAN}" "${HUB_WG1_PORT:-$WG1_PORT}"
  } >/etc/wireguard/wg1.conf

  # wg2: metrics plane
  {
    echo "[Interface]"
    echo "Address    = ${WG2_IP}"
    echo "PrivateKey = $(cat /etc/wireguard/wg2.key)"
    echo "ListenPort = ${WG2_PORT}"
    echo "MTU        = 1420"
    echo
    build_peer_block "${HUB_WG2_PUB:-${HUB_WG1_PUB:-}}" "${HUB_LAN:-$MASTER_LAN}" "${HUB_WG2_PORT:-$WG2_PORT}"
  } >/etc/wireguard/wg2.conf

  # wg3: optional k8s / app plane – configured similar, but peer optional
  {
    echo "[Interface]"
    echo "Address    = ${WG3_IP}"
    echo "PrivateKey = $(cat /etc/wireguard/wg3.key)"
    echo "ListenPort = ${WG3_PORT}"
    echo "MTU        = 1420"
    echo
    build_peer_block "${HUB_WG3_PUB:-${HUB_WG1_PUB:-}}" "${HUB_LAN:-$MASTER_LAN}" "${HUB_WG3_PORT:-$WG3_PORT}"
  } >/etc/wireguard/wg3.conf

  chmod 600 /etc/wireguard/*.conf
  umask "$_old_umask"

  systemctl daemon-reload || true
  systemctl enable --now wg-quick@wg1 || true
  systemctl enable --now wg-quick@wg2 || true
  systemctl enable --now wg-quick@wg3 || true
}

# ---------------------------------------------------------------------------
# nftables (minion)
# ---------------------------------------------------------------------------
nft_minion_firewall() {
  log "Writing nftables ruleset for minion"

  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept

    iifname "lo" accept

    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # SSH
    tcp dport 22 accept

    # Salt minion's outbound is allowed by output chain; inbound from master is via 4505/4506 on master side.

    # WireGuard
    udp dport { 51820, 51821, 51822, 51823 } accept

    # Traffic arriving via WireGuard planes
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

  chmod 600 /etc/nftables.conf
  systemctl enable nftables || true
  nft -f /etc/nftables.conf || true
}

# ---------------------------------------------------------------------------
# Salt minion configuration
# ---------------------------------------------------------------------------
configure_salt_minion() {
  log "Configuring Salt minion to talk to master at ${SALT_MASTER_IP}"

  install -d -m0755 /etc/salt/minion.d

  cat >/etc/salt/minion.d/master.conf <<EOF
master: ${SALT_MASTER_IP}
random_reauth_delay: 60
ipv6: False
id: $(hostname -f)
EOF

  # Tag this node with its role so top.sls 'role:*' matches work cleanly
  cat >/etc/salt/minion.d/grains.conf <<EOF
grains:
  role: ${ROLE}
  domain: ${DOMAIN}
EOF

  systemctl enable --now salt-minion || true
}

# ---------------------------------------------------------------------------
# Bash / tmux / vim / Python env – reuse same implementations as master
# ---------------------------------------------------------------------------
write_bashrc() {
  log "Writing clean .bashrc for all users (via /etc/skel)..."

  local BASHRC=/etc/skel/.bashrc

  cat > "$BASHRC" <<'EOF'
# ~/.bashrc - foundryBot minion console

[ -z "$PS1" ] && return

HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT='%F %T '
HISTCONTROL=ignoredups:erasedups

shopt -s histappend
shopt -s checkwinsize
shopt -s cdspell

PS1='\u@\h:\w\$ '

fb_banner() {
  cat << 'FBBANNER'
   ___                           __                  ______          __
 /'___\                         /\ \                /\     \        /\ \__
/\ \__/  ___   __  __    ___    \_\ \  _ __   __  __\ \ \L\ \    ___\ \ ,_\
\ \ ,__\/ __`\/\ \/\ \ /' _ `\  /'_` \/\`'__\/\ \/\ \\ \  _ <'  / __`\ \ \/
 \ \ \_/\ \L\ \ \ \_\ \/\ \/\ \/\ \L\ \ \ \/ \ \ \_\ \\ \ \L\ \/\ \L\ \ \ \_
  \ \_\\ \____/\ \____/\ \_\ \_\ \___,_\ \_\  \/`____ \\ \____/\ \____/\ \__\
   \/_/ \/___/  \/___/  \/_/\/_/\/__,_ /\/_/   `/___/> \\/___/  \/___/  \/__/
                                                  /\___/
                                                  \/__/
           secure cluster minion

FBBANNER
}

if [ -z "$FBNOBANNER" ]; then
  fb_banner
  export FBNOBANNER=1
fi

if [ "$EUID" -eq 0 ]; then
  PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
else
  PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi

if [ -f /etc/bash_completion ]; then
  # shellcheck source=/etc/bash_completion
  . /etc/bash_completion
fi

alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'

alias ls='ls --color=auto'
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias e='${EDITOR:-vim}'
alias vi='vim'

alias ports='ss -tuln'
alias df='df -h'
alias du='du -h'
alias tk='tmux kill-server'

echo "Welcome $USER — minion $(hostname) on $(date)"
EOF

  # BCC auto-activation hook will be appended later from setup_python_env()
}

write_tmux_conf() {
  log "Writing tmux.conf to /etc/skel and root"
  apt-get install -y tmux

  local TMUX_CONF="/etc/skel/.tmux.conf"

  cat > "$TMUX_CONF" <<'EOF'
# ~/.tmux.conf — Airline-style theme (minion)
set -g mouse on
setw -g mode-keys vi
set -g history-limit 10000
set -g default-terminal "screen-256color"
set-option -ga terminal-overrides ",xterm-256color:Tc"
set-option -g status on
set-option -g status-interval 5
set-option -g status-justify centre
set-option -g status-bg colour236
set-option -g status-fg colour250
set-option -g status-style bold
set-option -g status-left-length 60
set-option -g status-left "#[fg=colour0,bg=colour83] #S #[fg=colour83,bg=colour55,nobold,nounderscore,noitalics]"
set-option -g status-right-length 120
set-option -g status-right "#[fg=colour55,bg=colour236]#[fg=colour250,bg=colour55] %Y-%m-%d  %H:%M #[fg=colour236,bg=colour55]#[fg=colour0,bg=colour236] #H "
set-window-option -g window-status-current-style "fg=colour0,bg=colour83,bold"
set-window-option -g window-status-current-format " #I:#W "
set-window-option -g window-status-style "fg=colour250,bg=colour236"
set-window-option -g window-status-format " #I:#W "
set-option -g pane-border-style "fg=colour238"
set-option -g pane-active-border-style "fg=colour83"
set-option -g message-style "bg=colour55,fg=colour250"
set-option -g message-command-style "bg=colour55,fg=colour250"
set-window-option -g bell-action none
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
bind r source-file ~/.tmux.conf \; display-message "Reloaded!"
bind-key -T copy-mode-vi 'v' send -X begin-selection
bind-key -T copy-mode-vi 'y' send -X copy-selection-and-cancel
EOF

  cp "$TMUX_CONF" /root/.tmux.conf
}

setup_vim_config() {
  log "Writing standard Vim config (minion)..."
  apt-get install -y \
    vim git \
    vim-airline vim-airline-themes \
    vim-ctrlp vim-fugitive vim-gitgutter vim-tabular || true

  local VIMRC=/etc/skel/.vimrc
  mkdir -p /etc/skel/.vim/autoload/airline/themes

  cat > "$VIMRC" <<'EOF'
syntax on
filetype plugin indent on
set nocompatible
set tabstop=2 shiftwidth=2 expandtab
set autoindent smartindent
set background=dark
set ruler
set showcmd
set cursorline
set wildmenu
set incsearch
set hlsearch
set laststatus=2
set clipboard=unnamedplus
set showmatch
set backspace=indent,eol,start
set ignorecase
set smartcase
set scrolloff=5
set wildmode=longest,list,full
set splitbelow
set splitright
highlight ColorColumn ctermbg=darkgrey guibg=grey
highlight ExtraWhitespace ctermbg=red guibg=red
match ExtraWhitespace /\s\+$/
let g:airline_powerline_fonts = 1
let g:airline_theme = 'custom'
let g:airline#extensions#tabline#enabled = 1
let g:airline_section_z = '%l:%c'
let g:ctrlp_map = '<c-p>'
let g:ctrlp_cmd = 'CtrlP'
nmap <leader>gs :Gstatus<CR>
nmap <leader>gd :Gdiff<CR>
nmap <leader>gc :Gcommit<CR>
nmap <leader>gb :Gblame<CR>
let g:gitgutter_enabled = 1
autocmd FileType python,yaml setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType javascript,typescript,json setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType sh,bash,zsh setlocal tabstop=2 shiftwidth=2 expandtab
nnoremap <leader>w :w<CR>
nnoremap <leader>q :q<CR>
nnoremap <leader>tw :%s/\s\+$//e<CR>
if &term =~ 'xterm'
  let &t_SI = "\e[6 q"
  let &t_EI = "\e[2 q"
endif
EOF

  chmod 644 /etc/skel/.vimrc
  cat >/etc/skel/.vim/autoload/airline/themes/custom.vim <<'EOF'
let g:airline#themes#custom#palette = {}
let s:N1 = [ '#000000' , '#00ff5f' , 0 , 83 ]
let s:N2 = [ '#ffffff' , '#5f00af' , 255 , 55 ]
let s:N3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:I1 = [ '#000000' , '#5fd7ff' , 0 , 81 ]
let s:I2 = [ '#ffffff' , '#5f00d7' , 255 , 56 ]
let s:I3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:V1 = [ '#000000' , '#af5fff' , 0 , 135 ]
let s:V2 = [ '#ffffff' , '#8700af' , 255 , 91 ]
let s:V3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:R1 = [ '#000000' , '#ff5f00' , 0 , 202 ]
let s:R2 = [ '#ffffff' , '#d75f00' , 255 , 166 ]
let s:R3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:IA = [ '#aaaaaa' , '#1c1c1c' , 250 , 234 ]
let g:airline#themes#custom#palette.normal = airline#themes#generate_color_map(s:N1, s:N2, s:N3)
let g:airline#themes#custom#palette.insert = airline#themes#generate_color_map(s:I1, s:I2, s:I3)
let g:airline#themes#custom#palette.visual = airline#themes#generate_color_map(s:V1, s:V2, s:V3)
let g:airline#themes#custom#palette.replace = airline#themes#generate_color_map(s:R1, s:R2, s:R3)
let g:airline#themes#custom#palette.inactive = airline#themes#generate_color_map(s:IA, s:IA, s:IA)
EOF

  mkdir -p /root/.vim/autoload/airline/themes
  cp /etc/skel/.vimrc /root/.vimrc
  chmod 644 /root/.vimrc
  cp /etc/skel/.vim/autoload/airline/themes/custom.vim /root/.vim/autoload/airline/themes/custom.vim
  chmod 644 /root/.vim/autoload/airline/themes/custom.vim
}

setup_python_env() {
  log "Setting up Python for BCC scripts (minion)..."

  apt-get install -y python3-psutil python3-bpfcc || true

  local VENV_DIR="/root/bccenv"
  python3 -m venv --system-site-packages "$VENV_DIR"

  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install cryptography pyOpenSSL numba pytest
  deactivate

  log "Venv created at $VENV_DIR with system site-packages."

  local ROOT_BASHRC="/root/.bashrc"
  if ! grep -q "$VENV_DIR" "$ROOT_BASHRC" 2>/dev/null; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv"
      echo "source \"$VENV_DIR/bin/activate\""
    } >> "$ROOT_BASHRC"
  fi

  local SKEL_BASHRC="/etc/skel/.bashrc"
  if ! grep -q "$VENV_DIR" "$SKEL_BASHRC" 2>/dev/null; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv if available"
      echo "[ -d \"$VENV_DIR\" ] && source \"$VENV_DIR/bin/activate\""
    } >> "$SKEL_BASHRC"
  fi
}

sync_skel_to_existing_users() {
  log "Syncing skel configs to existing users (minion)..."

  local files=".bashrc .vimrc .tmux.conf"
  local homes="/root"
  homes+=" $(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)"

  for home in $homes; do
    for f in $files; do
      if [ -f "/etc/skel/$f" ]; then
        cp -f "/etc/skel/$f" "$home/$f"
      fi
    done
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main_minion() {
  log "BEGIN postinstall (cluster minion, role=${ROLE})"

  ensure_base_minion
  ensure_users_minion
  wg_minion_setup
  nft_minion_firewall
  configure_salt_minion
  write_bashrc
  write_tmux_conf
  setup_vim_config
  setup_python_env
  sync_skel_to_existing_users

  # Clean out junk we don't care about
  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Minion ready (role=${ROLE})."

  touch /root/.bootstrap_done
  sync || true

  systemctl disable bootstrap.service 2>/dev/null || true
  systemctl daemon-reload || true

  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}

main_minion
EOS
}

# =========================
# MINION WRAPPER
# =========================

emit_minion_wrapper() {
  # Usage: emit_minion_wrapper <outfile> <group> <wg0/32> <wg1/32> <wg2/32> <wg3/32>
  local out="$1" group="$2" wg0="$3" wg1="$4" wg2="$5" wg3="$6"
  local hub_src="$BUILD_ROOT/hub/hub.env"
  [[ -s "$hub_src" ]] || { err "emit_minion_wrapper: missing hub.env at $hub_src"; return 1; }

  cat >"$out" <<'EOSH'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/minion-wrapper.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Wrapper failed at line $LINENO" >&2' ERR
EOSH

  {
    echo 'mkdir -p /root/darksite/cluster-seed'
    echo 'cat > /root/darksite/cluster-seed/hub.env <<HUBEOF'
    cat "$hub_src"
    echo 'HUBEOF'
    echo 'chmod 0644 /root/darksite/cluster-seed/hub.env'
  } >>"$out"

  cat >>"$out" <<EOSH
install -d -m0755 /etc/environment.d
{
  echo "ADMIN_USER=\${ADMIN_USER:-$ADMIN_USER}"
  echo "MY_GROUP=${group}"
  echo "WG0_WANTED=${wg0}"
  echo "WG1_WANTED=${wg1}"
  echo "WG2_WANTED=${wg2}"
  echo "WG3_WANTED=${wg3}"
} >> /etc/environment.d/99-provision.conf
chmod 0644 /etc/environment.d/99-provision.conf
EOSH

  cat >>"$out" <<'EOSH'
install -d -m0755 /root/darksite
cat >/root/darksite/postinstall-minion.sh <<'EOMINION'
EOSH

  local __tmp_minion
  __tmp_minion="$(mktemp)"
  emit_postinstall_minion "$__tmp_minion"
  cat "$__tmp_minion" >>"$out"
  rm -f "$__tmp_minion"

  cat >>"$out" <<'EOSH'
EOMINION
chmod +x /root/darksite/postinstall-minion.sh
bash -lc '/root/darksite/postinstall-minion.sh'
EOSH
  chmod +x "$out"
}

# =============================================================================
# GENERIC: ensure hub enrollment seed exists
# =============================================================================

ensure_master_enrollment_seed() {
  local vmid="$1"
  pmx_guest_exec "$vmid" /bin/bash -lc 'set -euo pipefail
mkdir -p /srv/wg
# Do not touch /srv/wg/hub.env here – it is generated by postinstall (hub_seed).
: > /srv/wg/ENROLL_ENABLED'
}

# =============================================================================
# minion deploy helper
# =============================================================================

deploy_minion_vm() {
  # deploy_minion_vm <vmid> <name> <lan_ip> <group> <wg0/32> <wg1/32> <wg2/32> <wg3/32> <mem_mb> <cores> <disk_gb>
  local id="$1" name="$2" ip="$3" group="$4"
  local wg0="$5" wg1="$6" wg2="$7" wg3="$8"
  local mem="$9" cores="${10}" disk="${11}"

  local payload iso
  payload="$(mktemp)"
  emit_minion_wrapper "$payload" "$group" "$wg0" "$wg1" "$wg2" "$wg3"

  iso="$BUILD_ROOT/${name}.iso"
  mk_iso "$name" "$payload" "$iso" "$ip"
  pmx_deploy "$id" "$name" "$iso" "$mem" "$cores" "$disk"

  wait_poweroff "$id" 2400
  boot_from_disk "$id"
  wait_poweroff "$id" 2400
  pmx "qm start $id"
  pmx_wait_for_state "$id" "running" 600
}

# =============================================================================
# ORIGINAL: base proxmox_cluster
# =============================================================================

proxmox_cluster() {
  log "=== Building base Proxmox cluster (master + prom + graf + k8s-jump + storage) ==="

  # --- Master (hub) ---
  log "Emitting postinstall-master.sh"
  MASTER_PAYLOAD="$(mktemp)"
  emit_postinstall_master "$MASTER_PAYLOAD"

  MASTER_ISO="$BUILD_ROOT/master.iso"
  mk_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"
  pmx_deploy "$MASTER_ID" "$MASTER_NAME" "$MASTER_ISO" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"

  wait_poweroff "$MASTER_ID" 1800
  boot_from_disk "$MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  pmx "qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900

  ensure_master_enrollment_seed "$MASTER_ID"

  log "Fetching hub.env from master via QGA..."
  mkdir -p "$BUILD_ROOT/hub"
  DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "hub.env saved to ${DEST}"
  else
    err "QGA fetch failed; fallback to SSH probe"
    for u in "${ADMIN_USER}" ansible root; do
      if sssh "$u@${MASTER_LAN}" "test -r /srv/wg/hub.env" 2>/dev/null; then
        sscp "$u@${MASTER_LAN}:/srv/wg/hub.env" "${DEST}"
        break
      fi
    done
    [[ -s "$DEST" ]] || { err "Failed to retrieve hub.env"; exit 1; }
  fi

  pmx_guest_exec "$MASTER_ID" /bin/bash -lc ": >/srv/wg/ENROLL_ENABLED" || \
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment on || true' || \
    sssh root@"$MASTER_LAN" 'wg-enrollment on || true' || true

  deploy_minion_vm "$PROM_ID"  "$PROM_NAME"  "$PROM_IP"  "prom" \
    "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3" \
    "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$GRAF_ID"  "$GRAF_NAME"  "$GRAF_IP"  "graf" \
    "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3" \
    "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$K8S_ID"   "$K8S_NAME"   "$K8S_IP"   "k8s"  \
    "$K8S_WG0"  "$K8S_WG1" "$K8S_WG2" "$K8S_WG3" \
    "$K8S_MEM"  "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$STOR_ID"  "$STOR_NAME"  "$STOR_IP"  "storage" \
    "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3" \
    "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"

  log "Closing WireGuard enrollment on master..."
  pmx_guest_exec "$MASTER_ID" /bin/bash -lc "rm -f /srv/wg/ENROLL_ENABLED" || \
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment off || true' || \
    sssh root@"$MASTER_LAN" 'wg-enrollment off || true' || true

  log "Base cluster deployed and enrollment closed."
}

# =============================================================================
# Proxmox K8s node VMs
# =============================================================================

proxmox_k8s_ha() {
  log "=== Deploying K8s node VMs (LBs + CPs + workers) with unified pipeline ==="

  # Ensure master is up and hub.env present for wrappers
  pmx "qm start $MASTER_ID" >/dev/null 2>&1 || true
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900
  ensure_master_enrollment_seed "$MASTER_ID"

  mkdir -p "$BUILD_ROOT/hub"
  DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "hub.env refreshed at ${DEST}"
  else
    [[ -s "$DEST" ]] || die "Could not get hub.env for K8s nodes."
  fi

  pmx_guest_exec "$MASTER_ID" /bin/bash -lc ": >/srv/wg/ENROLL_ENABLED" || true

  # LBs
  deploy_minion_vm "$K8SLB1_ID" "$K8SLB1_NAME" "$K8SLB1_IP" "k8s-lb" \
    "$K8SLB1_WG0" "$K8SLB1_WG1" "$K8SLB1_WG2" "$K8SLB1_WG3" \
    "$K8S_LB_MEM" "$K8S_LB_CORES" "$K8S_LB_DISK_GB"

  deploy_minion_vm "$K8SLB2_ID" "$K8SLB2_NAME" "$K8SLB2_IP" "k8s-lb" \
    "$K8SLB2_WG0" "$K8SLB2_WG1" "$K8SLB2_WG2" "$K8SLB2_WG3" \
    "$K8S_LB_MEM" "$K8S_LB_CORES" "$K8S_LB_DISK_GB"

  # Control planes
  deploy_minion_vm "$K8SCP1_ID" "$K8SCP1_NAME" "$K8SCP1_IP" "k8s-cp" \
    "$K8SCP1_WG0" "$K8SCP1_WG1" "$K8SCP1_WG2" "$K8SCP1_WG3" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  deploy_minion_vm "$K8SCP2_ID" "$K8SCP2_NAME" "$K8SCP2_IP" "k8s-cp" \
    "$K8SCP2_WG0" "$K8SCP2_WG1" "$K8SCP2_WG2" "$K8SCP2_WG3" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  deploy_minion_vm "$K8SCP3_ID" "$K8SCP3_NAME" "$K8SCP3_IP" "k8s-cp" \
    "$K8SCP3_WG0" "$K8SCP3_WG1" "$K8SCP3_WG2" "$K8SCP3_WG3" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  # Workers
  deploy_minion_vm "$K8SW1_ID" "$K8SW1_NAME" "$K8SW1_IP" "k8s-worker" \
    "$K8SW1_WG0" "$K8SW1_WG1" "$K8SW1_WG2" "$K8SW1_WG3" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  deploy_minion_vm "$K8SW2_ID" "$K8SW2_NAME" "$K8SW2_IP" "k8s-worker" \
    "$K8SW2_WG0" "$K8SW2_WG1" "$K8SW2_WG2" "$K8SW2_WG3" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  deploy_minion_vm "$K8SW3_ID" "$K8SW3_NAME" "$K8SW3_IP" "k8s-worker" \
    "$K8SW3_WG0" "$K8SW3_WG1" "$K8SW3_WG2" "$K8SW3_WG3" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  pmx_guest_exec "$MASTER_ID" /bin/bash -lc "rm -f /srv/wg/ENROLL_ENABLED" || true

  log "K8s node VMs deployed (LBs/CPs/workers) via unified minion pipeline."
  log "⚠ Note: this script only provisions OS + WG + Salt/etc. K8s kubeadm bootstrap can be layered on in a follow-up step."
}

proxmox_all() {
  log "=== Running full Proxmox deployment: base cluster + K8s node VMs ==="
  proxmox_cluster
  proxmox_k8s_ha
  log "=== Proxmox ALL complete. ==="
}

packer_scaffold() {
  require_cmd packer
  mkdir -p "$PACKER_OUT_DIR"

  # Prefer a custom ISO if you have one; otherwise fall back to ISO_ORIG
  local iso="${MASTER_ISO:-${ISO_ORIG:-}}"
  if [[ -z "${iso:-}" ]]; then
    die "packer_scaffold: MASTER_ISO or ISO_ORIG must be set to a bootable Debian ISO"
  fi

  log "Emitting Packer QEMU template at: $PACKER_TEMPLATE (iso=$iso)"

  cat >"$PACKER_TEMPLATE" <<EOF
{
  "variables": {
    "image_name": "foundrybot-debian13",
    "iso_url": "${iso}",
    "iso_checksum": "none"
  },
  "builders": [
    {
      "type": "qemu",
      "name": "foundrybot-qemu",
      "iso_url": "{{user \\"iso_url\\"}}",
      "iso_checksum": "{{user \\"iso_checksum\\"}}",
      "output_directory": "${PACKER_OUT_DIR}/output",
      "shutdown_command": "sudo shutdown -P now",
      "ssh_username": "${ADMIN_USER:-admin}",
      "ssh_password": "disabled",
      "ssh_timeout": "45m",
      "headless": true,
      "disk_size": 20480,
      "format": "qcow2",
      "accelerator": "kvm",
      "http_directory": "${PACKER_OUT_DIR}/http",
      "boot_wait": "5s",
      "boot_command": [
        "<esc><wait>",
        "auto priority=critical console=ttyS0,115200n8 ",
        "preseed/file=/cdrom/preseed.cfg ",
        "debian-installer=en_US ",
        "language=en ",
        "country=US ",
        "locale=en_US.UTF-8 ",
        "hostname=packer ",
        "domain=${DOMAIN:-example.com} ",
        "<enter>"
      ]
    }
  ],
  "provisioners": [
    {
      "type": "shell",
      "inline": [
        "echo 'Packer provisioner hook - handoff to foundryBot bootstrap if desired.'"
      ]
    }
  ]
}
EOF

  log "Packer scaffold ready. Example:"
  log "  packer build $PACKER_TEMPLATE"
}

# =============================================================================
#  Export VMDK Images
# =============================================================================

export_vmdk() {
  require_cmd qemu-img

  if [[ ! -f "$BASE_DISK_IMAGE" ]]; then
    die "export_vmdk: BASE_DISK_IMAGE='$BASE_DISK_IMAGE' does not exist. Point it at your qcow2/raw image first."
  fi

  mkdir -p "$(dirname "$VMDK_OUTPUT")"

  log "Converting $BASE_DISK_IMAGE -> $VMDK_OUTPUT (ESXi-compatible VMDK)"
  qemu-img convert -O vmdk "$BASE_DISK_IMAGE" "$VMDK_OUTPUT"

  log "VMDK export complete: $VMDK_OUTPUT"
}

# =============================================================================
# Export Firecracker
# =============================================================================

firecracker_bundle() {
  mkdir -p "$FC_WORKDIR"

  if [[ ! -f "$FC_ROOTFS_IMG" ]]; then
    die "firecracker_bundle: FC_ROOTFS_IMG='$FC_ROOTFS_IMG' not found. Point it at your rootfs.ext4."
  fi
  if [[ ! -f "$FC_KERNEL" ]]; then
    die "firecracker_bundle: FC_KERNEL='$FC_KERNEL' not found. Point it at your vmlinux."
  fi
  if [[ ! -f "$FC_INITRD" ]]; then
    die "firecracker_bundle: FC_INITRD='$FC_INITRD' not found. Point it at your initrd.img."
  fi

  local cfg="$FC_WORKDIR/fc-config.json"
  log "Emitting Firecracker config: $cfg"

  cat >"$cfg" <<EOF
{
  "boot-source": {
    "kernel_image_path": "${FC_KERNEL}",
    "initrd_path": "${FC_INITRD}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=dhcp"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${FC_ROOTFS_IMG}",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": ${FC_VCPUS},
    "mem_size_mib": ${FC_MEM_MB},
    "ht_enabled": false
  },
  "network-interfaces": []
}
EOF

  local run="$FC_WORKDIR/run-fc.sh"
  cat >"$run" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

FC_BIN="${FC_BIN:-firecracker}"
FC_SOCKET="${FC_SOCKET:-/tmp/firecracker.sock}"
FC_CONFIG="${FC_CONFIG:-'"$cfg"'}"

rm -f "$FC_SOCKET"

$FC_BIN --api-sock "$FC_SOCKET" &
FC_PID=$!

cleanup() {
  kill "$FC_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Basic one-shot config load using the Firecracker API
curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' \
  -d @"$FC_CONFIG" /machine-config >/dev/null

curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' \
  -d @"$FC_CONFIG" /boot-source >/dev/null

curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' \
  -d @"$FC_CONFIG" /drives/rootfs >/dev/null

curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' \
  -d '{"action_type": "InstanceStart"}' /actions >/dev/null

wait "$FC_PID"
EOF
  chmod +x "$run"

  log "Firecracker bundle ready in $FC_WORKDIR"
  log "Run with: FC_CONFIG='$cfg' $run"
}

firecracker_flow() {
  firecracker_bundle
  log "Launching Firecracker microVM..."
  FC_CONFIG="$FC_WORKDIR/fc-config.json" "$FC_WORKDIR/run-fc.sh"
}

# =============================================================================
# AWS Exporters and Images
# =============================================================================

aws_bake_ami() {
  require_cmd aws
  require_cmd qemu-img

  [[ -n "${AWS_S3_BUCKET:-}" ]] || die "aws_bake_ami: AWS_S3_BUCKET must be set"
  [[ -n "${AWS_REGION:-}" ]]    || die "aws_bake_ami: AWS_REGION must be set"
  [[ -n "${AWS_IMPORT_ROLE:-}" ]] || die "aws_bake_ami: AWS_IMPORT_ROLE must be set (VM Import role)"

  if [[ ! -f "$BASE_DISK_IMAGE" ]]; then
    die "aws_bake_ami: BASE_DISK_IMAGE='$BASE_DISK_IMAGE' not found. Point it at your qcow2/raw image."
  fi

  mkdir -p "$BUILD_ROOT/aws"
  local raw="$BASE_RAW_IMAGE"
  local key="foundrybot/${AWS_ARCH}/$(date +%Y%m%d-%H%M%S)-root.raw"

  log "Converting $BASE_DISK_IMAGE -> raw: $raw"
  qemu-img convert -O raw "$BASE_DISK_IMAGE" "$raw"

  log "Uploading raw image to s3://$AWS_S3_BUCKET/$key"
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    s3 cp "$raw" "s3://$AWS_S3_BUCKET/$key"

  log "Starting EC2 import-image task"
  local task_id
  task_id=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 import-image \
    --description "foundryBot Debian 13 $AWS_ARCH" \
    --disk-containers "FileFormat=RAW,UserBucket={S3Bucket=$AWS_S3_BUCKET,S3Key=$key}" \
    --role-name "$AWS_IMPORT_ROLE" \
    --query 'ImportTaskId' --output text)

  log "Import task: $task_id (polling until completed...)"

  local status ami
  while :; do
    sleep 30
    status=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 describe-import-image-tasks \
      --import-task-ids "$task_id" \
      --query 'ImportImageTasks[0].Status' --output text)
    log "Import status: $status"
    if [[ "$status" == "completed" ]]; then
      ami=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 describe-import-image-tasks \
        --import-task-ids "$task_id" \
        --query 'ImportImageTasks[0].ImageId' --output text)
      break
    elif [[ "$status" == "deleted" || "$status" == "deleting" || "$status" == "cancelling" ]]; then
      die "aws_bake_ami: import task $task_id failed with status=$status"
    fi
  done

  log "AMI created: $ami"
  echo "AWS_AMI_ID=$ami"

  # You can export this to a file for later reuse
  echo "$ami" >"$BUILD_ROOT/aws/last-ami-id"
}

aws_run_from_ami() {
  require_cmd aws

  local ami="${AWS_AMI_ID:-}"
  if [[ -z "$ami" ]] && [[ -f "$BUILD_ROOT/aws/last-ami-id" ]]; then
    ami=$(<"$BUILD_ROOT/aws/last-ami-id")
  fi
  [[ -n "$ami" ]] || die "aws_run_from_ami: AWS_AMI_ID not set and no last-ami-id file found"

  [[ -n "${AWS_SUBNET_ID:-}" ]] || die "aws_run_from_ami: AWS_SUBNET_ID must be set"
  [[ -n "${AWS_SECURITY_GROUP_ID:-}" ]] || die "aws_run_from_ami: AWS_SECURITY_GROUP_ID must be set"

  log "Launching $AWS_RUN_COUNT x $AWS_INSTANCE_TYPE in $AWS_REGION from AMI $ami"

  local assoc_flag
  if [[ "$AWS_ASSOC_PUBLIC_IP" == "true" ]]; then
    assoc_flag='{"AssociatePublicIpAddress":true}'
  else
    assoc_flag='{"AssociatePublicIpAddress":false}'
  fi

  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 run-instances \
    --image-id "$ami" \
    --count "$AWS_RUN_COUNT" \
    --instance-type "$AWS_INSTANCE_TYPE" \
    --key-name "$AWS_KEY_NAME" \
    --subnet-id "$AWS_SUBNET_ID" \
    --security-group-ids "$AWS_SECURITY_GROUP_ID" \
    --network-interfaces "DeviceIndex=0,SubnetId=$AWS_SUBNET_ID,Groups=[$AWS_SECURITY_GROUP_ID],AssociatePublicIpAddress=${AWS_ASSOC_PUBLIC_IP}" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=stack,Value=$AWS_TAG_STACK},{Key=role,Value=$AWS_RUN_ROLE}]" \
    --output table
}

# =============================================================================
# MAIN
# =============================================================================

TARGET="${TARGET:-proxmox-all}"

case "$TARGET" in
  # Existing Proxmox flows
  proxmox-all)        proxmox_all        ;;
  proxmox-cluster)    proxmox_cluster    ;;
  proxmox-k8s-ha)     proxmox_k8s_ha     ;;

  # New image-only / scaffold modes
  image-only)         image_only ;;           # (optional; you can add this later)
  packer-scaffold)    packer_scaffold ;;

  # AWS
  aws-ami|aws_ami)    aws_bake_ami ;;
  aws-run|aws_run)    aws_run_from_ami ;;

  # Firecracker
  firecracker-bundle) firecracker_bundle ;;
  firecracker)        firecracker_flow ;;

  # ESXi / VMDK (optional)
  vmdk-export)        export_vmdk ;;

  *)
    die "Unknown TARGET '$TARGET'. Expected: proxmox-all | proxmox-cluster | proxmox-k8s-ha | image-only | packer-scaffold | aws-ami | aws-run | firecracker-bundle | firecracker | vmdk-export"
    ;;
esac
