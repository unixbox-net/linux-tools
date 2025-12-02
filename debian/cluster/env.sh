#!/usr/bin/env bash
# cluster/env.sh - global environment & defaults for foundryBot cluster deploys

set -euo pipefail

# -----------------------------------------------------------------------------
# Repo / build roots
# -----------------------------------------------------------------------------
FOUNDRY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${BUILD_ROOT:-/root/builds}"
mkdir -p "$BUILD_ROOT"

# Domain for all VMs.
DOMAIN="${DOMAIN:-unixbox.net}"

# INPUT: logical Proxmox selector (maps to PROXMOX_HOST).
#   1|fiend, 2|dragon, 3|lion
INPUT="${INPUT:-1}"

case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *)        echo "Unknown INPUT=$INPUT (expected 1|fiend, 2|dragon, 3|lion)" >&2; exit 1 ;;
esac

# -----------------------------------------------------------------------------
# Preseed / installer behaviour (legacy netinst flow – still available)
# -----------------------------------------------------------------------------
# PRESEED_LOCALE: system locale.
PRESEED_LOCALE="${PRESEED_LOCALE:-en_US.UTF-8}"

# PRESEED_KEYMAP: console keymap (us, uk, de, fr, ca, se, ...).
PRESEED_KEYMAP="${PRESEED_KEYMAP:-us}"

# PRESEED_TIMEZONE: tzdata timezone.
PRESEED_TIMEZONE="${PRESEED_TIMEZONE:-America/Vancouver}"

# PRESEED_MIRROR_COUNTRY: "manual" or country code (CA, US, DE, ...).
PRESEED_MIRROR_COUNTRY="${PRESEED_MIRROR_COUNTRY:-manual}"

# PRESEED_MIRROR_HOST: HTTP mirror host, used when PRESEED_MIRROR_COUNTRY=manual.
PRESEED_MIRROR_HOST="${PRESEED_MIRROR_HOST:-deb.debian.org}"

# PRESEED_MIRROR_DIR: mirror directory (usually /debian).
PRESEED_MIRROR_DIR="${PRESEED_MIRROR_DIR:-/debian}"

# PRESEED_HTTP_PROXY: HTTP proxy for installer APT.
PRESEED_HTTP_PROXY="${PRESEED_HTTP_PROXY:-}"

# PRESEED_ROOT_PASSWORD: root password in installer.
PRESEED_ROOT_PASSWORD="${PRESEED_ROOT_PASSWORD:-root}"

# PRESEED_BOOTDEV: install target disk inside the VM. (LEGACY)
# NOTE: for the live ZFS installer we’ll use separate ZFS_* variables instead.
PRESEED_BOOTDEV="${PRESEED_BOOTDEV:-/dev/sda}"

# PRESEED_EXTRA_PKGS: extra packages to install during base install.
PRESEED_EXTRA_PKGS="${PRESEED_EXTRA_PKGS:-openssh-server}"

# -----------------------------------------------------------------------------
# High-level deployment target (used by bin/foundrybot, not core logic)
# -----------------------------------------------------------------------------
# TARGET is usually handled by the CLI wrapper; kept here for completeness.
TARGET="${TARGET:-proxmox-all}"

# -----------------------------------------------------------------------------
# ISO source / Proxmox storage IDs
# -----------------------------------------------------------------------------
# ISO_ORIG: base Debian installer ISO (legacy netinst path).
ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-netinst.iso}"

# ISO_STORAGE: Proxmox storage ID for ISO upload.
ISO_STORAGE="${ISO_STORAGE:-local}"

# VM_STORAGE: Proxmox storage ID for VM disks.
VM_STORAGE="${VM_STORAGE:-local-zfs}"

# -----------------------------------------------------------------------------
# Master hub VM (control plane / hub)
# -----------------------------------------------------------------------------
MASTER_ID="${MASTER_ID:-2000}"
MASTER_NAME="${MASTER_NAME:-master}"
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

# LAN network config for all nodes.
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"

# NAMESERVER: resolvers inside guests (space-separated).
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

# -----------------------------------------------------------------------------
# Core minion VMs (classic 4-node layout)
# -----------------------------------------------------------------------------
PROM_ID="${PROM_ID:-2001}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.223}"
GRAF_ID="${GRAF_ID:-2002}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.222}"
K8S_ID="${K8S_ID:-2003}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.221}"
STOR_ID="${STOR_ID:-2004}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.220}"

# Future multi-disk support for storage node (not yet wired in code):
# Example: STOR_DATA_DISKS="/dev/sdb /dev/sdc /dev/sdd"
STOR_DATA_DISKS="${STOR_DATA_DISKS:-}"

# -----------------------------------------------------------------------------
# WireGuard hub addresses (planes / fabrics)
# -----------------------------------------------------------------------------
# wg0–wg3 live on master; minions get /32s carved out of them.
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"

# Allowed CIDRs for WG.
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# -----------------------------------------------------------------------------
# Per-minion WireGuard /32s (PROM / GRAF / K8S / STOR)
# -----------------------------------------------------------------------------
PROM_WG0="${PROM_WG0:-10.77.0.2/32}"; PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; PROM_WG2="${PROM_WG2:-10.79.0.2/32}"; PROM_WG3="${PROM_WG3:-10.80.0.2/32}"
GRAF_WG0="${GRAF_WG0:-10.77.0.3/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; GRAF_WG2="${GRAF_WG2:-10.79.0.3/32}"; GRAF_WG3="${GRAF_WG3:-10.80.0.3/32}"
K8S_WG0="${K8S_WG0:-10.77.0.4/32}";  K8S_WG1="${K8S_WG1:-10.78.0.4/32}";  K8S_WG2="${K8S_WG2:-10.79.0.4/32}";  K8S_WG3="${K8S_WG3:-10.80.0.4/32}"
STOR_WG0="${STOR_WG0:-10.77.0.5/32}"; STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; STOR_WG2="${STOR_WG2:-10.79.0.5/32}"; STOR_WG3="${STOR_WG3:-10.80.0.5/32}"

# -----------------------------------------------------------------------------
# Extended K8s HA layout VMs (LBs, control-plane, workers)
# -----------------------------------------------------------------------------
K8SLB1_ID="${K8SLB1_ID:-2005}"; K8SLB1_NAME="${K8SLB1_NAME:-k8s-lb1}"; K8SLB1_IP="${K8SLB1_IP:-10.100.10.213}"
K8SLB2_ID="${K8SLB2_ID:-2006}"; K8SLB2_NAME="${K8SLB2_NAME:-k8s-lb2}"; K8SLB2_IP="${K8SLB2_IP:-10.100.10.212}"

K8SCP1_ID="${K8SCP1_ID:-2007}"; K8SCP1_NAME="${K8SCP1_NAME:-k8s-cp1}"; K8SCP1_IP="${K8SCP1_IP:-10.100.10.219}"
K8SCP2_ID="${K8SCP2_ID:-2008}"; K8SCP2_NAME="${K8SCP2_NAME:-k8s-cp2}"; K8SCP2_IP="${K8SCP2_IP:-10.100.10.218}"
K8SCP3_ID="${K8SCP3_ID:-2009}"; K8SCP3_NAME="${K8SCP3_NAME:-k8s-cp3}"; K8SCP3_IP="${K8SCP3_IP:-10.100.10.217}"

K8SW1_ID="${K8SW1_ID:-2010}"; K8SW1_NAME="${K8SW1_NAME:-k8s-w1}"; K8SW1_IP="${K8SW1_IP:-10.100.10.216}"
K8SW2_ID="${K8SW2_ID:-2011}"; K8SW2_NAME="${K8SW2_NAME:-k8s-w2}"; K8SW2_IP="${K8SW2_IP:-10.100.10.215}"
K8SW3_ID="${K8SW3_ID:-2012}"; K8SW3_NAME="${K8SW3_NAME:-k8s-w3}"; K8SW3_IP="${K8SW3_IP:-10.100.10.214}"

# Per-node WG /32s for K8s HA (extended layout – mostly “don’t touch”)
K8SLB1_WG0="${K8SLB1_WG0:-10.77.0.101/32}"; K8SLB1_WG1="${K8SLB1_WG1:-10.78.0.101/32}"; K8SLB1_WG2="${K8SLB1_WG2:-10.79.0.101/32}"; K8SLB1_WG3="${K8SLB1_WG3:-10.80.0.101/32}"
K8SLB2_WG0="${K8SLB2_WG0:-10.77.0.102/32}"; K8SLB2_WG1="${K8SLB2_WG1:-10.78.0.102/32}"; K8SLB2_WG2="${K8SLB2_WG2:-10.79.0.102/32}"; K8SLB2_WG3="${K8SLB2_WG3:-10.80.0.102/32}"

K8SCP1_WG0="${K8SCP1_WG0:-10.77.0.110/32}"; K8SCP1_WG1="${K8SCP1_WG1:-10.78.0.110/32}"; K8SCP1_WG2="${K8SCP1_WG2:-10.79.0.110/32}"; K8SCP1_WG3="${K8SCP1_WG3:-10.80.0.110/32}"
K8SCP2_WG0="${K8SCP2_WG0:-10.77.0.111/32}"; K8SCP2_WG1="${K8SCP2_WG1:-10.78.0.111/32}"; K8SCP2_WG2="${K8SCP2_WG2:-10.79.0.111/32}"; K8SCP2_WG3="${K8SCP2_WG3:-10.80.0.111/32}"
K8SCP3_WG0="${K8SCP3_WG0:-10.77.0.112/32}"; K8SCP3_WG1="${K8SCP3_WG1:-10.78.0.112/32}"; K8SCP3_WG2="${K8SCP3_WG2:-10.79.0.112/32}"; K8SCP3_WG3="${K8SCP3_WG3:-10.80.0.112/32}"

K8SW1_WG0="${K8SW1_WG0:-10.77.0.120/32}"; K8SW1_WG1="${K8SW1_WG1:-10.78.0.120/32}"; K8SW1_WG2="${K8SW1_WG2:-10.79.0.120/32}"; K8SW1_WG3="${K8SW1_WG3:-10.80.0.120/32}"
K8SW2_WG0="${K8SW2_WG0:-10.77.0.121/32}"; K8SW2_WG1="${K8SW2_WG1:-10.78.0.121/32}"; K8SW2_WG2="${K8SW2_WG2:-10.79.0.121/32}"; K8SW2_WG3="${K8SW2_WG3:-10.80.0.121/32}"
K8SW3_WG0="${K8SW3_WG0:-10.77.0.122/32}"; K8SW3_WG1="${K8SW3_WG1:-10.78.0.122/32}"; K8SW3_WG2="${K8SW3_WG2:-10.79.0.122/32}"; K8SW3_WG3="${K8SW3_WG3:-10.80.0.122/32}"

# -----------------------------------------------------------------------------
# VM sizing
# -----------------------------------------------------------------------------
MASTER_MEM="${MASTER_MEM:-4096}"
MASTER_CORES="${MASTER_CORES:-4}"
MASTER_DISK_GB="${MASTER_DISK_GB:-40}"

MINION_MEM="${MINION_MEM:-4096}"
MINION_CORES="${MINION_CORES:-4}"
MINION_DISK_GB="${MINION_DISK_GB:-32}"

# K8s nodes sizing (can be tuned for HA)
K8S_MEM="${K8S_MEM:-8192}"
K8S_LB_MEM="${K8S_LB_MEM:-2048}"
K8S_CP_MEM="${K8S_CP_MEM:-8192}"
K8S_WK_MEM="${K8S_WK_MEM:-8192}"

# -----------------------------------------------------------------------------
# Admin user / SSH defaults
# -----------------------------------------------------------------------------
ADMIN_USER="${ADMIN_USER:-todd}"

# ADMIN_PUBKEY_FILE: if set + readable, overrides SSH_PUBKEY.
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-}"

# SSH_PUBKEY: your default pubkey string.
# (Shortened here for clarity; in your real env, keep full key.)
SSH_PUBKEY="${SSH_PUBKEY:-ssh-ed25519 AAAA... todd@onyx.unixbox.net}"

# Allow or deny password SSH for ADMIN_USER.
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-${ALLOW_TODD_PASSWORD:-no}}"

# GUI profile for postinstall:
#   server  = no full desktop
#   gnome   = full GNOME
#   minimal = minimal GUI
GUI_PROFILE="${GUI_PROFILE:-server}"

# Install Ansible on master?
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"

# Semaphore (Ansible UI):
#   yes = install, try = best-effort, no = skip
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-no}"

TMUX_CONF="${TMUX_CONF:-/etc/skel/.tmux.conf}"

# -----------------------------------------------------------------------------
# Build artifacts / disk image paths
# -----------------------------------------------------------------------------
BASE_DISK_IMAGE="${BASE_DISK_IMAGE:-$BUILD_ROOT/base-root.qcow2}"
BASE_RAW_IMAGE="${BASE_RAW_IMAGE:-$BUILD_ROOT/base-root.raw}"
BASE_VMDK_IMAGE="${BASE_VMDK_IMAGE:-$BUILD_ROOT/base-root.vmdk}"

# -----------------------------------------------------------------------------
# AWS image bake / EC2 run
# -----------------------------------------------------------------------------
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_S3_BUCKET="${AWS_S3_BUCKET:-foundrybot-images}"
AWS_IMPORT_ROLE="${AWS_IMPORT_ROLE:-vmimport}"
AWS_ARCH="${AWS_ARCH:-x86_64}"

AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t3.micro}"
AWS_ASSOC_PUBLIC_IP="${AWS_ASSOC_PUBLIC_IP:-true}"
AWS_KEY_NAME="${AWS_KEY_NAME:-clusterkey}"
AWS_SECURITY_GROUP_ID="${AWS_SECURITY_GROUP_ID:-}"
AWS_SUBNET_ID="${AWS_SUBNET_ID:-}"

AWS_AMI_NAME="${AWS_AMI_NAME:-foundrybot-debian13}"
AWS_AMI_DESCRIPTION="${AWS_AMI_DESCRIPTION:-FoundryBot Debian 13 image}"
AWS_AMI_ID="${AWS_AMI_ID:-}"
AWS_RUN_ROLE="${AWS_RUN_ROLE:-None}"
AWS_RUN_COUNT="${AWS_RUN_COUNT:-1}"

# -----------------------------------------------------------------------------
# Firecracker configuration
# -----------------------------------------------------------------------------
FC_VCPUS="${FC_VCPUS:-2}"
FC_MEM_MB="${FC_MEM_MB:-2048}"

FC_ROOTFS_IMG="${FC_ROOTFS_IMG:-$BUILD_ROOT/firecracker/rootfs.ext4}"
FC_KERNEL="${FC_KERNEL:-$BUILD_ROOT/firecracker/vmlinux}"
FC_INITRD="${FC_INITRD:-$BUILD_ROOT/firecracker/initrd.img}"
FC_WORKDIR="${FC_WORKDIR:-$BUILD_ROOT/firecracker}"

# -----------------------------------------------------------------------------
# Packer configuration
# -----------------------------------------------------------------------------
PACKER_OUT_DIR="${PACKER_OUT_DIR:-$BUILD_ROOT/packer}"
PACKER_TEMPLATE="${PACKER_TEMPLATE:-$PACKER_OUT_DIR/foundrybot-qemu.json}"

# -----------------------------------------------------------------------------
# ESXi / VMDK export
# -----------------------------------------------------------------------------
VMDK_OUTPUT="${VMDK_OUTPUT:-$BASE_VMDK_IMAGE}"

# -----------------------------------------------------------------------------
# Enrollment SSH keypair (WireGuard / cluster enrollment)
# -----------------------------------------------------------------------------
ENROLL_KEY_NAME="${ENROLL_KEY_NAME:-enroll_ed25519}"
ENROLL_KEY_DIR="${ENROLL_KEY_DIR:-$BUILD_ROOT/keys}"
ENROLL_KEY_PRIV="${ENROLL_KEY_PRIV:-$ENROLL_KEY_DIR/${ENROLL_KEY_NAME}}"
ENROLL_KEY_PUB="${ENROLL_KEY_PUB:-$ENROLL_KEY_DIR/${ENROLL_KEY_NAME}.pub}"

mkdir -p "$ENROLL_KEY_DIR"

