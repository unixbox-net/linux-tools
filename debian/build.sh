#!/usr/bin/env bash
# build.sh — Debian 13 universal SB+TPM ZFS image builder (Proxmox + AWS)
# UEFI-only, ZFS-on-root with Boot Environments, UKI signing, Secure Boot, Sanoid
# Modes: proxmox-cluster | image-only | aws | packer-scaffold | firecracker-bundle
set -Eeuo pipefail
shopt -s extglob
trap 'rc=$?; echo; echo "[X] ${BASH_COMMAND@Q} failed at line ${LINENO} (rc=${rc})";
      { command -v nl >/dev/null && nl -ba "$0" | sed -n "$((LINENO-6)),$((LINENO+6))p"; } || true; exit $rc' ERR

# ==============================================================================
# 0) DRIVER MODE (env or positional)
# ==============================================================================
TARGET="${TARGET:-proxmox-cluster}"  # default; can be overridden by $1
if [ "${1:-}" ]; then TARGET="$1"; shift; fi  # allow ./build.sh image-only, etc.

# ==============================================================================
# 1) GLOBAL CONFIG
# ==============================================================================
INPUT="${INPUT:-1}"  # 1|fiend, 2|dragon, 3|lion
DOMAIN="${DOMAIN:-unixbox.net}"
case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) echo "[ERROR] Unknown INPUT=$INPUT" >&2; exit 1 ;;
esac

BUILD_ROOT="${BUILD_ROOT:-/root/builds}"; mkdir -p "$BUILD_ROOT"
DARKSITE_SUITE="${DARKSITE_SUITE:-trixie}"     # Debian 13
ARCH="${ARCH:-amd64}"

# Secure Boot keys (db.key/db.crt) — real keys preferred; temp keys auto-generated if missing
SB_KEY="${SB_KEY:-$BUILD_ROOT/keys/db.key}"
SB_CRT="${SB_CRT:-$BUILD_ROOT/keys/db.crt}"
UEFI_BLOB="${UEFI_BLOB:-$BUILD_ROOT/keys/blob.bin}"  # optional: UEFI var-store blob for AWS --uefi-data

# AWS
AWS_S3_BUCKET="${AWS_S3_BUCKET:-}"
AWS_AMI_NAME="${AWS_AMI_NAME:-debian13-sb-zfs-$(date +%F)}"
AWS_LT_NAME="${AWS_LT_NAME:-debian13-sb-zfs-lt}"
UNIVERSAL_QCOW2="${UNIVERSAL_QCOW2:-$BUILD_ROOT/universal.qcow2}"
UNIVERSAL_RAW="${UNIVERSAL_RAW:-$BUILD_ROOT/universal.raw}"

# ISO input/output
ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-netinst.iso}"
ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"
ROOT_SCHEME="${ROOT_SCHEME:-zfs}"

# Network (site)
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3}"

# WireGuard hub subnets/ports (master on .1; minions start at .10)
WG0_IP="${WG0_IP:-10.77.0.1/16}";  WG0_PORT="${WG0_PORT:-51820}"   # control
WG1_IP="${WG1_IP:-10.78.0.1/16}";  WG1_PORT="${WG1_PORT:-51821}"   # telemetry
WG2_IP="${WG2_IP:-10.79.0.1/16}";  WG2_PORT="${WG2_PORT:-51822}"   # build
WG3_IP="${WG3_IP:-10.80.0.1/16}";  WG3_PORT="${WG3_PORT:-51823}"   # storage
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# Role IDs/IPs
MASTER_ID="${MASTER_ID:-6010}"; MASTER_NAME="${MASTER_NAME:-master}"; MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
PROM_ID="${PROM_ID:-6011}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.123}"
GRAF_ID="${GRAF_ID:-6012}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.122}"
K8S_ID="${K8S_ID:-6013}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.121}"
STOR_ID="${STOR_ID:-6014}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.120}"

# Sizing
MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-8}"; MASTER_DISK_GB="${MASTER_DISK_GB:-20}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-20}"
K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

# Admin / ops
ADMIN_USER="${ADMIN_USER:-todd}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-/home/todd/.ssh/id_ed25519.pub}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
GUI_PROFILE="${GUI_PROFILE:-server}"   # server by default (no fluxbox)
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
ZFS_MOUNTPOINT="${ZFS_MOUNTPOINT:-/mnt/share}"

# ==============================================================================
# 2) UTILS + SANITY
# ==============================================================================
log()  { echo "[INFO]  $(date '+%F %T') - $*"; }
warn() { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err()  { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()  { err "$*"; exit 1; }

SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }
retry(){ local n="$1" s="$2"; shift 2; local i; for ((i=1;i<=n;i++)); do "$@" && return 0; sleep "$s"; done; return 1; }

validate_env_or_die() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
  case "$TARGET" in
    image-only|packer-scaffold|firecracker-bundle) local -a req=(BUILD_ROOT ISO_ORIG) ;;
    proxmox-cluster)                               local -a req=(BUILD_ROOT ISO_ORIG PROXMOX_HOST VM_STORAGE ISO_STORAGE) ;;
    aws)                                           local -a req=(BUILD_ROOT AWS_S3_BUCKET) ;;
    *)                                             local -a req=(BUILD_ROOT ISO_ORIG) ;;
  esac
  local -a miss=(); for v in "${req[@]}"; do [[ -n "${!v:-}" ]] || miss+=("$v"); done
  ((${#miss[@]}==0)) || die "missing: ${miss[*]}"
  [[ -r "$ISO_ORIG" ]] || { [[ "$TARGET" == aws ]] || die "ISO_ORIG not readable: $ISO_ORIG"; }
  mkdir -p "$BUILD_ROOT" "$BUILD_ROOT/keys"
}
validate_env_or_die

mask_to_cidr(){ awk -v m="$1" 'BEGIN{split(m,a,".");c=0;for(i=1;i<=4;i++){x=a[i]+0;for(j=7;j>=0;j--) if((x>>j)&1) c++; else break}print c}'; }

# ----------------------------------------------------------------------
# PROXMOX VM: q35 + OVMF (UEFI), EFI vars in Setup Mode, TPM v2 ON
# ----------------------------------------------------------------------
pmx(){ sssh root@"${PROXMOX_HOST}" "$@"; }
pmx_vm_state(){ pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }
pmx_wait_for_state(){ local id="$1" want="$2" t="${3:-2400}" s=$(date +%s) st; while :; do st="$(pmx_vm_state "$id")"; [[ "$st" == "$want" ]] && return 0; (( $(date +%s)-s > t )) && return 1; sleep 5; done; }
pmx_upload_iso(){ local iso="$1" base; base="$(basename "$iso")"
  sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base" || { sleep 2; sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base"; }
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${base}\" && exit 0; sleep 1; done; exit 0" || true
  echo "$base"; }
pmx_deploy_uefi(){ # id name iso mem cores disk_gb
  local vmid="$1" name="$2" iso="$3" mem="$4" cores="$5" disk_gb="$6"
  local base; base="$(pmx_upload_iso "$iso")"
  pmx VMID="$vmid" VMNAME="${name}.${DOMAIN}-$vmid" FINAL_ISO="$base" VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
qm destroy "$VMID" --purge >/dev/null 2>&1 || true
qm create "$VMID" --name "$VMNAME" --machine q35 --bios ovmf --ostype l26 \
  --agent enabled=1,fstrim_cloned_disks=1 --memory "$MEMORY_MB" --cores "$CORES" \
  --scsihw virtio-scsi-single --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB},ssd=1,discard=on,iothread=1 \
  --net0 virtio,bridge=vmbr0,firewall=1 --serial0 socket --rng0 source=/dev/urandom
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0
qm set "$VMID" --tpmstate0 ${VM_STORAGE}:1,version=v2.0
for i in {1..10}; do qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom && break || sleep 1; done
qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}
wait_poweroff(){ pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }
boot_from_disk_uefi(){ local id="$1"; pmx "qm set $id --delete ide2; qm set $id --boot order=scsi0; qm start $id"; pmx_wait_for_state "$id" "running" 600; }

# ==============================================================================
# DARKSITE REPO (APT + offline extras)
# ==============================================================================
: "${ARCH:=amd64}"
: "${DARKSITE_SUITE:=trixie}"
: "${DARKSITE:=/root/builds/darksite}"

build_dark_repo() {
  local out="$1" arch="${2:-$ARCH}" suite="${3:-$DARKSITE_SUITE}"
  [[ -n "$out" ]] || { echo "[X] build_dark_repo: outdir required" >&2; return 2; }
  rm -f "$out/.stamp" 2>/dev/null || true
  rm -rf "$out"; mkdir -p "$out" "$out/extras" "$out/45wg"
  docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive -e SUITE="$suite" -e ARCH="$arch" \
    -e BASE_PACKAGES="apt apt-utils openssh-server wireguard-tools nftables qemu-guest-agent \
dracut systemd-boot-efi systemd-ukify sbsigntool tpm2-tools mokutil efitools efivar \
zfsutils-linux zfs-dkms zfs-dracut dkms build-essential linux-headers-amd64 linux-image-amd64 \
sudo ca-certificates curl wget jq unzip tar xz-utils iproute2 iputils-ping ethtool tcpdump net-tools chrony rsyslog \
bpftrace bpfcc-tools perf-tools-unstable sysstat strace lsof xorriso syslinux ansible nginx \
sanoid syncoid debsums" \
    -v "$out:/repo" "debian:${suite}" bash -lc '
set -euo pipefail
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${SUITE} main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${SUITE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free non-free-firmware
EOF
echo "Acquire::Languages \"none\";" >/etc/apt/apt.conf.d/99nolangs
apt-get update -y
apt-get install -y --no-install-recommends apt apt-utils dpkg-dev apt-rdepends gnupg
tmp_list=$(mktemp)
apt-rdepends $BASE_PACKAGES 2>/dev/null | awk "/^[A-Za-z0-9][A-Za-z0-9+.-]*$/{print}" | sort -u >"$tmp_list"
: > /tmp/want.lock
while read -r pkg; do cand=$(apt-cache policy "$pkg" | awk "/Candidate:/{print \$2}"); if [ -n "${cand:-}" ] && [ "$cand" != "(none)" ]; then echo "$pkg=$cand" >> /tmp/want.lock; fi; done <"$tmp_list"
work=/tmp/aptdownload; install -d -m0777 "$work"; chown _apt:_apt "$work" 2>/dev/null || true
runuser -u _apt -- bash -lc "cd \"$work\"; while read -r pv; do apt-get download \"\$pv\" || apt-get download \"\${pv%%=*}\"; done </tmp/want.lock"
mkdir -p /repo/pool/main
mv -f "$work"/*.deb /repo/pool/main/ 2>/dev/null || true
for sec in main extra; do mkdir -p /repo/dists/${SUITE}/${sec}/binary-${ARCH} /repo/dists/${SUITE}/${sec}/binary-all; done
apt-ftparchive packages /repo/pool/main > /repo/dists/${SUITE}/main/binary-${ARCH}/Packages
gzip -9fk  /repo/dists/${SUITE}/main/binary-${ARCH}/Packages
xz   -T0 -9e -f /repo/dists/${SUITE}/main/binary-${ARCH}/Packages
cp -a /repo/dists/${SUITE}/main/binary-${ARCH}/Packages* /repo/dists/${SUITE}/main/binary-all/ || : > /repo/dists/${SUITE}/main/binary-all/Packages
cat > /tmp/aptconf <<APTCONF
Dir { ArchiveDir "/repo"; };
Default { Packages::Compress ". gz xz"; };
APTCONF
apt-ftparchive -c /tmp/aptconf release /repo/dists/${SUITE} > /repo/dists/${SUITE}/Release
chmod -R a+rX /repo
echo "[OK] Dark repo ready"
'
  echo "[OK] built APT darksite at: $out"
}

darksite_stage_extras() {
  local out="$1"; shift || true
  [[ -n "${out:-}" ]] || { echo "[X] darksite_stage_extras: outdir required" >&2; return 2; }
  mkdir -p "$out/extras"
  [ "$#" -gt 0 ] || { echo "[i] darksite_stage_extras: no extras provided; skipping"; return 0; }
  for src in "$@"; do
    if [ -d "$src" ]; then rsync -a --delete "$src"/ "$out/extras/$(basename "$src")"/
    elif [ -f "$src" ]; then install -D -m0644 "$src" "$out/extras/$(basename "$src")"
    else echo "[WARN] darksite_stage_extras: missing path: $src" >&2; fi
  done
  chmod -R a+rX "$out/extras"
  echo "[OK] staged extras into: $out/extras"
}

darksite_fetch_repos() {
  local out="$1"; shift || true
  [[ -n "${out:-}" ]] || { echo "[X] darksite_fetch_repos: outdir required" >&2; return 2; }
  local vend="$out/extras/vendor"; mkdir -p "$vend"
  local manifest="$vend/_manifest.tsv"; : > "$manifest"
  while [ "$#" -gt 0 ]; do
    local spec="$1"; shift
    local url="${spec%@*}"; local ref=""; [[ "$spec" == *@* ]] && ref="${spec##*@}"
    local name="$(basename "${url%.git}")"; local tmpd; tmpd="$(mktemp -d)"
    echo "[*] Fetching $url ${ref:+(@ $ref)}"
    git clone --depth 1 ${ref:+--branch "$ref"} "$url" "$tmpd/$name"
    ( cd "$tmpd/$name" && git rev-parse HEAD ) > "$tmpd/$name/.git-rev"
    tar -C "$tmpd" -czf "$vend/${name}.tar.gz" "$name"
    echo -e "$name\t$url\t${ref:-HEAD}\t$(cat "$tmpd/$name/.git-rev")\t$(date -u +%F)" >> "$manifest"
    rm -rf "$tmpd"
  done
  chmod -R a+rX "$vend"
  echo "[OK] vendored repos -> $vend (manifest: $(wc -l < "$manifest") entries)"
}

# ==============================================================================
# Secure Boot keys (db.key/db.crt) & UEFI blob placeholders
# ==============================================================================
emit_sb_keys_if_missing(){
  mkdir -p "$(dirname "$SB_KEY")"
  if [[ ! -s "$SB_KEY" || ! -s "$SB_CRT" ]]; then
    log "[*] Generating TEMP Secure Boot signing keypair (db.key/db.crt) — replace with real keys!"
    openssl req -new -x509 -newkey rsa:3072 -keyout "$SB_KEY" -out "$SB_CRT" -days 3650 -nodes -subj "/CN=unixbox-db/"
    chmod 600 "$SB_KEY"; chmod 644 "$SB_CRT"
  fi
  if [[ ! -s "$UEFI_BLOB" ]]; then
    warn "[!] No UEFI var-store blob at $UEFI_BLOB. You can still boot with platform keys or shim+MOK."
  fi
}

# ==============================================================================
# Dracut module: WireGuard pre-mount (Stage-0) — optional
# ==============================================================================
emit_wg_dracut(){
  local out="$1"; mkdir -p "$out/45wg"
  cat >"$out/45wg/module-setup.sh" <<'__WGSETUP__'
#!/bin/bash
check(){ return 0; }
depends(){ echo "zfs network"; }
install(){
  inst_multiple wg wg-quick ip jq curl awk sed tpm2_unseal
  inst_simple "$moddir/wg-pre-mount.sh" /sbin/wg-pre-mount.sh
  mkdir -p "$initdir/etc/dracut/hooks/pre-mount"
  printf '%s\n' '/sbin/wg-pre-mount.sh' > "$initdir/etc/dracut/hooks/pre-mount/10-wg.sh"
}
__WGSETUP__
  chmod +x "$out/45wg/module-setup.sh"
  cat >"$out/45wg/wg-pre-mount.sh" <<'__WGPRERUN__'
#!/bin/sh
set -eu
TOKEN="$(curl -sX PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token || true)"
IID="$(curl -sH "X-aws-ec2-metadata-token: ${TOKEN:-}" http://169.254.169.254/latest/dynamic/instance-identity/document || true)" || true
if [ -s /etc/wireguard/wg0.key.sealed ]; then
  tpm2_unseal -c /etc/wireguard/wg0.key.sealed -o /run/wg.key || true
fi
PRIV=""
[ -s /run/wg.key ] && PRIV="$(cat /run/wg.key)" || PRIV="$(cat /etc/wireguard/wg0.key 2>/dev/null || echo '')"
mkdir -p /etc/wireguard
cat >/etc/wireguard/wg0.conf <<CFG
[Interface]
PrivateKey = ${PRIV}
Address    = 10.77.0.10/32
DNS        = 1.1.1.1
MTU        = 1420
SaveConfig = false
[Peer]
PublicKey  = REPLACE_HUB_PUBKEY
Endpoint   = hub.example:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CFG
wg-quick up wg0 || true
exit 0
__WGPRERUN__
  chmod +x "$out/45wg/wg-pre-mount.sh"
}

# ==============================================================================
# ZFS boot-environment toolkit & hooks (installed in target by late.sh)
# ==============================================================================
emit_zfs_be_toolkit(){
  local out_dir="$1"; mkdir -p "$out_dir/be"
  # zfs-bectl
  cat >"$out_dir/be/zfs-bectl" <<'__BECTL__'
#!/usr/bin/env bash
# zfs-bectl — tiny ZFS boot environment manager for systemd-boot + UKI
set -euo pipefail
SB_KEY="${SB_KEY:-/root/darksite/db.key}"
SB_CRT="${SB_CRT:-/root/darksite/db.crt}"

pool_bootfs() { zpool get -H -o value bootfs rpool; }
current_be()  { pool_bootfs | awk -F/ '{print $3}'; }
rootds_of()   { echo "rpool/ROOT/$1"; }

build_sign_uki() {
  local be="$1" rootds="rpool/ROOT/$1"
  local kver
  kver="$(uname -r || ls /lib/modules | sort -V | tail -1)"
  local out="/boot/efi/EFI/Linux/${be}-${kver}.efi"
  mkdir -p /boot/efi/EFI/Linux
  ukify build \
    --linux "/usr/lib/kernel/vmlinuz-${kver}" \
    --initrd "/boot/initrd.img-${kver}" \
    --cmdline "root=ZFS=${rootds} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${out}"
  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then
    sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${out}" "${out}"
  fi
  cat >/boot/loader/entries/debian.conf <<EOF
title   Debian ${be}
linux   ${out#/boot/efi}
EOF
  bootctl update || true
}

cmd="${1:-}"; shift || true
case "${cmd}" in
  list)
    zfs list -H -o name | awk '/^rpool\/ROOT\//'
    ;;
  create)
    be="${1:?usage: zfs-bectl create <be-name>}"
    cur="$(current_be)"
    snap="pre-clone-$(date +%Y%m%d%H%M%S)"
    zfs snapshot "rpool/ROOT/${cur}@${snap}"
    zfs clone   "rpool/ROOT/${cur}@${snap}" "$(rootds_of "$be")"
    zfs set canmount=noauto "$(rootds_of "$be")"
    build_sign_uki "$be"
    echo "[OK] created $be"
    ;;
  activate)
    be="${1:?usage: zfs-bectl activate <be>}"
    zpool set bootfs="$(rootds_of "$be")" rpool
    build_sign_uki "$be"
    echo "[OK] activated $be"
    ;;
  destroy)
    be="${1:?usage: zfs-bectl destroy <be>}"
    zfs destroy -r "$(rootds_of "$be")"
    echo "[OK] destroyed $be"
    ;;
  rollback)
    spec="${1:?usage: zfs-bectl rollback <be@snap>}"
    be="${spec%@*}"; snap="${spec##*@}"
    zfs rollback -r "$(rootds_of "$be")@${snap}"
    build_sign_uki "$be"
    echo "[OK] rolled back ${be} to @${snap}"
    ;;
  *)
    echo "Usage: zfs-bectl {list|create|activate|destroy|rollback}" >&2
    exit 2
    ;;
esac
__BECTL__
  chmod +x "$out_dir/be/zfs-bectl"

  # APT snapshot hook
  cat >"$out_dir/be/90-zfs-snapshots" <<'__SNAPHK__'
DPKg::Pre-Invoke  { "if command -v zfs >/dev/null 2>&1; then root=$(zpool get -H -o value bootfs rpool 2>/dev/null); ts=$(date +%Y%m%d%H%M%S); [ -n \"$root\" ] && zfs snapshot ${root}@apt-pre-${ts} || true; fi"; };
DPkg::Post-Invoke { "if command -v zfs >/dev/null 2>&1; then root=$(zpool get -H -o value bootfs rpool 2>/dev/null); ts=$(date +%Y%m%d%H%M%S); [ -n \"$root\" ] && zfs snapshot ${root}@apt-post-${ts} || true; fi"; };
__SNAPHK__

  # Kernel postinst UKI builder/sign
  cat >"$out_dir/be/zz-uki-sign" <<'__UKIHOOK__'
#!/bin/sh
set -eu
SB_KEY="${SB_KEY:-/root/darksite/db.key}"
SB_CRT="${SB_CRT:-/root/darksite/db.crt}"
POOL="${POOL:-rpool}"
BE="$(zpool get -H -o value bootfs "${POOL}" | awk -F/ '{print $3}')"
KVER="${1:-$(uname -r)}"
OUT="/boot/efi/EFI/Linux/${BE}-${KVER}.efi"

if command -v ukify >/dev/null 2>&1; then
  ukify build \
    --linux "/usr/lib/kernel/vmlinuz-${KVER}" \
    --initrd "/boot/initrd.img-${KVER}" \
    --cmdline "root=ZFS=${POOL}/ROOT/${BE} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${OUT}" || true
  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then
    sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${OUT}" "${OUT}" || true
  fi
  cat >/boot/loader/entries/debian.conf <<EOF2
title   Debian ${BE}
linux   ${OUT#/boot/efi}
EOF2
  bootctl update || true
fi
exit 0
__UKIHOOK__
  chmod +x "$out_dir/be/zz-uki-sign"
}

emit_darksite_payload() {
  local dark="${1:?darksite-dir-required}"
  mkdir -p "$dark"

  # ---------------------------------------------------------------------------
  # late.sh - runs inside d-i as preseed/late_command
  # Responsibilities:
  #   - Copy /cdrom/darksite into /target/root/darksite
  #   - Install bootstrap.service into /target
  #   - Enable bootstrap.service via symlink
  #   - Log everything to /target/var/log/bootstrap-setup.log
  #   - Power off cleanly so Proxmox can flip to boot-from-disk
  # ---------------------------------------------------------------------------
  cat >"$dark/late.sh" <<"__LATE__"
#!/bin/sh
set -eu

LOG=/target/var/log/bootstrap-setup.log
mkdir -p "$(dirname "$LOG")"
# d-i environment; /target exists and is mounted
{
  echo "[LATE] starting darksite late.sh at $(date -Is)"
  echo "[LATE] pwd: $(pwd)"
  echo "[LATE] ls /cdrom:"
  ls -al /cdrom || true

  # Copy darksite payload into installed system
  mkdir -p /target/root
  if [ -d /cdrom/darksite ]; then
    rm -rf /target/root/darksite 2>/dev/null || true
    cp -a /cdrom/darksite /target/root/
    echo "[LATE] copied /cdrom/darksite -> /target/root/darksite"
  else
    echo "[LATE][WARN] /cdrom/darksite missing"
  fi

  # Install bootstrap.service into /target
  if [ -f /target/root/darksite/bootstrap.service ]; then
    mkdir -p /target/etc/systemd/system
    cp /target/root/darksite/bootstrap.service \
       /target/etc/systemd/system/bootstrap.service
    echo "[LATE] installed /etc/systemd/system/bootstrap.service"
    # enable by hand (don't depend on systemctl)
    mkdir -p /target/etc/systemd/system/multi-user.target.wants
    ln -sf /etc/systemd/system/bootstrap.service \
       /target/etc/systemd/system/multi-user.target.wants/bootstrap.service
    echo "[LATE] enabled bootstrap.service"
  else
    echo "[LATE][WARN] bootstrap.service not found in darksite"
  fi

  echo "[LATE] late.sh finished; syncing + powering off"
} >>"$LOG" 2>&1

sync
poweroff -f
__LATE__
  chmod +x "$dark/late.sh"

  # ---------------------------------------------------------------------------
  # bootstrap.service - runs on FIRST BOOT of ext4 system
  # It executes /root/darksite/postinstall.sh ONCE, then disables itself.
  # ---------------------------------------------------------------------------
  cat >"$dark/bootstrap.service" <<"__BOOTSTRAP__"
[Unit]
Description=One-shot bootstrap for darksite postinstall (ZFS conversion, etc)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/darksite/postinstall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
__BOOTSTRAP__

  # ---------------------------------------------------------------------------
  # postinstall.sh - first boot, still on ext4
  # Responsibilities:
  #   - Write logs to /var/log/bootstrap.log
  #   - Run convert-to-zfs.sh (which does the heavy ZFS work)
  #   - If successful, disable bootstrap.service and reboot
  # ---------------------------------------------------------------------------
  cat >"$dark/postinstall.sh" <<"__POST__"
#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/bootstrap.log
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "[POST] bootstrap starting at $(date -Is)"
echo "[POST] uname: $(uname -a)"

if mount | grep -q ' on / type zfs '; then
  echo "[POST] Root already on ZFS; nothing to do. Disabling bootstrap.service."
  systemctl disable bootstrap.service || true
  exit 0
fi

if [ ! -x /root/darksite/convert-to-zfs.sh ]; then
  echo "[POST][X] /root/darksite/convert-to-zfs.sh missing or not executable"
  exit 1
fi

# Run the conversion; it will log aggressively to /var/log/convert-to-zfs.log
echo "[POST] Invoking convert-to-zfs.sh ..."
if /root/darksite/convert-to-zfs.sh; then
  echo "[POST] convert-to-zfs.sh completed successfully."
  echo "[POST] Disabling bootstrap.service and rebooting to new ZFS root."
  systemctl disable bootstrap.service || true
  sleep 2
  systemctl reboot
else
  rc=$?
  echo "[POST][X] convert-to-zfs.sh failed (rc=$rc). Keeping bootstrap.service enabled."
  echo "[POST] Inspect /var/log/convert-to-zfs.log and fix issues, then re-run manually."
  exit $rc
fi
__POST__
  chmod +x "$dark/postinstall.sh"

  # ---------------------------------------------------------------------------
  # convert-to-zfs.sh - **THIS IS WHERE THE MAGIC HAPPENS**
  # - Runs on first boot under ext4 root
  # - Creates rpool (single-disk) on current root partition
  # - Copies system into rpool/ROOT/debian
  # - Configures systemd-boot with a unified kernel image
  # - Reboots via postinstall.sh
  # NOTE: This assumes a single disk /dev/vda with:
  #   - /dev/vda1 = EFI System Partition (vfat)
  #   - /dev/vda2 = ext4 root (what d-i created)
  # You can extend cases for /dev/sda, NVMe, etc.
  # ---------------------------------------------------------------------------
  cat >"$dark/convert-to-zfs.sh" <<"__C2Z__"
#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/convert-to-zfs.log
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "[C2Z] ==========================================================="
echo "[C2Z] convert-to-zfs.sh starting at $(date -Is)"
echo "[C2Z] Running kernel: $(uname -r)"
echo "[C2Z] ==========================================================="

# Safety checks
if mount | grep -q ' on / type zfs '; then
  echo "[C2Z] Root already on ZFS; aborting."
  exit 0
fi

if ! command -v findmnt >/dev/null 2>&1; then
  echo "[C2Z][X] findmnt not available; cannot safely detect root device."
  exit 1
fi

ROOTSRC="$(findmnt -no SOURCE / || true)"
FSTYPE="$(findmnt -no FSTYPE / || true)"
echo "[C2Z] Current root device: $ROOTSRC (fstype=$FSTYPE)"

if [ -z "$ROOTSRC" ] || [ "$FSTYPE" != "ext4" ]; then
  echo "[C2Z][X] Expected ext4 root; got '$FSTYPE' on '$ROOTSRC'"
  exit 1
fi

DISK=""
PART_SUFFIX=""
case "$ROOTSRC" in
  /dev/vd[a-z]2)
    DISK="${ROOTSRC%2}"
    PART_SUFFIX=""
    ;;
  /dev/sd[a-z]2)
    DISK="${ROOTSRC%2}"
    PART_SUFFIX=""
    ;;
  /dev/nvme*n1p2)
    DISK="${ROOTSRC%p2}"
    PART_SUFFIX="p"
    ;;
  *)
    echo "[C2Z][X] Unsupported root device layout: $ROOTSRC"
    echo "[C2Z] Add a case for it in convert-to-zfs.sh and re-run."
    exit 1
    ;;
esac

ESP="${DISK}${PART_SUFFIX}1"
ZPART="$ROOTSRC"
POOL="rpool"

echo "[C2Z] Base disk: $DISK"
echo "[C2Z] ESP partition: $ESP"
echo "[C2Z] ZFS data partition: $ZPART"

# Ensure required tools
echo "[C2Z] Installing required packages (zfs, dracut, ukify, systemd-boot)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  zfs-dkms zfsutils-linux zfs-dracut \
  dracut systemd-boot-efi \
  efivar efitools sbsigntool mokutil \
  rsync jq xz-utils curl wget ca-certificates

modprobe zfs || true

echo "[C2Z] Preparing tmpfs for pivot_root..."
mkdir -p /mnt/newroot /mnt/oldroot

if mountpoint -q /mnt/newroot; then
  echo "[C2Z][WARN] /mnt/newroot already mounted; reusing"
else
  mount -t tmpfs -o size=2G tmpfs /mnt/newroot
fi

echo "[C2Z] Rsyncing current root into /mnt/newroot (this may take a while)..."
rsync -aHAX --numeric-ids \
  --exclude="/mnt/*" \
  --exclude="/proc/*" \
  --exclude="/sys/*" \
  --exclude="/dev/*" \
  --exclude="/run/*" \
  --exclude="/tmp/*" \
  / /mnt/newroot/

echo "[C2Z] Bind-mounting /dev, /proc, /sys into new root..."
mount --rbind /dev  /mnt/newroot/dev
mount --rbind /proc /mnt/newroot/proc
mount --rbind /sys  /mnt/newroot/sys
mount --make-rprivate /mnt/newroot/dev || true
mount --make-rprivate /mnt/newroot/proc || true
mount --make-rprivate /mnt/newroot/sys || true

echo "[C2Z] Performing pivot_root to tmpfs..."
cd /mnt/newroot
pivot_root . mnt/oldroot

echo "[C2Z] Now running with new root on tmpfs; old root is at /mnt/oldroot"
mount | grep "on / " || true

# Inside pivoted root now
echo "[C2Z] Unmounting old root filesystems so we can reuse $ZPART for ZFS..."
umount -lf /mnt/oldroot/proc  2>/dev/null || true
umount -lf /mnt/oldroot/sys   2>/dev/null || true
umount -lf /mnt/oldroot/dev   2>/dev/null || true
umount -lf /mnt/oldroot/run   2>/dev/null || true
umount -lf /mnt/oldroot/boot/efi 2>/dev/null || true
umount -lf /mnt/oldroot       2>/dev/null || true

echo "[C2Z] Creating ZFS pool on $ZPART ..."
zpool destroy "$POOL" 2>/dev/null || true
zpool create -f \
  -o ashift=12 \
  -O acltype=posixacl -O xattr=sa -O dnodesize=auto \
  -O compression=zstd \
  -O relatime=on \
  -O canmount=off -O mountpoint=/ \
  "$POOL" "$ZPART"

echo "[C2Z] Creating dataset layout..."
zfs create -o canmount=off -o mountpoint=none "$POOL/ROOT"
zfs create -o canmount=noauto -o mountpoint=/ "$POOL/ROOT/debian"
zfs mount "$POOL/ROOT/debian"

# Copy system into ZFS root
echo "[C2Z] Rsyncing system into ZFS dataset /$POOL/ROOT/debian..."
rsync -aHAX --numeric-ids \
  --exclude="/proc/*" \
  --exclude="/sys/*" \
  --exclude="/dev/*" \
  --exclude="/run/*" \
  --exclude="/tmp/*" \
  / /"$POOL"/ROOT/debian/

# ESP handling
echo "[C2Z] Mounting ESP $ESP into /$POOL/ROOT/debian/boot/efi..."
mkdir -p /"$POOL"/ROOT/debian/boot/efi
mount "$ESP" /"$POOL"/ROOT/debian/boot/efi

ESP_UUID="$(blkid -s UUID -o value "$ESP" || true)"
if [ -n "$ESP_UUID" ]; then
  echo "[C2Z] Writing /etc/fstab with ESP UUID=$ESP_UUID"
  cat > /"$POOL"/ROOT/debian/etc/fstab <<EOF
UUID=${ESP_UUID} /boot/efi vfat umask=0077 0 1
EOF
else
  echo "[C2Z][WARN] Could not obtain ESP UUID; please fix /etc/fstab manually."
fi

echo "[C2Z] Setting bootfs property..."
zpool set bootfs="$POOL/ROOT/debian" "$POOL"

# Chroot into new ZFS root to build initrd + unified kernel & systemd-boot
echo "[C2Z] Chrooting into ZFS root to build initrd + systemd-boot entry..."
chroot /"$POOL"/ROOT/debian /usr/bin/env bash -eux <<'EOCH'
export DEBIAN_FRONTEND=noninteractive

# Make sure dracut + zfs dracut bits are in place
apt-get update -y
apt-get install -y --no-install-recommends \
  dracut zfs-dracut systemd-boot-efi linux-image-amd64 linux-headers-amd64

KVER="$(uname -r || ls /lib/modules | sort -V | tail -1)"
echo "[C2Z-CHROOT] Using kernel version: ${KVER}"

dracut --force "/boot/initrd.img-${KVER}" "${KVER}"

mkdir -p /boot/efi/EFI/Linux

if command -v ukify >/dev/null 2>&1; then
  echo "[C2Z-CHROOT] Building unified kernel image with ukify..."
  ukify build \
    --linux "/boot/vmlinuz-${KVER}" \
    --initrd "/boot/initrd.img-${KVER}" \
    --cmdline "root=ZFS=rpool/ROOT/debian systemd.force_fsck=yes" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "/boot/efi/EFI/Linux/debian-${KVER}.efi" || true
else
  echo "[C2Z-CHROOT][WARN] ukify not found; systemd-boot may need manual tweaking."
fi

bootctl install || true
bootctl update  || true

cat >/boot/loader/entries/zfs-root.conf <<EOF2
title   Debian (ZFS root)
linux   /EFI/Linux/debian-${KVER}.efi
options root=ZFS=rpool/ROOT/debian
EOF2

cat >/boot/loader/loader.conf <<EOF2
default zfs-root.conf
timeout 3
EOF2

EOCH

echo "[C2Z] ZFS conversion finished; new root is rpool/ROOT/debian."
echo "[C2Z] Handing control back to postinstall.sh (which will reboot)."
__C2Z__
  chmod +x "$dark/convert-to-zfs.sh"
}


# ==============================================================================
# *** EARLY INSTALLER (RUNS INSIDE d-i) — minimal ext4; ZFS migration after 1st boot ***
# ==============================================================================
emit_early_zfs_install_be_script() {
  local out="$1"
  install -D -m0755 /dev/null "$out"

  cat >"$out" <<"__EARLYZFS__"
#!/bin/sh
#
#
# Run from *inside the installer chroot* via:
#
# It assumes:
#   - running on trixie
#   - / is still the d-i target root (i.e. /target for the installer)
#   - /cdrom is mounted with darksite packages
#
# It will:
#   - Wipe /dev/sda (override with ZFS_DISK env if needed)
#   - Partition it GPT: ESP, bpool, rpool
#   - Create bpool & rpool following the trixie HOWTO
#   - debootstrap a fresh trixie into /mnt/zfs-root
#   - Configure ZFS, GRUB, systemd units
#   - Replace current root with the ZFS root
#
# WARNING: This *DESTROYS* the selected disk.

set -eu

### --- CONFIG ----------------------------------------------------------------

ZFS_DISK="${ZFS_DISK:-/dev/sda}"
ZFS_HOSTNAME="${ZFS_HOSTNAME:-master}"
ZFS_RELEASE="${ZFS_RELEASE:-trixie}i"
ZFS_POOL_BPOOL="bpool"
ZFS_POOL_RPOOL="rpool"


### --- LOGGING ---------------------------------------------------------------

mkdir -p "$(dirname "$LOGFILE")"
# Tee all output into logfile
exec > >(tee -a "$LOGFILE") 2>&1

log() {
}

fatal() {
  log "FATAL: $*"
  exit 1
}

run() {
  log "+ $*"
  "$@"
}

log "==================================================================="

### --- BASIC SANITY ----------------------------------------------------------

[ "$(id -u)" -eq 0 ] || fatal "Script must be run as root."
[ -b "$ZFS_DISK" ] || fatal "Disk $ZFS_DISK is not a block device."

# We expect d-i to have mounted the target at / (because of in-target).
# But we *do not* trust what it did to the disk; we're going to wipe it.
if [ -d /target ]; then
  fatal "This script must be run *inside* in-target (chroot); got /target present."
fi

# Make sure essential tools are present (they should be in your darksite repo)
NEEDED_CMDS="sgdisk zpool zfs debootstrap mkfs.vfat mkfs.ext4 grub-install update-initramfs update-grub"
MISSING=""
for c in $NEEDED_CMDS; do
  if ! command -v "$c" >/dev/null 2>&1; then
    MISSING="$MISSING $c"
  fi
done

if [ -n "$MISSING" ]; then
  fatal "Missing required commands (ensure darksite packages installed):$MISSING"
fi

### --- STEP 0: ensure ZFS module is loaded -----------------------------------

if ! lsmod | grep -q '^zfs'; then
  run modprobe zfs || fatal "Failed to modprobe zfs"
fi

### --- STEP 1: DESTROY EXISTING LAYOUT ---------------------------------------

log "STEP 1: Wiping existing partition table on $ZFS_DISK"
run swapoff -a || true

# Best-effort wipefs, then zap with sgdisk:
run wipefs -a "$ZFS_DISK" || true
run sgdisk --zap-all "$ZFS_DISK"

# Ask kernel to re-read:
run partprobe "$ZFS_DISK" || true
sleep 2

### --- STEP 2: Partition disk (trixie HOWTO style) -------------------------

log "STEP 2: Creating GPT partition scheme"

# 1: (optional) BIOS boot (we keep it tiny; won't hurt)
run sgdisk -a1 -n1:24K:+1000K -t1:EF02 "$ZFS_DISK"

# 2: ESP 512M (UEFI)
run sgdisk -n2:1M:+512M   -t2:EF00 "$ZFS_DISK"

# 3: bpool 1G
run sgdisk -n3:0:+1G      -t3:BF01 "$ZFS_DISK"

# 4: rpool rest
run sgdisk -n4:0:0        -t4:BF00 "$ZFS_DISK"

run partprobe "$ZFS_DISK" || true
sleep 2

ESP_PART="${ZFS_DISK}2"
BPOOL_PART="${ZFS_DISK}3"
RPOOL_PART="${ZFS_DISK}4"

[ -b "$ESP_PART" ]   || fatal "ESP partition $ESP_PART not found."
[ -b "$BPOOL_PART" ] || fatal "bpool partition $BPOOL_PART not found."
[ -b "$RPOOL_PART" ] || fatal "rpool partition $RPOOL_PART not found."

log "Partition layout:"
run sgdisk -p "$ZFS_DISK"

### --- STEP 3: Create ZFS pools ----------------------------------------------

log "STEP 3: Creating ZFS boot pool ($ZFS_POOL_BPOOL)"
run zpool create \
  -f \
  -o ashift=12 \
  -o autotrim=on \
  -o compatibility=grub2 \
  -o cachefile=/etc/zfs/zpool.cache \
  -O devices=off \
  -O acltype=posixacl -O xattr=sa \
  -O compression=lz4 \
  -O normalization=formD \
  -O relatime=on \
  -O canmount=off -O mountpoint=/boot -R /mnt \
  "$ZFS_POOL_BPOOL" "$BPOOL_PART"

log "STEP 3: Creating ZFS root pool ($ZFS_POOL_RPOOL)"
run zpool create \
  -f \
  -o ashift=12 \
  -o autotrim=on \
  -O acltype=posixacl -O xattr=sa -O dnodesize=auto \
  -O compression=lz4 \
  -O normalization=formD \
  -O relatime=on \
  -O canmount=off -O mountpoint=/ -R /mnt \
  "$ZFS_POOL_RPOOL" "$RPOOL_PART"

### --- STEP 4: ZFS dataset layout --------------------------------------------

log "STEP 4: Creating ZFS dataset layout"

# Container datasets
run zfs create -o canmount=off -o mountpoint=none "$ZFS_POOL_RPOOL/ROOT"
run zfs create -o canmount=off -o mountpoint=none "$ZFS_POOL_BPOOL/BOOT"

# Root datasets
run zfs create -o canmount=noauto -o mountpoint=/ "$ZFS_POOL_RPOOL/ROOT/debian"
run zfs mount "$ZFS_POOL_RPOOL/ROOT/debian"

run zfs create -o mountpoint=/boot "$ZFS_POOL_BPOOL/BOOT/debian"

# Other datasets
run zfs create "$ZFS_POOL_RPOOL/home"
run zfs create -o mountpoint=/root "$ZFS_POOL_RPOOL/home/root"
run chmod 700 /mnt/root

run zfs create -o canmount=off "$ZFS_POOL_RPOOL/var"
run zfs create -o canmount=off "$ZFS_POOL_RPOOL/var/lib"
run zfs create "$ZFS_POOL_RPOOL/var/log"
run zfs create "$ZFS_POOL_RPOOL/var/spool"

run zfs create -o com.sun:auto-snapshot=false "$ZFS_POOL_RPOOL/var/cache"
run zfs create -o com.sun:auto-snapshot=false "$ZFS_POOL_RPOOL/var/tmp"
run chmod 1777 /mnt/var/tmp

run zfs create -o canmount=off "$ZFS_POOL_RPOOL/usr"
run zfs create "$ZFS_POOL_RPOOL/usr/local"

run zfs create "$ZFS_POOL_RPOOL/var/mail"
run zfs create "$ZFS_POOL_RPOOL/var/www"

# Optional /tmp as dataset (you can switch to tmpfs later)
run zfs create -o com.sun:auto-snapshot=false "$ZFS_POOL_RPOOL/tmp"
run chmod 1777 /mnt/tmp

### --- STEP 5: Prepare /mnt/run tmpfs ----------------------------------------

log "STEP 5: Preparing /mnt/run tmpfs"

run mkdir -p /mnt/run
run mount -t tmpfs tmpfs /mnt/run
run mkdir -p /mnt/run/lock

### --- STEP 6: debootstrap base system ---------------------------------------

log "STEP 6: debootstrap $ZFS_RELEASE into ZFS root"

run debootstrap "$ZFS_RELEASE" /mnt

# Copy zpool.cache into new system
run mkdir -p /mnt/etc/zfs
run cp /etc/zfs/zpool.cache /mnt/etc/zfs/

### --- STEP 7: Basic system config (hostname, apt, network) ------------------

log "STEP 7: Basic chroot configuration"

# hostname
echo "$ZFS_HOSTNAME" > /mnt/etc/hostname

cat <<EOF >/mnt/etc/hosts
127.0.0.1       localhost
127.0.1.1       $ZFS_HOSTNAME

# IPv6
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

# minimal network config: assume DHCP on first interface
FIRST_IFACE="$(ip -o link show | awk -F': ' '!/ lo:/{print $2; exit}' || true)"
if [ -n "$FIRST_IFACE" ]; then
  mkdir -p /mnt/etc/network/interfaces.d
  cat <<EOF >/mnt/etc/network/interfaces.d/$FIRST_IFACE
auto $FIRST_IFACE
iface $FIRST_IFACE inet dhcp
EOF
fi

# apt sources
cat <<'EOF' >/mnt/etc/apt/sources.list
deb http://deb.debian.org/debian trixie main contrib non-free-firmware
deb http://deb.debian.org/debian-security trixie-security main contrib non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free-firmware
EOF

### --- Helper for chroot exec ------------------------------------------------

chrun() {
  log "CHROOT: $*"
  chroot /mnt /usr/bin/env DISK="$ZFS_DISK" bash -eu -c "$*"
}

### --- STEP 8: Inside-chroot package installs --------------------------------

log "STEP 8: Installing base packages (inside chroot)"

chrun "apt update"

chrun "DEBIAN_FRONTEND=noninteractive apt install --yes \
  locales console-setup tzdata keyboard-configuration"

# Configure locales minimally: ensure en_US.UTF-8
chrun "sed -i 's/^# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen"

# Kernel + ZFS
chrun "DEBIAN_FRONTEND=noninteractive apt install --yes \
  linux-image-amd64 linux-headers-amd64 zfs-initramfs"

# Time sync
chrun "DEBIAN_FRONTEND=noninteractive apt install --yes systemd-timesyncd"

# GRUB / EFI tooling
chrun "DEBIAN_FRONTEND=noninteractive apt install --yes \
  grub-efi-amd64 shim-signed dosfstools"

# Optional convenience: SSH server
#chrun "DEBIAN_FRONTEND=noninteractive apt install --yes openssh-server"

### --- STEP 9: Create & mount EFI system partition ---------------------------

log "STEP 9: Formatting and mounting ESP ($ESP_PART)"

ESP_UUID="$(blkid -s UUID -o value "$ESP_PART" || true)"
if [ -z "$ESP_UUID" ]; then
  run mkfs.vfat -F32 -n EFI "$ESP_PART"
  ESP_UUID="$(blkid -s UUID -o value "$ESP_PART")"
fi

chrun "mkdir -p /boot/efi"
cat <<EOF >>/mnt/etc/fstab
/dev/disk/by-uuid/$ESP_UUID  /boot/efi  vfat  defaults  0  0
EOF

# Mount ESP inside chroot
chrun "mount /boot/efi"

### --- STEP 10: Root password & user ----------------------------------------

log "STEP 10: Setting root password placeholder"
# You can later change this via cloud-init or your own bootstrap.
# For now, set root password to 'root' (change ASAP).
chrun "echo 'root:root' | chpasswd"

### --- STEP 11: zfs-import-bpool.service -------------------------------------

log "STEP 11: Installing zfs-import-bpool.service"

cat <<'EOF' >/mnt/etc/systemd/system/zfs-import-bpool.service
[Unit]
DefaultDependencies=no
Before=zfs-import-scan.service
Before=zfs-import-cache.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/zpool import -N -o cachefile=none bpool
ExecStartPre=-/bin/mv /etc/zfs/zpool.cache /etc/zfs/preboot_zpool.cache
ExecStartPost=-/bin/mv /etc/zfs/preboot_zpool.cache /etc/zfs/zpool.cache

[Install]
WantedBy=zfs-import.target
EOF

chrun "systemctl enable zfs-import-bpool.service"

### --- STEP 12: ZFS mount generator cache -----------------------------------

log "STEP 12: Generating /etc/zfs/zfs-list.cache"

chrun "mkdir -p /etc/zfs/zfs-list.cache"
chrun "touch /etc/zfs/zfs-list.cache/bpool /etc/zfs/zfs-list.cache/rpool"

# Start zed temporarily to populate cache
chrun "zed -F & sleep 5; killall zed || true"

# If empty, force update
chrun "[ -s /etc/zfs/zfs-list.cache/bpool ] || zfs set canmount=on     bpool/BOOT/debian"
chrun "[ -s /etc/zfs/zfs-list.cache/rpool ] || zfs set canmount=noauto rpool/ROOT/debian || true"

# Fix paths (/mnt → /)
sed -Ei "s|/mnt/?|/|" /mnt/etc/zfs/zfs-list.cache/* || true

### --- STEP 13: GRUB config for ZFS root ------------------------------------

log "STEP 13: Configuring GRUB for ZFS root"

cat <<EOF >>/mnt/etc/default/grub
GRUB_CMDLINE_LINUX="root=ZFS=$ZFS_POOL_RPOOL/ROOT/debian"
# Debug-friendly boot; you can re-enable quiet later
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_TERMINAL=console
EOF

# Probing & initramfs
chrun "update-initramfs -c -k all"
chrun "update-grub"

# Install GRUB to EFI
chrun "grub-install --target=x86_64-efi --efi-directory=/boot/efi \
  --bootloader-id=debian --recheck --no-floppy"

### --- STEP 14: Enable tmp.mount (optional) ----------------------------------

log "STEP 14: Configuring tmpfs /tmp (optional)"
# If you prefer tmpfs instead of ZFS dataset, enable this and maybe remove rpool/tmp.
# For now we leave it commented out.
# chrun "cp /usr/share/systemd/tmp.mount /etc/systemd/system/ && systemctl enable tmp.mount"

### --- STEP 15: Snapshot initial state ---------------------------------------

log "STEP 15: Creating initial snapshots"

run zfs snapshot "$ZFS_POOL_BPOOL/BOOT/debian@install"
run zfs snapshot "$ZFS_POOL_RPOOL/ROOT/debian@install"

### --- STEP 16: Cleanup mounts & export pools --------------------------------

log "STEP 16: Cleaning up mounts and exporting pools"

# Leave /mnt still mounted – the installer, on exit, will reboot.
# But ensure no leftover bind mounts from d-i.
mount | grep '/mnt' || true

# Export pools cleanly; they will be imported by initramfs on next boot.
run zpool export "$ZFS_POOL_RPOOL"
run zpool export "$ZFS_POOL_BPOOL"

log "==================================================================="
log "System is ready to reboot into ZFS root."
log "==================================================================="

exit 0
__EARLYZFS__
}

# ==============================================================================
# Installer boot menu + preseed
# ==============================================================================
write_bootloader_entries(){
  local cust="$1"; local K="/install.amd/vmlinuz"; local I="/install.amd/initrd.gz"
  [[ -f "$cust$K" ]] || { K="/debian-installer/amd64/linux"; I="/debian-installer/amd64/initrd.gz"; }
  cat >"$cust/boot/grub/grub.cfg" <<GRUB
set default=0
set timeout=2
menuentry "Install (auto, ZFS-on-root early, UEFI, BE-aware)" {
    linux ${K} auto=true priority=critical \
      preseed/file=/cdrom/preseed.cfg \
      debconf/frontend=noninteractive \
      locale=en_US.UTF-8 keyboard-configuration/xkb-keymap=us \
      netcfg/choose_interface=auto --- quiet
    initrd ${I}
}
GRUB
}

emit_preseed_minimal() {
  local WORKDIR="$1"
  local HOSTNAME="${2:-master}"
  local STATIC_IP="${3:-}"

  : "${WORKDIR:?emit_preseed_minimal: WORKDIR not set}"
  mkdir -p "${WORKDIR}"

  # Build NETBLOCK dynamically (DHCP vs static)
  local NETBLOCK=""
  if [[ -z "${STATIC_IP}" ]]; then
    # DHCP mode (fallback)
    NETBLOCK="
d-i netcfg/choose_interface select auto
d-i netcfg/disable_dhcp boolean false
d-i netcfg/get_hostname string ${HOSTNAME}
d-i netcfg/get_domain string ${DOMAIN}
"
  else
    # Static mode (what you actually want on your pfSense / Proxmox segment)
    NETBLOCK="
d-i netcfg/disable_dhcp boolean true
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string ${HOSTNAME}
d-i netcfg/get_domain string ${DOMAIN}
d-i netcfg/get_nameservers string ${NAMESERVER}
d-i netcfg/get_ipaddress string ${STATIC_IP}
d-i netcfg/get_netmask string ${NETMASK}
d-i netcfg/get_gateway string ${GATEWAY}
d-i netcfg/confirm_static boolean true
"
  fi

  cat > "${WORKDIR}/preseed.cfg" <<EOF
### ===============================
### Debian automated install (classic ext4-on-LVM root)
### ===============================

### Locale / keyboard
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i console-setup/layoutcode string us
d-i keyboard-configuration/xkb-keymap select us

### Network (DHCP or static depending on NETBLOCK)
${NETBLOCK}

### Clock / time zone
d-i clock-setup/utc boolean true
d-i time/zone string America/Vancouver
d-i clock-setup/ntp boolean true

### Mirror
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

### Accounts
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string Debian Admin
d-i passwd/username string debian
d-i passwd/user-password password changeme
d-i passwd/user-password-again password changeme
d-i user-setup/allow-password-weak boolean true

### Partitioning (classic LVM over whole disk)
d-i partman-auto/disk string /dev/sda
d-i partman-auto/method string lvm

d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true

d-i partman-auto/choose_recipe select atomic
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

### Base system
d-i base-installer/kernel/override-image string linux-image-amd64

### APT setup
d-i apt-setup/use_mirror boolean true
d-i apt-setup/services-select multiselect security, updates
d-i apt-setup/non-free-firmware boolean true

### Package selection
tasksel tasksel/first multiselect standard
d-i pkgsel/include string openssh-server curl vim less rsync sudo
d-i pkgsel/upgrade select safe-upgrade
d-i pkgsel/update-policy select unattended-upgrades

### GRUB / boot loader
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string /dev/sda

### Late command: stage darksite and bootstrap (no ZFS conversion)
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

### Finish: avoid interactive “Installation complete” dialog as much as possible
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/halt boolean true
d-i debian-installer/exit/poweroff boolean true
EOF
}

# ==============================================================================
# mk_iso — builds custom ISO (UEFI-only) with preseed + darksite + dracut + early ZFS(BE)
# ==============================================================================
mk_iso(){  # mk_iso <name> <postinstall_src> <iso_out> [static_ip]
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"
  local build="$BUILD_ROOT/$name"
  local mnt="$build/mnt"
  local cust="$build/custom"
  local dark="$cust/darksite"
  local suite="${DARKSITE_SUITE:-trixie}" arch="${ARCH:-amd64}"
  rm -rf "$build"; mkdir -p "$mnt" "$cust" "$dark" "$cust/extras"

  emit_sb_keys_if_missing
  emit_wg_dracut  "$dark"
  emit_zfs_be_toolkit "$dark"
  emit_darksite_payload "$cust/darksite"

  (
    set -euo pipefail
    trap "umount -f '$mnt' 2>/dev/null || true" EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    cp -a "$mnt/"* "$cust/"
    cp -a "$mnt/.disk" "$cust/" 2>/dev/null || true
  )

  install -m0755 "$postinstall_src" "$dark/postinstall.sh"

  cat >"$dark/bootstrap.service" <<'__BOOTSTRAPUNIT__'
[Unit]
Description=Initial Bootstrap Script (one-time)
DefaultDependencies=no
After=network-online.target systemd-networkd-wait-online.service
Wants=network-online.target
Before=multi-user.target

[Service]
Type=oneshot
Environment=DEBIAN_FRONTEND=noninteractive
WorkingDirectory=/root/darksite
# Run the postinstall, but never hard-fail the boot; log errors to its own log.
ExecStart=/usr/bin/env bash -lc '/root/darksite/postinstall.sh || true'
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
__BOOTSTRAPUNIT__

  cat >"$dark/late.sh" <<'__LATE__'
#!/bin/sh
set -eux
mkdir -p /target/root/darksite
cp -a /cdrom/darksite/. /target/root/darksite/ 2>/dev/null || true
in-target install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch || true
in-target install -D -m0755 /root/darksite/postinstall.sh /root/darksite/postinstall.sh || true
in-target install -D -m0644 /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service || true
in-target systemctl daemon-reload || true
in-target systemctl enable bootstrap.service || true
in-target apt-get purge -y grub-pc grub-efi-amd64 grub-common || true
in-target bootctl install || true
in-target install -D -m0755 /root/darksite/be/zfs-bectl /usr/local/sbin/zfs-bectl
in-target install -D -m0644 /root/darksite/be/90-zfs-snapshots /etc/apt/apt.conf.d/90-zfs-snapshots
in-target install -D -m0755 /root/darksite/be/zz-uki-sign /etc/kernel/postinst.d/zz-uki-sign
in-target mkdir -p /usr/lib/dracut/modules.d/45wg
in-target cp -a /root/darksite/45wg/. /usr/lib/dracut/modules.d/45wg/
in-target dracut --force || true
in-target /bin/systemctl --no-block poweroff || true
exit 0
__LATE__
  chmod +x "$dark/late.sh"

  mkdir -p "$dark/repo"
  build_dark_repo "$dark/repo" "$arch" "$suite"
  darksite_stage_extras "$dark/repo" "./scripts" "./patches"

  cat >"$dark/apt-arch.conf" <<'__APTARCH__'
APT::Architectures { "amd64"; };
DPkg::Architectures { "amd64"; };
Acquire::Languages "none";
__APTARCH__

  emit_preseed_minimal "$cust" "$name" "$static_ip"
  write_bootloader_entries "$cust"
    write_bootloader_entries "$cust"

  echo "======== /preseed.cfg ========";  sed -n '1,999p' "$cust/preseed.cfg"

  # >>> add udeb staging here <<<
    # --- stage d-i udebs onto the ISO (offline, reproducible) ---
  # --- stage d-i udebs onto the ISO (offline, reproducible, quiet) ---
stage_di_udebs() {
  local iso_root="$1" suite="${2:-trixie}" arch="${3:-amd64}"
  local out="$iso_root/darksite-udeb"
  echo "[udeb] staging udebs → $out (suite=$suite arch=$arch)"
  rm -rf "$out"; mkdir -p "$out"

  docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -e SUITE="$suite" -e ARCH="$arch" \
    -v "$out:/out" "debian:${suite}" bash -lc '
set -euo pipefail

# Keep apt quiet and single-sourced
echo "Acquire::Languages \"none\";" >/etc/apt/apt.conf.d/99nolangs
rm -f /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${SUITE} main
deb http://deb.debian.org/debian ${SUITE} main/debian-installer
EOF

# Use root as the sandbox user to avoid the “unsandboxed as root” warning
echo "APT::Sandbox::User \"root\";" >/etc/apt/apt.conf.d/00nosandbox

apt-get -qq update
apt-get -qq install -y --no-install-recommends apt-utils dpkg-dev ca-certificates >/dev/null

mkdir -p /out/pool/main /out/dists/${SUITE}/main/debian-installer/binary-${ARCH}
work=/tmp/w; mkdir -p "$work"
cd "$work"

pkgs="busybox-udeb kmod-udeb udev-udeb parted-udeb util-linux-udeb e2fsprogs-udeb dosfstools-udeb debootstrap-udeb"

# Fetch udebs (quiet)
for p in $pkgs; do apt-get -qq download "$p"; done

shopt -s nullglob
mv ./*.udeb /out/pool/main/

# Minimal index for anna/apt in d-i
apt-ftparchive packages /out/pool/main > /out/dists/${SUITE}/main/debian-installer/binary-${ARCH}/Packages
gzip -9f /out/dists/${SUITE}/main/debian-installer/binary-${ARCH}/Packages

chmod -R a+rX /out
echo "[udeb] done"
'
}


  stage_di_udebs "$cust" "trixie" "amd64"

  stage_di_udebs "$cust"
  # <<< end udeb staging >>>

  local have_uefi=0 efi_img=""
  [[ -f "$cust/boot/grub/efi.img" ]] && { efi_img="boot/grub/efi.img"; have_uefi=1; }
  [[ -f "$cust/efi.img" ]] &&        { efi_img="efi.img";            have_uefi=1; }
  [[ $have_uefi -eq 1 ]] || die "No UEFI image found inside ISO tree."

  local args=( -as mkisofs -o "$iso_out" -r -J -joliet-long -l )
  args+=( -eltorito-alt-boot -e "$efi_img" -no-emul-boot -isohybrid-gpt-basdat "$cust" )
  echo "[mk_iso] Building (UEFI-only) → $iso_out"
  xorriso "${args[@]}"
  stat -c '[mk_iso] ISO size: %s bytes' "$iso_out" || true
  sha256sum "$iso_out" || true
}


# ==============================================================================
# MASTER POSTINSTALL — hardened base, WG hub, Sanoid/Syncoid, UKI signing
# ==============================================================================
emit_postinstall_master() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
[ -r /etc/environment.d/99-provision.conf ] && . /etc/environment.d/99-provision.conf

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"

GUI_PROFILE="${GUI_PROFILE:-rdp-minimal}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
ADMIN_USER="${ADMIN_USER:-todd}"

DOMAIN="${DOMAIN:-unixbox.net}"
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

LOG="/var/log/postinstall-master.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq xxd unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    nftables wireguard-tools vim \
    chrony rsyslog qemu-guest-agent dbus-x11 || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true
  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true

  cat >/etc/sysctl.d/99-wg.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
  sysctl --system || true
}

ensure_users_harden(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"

  mk(){ local u="$1" k="$2";
    id -u "$u" &>/dev/null || useradd -m -s /bin/bash "$u";
    install -d -m700 -o "$u" -g "$u" "/home/$u/.ssh";
    touch "/home/$u/.ssh/authorized_keys"; chmod 600 "/home/$u/.ssh/authorized_keys"
    chown -R "$u:$u" "/home/$u/.ssh"
    [[ -n "$k" ]] && grep -qxF "$k" "/home/$u/.ssh/authorized_keys" || { [[ -n "$k" ]] && printf '%s\n' "$k" >> "/home/$u/.ssh/authorized_keys"; }
    install -d -m755 /etc/sudoers.d; printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$u" >"/etc/sudoers.d/90-$u"; chmod 0440 "/etc/sudoers.d/90-$u";
  }
  mk "$ADMIN_USER" "$PUB"

  id -u ansible &>/dev/null || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys; chmod 600 /home/ansible/.ssh/authorized_keys

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress ${MASTER_LAN}
ListenAddress $(echo "${WG0_IP}" | cut -d/ -f1)
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
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  (sshd -t && systemctl daemon-reload && systemctl restart ssh) || true
}

wg_prepare_conf(){
  local ifn="$1" ipcidr="$2" port="$3"
  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077
  [[ -f /etc/wireguard/${ifn}.key ]] || wg genkey | tee /etc/wireguard/${ifn}.key | wg pubkey >/etc/wireguard/${ifn}.pub
  cat >/etc/wireguard/${ifn}.conf <<EOF
[Interface]
Address    = ${ipcidr}
ListenPort = ${port}
PrivateKey = $(cat /etc/wireguard/${ifn}.key)
SaveConfig = true
MTU = 1420
EOF
  chmod 600 /etc/wireguard/${ifn}.conf
  umask "$_old_umask"
}
wg_try_systemd(){ systemctl daemon-reload || true; systemctl enable --now "wg-quick@${1}" || return 1; }
wg_bringup_manual(){
  local ifn="$1" ipcidr="$2" port="$3"
  ip link show "$ifn" >/dev/null 2>&1 || ip link add "$ifn" type wireguard || true
  ip -4 addr show dev "$ifn" | grep -q "${ipcidr%/*}" || ip addr add "$ipcidr" dev "$ifn" || true
  wg set "$ifn" listen-port "$port" private-key /etc/wireguard/${ifn}.key || true
  ip link set "$ifn" mtu 1420 up || true
}
wg_up_all(){
  wg_prepare_conf wg0 "$WG0_IP" "$WG0_PORT"; wg_try_systemd wg0 || wg_bringup_manual wg0 "$WG0_IP" "$WG0_PORT"
  wg_prepare_conf wg1 "$WG1_IP" "$WG1_PORT"; wg_try_systemd wg1 || wg_bringup_manual wg1 "$WG1_IP" "$WG1_PORT"
  wg_prepare_conf wg2 "$WG2_IP" "$WG2_PORT"; wg_try_systemd wg2 || wg_bringup_manual wg2 "$WG2_IP" "$WG2_PORT"
  wg_prepare_conf wg3 "$WG3_IP" "$WG3_PORT"; wg_try_systemd wg3 || wg_bringup_manual wg3 "$WG3_IP" "$WG3_PORT"
}

nft_firewall(){
  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    tcp dport 22 accept
    udp dport { 51820,51821,51822,51823 } accept
    tcp dport 3389 accept
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

hub_seed(){
  install -d -m0755 /srv/wg
  cat >/srv/wg/hub.env <<EOF
WG0_IP=${WG0_IP}
WG1_IP=${WG1_IP}
WG2_IP=${WG2_IP}
WG3_IP=${WG3_IP}
WG0_PORT=${WG0_PORT}
WG1_PORT=${WG1_PORT}
WG2_PORT=${WG2_PORT}
WG3_PORT=${WG3_PORT}
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}
HUB_LAN=${MASTER_LAN}
WG0_PUB=$(cat /etc/wireguard/wg0.pub 2>/dev/null || echo "")
WG1_PUB=$(cat /etc/wireguard/wg1.pub 2>/dev/null || echo "")
WG2_PUB=$(cat /etc/wireguard/wg2.pub 2>/dev/null || echo "")
WG3_PUB=$(cat /etc/wireguard/wg3.pub 2>/dev/null || echo "")
EOF
  chmod 0644 /srv/wg/hub.env
  : >/srv/wg/ENROLL_ENABLED
}

helper_tools(){
  cat >/usr/local/sbin/wg-add-peer <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
PUB="${1:-}"; ADDR="${2:-}"; IFN="${3:-wg0}"
FLAG="/srv/wg/ENROLL_ENABLED"
[[ -f "$FLAG" ]] || { echo "[X] enrollment closed"; exit 2; }
[[ -n "$PUB" && -n "$ADDR" ]] || { echo "usage: wg-add-peer <pubkey> <ip/cidr> [ifname]"; exit 1; }
if wg show "$IFN" peers | grep -qx "$PUB"; then
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR"
else
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR" persistent-keepalive 25
fi
CONF="/etc/wireguard/${IFN}.conf"
if ! grep -q "$PUB" "$CONF"; then
  printf "\n[Peer]\nPublicKey  = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n" "$PUB" "$ADDR" >> "$CONF"
fi
systemctl reload "wg-quick@${IFN}" 2>/dev/null || true
echo "[+] added $PUB $ADDR on $IFN"
EOF
  chmod 0755 /usr/local/sbin/wg-add-peer

  cat >/usr/local/sbin/wg-enrollment <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FLAG="/srv/wg/ENROLL_ENABLED"
case "${1:-}" in
  on)  : >"$FLAG"; echo "enrollment enabled";;
  off) rm -f "$FLAG"; echo "enrollment disabled";;
  *) echo "usage: wg-enrollment on|off"; exit 1;;
esac
EOF
  chmod 0755 /usr/local/sbin/wg-enrollment

  cat >/usr/local/sbin/register-minion <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
GROUP="${1:-}"; HOST="${2:-}"; IP="${3:-}"
[[ -z "$GROUP" || -z "$HOST" || -z "$IP" ]] && { echo "usage: $0 <group> <hostname> <wg1-ip>"; exit 2; }
ANS_HOSTS="/etc/ansible/hosts"
mkdir -p "$(dirname "$ANS_HOSTS")"; touch "$ANS_HOSTS"
if ! grep -q "^\[${GROUP}\]" "$ANS_HOSTS"; then echo -e "\n[${GROUP}]" >> "$ANS_HOSTS"; fi
sed -i "/^${HOST}\b/d" "$ANS_HOSTS"
echo "${HOST} ansible_host=${IP}" >> "$ANS_HOSTS"
mkdir -p /etc/prometheus/targets.d
TGT="/etc/prometheus/targets.d/${GROUP}.json"
[[ -s "$TGT" ]] || echo '[]' > "$TGT"
tmp="$(mktemp)"; jq --arg target "${IP}:9100" 'map(select(.targets|index($target)|not)) + [{"targets":[$target]}]' "$TGT" > "$tmp" && mv "$tmp" "$TGT"
if pidof prometheus >/dev/null 2>&1; then pkill -HUP prometheus || systemctl reload prometheus || true; fi
echo "[OK] Registered ${HOST} (${IP}) in group ${GROUP}"
EOF
  chmod 0755 /usr/local/sbin/register-minion
}

telemetry_stack(){
  local wg1_ip; wg1_ip="$(ip -4 addr show dev wg1 | awk '/inet /{print $2}' | cut -d/ -f1)"
  [[ -n "$wg1_ip" ]] || wg1_ip="${WG1_IP%/*}"

  apt-get install -y prometheus prometheus-node-exporter grafana || true

  install -d -m755 /etc/prometheus/targets.d
  cat >/etc/prometheus/prometheus.yml <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 30s
scrape_configs:
  - job_name: 'node'
    file_sd_configs:
      - files:
        - /etc/prometheus/targets.d/*.json
EOF

  install -d -m755 /etc/systemd/system/prometheus.service.d
  cat >/etc/systemd/system/prometheus.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus --web.listen-address=${wg1_ip}:9090 --config.file=/etc/prometheus/prometheus.yml
EOF
  install -d -m755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=${wg1_ip}:9100 --web.disable-exporter-metrics
EOF
  cat >/etc/systemd/system/prometheus.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  systemctl daemon-reload
  systemctl enable --now prometheus prometheus-node-exporter || true

  install -d /etc/grafana/provisioning/{datasources,dashboards}
  cat >/etc/grafana/provisioning/datasources/prom.yaml <<EOF
apiVersion: 1
datasources:
- name: Prometheus
  type: prometheus
  access: proxy
  url: http://${wg1_ip}:9090
  isDefault: true
EOF
  install -d -m755 /var/lib/grafana/dashboards/node
  cat >/etc/grafana/provisioning/dashboards/node.yaml <<'EOF'
apiVersion: 1
providers:
- name: node
  orgId: 1
  folder: "Node"
  type: file
  options:
    path: /var/lib/grafana/dashboards/node
EOF
  cat >/var/lib/grafana/dashboards/node/quick-node.json <<'EOF'
{"annotations":{"list":[{"builtIn":1,"datasource":{"type":"grafana","uid":"grafana"},"enable":true,"hide":true,"iconColor":"rgba(0, 211, 255, 1)","name":"Annotations & Alerts","type":"dashboard"}]},"editable":true,"graphTooltip":0,"panels":[{"type":"stat","title":"Up targets","datasource":"Prometheus","targets":[{"expr":"up"}]}],"schemaVersion":39,"style":"dark","time":{"from":"now-15m","to":"now"},"title":"Quick Node","version":1}
EOF
  systemctl enable --now grafana-server || true
}

control_stack(){
  apt-get install -y --no-install-recommends salt-master salt-api salt-common || true
  install -d -m0755 /etc/salt/master.d
  cat >/etc/salt/master.d/network.conf <<'EOF'
interface: 10.77.0.1
ipv6: False
publish_port: 4505
ret_port: 4506
EOF
  cat >/etc/salt/master.d/api.conf <<'EOF'
rest_cherrypy:
  host: 10.77.0.1
  port: 8000
  disable_ssl: True
EOF
  install -d -m0755 /etc/systemd/system/salt-master.service.d
  cat >/etc/systemd/system/salt-master.service.d/override.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now salt-master salt-api || true

  if [ "${INSTALL_ANSIBLE}" = "yes" ]; then apt-get install -y ansible || true; fi

  if [ "${INSTALL_SEMAPHORE}" != "no" ]; then
    install -d -m755 /etc/semaphore
    if curl -fsSL -o /usr/local/bin/semaphore https://github.com/ansible-semaphore/semaphore/releases/latest/download/semaphore_linux_amd64 2>/dev/null; then
      chmod +x /usr/local/bin/semaphore
      cat >/etc/systemd/system/semaphore.service <<'EOF'
[Unit]
Description=Ansible Semaphore
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service
[Service]
ExecStart=/usr/local/bin/semaphore server --listen 10.77.0.1:3000
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload; systemctl enable --now semaphore || true
    else
      echo "[WARN] Semaphore binary not fetched; install later." >&2
    fi
  fi
}

desktop_gui() {
  case "${GUI_PROFILE}" in
    rdp-minimal)
      apt-get install -y --no-install-recommends xorg xrdp xorgxrdp openbox xterm firefox-esr || true
      if [[ -f /etc/xrdp/xrdp.ini ]]; then
        sed -i 's/^\s*port\s*=.*/; &/' /etc/xrdp/xrdp.ini || true
        if grep -qE '^\s*address=' /etc/xrdp/xrdp.ini; then
          sed -i "s|^\s*address=.*|address=${MASTER_LAN}|" /etc/xrdp/xrdp.ini
        else
          sed -i "1i address=${MASTER_LAN}" /etc/xrdp/xrdp.ini
        fi
        if grep -qE '^\s*;port=' /etc/xrdp/xrdp.ini; then
          sed -i 's|^\s*;port=.*|port=3389|' /etc/xrdp/xrdp.ini
        elif grep -qE '^\s*port=' /etc/xrdp/xrdp.ini; then
          sed -i 's|^\s*port=.*|port=3389|' /etc/xrdp/xrdp.ini
        else
          sed -i '1i port=3389' /etc/xrdp/xrdp.ini
        fi
      fi
      cat >/etc/xrdp/startwm.sh <<'EOSH'
#!/bin/sh
export DESKTOP_SESSION=openbox
export XDG_SESSION_DESKTOP=openbox
export XDG_CURRENT_DESKTOP=openbox
[ -x /usr/bin/openbox-session ] && exec /usr/bin/openbox-session
[ -x /usr/bin/openbox ] && exec /usr/bin/openbox
exec /usr/bin/xterm
EOSH
      chmod +x /etc/xrdp/startwm.sh
      systemctl daemon-reload || true
      systemctl enable --now xrdp || true
      ;;
    wayland-gdm-minimal)
      apt-get install -y --no-install-recommends gdm3 gnome-shell gnome-session-bin firefox-esr || true
      systemctl enable --now gdm3 || true
      ;;
  esac
}

main_master(){
  log "BEGIN postinstall (master hub)"
  export DEBIAN_FRONTEND=noninteractive
  ensure_base
  ensure_users_harden

  # Salt/Grafana repos (unchanged)
  install -d -m0755 /etc/apt/keyrings
  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.gpg || true
  curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.sources -o /etc/apt/sources.list.d/salt.sources || true
  sed -i 's#/etc/apt/keyrings/salt-archive-keyring\.pgp#/etc/apt/keyrings/salt-archive-keyring.pgp#' /etc/apt/sources.list.d/salt.sources || true
  cat >/etc/apt/preferences.d/salt-pin-1001 <<'EOF'
Package: salt-*
Pin: version 3006.*
Pin-Priority: 1001
EOF
  curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg || true
  chmod 0644 /etc/apt/keyrings/grafana.gpg || true
  cat >/etc/apt/sources.list.d/grafana.sources <<'EOF'
Types: deb
URIs: https://apt.grafana.com
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/grafana.gpg
EOF
  apt-get update -y || true

  wg_up_all
  nft_firewall
  hub_seed
  helper_tools
  telemetry_stack
  control_stack
  desktop_gui

  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Master hub ready."
  systemctl disable bootstrap.service || true
  systemctl daemon-reload || true
  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}
main_master
EOS
}

# ==============================================================================
# MINION POSTINSTALL
# ==============================================================================
emit_postinstall_minion(){
  local out="$1"
  cat >"$out" <<'__MINION__'
#!/usr/bin/env bash
# minion postinstall (UEFI-only, dracut + UKI, ZFS utils from darksite when present)
set -Eeuo pipefail
LOG="/var/log/minion-postinstall.log"; exec > >(tee -a "$LOG") 2>&1

log(){ echo "[INFO] $(date '+%F %T') - $*"; }
die(){ echo "[ERROR] $*" >&2; exit 1; }

# ---- tunables via env or /etc/environment.d/99-provision.conf ----
ADMIN_USER="${ADMIN_USER:-todd}"
MY_GROUP="${MY_GROUP:-prom}"

# Secure Boot signing materials staged by ISO (optional but preferred)
SB_KEY="/root/darksite/db.key"
SB_CRT="/root/darksite/db.crt"

# --- helpers -------------------------------------------------------
dpkg_script_sanity_fix(){
  shopt -s nullglob
  for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
    [ -f "$f" ] || continue
    head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"
    sed -i 's/\r$//' "$f" 2>/dev/null || true
    chmod +x "$f" || true
  done
  dpkg --configure -a || true
}

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive

  dpkg_script_sanity_fix

  # Prefer local darksite if present; fall back to Debian online (harmless on an offline darksite).
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo trixie main
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch || true

  for i in 1 2 3; do
    apt-get update -y && break || sleep $((i*3))
  done

  # NOTE: dkms + zfs-dkms + headers needed to build ZFS for the *running* kernel
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar xz-utils \
    iproute2 iputils-ping ethtool tcpdump net-tools wireguard-tools nftables \
    chrony rsyslog qemu-guest-agent debsums \
    build-essential dkms linux-headers-$(uname -r) \
    zfsutils-linux zfs-dkms zfs-initramfs dracut systemd-boot-efi systemd-ukify-efi \
    efitools efivar mokutil sbsigntool ukify \
    sanoid syncoid || true

  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

ensure_users(){
  local PUB=""
  if [ -s "/root/darksite/authorized_keys.${ADMIN_USER}" ]; then
    PUB="$(head -n1 "/root/darksite/authorized_keys.${ADMIN_USER}")"
  fi

  id -u "${ADMIN_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${ADMIN_USER}"

  install -d -m700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  touch "/home/${ADMIN_USER}/.ssh/authorized_keys"
  if [ -n "$PUB" ] && ! grep -qxF "$PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys"; then
    echo "$PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"
  fi
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"

  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" >/etc/sudoers.d/90-${ADMIN_USER}
  chmod 0440 /etc/sudoers.d/90-${ADMIN_USER}
}

# ---------- hub bootstrap (wg, ports, allowlist) ----------
read_hub(){
  for f in \
    /root/cluster-seed/hub.env \
    /srv/wg/hub.env \
    /root/darksite/cluster-seed/hub.env \
    /root/darksite/hub.env
  do
    if [ -r "$f" ]; then HUB_ENV="$f"; break; fi
  done
  [ -n "${HUB_ENV:-}" ] || die "missing hub.env (looked in: /root/cluster-seed, /srv/wg, /root/darksite/cluster-seed, /root/darksite)"

  # Safe-ish env import (key=val; ignore comments/blank)
  eval "$(
    awk -F= '
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      /^[A-Za-z0-9_]+=/ {
        key=$1; $1=""; sub(/^=/,"");
        val=$0; gsub(/^[ \t]+|[ \t]+$/,"",val);
        gsub(/"/,"\\\"",val);
        print key "=\"" val "\""
      }' "$HUB_ENV"
  )"

  : "${WG0_PORT:?missing WG0_PORT}"
  : "${WG_ALLOWED_CIDR:?missing WG_ALLOWED_CIDR}"
  : "${HUB_LAN:?missing HUB_LAN}"
  : "${WG0_PUB:?missing WG0_PUB}"
}

wg_setup(){
  install -d -m700 /etc/wireguard
  umask 077
  [ -f /etc/wireguard/wg0.key ] || wg genkey | tee /etc/wireguard/wg0.key | wg pubkey >/etc/wireguard/wg0.pub

  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/wg0.key)
Address    = ${WG0_WANTED:-10.77.0.10/32}
DNS        = 1.1.1.1
MTU        = 1420

[Peer]
PublicKey  = ${WG0_PUB}
Endpoint   = ${HUB_LAN}:${WG0_PORT}
AllowedIPs = ${WG_ALLOWED_CIDR}
PersistentKeepalive = 25
EOF

  systemctl enable --now wg-quick@wg0 || true
}

nft_base(){
  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    tcp dport 22 accept
    iifname "wg0" accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

sanoid_minion(){
  mkdir -p /etc/sanoid
  cat >/etc/sanoid/sanoid.conf <<'EOC'
[rpool/ROOT/*]
  use_template = be
[rpool/home]
  use_template = user

[template_be]
  daily = 7
  autosnap = yes
  autoprune = yes

[template_user]
  daily = 7
  autosnap = yes
  autoprune = yes
EOC
  systemctl enable --now sanoid.timer || true
}

# -------- UKI build/sign for ZFS root (dracut handles initrd) --------
build_sign_uki(){
  local kver
  kver="$(uname -r || ls /lib/modules | sort -V | tail -1)"
  local rootds
  rootds="$(zpool get -H -o value bootfs rpool 2>/dev/null || echo 'rpool/ROOT/debian')"
  local out="/boot/efi/EFI/Linux/debian-${kver}.efi"

  # Ensure dracut initramfs exists for this kernel
  dracut --force "/boot/initrd.img-${kver}" "${kver}" || true

  mkdir -p /boot/efi/EFI/Linux
  ukify build \
    --linux "/usr/lib/kernel/vmlinuz-${kver}" \
    --initrd "/boot/initrd.img-${kver}" \
    --cmdline "root=ZFS=${rootds} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${out}" || true

  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then
    sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${out}" "${out}" || true
  fi

  install -d -m755 /boot/loader/entries
  cat >/boot/loader/entries/debian.conf <<EOF
title   Debian (ZFS, ${kver})
linux   ${out#/boot/efi}
EOF
  printf "default debian.conf\ntimeout 1\n" >/boot/loader/loader.conf
  bootctl update || true
}

verify_uefi_only(){
  test -d /sys/firmware/efi || die "System not booted via UEFI (no /sys/firmware/efi)"
  bootctl status || true
  ls -l /boot/efi/EFI || true
}

main(){
  log "minion bootstrap start"
  ensure_base
  ensure_users
  read_hub
  wg_setup
  nft_base
  sanoid_minion
  secureboot_enroll_and_enable
  build_sign_uki
  verify_uefi_only
  log "minion bootstrap done; poweroff in 2s"
  (sleep 2; systemctl --no-block poweroff) & disown
}
main
__MINION__
}

# ==============================================================================
# MINION WRAPPER — embeds hub.env + env vars + drops/minion postinstall & runs it
# ==============================================================================
emit_minion_wrapper(){
  local out="$1" group="$2" wg0="$3" wg1="$4" wg2="$5" wg3="$6"
  local hub_src="$BUILD_ROOT/hub/hub.env"
  if [[ ! -s "$hub_src" ]]; then
    err "emit_minion_wrapper: missing hub.env at $hub_src"
    return 1
  fi

  cat >"$out" <<'__WRAPHEAD__'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/minion-wrapper.log"; exec > >(tee -a "$LOG") 2>&1
trap 'echo "[WRAP] failed: ${BASH_COMMAND@Q}  (line ${LINENO})" >&2' ERR
__WRAPHEAD__

  {
    echo 'mkdir -p /root/darksite/cluster-seed'
    echo 'cat > /root/darksite/cluster-seed/hub.env <<HUBEOF'
    cat "$hub_src"
    echo 'HUBEOF'
    echo 'chmod 0644 /root/darksite/cluster-seed/hub.env'
  } >>"$out"

  cat >>"$out" <<__WRAPENV__
install -d -m0755 /etc/environment.d
cat >/etc/environment.d/99-provision.conf <<EOF
ADMIN_USER=$ADMIN_USER
MY_GROUP=${group}
WG0_WANTED=${wg0}
WG1_WANTED=${wg1}
WG2_WANTED=${wg2}
WG3_WANTED=${wg3}
EOF
chmod 0644 /etc/environment.d/99-provision.conf
__WRAPENV__

  cat >>"$out" <<'__WRAPBODY__'
install -d -m0755 /root/darksite
cat >/root/darksite/postinstall-minion.sh <<'EOMINION'
__WRAPBODY__

  local tmp; tmp="$(mktemp)"
  emit_postinstall_minion "$tmp"
  cat "$tmp" >>"$out"
  rm -f "$tmp"

  cat >>"$out" <<'__WRAPTAIL__'
EOMINION
perl -0777 -pe 's/\r\n/\n/g; s/\r/\n/g' -i /root/darksite/postinstall-minion.sh
sed -i '1s|.*|#!/usr/bin/env bash|' /root/darksite/postinstall-minion.sh
chmod +x /root/darksite/postinstall-minion.sh
/usr/bin/env bash /root/darksite/postinstall-minion.sh
__WRAPTAIL__

  chmod +x "$out"
}

# ==============================================================================
# BUILD ALL ISOS — master first (to harvest hub.env), then minions
# ==============================================================================
build_all_isos(){
  log "[*] Building all ISOs into $BUILD_ROOT"
  mkdir -p "$BUILD_ROOT/hub"

  # ---- master ISO: produces hub.env on first boot ----
  local master_payload master_iso
  master_payload="$(mktemp)"; emit_postinstall_master "$master_payload"
  master_iso="$BUILD_ROOT/master.iso"
  mk_iso "master" "$master_payload" "$master_iso" "$MASTER_LAN"
  log "[OK] master ISO: $master_iso"

  # Boot master twice (install → convert → poweroff), then capture hub.env via QGA
  pmx_deploy_uefi "$MASTER_ID" "$MASTER_NAME" "$master_iso" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"
  wait_poweroff "$MASTER_ID" 2400
  boot_from_disk_uefi "$MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  pmx "qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600

  pmx_wait_qga(){ local id="$1" t="${2:-900}" s=$(date +%s); while :; do
    pmx "qm agent $id ping >/dev/null 2>&1 || qm guest ping $id >/dev/null 2>&1" && return 0
    (( $(date +%s)-s > t )) && return 1
    sleep 3
  done; }
  pmx_wait_qga "$MASTER_ID" 900

  local DEST="$BUILD_ROOT/hub/hub.env"
  if pmx "qm guest exec $MASTER_ID --output-format json -- /bin/cat /srv/wg/hub.env" | \
     sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | base64 -d > "${DEST}.tmp" 2>/dev/null \
     && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "[OK] captured hub.env → $DEST"
  else
    err "Failed to retrieve hub.env via QGA"; exit 1
  fi

  # ---- minion ISOs (prom, graf, k8s, storage) ----
  local pld iso
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "prom"    "10.77.0.10/32" "10.78.0.10/32" "10.79.0.10/32" "10.80.0.10/32"; iso="$BUILD_ROOT/prom.iso";    mk_iso "$PROM_NAME" "$pld" "$iso" "$PROM_IP"; log "[OK] prom ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "graf"    "10.77.0.11/32" "10.78.0.11/32" "10.79.0.11/32" "10.80.0.11/32"; iso="$BUILD_ROOT/graf.iso";    mk_iso "$GRAF_NAME" "$pld" "$iso" "$GRAF_IP"; log "[OK] graf ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "k8s"     "10.77.0.12/32" "10.78.0.12/32" "10.79.0.12/32" "10.80.0.12/32"; iso="$BUILD_ROOT/k8s.iso";     mk_iso "$K8S_NAME"  "$pld" "$iso" "$K8S_IP";  log "[OK] k8s ISO:     $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "storage" "10.77.0.13/32" "10.78.0.13/32" "10.79.0.13/32" "10.80.0.13/32"; iso="$BUILD_ROOT/storage.iso"; mk_iso "$STOR_NAME" "$pld" "$iso" "$STOR_IP";  log "[OK] storage ISO: $iso"
}

# ==============================================================================
# PROXMOX CLUSTER DEPLOY — UEFI-ONLY path; ZFS root with BE + signed UKI
# ==============================================================================
proxmox_cluster(){
  build_all_isos

  pmx_deploy_uefi "$PROM_ID" "$PROM_NAME" "$BUILD_ROOT/prom.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$PROM_ID" 2400; boot_from_disk_uefi "$PROM_ID"; wait_poweroff "$PROM_ID" 2400; pmx "qm start $PROM_ID"; pmx_wait_for_state "$PROM_ID" "running" 600

  pmx_deploy_uefi "$GRAF_ID" "$GRAF_NAME" "$BUILD_ROOT/graf.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$GRAF_ID" 2400; boot_from_disk_uefi "$GRAF_ID"; wait_poweroff "$GRAF_ID" 2400; pmx "qm start $GRAF_ID"; pmx_wait_for_state "$GRAF_ID" "running" 600

  pmx_deploy_uefi "$K8S_ID"  "$K8S_NAME"  "$BUILD_ROOT/k8s.iso"  "$K8S_MEM"    "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$K8S_ID"  2400; boot_from_disk_uefi "$K8S_ID";  wait_poweroff "$K8S_ID"  2400; pmx "qm start $K8S_ID";  pmx_wait_for_state "$K8S_ID"  "running" 600

  pmx_deploy_uefi "$STOR_ID" "$STOR_NAME" "$BUILD_ROOT/storage.iso" "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"
  wait_poweroff "$STOR_ID" 2400; boot_from_disk_uefi "$STOR_ID"; wait_poweroff "$STOR_ID" 2400; pmx "qm start $STOR_ID"; pmx_wait_for_state "$STOR_ID" "running" 600

  log "Done. Master + minions deployed (UEFI-only, ZFS root with BE + Sanoid + signed UKI)."
}

# ==============================================================================
# AWS IMPORT — qcow2/raw → S3 → import-image → register UEFI+TPM
# ==============================================================================
aws_import_register_launch(){
  command -v aws >/dev/null || die "aws cli required"
  [[ -n "$AWS_S3_BUCKET" ]] || die "Set AWS_S3_BUCKET to an S3 bucket you control"

  if [[ -s "$UNIVERSAL_QCOW2" ]]; then
    log "[*] Converting qcow2 → raw"
    qemu-img convert -p -O raw "$UNIVERSAL_QCOW2" "$UNIVERSAL_RAW"
  fi
  [[ -s "$UNIVERSAL_RAW" ]] || die "Provide UNIVERSAL_QCOW2 or UNIVERSAL_RAW"

  log "[*] Upload RAW to s3://${AWS_S3_BUCKET}/import/${AWS_AMI_NAME}.raw"
  aws s3 cp "$UNIVERSAL_RAW" "s3://${AWS_S3_BUCKET}/import/${AWS_AMI_NAME}.raw"

  log "[*] Start import-image"
  IID=$(aws ec2 import-image \
          --description "$AWS_AMI_NAME import" \
          --disk-containers "Format=raw,UserBucket={S3Bucket=${AWS_S3_BUCKET},S3Key=import/${AWS_AMI_NAME}.raw}" \
          --query 'ImportImageTasks[0].ImportTaskId' --output text)

  log "[*] Waiting for import ($IID)"
  while :; do
    ST=$(aws ec2 describe-import-image-tasks --import-task-ids "$IID" --query 'ImportImageTasks[0].Status' --output text)
    [[ "$ST" == "completed" ]] && break
    [[ "$ST" == "deleted" || "$ST" == "deleting" ]] && die "Import failed ($ST)"
    sleep 15
  done

  SRC_AMI=$(aws ec2 describe-import-image-tasks --import-task-ids "$IID" --query 'ImportImageTasks[0].ImageId' --output text)
  SNAP=$(aws ec2 describe-images --image-ids "$SRC_AMI" --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)

  log "[*] Register image with UEFI+TPM ${UEFI_BLOB:+and your UEFI var-store}"
  AMI=$(aws ec2 register-image \
          --name "$AWS_AMI_NAME" \
          --architecture x86_64 \
          --root-device-name /dev/xvda \
          --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${SNAP},DeleteOnTermination=true}" \
          --virtualization-type hvm --ena-support \
          --boot-mode uefi --tpm-support v2.0 \
          ${UEFI_BLOB:+--uefi-data fileb://${UEFI_BLOB}} \
          --query 'ImageId' --output text)

  log "[OK] AMI: $AMI"

  set +e
  aws ec2 create-launch-template --launch-template-name "$AWS_LT_NAME" \
      --launch-template-data "{\"ImageId\":\"$AMI\",\"InstanceType\":\"c6a.large\",\"EbsOptimized\":true}" >/dev/null 2>&1
  set -e

  aws ec2 create-launch-template-version --launch-template-name "$AWS_LT_NAME" --source-version '$Latest' \
      --launch-template-data "{\"ImageId\":\"$AMI\"}" >/dev/null
  aws ec2 modify-launch-template --launch-template-name "$AWS_LT_NAME" --default-version '$Latest' >/devnull 2>&1 || true

  IID2=$(aws ec2 run-instances --launch-template "LaunchTemplateName=${AWS_LT_NAME},Version=\$Default" --count 1 --query 'Instances[0].InstanceId' --output text)
  log "[OK] Instance: $IID2"
}

# ==============================================================================
# PACKER + FIRECRACKER SCAFFOLDS (unchanged)
# ==============================================================================
emit_packer_scaffold(){
  local out="${PACKER_OUT:-${BUILD_ROOT}/packer}"
  mkdir -p "$out"
  cat >"$out/README.txt" <<'EOF'
Packer scaffold:
packer {
  required_plugins { qemu = { source = "github.com/hashicorp/qemu", version = ">=1.1.0" } }
}
variable "iso_path" { type=string }
variable "vm_name" { type=string default="debian-guest" }
source "qemu" "debian" {
  iso_url = var.iso_path
  output_directory = "output-${var.vm_name}"
  headless = true
  accelerator = "kvm"
  cpus = 2
  memory = 2048
  disk_size = "20G"
  ssh_username = "root"
  ssh_password = "root"
  ssh_timeout  = "30m"
  boot_wait    = "5s"
}
build { name = var.vm_name sources = ["source.qemu.debian"] }
EOF
  log "[OK] packer scaffold at: $out"
}

emit_firecracker_scaffold(){
  local out="${FIRECRACKER_OUT:-${BUILD_ROOT}/firecracker}"
  install -d "$out"
  cat >"$out/extract-kernel-initrd.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
RAW_IMG="${1:-}"; OUT_DIR="${2:-.}"
[[ -n "$RAW_IMG" && -s "$RAW_IMG" ]] || { echo "usage: $0 <rootfs.raw> [outdir]" >&2; exit 2; }
mkdir -p "$OUT_DIR"
command -v guestmount >/dev/null || { echo "[X] apt install libguestfs-tools"; exit 1; }
mnt="$(mktemp -d)"
trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' EXIT
guestmount -a "$RAW_IMG" -i "$mnt"
cp -Lf "$mnt"/boot/vmlinuz* "$OUT_DIR/kernel"
cp -Lf "$mnt"/boot/initrd*  "$OUT_DIR/initrd"
echo "[OK] kernel/initrd -> $OUT_DIR"
EOF
  chmod +x "$out/extract-kernel-initrd.sh"
  log "[OK] Firecracker scaffold in $out"
}

# ==============================================================================
# DISPATCHER
# ==============================================================================
case "$TARGET" in
  proxmox-cluster)     proxmox_cluster ;;
  image-only)
    log "[*] Building role ISOs only…"
    emit_sb_keys_if_missing
    MASTER_PAYLOAD="$(mktemp)"; emit_postinstall_master "$MASTER_PAYLOAD"
    MASTER_ISO="$BUILD_ROOT/master.iso"; mk_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"

    mkdir -p "$BUILD_ROOT/hub"
    # Seed placeholder hub.env (real one overwritten after master boots)
    cat >"$BUILD_ROOT/hub/hub.env" <<EOF
WG0_IP=${WG0_IP}
WG1_IP=${WG1_IP}
WG2_IP=${WG2_IP}
WG3_IP=${WG3_IP}
WG0_PORT=${WG0_PORT}
WG1_PORT=${WG1_PORT}
WG2_PORT=${WG2_PORT}
WG3_PORT=${WG3_PORT}
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}
HUB_LAN=${MASTER_LAN}
WG0_PUB=
WG1_PUB=
WG2_PUB=
WG3_PUB=
EOF

    P="$(mktemp)"; emit_minion_wrapper "$P" "prom"    "10.77.0.10/32" "10.78.0.10/32" "10.79.0.10/32" "10.80.0.10/32"; mk_iso "$PROM_NAME" "$P" "$BUILD_ROOT/prom.iso"    "$PROM_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "graf"    "10.77.0.11/32" "10.78.0.11/32" "10.79.0.11/32" "10.80.0.11/32"; mk_iso "$GRAF_NAME" "$P" "$BUILD_ROOT/graf.iso"    "$GRAF_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "k8s"     "10.77.0.12/32" "10.78.0.12/32" "10.79.0.12/32" "10.80.0.12/32"; mk_iso "$K8S_NAME"  "$P" "$BUILD_ROOT/k8s.iso"     "$K8S_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "storage" "10.77.0.13/32" "10.78.0.13/32" "10.79.0.13/32" "10.80.0.13/32"; mk_iso "$STOR_NAME" "$P" "$BUILD_ROOT/storage.iso" "$STOR_IP"
    log "[DONE] ISOs in $BUILD_ROOT"
    ;;
  aws)                 emit_sb_keys_if_missing; aws_import_register_launch ;;
  packer-scaffold)     emit_packer_scaffold ;;
  firecracker-bundle)  emit_firecracker_scaffold ;;
  *)                   die "Unknown TARGET=$TARGET" ;;
esac
(eBPF) root@onyx:~/fb-back-no30# 
