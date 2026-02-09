#!/usr/bin/env bash
# deploy-beta.v3.sh — 3 roles: master / etcd / worker
#
# UPDATED (beta.v3):
#   - etcd stays cattle, but gets gold-standard k8s+calico+helm bashrc
#   - helm installed on master + etcd
#   - ansible user + keys on ALL nodes (and ansible pkg)
#   - k8s/cni prereqs hardened: extra modules + sysctls
#   - FIX: node nftables FORWARD is no longer policy drop (breaks k8s networking)
#   - helm-autobootstrap hook runs after cluster bootstrap (exec /srv/k8s/helm/bootstrap.sh)
#   - FIX(beta3): install Calico using Tigera Operator (tigera-operator.yaml + custom-resources.yaml)
#   - FIX(beta3): open Calico Typha port 5473 (LAN)
#   - FIX(beta3): add rp_filter=0 + src_valid_mark=1 sysctls (Calico/WG friendliness)
#   - FIX(beta3): ensure /opt/cni/bin exists + has plugin binaries
#
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

# =============================================================================
# Logging / errors
# =============================================================================
ts() { date '+%F %T'; }
log()  { echo "[INFO]  $(ts) - $*"; }
warn() { echo "[WARN]  $(ts) - $*" >&2; }
err()  { echo "[ERROR] $(ts) - $*" >&2; }
die()  { err "$*"; exit 1; }

on_err() {
  local ec=$?
  err "Failed at line $1 (exit=$ec)"
  exit "$ec"
}
trap 'on_err $LINENO' ERR

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

# =============================================================================
# Paths
# =============================================================================
_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
_repo_root="$(git -C "$_script_dir" rev-parse --show-toplevel 2>/dev/null || echo "$_script_dir")"

BUILD_ROOT="${BUILD_ROOT:-/root/builds}"
mkdir -p "$BUILD_ROOT"

DARKSITE_SRC="${DARKSITE_SRC:-${_repo_root}/payload/darksite}"

# =============================================================================
# User / auth
# =============================================================================
ADMIN_USER="${ADMIN_USER:-todd}"
ANSIBLE_USER="${ANSIBLE_USER:-ansible}"          # NEW: ansible user everywhere
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"   # yes|no
SSH_PUBKEY="${SSH_PUBKEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgqdaF+C41xwLS41+dOTnpsrDTPkAwo4Zejn4tb0lOt todd@onyx.unixbox.net}"

# Optional enrollment SSH keypair (embedded for emergency/manual rescue)
ENROLL_KEY_DIR="${ENROLL_KEY_DIR:-$BUILD_ROOT/keys}"
ENROLL_KEY_NAME="${ENROLL_KEY_NAME:-enroll_ed25519}"
ENROLL_KEY_PRIV="$ENROLL_KEY_DIR/$ENROLL_KEY_NAME"
ENROLL_KEY_PUB="$ENROLL_KEY_DIR/$ENROLL_KEY_NAME.pub"

ensure_enroll_keypair() {
  mkdir -p "$ENROLL_KEY_DIR"
  if [[ ! -s "$ENROLL_KEY_PRIV" || ! -s "$ENROLL_KEY_PUB" ]]; then
    require_cmd ssh-keygen
    log "Generating enrollment SSH keypair: $ENROLL_KEY_PRIV"
    ssh-keygen -t ed25519 -N "" -f "$ENROLL_KEY_PRIV" -C "enroll@cluster" >/dev/null
  else
    log "Using existing enrollment keypair: $ENROLL_KEY_PRIV"
  fi
}

# =============================================================================
# Helm intent (NEW)
# =============================================================================
HELM_ENABLE="${HELM_ENABLE:-yes}"                       # yes|no
HELM_BOOTSTRAP_ENABLE="${HELM_BOOTSTRAP_ENABLE:-yes}"   # yes|no
HELM_BOOTSTRAP_SCRIPT="${HELM_BOOTSTRAP_SCRIPT:-/srv/k8s/helm/bootstrap.sh}"

# =============================================================================
# Proxmox target
# =============================================================================
INPUT="${INPUT:-1}"
case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) die "Unknown INPUT=$INPUT (expected 1|fiend,2|dragon,3|lion)" ;;
esac

ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"

# =============================================================================
# Debian installer inputs
# =============================================================================
ISO_ORIG="${ISO_ORIG:-/root/debian-13.2.0-amd64-netinst.iso}"
DEBIAN_CODENAME="${DEBIAN_CODENAME:-trixie}"
ARCH="${ARCH:-amd64}"

PRESEED_LOCALE="${PRESEED_LOCALE:-en_US.UTF-8}"
PRESEED_KEYMAP="${PRESEED_KEYMAP:-us}"
PRESEED_TIMEZONE="${PRESEED_TIMEZONE:-America/Vancouver}"
PRESEED_BOOTDEV="${PRESEED_BOOTDEV:-/dev/sda}"

PRESEED_ROOT_PASSWORD_HASH="${PRESEED_ROOT_PASSWORD_HASH:-}"
PRESEED_ROOT_PASSWORD="${PRESEED_ROOT_PASSWORD:-root}"

# Keep minimal, but include tools we rely on early.
# NEW: add bash-completion + ansible so it’s always there early.
PRESEED_EXTRA_PKGS="${PRESEED_EXTRA_PKGS:-openssh-server qemu-guest-agent ca-certificates curl gpg jq rsync nftables wireguard-tools bash-completion ansible linux-headers-6.12.57+deb13-amd64 bpfcc-tools python3-bpfcc}"

NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3}"
DOMAIN="${DOMAIN:-unixbox.net}"

# =============================================================================
# WireGuard (management plane)
# =============================================================================
WG_IF="${WG_IF:-wg0}"
WG_NET="${WG_NET:-10.78.0.0/16}"
WG_PORT="${WG_PORT:-51821}"
WG_MTU="${WG_MTU:-1420}"
MASTER_WG_CIDR="${MASTER_WG_CIDR:-10.78.0.1/16}"

# =============================================================================
# Salt / Ansible intent
# =============================================================================
SALT_ENABLE="${SALT_ENABLE:-yes}"           # yes|no
SALT_BIND_ADDR="${SALT_BIND_ADDR:-0.0.0.0}"
SALT_AUTO_ACCEPT="${SALT_AUTO_ACCEPT:-yes}" # yes|no
ANSIBLE_ENABLE="${ANSIBLE_ENABLE:-yes}"     # yes|no

# =============================================================================
# Kubernetes / cluster bootstrap (optional)
# =============================================================================
K8S_MINOR="${K8S_MINOR:-v1.35}"
POD_CIDR="${POD_CIDR:-192.168.0.0/16}"
SVC_CIDR="${SVC_CIDR:-10.96.0.0/12}"

CALICO_INSTALL="${CALICO_INSTALL:-yes}"
CALICO_VERSION="${CALICO_VERSION:-v3.31.3}"
CALICO_INSTALL_METHOD="${CALICO_INSTALL_METHOD:-operator}" # operator|manifest

# Optional placeholders (not used directly here, but passed through config for future expansion)
TIGERA_ENTERPRISE_ENABLE="${TIGERA_ENTERPRISE_ENABLE:-no}"  # yes|no
TIGERA_EE_VERSION="${TIGERA_EE_VERSION:-v3.22.1}"

CLUSTER_BOOTSTRAP_ENABLE="${CLUSTER_BOOTSTRAP_ENABLE:-yes}"  # yes|no

# =============================================================================
# Inventory / sizing
# =============================================================================
MASTER_ID="${MASTER_ID:-999}"
MASTER_NAME="${MASTER_NAME:-master}"
MASTER_LAN="${MASTER_LAN:-10.100.10.20}"

ETCD_COUNT="${ETCD_COUNT:-1}"
WORKER_COUNT="${WORKER_COUNT:-2}"

ETCD_VMID_BASE="${ETCD_VMID_BASE:-1000}"
ETCD_LAN_BASE="${ETCD_LAN_BASE:-10.100.10.30}"
ETCD_WG_BASE_OCTET="${ETCD_WG_BASE_OCTET:-5}"

WORKER_VMID_BASE="${WORKER_VMID_BASE:-1010}"
WORKER_LAN_BASE="${WORKER_LAN_BASE:-10.100.10.40}"
WORKER_WG_BASE_OCTET="${WORKER_WG_BASE_OCTET:-11}"

MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-4}"; MASTER_DISK_GB="${MASTER_DISK_GB:-40}"
ETCD_MEM="${ETCD_MEM:-8192}";     ETCD_CORES="${ETCD_CORES:-4}";     ETCD_DISK_GB="${ETCD_DISK_GB:-50}"
WORKER_MEM="${WORKER_MEM:-8192}"; WORKER_CORES="${WORKER_CORES:-4}"; WORKER_DISK_GB="${WORKER_DISK_GB:-60}"

LEAVE_RUNNING="${LEAVE_RUNNING:-yes}" # yes|no

# =============================================================================
# SSH to Proxmox (host key pinned per-run file)
# =============================================================================
KNOWN_HOSTS="${KNOWN_HOSTS:-$BUILD_ROOT/known_hosts}"
mkdir -p "$(dirname "$KNOWN_HOSTS")"
touch "$KNOWN_HOSTS"
chmod 600 "$KNOWN_HOSTS"

SSH_OPTS=(
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$KNOWN_HOSTS"
  -o GlobalKnownHostsFile=/dev/null
  -o CheckHostIP=yes
  -o ConnectTimeout=8
  -o BatchMode=yes
)

sssh() { ssh -q "${SSH_OPTS[@]}" "$@"; }
sscp() { scp -q -o BatchMode=yes -o ConnectTimeout=8 -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new "$@"; }
pmx()  { sssh root@"$PROXMOX_HOST" "$@"; }

# =============================================================================
# Proxmox helpers
# =============================================================================
pmx_vm_state() { pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }

pmx_wait_for_state() {
  local vmid="$1" want="$2" timeout="${3:-2400}" poll="${4:-2}"
  local start state
  start="$(date +%s)"
  log "Waiting for VM $vmid to be $want ..."
  while :; do
    state="$(pmx_vm_state "$vmid")"
    [[ "$state" == "$want" ]] && { log "VM $vmid is $state"; return 0; }
    (( $(date +%s) - start > timeout )) && die "Timeout waiting VM $vmid to be $want (state=$state)"
    sleep "$poll"
  done
}

pmx_upload_iso() {
  local iso_file="$1"
  local iso_base; iso_base="$(basename "$iso_file")"
  sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base"
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${iso_base}\" && exit 0; sleep 1; done; exit 1" \
    || warn "pvesm list didn't show ${iso_base} yet—will still try to attach"
  echo "$iso_base"
}

pmx_deploy_vm() {
  local vmid="$1" vmname="$2" lan_ip="$3" iso_file="$4" mem="$5" cores="$6" disk_gb="$7"
  local iso_base
  iso_base="$(pmx_upload_iso "$iso_file")"

  pmx \
    VMID="$vmid" VMNAME="${vmname}-${DOMAIN}" VMIP="$lan_ip" FINAL_ISO="$iso_base" \
    VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" \
    DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
qm destroy "$VMID" --purge >/dev/null 2>&1 || true

qm create "$VMID" \
  --name "$VMNAME" \
  --description "$VMIP" \
  --memory "$MEMORY_MB" --cores "$CORES" \
  --cpu host --sockets 1 \
  --machine q35 \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} \
  --serial0 socket \
  --ostype l26 \
  --agent enabled=1,fstrim_cloned_disks=1

qm set "$VMID" --description "$VMIP" >/dev/null 2>&1 || true

qm set "$VMID" --bios ovmf
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=1
qm set "$VMID" --tpmstate0 ${VM_STORAGE}:1,version=v2.0,size=4M

for i in {1..10}; do
  if qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom 2>/dev/null; then
    break
  fi
  sleep 1
done

qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}

pmx_boot_from_disk() {
  local vmid="$1"
  pmx "qm set $vmid --delete ide2 2>/dev/null || true; qm set $vmid --boot order=scsi0; qm start $vmid"
  pmx_wait_for_state "$vmid" "running" 600 2
}

# =============================================================================
# Node spec generation
# =============================================================================
ip_dec_last_octet() {
  local ip="$1" dec="$2"
  local a b c d
  IFS=. read -r a b c d <<<"$ip"
  d=$((d - dec))
  echo "${a}.${b}.${c}.${d}"
}

wg_from_octet() { local oct="$1"; echo "10.78.0.${oct}/32"; }

DEFAULT_NODE_SPEC="$(
  {
    echo "#vmid name role lan_ip wg_cidr"
    echo "${MASTER_ID} ${MASTER_NAME} master ${MASTER_LAN} ${MASTER_WG_CIDR}"

    for ((i=1; i<=ETCD_COUNT; i++)); do
      vmid=$((ETCD_VMID_BASE + (i-1)))
      lan="$(ip_dec_last_octet "$ETCD_LAN_BASE" $((i-1)))"
      wg_oct=$((ETCD_WG_BASE_OCTET + (i-1)))
      echo "${vmid} etcd-${i} etcd ${lan} $(wg_from_octet "$wg_oct")"
    done

    for ((i=1; i<=WORKER_COUNT; i++)); do
      vmid=$((WORKER_VMID_BASE + (i-1)))
      lan="$(ip_dec_last_octet "$WORKER_LAN_BASE" $((i-1)))"
      wg_oct=$((WORKER_WG_BASE_OCTET + (i-1)))
      echo "${vmid} worker-${i} worker ${lan} $(wg_from_octet "$wg_oct")"
    done
  } | sed 's/[[:space:]]\+/ /g'
)"
NODE_SPEC="${NODE_SPEC:-$DEFAULT_NODE_SPEC}"

declare -a NODE_VMID NODE_NAME NODE_ROLE NODE_LAN NODE_WG

parse_nodes() {
  local line vmid name role lan wg
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    IFS=' ' read -r vmid name role lan wg <<<"$line"
    [[ -n "${vmid:-}" && -n "${name:-}" && -n "${role:-}" && -n "${lan:-}" && -n "${wg:-}" ]] \
      || die "Bad NODE_SPEC line: $line"
    NODE_VMID+=("$vmid"); NODE_NAME+=("$name"); NODE_ROLE+=("$role"); NODE_LAN+=("$lan"); NODE_WG+=("$wg")
  done <<<"$NODE_SPEC"

  local found_master=0
  for ((i=0; i<${#NODE_VMID[@]}; i++)); do
    if [[ "${NODE_ROLE[$i]}" == "master" ]]; then
      found_master=1
      MASTER_ID="${NODE_VMID[$i]}"
      MASTER_NAME="${NODE_NAME[$i]}"
      MASTER_LAN="${NODE_LAN[$i]}"
      MASTER_WG_CIDR="${NODE_WG[$i]}"
    fi
  done
  ((found_master==1)) || die "NODE_SPEC must include one 'master' role"
}

# =============================================================================
# Preseed helpers
# =============================================================================
preseed_password_block() {
  if [[ -n "$PRESEED_ROOT_PASSWORD_HASH" ]]; then
    cat <<EOF
d-i passwd/root-login boolean true
d-i passwd/root-password-crypted password ${PRESEED_ROOT_PASSWORD_HASH}
d-i passwd/make-user boolean false
EOF
  else
    warn "PRESEED_ROOT_PASSWORD_HASH not set; using plaintext PRESEED_ROOT_PASSWORD (not recommended)."
    cat <<EOF
d-i passwd/root-login boolean true
d-i passwd/root-password password ${PRESEED_ROOT_PASSWORD}
d-i passwd/root-password-again password ${PRESEED_ROOT_PASSWORD}
d-i passwd/make-user boolean false
EOF
  fi
}

emit_bootstrap_unit() {
  cat <<'EOF'
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
}

# =============================================================================
# POSTINSTALL: MASTER
# =============================================================================
emit_postinstall_master() {
  cat <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022
LOG="/var/log/postinstall-master.log"
exec > >(tee -a "$LOG") 2>&1

ts(){ date '+%F %T'; }
log(){ echo "[INFO]  $(ts) - $*"; }
warn(){ echo "[WARN]  $(ts) - $*" >&2; }

finalize_poweroff() {
  log "Finalizing: mark bootstrap done, disable bootstrap.service, power off"
  touch /root/.bootstrap_done || true

  systemctl disable bootstrap.service 2>/dev/null || true
  systemctl daemon-reload || true
  sync || true

  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run --unit=bootstrap-poweroff --description="Bootstrap poweroff" \
      --property=Type=oneshot --on-active=4 \
      /usr/bin/systemctl poweroff --no-wall --force --force >/dev/null 2>&1 || true
    return 0
  fi

  /usr/bin/systemctl --no-block poweroff --no-wall --force --force \
    || poweroff -f \
    || shutdown -h now \
    || true
}

on_err() {
  warn "Postinstall FAILED at line $1"
  touch /root/.bootstrap_failed || true
  finalize_poweroff
  exit 1
}
trap 'on_err $LINENO' ERR

# Load seeded env
if [[ -r /etc/environment.d/99-provision.conf ]]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/environment.d/99-provision.conf
  set +a
fi

: "${DEBIAN_CODENAME:=trixie}"
: "${DOMAIN:=unixbox.net}"
: "${ADMIN_USER:=todd}"
: "${ANSIBLE_USER:=ansible}"
: "${ALLOW_ADMIN_PASSWORD:=no}"
: "${MASTER_LAN:=10.100.10.20}"

: "${WG_IF:=wg0}"
: "${WG_PORT:=51821}"
: "${WG_MTU:=1420}"
: "${WG_NET:=10.78.0.0/16}"
: "${MASTER_WG_CIDR:=10.78.0.1/16}"

: "${SALT_ENABLE:=yes}"
: "${SALT_BIND_ADDR:=0.0.0.0}"
: "${SALT_AUTO_ACCEPT:=yes}"
: "${ANSIBLE_ENABLE:=yes}"

: "${HELM_ENABLE:=yes}"
: "${HELM_BOOTSTRAP_ENABLE:=yes}"
: "${HELM_BOOTSTRAP_SCRIPT:=/srv/k8s/helm/bootstrap.sh}"

: "${K8S_MINOR:=v1.35}"
: "${POD_CIDR:=192.168.0.0/16}"
: "${SVC_CIDR:=10.96.0.0/12}"

: "${CALICO_INSTALL:=yes}"
: "${CALICO_VERSION:=v3.31.3}"
: "${CALICO_INSTALL_METHOD:=operator}"
: "${TIGERA_ENTERPRISE_ENABLE:=no}"
: "${TIGERA_EE_VERSION:=v3.22.1}"

: "${ETCD_COUNT:=1}"
: "${WORKER_COUNT:=2}"

: "${CLUSTER_BOOTSTRAP_ENABLE:=yes}"

noninteractive_guards() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a

  install -d -m0755 /etc/needrestart/conf.d || true
  cat >/etc/needrestart/conf.d/99-noninteractive.conf <<'EOF'
$nrconf{restart} = 'a';
EOF

  # Global dpkg conffile policy: keep existing, accept defaults, never prompt.
  cat >/etc/apt/apt.conf.d/99noninteractive <<'EOF'
Dpkg::Options { "--force-confdef"; "--force-confold"; };
APT::Get::Assume-Yes "true";
EOF

  cat >/etc/apt/apt.conf.d/99force-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
EOF
}

apt_sources_fix() {
  log "Setting APT sources (HTTPS)"
  cat >/etc/apt/sources.list <<EOF
deb https://deb.debian.org/debian ${DEBIAN_CODENAME} main contrib non-free non-free-firmware
deb https://security.debian.org/debian-security ${DEBIAN_CODENAME}-security main contrib non-free non-free-firmware
deb https://deb.debian.org/debian ${DEBIAN_CODENAME}-updates main contrib non-free non-free-firmware
EOF

  for i in 1 2 3 4 5; do
    apt-get update -y && return 0
    sleep $((i*3))
  done
  return 1
}

apt_repair_if_needed() {
  dpkg --configure -a || true
  apt-get -f install -y || true
}

ensure_base() {
  noninteractive_guards
  apt_sources_fix
  apt_repair_if_needed
  log "Installing base packages"
  apt-get install -y --no-install-recommends \
    sudo openssh-server ca-certificates curl wget gpg jq rsync \
    qemu-guest-agent chrony rsyslog \
    nftables wireguard-tools \
    python3 python3-venv \
    git vim tmux \
    bash-completion \
    ansible

  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true
}

ensure_user_with_keys() {
  local user="$1"
  local keys_file="$2"
  log "Ensuring user: $user"
  id -u "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
  install -d -m700 -o "$user" -g "$user" "/home/$user/.ssh"
  touch "/home/$user/.ssh/authorized_keys"
  chmod 600 "/home/$user/.ssh/authorized_keys"
  chown -R "$user:$user" "/home/$user/.ssh"

  if [[ -s "$keys_file" ]]; then
    while IFS= read -r k; do
      [[ -z "$k" ]] && continue
      grep -qxF "$k" "/home/$user/.ssh/authorized_keys" || echo "$k" >>"/home/$user/.ssh/authorized_keys"
    done <"$keys_file"
  fi

  if [[ -s "/root/darksite/enroll_ed25519.pub" ]]; then
    k="$(head -n1 /root/darksite/enroll_ed25519.pub)"
    grep -qxF "$k" "/home/$user/.ssh/authorized_keys" || echo "$k" >>"/home/$user/.ssh/authorized_keys"
  fi

  install -d -m755 /etc/sudoers.d
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" >"/etc/sudoers.d/90-${user}"
  chmod 0440 "/etc/sudoers.d/90-${user}"
  visudo -c >/dev/null || true
}

ensure_admin_and_ansible_users() {
  ensure_user_with_keys "$ADMIN_USER" "/root/darksite/authorized_keys.${ADMIN_USER}"
  ensure_user_with_keys "$ANSIBLE_USER" "/root/darksite/authorized_keys.${ANSIBLE_USER}"
}

ssh_harden() {
  log "Hardening SSH"
  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/99-hard.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

  if [[ "$ALLOW_ADMIN_PASSWORD" == "yes" ]]; then
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi

  sshd -t && systemctl restart ssh || true
}

# -----------------------------------------------------------------------------
# Console profile (MASTER): bashrc + tmux + vim, seeded to /etc/skel and synced
# -----------------------------------------------------------------------------
seed_tmux_conf_common() {
  apt-get install -y --no-install-recommends tmux >/dev/null 2>&1 || true
  install -d -m0755 /etc/skel

  cat > /etc/skel/.tmux.conf <<'EOF'
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

  cp -f /etc/skel/.tmux.conf /root/.tmux.conf || true
}

seed_vim_conf_common() {
  apt-get install -y --no-install-recommends vim git >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends \
    vim-airline vim-airline-themes vim-ctrlp vim-fugitive vim-gitgutter vim-tabular \
    >/dev/null 2>&1 || true

  install -d -m0755 /etc/skel
  install -d -m0755 /etc/skel/.vim/autoload/airline/themes

  cat > /etc/skel/.vimrc <<'EOF'
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
let g:airline_theme = 'dark'
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

  install -d -m0755 /root/.vim/autoload/airline/themes
  cp -f /etc/skel/.vimrc /root/.vimrc || true
  cp -f /etc/skel/.vim/autoload/airline/themes/custom.vim /root/.vim/autoload/airline/themes/custom.vim || true
}

seed_bashrc_master() {
  install -d -m0755 /etc/skel

  cat > /etc/skel/.bashrc <<'EOF'

fb_banner() {
  cat << 'FBBANNER'

        ..                           ..                  ..
  < .z@8"`                     . uW8"                  dF
   !@88E           x.    .     `t888                  '88bu.
   '888E   u     .@88k  z88u    8888   .        .u    '*88888bu
    888E u@8NL  ~"8888 ^8888    9888.z88N    ud8888.    ^"*8888N
    888E`"88*"    8888  888R    9888  888E :888'8888.  beWE "888L
    888E .dN.     8888  888R    9888  888E d888 '88%"  888E  888E
    888E~8888     8888  888R    9888  888E 8888.+"     888E  888E
    888E '888&    8888 ,888B .  9888  888E 8888L       888E  888F
    888E  9888.  "8888Y 8888"  .8888  888" '8888c. .+ .888N..888
  '"888*" 4888"   `Y"   'YP     `%888*%"    "88888%    `"888*""
     ""    ""                      "`         "YP'        "" os
                secure · platfourms -> everywhere

FBBANNER
}

if [ -z "${FBNOBANNER:-}" ]; then
  fb_banner
  export FBNOBANNER=1
fi

if [ "$EUID" -eq 0 ]; then
  PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
else
  PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi

if [ -f /etc/bash_completion ]; then
  . /etc/bash_completion
fi

alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -rf'
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

# Salt helper commands
slist() {
  salt --static --no-color --out=json --out-indent=-1 "*" \
    grains.item host os osrelease ipv4 num_cpus mem_total roles lan_ip wg_ip role \
  | jq -r '
      to_entries[]
      | .key as $id
      | .value as $v
      | ($v.ipv4 // []
         | map(select(. != "127.0.0.1" and . != "0.0.0.0"))
         | join("  ")) as $ips
      | [
          $id,
          ($v.host // ""),
          (($v.os // "") + " " + ($v.osrelease // "")),
          ($v.lan_ip // ""),
          ($v.wg_ip // ""),
          $ips,
          ($v.num_cpus // ""),
          ($v.mem_total // ""),
          ($v.role // "")
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

# K8s helper commands (via role:etcd control plane)
skcls()   { salt -G "role:etcd" cmd.run 'kubectl cluster-info' -l quiet; }
sknodes() { salt -G "role:etcd" cmd.run 'kubectl get nodes -o wide' -l quiet; }
skpods()  { salt -G "role:etcd" cmd.run 'kubectl get pods -A -o wide' -l quiet; }

shl() {
  printf "%s\n" \
"Salt / cluster helper commands:" \
"  slist  sping  ssall  skservices  sdfall  stop5  smem5" \
"Kubernetes helpers (via role:etcd):" \
"  skcls  sknodes  skpods"
}

VENV_DIR="/root/bccenv"
if [ -d "$VENV_DIR" ] && [ -n "$PS1" ]; then
  if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$VENV_DIR" ]; then
    source "$VENV_DIR/bin/activate"
  fi
fi

echo "Welcome $USER — connected to $(hostname) on $(date)"
echo "Type 'shl' for the helper commandis list."
EOF

  cp -f /etc/skel/.bashrc /root/.bashrc || true
}

sync_skel_to_existing_users() {
  local files=(.bashrc .vimrc .tmux.conf)
  local home f

  for home in /root $(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null); do
    for f in "${files[@]}"; do
      [[ -f "/etc/skel/$f" ]] || continue
      cp -f "/etc/skel/$f" "$home/$f" || true
    done
  done
}

console_profile_apply_master() {
  log "Seeding console profile (bashrc + tmux + vim)"
  seed_bashrc_master
  seed_tmux_conf_common
  seed_vim_conf_common
  sync_skel_to_existing_users
}

wg_hub() {
  log "Configuring WireGuard hub (${WG_IF})"
  install -d -m700 /etc/wireguard
  umask 077
  if [[ ! -s "/etc/wireguard/${WG_IF}.key" ]]; then
    wg genkey | tee "/etc/wireguard/${WG_IF}.key" | wg pubkey >"/etc/wireguard/${WG_IF}.pub"
  fi
  umask 022

  cat >"/etc/wireguard/${WG_IF}.conf" <<EOF
[Interface]
Address    = ${MASTER_WG_CIDR}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "/etc/wireguard/${WG_IF}.key")
MTU        = ${WG_MTU}
EOF
  chmod 600 "/etc/wireguard/${WG_IF}.conf"

  systemctl enable --now "wg-quick@${WG_IF}" || true
}

master_sysctls() {
  log "Enabling IP forwarding (required for WG hub routing)"
  cat >/etc/sysctl.d/98-wg-hub.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

salt_repo_setup() {
  log "Setting up SaltProject repo"
  install -d -m0755 /etc/apt/keyrings

  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public \
    -o /etc/apt/keyrings/salt-archive-keyring.pgp
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp

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
}

salt_master_setup() {
  [[ "$SALT_ENABLE" == "yes" ]] || { log "Salt disabled"; return 0; }
  log "Installing Salt master (bind=${SALT_BIND_ADDR})"
  salt_repo_setup
  apt-get install -y --no-install-recommends salt-master salt-api salt-common

  install -d -m0755 /etc/salt/master.d

  cat >/etc/salt/master.d/network.conf <<EOF
interface: ${SALT_BIND_ADDR}
ipv6: False
publish_port: 4505
ret_port: 4506
EOF

  cat >/etc/salt/master.d/api.conf <<EOF
rest_cherrypy:
  host: ${SALT_BIND_ADDR}
  port: 8000
  disable_ssl: True
EOF

  if [[ "$SALT_AUTO_ACCEPT" == "yes" ]]; then
    cat >/etc/salt/master.d/autoaccept.conf <<'EOF'
auto_accept: True
EOF
  fi

  systemctl enable --now salt-master salt-api || true
}

ansible_setup() {
  [[ "$ANSIBLE_ENABLE" == "yes" ]] || { log "Ansible disabled"; return 0; }
  log "Installing Ansible (and baseline config)"
  apt-get install -y --no-install-recommends ansible

  mkdir -p /etc/ansible
  cat >/etc/ansible/ansible.cfg <<'EOF'
[defaults]
host_key_checking = False
inventory = /etc/ansible/hosts
timeout = 30
forks = 20

[ssh_connection]
pipelining = True
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o ServerAliveInterval=15 -o ServerAliveCountMax=3
EOF

  : > /etc/ansible/hosts
}

k8s_repo_setup_master_kubectl() {
  log "Installing kubectl on master (for calico/bootstrap)"
  apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl gpg
  install -d -m0755 /etc/apt/keyrings
  curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" \
    | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /" \
    > /etc/apt/sources.list.d/kubernetes.list
  apt-get update -y || true
  apt-get install -y --no-install-recommends kubectl
  apt-mark hold kubectl || true
}

install_helm() {
  [[ "${HELM_ENABLE}" == "yes" ]] || { log "Helm disabled"; return 0; }
  command -v helm >/dev/null 2>&1 && { log "Helm already installed"; return 0; }

  log "Installing Helm"
  # Try Debian first; fallback to official installer script.
  if apt-cache show helm >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends helm || true
  fi
  if command -v helm >/dev/null 2>&1; then
    return 0
  fi

  # Fallback: official get-helm-3 script
  curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  chmod 700 /tmp/get_helm.sh
  /tmp/get_helm.sh || true
  rm -f /tmp/get_helm.sh || true

  command -v helm >/dev/null 2>&1 || warn "Helm install appears to have failed"
}

nft_firewall() {
  log "Configuring nftables (ssh + salt + wg hub routing)"
  local lan_if
  lan_if="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')" || true
  : "${lan_if:=ens18}"

  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept

    tcp dport 22 accept
    udp dport ${WG_PORT} accept
    tcp dport { 4505, 4506, 8000 } accept

    # Allow anything arriving on wg (master is management hub)
    iifname "${WG_IF}" accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept

    # WG peers must be able to talk to each other (wg0 -> wg0)
    iifname "${WG_IF}" oifname "${WG_IF}" accept

    # WG <-> LAN (management plane reachability)
    iifname "${WG_IF}" oifname "${lan_if}" accept
    iifname "${lan_if}" oifname "${WG_IF}" accept
  }

  chain output { type filter hook output priority 0; policy accept; }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "${lan_if}" masquerade
  }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

install_wg_sync_timer() {
  log "Installing wg-sync-salt tool + systemd timer (auto peer management)"
  install -d -m0755 /usr/local/sbin

  cat >/usr/local/sbin/wg-sync-salt <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ts(){ date '+%F %T'; }
log(){ echo "[wg-sync] $(ts) - $*"; }
warn(){ echo "[wg-sync] $(ts) - WARN: $*" >&2; }

if [[ -r /etc/environment.d/99-provision.conf ]]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/environment.d/99-provision.conf
  set +a
fi

: "${WG_IF:=wg0}"
: "${WG_PORT:=51821}"
: "${WG_MTU:=1420}"
: "${WG_NET:=10.78.0.0/16}"
: "${MASTER_LAN:=10.100.10.20}"
: "${MASTER_WG_CIDR:=10.78.0.1/16}"

CONF="/etc/wireguard/${WG_IF}.conf"
PUBF="/etc/wireguard/${WG_IF}.pub"

command -v salt >/dev/null 2>&1 || { warn "salt not installed"; exit 0; }
command -v jq   >/dev/null 2>&1 || { warn "jq not installed"; exit 0; }
command -v wg   >/dev/null 2>&1 || { warn "wg not installed"; exit 0; }
command -v wg-quick >/dev/null 2>&1 || { warn "wg-quick not installed"; exit 0; }
[[ -s "$CONF" && -s "$PUBF" ]] || { warn "missing $CONF or $PUBF"; exit 0; }

MASTER_PUB="$(cat "$PUBF")"
json="$(salt --static --no-color --out=json '*' grains.item wg_pub wg_cidr wg_ip role lan_ip 2>/dev/null || echo '{}')"

peers_tsv="$(jq -r '
  to_entries[]
  | .key as $id
  | .value as $v
  | [$id, ($v.wg_pub // ""), ($v.wg_cidr // ""), ($v.wg_ip // ""), ($v.role // "worker"), ($v.lan_ip // "")]
  | @tsv
' <<<"$json" || true)"

iface_tmp="$(mktemp)"
awk 'BEGIN{p=1} /^\[Peer\]/{p=0} p{print}' "$CONF" >"$iface_tmp"

newconf="$(mktemp)"
{
  cat "$iface_tmp"
  echo ""
  while IFS=$'\t' read -r minion pub cidr ip role lanip; do
    [[ -n "$pub" && -n "$cidr" ]] || continue
    echo "[Peer]"
    echo "# ${minion} role=${role} wg_ip=${ip} lan_ip=${lanip}"
    echo "PublicKey = ${pub}"
    echo "AllowedIPs = ${cidr}"
    echo "PersistentKeepalive = 25"
    echo ""
  done <<<"$peers_tsv"
} >"$newconf"

if ! cmp -s "$newconf" "$CONF"; then
  install -m600 "$newconf" "$CONF"
  log "Updated $CONF (peers changed); syncing live config"
  wg syncconf "$WG_IF" <(wg-quick strip "$CONF") >/dev/null 2>&1 || systemctl restart "wg-quick@${WG_IF}" || true
fi

# Ansible inventory stays on WG (management plane)
inv_tmp="$(mktemp)"
{
  echo "[master]"
  echo "master ansible_host=${MASTER_WG_CIDR%/*}"
  echo ""
  echo "[etcd]"
  while IFS=$'\t' read -r minion pub cidr ip role lanip; do
    [[ "$role" == "etcd" && -n "$ip" ]] && echo "${minion} ansible_host=${ip}"
  done <<<"$peers_tsv"
  echo ""
  echo "[workers]"
  while IFS=$'\t' read -r minion pub cidr ip role lanip; do
    [[ "$role" == "worker" && -n "$ip" ]] && echo "${minion} ansible_host=${ip}"
  done <<<"$peers_tsv"
} >"$inv_tmp"
install -d -m0755 /etc/ansible
install -m0644 "$inv_tmp" /etc/ansible/hosts

# Push wg0 client config to minions (idempotent overwrite + enable)
while IFS=$'\t' read -r minion pub cidr ip role lanip; do
  [[ -n "$cidr" ]] || continue

  remote="$(cat <<RO
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

command -v wg >/dev/null 2>&1 || exit 0
command -v systemctl >/dev/null 2>&1 || exit 0

install -d -m700 /etc/wireguard
umask 077
if [[ ! -s /etc/wireguard/${WG_IF}.key ]]; then
  wg genkey | tee /etc/wireguard/${WG_IF}.key | wg pubkey >/etc/wireguard/${WG_IF}.pub
fi
priv="\$(cat /etc/wireguard/${WG_IF}.key)"
umask 022

cat >/etc/wireguard/${WG_IF}.conf <<EOF2
[Interface]
Address    = ${cidr}
PrivateKey = \${priv}
ListenPort = 0
MTU        = ${WG_MTU}

[Peer]
PublicKey  = ${MASTER_PUB}
Endpoint   = ${MASTER_LAN}:${WG_PORT}
AllowedIPs = ${WG_NET}
PersistentKeepalive = 25
EOF2

chmod 600 /etc/wireguard/${WG_IF}.conf
systemctl enable --now wg-quick@${WG_IF} >/dev/null 2>&1 || true
RO
)"
  b64="$(printf '%s' "$remote" | base64 -w0)"
  salt --static -l quiet --timeout=10 "$minion" cmd.run \
    "echo '$b64' | base64 -d >/tmp/wg-apply.sh && bash /tmp/wg-apply.sh && rm -f /tmp/wg-apply.sh" \
    >/dev/null 2>&1 || true
done <<<"$peers_tsv"

rm -f "$iface_tmp" "$newconf" "$inv_tmp" 2>/dev/null || true
EOF
  chmod 0755 /usr/local/sbin/wg-sync-salt

  cat >/etc/systemd/system/wg-sync-salt.service <<'EOF'
[Unit]
Description=Sync WireGuard peers from Salt grains
After=wg-quick@wg0.service salt-master.service network-online.target
Wants=wg-quick@wg0.service salt-master.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wg-sync-salt
EOF

  cat >/etc/systemd/system/wg-sync-salt.timer <<'EOF'
[Unit]
Description=Periodic WireGuard peer sync from Salt

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
RandomizedDelaySec=5
AccuracySec=5s
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload || true
  systemctl enable --now wg-sync-salt.timer >/dev/null 2>&1 || true
  systemctl start wg-sync-salt.service >/dev/null 2>&1 || true
}

install_cluster_autobootstrap() {
  [[ "$CLUSTER_BOOTSTRAP_ENABLE" == "yes" ]] || { log "Cluster autobootstrap disabled"; return 0; }

  log "Installing cluster-autobootstrap (systemd timer)"
  install -d -m0755 /usr/local/sbin /etc/systemd/system /srv/k8s /root/.kube

  cat >/usr/local/sbin/cluster-autobootstrap <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

LOG="/var/log/cluster-autobootstrap.log"
exec >>"$LOG" 2>&1

ts(){ date '+%F %T'; }
log(){ echo "[INFO]  $(ts) - $*"; }
warn(){ echo "[WARN]  $(ts) - $*" >&2; }

need(){ command -v "$1" >/dev/null 2>&1 || { warn "missing $1"; exit 2; }; }
need salt; need jq; need awk; need sed; need curl

DONE_FLAG="/root/.cluster_bootstrap_done"
[[ -f "$DONE_FLAG" ]] && { log "done flag present; exiting"; exit 0; }

if [[ -r /etc/environment.d/99-provision.conf ]]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/environment.d/99-provision.conf
  set +a
fi

: "${POD_CIDR:=192.168.0.0/16}"
: "${SVC_CIDR:=10.96.0.0/12}"

: "${CALICO_INSTALL:=yes}"
: "${CALICO_VERSION:=v3.31.3}"
: "${CALICO_INSTALL_METHOD:=operator}"

salt_json() { salt --out=json --static --no-color "$@" 2>/dev/null || echo '{}'; }
salt_one() { salt --out=newline_values_only -l quiet "$1" cmd.run "$2" 2>/dev/null | tr -d '\r' || true; }

refresh_wg() { command -v wg-sync-salt >/dev/null 2>&1 && wg-sync-salt || true; }

pick_first_etcd() {
  ping="$(salt_json -G 'role:etcd' test.ping)"
  echo "$ping" | jq -r 'keys[]' 2>/dev/null | sort | head -n1
}
list_etcd() {
  ping="$(salt_json -G 'role:etcd' test.ping)"
  echo "$ping" | jq -r 'keys[]' 2>/dev/null | sort
}
list_workers() {
  ping="$(salt_json -G 'role:worker' test.ping)"
  echo "$ping" | jq -r 'keys[]' 2>/dev/null | sort
}

get_lan_ip() {
  local m="$1"
  salt --out=newline_values_only -l quiet "$m" grains.get lan_ip 2>/dev/null | head -n1 | tr -d '\r' || true
}

ensure_runtime_ready() {
  local m="$1"
  local ok
  ok="$(salt_one "$m" 'systemctl is-active containerd >/dev/null 2>&1 && test -S /run/containerd/containerd.sock && echo ok || echo no')"
  [[ "$ok" == "ok" ]]
}

wait_apiserver_on_cp0() {
  local cp0="$1"
  for i in {1..90}; do
    ok="$(salt_one "$cp0" 'kubectl --kubeconfig=/etc/kubernetes/admin.conf get --raw=/readyz >/dev/null 2>&1 && echo ok || echo no')"
    [[ "$ok" == "ok" ]] && return 0
    sleep 2
  done
  return 1
}

ensure_kubeconfig_on_master() {
  local cp0="$1"
  local cfg="/root/.kube/config"
  [[ -s "$cfg" ]] && return 0
  log "Fetching admin.conf from ${cp0} -> ${cfg}"
  mkdir -p /root/.kube
  salt --out=newline_values_only -l quiet "$cp0" cmd.run "cat /etc/kubernetes/admin.conf 2>/dev/null || true" \
    | awk 'NF{print}' > "${cfg}.tmp" || true
  if [[ -s "${cfg}.tmp" ]]; then
    install -m0600 "${cfg}.tmp" "$cfg"
    rm -f "${cfg}.tmp"
    log "kubeconfig installed on master"
  else
    rm -f "${cfg}.tmp"
    warn "admin.conf not readable yet on ${cp0}"
  fi
}

fetch_url() {
  local url="$1"
  curl -fsSL --connect-timeout 10 --retry 6 --retry-delay 2 "$url"
}

calico_install_operator() {
  [[ "$CALICO_INSTALL" == "yes" ]] || return 0
  command -v kubectl >/dev/null 2>&1 || { warn "kubectl missing on master"; return 0; }
  [[ -s /root/.kube/config ]] || return 0

  # If calico-system already exists with calico-node, we’re done.
  if kubectl get ds -n calico-system calico-node >/dev/null 2>&1; then
    log "Calico (operator style) already present; skipping"
    return 0
  fi

  local ver="${CALICO_VERSION}"
  local op="https://raw.githubusercontent.com/projectcalico/calico/${ver}/manifests/tigera-operator.yaml"
  local cr="https://raw.githubusercontent.com/projectcalico/calico/${ver}/manifests/custom-resources.yaml"

  log "Installing Calico via Tigera Operator (version=${ver})"
  kubectl apply -f "$op" || true

  # Wait for operator deployment to exist, then be available.
  for i in {1..60}; do
    kubectl -n tigera-operator get deploy tigera-operator >/dev/null 2>&1 && break
    sleep 2
  done
  kubectl -n tigera-operator rollout status deploy/tigera-operator --timeout=240s || true

  # Apply custom-resources but patch CIDR to your POD_CIDR.
  tmp="$(mktemp)"
  if fetch_url "$cr" >"$tmp"; then
    sed -i "s#cidr: 192.168.0.0/16#cidr: ${POD_CIDR}#g" "$tmp" || true
    kubectl apply -f "$tmp" || true
  else
    warn "Failed to fetch custom-resources.yaml"
  fi
  rm -f "$tmp" || true

  # Wait for calico-node DS to appear and roll out.
  for i in {1..120}; do
    kubectl -n calico-system get ds calico-node >/dev/null 2>&1 && break
    sleep 2
  done
  kubectl -n calico-system rollout status ds/calico-node --timeout=600s || true
  kubectl -n calico-system rollout status deploy/calico-kube-controllers --timeout=600s || true
}

calico_install_manifest_legacy() {
  [[ "$CALICO_INSTALL" == "yes" ]] || return 0
  command -v kubectl >/dev/null 2>&1 || { warn "kubectl missing on master"; return 0; }
  [[ -s /root/.kube/config ]] || return 0

  if kubectl get ds -n calico-system calico-node >/dev/null 2>&1; then
    log "Calico already present; skipping"
    return 0
  fi

  log "Applying legacy Calico manifest (calico.yaml, version=${CALICO_VERSION})"
  kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml" || true
}

calico_apply_if_needed() {
  case "${CALICO_INSTALL_METHOD}" in
    operator)  calico_install_operator ;;
    manifest)  calico_install_manifest_legacy ;;
    *) warn "Unknown CALICO_INSTALL_METHOD=${CALICO_INSTALL_METHOD}; defaulting to operator"; calico_install_operator ;;
  esac
}

push_adminconf_to_all_etcd() {
  local cp0="$1"
  admin="$(salt_one "$cp0" 'cat /etc/kubernetes/admin.conf 2>/dev/null || true')"
  [[ -n "$admin" ]] || return 0
  b64="$(printf '%s' "$admin" | base64 -w0)"
  for m in $(list_etcd); do
    salt "$m" cmd.run "mkdir -p /etc/kubernetes /root/.kube && echo '$b64' | base64 -d >/etc/kubernetes/admin.conf && cp -f /etc/kubernetes/admin.conf /root/.kube/config && chmod 600 /etc/kubernetes/admin.conf /root/.kube/config" \
      --out=newline_values_only -l quiet >/dev/null 2>&1 || true
  done
}

bootstrap_k8s() {
  local cp0; cp0="$(pick_first_etcd)"
  [[ -n "$cp0" ]] || { log "No control-plane (role:etcd) minions reachable yet"; return 0; }

  local cp0_lan; cp0_lan="$(get_lan_ip "$cp0")"
  [[ -n "$cp0_lan" ]] || { warn "cp0 lan_ip missing (grains)"; return 0; }

  if ! ensure_runtime_ready "$cp0"; then
    warn "containerd not ready on ${cp0}; waiting"
    return 0
  fi

  init_flag="$(salt_one "$cp0" 'test -f /etc/kubernetes/admin.conf && echo yes || echo no')"
  if [[ "$init_flag" != "yes" ]]; then
    log "Running kubeadm init on ${cp0} (LAN advertise=${cp0_lan})"
    salt "$cp0" cmd.run \
      "kubeadm init \
        --pod-network-cidr=${POD_CIDR} \
        --service-cidr=${SVC_CIDR} \
        --apiserver-advertise-address=${cp0_lan} \
        --control-plane-endpoint=${cp0_lan}:6443" \
      -l info --out=newline_values_only || true

    salt "$cp0" cmd.run \
      "mkdir -p /root/.kube && cp -f /etc/kubernetes/admin.conf /root/.kube/config && chmod 600 /root/.kube/config" \
      -l quiet --out=newline_values_only || true
  else
    log "Cluster already initialized on ${cp0}"
  fi

  if ! wait_apiserver_on_cp0 "$cp0"; then
    warn "API server not ready on ${cp0} yet"
    return 0
  fi

  ensure_kubeconfig_on_master "$cp0"
  calico_apply_if_needed

  join_base="$(salt_one "$cp0" 'kubeadm token create --print-join-command 2>/dev/null || true')"
  cert_key="$(salt_one "$cp0" 'kubeadm init phase upload-certs --upload-certs 2>/dev/null | tail -n1 || true')"
  [[ -n "$join_base" ]] || { warn "join command not available yet"; return 0; }

  mkdir -p /srv/k8s
  echo "#!/usr/bin/env bash" > /srv/k8s/join-worker.sh
  echo "$join_base" >> /srv/k8s/join-worker.sh
  chmod 0755 /srv/k8s/join-worker.sh

  echo "#!/usr/bin/env bash" > /srv/k8s/join-control-plane.sh
  if [[ -n "$cert_key" ]]; then
    echo "$join_base --control-plane --certificate-key ${cert_key}" >> /srv/k8s/join-control-plane.sh
  else
    echo "echo 'cert key missing; rerun cluster-autobootstrap'" >> /srv/k8s/join-control-plane.sh
  fi
  chmod 0755 /srv/k8s/join-control-plane.sh

  for m in $(list_etcd); do
    [[ "$m" == "$cp0" ]] && continue
    already="$(salt_one "$m" 'test -f /etc/kubernetes/kubelet.conf && echo yes || echo no')"
    [[ "$already" == "yes" ]] && continue

    if ! ensure_runtime_ready "$m"; then
      warn "containerd not ready on ${m}; skipping"
      continue
    fi

    local m_lan; m_lan="$(get_lan_ip "$m")"
    [[ -n "$m_lan" ]] || { warn "lan_ip missing for ${m}; skipping"; continue; }
    [[ -n "$cert_key" ]] || { warn "cert key missing; cannot join other control-planes yet"; break; }

    log "Joining control-plane: $m (LAN advertise=${m_lan})"
    salt "$m" cmd.run "$join_base --control-plane --certificate-key ${cert_key} --apiserver-advertise-address=${m_lan}" \
      --out=newline_values_only -l info || true
  done

  for w in $(list_workers); do
    already="$(salt_one "$w" 'test -f /etc/kubernetes/kubelet.conf && echo yes || echo no')"
    [[ "$already" == "yes" ]] && continue

    if ! ensure_runtime_ready "$w"; then
      warn "containerd not ready on ${w}; skipping"
      continue
    fi

    log "Joining worker: $w"
    salt "$w" cmd.run "$join_base" --out=newline_values_only -l info || true
  done

  push_adminconf_to_all_etcd "$cp0"

  # improved done criteria: wait for all expected nodes to be Ready
  if command -v kubectl >/dev/null 2>&1 && [[ -s /root/.kube/config ]]; then
    expected="$( (list_etcd; list_workers) 2>/dev/null | wc -l | tr -d ' ' )"
    ready="$(kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{c++} END{print c+0}')"
    total="$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"
    log "kubectl sees nodes: total=${total} ready=${ready} expected(from salt)=${expected}"
    if [[ "${expected}" -gt 0 && "${ready}" -ge "${expected}" ]]; then
      touch "$DONE_FLAG"
      systemctl disable --now cluster-autobootstrap.timer >/dev/null 2>&1 || true
      log "Cluster bootstrap marked DONE"
    fi
  fi
}

main() {
  refresh_wg
  bootstrap_k8s
}
main
EOF
  chmod 0755 /usr/local/sbin/cluster-autobootstrap

  cat >/etc/systemd/system/cluster-autobootstrap.service <<'EOF'
[Unit]
Description=Cluster Autobootstrap (kubeadm init/join + calico)
After=network-online.target salt-master.service wg-sync-salt.service
Wants=network-online.target salt-master.service
ConditionPathExists=/root/.bootstrap_done
ConditionPathExists=!/root/.cluster_bootstrap_done

[Service]
Type=oneshot
EnvironmentFile=-/etc/environment.d/99-provision.conf
ExecStart=/usr/local/sbin/cluster-autobootstrap
EOF

  cat >/etc/systemd/system/cluster-autobootstrap.timer <<'EOF'
[Unit]
Description=Run cluster-autobootstrap periodically until done

[Timer]
OnBootSec=120
OnUnitActiveSec=60
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload || true
  systemctl enable cluster-autobootstrap.timer >/dev/null 2>&1 || true
}

install_helm_autobootstrap() {
  [[ "${HELM_ENABLE}" == "yes" ]] || return 0
  [[ "${HELM_BOOTSTRAP_ENABLE}" == "yes" ]] || { log "Helm autobootstrap disabled"; return 0; }

  log "Installing helm-autobootstrap (runs ${HELM_BOOTSTRAP_SCRIPT} after cluster is ready)"
  install -d -m0755 /usr/local/sbin /etc/systemd/system /srv/k8s/helm

  cat >/usr/local/sbin/helm-autobootstrap <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

LOG="/var/log/helm-autobootstrap.log"
exec >>"$LOG" 2>&1

ts(){ date '+%F %T'; }
log(){ echo "[INFO]  $(ts) - $*"; }
warn(){ echo "[WARN]  $(ts) - $*" >&2; }

DONE="/root/.helm_bootstrap_done"
[[ -f "$DONE" ]] && exit 0

if [[ -r /etc/environment.d/99-provision.conf ]]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/environment.d/99-provision.conf
  set +a
fi

: "${HELM_BOOTSTRAP_SCRIPT:=/srv/k8s/helm/bootstrap.sh}"

command -v helm >/dev/null 2>&1 || { warn "helm missing"; exit 0; }
command -v kubectl >/dev/null 2>&1 || { warn "kubectl missing"; exit 0; }

# Wait for kubeconfig + API
for i in {1..120}; do
  [[ -s /root/.kube/config ]] && kubectl get --raw=/readyz >/dev/null 2>&1 && break
  sleep 2
done
kubectl get --raw=/readyz >/dev/null 2>&1 || { warn "API not ready"; exit 0; }

if [[ -x "$HELM_BOOTSTRAP_SCRIPT" ]]; then
  log "Running: $HELM_BOOTSTRAP_SCRIPT"
  "$HELM_BOOTSTRAP_SCRIPT" && touch "$DONE" && exit 0
  warn "bootstrap script failed (will retry)"
  exit 1
fi

log "No executable $HELM_BOOTSTRAP_SCRIPT found; nothing to do."
touch "$DONE"
EOF
  chmod 0755 /usr/local/sbin/helm-autobootstrap

  cat >/etc/systemd/system/helm-autobootstrap.service <<'EOF'
[Unit]
Description=Helm Autobootstrap (post kubeadm + calico)
After=network-online.target cluster-autobootstrap.service
Wants=network-online.target
ConditionPathExists=/root/.bootstrap_done
ConditionPathExists=!/root/.helm_bootstrap_done

[Service]
Type=oneshot
EnvironmentFile=-/etc/environment.d/99-provision.conf
ExecStart=/usr/local/sbin/helm-autobootstrap
EOF

  cat >/etc/systemd/system/helm-autobootstrap.timer <<'EOF'
[Unit]
Description=Run helm-autobootstrap until done

[Timer]
OnBootSec=180
OnUnitActiveSec=60
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload || true
  systemctl enable --now helm-autobootstrap.timer >/dev/null 2>&1 || true
}

main() {
  log "Master postinstall start"
  ensure_base
  ensure_admin_and_ansible_users
  ssh_harden

  console_profile_apply_master

  wg_hub
  master_sysctls
  salt_master_setup
  ansible_setup
  k8s_repo_setup_master_kubectl
  install_helm
  nft_firewall
  install_wg_sync_timer
  install_cluster_autobootstrap
  install_helm_autobootstrap
  finalize_poweroff
}
main
EOS
}

# =============================================================================
# POSTINSTALL: NODE (etcd/worker)
# =============================================================================
emit_postinstall_node() {
  cat <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022
LOG="/var/log/postinstall-node.log"
exec > >(tee -a "$LOG") 2>&1

ts(){ date '+%F %T'; }
log(){ echo "[INFO]  $(ts) - $*"; }
warn(){ echo "[WARN]  $(ts) - $*" >&2; }

finalize_poweroff() {
  log "Finalizing: mark bootstrap done, disable bootstrap.service, power off"
  touch /root/.bootstrap_done || true

  systemctl disable bootstrap.service 2>/dev/null || true
  systemctl daemon-reload || true
  sync || true

  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run --unit=bootstrap-poweroff --description="Bootstrap poweroff" \
      --property=Type=oneshot --on-active=4 \
      /usr/bin/systemctl poweroff --no-wall --force --force >/dev/null 2>&1 || true
    return 0
  fi

  /usr/bin/systemctl --no-block poweroff --no-wall --force --force \
    || poweroff -f \
    || shutdown -h now \
    || true
}

on_err() {
  warn "Postinstall FAILED at line $1"
  touch /root/.bootstrap_failed || true
  finalize_poweroff
  exit 1
}
trap 'on_err $LINENO' ERR

if [[ -r /etc/environment.d/99-provision.conf ]]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/environment.d/99-provision.conf
  set +a
fi

: "${DEBIAN_CODENAME:=trixie}"
: "${DOMAIN:=unixbox.net}"
: "${ROLE:=worker}"
: "${ADMIN_USER:=todd}"
: "${ANSIBLE_USER:=ansible}"
: "${ALLOW_ADMIN_PASSWORD:=no}"
: "${MASTER_LAN:=10.100.10.20}"

: "${WG_IF:=wg0}"
: "${WG_WANTED:=10.78.0.11/32}"

: "${SALT_ENABLE:=yes}"
: "${SALT_MASTER:=${MASTER_LAN}}"

: "${HELM_ENABLE:=yes}"

: "${K8S_MINOR:=v1.35}"
: "${CALICO_INSTALL_METHOD:=operator}"

noninteractive_guards() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a

  install -d -m0755 /etc/needrestart/conf.d || true
  cat >/etc/needrestart/conf.d/99-noninteractive.conf <<'EOF'
$nrconf{restart} = 'a';
EOF

  # Global dpkg conffile policy (critical for containerd): keep existing, accept defaults, never prompt.
  cat >/etc/apt/apt.conf.d/99noninteractive <<'EOF'
Dpkg::Options { "--force-confdef"; "--force-confold"; };
APT::Get::Assume-Yes "true";
EOF

  cat >/etc/apt/apt.conf.d/99force-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
EOF
}

apt_sources_fix() {
  log "Setting APT sources (HTTPS)"
  cat >/etc/apt/sources.list <<EOF
deb https://deb.debian.org/debian ${DEBIAN_CODENAME} main contrib non-free non-free-firmware
deb https://security.debian.org/debian-security ${DEBIAN_CODENAME}-security main contrib non-free non-free-firmware
deb https://deb.debian.org/debian ${DEBIAN_CODENAME}-updates main contrib non-free non-free-firmware
EOF

  for i in 1 2 3 4 5; do
    apt-get update -y && return 0
    sleep $((i*3))
  done
  return 1
}

apt_repair_if_needed() {
  dpkg --configure -a || true
  apt-get -f install -y || true
}

detect_lan_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' \
    || ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

detect_lan_if() {
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || echo "ens18"
}

ensure_base() {
  noninteractive_guards
  apt_sources_fix
  apt_repair_if_needed

  log "Installing base packages"
  apt-get install -y --no-install-recommends \
    sudo openssh-server ca-certificates curl wget gpg jq rsync \
    qemu-guest-agent chrony rsyslog \
    nftables wireguard-tools \
    iproute2 iputils-ping net-tools ethtool tcpdump \
    lsb-release \
    python3 python3-venv \
    git vim tmux \
    bash-completion \
    ansible

  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true
}

ensure_user_with_keys() {
  local user="$1"
  local keys_file="$2"
  log "Ensuring user: $user"
  id -u "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
  install -d -m700 -o "$user" -g "$user" "/home/$user/.ssh"
  touch "/home/$user/.ssh/authorized_keys"
  chmod 600 "/home/$user/.ssh/authorized_keys"
  chown -R "$user:$user" "/home/$user/.ssh"

  if [[ -s "$keys_file" ]]; then
    while IFS= read -r k; do
      [[ -z "$k" ]] && continue
      grep -qxF "$k" "/home/$user/.ssh/authorized_keys" || echo "$k" >>"/home/$user/.ssh/authorized_keys"
    done <"$keys_file"
  fi

  if [[ -s "/root/darksite/enroll_ed25519.pub" ]]; then
    k="$(head -n1 /root/darksite/enroll_ed25519.pub)"
    grep -qxF "$k" "/home/$user/.ssh/authorized_keys" || echo "$k" >>"/home/$user/.ssh/authorized_keys"
  fi

  install -d -m755 /etc/sudoers.d
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" >"/etc/sudoers.d/90-${user}"
  chmod 0440 "/etc/sudoers.d/90-${user}"
  visudo -c >/dev/null || true
}

ensure_admin_and_ansible_users() {
  ensure_user_with_keys "$ADMIN_USER" "/root/darksite/authorized_keys.${ADMIN_USER}"
  ensure_user_with_keys "$ANSIBLE_USER" "/root/darksite/authorized_keys.${ANSIBLE_USER}"
}

ssh_harden() {
  log "Hardening SSH"
  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/99-hard.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

  if [[ "$ALLOW_ADMIN_PASSWORD" == "yes" ]]; then
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi

  sshd -t && systemctl restart ssh || true
}

# -----------------------------------------------------------------------------
# Console profile (NODE): bashrc + tmux + vim, seeded to /etc/skel and synced
# -----------------------------------------------------------------------------
seed_tmux_conf_common() {
  apt-get install -y --no-install-recommends tmux >/dev/null 2>&1 || true
  install -d -m0755 /etc/skel

  cat > /etc/skel/.tmux.conf <<'EOF'
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

  cp -f /etc/skel/.tmux.conf /root/.tmux.conf || true
}

seed_vim_conf_common() {
  apt-get install -y --no-install-recommends vim git >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends \
    vim-airline vim-airline-themes vim-ctrlp vim-fugitive vim-gitgutter vim-tabular \
    >/dev/null 2>&1 || true

  install -d -m0755 /etc/skel
  install -d -m0755 /etc/skel/.vim/autoload/airline/themes

  cat > /etc/skel/.vimrc <<'EOF'
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

  install -d -m0755 /root/.vim/autoload/airline/themes
  cp -f /etc/skel/.vimrc /root/.vimrc || true
  cp -f /etc/skel/.vim/autoload/airline/themes/custom.vim /root/.vim/autoload/airline/themes/custom.vim || true
}

seed_bashrc_node() {
  install -d -m0755 /etc/skel

  if [[ "${ROLE}" == "etcd" ]]; then
    # Gold standard etcd console (k8s+calico+helm helpers)
    cat > /etc/skel/.bashrc <<'ETCDBASHRC'
############################################################
# /root/.bashrc - minimal, stable k8s + calico + helm helpers
# (etcd/control-plane node — still cattle, but has kubectl+helm)
############################################################

# Only run in interactive bash
[[ -n "${BASH_VERSION:-}" ]] || return
case $- in
  *i*) ;;
  *) return ;;
esac

fb_banner() {
  cat << 'FBBANNER'

     _______
   <  Moo!?  >
     -------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

  Role      : etcd/control-plane (cattle)
  Directive : "If it breaks, replace it."
  Status    : ready to be re-provisioned

FBBANNER
}

if [ -z "${FBNOBANNER:-}" ]; then
  fb_banner
  export FBNOBANNER=1
fi

############################################################
# Optional Python venv (Ansible) - keep if you use it
############################################################
if [[ -f /root/ansible/venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  . /root/ansible/venv/bin/activate
fi

############################################################
# History, shell opts, completion, PATH
############################################################
HISTSIZE=100000
HISTFILESIZE=200000
HISTTIMEFORMAT='%F %T '
HISTCONTROL=ignoredups:erasedups
shopt -s histappend checkwinsize
shopt -s cdspell 2>/dev/null || true

if [[ -f /etc/bash_completion ]]; then
  # shellcheck disable=SC1091
  . /etc/bash_completion
fi

export PATH="$HOME/.local/bin:$PATH"
[[ -d "$HOME/go/bin" ]] && export PATH="$PATH:$HOME/go/bin"

############################################################
# Core aliases (safe defaults)
############################################################
alias grep='grep --color=auto'
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -rf'
alias df='df -h'
alias du='du -h'
alias ports='ss -tuln'
alias ..='cd ..'
alias ...='cd ../..'

alias ccat='function _ccat(){ clear; find "$1" -type f -print0 | sort -z | xargs -0 -I{} sh -c '"'"'printf "\n===== %s =====\n" "{}"; cat -- "{}"'"'"'; }; _ccat'

############################################################
# Bracketed paste toggles (fixes: $'\E[200~source' ...)
############################################################
bpoff() { bind 'set enable-bracketed-paste off' 2>/dev/null || true; }
bpon()  { bind 'set enable-bracketed-paste on'  2>/dev/null || true; }

############################################################
# Docker helpers
############################################################
alias dps='docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias dcu='docker compose up -d'
alias dcd='docker compose down'

dssh() {
  local name="${1:?container_name}"
  docker exec -it "$name" /bin/bash 2>/dev/null || docker exec -it "$name" /bin/sh
}

############################################################
# Kubernetes defaults
############################################################
export KUBECONFIG="${KUBECONFIG:-/etc/kubernetes/admin.conf}"
alias k='kubectl'

############################################################
# Internal helpers
############################################################
__have() { command -v "$1" >/dev/null 2>&1; }

__require_kubectl() {
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found" >&2; return 127; }
}

__require_helm() {
  command -v helm >/dev/null 2>&1 || { echo "helm not found" >&2; return 127; }
}

__fn_exists() { declare -F "$1" >/dev/null 2>&1; }

# kubectl bash completion (and completion for alias 'k')
if [[ -f /usr/share/bash-completion/completions/kubectl ]]; then
  # shellcheck disable=SC1091
  . /usr/share/bash-completion/completions/kubectl
elif __have kubectl && ! __fn_exists __start_kubectl; then
  # shellcheck disable=SC1090
  source <(kubectl completion bash) 2>/dev/null || true
fi
__fn_exists __start_kubectl && complete -o default -F __start_kubectl k 2>/dev/null || true

_kcur_ns() {
  local ns
  ns="$(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || true)"
  [[ -n "$ns" ]] && echo "$ns" || echo "default"
}

__prompt_char() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] && echo "#" || echo "$"
}

############################################################
# Prompt: [<ns>] <path> <user@host><#/$>
############################################################
__ps1_ns() { _kcur_ns 2>/dev/null || echo "default"; }
PS1='\[\e[96m\][$(__ps1_ns)\[\e[96m\]]\[\e[0m\] \w \[\e[95m\]\u@\h\[\e[0m\]$(__prompt_char) '

############################################################
# Context switcher
############################################################
kc() {
  __require_kubectl || return
  local sub="${1:-}"

  case "$sub" in
    ""|cur|current)
      echo "context:   $(kubectl config current-context 2>/dev/null || echo "<none>")"
      echo "namespace: $(_kcur_ns)"
      ;;
    ls|list) kubectl config get-contexts ;;
    use)
      local ctx="${2:?usage: kc use <context>}"
      kubectl config use-context "$ctx" >/dev/null
      echo "context:   $ctx"
      echo "namespace: $(_kcur_ns)"
      ;;
    *)
      echo "usage: kc [ls|use <context>|cur]" >&2
      return 1
      ;;
  esac
}

############################################################
# Namespace switcher
############################################################
kns() {
  __require_kubectl || return
  local arg="${1:-}"
  local ctx cur

  ctx="$(kubectl config current-context 2>/dev/null || true)"
  cur="$(_kcur_ns)"

  if [[ -z "$arg" ]]; then
    echo "context:   ${ctx:-<none>}"
    echo "namespace: ${cur:-default}"
    return 0
  fi

  if [[ "$arg" == "-" ]]; then
    if [[ -n "${KNS_PREV:-}" ]]; then
      arg="$KNS_PREV"
    else
      echo "no previous namespace recorded" >&2
      return 1
    fi
  fi

  KNS_PREV="$cur"
  kubectl config set-context --current --namespace="$arg" >/dev/null
  echo "namespace: $arg"
}

kn() {
  __require_kubectl || return
  local sub="${1:-ls}"

  case "$sub" in
    ls|"") kubectl get ns ;;
    cur) kns ;;
    use) kns "${2:?usage: kn use <ns>}" ;;
    new) kubectl create ns "${2:?usage: kn new <ns>}" ;;
    delete|del|rm)
      local ns="${2:?usage: kn delete <ns>}"
      echo "CONFIRM: delete namespace: $ns"
      read -r -p "Type '$ns' to continue: " ans
      [[ "$ans" == "$ns" ]] || { echo "aborted"; return 1; }
      kubectl delete ns "$ns"
      ;;
    edit) kubectl edit ns "${2:?usage: kn edit <ns>}" ;;
    *) echo "usage: kn [ls|cur|use <ns>|new <ns>|delete <ns>|edit <ns>]" >&2; return 1 ;;
  esac
}

############################################################
# Quick workload views
############################################################
kp()  {
  __require_kubectl || return
  local arg="${1:-}"
  if [[ -z "$arg" ]]; then
    kubectl get pods -o wide --sort-by=.spec.nodeName
  elif [[ "$arg" == "all" || "$arg" == "-A" ]]; then
    kubectl get pods -A -o wide --sort-by=.metadata.namespace
  else
    kubectl -n "$arg" get pods -o wide --sort-by=.spec.nodeName
  fi
}
kpa() { __require_kubectl || return; kubectl get pods -A -o wide --sort-by=.metadata.namespace; }
ksvc() {
  __require_kubectl || return
  local arg="${1:-}"
  if [[ -z "$arg" ]]; then
    kubectl get svc -o wide
  elif [[ "$arg" == "all" || "$arg" == "-A" ]]; then
    kubectl get svc -A -o wide --sort-by=.metadata.namespace
  else
    kubectl -n "$arg" get svc -o wide
  fi
}
ks()   { ksvc "$@"; }

king() {
  __require_kubectl || return
  local arg="${1:-}"
  if [[ -z "$arg" ]]; then
    kubectl get ing -o wide 2>/dev/null || kubectl get ingress -o wide
  elif [[ "$arg" == "all" || "$arg" == "-A" ]]; then
    kubectl get ing -A -o wide --sort-by=.metadata.namespace 2>/dev/null || kubectl get ingress -A -o wide --sort-by=.metadata.namespace
  else
    kubectl -n "$arg" get ing -o wide 2>/dev/null || kubectl -n "$arg" get ingress -o wide
  fi
}

kep() {
  __require_kubectl || return
  local arg="${1:-}"
  if [[ -z "$arg" ]]; then
    kubectl get ep -o wide 2>/dev/null || kubectl get endpoints -o wide
  elif [[ "$arg" == "all" || "$arg" == "-A" ]]; then
    kubectl get ep -A -o wide --sort-by=.metadata.namespace 2>/dev/null || kubectl get endpoints -A -o wide --sort-by=.metadata.namespace
  else
    kubectl -n "$arg" get ep -o wide 2>/dev/null || kubectl -n "$arg" get endpoints -o wide
  fi
}

kdep() { __require_kubectl || return; kubectl get deploy -o wide; }
kno()  { __require_kubectl || return; kubectl get nodes -o wide; }
kall() { __require_kubectl || return; kubectl get all -o wide; }

############################################################
# Namespace snapshot
############################################################
kshow() {
  __require_kubectl || return
  local ns="${1:-$(_kcur_ns)}"
  ns="${ns:-default}"

  echo "== ns: $ns =="; echo
  echo "== workloads =="; kubectl -n "$ns" get deploy,sts,ds,job,cronjob,pods -o wide 2>/dev/null || true; echo
  echo "== svc/ing/ep =="; kubectl -n "$ns" get svc,ing,ep -o wide 2>/dev/null || true; echo
  echo "== config =="; kubectl -n "$ns" get cm,secret,sa 2>/dev/null || true; echo
  echo "== rbac =="; kubectl -n "$ns" get role,rolebinding 2>/dev/null || true; echo
  echo "== pvc =="; kubectl -n "$ns" get pvc 2>/dev/null || true; echo
  echo "== events (tail 25) =="; kubectl -n "$ns" get events --sort-by=.lastTimestamp 2>/dev/null | tail -n 25 || true; echo
  echo "== policies =="; kubectl -n "$ns" get netpol 2>/dev/null || true
  kubectl -n "$ns" get networkpolicies.crd.projectcalico.org 2>/dev/null || true
  echo
}

############################################################
# Calico helpers
############################################################
kcal() {
  __require_kubectl || return
  echo "== calico-system pods =="; kubectl -n calico-system get pods -o wide 2>/dev/null || true
  echo
  echo "== tigera-operator pods =="; kubectl -n tigera-operator get pods -o wide 2>/dev/null || true
  echo
  echo "== calico/tigera CRDs =="; kubectl get crd 2>/dev/null | grep -E -i 'projectcalico|tigera' || true
  echo
  echo "== tigerastatus (if present) =="; kubectl get tigerastatus 2>/dev/null || true
}

khealth() {
  __require_kubectl || return
  echo "== nodes =="; kubectl get nodes -o wide 2>/dev/null || true
  echo
  echo "== kube-system pods (bad states) =="; kubectl -n kube-system get pods 2>/dev/null | egrep -v 'Running|Completed' || echo "OK: kube-system looks clean"
  echo
  echo "== calico-system pods (bad states) =="; kubectl -n calico-system get pods 2>/dev/null | egrep -v 'Running|Completed' || echo "OK: calico-system looks clean"
  echo
  echo "== tigera-operator pods (bad states) =="; kubectl -n tigera-operator get pods 2>/dev/null | egrep -v 'Running|Completed' || echo "OK: tigera-operator looks clean"
  echo
  echo "== recent warning events =="; kubectl get events -A --sort-by=.lastTimestamp 2>/dev/null | egrep -i 'warning|failed|error|backoff|unhealthy' | tail -n 40 || echo "OK: no recent warning events"
}

kfixns() {
  __require_kubectl || return
  local ns="${1:?usage: kfixns <ns>}"
  echo "== checking namespace: $ns =="
  kubectl get ns "$ns" -o jsonpath='{.status.phase}{"\n"}' 2>/dev/null || { echo "ERR: ns not found: $ns"; return 1; }

  echo "== removing finalizers (force) =="
  kubectl get ns "$ns" -o json \
    | sed 's/"finalizers":[[][^]]*[]]/"finalizers":[]/g' \
    | kubectl replace --raw "/api/v1/namespaces/$ns/finalize" -f - >/dev/null 2>&1 \
    && echo "OK: finalize request sent" \
    || echo "WARN: finalize request failed (RBAC?)"

  echo "== current status =="
  kubectl get ns "$ns" 2>/dev/null || true
}

############################################################
# HELM helpers
############################################################
alias h='helm'

if [[ -f /usr/share/bash-completion/completions/helm ]]; then
  # shellcheck disable=SC1091
  . /usr/share/bash-completion/completions/helm
elif __have helm && ! __fn_exists __start_helm; then
  # shellcheck disable=SC1090
  source <(helm completion bash) 2>/dev/null || true
fi
__fn_exists __start_helm && complete -o default -F __start_helm h 2>/dev/null || true

hl() {
  __require_helm || return
  __require_kubectl || return
  local arg="${1:-}"
  local cur="$(_kcur_ns)"
  if [[ -z "$arg" ]]; then
    helm list -n "$cur"
  elif [[ "$arg" == "all" || "$arg" == "-A" ]]; then
    helm list -A
  else
    helm list -n "$arg"
  fi
}
hs() { __require_helm || return; helm status "${1:?usage: hs <rel> [ns]}" -n "${2:-$(_kcur_ns)}"; }
hm() { __require_helm || return; helm get manifest "${1:?usage: hm <rel> [ns]}" -n "${2:-$(_kcur_ns)}"; }
hv() { __require_helm || return; helm get values "${1:?usage: hv <rel> [ns]}" -n "${2:-$(_kcur_ns)}" --all; }
hh() { __require_helm || return; helm history "${1:?usage: hh <rel> [ns]}" -n "${2:-$(_kcur_ns)}"; }

hown() {
  __require_kubectl || return
  local rel="${1:-}"
  local ns="${2:-$(_kcur_ns)}"
  [[ -n "$rel" ]] || { echo "usage: hown <release> [ns|all]" >&2; return 1; }

  if [[ "$ns" == "all" || "$ns" == "-A" ]]; then
    echo "== namespaced objects (all namespaces, release=$rel) =="
    kubectl get all -A -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
    kubectl get cm,secret,sa,role,rolebinding,netpol,ing,ep,svc -A -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
    kubectl get networkpolicies.crd.projectcalico.org -A -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
  else
    echo "== namespaced objects (ns=$ns, release=$rel) =="
    kubectl -n "$ns" get all -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
    kubectl -n "$ns" get cm,secret,sa,role,rolebinding,netpol,ing,ep,svc -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
    kubectl -n "$ns" get networkpolicies.crd.projectcalico.org -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
  fi

  echo
  echo "== cluster-scoped objects (if any, release=$rel) =="
  kubectl get globalnetworkpolicies.crd.projectcalico.org -o wide -l "app.kubernetes.io/instance=$rel" 2>/dev/null || true
}

khelp() {
cat <<'EOF'
PROMPT
  [<namespace>] <path> <user@host><#/$>

CONTEXT
  kc              # show current context + ns
  kc ls           # list contexts
  kc use <ctx>    # switch context

NAMESPACE
  kn              # list namespaces
  kn cur          # show current context + ns
  kn use bookinfo # switch namespace
  kns bookinfo
  kns -

WORKLOAD
  kp              # pods (wide) in current ns
  kp kube-system
  kp all          # pods across ALL namespaces
  ks              # services (wide)
  king            # ingresses
  kep             # endpoints
  kdep            # deployments
  kno             # nodes
  kall            # common types
  kshow           # snapshot of ns

CALICO / HEALTH
  kcal
  khealth
  kfixns <ns>

HELM
  hl              # helm list current ns
  hl all
  hs/hm/hv/hh <rel> [ns]
  hown <rel> [ns|all]
EOF
}

echo "Welcome $USER — connected to $(hostname) on $(date)"
echo "Type 'khelp' for k8s helper command list."
ETCDBASHRC
  else
    # Worker/minion simple cattle profile
    cat > /etc/skel/.bashrc <<'EOF'
# ~/.bashrc - foundryBot cluster console (WORKER/MINION)
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

     _______
   <  Moo!?  >
     -------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

  Role      : worker node (cattle)
  Directive : "If it breaks, replace it."
  Status    : ready to be re-provisioned

FBBANNER
}

if [ -z "${FBNOBANNER:-}" ]; then
  fb_banner
  export FBNOBANNER=1
fi

if [ "$EUID" -eq 0 ]; then
  PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
else
  PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi

if [ -f /etc/bash_completion ]; then
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

VENV_DIR="/root/bccenv"
if [ -d "$VENV_DIR" ] && [ -n "$PS1" ]; then
  if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$VENV_DIR" ]; then
    source "$VENV_DIR/bin/activate"
  fi
fi

echo "Welcome $USER — connected to $(hostname) on $(date)"
EOF
  fi

  cp -f /etc/skel/.bashrc /root/.bashrc || true
}

sync_skel_to_existing_users() {
  local files=(.bashrc .vimrc .tmux.conf)
  local home f

  for home in /root $(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null); do
    for f in "${files[@]}"; do
      [[ -f "/etc/skel/$f" ]] || continue
      cp -f "/etc/skel/$f" "$home/$f" || true
    done
  done
}

console_profile_apply_node() {
  log "Seeding console profile (bashrc + tmux + vim) for ROLE=${ROLE}"
  seed_bashrc_node
  seed_tmux_conf_common
  seed_vim_conf_common
  sync_skel_to_existing_users
}

wg_generate_keys() {
  log "Generating WireGuard keys (${WG_IF})"
  install -d -m700 /etc/wireguard
  umask 077
  if [[ ! -s "/etc/wireguard/${WG_IF}.key" ]]; then
    wg genkey | tee "/etc/wireguard/${WG_IF}.key" | wg pubkey >"/etc/wireguard/${WG_IF}.pub"
  fi
  umask 022
  chmod 600 "/etc/wireguard/${WG_IF}.key" "/etc/wireguard/${WG_IF}.pub" || true
}

salt_repo_setup() {
  log "Setting up SaltProject repo"
  install -d -m0755 /etc/apt/keyrings

  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public \
    -o /etc/apt/keyrings/salt-archive-keyring.pgp
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp

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
}

salt_minion_setup() {
  [[ "$SALT_ENABLE" == "yes" ]] || { log "Salt disabled"; return 0; }
  log "Installing Salt minion (master=${SALT_MASTER})"
  salt_repo_setup
  apt-get install -y --no-install-recommends salt-minion salt-common

  install -d -m0755 /etc/salt/minion.d
  cat >/etc/salt/minion.d/master.conf <<EOF
master: ${SALT_MASTER}
ipv6: False
EOF

  local pub ip lan_ip
  pub="$(cat "/etc/wireguard/${WG_IF}.pub" 2>/dev/null || true)"
  ip="${WG_WANTED%/*}"
  lan_ip="$(detect_lan_ip || true)"

  cat >/etc/salt/minion.d/grains.conf <<EOF
grains:
  role: ${ROLE}
  lan_ip: ${lan_ip}
  wg_cidr: ${WG_WANTED}
  wg_ip: ${ip}
  wg_pub: ${pub}
EOF

  systemctl enable --now salt-minion || true
  systemctl restart salt-minion || true
}

kernel_tweaks() {
  log "Applying kernel sysctl and swap settings"
  swapoff -a || true
  sed -ri '/\sswap\s/s/^/#/' /etc/fstab || true

  cat >/etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
ipip
vxlan
nf_conntrack
ip_tables
iptable_nat
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
ip_set
xt_set
EOF

  for m in overlay br_netfilter ipip vxlan nf_conntrack ip_tables iptable_nat ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh ip_set xt_set; do
    modprobe "$m" 2>/dev/null || true
  done

  cat >/etc/sysctl.d/99-k8s.conf <<'EOF'
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.src_valid_mark=1
EOF
  sysctl --system || true
}

containerd_install_and_setup() {
  log "Installing + configuring containerd (SystemdCgroup=true)"
  apt_repair_if_needed
  apt-get install -y --no-install-recommends containerd runc criu

  mkdir -p /etc/containerd
  if [[ ! -s /etc/containerd/config.toml ]]; then
    containerd config default >/etc/containerd/config.toml
  fi

  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml || true

  systemctl enable --now containerd || true
  systemctl restart containerd || true

  cat >/etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: false
EOF

  test -S /run/containerd/containerd.sock || test -S /var/run/containerd/containerd.sock || true
}

k8s_repo_setup() {
  log "Setting up Kubernetes apt repo (pkgs.k8s.io core:/stable:/${K8S_MINOR})"
  apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl gpg
  install -d -m0755 /etc/apt/keyrings
  curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" \
    | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  chmod 0644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /" \
    > /etc/apt/sources.list.d/kubernetes.list
  apt-get update -y || true
}

kubelet_nodeip_pin() {
  local lan_ip
  lan_ip="$(detect_lan_ip || true)"
  [[ -n "$lan_ip" ]] || return 0

  cat >/etc/default/kubelet <<EOF
KUBELET_EXTRA_ARGS=--node-ip=${lan_ip}
EOF
}

k8s_bits_install() {
  log "Installing Kubernetes bits for role=${ROLE}"
  apt-get install -y --no-install-recommends conntrack socat ebtables ipset iptables ipvsadm
  apt-get install -y --no-install-recommends cri-tools containernetworking-plugins

  # kubelet/containerd commonly expect CNI binaries in /opt/cni/bin
  install -d -m0755 /opt/cni/bin /etc/cni/net.d || true
  if [[ -d /usr/lib/cni ]]; then
    ln -sf /usr/lib/cni/* /opt/cni/bin/ 2>/dev/null || true
  fi

  if [[ "$ROLE" == "etcd" ]]; then
    apt-get install -y --no-install-recommends kubelet kubeadm kubectl
    apt-mark hold kubelet kubeadm kubectl || true
  else
    apt-get install -y --no-install-recommends kubelet kubeadm
    apt-mark hold kubelet kubeadm || true
  fi

  kubelet_nodeip_pin
  systemctl enable --now kubelet || true
  systemctl restart kubelet || true
}

install_helm() {
  [[ "${HELM_ENABLE}" == "yes" ]] || return 0
  [[ "${ROLE}" == "etcd" ]] || return 0
  command -v helm >/dev/null 2>&1 && return 0

  log "Installing Helm on etcd/control-plane"
  if apt-cache show helm >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends helm || true
  fi
  if command -v helm >/dev/null 2>&1; then
    return 0
  fi

  curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  chmod 700 /tmp/get_helm.sh
  /tmp/get_helm.sh || true
  rm -f /tmp/get_helm.sh || true
}

nft_k8s_firewall() {
  log "Configuring nftables (WG mgmt only; k8s on LAN only)"

  local lan_if lan_ip
  lan_if="$(detect_lan_if || true)"
  lan_ip="$(detect_lan_ip || true)"
  : "${lan_if:=ens18}"

  local LAN_CIDR="10.100.10.0/24"

  # Calico: BGP(179) + Typha(5473)
  local CALICO_TCP_SET="{ 179, 5473 }"
  local CALICO_UDP="4789"
  local KUBELET_TCP="10250"

  local APISERVER_TCP="6443"
  local ETCD_TCP_FROM="2379"
  local ETCD_TCP_TO="2380"

  local NODEPORT_FROM="30000"
  local NODEPORT_TO="32767"

  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept

    tcp dport 22 accept

    # WG mgmt: only ssh+icmp on wg0 (no blanket wg0 allow)
    iifname "${WG_IF}" tcp dport 22 accept
    iifname "${WG_IF}" ip protocol icmp accept

    # Calico (LAN only)
    iifname "${lan_if}" ip saddr ${LAN_CIDR} tcp dport ${CALICO_TCP_SET} accept
    iifname "${lan_if}" ip saddr ${LAN_CIDR} udp dport ${CALICO_UDP} accept
    iifname "${lan_if}" ip saddr ${LAN_CIDR} ip protocol 4 accept

    # Kubelet (LAN only)
    iifname "${lan_if}" ip saddr ${LAN_CIDR} tcp dport ${KUBELET_TCP} accept
EOF

  if [[ "$ROLE" == "etcd" ]]; then
    cat >>/etc/nftables.conf <<EOF
    # API server + etcd (LAN only)
    iifname "${lan_if}" ip saddr ${LAN_CIDR} tcp dport ${APISERVER_TCP} accept
    iifname "${lan_if}" ip saddr ${LAN_CIDR} tcp dport ${ETCD_TCP_FROM}-${ETCD_TCP_TO} accept
EOF
  else
    cat >>/etc/nftables.conf <<EOF
    # NodePort (LAN only)
    iifname "${lan_if}" ip saddr ${LAN_CIDR} tcp dport ${NODEPORT_FROM}-${NODEPORT_TO} accept
    iifname "${lan_if}" ip saddr ${LAN_CIDR} udp dport ${NODEPORT_FROM}-${NODEPORT_TO} accept
EOF
  fi

  cat >>/etc/nftables.conf <<'EOF'
  }

  # IMPORTANT: Kubernetes needs forwarding. Policy drop here breaks pod/service networking.
  chain forward {
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
  }

  chain output { type filter hook output priority 0; policy accept; }
}
EOF

  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

main() {
  log "Node postinstall start (ROLE=${ROLE})"
  ensure_base
  ensure_admin_and_ansible_users
  ssh_harden

  console_profile_apply_node

  wg_generate_keys
  salt_minion_setup

  kernel_tweaks
  containerd_install_and_setup
  k8s_repo_setup
  k8s_bits_install
  install_helm

  nft_k8s_firewall
  finalize_poweroff
}
main
EOS
}

# =============================================================================
# Bootloader patching (BIOS + UEFI)
# =============================================================================
patch_bootloaders() {
  local cust="$1" workdir="$2" kargs="$3"

  log "Patching bootloaders for unattended install..."

  if [[ -f "$cust/isolinux/txt.cfg" ]]; then
    if ! grep -qE '^label[[:space:]]+auto$' "$cust/isolinux/txt.cfg"; then
      cat >>"$cust/isolinux/txt.cfg" <<EOF

label auto
  menu label ^auto (preseed)
  kernel /install.amd/vmlinuz
  append initrd=/install.amd/initrd.gz ${kargs}
EOF
    fi
    if [[ -f "$cust/isolinux/isolinux.cfg" ]]; then
      sed -i 's/^default .*/default auto/' "$cust/isolinux/isolinux.cfg" 2>/dev/null || true
      sed -i 's/^timeout .*/timeout 10/' "$cust/isolinux/isolinux.cfg" 2>/dev/null || true
    fi
  fi

  _patch_grub_cfg() {
    local cfg="$1"
    [[ -f "$cfg" ]] || return 0

    if grep -qE '^set[[:space:]]+default=' "$cfg"; then
      sed -i 's/^set[[:space:]]\+default=.*/set default="0"/' "$cfg" || true
    else
      sed -i '1i set default="0"' "$cfg" || true
    fi

    if grep -qE '^set[[:space:]]+timeout=' "$cfg"; then
      sed -i 's/^set[[:space:]]\+timeout=.*/set timeout=1/' "$cfg" || true
    else
      sed -i '1i set timeout=1' "$cfg" || true
    fi

    if ! grep -qF 'preseed/file=/cdrom/preseed.cfg' "$cfg"; then
      sed -i -E "s#^([[:space:]]*(linux|linuxefi)[[:space:]]+[^[:space:]]+)#\\1 ${kargs}#g" "$cfg" || true
    fi
  }

  local cfg
  for cfg in \
    "$cust/boot/grub/grub.cfg" \
    "$cust/boot/grub/x86_64-efi/grub.cfg" \
    "$cust/EFI/boot/grub.cfg" \
    "$cust/EFI/BOOT/grub.cfg"
  do
    [[ -f "$cfg" ]] && _patch_grub_cfg "$cfg"
  done

  local efi_img=""
  if [[ -f "$cust/boot/grub/efi.img" ]]; then
    efi_img="$cust/boot/grub/efi.img"
  elif [[ -f "$cust/efi.img" ]]; then
    efi_img="$cust/efi.img"
  fi

  if [[ -n "$efi_img" ]]; then
    local efimnt="$workdir/efimnt"
    mkdir -p "$efimnt"

    if mount -o loop,rw "$efi_img" "$efimnt" 2>/dev/null; then
      local inner_cfg=""
      inner_cfg="$(find "$efimnt" -maxdepth 4 -type f -iname 'grub.cfg' | head -n1 || true)"
      if [[ -n "$inner_cfg" && -f "$inner_cfg" ]]; then
        log "Patching UEFI grub.cfg inside efi.img: ${inner_cfg#"$efimnt"/}"
        _patch_grub_cfg "$inner_cfg"
        sync || true
      else
        warn "efi.img mounted but grub.cfg not found inside; UEFI autoinstall may not work"
      fi
      umount "$efimnt" 2>/dev/null || true
    else
      warn "Could not mount efi.img RW ($efi_img). UEFI autoinstall may not work on this ISO."
    fi
  else
    warn "No efi.img found in ISO tree; ISO may be BIOS-only or unusual UEFI layout."
  fi

  if [[ -f "$cust/md5sum.txt" ]]; then
    log "Regenerating md5sum.txt"
    ( cd "$cust" && find . -type f ! -name md5sum.txt -print0 | xargs -0 md5sum > md5sum.txt ) || true
  fi
}

# =============================================================================
# mk_iso
# =============================================================================
mk_iso() {
  # mk_iso <name> <role> <lan_ip> <wg_cidr> <iso_out>
  local name="$1" role="$2" lan_ip="$3" wg_cidr="$4" iso_out="$5"

  require_cmd xorriso
  require_cmd mount
  require_cmd umount
  require_cmd sed
  require_cmd perl

  local build="$BUILD_ROOT/iso-$name"
  local mnt="$build/mnt"
  local cust="$build/custom"
  rm -rf "$build"
  mkdir -p "$mnt" "$cust"

  (
    trap 'umount -f "$mnt" >/dev/null 2>&1 || true' EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    cp -a "$mnt/"* "$cust/"
    cp -a "$mnt/.disk" "$cust/" 2>/dev/null || true
  )

  local dark="$cust/darksite"
  mkdir -p "$dark"

  if [[ -d "$DARKSITE_SRC" ]]; then
    rsync -a --delete "$DARKSITE_SRC"/ "$dark"/
  fi

  # Keys for ADMIN + ANSIBLE users
  if [[ -n "${SSH_PUBKEY}" ]]; then
    printf '%s\n' "$SSH_PUBKEY" >"$dark/authorized_keys.${ADMIN_USER}"
    printf '%s\n' "$SSH_PUBKEY" >"$dark/authorized_keys.${ANSIBLE_USER}"
  else
    : >"$dark/authorized_keys.${ADMIN_USER}"
    : >"$dark/authorized_keys.${ANSIBLE_USER}"
  fi
  chmod 0644 "$dark/authorized_keys.${ADMIN_USER}" "$dark/authorized_keys.${ANSIBLE_USER}"

  if [[ -s "$ENROLL_KEY_PRIV" && -s "$ENROLL_KEY_PUB" ]]; then
    install -m0600 "$ENROLL_KEY_PRIV" "$dark/enroll_ed25519"
    install -m0644 "$ENROLL_KEY_PUB"  "$dark/enroll_ed25519.pub"
  fi

  local post="$build/postinstall.sh"
  if [[ "$role" == "master" ]]; then
    emit_postinstall_master >"$post"
  else
    emit_postinstall_node >"$post"
  fi
  chmod 0755 "$post"
  install -m0755 "$post" "$dark/postinstall.sh"

  emit_bootstrap_unit >"$dark/bootstrap.service"
  chmod 0644 "$dark/bootstrap.service"

  {
    echo "DEBIAN_CODENAME=${DEBIAN_CODENAME}"
    echo "DOMAIN=${DOMAIN}"
    echo "ADMIN_USER=${ADMIN_USER}"
    echo "ANSIBLE_USER=${ANSIBLE_USER}"
    echo "ALLOW_ADMIN_PASSWORD=${ALLOW_ADMIN_PASSWORD}"
    echo "ROLE=${role}"
    echo "LAN_IP=${lan_ip}"
    echo "MASTER_LAN=${MASTER_LAN}"
    echo "WG_IF=${WG_IF}"
    echo "WG_WANTED=${wg_cidr}"
    echo "WG_PORT=${WG_PORT}"
    echo "WG_MTU=${WG_MTU}"
    echo "WG_NET=${WG_NET}"
    echo "MASTER_WG_CIDR=${MASTER_WG_CIDR}"
    echo "SALT_ENABLE=${SALT_ENABLE}"
    echo "SALT_BIND_ADDR=${SALT_BIND_ADDR}"
    echo "SALT_AUTO_ACCEPT=${SALT_AUTO_ACCEPT}"
    echo "ANSIBLE_ENABLE=${ANSIBLE_ENABLE}"
    echo "HELM_ENABLE=${HELM_ENABLE}"
    echo "HELM_BOOTSTRAP_ENABLE=${HELM_BOOTSTRAP_ENABLE}"
    echo "HELM_BOOTSTRAP_SCRIPT=${HELM_BOOTSTRAP_SCRIPT}"
    echo "K8S_MINOR=${K8S_MINOR}"
    echo "POD_CIDR=${POD_CIDR}"
    echo "SVC_CIDR=${SVC_CIDR}"
    echo "CALICO_INSTALL=${CALICO_INSTALL}"
    echo "CALICO_VERSION=${CALICO_VERSION}"
    echo "CALICO_INSTALL_METHOD=${CALICO_INSTALL_METHOD}"
    echo "TIGERA_ENTERPRISE_ENABLE=${TIGERA_ENTERPRISE_ENABLE}"
    echo "TIGERA_EE_VERSION=${TIGERA_EE_VERSION}"
    echo "ETCD_COUNT=${ETCD_COUNT}"
    echo "WORKER_COUNT=${WORKER_COUNT}"
    echo "CLUSTER_BOOTSTRAP_ENABLE=${CLUSTER_BOOTSTRAP_ENABLE}"
  } >"$dark/99-provision.conf"
  chmod 0644 "$dark/99-provision.conf"

  local NETBLOCK
  NETBLOCK="d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string ${name}
d-i netcfg/hostname string ${name}
d-i netcfg/get_domain string ${DOMAIN}
d-i netcfg/disable_dhcp boolean true
d-i netcfg/get_ipaddress string ${lan_ip}
d-i netcfg/get_netmask string ${NETMASK}
d-i netcfg/get_gateway string ${GATEWAY}
d-i netcfg/get_nameservers string ${NAMESERVER}"

  local PASSBLOCK; PASSBLOCK="$(preseed_password_block)"

  cat >"$cust/preseed.cfg" <<'EOF'
d-i debconf/frontend select Noninteractive
d-i debconf/priority string critical

d-i apt-cdrom-setup/another boolean false
d-i debian-installer/locale string __LOCALE__
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select __KEYMAP__

__NETBLOCK__

__PASSBLOCK__

d-i time/zone string __TZ__
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
d-i pkgsel/include string __EXTRA_PKGS__
d-i pkgsel/upgrade select none
d-i pkgsel/ignore-recommends boolean true
popularity-contest popularity-contest/participate boolean false

d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string __BOOTDEV__

d-i cdrom-detect/eject boolean false

d-i preseed/late_command string \
  set -e; \
  FQDN="__FQDN__"; \
  echo "$FQDN" > /target/etc/hostname; \
  in-target hostnamectl set-hostname "$FQDN" || true; \
  mkdir -p /target/root/darksite; \
  cp -a /cdrom/darksite/. /target/root/darksite/; \
  in-target mkdir -p /etc/systemd/system /etc/environment.d; \
  in-target install -m 0644 /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service; \
  in-target install -m 0644 /root/darksite/99-provision.conf /etc/environment.d/99-provision.conf; \
  in-target chmod 0644 /etc/environment.d/99-provision.conf; \
  in-target systemctl daemon-reload; \
  in-target systemctl enable bootstrap.service 2>/dev/null || true

d-i finish-install/reboot_in_progress note
d-i finish-install/exit-installer boolean true
d-i debian-installer/exit/poweroff boolean true
EOF

  local fqdn="${name}.${DOMAIN}"

  sed -i \
    -e "s|__LOCALE__|${PRESEED_LOCALE}|g" \
    -e "s|__KEYMAP__|${PRESEED_KEYMAP}|g" \
    -e "s|__TZ__|${PRESEED_TIMEZONE}|g" \
    -e "s|__EXTRA_PKGS__|${PRESEED_EXTRA_PKGS}|g" \
    -e "s|__BOOTDEV__|${PRESEED_BOOTDEV}|g" \
    -e "s|__FQDN__|${fqdn}|g" \
    "$cust/preseed.cfg"

  export NETBLOCK PASSBLOCK
  perl -0777 -i -pe 's/__NETBLOCK__/$ENV{NETBLOCK}/g' "$cust/preseed.cfg"
  perl -0777 -i -pe 's/__PASSBLOCK__/$ENV{PASSBLOCK}/g' "$cust/preseed.cfg"

  local KARGS="auto=true priority=critical vga=788 preseed/file=/cdrom/preseed.cfg ---"
  patch_bootloaders "$cust" "$build" "$KARGS"

  local efi_img=""
  if [[ -f "$cust/boot/grub/efi.img" ]]; then
    efi_img="boot/grub/efi.img"
  elif [[ -f "$cust/efi.img" ]]; then
    efi_img="efi.img"
  fi

  if [[ -f "$cust/isolinux/isolinux.bin" && -f "$cust/isolinux/boot.cat" && -f /usr/share/syslinux/isohdpfx.bin ]]; then
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
    [[ -n "$efi_img" ]] || die "EFI image not found in ISO tree; cannot build bootable ISO"
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
# Deployment orchestration
# =============================================================================
deploy_one() {
  local vmid="$1" name="$2" role="$3" lan="$4" wg="$5"

  local iso="$BUILD_ROOT/${name}.iso"
  log "Building ISO for ${name} (${role}) -> $iso"
  mk_iso "$name" "$role" "$lan" "$wg" "$iso"

  local mem cores disk
  case "$role" in
    master)  mem="$MASTER_MEM";  cores="$MASTER_CORES";  disk="$MASTER_DISK_GB" ;;
    etcd)    mem="$ETCD_MEM";    cores="$ETCD_CORES";    disk="$ETCD_DISK_GB" ;;
    worker)  mem="$WORKER_MEM";  cores="$WORKER_CORES";  disk="$WORKER_DISK_GB" ;;
    *) die "Unknown role: $role" ;;
  esac

  log "Deploying VM $vmid ($name) on Proxmox $PROXMOX_HOST"
  pmx_deploy_vm "$vmid" "$name" "$lan" "$iso" "$mem" "$cores" "$disk"

  pmx_wait_for_state "$vmid" "stopped" 3600 1
  pmx_boot_from_disk "$vmid"
  pmx_wait_for_state "$vmid" "stopped" 5400 2

  if [[ "${LEAVE_RUNNING}" == "yes" ]]; then
    pmx "qm start $vmid" >/dev/null || true
    pmx_wait_for_state "$vmid" "running" 600 2
  fi
}

# =============================================================================
# Targets
# =============================================================================
TARGET="${TARGET:-proxmox-all}"

main_proxmox_all() {
  require_cmd ssh
  require_cmd scp
  require_cmd xorriso
  require_cmd mount
  require_cmd umount
  require_cmd perl
  require_cmd sed

  [[ -f "$ISO_ORIG" ]] || die "ISO_ORIG not found: $ISO_ORIG"

  ensure_enroll_keypair
  parse_nodes

  log "=== Plan (NODE_SPEC) ==="
  echo "$NODE_SPEC" | sed 's/^/  /'
  log "Proxmox host: $PROXMOX_HOST"

  deploy_one "$MASTER_ID" "$MASTER_NAME" "master" "$MASTER_LAN" "$MASTER_WG_CIDR"

  local i
  for ((i=0; i<${#NODE_VMID[@]}; i++)); do
    [[ "${NODE_ROLE[$i]}" == "master" ]] && continue
    deploy_one "${NODE_VMID[$i]}" "${NODE_NAME[$i]}" "${NODE_ROLE[$i]}" "${NODE_LAN[$i]}" "${NODE_WG[$i]}"
  done

  log "=== DONE: master + etcd + workers deployed ==="
  log "WG mgmt sync: wg-sync-salt.timer (30s)"
  log "K8s bootstrap (LAN IPs): cluster-autobootstrap.timer (60s) if enabled"
  log "Helm defaults hook: helm-autobootstrap.timer (if HELM_BOOTSTRAP_ENABLE=yes)"
}

main_image_only() {
  require_cmd xorriso
  require_cmd mount
  require_cmd umount
  require_cmd perl
  require_cmd sed

  [[ -f "$ISO_ORIG" ]] || die "ISO_ORIG not found: $ISO_ORIG"

  ensure_enroll_keypair
  parse_nodes

  log "Building ISOs only."
  local i iso
  for ((i=0; i<${#NODE_VMID[@]}; i++)); do
    iso="$BUILD_ROOT/${NODE_NAME[$i]}.iso"
    mk_iso "${NODE_NAME[$i]}" "${NODE_ROLE[$i]}" "${NODE_LAN[$i]}" "${NODE_WG[$i]}" "$iso"
    log "Built $iso"
  done
}

case "$TARGET" in
  proxmox-all) main_proxmox_all ;;
  image-only)  main_image_only ;;
  *) die "Unknown TARGET=$TARGET (expected proxmox-all | image-only)" ;;
esac
