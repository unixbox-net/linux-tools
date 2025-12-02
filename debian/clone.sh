#!/usr/bin/env bash
# Merged: Template builder + Clone fanout + WireGuard auto-provision + extra disks (robust)
set -euo pipefail

LOG_FILE="/root/install.txt"
exec &> >(tee -a "$LOG_FILE")

log()       { echo "[INFO]  $(date '+%F %T') - $*"; }
warn()      { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
error_log() { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()       { error_log "$*"; exit 1; }

# =============================================================================
# CONFIG
# =============================================================================

# --- ISO source (Debian 13.x) ---
ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-netinst.iso}"
# ISO_ORIG="${ISO_ORIG:-/root/debian-13.0.0-amd64-DVD-1.iso}"

# Build workspace
BUILD_DIR="${BUILD_DIR:-/root/build}"
CUSTOM_DIR="$BUILD_DIR/custom"
MOUNT_DIR="${MOUNT_DIR:-/mnt/build}"
DARKSITE_DIR="$CUSTOM_DIR/darksite"
PRESEED_FILE="preseed.cfg"
OUTPUT_ISO="$BUILD_DIR/base.iso"
FINAL_ISO="${FINAL_ISO:-/root/clone.iso}"

# Cluster target (Proxmox host selector)
INPUT="${INPUT:-1}"   # 1|fiend, 2|dragon, 3|lion
VMID="${VMID:-7100}"
VMNAME="${VMNAME:-server}"      # short base name; domain added below

# Domain
DOMAIN="${DOMAIN:-foundrybot.ca}"

# Storage
VM_STORAGE="${VM_STORAGE:-void}"   # (ceph->void (nvme->local-zfs (rust>fireball
ISO_STORAGE="${ISO_STORAGE:-local}"     # dir storage for ISO (usually 'local')

# VM sizing
DISK_SIZE_GB="${DISK_SIZE_GB:-10}"
MEMORY_MB="${MEMORY_MB:-8192}"
CORES="${CORES:-4}"

# Installer networking for the template VM
NETWORK_MODE="${NETWORK_MODE:-dhcp}"     # static | dhcp
STATIC_IP="${STATIC_IP:-10.100.10.10}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3}"

# Cloud-Init toggle for clones
USE_CLOUD_INIT="${USE_CLOUD_INIT:-true}"
CLONE_VLAN_ID="${CLONE_VLAN_ID:-}"

# Clone fanout
NUM_CLONES="${NUM_CLONES:-5}"
BASE_CLONE_VMID="${BASE_CLONE_VMID:-7101}"
BASE_CLONE_IP="${BASE_CLONE_IP:-$STATIC_IP}"     # starting LAN IP for clones (static mode)
CLONE_MEMORY_MB="${CLONE_MEMORY_MB:-4096}"
CLONE_CORES="${CLONE_CORES:-4}"
CLONE_NETWORK_MODE="${CLONE_NETWORK_MODE:-static}"   # static|dhcp (static recommended for IP->WG mapping)

# Extra disks for clones
EXTRA_DISK_COUNT="${EXTRA_DISK_COUNT:-1}"          # 0 to disable
EXTRA_DISK_SIZE_GB="${EXTRA_DISK_SIZE_GB:-10}"
EXTRA_DISK_TARGET="${EXTRA_DISK_TARGET:-fireball}"  # storage name for extra disks

# Install Profile: server | gnome-min | gnome-full | xfce-min | kde-min
INSTALL_PROFILE="${INSTALL_PROFILE:-server}"

# Optional extra scripts into ISO
SCRIPTS_DIR="${SCRIPTS_DIR:-/root/custom-scripts}"

# ------------------------ WireGuard settings ------------------------
WG_PLANES="${WG_PLANES:-wg0,wg1,wg2,wg3}"

# Master host for peering (LAN endpoint); 10.77.0.1/10.78.0.1/.. are the master's WG addresses
WG_MASTER_HOST="${WG_MASTER_HOST:-10.100.10.224}"

# Ports per plane (defaults match your advanced script)
WG0_PORT="${WG0_PORT:-51820}"
WG1_PORT="${WG1_PORT:-51821}"
WG2_PORT="${WG2_PORT:-51822}"
WG3_PORT="${WG3_PORT:-51823}"

# Allowed ranges
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# Optional master public keys (if not provided, we will try SSH to WG_MASTER_HOST to read /etc/wireguard/wg*.pub)
WG0_MASTER_PUB="${WG0_MASTER_PUB:-}"
WG1_MASTER_PUB="${WG1_MASTER_PUB:-}"
WG2_MASTER_PUB="${WG2_MASTER_PUB:-}"
WG3_MASTER_PUB="${WG3_MASTER_PUB:-}"

# SSH options for Proxmox and (optional) master pubkey fetch
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

# =============================================================================
# Compute / Validate basics
# =============================================================================

VMNAME_CLEAN="${VMNAME//[_\.]/-}"
VMNAME_CLEAN="$(echo "$VMNAME_CLEAN" | sed 's/^-*//;s/-*$//;s/--*/-/g' | tr '[:upper:]' '[:lower:]')"
[[ "$VMNAME_CLEAN" =~ ^[a-z0-9-]+$ ]] || die "Invalid VM name after cleanup: '$VMNAME_CLEAN' (letters, digits, dashes only)."
VMNAME="$VMNAME_CLEAN"

case "$INPUT" in
  1|fiend)  HOST_NAME="fiend.${DOMAIN}";  PROXMOX_HOST="10.100.10.225" ;;
  2|dragon) HOST_NAME="dragon.${DOMAIN}"; PROXMOX_HOST="10.100.10.226" ;;
  3|lion)   HOST_NAME="lion.${DOMAIN}";   PROXMOX_HOST="10.100.10.227" ;;
  *) die "Unknown host: $INPUT" ;;
esac

BASE_FQDN="${VMNAME}.${DOMAIN}"
BASE_VMNAME="${BASE_FQDN}-template"

log "Target: $HOST_NAME ($PROXMOX_HOST)  VMID=$VMID  VMNAME=$BASE_VMNAME"
log "Storages: VM_STORAGE=$VM_STORAGE  ISO_STORAGE=$ISO_STORAGE  Disk=${DISK_SIZE_GB}G"
log "Network: $NETWORK_MODE  DOMAIN=$DOMAIN  Cloud-Init: $USE_CLOUD_INIT  Profile: $INSTALL_PROFILE"
log "WireGuard: master=$WG_MASTER_HOST  ports=$WG0_PORT/$WG1_PORT/$WG2_PORT/$WG3_PORT  planes=$WG_PLANES"

# =============================================================================
# Helpers
# =============================================================================

ip_prefix() { echo "$1" | cut -d. -f1-3; }
ip_host()   { echo "$1" | cut -d. -f4; }

mask_to_cidr() { # dotted mask -> /cidr
  local m="$1"
  awk -v m="$m" 'BEGIN{split(m,a,".");c=0;for(i=1;i<=4;i++){x=a[i]+0;for(j=7;j>=0;j--) if((x>>j)&1)c++; else break} print c}'
}

storage_is_active() {
  local stor="$1"
  ssh $SSH_OPTS root@"$PROXMOX_HOST" "pvesm status --storage '$stor' 2>/dev/null | awk 'NR>1{print \$6}'" | grep -qx active
}

# =============================================================================
# Build ISO payload
# =============================================================================

log "Cleaning build dir..."
umount "$MOUNT_DIR" 2>/dev/null || true
rm -rf "$BUILD_DIR"
mkdir -p "$CUSTOM_DIR" "$MOUNT_DIR" "$DARKSITE_DIR"

[[ -r "$ISO_ORIG" ]] || die "ISO not readable: $ISO_ORIG"

log "Mount ISO..."
mount -o loop,ro "$ISO_ORIG" "$MOUNT_DIR"

log "Copy ISO contents..."
cp -a "$MOUNT_DIR/"* "$CUSTOM_DIR/"
cp -a "$MOUNT_DIR/.disk" "$CUSTOM_DIR/" 2>/dev/null || true
umount "$MOUNT_DIR"

log "Stage custom scripts..."
mkdir -p "$DARKSITE_DIR/scripts"
if [[ -d "$SCRIPTS_DIR" ]] && compgen -G "$SCRIPTS_DIR/*" >/dev/null; then
  rsync -a "$SCRIPTS_DIR"/ "$DARKSITE_DIR/scripts"/
  log "Added scripts from $SCRIPTS_DIR"
else
  log "No scripts at $SCRIPTS_DIR; skipping."
fi

# -----------------------------------------------------------------------------
# postinstall.sh (runs inside the installed VM on first boot)
# Includes clone-finalize that WireGuard-configures a clone using env pushed via QGA
# -----------------------------------------------------------------------------
log "Writing postinstall.sh..."
cat > "$DARKSITE_DIR/postinstall.sh" <<'EOSCRIPT'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/postinstall.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

# Load runtime vars (baked during ISO build)
if [ -f /etc/environment.d/99-provision.conf ]; then
  . /etc/environment.d/99-provision.conf
fi

: "${DOMAIN:?}"
: "${USE_CLOUD_INIT:=false}"
INSTALL_PROFILE="${INSTALL_PROFILE:-server}"

# Users & SSH keys
USERS=(
  "todd:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTeqWqq0ahMQzCbkZRz6/OoVBRat0QXWJGDMy2FzfEh todd@onyx"
)

# Build AllowUsers
ALLOW_USERS=""
for e in "${USERS[@]}"; do u="${e%%:*}"; ALLOW_USERS+="$u "; done
ALLOW_USERS="${ALLOW_USERS%% }"

wait_for_network() {
  log "Waiting for basic network..."
  for i in {1..60}; do
    ip route show default &>/dev/null && ping -c1 -W1 1.1.1.1 &>/dev/null && return 0
    sleep 2
  done
  log "No network after wait; continuing."
}

update_and_upgrade() {
  log "APT sources -> trixie"
  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt -y upgrade
}

install_base_packages() {
  log "Installing base packages..."
  apt install -y --no-install-recommends \
    dbus polkitd pkexec \
    curl wget ca-certificates gnupg lsb-release unzip \
    net-tools traceroute tcpdump sysstat strace lsof \
    rsync rsyslog cron chrony sudo git ethtool jq \
    qemu-guest-agent openssh-server \
    ngrep nmap \
    bpfcc-tools bpftrace libbpf-dev python3-bpfcc python3 python3-pip \
    uuid-runtime tmux htop python3.13-venv \
    linux-image-amd64 linux-headers-amd64 \
    wireguard-tools nftables
}

maybe_install_desktop() {
  case "$INSTALL_PROFILE" in
    gnome-min)
      log "Installing minimal GNOME + NetworkManager..."
      apt install -y --no-install-recommends gnome-core gdm3 gnome-terminal network-manager
      systemctl enable --now NetworkManager gdm3 || true
      ;;
    gnome-full)
      log "Installing full GNOME (task-gnome-desktop)..."
      apt install -y task-gnome-desktop
      ;;
    xfce-min)
      log "Installing minimal XFCE..."
      apt install -y --no-install-recommends xfce4 xfce4-terminal lightdm xorg network-manager
      systemctl enable --now NetworkManager lightdm || true
      ;;
    kde-min)
      log "Installing minimal KDE Plasma..."
      apt install -y --no-install-recommends plasma-desktop sddm plasma-workspace-wayland kwin-wayland konsole network-manager
      systemctl enable --now NetworkManager sddm || true
      ;;
    server) log "Server profile selected. Skipping desktop." ;;
    *)      log "Unknown INSTALL_PROFILE='$INSTALL_PROFILE'. Skipping desktop." ;;
  esac
}

enforce_wayland_defaults() {
  if systemctl list-unit-files | grep -q '^gdm3\.service'; then
    mkdir -p /etc/gdm3
    if [ -f /etc/gdm3/daemon.conf ]; then
      if grep -q '^[# ]*WaylandEnable=' /etc/gdm3/daemon.conf; then
        sed -i 's/^[# ]*WaylandEnable=.*/WaylandEnable=true/' /etc/gdm3/daemon.conf
      else
        printf '\n[daemon]\nWaylandEnable=true\n' >> /etc/gdm3/daemon.conf
      fi
    else
      cat > /etc/gdm3/daemon.conf <<'EOF'
[daemon]
WaylandEnable=true
EOF
    fi
  fi
  if systemctl list-unit-files | grep -q '^sddm\.service'; then
    mkdir -p /etc/sddm.conf.d
    cat > /etc/sddm.conf.d/10-wayland.conf <<'EOF'
[General]
Session=plasmawayland.desktop
[Wayland]
EnableHiDPI=true
EOF
  fi
}

maybe_install_cloud_init() {
  if [[ "$USE_CLOUD_INIT" == "true" ]]; then
    log "Installing cloud-init..."
    apt install -y cloud-init cloud-guest-utils
    systemctl enable cloud-init cloud-init-local cloud-config cloud-final || true
  else
    log "Cloud-Init disabled."
  fi
}

disable_ipv6() {
  log "Disabling IPv6..."
  cat >/etc/sysctl.d/99-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  sysctl -p /etc/sysctl.d/99-disable-ipv6.conf || true
}

write_bashrc() {
  log "Writing /etc/skel/.bashrc"
  cat >/etc/skel/.bashrc <<'EOF'
# ~/.bashrc
[ -z "$PS1" ] && return
PS1='\[\e[0;32m\]\u@\h\[\e[m\]:\[\e[0;34m\]\w\[\e[m\]\$ '
HISTSIZE=10000; HISTFILESIZE=20000; HISTTIMEFORMAT='%F %T '; HISTCONTROL=ignoredups:erasedups
shopt -s histappend checkwinsize cdspell
alias grep='grep --color=auto'
alias ll='ls -alF'; alias la='ls -A'; alias l='ls -CF'
alias ports='ss -tuln'; alias df='df -h'; alias du='du -h'
[ -f /etc/bash_completion ] && . /etc/bash_completion
VENV_DIR="/root/bccenv"; [ -d "$VENV_DIR" ] && [ -n "$PS1" ] && . "$VENV_DIR/bin/activate"
echo "$USER connected to $(hostname) on $(date)"
EOF
  for u in root ansible debian; do
    h=$(eval echo "~$u") || true
    [ -d "$h" ] || continue
    cp /etc/skel/.bashrc "$h/.bashrc"; chown "$u:$u" "$h/.bashrc" || true
  done
}

configure_ufw_firewall() {
  log "Configuring UFW..."
  apt-get install -y ufw
  sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw --force enable
}

write_tmux_conf() {
  log "Writing tmux config..."
  cat >/etc/skel/.tmux.conf <<'EOF'
set -g mouse on
setw -g mode-keys vi
set -g history-limit 10000
set -g default-terminal "screen-256color"
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
bind r source-file ~/.tmux.conf \; display-message "Reloaded!"
EOF
  cp /etc/skel/.tmux.conf /root/.tmux.conf
}

install_custom_scripts() {
  log "Installing custom scripts (if any)..."
  if [[ -d /root/darksite/scripts ]] && compgen -G "/root/darksite/scripts/*" >/dev/null; then
    cp -a /root/darksite/scripts/* /usr/local/bin/
    chmod +x /usr/local/bin/* || true
  fi
}

setup_vim_config() {
  log "Setting up Vim..."
  apt-get install -y vim vim-airline vim-airline-themes vim-ctrlp vim-fugitive vim-gitgutter vim-tabular
  mkdir -p /etc/skel/.vim/autoload/airline/themes
  cat >/etc/skel/.vimrc <<'EOF'
syntax on
filetype plugin indent on
set number
set relativenumber
set tabstop=2 shiftwidth=2 expandtab
EOF
}

setup_python_env() {
  log "Python env for BCC..."
  apt-get install -y python3-psutil python3-bpfcc
  local VENV_DIR="/root/bccenv"
  python3 -m venv --system-site-packages "$VENV_DIR"
  . "$VENV_DIR/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install cryptography pyOpenSSL numba pytest
  deactivate
  for f in /root/.bashrc /etc/skel/.bashrc; do
    grep -q "$VENV_DIR" "$f" 2>/dev/null || echo -e "\n# Auto-activate BCC venv\n[ -d \"$VENV_DIR\" ] && . \"$VENV_DIR/bin/activate\"" >> "$f"
  done
}

setup_users_and_ssh() {
  log "Creating users and hardening sshd..."
  for entry in "${USERS[@]}"; do
    u="${entry%%:*}"; key="${entry#*:}"
    id -u "$u" &>/dev/null || useradd --create-home --shell /bin/bash "$u"
    h="/home/$u"; mkdir -p "$h/.ssh"; chmod 700 "$h/.ssh"
    echo "$key" >"$h/.ssh/authorized_keys"; chmod 600 "$h/.ssh/authorized_keys"
    chown -R "$u:$u" "$h"
    echo "$u ALL=(ALL) NOPASSWD:ALL" >"/etc/sudoers.d/90-$u"; chmod 440 "/etc/sudoers.d/90-$u"
  done
  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/99-custom.conf <<EOF
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${ALLOW_USERS}
EOF
  chmod 600 /etc/ssh/sshd_config.d/99-custom.conf
  systemctl restart ssh
}

configure_dns_hosts() {
  log "Hostname and /etc/hosts..."
  VMNAME="$(hostname --short)"
  FQDN="${VMNAME}.${DOMAIN}"
  hostnamectl set-hostname "$FQDN"
  echo "$VMNAME" >/etc/hostname
  cat >/etc/hosts <<EOF
127.0.0.1 localhost
127.0.1.1 ${FQDN} ${VMNAME}
EOF
}

sync_skel_to_existing_users() {
  for u in root ansible debian; do
    h=$(eval echo "~$u") || true
    [ -d "$h" ] || continue
    cp /etc/skel/.bashrc "$h/.bashrc" || true
    cp /etc/skel/.tmux.conf "$h/.tmux.conf" || true
    cp /etc/skel/.vimrc "$h/.vimrc" || true
    chown -R "$u:$u" "$h" || true
  done
}

enable_services() {
  systemctl enable qemu-guest-agent ssh rsyslog chrony || true
  if [[ "$USE_CLOUD_INIT" == "true" ]]; then
    systemctl enable cloud-init cloud-init-local cloud-config cloud-final || true
  fi
}

cleanup_identity() {
  log "Cleaning identity for template safety..."
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id
  ln -s /etc/machine-id /var/lib/dbus/machine-id
  rm -f /etc/ssh/ssh_host_* || true
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure openssh-server
}

final_cleanup() {
  apt autoremove -y || true
  apt clean || true
  rm -rf /tmp/* /var/tmp/* || true
  find /var/log -type f -exec truncate -s 0 {} \; || true
}

# -------- clone-finalize (runs *inside* each clone via QGA) --------
install -d -m0755 /usr/local/sbin
cat >/usr/local/sbin/clone-finalize <<'EOF_CF'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/clone-finalize.log"
exec > >(tee -a "$LOG") 2>&1
log(){ echo "[CF] $(date '+%F %T') - $*"; }

# Read environment (pushed by the builder)
for f in /etc/environment.d/*.conf; do [ -r "$f" ] && . "$f"; done

WG_MASTER_HOST="${WG_MASTER_HOST:-10.100.10.224}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"
WG0_PORT="${WG0_PORT:-51820}"; WG1_PORT="${WG1_PORT:-51821}"; WG2_PORT="${WG2_PORT:-51822}"; WG3_PORT="${WG3_PORT:-51823}"

# If WG*_WANTED are not provided, compute from LAN last-octet
lan_ip="$(ip -4 addr show scope global | awk '/inet /{gsub(/\/.*/,"",$2);print $2; exit}')"
last_oct="${lan_ip##*.}"

: "${WG0_WANTED:="10.77.0.${last_oct}/16"}"
: "${WG1_WANTED:="10.78.0.${last_oct}/16"}"
: "${WG2_WANTED:="10.79.0.${last_oct}/16"}"
: "${WG3_WANTED:="10.80.0.${last_oct}/16"}"

install -d -m700 /etc/wireguard
umask 077
for i in 0 1 2 3; do
  test -f /etc/wireguard/wg${i}.key || wg genkey | tee /etc/wireguard/wg${i}.key | wg pubkey >/etc/wireguard/wg${i}.pub
done

mk_if(){
  local ifn="$1" ipcidr="$2" port="$3" master_pub="$4"
  cat >/etc/wireguard/${ifn}.conf <<EOF
[Interface]
Address    = ${ipcidr}
PrivateKey = $(cat /etc/wireguard/${ifn}.key)
ListenPort = 0
MTU        = 1420
SaveConfig = true
EOF
  # Peer to master if pub is known
  if [ -n "$master_pub" ]; then
    cat >>/etc/wireguard/${ifn}.conf <<EOF
[Peer]
PublicKey  = ${master_pub}
Endpoint   = ${WG_MASTER_HOST}:${port}
AllowedIPs = ${WG_ALLOWED_CIDR}
PersistentKeepalive = 25
EOF
  fi
  chmod 600 /etc/wireguard/${ifn}.conf
  systemctl enable --now "wg-quick@${ifn}" || true
}

mk_if wg0 "$WG0_WANTED" "$WG0_PORT" "${WG0_MASTER_PUB:-}"
mk_if wg1 "$WG1_WANTED" "$WG1_PORT" "${WG1_MASTER_PUB:-}"
mk_if wg2 "$WG2_WANTED" "$WG2_PORT" "${WG2_MASTER_PUB:-}"
mk_if wg3 "$WG3_WANTED" "$WG3_PORT" "${WG3_MASTER_PUB:-}"

# simple nft to allow ssh + wg egress
cat >/etc/nftables.conf <<'EONFT'
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
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EONFT
systemctl enable --now nftables || true

log "clone-finalize done."
EOF_CF
chmod +x /usr/local/sbin/clone-finalize

log "BEGIN postinstall"
wait_for_network
update_and_upgrade
install_base_packages
maybe_install_desktop
enforce_wayland_defaults
maybe_install_cloud_init
disable_ipv6
setup_vim_config
write_bashrc
configure_ufw_firewall
write_tmux_conf
sync_skel_to_existing_users
setup_users_and_ssh
setup_python_env
configure_dns_hosts
install_custom_scripts
enable_services
cleanup_identity
final_cleanup

log "Disabling bootstrap service..."
systemctl disable bootstrap.service || true
rm -f /etc/systemd/system/bootstrap.service
rm -f /etc/systemd/system/multi-user.target.wants/bootstrap.service

log "Postinstall complete. Forcing poweroff..."
/sbin/poweroff -f
EOSCRIPT
chmod +x "$DARKSITE_DIR/postinstall.sh"

# -----------------------------------------------------------------------------
# bootstrap.service
# -----------------------------------------------------------------------------
log "Writing bootstrap.service..."
cat > "$DARKSITE_DIR/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (One-time)
After=network.target
Wants=network.target
ConditionPathExists=/root/darksite/postinstall.sh

[Service]
Type=oneshot
ExecStart=/bin/bash -lc '/root/darksite/postinstall.sh'
TimeoutStartSec=0
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

# -----------------------------------------------------------------------------
# Bake 99-provision.conf now (no heredoc in preseed)
# -----------------------------------------------------------------------------
cat > "$DARKSITE_DIR/99-provision.conf" <<EOF
DOMAIN=$DOMAIN
USE_CLOUD_INIT=$USE_CLOUD_INIT
INSTALL_PROFILE=$INSTALL_PROFILE
EOF

# -----------------------------------------------------------------------------
# finalize-template.sh (runs on the build host; controls Proxmox cloning + WG env push)
# -----------------------------------------------------------------------------
log "Writing finalize-template.sh..."
cat > "$DARKSITE_DIR/finalize-template.sh" <<'EOSCRIPT'
#!/usr/bin/env bash
set -euo pipefail

: "${PROXMOX_HOST:?Missing PROXMOX_HOST}"
: "${TEMPLATE_VMID:?Missing TEMPLATE_VMID}"
: "${NUM_CLONES:?Missing NUM_CLONES}"
: "${BASE_CLONE_VMID:?Missing BASE_CLONE_VMID}"
: "${BASE_CLONE_IP:?Missing BASE_CLONE_IP}"
: "${CLONE_MEMORY_MB:=4096}"
: "${CLONE_CORES:=4}"
: "${CLONE_VLAN_ID:=}"
: "${CLONE_GATEWAY:=}"
: "${CLONE_NAMESERVER:=}"
: "${CLONE_NETMASK:=255.255.255.0}"
: "${VMNAME_CLEAN:?Missing VMNAME_CLEAN}"
: "${VM_STORAGE:?Missing VM_STORAGE}"
: "${ISO_STORAGE:=local}"
: "${USE_CLOUD_INIT:=false}"
: "${DOMAIN:=localdomain}"
: "${EXTRA_DISK_COUNT:=0}"
: "${EXTRA_DISK_SIZE_GB:=100}"
: "${EXTRA_DISK_TARGET:=}"
: "${CLONE_NETWORK_MODE:=static}"

# WireGuard settings passed in
: "${WG_MASTER_HOST:=10.100.10.224}"
: "${WG_ALLOWED_CIDR:=10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"
: "${WG0_PORT:=51820}"; : "${WG1_PORT:=51821}"; : "${WG2_PORT:=51822}"; : "${WG3_PORT:=51823}"
: "${WG_PLANES:=wg0,wg1,wg2,wg3}"
: "${WG0_MASTER_PUB:=}"; : "${WG1_MASTER_PUB:=}"; : "${WG2_MASTER_PUB:=}"; : "${WG3_MASTER_PUB:=}"

SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=6"

echo "[*] Waiting for VM $TEMPLATE_VMID on $PROXMOX_HOST to shut down..."
SECONDS=0; TIMEOUT=900
while ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm status $TEMPLATE_VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { echo "[!] Timeout waiting for shutdown"; exit 1; }
  sleep 15
done

echo "[*] Converting $TEMPLATE_VMID to template..."
ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm template $TEMPLATE_VMID"

check_storage() {
  local stor="$1"
  ssh $SSH_OPTS root@"$PROXMOX_HOST" "pvesm status --storage $stor 2>/dev/null | awk 'NR>1 {print \$6}'" | grep -qx active
}

ip_prefix(){ echo "$1" | cut -d. -f1-3; }
ip_host(){ echo "$1" | cut -d. -f4; }
mask_to_cidr() {
  local m="$1"
  awk -v m="$m" 'BEGIN{split(m,a,".");c=0;for(i=1;i<=4;i++){x=a[i]+0;for(j=7;j>=0;j--) if((x>>j)&1)c++; else break} print c}'
}

# Try to fetch master public keys if not provided
fetch_master_pubs() {
  local host="${WG_MASTER_HOST}"
  for n in 0 1 2 3; do
    local var="WG${n}_MASTER_PUB"
    if [ -z "${!var}" ]; then
      pub="$(ssh $SSH_OPTS root@"$host" "cat /etc/wireguard/wg${n}.pub 2>/dev/null" || true)"
      if [ -n "$pub" ]; then
        printf -v "$var" '%s' "$pub"; export "$var"
        echo "[OK] fetched ${var} from $host"
      else
        echo "[WARN] could not fetch ${var} from $host; clones will bring up ${n} without a peer (you can push later)."
      fi
    fi
  done
}

# QGA helpers
qga_has_json() {
  ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm guest exec -h 2>&1 | grep -q -- '--output-format' && echo yes || echo no"
}
guest_exec() { # guest_exec <vmid> <command...>
  local vmid="$1"; shift
  local cmd="qm guest exec $vmid -- $* >/dev/null 2>&1 || true"
  ssh $SSH_OPTS root@"$PROXMOX_HOST" "$cmd"
}
guest_push_env() { # guest_push_env <vmid> <key=value>...
  local vmid="$1"; shift
  local tmp="$(mktemp)"; : >"$tmp"
  for kv in "$@"; do echo "$kv" >> "$tmp"; done
  # shell-safe payload
  local payload; payload="$(sed 's/[$`\\]/\\&/g' "$tmp" | sed 's/"/\\"/g')"; rm -f "$tmp"
  ssh $SSH_OPTS root@"$PROXMOX_HOST" \
    "qm guest exec $vmid -- /bin/bash -lc 'install -d -m0755 /etc/environment.d && printf \"%s\n\" \"$payload\" > /etc/environment.d/97-clone.conf && chmod 0644 /etc/environment.d/97-clone.conf' >/dev/null 2>&1 || true"
}
wait_qga() { # wait_qga <vmid> [timeout]
  local vmid="$1" timeout="${2:-900}" start
  start="$(date +%s)"
  while :; do
    if ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm agent $vmid ping >/dev/null 2>&1 || qm guest ping $vmid >/dev/null 2>&1"; then
      return 0
    fi
    (( $(date +%s)-start > timeout )) && return 1
    sleep 3
  done
}

# Pre-check storages
check_storage "$VM_STORAGE" || { echo "[X] VM_STORAGE '$VM_STORAGE' inactive"; exit 1; }
if [[ "$EXTRA_DISK_COUNT" -gt 0 ]]; then
  check_storage "$EXTRA_DISK_TARGET" || { echo "[X] EXTRA_DISK_TARGET '$EXTRA_DISK_TARGET' inactive"; EXTRA_DISK_COUNT=0; }
fi

# Pre-fetch master pubs if possible
fetch_master_pubs || true

lan_prefix="$(ip_prefix "$BASE_CLONE_IP")"
lan_host="$(ip_host "$BASE_CLONE_IP")"

for ((i=0; i<NUM_CLONES; i++)); do
  CLONE_VMID=$((BASE_CLONE_VMID + i))

  case "$CLONE_NETWORK_MODE" in
    static)      CLONE_IP="${lan_prefix}.$((lan_host + i))" ;;
    dhcp)        CLONE_IP="dhcp" ;;
    *)           echo "[X] Unknown CLONE_NETWORK_MODE '$CLONE_NETWORK_MODE'"; exit 1 ;;
  esac

  INDEX=$((i+1))
  FQDN="${VMNAME_CLEAN}.${DOMAIN}"
  CLONE_NAME="${VMNAME_CLEAN}.${DOMAIN}-${INDEX}-${CLONE_IP}"
  DESC="${FQDN} - ${CLONE_IP}"

  # WG wanted addresses (follow last octet of LAN IP, or use base+offset if DHCP)
  if [[ "$CLONE_IP" == "dhcp" ]]; then
    # derive from base + i
    last=$((lan_host + i))
  else
    last="${CLONE_IP##*.}"
  fi
  WG0_WANTED="10.77.0.${last}/16"
  WG1_WANTED="10.78.0.${last}/16"
  WG2_WANTED="10.79.0.${last}/16"
  WG3_WANTED="10.80.0.${last}/16"

  echo "[*] Cloning $CLONE_NAME (VMID $CLONE_VMID, LAN $CLONE_IP, WG0 $WG0_WANTED)..."

  ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm clone $TEMPLATE_VMID $CLONE_VMID --name '$CLONE_NAME' --full 1 --storage $VM_STORAGE"
  ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --delete ide3 || true"

  NET_OPTS="virtio,bridge=vmbr0"
  [[ -n "$CLONE_VLAN_ID" ]] && NET_OPTS="$NET_OPTS,tag=$CLONE_VLAN_ID"

  ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --memory $CLONE_MEMORY_MB --cores $CLONE_CORES --net0 $NET_OPTS --agent enabled=1 --boot order=scsi0"

  if [[ "$USE_CLOUD_INIT" == "true" ]]; then
    ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --ide3 ${VM_STORAGE}:cloudinit"
    if [[ "$CLONE_NETWORK_MODE" == "static" ]]; then
      CIDR="$(mask_to_cidr "$CLONE_NETMASK")"
      ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --ipconfig0 ip=${CLONE_IP}/${CIDR}${CLONE_GATEWAY:+,gw=${CLONE_GATEWAY}}"
      [[ -n "$CLONE_NAMESERVER" ]] && ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --nameserver '$CLONE_NAMESERVER'"
    else
      ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --ipconfig0 ip=dhcp"
      [[ -n "$CLONE_NAMESERVER" ]] && ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --nameserver '$CLONE_NAMESERVER'"
    fi
  fi

  if [[ "$EXTRA_DISK_COUNT" -gt 0 ]]; then
    echo "[*] Adding $EXTRA_DISK_COUNT extra disk(s) to VM $CLONE_VMID on $EXTRA_DISK_TARGET (${EXTRA_DISK_SIZE_GB}G each)..."
    for ((d=1; d<=EXTRA_DISK_COUNT; d++)); do
      DISK_BUS="scsi$((d))"
      ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --${DISK_BUS} ${EXTRA_DISK_TARGET}:${EXTRA_DISK_SIZE_GB}"
    done
  fi

  ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm set $CLONE_VMID --description '$DESC'"
  ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm start $CLONE_VMID"
  echo "[+] Clone $CLONE_NAME started."

  # Wait for QGA then push WG env and run clone-finalize
  if wait_qga "$CLONE_VMID" 900; then
    guest_push_env "$CLONE_VMID" \
      "WG_MASTER_HOST=$WG_MASTER_HOST" \
      "WG_ALLOWED_CIDR=$WG_ALLOWED_CIDR" \
      "WG0_PORT=$WG0_PORT" "WG1_PORT=$WG1_PORT" "WG2_PORT=$WG2_PORT" "WG3_PORT=$WG3_PORT" \
      "WG0_WANTED=$WG0_WANTED" "WG1_WANTED=$WG1_WANTED" "WG2_WANTED=$WG2_WANTED" "WG3_WANTED=$WG3_WANTED" \
      "WG0_MASTER_PUB=$WG0_MASTER_PUB" "WG1_MASTER_PUB=$WG1_MASTER_PUB" "WG2_MASTER_PUB=$WG2_MASTER_PUB" "WG3_MASTER_PUB=$WG3_MASTER_PUB"

    guest_exec "$CLONE_VMID" /bin/bash -lc "/usr/local/sbin/clone-finalize || true"
  else
    echo "[WARN] QGA not ready on VMID $CLONE_VMID; WG will configure at next manual run: /usr/local/sbin/clone-finalize"
  fi
done

echo "[OK] All clones created and provisioned."
EOSCRIPT
chmod +x "$DARKSITE_DIR/finalize-template.sh"

# =============================================================================
# Preseed (Network + Profile)
# =============================================================================
log "Creating preseed.cfg..."

if [[ "$NETWORK_MODE" == "dhcp" ]]; then
  NETBLOCK=$(cat <<EOF
# Networking (DHCP)
d-i netcfg/choose_interface select auto
d-i netcfg/disable_dhcp boolean false
d-i netcfg/get_hostname string $VMNAME
d-i netcfg/get_domain string $DOMAIN
EOF
)
else
  NETBLOCK=$(cat <<EOF
# Networking (Static)
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string $VMNAME
d-i netcfg/get_domain string $DOMAIN
d-i netcfg/disable_dhcp boolean true
d-i netcfg/get_ipaddress string $STATIC_IP
d-i netcfg/get_netmask string $NETMASK
d-i netcfg/get_gateway string $GATEWAY
d-i netcfg/get_nameservers string $NAMESERVER
EOF
)
fi

case "$INSTALL_PROFILE" in
  server)
    PROFILEBLOCK=$(cat <<'EOF'
# Server profile (no desktop)
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  gnome-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal GNOME (Wayland via gdm3)
tasksel tasksel/first multiselect standard
d-i pkgsel/include string gnome-core gdm3 gnome-terminal network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  gnome-full)
    PROFILEBLOCK=$(cat <<'EOF'
# Full GNOME
tasksel tasksel/first multiselect standard, desktop, gnome-desktop, ssh-server
d-i pkgsel/include string
d-i pkgsel/ignore-recommends boolean false
d-i pkgsel/upgrade select none
EOF
)
    ;;
  xfce-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal XFCE (X11)
tasksel tasksel/first multiselect standard
d-i pkgsel/include string xfce4 xfce4-terminal lightdm xorg network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  kde-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal KDE Plasma (Wayland)
tasksel tasksel/first multiselect standard
d-i pkgsel/include string plasma-desktop sddm plasma-workspace-wayland kwin-wayland konsole network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  *) die "Unknown INSTALL_PROFILE: $INSTALL_PROFILE" ;;
esac

cat > "$CUSTOM_DIR/$PRESEED_FILE" <<EOF
# Locale & keyboard
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us

$NETBLOCK

# Mirrors (we will re-point in postinstall)
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
d-i apt-setup/use_mirror boolean false
d-i apt-setup/non-free boolean true
d-i apt-setup/contrib boolean true

# Temporary user (postinstall creates real users)
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/username string debian
d-i passwd/user-fullname string Debian User
d-i passwd/user-password password debian
d-i passwd/user-password-again password debian

# Timezone
d-i time/zone string America/Toronto
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true

# Disk (guided LVM on whole disk)
d-i partman-auto/method string lvm
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-lvm/confirm_write_new_label boolean true
d-i partman-auto-lvm/guided_size string max

$PROFILEBLOCK

d-i grub-installer/bootdev string /dev/sda
d-i grub-installer/only_debian boolean true

d-i finish-install/keep-consoles boolean false
d-i finish-install/exit-installer boolean true
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true
d-i cdrom-detect/eject boolean true

tasksel tasksel/first multiselect standard, ssh-server
d-i finish-install/reboot_in_progress note
# Late command: copy darksite payload and enable bootstrap
d-i preseed/late_command string \
  mkdir -p /target/root/darksite ; \
  cp -a /cdrom/darksite/* /target/root/darksite/ ; \
  in-target chmod +x /root/darksite/postinstall.sh ; \
  in-target cp /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service ; \
  in-target mkdir -p /etc/environment.d ; \
  in-target cp /root/darksite/99-provision.conf /etc/environment.d/99-provision.conf ; \
  in-target chmod 0644 /etc/environment.d/99-provision.conf ; \
  in-target systemctl daemon-reload ; \
  in-target systemctl enable bootstrap.service ;

# Power off the installer VM (no reboot)
d-i debian-installer/exit/poweroff boolean true
EOF

# =============================================================================
# Boot menu & ISO rebuild
# =============================================================================
log "Updating isolinux/txt.cfg..."
TXT_CFG="$CUSTOM_DIR/isolinux/txt.cfg"
ISOLINUX_CFG="$CUSTOM_DIR/isolinux/isolinux.cfg"
cat >> "$TXT_CFG" <<EOF
label auto
  menu label ^base
  kernel /install.amd/vmlinuz
  append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz preseed/file=/cdrom/$PRESEED_FILE ---
EOF
sed -i 's/^default .*/default auto/' "$ISOLINUX_CFG"

log "Rebuilding ISO..."
xorriso -as mkisofs \
  -o "$OUTPUT_ISO" \
  -r -J -joliet-long -l \
  -b isolinux/isolinux.bin \
  -c isolinux/boot.cat \
  -no-emul-boot -boot-load-size 4 -boot-info-table \
  -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
  -no-emul-boot -isohybrid-gpt-basdat \
  "$CUSTOM_DIR"

mv "$OUTPUT_ISO" "$FINAL_ISO"
log "ISO ready: $FINAL_ISO"

# =============================================================================
# Upload ISO & create the base VM on Proxmox
# =============================================================================
log "Uploading ISO to $PROXMOX_HOST..."
scp $SSH_OPTS -q "$FINAL_ISO" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/"
FINAL_ISO_BASENAME="$(basename "$FINAL_ISO")"

log "Creating VM $VMID on $PROXMOX_HOST..."
ssh $SSH_OPTS root@"$PROXMOX_HOST" \
  VMID="$VMID" VMNAME="$BASE_VMNAME" FINAL_ISO="$FINAL_ISO_BASENAME" \
  VM_STORAGE="${VM_STORAGE:-void}" ISO_STORAGE="${ISO_STORAGE:-local}" \
  DISK_SIZE_GB="${DISK_SIZE_GB:-32}" MEMORY_MB="${MEMORY_MB:-4096}" \
  CORES="${CORES:-4}" USE_CLOUD_INIT="${USE_CLOUD_INIT:-false}" \
  'bash -s' <<'EOSSH'
set -euo pipefail
: "${VMID:?}"; : "${VMNAME:?}"; : "${FINAL_ISO:?}"
: "${VM_STORAGE:?}"; : "${ISO_STORAGE:?}"
: "${DISK_SIZE_GB:?}"; : "${MEMORY_MB:?}"; : "${CORES:?}"

qm destroy "$VMID" --purge || true

qm create "$VMID" \
  --name "$VMNAME" \
  --memory "$MEMORY_MB" \
  --cores "$CORES" \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom \
  --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} \
  --serial0 socket \
  --ostype l26 \
  --agent enabled=1

qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0
qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH

# =============================================================================
# Wait for preseed shutdown, flip boot, set description
# =============================================================================
log "Waiting for VM $VMID to power off after installer..."
SECONDS=0; TIMEOUT=1800
while ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { error_log "Timeout waiting for installer shutdown"; exit 1; }
  sleep 20
done

if [[ "$NETWORK_MODE" == "static" ]]; then
  BASE_DESC="${BASE_FQDN}-template - ${STATIC_IP}"
else
  BASE_DESC="${BASE_FQDN}-template - DHCP"
fi

log "Detach ISO, set boot=scsi0, optionally add cloudinit, set description..."
ssh $SSH_OPTS root@"$PROXMOX_HOST" 'bash -s --' "$VMID" "$VM_STORAGE" "$USE_CLOUD_INIT" "$BASE_DESC" <<'EOSSH'
set -euo pipefail
VMID="$1"; VM_STORAGE="$2"; USE_CLOUD_INIT="$3"; VM_DESC="$4"

qm set "$VMID" --delete ide2
qm set "$VMID" --boot order=scsi0
if [ "$USE_CLOUD_INIT" = "true" ]; then
  qm set "$VMID" --ide3 ${VM_STORAGE}:cloudinit
fi
qm set "$VMID" --description "$VM_DESC"
qm start "$VMID"
EOSSH

# =============================================================================
# Wait for postinstall poweroff, then template + clone
# =============================================================================
log "Waiting for VM $VMID to power off after postinstall..."
SECONDS=0; TIMEOUT=1800
while ssh $SSH_OPTS root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { error_log "Timeout waiting for postinstall shutdown"; exit 1; }
  sleep 20
done

log "Template + clone loop (with WG provisioning)..."
IP_PREFIX="$(echo "$BASE_CLONE_IP" | cut -d. -f1-3)"
IP_START="$(echo "$BASE_CLONE_IP" | cut -d. -f4)"

# Export knobs for finalize-template.sh
export PROXMOX_HOST TEMPLATE_VMID="$VMID" VM_STORAGE USE_CLOUD_INIT DOMAIN
export NUM_CLONES BASE_CLONE_VMID BASE_CLONE_IP CLONE_MEMORY_MB CLONE_CORES
export CLONE_VLAN_ID CLONE_GATEWAY="$GATEWAY" CLONE_NAMESERVER="$NAMESERVER" CLONE_NETMASK="$NETMASK" CLONE_NETWORK_MODE
export VMNAME_CLEAN="$VMNAME" EXTRA_DISK_COUNT EXTRA_DISK_SIZE_GB EXTRA_DISK_TARGET ISO_STORAGE

# WireGuard plane info (and optional master pubs)
export WG_MASTER_HOST WG_ALLOWED_CIDR WG0_PORT WG1_PORT WG2_PORT WG3_PORT WG_PLANES
export WG0_MASTER_PUB WG1_MASTER_PUB WG2_MASTER_PUB WG3_MASTER_PUB

bash "$DARKSITE_DIR/finalize-template.sh"

log "All done."
