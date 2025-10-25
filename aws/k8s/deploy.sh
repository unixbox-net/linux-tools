#!/usr/bin/env bash
# unified cluster builder: proxmox + iso9660 + k8s+cilium + aws ami/run + firecracker
# source: merged from your current script + cluster-deploy.sh + scc.sh
# mode switch via TARGET=... (see bottom)

set -Eeuo pipefail
trap 'rc=$?; echo; echo "[X] ${BASH_COMMAND@Q} failed at line ${LINENO} (rc=${rc})";
      { command -v nl >/dev/null && nl -ba "$0" | sed -n "$((LINENO-5)),$((LINENO+5))p"; } || true; exit $rc' ERR

# ============================ DRIVER MODE ================================
# proxmox-cluster | image-only | packer-scaffold | firecracker-bundle | firecracker
# aws-ami | aws-run | k8s-only (run K8s/Cilium on an already-reachable host set)
TARGET="${TARGET:-proxmox-cluster}"

# ============================ GLOBAL CONFIG =============================
INPUT="${INPUT:-1}"   # 1|fiend, 2|dragon, 3|lion
DOMAIN="${DOMAIN:-unixbox.net}"
case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) echo "[ERROR] Unknown INPUT=$INPUT" >&2; exit 1 ;;
esac

BUILD_ROOT="${BUILD_ROOT:-/root/builds}"; mkdir -p "$BUILD_ROOT"

log()  { echo "[INFO]  $(date '+%F %T') - $*"; }
warn() { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err()  { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()  { err "$*"; exit 1; }

# SSH helpers (Proxmox fanout and generic)
SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }

IMAGE_FORMATS="${IMAGE_FORMATS:-iso,qcow2,raw}"
DISK_GB_DEFAULT="${DISK_GB_DEFAULT:-10}"
PACKER_OUT="${PACKER_OUT:-${BUILD_ROOT}/packer}"
FIRECRACKER_OUT="${FIRECRACKER_OUT:-${BUILD_ROOT}/firecracker}"

# Debian netinst ISO (works offline via darksite)
ISO_ORIG="${ISO_ORIG:-/var/lib/libvirt/boot/debian-13.1.0-amd64-netinst.iso}"
ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"
ROOT_SCHEME="${ROOT_SCHEME:-zfs}"

# Proxmox roles/IDs/IPs
MASTER_ID="${MASTER_ID:-5010}"; MASTER_NAME="${MASTER_NAME:-master}"; MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
PROM_ID="${PROM_ID:-5011}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.123}"
GRAF_ID="${GRAF_ID:-5012}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.122}"
K8S_ID="${K8S_ID:-5013}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.121}"
STOR_ID="${STOR_ID:-5014}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.120}"

NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3}"

# WG hub (master) subnets/ports
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# Minion per-plane IPs (/32)
PROM_WG0="${PROM_WG0:-10.77.0.2/32}"; PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; PROM_WG2="${PROM_WG2:-10.79.0.2/32}"; PROM_WG3="${PROM_WG3:-10.80.0.2/32}"
GRAF_WG0="${GRAF_WG0:-10.77.0.3/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; GRAF_WG2="${GRAF_WG2:-10.79.0.3/32}"; GRAF_WG3="${GRAF_WG3:-10.80.0.3/32}"
K8S_WG0="${K8S_WG0:-10.77.0.4/32}";  K8S_WG1="${K8S_WG1:-10.78.0.4/32}";  K8S_WG2="${K8S_WG2:-10.79.0.4/32}";  K8S_WG3="${K8S_WG3:-10.80.0.4/32}"
STOR_WG0="${STOR_WG0:-10.77.0.5/32}"; STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; STOR_WG2="${STOR_WG2:-10.79.0.5/32}"; STOR_WG3="${STOR_WG3:-10.80.0.5/32}"

# ================= Kubernetes / Cilium (Pattern A default) =================
K8S_ENABLE="${K8S_ENABLE:-yes}"
K8S_VERSION="${K8S_VERSION:-1.29}"
K8S_POD_CIDR="${K8S_POD_CIDR:-10.244.0.0/16}"
K8S_SVC_CIDR="${K8S_SVC_CIDR:-10.96.0.0/12}"
K8S_API_ADVERTISE_IFACE="${K8S_API_ADVERTISE_IFACE:-wg2}"
K8S_NODE_IP_IFACE="${K8S_NODE_IP_IFACE:-wg2}"
K8S_RUNTIME="${K8S_RUNTIME:-containerd}"

CILIUM_VERSION="${CILIUM_VERSION:-1.14.6}"
CILIUM_ENCRYPTION="${CILIUM_ENCRYPTION:-disabled}"   # disabled (native routing)
CILIUM_WG_INTERFACE="${CILIUM_WG_INTERFACE:-wg2}"
CILIUM_KPR="${CILIUM_KPR:-strict}"
CILIUM_TUNNEL_MODE="${CILIUM_TUNNEL_MODE:-disabled}"
CILIUM_AUTO_DIRECT_ROUTES="${CILIUM_AUTO_DIRECT_ROUTES:-true}"
CILIUM_BPF_MASQ="${CILIUM_BPF_MASQ:-true}"

# MetalLB
METALLB_POOL_CIDRS="${METALLB_POOL_CIDRS:-10.100.10.111-10.100.10.130}"
METALLB_NAMESPACE="${METALLB_NAMESPACE:-metallb-system}"

# Sizing
MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-8}"; MASTER_DISK_GB="${MASTER_DISK_GB:-20}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-20}"
K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

# Admin
ADMIN_USER="${ADMIN_USER:-todd}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-/home/todd/.ssh/id_ed25519.pub}"
SSH_PUBKEY="${SSH_PUBKEY:-}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
GUI_PROFILE="${GUI_PROFILE:-rdp-minimal}"

# Ops extras
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
ZFS_MOUNTPOINT="${ZFS_MOUNTPOINT:-/mnt/share}"

# ============================ AWS GLOBALS =============================
# Values can be overridden via env:
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_VPC_ID="${AWS_VPC_ID:-}"                # existing VPC or blank to create
AWS_SUBNET_ID="${AWS_SUBNET_ID:-}"          # existing subnet or blank to create
AWS_SG_ID="${AWS_SG_ID:-}"                  # existing SG or blank to create
AWS_KEY_NAME="${AWS_KEY_NAME:-clusterkey}"  # EC2 KeyPair name (will import if public key path set)
AWS_PUBLIC_KEY_PATH="${AWS_PUBLIC_KEY_PATH:-}" # file path to .pub key to import as KeyPair
AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-m5.large}"
AWS_ARCH="${AWS_ARCH:-x86_64}"              # x86_64 | arm64
AWS_ENABLE_SSH="${AWS_ENABLE_SSH:-true}"    # authorize port 22 from your IP (/32)
AWS_SSH_CIDR="${AWS_SSH_CIDR:-}"            # override allow-list for SSH ingress
AWS_ASSOC_PUBLIC_IP="${AWS_ASSOC_PUBLIC_IP:-true}" # attach public IPs to instances
AWS_AMI_NAME_PREFIX="${AWS_AMI_NAME_PREFIX:-unixbox-debian13}"
AWS_TAG_STACK="${AWS_TAG_STACK:-ucluster}"
AWS_RUN_COUNT="${AWS_RUN_COUNT:-5}"
AWS_PRIVATE_IP_BASE="${AWS_PRIVATE_IP_BASE:-10.0.1.5}"  # starting private IP (AWS reserves .0-.3 & .255)
AWS_RUN_ROLE="${AWS_RUN_ROLE:-k8s}"          # label instances role (k8s|prom|graf|storage|master)

# -------------------- Early validation / helpers --------------------
validate_env_or_die() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
  local -a req=(BUILD_ROOT ISO_ORIG)
  local -a miss=(); for v in "${req[@]}"; do [[ -n "${!v:-}" ]] || miss+=("$v"); done
  ((${#miss[@]}==0)) || die "missing: ${miss[*]}"
  [[ -r "$ISO_ORIG" ]] || die "ISO_ORIG not readable: $ISO_ORIG"
  mkdir -p "$BUILD_ROOT"
  log "[OK] environment validated"
}
validate_env_or_die

retry(){ local n="$1" s="$2"; shift 2; local i; for ((i=1;i<=n;i++)); do "$@" && return 0; sleep "$s"; done; return 1; }
mask_to_cidr(){ awk -v m="$1" 'BEGIN{split(m,a,".");c=0;for(i=1;i<=4;i++){x=a[i]+0;for(j=7;j>=0;j--) if((x>>j)&1) c++; else break}print c}'; }
inc_ip(){ # increment dotted IP by N (default 1)
  local ip="$1" inc="${2:-1}"
  python3 - "$ip" "$inc" <<'PY'
import ipaddress,sys
ip=ipaddress.IPv4Address(sys.argv[1]); inc=int(sys.argv[2]); print(str(ip+inc))
PY
}

# -------- Proxmox helpers (QGA aware) --------
pmx(){ sssh root@"$PROXMOX_HOST" "$@"; }
pmx_vm_state(){ pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }
pmx_wait_for_state(){ local id="$1" want="$2" t="${3:-2400}" s="$(date +%s)" st; while :; do st="$(pmx_vm_state "$id")"; [[ "$st" == "$want" ]] && return 0; (( $(date +%s) - s > t )) && return 1; sleep 5; done; }
pmx_wait_qga(){ local id="$1" t="${2:-1200}" s=$(date +%s); while :; do pmx "qm agent $id ping >/dev/null 2>&1 || qm guest ping $id >/dev/null 2>&1" && return 0; (( $(date +%s) - s > t )) && return 1; sleep 3; done; }
pmx_qga_has_json(){ PMX_QGA_JSON="${PMX_QGA_JSON:-$(pmx "qm guest exec -h 2>&1 | grep -q -- '--output-format' && echo yes || echo no" | tr -d '\r')}"; echo "$PMX_QGA_JSON"; }
pmx_guest_exec(){ local id="$1"; shift; local q=(); for a in "$@"; do q+=("$(printf '%q' "$a")"); done; pmx "qm guest exec $id -- ${q[*]} >/dev/null 2>&1 || true"; }
pmx_guest_cat(){
  local id="$1" path="$2" has_json out pid st data
  has_json="$(pmx_qga_has_json)"
  if [[ "$has_json" == "yes" ]]; then
    out="$(pmx "qm guest exec $id --output-format json -- /bin/cat '$path' 2>/dev/null || true")"
    pid="$(printf '%s\n' "$out" | sed -n 's/.*\"pid\"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p')"
    [[ -n "$pid" ]] || return 2
    while :; do
      st="$(pmx "qm guest exec-status $id $pid --output-format json 2>/dev/null || true")" || true
      if printf '%s' "$st" | grep -Eq '"exited"[[:space:]]*:[[:space:]]*(true|1)'; then
        data="$(printf '%s' "$st" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
        [[ -n "$data" ]] && { printf '%s' "$data" | base64 -d 2>/dev/null; return 0; }
        data="$(printf '%s' "$st" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
        printf '%b' "${data//\\n/$'\n'}"; return 0
      fi; sleep 1; done
  else
    out="$(pmx "qm guest exec $id -- /bin/cat '$path' 2>/dev/null || true")"
    data="$(printf '%s\n' "$out" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
    [[ -n "$data" ]] && { printf '%s' "$data" | base64 -d 2>/dev/null; return 0; }
    data="$(printf '%s\n' "$out" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
    [[ -n "$data" ]] || return 3
    printf '%b' "${data//\\n/$'\n'}"
  fi
}

pmx_upload_iso(){
  local iso="$1" base; base="$(basename "$iso")"
  sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base" || { log "retry ISO upload $base"; sleep 2; sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base"; }
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${base}\" && exit 0; sleep 1; done; exit 0" || true
  echo "$base"
}

pmx_deploy(){
  local vmid="$1" name="$2" iso="$3" mem="$4" cores="$5" disk_gb="$6"
  local base; base="$(pmx_upload_iso "$iso")"
  pmx VMID="$vmid" VMNAME="${name}.${DOMAIN}-$vmid" FINAL_ISO="$base" VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
qm destroy "$VMID" --purge >/dev/null 2>&1 || true
qm create "$VMID" --name "$VMNAME" --memory "$MEMORY_MB" --cores "$CORES" \
  --net0 virtio,bridge=vmbr0,firewall=1 --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} --serial0 socket --ostype l26 --agent enabled=1
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0
for i in {1..10}; do qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom && break || sleep 1; done
qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}
wait_poweroff(){ pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }
boot_from_disk(){ local id="$1"; pmx "qm set $id --delete ide2; qm set $id --boot order=scsi0; qm start $id"; pmx_wait_for_state "$id" "running" 600; }

# ================= AWS helpers (from scc.sh; trimmed/merged) =================
aws_cli(){ AWS_REGION="${AWS_REGION:-us-east-1}" AWS_PROFILE="${AWS_PROFILE:-default}" aws --region "$AWS_REGION" --profile "$AWS_PROFILE" "$@"; }

resolve_debian13_ami(){ # by arch; latest official debian 13 (hvm/ebs)
  local arch="${1:-x86_64}" owners="136693071363" # Debian official
  aws_cli ec2 describe-images \
    --owners "$owners" \
    --filters "Name=name,Values=debian-13-amd64-*-*","Name=architecture,Values=${arch}" \
              "Name=virtualization-type,Values=hvm" "Name=root-device-type,Values=ebs" \
    --query 'reverse(sort_by(Images,&CreationDate))[0].ImageId' --output text
}

wait_for_instance(){ local id="$1"; aws_cli ec2 wait instance-running --instance-ids "$id"; }
get_instance_private_ip(){ local id="$1"; aws_cli ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text; }
get_instance_public_ip(){ local id="$1";  aws_cli ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text; }

wait_for_ssh(){ local host="$1" user="$2" key="${3:-}" timeout="${4:-600}" start; start=$(date +%s)
  while :; do
    if [[ -n "$key" ]]; then ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "$key" "$user@$host" "true" 2>/dev/null && return 0; else
      ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$user@$host" "true" 2>/dev/null && return 0; fi
    (( $(date +%s)-start > timeout )) && return 1
    sleep 5
  done
}

aws_ensure_network(){
  # Reuse or create VPC/Subnet/SG suitable for the cluster
  if [[ -z "${AWS_VPC_ID:-}" ]]; then
    AWS_VPC_ID="$(aws_cli ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)"
    aws_cli ec2 modify-vpc-attribute --vpc-id "$AWS_VPC_ID" --enable-dns-hostnames
    aws_cli ec2 create-tags --resources "$AWS_VPC_ID" --tags Key=Name,Value="${AWS_TAG_STACK}-vpc"
  fi
  if [[ -z "${AWS_SUBNET_ID:-}" ]]; then
    AWS_SUBNET_ID="$(aws_cli ec2 create-subnet --vpc-id "$AWS_VPC_ID" --cidr-block 10.0.1.0/24 --query 'Subnet.SubnetId' --output text)"
    aws_cli ec2 modify-subnet-attribute --subnet-id "$AWS_SUBNET_ID" --map-public-ip-on-launch
    aws_cli ec2 create-tags --resources "$AWS_SUBNET_ID" --tags Key=Name,Value="${AWS_TAG_STACK}-subnet"
  fi
  if [[ -z "${AWS_SG_ID:-}" ]]; then
    AWS_SG_ID="$(aws_cli ec2 create-security-group --vpc-id "$AWS_VPC_ID" --group-name "${AWS_TAG_STACK}-sg" --description "ucluster sg" --query 'GroupId' --output text)"
    # allow intra-subnet all, and SSH (optionally limited)
    aws_cli ec2 authorize-security-group-ingress --group-id "$AWS_SG_ID" --ip-permissions 'IpProtocol=-1,UserIdGroupPairs=[{GroupId='"\"$AWS_SG_ID\""'}]'
    local myip cidr
    myip="$(curl -fsSL https://checkip.amazonaws.com || true)"; myip="${myip//$'\n'/}"
    if [[ "${AWS_ENABLE_SSH}" == "true" ]]; then
      cidr="${AWS_SSH_CIDR:-${myip:+${myip}/32}}"
      [[ -n "$cidr" ]] && aws_cli ec2 authorize-security-group-ingress --group-id "$AWS_SG_ID" \
        --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=\"${cidr}\"}]"
    fi
    aws_cli ec2 create-tags --resources "$AWS_SG_ID" --tags Key=Name,Value="${AWS_TAG_STACK}-sg"
  fi
  export AWS_VPC_ID AWS_SUBNET_ID AWS_SG_ID
}

aws_import_key_if_needed(){
  [[ -n "$AWS_PUBLIC_KEY_PATH" && -r "$AWS_PUBLIC_KEY_PATH" ]] || return 0
  local exists; exists="$(aws_cli ec2 describe-key-pairs --key-names "$AWS_KEY_NAME" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null || true)"
  [[ "$exists" == "$AWS_KEY_NAME" ]] || aws_cli ec2 import-key-pair --key-name "$AWS_KEY_NAME" --public-key-material "fileb://$AWS_PUBLIC_KEY_PATH" >/dev/null
}

aws_bake_ami(){
  # Launch a clean Debian 13, install darksite + your first-boot bits, create AMI
  local base_ami="${AWS_BASE_AMI:-auto}" arch="${AWS_ARCH:-x86_64}"
  [[ "$base_ami" == "auto" ]] && base_ami="$(resolve_debian13_ami "$arch")"
  aws_ensure_network
  aws_import_key_if_needed

  local iid; iid="$(aws_cli ec2 run-instances \
    --image-id "$base_ami" --instance-type "$AWS_INSTANCE_TYPE" \
    --key-name "$AWS_KEY_NAME" --subnet-id "$AWS_SUBNET_ID" \
    --security-group-ids "$AWS_SG_ID" \
    --associate-public-ip-address \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${AWS_TAG_STACK}-bake},{Key=Stack,Value=${AWS_TAG_STACK}}]" \
    --query 'Instances[0].InstanceId' --output text)"

  wait_for_instance "$iid"
  local pub; pub="$(get_instance_public_ip "$iid")"
  log "Baker instance: $iid  public=$pub"

  # push minimal bootstrap (reuse your ISO darksite layout and zfs pivot optional)
  # Keep it short: install containerd, kube bits optional; you can expand as needed
  local SSHKEY="${AWS_SSH_KEY_PATH:-}"
  [[ -z "$SSHKEY" && -n "$AWS_PUBLIC_KEY_PATH" ]] && SSHKEY="${AWS_PUBLIC_KEY_PATH%.pub}"
  [[ -z "$SSHKEY" && -r "$HOME/.ssh/id_ed25519" ]] && SSHKEY="$HOME/.ssh/id_ed25519"
  wait_for_ssh "$pub" "admin" "$SSHKEY" 900 || wait_for_ssh "$pub" "debian" "$SSHKEY" 900 || true

  # Try common usernames
  local user; for user in admin adminuser debian ubuntu root; do
    if ssh -o BatchMode=yes -i "$SSHKEY" -o StrictHostKeyChecking=accept-new "$user@$pub" 'true' 2>/dev/null; then break; fi
  done

  # seed and harden
  ssh -o StrictHostKeyChecking=accept-new -i "$SSHKEY" "$user@$pub" bash -s <<'REMOTE'
set -euo pipefail
sudo bash -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl gnupg jq unzip tar \
  sudo openssh-server chrony rsyslog wireguard-tools nftables qemu-guest-agent
systemctl enable --now qemu-guest-agent chrony rsyslog
'
REMOTE

  # create AMI
  local ami_name="${AWS_AMI_NAME_PREFIX}-$(date +%Y%m%d%H%M%S)"
  local image_id; image_id="$(aws_cli ec2 create-image --instance-id "$iid" --name "$ami_name" --no-reboot --query 'ImageId' --output text)"
  log "AMI requested: $image_id ($ami_name). Waiting available…"
  aws_cli ec2 wait image-available --image-ids "$image_id"
  log "AMI available: $image_id"

  # terminate baker
  aws_cli ec2 terminate-instances --instance-ids "$iid" >/dev/null
  echo "$image_id"
}

aws_run_from_ami(){
  local ami_id="${AWS_AMI_ID:-}"
  [[ -z "$ami_id" ]] && die "Set AWS_AMI_ID (or run TARGET=aws-ami first)"
  aws_ensure_network
  aws_import_key_if_needed

  local -a ids=()
  local ip="$AWS_PRIVATE_IP_BASE"
  for ((i=0;i<${AWS_RUN_COUNT};i++)); do
    local this_ip; this_ip="$(inc_ip "$ip" "$i")"
    local iid; iid="$(aws_cli ec2 run-instances \
      --image-id "$ami_id" \
      --instance-type "$AWS_INSTANCE_TYPE" \
      --key-name "$AWS_KEY_NAME" \
      --network-interfaces "DeviceIndex=0,SubnetId=${AWS_SUBNET_ID},Groups=${AWS_SG_ID},AssociatePublicIpAddress=${AWS_ASSOC_PUBLIC_IP},PrivateIpAddress=${this_ip}" \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${AWS_TAG_STACK}-${AWS_RUN_ROLE}-${i}},{Key=Stack,Value=${AWS_TAG_STACK}},{Key=Role,Value=${AWS_RUN_ROLE}}]" \
      --query 'Instances[0].InstanceId' --output text)"
    ids+=("$iid")
    log "launched $iid  private=${this_ip}"
  done

  [[ "${#ids[@]}" -gt 0 ]] || die "no instances launched"
  aws_cli ec2 wait instance-running --instance-ids "${ids[@]}"
  log "instances running: ${ids[*]}"

  # print inventory (private & public IPs)
  for id in "${ids[@]}"; do
    pvt="$(get_instance_private_ip "$id")"; pub="$(get_instance_public_ip "$id")"
    echo "$id  private=$pvt  public=${pub:--}"
  done
}

# ================= DARKSITE repo (offline bootstrap) =================
build_dark_repo(){
  local out="$1" arch="${2:-amd64}" suite="${3:-trixie}"
  [[ -n "$out" ]] || { echo "[X] build_dark_repo: outdir required" >&2; return 2; }
  rm -rf "$out"; mkdir -p "$out"
  docker run --rm -e DEBIAN_FRONTEND=noninteractive -e SUITE="$suite" -e ARCH="$arch" \
    -e BASE_PACKAGES="openssh-server wireguard-tools nftables qemu-guest-agent zfsutils-linux zfs-dkms zfs-initramfs dkms build-essential linux-headers-amd64 linux-image-amd64 sudo ca-certificates curl wget jq unzip tar iproute2 iputils-ping ethtool tcpdump net-tools chrony rsyslog bpftrace bpfcc-tools perf-tools-unstable sysstat strace lsof" \
    -v "$out:/repo" debian:trixie bash -lc '
set -euo pipefail
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${SUITE} main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${SUITE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free non-free-firmware
EOF
echo "Acquire::Languages \"none\";" >/etc/apt/apt.conf.d/99nolangs
apt-get update -y
apt-get install -y --no-install-recommends apt apt-utils ca-certificates curl wget gnupg xz-utils dpkg-dev apt-rdepends
tmp_list=$(mktemp)
apt-rdepends $BASE_PACKAGES 2>/dev/null | awk "/^[A-Za-z0-9][A-Za-z0-9+.-]*$/{print}" | sort -u >"$tmp_list"
: > /tmp/want.lock
while read -r pkg; do cand=$(apt-cache policy "$pkg" | awk "/Candidate:/{print \$2}"); [ -n "$cand" ] && [ "$cand" != "(none)" ] && echo "$pkg=$cand" >> /tmp/want.lock || true; done <"$tmp_list"
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
}

# ================= ZFS pivot (first boot, one-shot) =================
emit_zfs_rootify(){
  local out_dir="$1"; mkdir -p "$out_dir"

  # systemd unit: run once, before our bootstrap
  cat >"$out_dir/zfs-rootify.service" <<'EOF'
[Unit]
Description=Pivot to ZFS on first boot (one-time)
DefaultDependencies=no
After=local-fs.target
Before=bootstrap.service
ConditionPathExists=/root/darksite/zfs-rootify.sh
[Service]
Type=oneshot
ExecStart=/usr/bin/env bash -lc '/root/darksite/zfs-rootify.sh'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

  # pivot script: builds rpool on /dev/sda3 and rsyncs system over
  cat >"$out_dir/zfs-rootify.sh" <<'EOSH'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG=/var/log/zfs-rootify.log
exec > >(tee -a "$LOG") 2>&1
[ -f /var/lib/zfs-rootify.done ] && exit 0

# detect primary disk and partition suffix (nvme -> p)
DISK="$(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print "/dev/"$1; exit}')"; [ -n "$DISK" ] || exit 1
case "$DISK" in /dev/nvme*|/dev/mmcblk*|/dev/loop*|/dev/md*|/dev/dm-*) p="p";; *) p="";; esac
EFI=${DISK}${p}1; ROOT=${DISK}${p}2; ZP=${DISK}${p}3

# ensure p3 exists (reserved free space from preseed); if missing, create it
if [ ! -b "$ZP" ]; then echo -e ",,\n" | sfdisk -N 3 "$DISK" >/dev/null; partprobe "$DISK" || true; udevadm settle || true; fi

# install zfs stack (prefer local media), load module even if DKMS warns about MOK
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y --no-install-recommends build-essential dkms linux-headers-$(uname -r) zfs-dkms zfsutils-linux zfs-initramfs || true
modprobe zfs || true

# create pool/datasets (mountpoint=none; root dataset mounted at /)
zpool create -f -o ashift=12 -O acltype=posixacl -O atime=off -O xattr=sa -O compression=zstd -O normalization=formD -O mountpoint=none -R /mnt/zfsroot rpool "$ZP"
zfs create -o mountpoint=none rpool/ROOT
zfs create -o mountpoint=/ rpool/ROOT/debian
for d in home var var/log var/tmp root usr-local; do zfs create -o mountpoint=/${d//usr-local/usr/local} rpool/${d//\//-}; done

# rsync the running system into ZFS root
rsync -aHAX --info=progress2 --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} / /mnt/zfsroot/
install -d -m1777 /mnt/zfsroot/tmp; install -d -m0755 /mnt/zfsroot/{proc,sys,dev,run}
mount --bind /dev  /mnt/zfsroot/dev; mount --bind /proc /mnt/zfsroot/proc; mount --bind /sys  /mnt/zfsroot/sys

# chroot: fstab, initramfs w/ zfs, grub, bootfs
chroot /mnt/zfsroot /usr/bin/env bash -lc '
blkid -o export '"$EFI"' | awk -F= "/^UUID=/{print \$2}" | xargs -I{} bash -lc "printf \"UUID=%s /boot/efi vfat umask=0077 0 1\n\" \"{}\" >> /etc/fstab"
printf "ZFS=rpool/ROOT/debian\n" > /etc/initramfs-tools/conf.d/zfs; update-initramfs -u
sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"root=ZFS=rpool\\/ROOT\\/debian\"/" /etc/default/grub || true
update-grub
apt-get install -y --no-install-recommends grub-efi-amd64 shim-signed || true
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id="debian" --recheck || true
update-grub
'
zpool set bootfs=rpool/ROOT/debian rpool
touch /var/lib/zfs-rootify.done
(sleep 2; systemctl --no-block reboot) & disown
EOSH
  chmod +x "$out_dir/zfs-rootify.sh"
}

# ================= ISO builder (preseed + darksite + pivot) =================
write_bootloader_entries(){  # BIOS + UEFI menus; ZFS-pivot default
  local cust="$1"
  local KARGS_COMMON="auto=true auto-install/enable=true priority=critical preseed/file=/cdrom/preseed.cfg locale=en_US.UTF-8 keyboard-configuration/xkb-keymap=us debconf/frontend=noninteractive"

  # BIOS (ISOLINUX)
  if [[ -f "$cust/isolinux/txt.cfg" ]]; then
    local K="/install.amd/vmlinuz" I="/install.amd/initrd.gz"
    [[ -f "$cust$K" ]] || { K="/debian-installer/amd64/linux"; I="/debian-installer/amd64/initrd.gz"; }
    if [[ -f "$cust/isolinux/isolinux.cfg" ]]; then
      sed -i -E -e 's/^(default).*$/\1 auto-zfs/' -e 's/^(timeout).*$/\1 5/' "$cust/isolinux/isolinux.cfg" || true
      grep -q '^default ' "$cust/isolinux/isolinux.cfg" || echo 'default auto-zfs' >> "$cust/isolinux/isolinux.cfg"
      grep -q '^timeout ' "$cust/isolinux/isolinux.cfg" || echo 'timeout 5'     >> "$cust/isolinux/isolinux.cfg"
    fi
    cat >"$cust/isolinux/txt.cfg" <<EOF
default auto-zfs
timeout 5
label auto-zfs
  menu label ^Install (auto, ZFS pivot)
  kernel ${K}
  append initrd=${I} ${KARGS_COMMON}
label auto-lvm
  menu label Install (auto, EXT4/LVM only — disable ZFS pivot)
  kernel ${K}
  append initrd=${I} ${KARGS_COMMON} unixbox/disable_zfs_pivot=true
EOF
  fi

  # UEFI (GRUB)
  if [[ -f "$cust/boot/grub/grub.cfg" ]]; then
    local K="/install.amd/vmlinuz" I="/install.amd/initrd.gz"
    [[ -f "$cust$K" ]] || { K="/debian-installer/amd64/linux"; I="/debian-installer/amd64/initrd.gz"; }
    cat >"$cust/boot/grub/grub.cfg" <<GRUB
set default=0
set timeout=2
menuentry "Install (auto, ZFS pivot)" { linux ${K} ${KARGS_COMMON}; initrd ${I}; }
menuentry "Install (auto, EXT4/LVM only — disable ZFS pivot)" { linux ${K} ${KARGS_COMMON} unixbox/disable_zfs_pivot=true; initrd ${I}; }
GRUB
  fi
}

mk_iso(){  # Builds custom ISO with preseed + darksite + (optional) static IP
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"
  local build="$BUILD_ROOT/$name"; local mnt="$build/mnt"; local cust="$build/custom"; local dark="$cust/darksite"
  local suite="trixie" arch="amd64"
  rm -rf "$build"; mkdir -p "$mnt" "$cust" "$dark"

  # include ZFS pivot assets
  emit_zfs_rootify "$dark"

  (
    set -euo pipefail
    trap "umount -f '$mnt' 2>/dev/null || true" EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    cp -a "$mnt/"* "$cust/"; cp -a "$mnt/.disk" "$cust/" 2>/dev/null || true
  )

  # Stage payloads
  install -m0755 "$postinstall_src" "$dark/postinstall.sh"

  # First-boot bootstrap service (safe env; no User= to avoid Permission errors)
  cat >"$dark/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (one-time)
After=local-fs.target network-online.target
Wants=network-online.target
ConditionPathExists=/root/darksite/postinstall.sh
ConditionPathIsExecutable=/root/darksite/postinstall.sh
[Service]
Type=oneshot
Environment=DEBIAN_FRONTEND=noninteractive
WorkingDirectory=/root/darksite
ExecStart=/usr/bin/env bash -lc '/root/darksite/postinstall.sh'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

  # keep APT quiet/offline-friendly
  cat >"$dark/apt-arch.conf" <<'EOF'
APT::Architectures { "amd64"; };
DPkg::Architectures { "amd64"; };
Acquire::Languages "none";
EOF

  # late.sh: copy darksite, enable bootstrap, enable zfs-pivot (unless disabled), schedule poweroff
  cat >"$dark/late.sh" <<'EOSH'
#!/bin/sh
set -eux
mkdir -p /target/root/darksite
cp -a /cdrom/darksite/. /target/root/darksite/ 2>/dev/null || true
in-target install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch || true
in-target install -D -m0755 /root/darksite/postinstall.sh /root/darksite/postinstall.sh || true
in-target install -D -m0644 /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service || true
in-target systemctl daemon-reload || true
in-target systemctl enable bootstrap.service || true
if ! grep -qw 'unixbox/disable_zfs_pivot=true' /proc/cmdline; then
  in-target install -D -m0644 /root/darksite/zfs-rootify.service /etc/systemd/system/zfs-rootify.service || true
  in-target install -D -m0755 /root/darksite/zfs-rootify.sh /root/darksite/zfs-rootify.sh || true
  in-target systemctl enable zfs-rootify.service || true
fi
in-target /bin/systemctl --no-block poweroff || true
exit 0
EOSH
  chmod +x "$dark/late.sh"

  # local dark repo (for .debs on first boot)
  mkdir -p "$dark/repo"
  build_dark_repo "$dark/repo" "$arch" "$suite"

  # ------- networking preseed block -------
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

  # No network mirrors during install; rely on CD/darksite
  local MIRRORBLOCK="d-i apt-setup/use_mirror boolean false"

  # --------------- preseed.cfg ----------------
  : > "$cust/preseed.cfg"
  cat > "$cust/preseed.cfg" <<'EOF_HEADER'
# ===== Preseed: ZFS pivot model (tiny ext4 now, ZFS rpool on first boot) =====
# Locale & keyboard
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us
EOF_HEADER
  printf '%s\n\n' "$NETBLOCK"     >> "$cust/preseed.cfg"
  printf '%s\n\n' "$MIRRORBLOCK"  >> "$cust/preseed.cfg"

  cat >> "$cust/preseed.cfg" <<'EOF_PART'
# ---- Storage policy (no LVM/swap in installer) ----
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto/no_swap boolean true
d-i partman-swapfile/no_swap boolean true

# ---- Partitioning on /dev/sda ----
d-i partman-auto/disk string /dev/sda
d-i partman-auto/method string regular

# Allow writing labels/changes without interactive confirms
d-i partman/early_command string debconf-set partman-auto/disk /dev/sda
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/confirm_write_new_label boolean true
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

# Recipe:
#   p1 EFI (vfat)
#   p2 small ext4 / (temp root)
#   p3 keep free (claimed by zfs-rootify on first boot)
d-i partman-auto/expert_recipe string                           \
  zfspivot ::                                                   \
    512 512 512 fat32                                           \
      $primary{ } $iflabel{ gpt } method{ efi } format{ }       \
    .                                                           \
    8000 8000 16000 ext4                                        \
      $primary{ } $bootable{ } method{ format } format{ }       \
      use_filesystem{ } filesystem{ ext4 } mountpoint{ / }      \
    .                                                           \
    1 1 -1 free                                                 \
      $primary{ } method{ keep }                                \
    .
d-i partman-auto/choose_recipe select zfspivot
EOF_PART

  cat >> "$cust/preseed.cfg" <<'EOF_COMMON'
# Keep CDROM enabled; add our local darksite repo entry
d-i apt-setup/disable-cdrom-entries boolean false
d-i apt-setup/services-select multiselect
d-i apt-setup/local0/repository string deb [trusted=yes] file:/cdrom/darksite/repo trixie main extra
d-i apt-setup/local0/comment string Local Darksite Repo
d-i apt-setup/local0/source boolean false

# Accounts & time
d-i passwd/root-login boolean true
d-i passwd/root-password password root
d-i passwd/root-password-again password root
d-i passwd/make-user boolean false
d-i time/zone string America/Vancouver
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true

# Minimal base (ZFS via first-boot pivot)
d-i pkgsel/run_tasksel boolean false
d-i pkgsel/upgrade select none
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/include string openssh-server wireguard-tools nftables qemu-guest-agent

# Late command (copies darksite, enables bootstrap/pivot, schedules poweroff)
d-i preseed/late_command string /bin/sh /cdrom/darksite/late.sh

# GRUB: install to /dev/sda
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/sda
d-i grub-installer/choose_bootdev select /dev/sda
d-i grub-pc/install_devices multiselect /dev/sda
d-i grub-pc/install_devices_empty boolean false

# Finish
d-i cdrom-detect/eject boolean true
d-i finish-install/reboot_in_progress note
d-i finish-install/exit-installer boolean true
d-i debian-installer/exit/poweroff boolean true
EOF_COMMON

  # Boot menus (pivot default; LVM-only opts-out)
  write_bootloader_entries "$cust"

  # Build ISO
  xorriso -as mkisofs -o "$iso_out" -r -J -joliet-long -l \
    -b isolinux/isolinux.bin -c isolinux/boot.cat \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
    -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat \
    "$cust"
}

# ----------------- Master payload -----------------
emit_postinstall_master(){
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/postinstall-master.log"; exec > >(tee -a "$LOG") 2>&1
log(){ echo "[INFO] $(date '+%F %T') - $*"; }
warn(){ echo "[WARN] $(date '+%F %T') - $*" >&2; }
err(){ echo "[ERROR] $(date '+%F %T') - $*" >&2; }

# --- dpkg hygiene to avoid broken maintainer scripts blocking install ---
dpkg_script_sanity_fix(){
  shopt -s nullglob
  for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
    [ -f "$f" ] || continue
    head -c 4 "$f" | grep -q $'^\x7fELF' && continue
    sed -i 's/\r$//' "$f" 2>/dev/null || true
    head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"
    chmod +x "$f" || true
  done
  dpkg --configure -a || true
}

# --- env (may be provided via ISO build-time vars) ---
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
GUI_PROFILE="${GUI_PROFILE:-rdp-minimal}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
ADMIN_USER="${ADMIN_USER:-todd}"
DOMAIN="${DOMAIN:-unixbox.net}"
MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"
ZFS_MOUNTPOINT="${ZFS_MOUNTPOINT:-/mnt/share}"

# Optional extras (legacy hooks)
EXTRAS_DIR="/root/darksite/extras"
CLUSTER_DEPLOY="${CLUSTER_DEPLOY:-$EXTRAS_DIR/cluster-deploy.sh}"
SCC_SCRIPT="${SCC_SCRIPT:-$EXTRAS_DIR/scc.sh}"
NEW_SCRIPT="${NEW_SCRIPT:-$EXTRAS_DIR/new.sh}"

# --- baseline packages, repos and services ---
ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  install -d -m0755 /var/lib/apt/lists; install -d -m0700 -o _apt -g root /var/lib/apt/lists/partial || true
  chmod -R a+rX /root/darksite/repo 2>/dev/null || true
  dpkg_script_sanity_fix
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo trixie main extra
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch
  install -d -m0755 /etc/apt/preferences.d
  cat > /etc/apt/preferences.d/00-darksite-pin <<'EOF'
Package: *
Pin: release o=darksite
Pin-Priority: 1001
EOF
  cat > /etc/apt/preferences.d/90-deprioritize-others <<'EOF'
Package: *
Pin: origin "*"
Pin-Priority: 1
EOF
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    build-essential dkms linux-headers-$(uname -r) \
    zfs-dkms zfsutils-linux zfs-initramfs \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    wireguard-tools nftables chrony rsyslog qemu-guest-agent nfs-common \
    bpftrace bpfcc-tools perf-tools-unstable sysstat strace lsof || true
  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

# --- users, ssh hardening, ordering with wg1 ---
ensure_users_harden(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"
  id -u "$ADMIN_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$ADMIN_USER"
  install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
  touch "/home/$ADMIN_USER/.ssh/authorized_keys"; chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
  [[ -n "$PUB" ]] && grep -qxF "$PUB" "/home/$ADMIN_USER/.ssh/authorized_keys" || { [[ -n "$PUB" ]] && printf '%s\n' "$PUB" >> "/home/$ADMIN_USER/.ssh/authorized_keys"; }
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" >"/etc/sudoers.d/90-$ADMIN_USER"; chmod 0440 "/etc/sudoers.d/90-$ADMIN_USER"

  id -u ansible >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys; chmod 600 /home/ansible/.ssh/authorized_keys

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress ${MASTER_LAN}
ListenAddress $(echo "${WG1_IP}" | cut -d/ -f1)
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

# --- WireGuard base + bring-up helpers ---
wg_prepare_conf(){
  local ifn="$1" ipcidr="$2" port="$3"
  install -d -m700 /etc/wireguard
  umask 077; [[ -f /etc/wireguard/${ifn}.key ]] || wg genkey | tee /etc/wireguard/${ifn}.key | wg pubkey >/etc/wireguard/${ifn}.pub
  cat >/etc/wireguard/${ifn}.conf <<EOF
[Interface]
Address    = ${ipcidr}
ListenPort = ${port}
PrivateKey = $(cat /etc/wireguard/${ifn}.key)
SaveConfig = true
MTU = 1420
EOF
  chmod 600 /etc/wireguard/${ifn}.conf
}
wg_try_systemd(){ systemctl daemon-reload || true; systemctl enable --now "wg-quick@${1}" || return 1; }
wg_bringup_manual(){ local ifn="$1" ipcidr="$2" port="$3"; ip link add "$ifn" type wireguard 2>/dev/null || true; ip addr add "$ipcidr" dev "$ifn" 2>/dev/null || true; wg set "$ifn" listen-port "$port" private-key /etc/wireguard/${ifn}.key || true; ip link set "$ifn" mtu 1420 up || true; }
wg_up_all(){ wg_prepare_conf wg0 "$WG0_IP" "$WG0_PORT"; wg_try_systemd wg0 || wg_bringup_manual wg0 "$WG0_IP" "$WG0_PORT"; wg_prepare_conf wg1 "$WG1_IP" "$WG1_PORT"; wg_try_systemd wg1 || wg_bringup_manual wg1 "$WG1_IP" "$WG1_PORT"; wg_prepare_conf wg2 "$WG2_IP" "$WG2_PORT"; wg_try_systemd wg2 || wg_bringup_manual wg2 "$WG2_IP" "$WG2_PORT"; wg_prepare_conf wg3 "$WG3_IP" "$WG3_PORT"; wg_try_systemd wg3 || wg_bringup_manual wg3 "$WG3_IP" "$WG3_PORT"; }

# --- nftables basic policy (open SSH, WG ports, RDP; drop rest inbound) ---
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
    iifname { "wg0","wg1","wg2","wg3" } accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

# --- publish hub metadata (ports, pubkeys, enrollment flag) ---
hub_seed(){
  install -d -m0755 /srv/wg
  local _wg0pub _wg1pub _wg2pub _wg3pub _anspub _adminpub
  _wg0pub="$(cat /etc/wireguard/wg0.pub 2>/dev/null || true)"
  _wg1pub="$(cat /etc/wireguard/wg1.pub 2>/dev/null || true)"
  _wg2pub="$(cat /etc/wireguard/wg2.pub 2>/dev/null || true)"
  _wg3pub="$(cat /etc/wireguard/wg3.pub 2>/dev/null || true)"
  _anspub="$(cat /home/ansible/.ssh/id_ed25519.pub 2>/dev/null || true)"
  _adminpub="$( [ -n "${ADMIN_USER:-}" ] && cat "/home/${ADMIN_USER}/.ssh/authorized_keys" 2>/dev/null | head -n1 || true )"
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
WG0_PUB="${_wg0pub}"
WG1_PUB="${_wg1pub}"
WG2_PUB="${_wg2pub}"
WG3_PUB="${_wg3pub}"
ANSIBLE_PUB="${_anspub}"
ADMIN_PUB="${_adminpub}"
EOF
  chmod 0644 /srv/wg/hub.env
  : >/srv/wg/ENROLL_ENABLED
}

# --- CLI helpers (add peer, toggle enrollment, register nodes for prom/ansible) ---
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

# --- Prometheus + Grafana listening on wg1 IP ---
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

# --- Salt master + optional Ansible/Semaphore on wg1 ---
control_stack(){
  local CONTROL_IF="wg1"; local CONTROL_IP; CONTROL_IP="$(echo "${WG1_IP}" | cut -d/ -f1)"
  apt-get install -y --no-install-recommends salt-master salt-api salt-common || true
  install -d -m0755 /etc/salt/master.d
  cat >/etc/salt/master.d/network.conf <<EOF
interface: ${CONTROL_IP}
ipv6: False
publish_port: 4505
ret_port: 4506
EOF
  cat >/etc/salt/master.d/api.conf <<EOF
rest_cherrypy:
  host: ${CONTROL_IP}
  port: 8000
  disable_ssl: True
EOF
  install -d -m0755 /etc/systemd/system/salt-master.service.d
  cat >/etc/systemd/system/salt-master.service.d/override.conf <<EOF
[Unit]
After=wg-quick@${CONTROL_IF}.service network-online.target
Wants=wg-quick@${CONTROL_IF}.service network-online.target
EOF
  install -d -m0755 /etc/systemd/system/salt-api.service.d
  cat >/etc/systemd/system/salt-api.service.d/override.conf <<EOF
[Unit]
After=wg-quick@${CONTROL_IF}.service network-online.target
Wants=wg-quick@${CONTROL_IF}.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now salt-master salt-api || true

  if [ "${INSTALL_ANSIBLE}" = "yes" ]; then apt-get install -y ansible || true; fi
  if [ "${INSTALL_SEMAPHORE}" != "no" ]; then
    install -d -m755 /etc/semaphore
    if curl -fsSL -o /usr/local/bin/semaphore https://github.com/ansible-semaphore/semaphore/releases/latest/download/semaphore_linux_amd64 2>/dev/null; then
      chmod +x /usr/local/bin/semaphore
      cat >/etc/systemd/system/semaphore.service <<EOF
[Unit]
Description=Ansible Semaphore
After=wg-quick@${CONTROL_IF}.service network-online.target
Wants=wg-quick@${CONTROL_IF}.service
[Service]
ExecStart=/usr/local/bin/semaphore server --listen ${CONTROL_IP}:3000
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now semaphore || true
    else
      warn "Semaphore binary not fetched; install later."
    fi
  fi
}

# --- minimal GUI (optional) ---
desktop_gui() {
  case "${GUI_PROFILE}" in
    rdp-minimal)
      apt-get install -y --no-install-recommends xorg xrdp xorgxrdp openbox xterm firefox-esr || true
      local INI="/etc/xrdp/xrdp.ini"
      if [ -f "$INI" ]; then
        sed -i 's/^[[:space:]]*port[[:space:]]*=.*/; &/' "$INI" || true
        if grep -qE '^[[:space:]]*address=' "$INI"; then
          sed -i "s|^[[:space:]]*address=.*|address=${MASTER_LAN}|" "$INI"
        else
          sed -i "1i address=${MASTER_LAN}" "$INI"
        fi
        if grep -qE '^[[:space:]]*;port=' "$INI"; then
          sed -i 's|^[[:space:]]*;port=.*|port=3389|' "$INI"
        elif grep -qE '^[[:space:]]*port=' "$INI"; then
          sed -i 's|^[[:space:]]*port=.*|port=3389|' "$INI"
        else
          sed -i '1i port=3389' "$INI"
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

# --- NFS share on wg3 subnet ---
storage_share_setup(){
  local share="${ZFS_MOUNTPOINT:-/mnt/share}"
  apt-get install -y --no-install-recommends nfs-kernel-server >/dev/null 2>&1 || true
  install -d -m0755 "$share"
  grep -q "^[[:space:]]*${share}[[:space:]]" /etc/exports 2>/dev/null || \
    echo "${share} 10.80.0.0/16(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
  echo 'RPCMOUNTDOPTS="--port 20048"' >/etc/default/nfs-kernel-server
  echo 'STATDOPTS="--port 32765 --outgoing-port 32766"' >/etc/default/nfs-common
  install -d -m0755 /etc/systemd/system/nfs-server.service.d
  cat >/etc/systemd/system/nfs-server.service.d/override.conf <<'EOF'
[Service]
Environment=RPCMOUNTDOPTS=--port=20048
EOF
  systemctl daemon-reload || true
  exportfs -ra || true
  systemctl enable --now nfs-server || true
  log "NFS share ${share} exported on wg3."
}

# --- optional legacy extras (cluster-deploy/scc/new) ---
run_legacy_extras(){
  if [[ -x "$CLUSTER_DEPLOY" ]]; then
    log "Running legacy cluster-deploy: $CLUSTER_DEPLOY"
    "$CLUSTER_DEPLOY" || warn "cluster-deploy exited non-zero"
  fi
  if [[ -x "$SCC_SCRIPT" ]]; then
    log "Running legacy scc: $SCC_SCRIPT"
    "$SCC_SCRIPT" || warn "scc exited non-zero"
  fi
  if [[ -x "$NEW_SCRIPT" ]]; then
    log "Running legacy new: $NEW_SCRIPT"
    "$NEW_SCRIPT" || warn "new.sh exited non-zero"
  fi
}

# --- main entry for master hub ---
main_master(){
  log "BEGIN postinstall (master hub)"
  ensure_base
  ensure_users_harden

  # optional upstream repos for Salt and Grafana
  install -d -m0755 /etc/apt/keyrings
  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
  curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.sources -o /etc/apt/sources.list.d/salt.sources || true
  sed -i 's#/etc/apt/keyrings/salt-archive-keyring\.pgp#/etc/apt/keyrings/salt-archive-keyring.pgp#' /etc/apt/sources.list.d/salt.sources || true
  curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg || true
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
  storage_share_setup
  telemetry_stack
  control_stack
  desktop_gui
  run_legacy_extras

  # misc hardening
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

# ----------------- Minion payload (runs inside guest) -----------------
emit_postinstall_minion(){
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/minion-postinstall.log"; exec > >(tee -a "$LOG") 2>&1
log(){ echo "[INFO] $(date '+%F %T') - $*"; }
warn(){ echo "[WARN] $(date '+%F %T') - $*"; }
err(){ echo "[ERROR] $(date '+%F %T') - $*" >&2; }

# --- dpkg hygiene to avoid maintainer-script weirdness ---
dpkg_script_sanity_fix() {
  set +u
  shopt -s nullglob
  for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
    [ -f "$f" ] || continue
    head -c 4 "$f" | grep -q $'^\x7fELF' && continue
    sed -i 's/\r$//' "$f" 2>/dev/null || true
    head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"
    chmod +x "$f" || true
  done
  dpkg --configure -a || true
  set -u
}

# --- env expected via wrapper/seed ---
ADMIN_USER="${ADMIN_USER:-todd}"
MY_GROUP="${MY_GROUP:-prom}"

WG0_WANTED="${WG0_WANTED:-10.77.0.2/32}"
WG1_WANTED="${WG1_WANTED:-10.78.0.2/32}"
WG2_WANTED="${WG2_WANTED:-10.79.0.2/32}"
WG3_WANTED="${WG3_WANTED:-10.80.0.2/32}"

# Kubernetes / Cilium knobs (inherited from ISO/global env)
K8S_ENABLE="${K8S_ENABLE:-yes}"
K8S_VERSION="${K8S_VERSION:-1.29}"
K8S_POD_CIDR="${K8S_POD_CIDR:-10.244.0.0/16}"
K8S_SVC_CIDR="${K8S_SVC_CIDR:-10.96.0.0/12}"
K8S_API_ADVERTISE_IFACE="${K8S_API_ADVERTISE_IFACE:-wg2}"
K8S_NODE_IP_IFACE="${K8S_NODE_IP_IFACE:-wg2}"
K8S_RUNTIME="${K8S_RUNTIME:-containerd}"

CILIUM_VERSION="${CILIUM_VERSION:-1.14.6}"
CILIUM_ENCRYPTION="${CILIUM_ENCRYPTION:-disabled}"
CILIUM_WG_INTERFACE="${CILIUM_WG_INTERFACE:-wg2}"
CILIUM_KPR="${CILIUM_KPR:-strict}"
CILIUM_TUNNEL_MODE="${CILIUM_TUNNEL_MODE:-disabled}"
CILIUM_AUTO_DIRECT_ROUTES="${CILIUM_AUTO_DIRECT_ROUTES:-true}"
CILIUM_BPF_MASQ="${CILIUM_BPF_MASQ:-true}"

# MetalLB
METALLB_POOL_CIDRS="${METALLB_POOL_CIDRS:-10.100.10.111-10.100.10.130}"
METALLB_NAMESPACE="${METALLB_NAMESPACE:-metallb-system}"

# Optional extras (legacy hooks)
EXTRAS_DIR="/root/darksite/extras"
CLUSTER_DEPLOY="${CLUSTER_DEPLOY:-$EXTRAS_DIR/cluster-deploy.sh}"
SCC_SCRIPT="${SCC_SCRIPT:-$EXTRAS_DIR/scc.sh}"
NEW_SCRIPT="${NEW_SCRIPT:-$EXTRAS_DIR/new.sh}"

# Hub seed locations (wrapper drops hub.env in one of these)
HUB_ENV_CANDIDATES=(/root/cluster-seed/hub.env /srv/wg/hub.env /root/darksite/cluster-seed/hub.env /root/darksite/hub.env)

# --- base OS bits ---
ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  install -d -m0755 /var/lib/apt/lists; install -d -m0700 -o _apt -g root /var/lib/apt/lists/partial || true
  chmod -R a+rX /root/darksite/repo 2>/dev/null || true
  dpkg_script_sanity_fix
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo trixie main extra
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free non-free-firmware
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch
  install -d -m0755 /etc/apt/preferences.d
  cat > /etc/apt/preferences.d/00-darksite-pin <<'EOF'
Package: *
Pin: release o=darksite
Pin-Priority: 1001
EOF
  cat > /etc/apt/preferences.d/90-deprioritize-others <<'EOF'
Package: *
Pin: origin "*"
Pin-Priority: 1
EOF
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    wireguard-tools nftables chrony rsyslog qemu-guest-agent \
    build-essential dkms linux-headers-$(uname -r) \
    zfsutils-linux zfs-dkms zfs-initramfs nfs-common \
    bpftrace bpfcc-tools perf-tools-unstable sysstat strace lsof || true
  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

# --- local users (admin + ansible) ---
ensure_admin_user(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"; local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"
  id -u "${ADMIN_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${ADMIN_USER}"
  install -d -m700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  touch "/home/${ADMIN_USER}/.ssh/authorized_keys"
  [[ -n "$PUB" ]] && ! grep -qxF "$PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys" && echo "$PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys" || true
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
}
ensure_ansible_user(){
  id -u ansible >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -n "${ANSIBLE_PUB:-}" ]] && { printf '%s\n' "$ANSIBLE_PUB" >> /home/ansible/.ssh/authorized_keys; sort -u -o /home/ansible/.ssh/authorized_keys /home/ansible/.ssh/authorized_keys; chown -R ansible:ansible /home/ansible/.ssh; chmod 600 /home/ansible/.ssh/authorized_keys; }
}

# --- consume hub.env into shell vars (safe eval) ---
read_hub(){
  local f; for f in "${HUB_ENV_CANDIDATES[@]}"; do [[ -r "$f" ]] && { HUB_ENV_FILE="$f"; break; }; done
  [[ -n "${HUB_ENV_FILE:-}" ]] || { err "missing hub.env"; return 1; }
  eval "$(
    awk -F= '
      /^[[:space:]]*#/ {next}
      /^[A-Za-z0-9_]+=/ {key=$1; $1=""; sub(/^=/,""); val=$0; gsub(/^[ \t]+|[ \t]+$/,"",val); gsub(/"/,"\\\"",val); print key "=\"" val "\""}' "$HUB_ENV_FILE"
  )"
  : "${HUB_LAN:?missing HUB_LAN}"
  : "${WG0_PORT:?missing WG0_PORT}"
  : "${WG_ALLOWED_CIDR:?missing WG_ALLOWED_CIDR}"
}

# --- configure wg0 (hub) and wg1..wg3 local addresses ---
wg_setup_all(){
  install -d -m700 /etc/wireguard; umask 077
  for IFN in wg0 wg1 wg2 wg3; do [[ -f /etc/wireguard/${IFN}.key ]] || wg genkey | tee /etc/wireguard/${IFN}.key | wg pubkey >/etc/wireguard/${IFN}.pub; done
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${WG0_WANTED}
PrivateKey = $(cat /etc/wireguard/wg0.key)
ListenPort = 0
DNS        = 1.1.1.1
MTU        = 1420
SaveConfig = true
[Peer]
PublicKey  = ${WG0_PUB}
Endpoint   = ${HUB_LAN}:${WG0_PORT}
AllowedIPs = ${WG_ALLOWED_CIDR}
PersistentKeepalive = 25
EOF
  for n in 1 2 3; do
    cat >/etc/wireguard/wg${n}.conf <<EOF
[Interface]
Address    = $(eval echo \${WG${n}_WANTED})
PrivateKey = $(cat /etc/wireguard/wg${n}.key)
ListenPort = 0
MTU        = 1420
SaveConfig = true
EOF
  done
  chmod 600 /etc/wireguard/*.conf
  install -d -m755 /etc/systemd/system/wg-quick@wg0.service.d
  cat >/etc/systemd/system/wg-quick@wg0.service.d/override.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF
  for ifn in wg1 wg2 wg3; do
    install -d -m755 /etc/systemd/system/wg-quick@${ifn}.service.d
    cat >/etc/systemd/system/wg-quick@${ifn}.service.d/override.conf <<EOF
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  done
  systemctl daemon-reload || true
  systemctl enable --now wg-quick@wg0 || true
  for ifn in wg1 wg2 wg3; do systemctl enable --now "wg-quick@${ifn}" || true; done
}

# ---------------------- KUBERNETES ----------------------

k8s_sysctl_prereqs(){
  swapoff -a || true
  sed -ri 's/^[#\s]*([a-z]+swap).*/# \1 disabled by bootstrap/' /etc/fstab || true
  modprobe overlay || true
  modprobe br_netfilter || true
  cat >/etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
EOF
  cat >/etc/sysctl.d/99-k8s.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
  sysctl --system || true
}

install_containerd(){
  apt-get install -y --no-install-recommends containerd || true
  mkdir -p /etc/containerd
  containerd config default >/etc/containerd/config.toml
  # Systemd cgroup driver for kubelet compatibility
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml || true
  systemctl enable --now containerd || true
}

install_kube_binaries(){
  local ver="${K8S_VERSION}"
  # prefer distro if available, otherwise upstream packages
  if ! command -v kubeadm >/dev/null 2>&1; then
    # Upstream repo (kubernetes-apt)
    install -d -m0755 /etc/apt/keyrings
    curl -fsSL https://pkgs.k8s.io/core:/stable:/v${ver}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    cat >/etc/apt/sources.list.d/kubernetes.list <<EOF
deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${ver}/deb/ / 
EOF
    apt-get update -y || true
    apt-get install -y kubelet kubeadm kubectl || true
    apt-mark hold kubelet kubeadm kubectl || true
  fi
}

kubeadm_init_if_needed(){
  [[ "$MY_GROUP" == "k8s" ]] || return 0
  [[ "${K8S_ENABLE}" == "yes" ]] || { log "K8s disabled via K8S_ENABLE=no"; return 0; }
  if kubectl cluster-info >/dev/null 2>&1; then
    log "K8s already initialized; skipping init."
    return 0
  fi

  k8s_sysctl_prereqs
  install_containerd
  install_kube_binaries

  local adv_ip node_ip
  adv_ip="$(ip -4 addr show dev "${K8S_API_ADVERTISE_IFACE}" | awk '/inet /{print $2}' | cut -d/ -f1)"
  node_ip="$(ip -4 addr show dev "${K8S_NODE_IP_IFACE}" | awk '/inet /{print $2}' | cut -d/ -f1)"
  [[ -n "$adv_ip" && -n "$node_ip" ]] || { err "Failed to determine advertise or node IP on ${K8S_API_ADVERTISE_IFACE}/${K8S_NODE_IP_IFACE}"; return 1; }

  cat >/root/kubeadm-config.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: v${K8S_VERSION}
clusterName: unixbox
networking:
  podSubnet: "${K8S_POD_CIDR}"
  serviceSubnet: "${K8S_SVC_CIDR}"
controlPlaneEndpoint: "${adv_ip}:6443"
apiServer:
  certSANs:
  - "${adv_ip}"
controllerManager: {}
scheduler: {}
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: "${adv_ip}"
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  kubeletExtraArgs:
    node-ip: "${node_ip}"
    cgroup-driver: "systemd"
EOF

  log "Running kubeadm init..."
  kubeadm init --config=/root/kubeadm-config.yaml --upload-certs || {
    err "kubeadm init failed"; return 1;
  }

  mkdir -p /root/.kube /home/${ADMIN_USER}/.kube /home/ansible/.kube
  cp -f /etc/kubernetes/admin.conf /root/.kube/config
  install -o "${ADMIN_USER}" -g "${ADMIN_USER}" -m 0600 /etc/kubernetes/admin.conf "/home/${ADMIN_USER}/.kube/config"
  install -o ansible -g ansible -m 0600 /etc/kubernetes/admin.conf "/home/ansible/.kube/config"

  # Single-node control-plane: allow workloads
  kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true
  kubectl taint nodes --all node-role.kubernetes.io/master- || true
}

install_cilium(){
  [[ "$MY_GROUP" == "k8s" ]] || return 0
  [[ "${K8S_ENABLE}" == "yes" ]] || return 0
  [[ -x /usr/local/bin/cilium ]] || {
    curl -fsSL -o /usr/local/bin/cilium https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64
    chmod +x /usr/local/bin/cilium
  }
  # Ensure kubeconfig
  export KUBECONFIG=/etc/kubernetes/admin.conf

  # Install Cilium with native routing and optional encryption settings
  local enc=""
  if [[ "${CILIUM_ENCRYPTION}" == "wireguard" ]]; then
    enc="--set encryption.enabled=true --set encryption.type=wireguard --set encryption.nodeEncryption=true --set encryption.interface=${CILIUM_WG_INTERFACE}"
  elif [[ "${CILIUM_ENCRYPTION}" == "ipsec" ]]; then
    enc="--set encryption.enabled=true --set encryption.type=ipsec"
  fi

  cilium install \
    --version "v${CILIUM_VERSION}" \
    --set cluster.name=unixbox \
    --set kubeProxyReplacement=${CILIUM_KPR} \
    --set tunnel=${CILIUM_TUNNEL_MODE} \
    --set autoDirectNodeRoutes=${CILIUM_AUTO_DIRECT_ROUTES} \
    --set bpf.masquerade=${CILIUM_BPF_MASQ} \
    --set ipam.mode=kubernetes ${enc} || warn "cilium install reported an error"

  cilium status --wait || warn "cilium not ready yet"
}

install_metallb(){
  [[ "$MY_GROUP" == "k8s" ]] || return 0
  [[ "${K8S_ENABLE}" == "yes" ]] || return 0
  export KUBECONFIG=/etc/kubernetes/admin.conf

  kubectl get ns "${METALLB_NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${METALLB_NAMESPACE}"
  # Install CRDs & controller via upstream manifests
  if ! kubectl -n "${METALLB_NAMESPACE}" get deploy controller >/dev/null 2>&1; then
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml
  fi

  # Wait for webhook/controller
  kubectl -n "${METALLB_NAMESPACE}" rollout status deploy/controller --timeout=180s || true
  kubectl -n "${METALLB_NAMESPACE}" rollout status ds/speaker     --timeout=180s || true

  # Configure address pool + L2Advertisement
  cat >/root/metallb-pool.yaml <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: pool1
  namespace: ${METALLB_NAMESPACE}
spec:
  addresses:
  - ${METALLB_POOL_CIDRS}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: l2adv1
  namespace: ${METALLB_NAMESPACE}
spec:
  ipAddressPools:
  - pool1
EOF
  kubectl apply -f /root/metallb-pool.yaml || warn "MetalLB pool apply failed"
}

# --- optional legacy extras (cluster-deploy/scc/new) ---
run_legacy_extras(){
  if [[ -x "$CLUSTER_DEPLOY" ]]; then
    log "Running legacy cluster-deploy: $CLUSTER_DEPLOY"
    "$CLUSTER_DEPLOY" || warn "cluster-deploy exited non-zero"
  fi
  if [[ -x "$SCC_SCRIPT" ]]; then
    log "Running legacy scc: $SCC_SCRIPT"
    "$SCC_SCRIPT" || warn "scc exited non-zero"
  fi
  if [[ -x "$NEW_SCRIPT" ]]; then
    log "Running legacy new: $NEW_SCRIPT"
    "$NEW_SCRIPT" || warn "new.sh exited non-zero"
  fi
}

main(){
  log "minion bootstrap start (group=${MY_GROUP})"
  ensure_base
  read_hub
  ensure_admin_user
  ensure_ansible_user
  wg_setup_all

  if [[ "$MY_GROUP" == "k8s" && "${K8S_ENABLE}" == "yes" ]]; then
    kubeadm_init_if_needed
    install_cilium
    install_metallb
  fi

  run_legacy_extras

  log "minion bootstrap done; powering off in 2s"
  (sleep 2; systemctl --no-block poweroff) & disown
}
main
EOS
}

# ----------------- Minion wrapper (runs during ISO postinstall) -----------------
emit_minion_wrapper(){
  local out="$1" group="$2" wg0="$3" wg1="$4" wg2="$5" wg3="$6"
  local hub_src="$BUILD_ROOT/hub/hub.env"; [[ -s "$hub_src" ]] || { err "emit_minion_wrapper: missing hub.env at $hub_src"; return 1; }

  cat >"$out" <<'EOSH'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/minion-wrapper.log"; exec > >(tee -a "$LOG") 2>&1
trap 'echo "[WRAP] failed: ${BASH_COMMAND@Q}  (line ${LINENO})" >&2' ERR
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
cat >/etc/environment.d/99-provision.conf <<EOF
ADMIN_USER=$ADMIN_USER
MY_GROUP=${group}
WG0_WANTED=${wg0}
WG1_WANTED=${wg1}
WG2_WANTED=${wg2}
WG3_WANTED=${wg3}
K8S_ENABLE=${K8S_ENABLE}
K8S_VERSION=${K8S_VERSION}
K8S_POD_CIDR=${K8S_POD_CIDR}
K8S_SVC_CIDR=${K8S_SVC_CIDR}
K8S_API_ADVERTISE_IFACE=${K8S_API_ADVERTISE_IFACE}
K8S_NODE_IP_IFACE=${K8S_NODE_IP_IFACE}
K8S_RUNTIME=${K8S_RUNTIME}
CILIUM_VERSION=${CILIUM_VERSION}
CILIUM_ENCRYPTION=${CILIUM_ENCRYPTION}
CILIUM_WG_INTERFACE=${CILIUM_WG_INTERFACE}
CILIUM_KPR=${CILIUM_KPR}
CILIUM_TUNNEL_MODE=${CILIUM_TUNNEL_MODE}
CILIUM_AUTO_DIRECT_ROUTES=${CILIUM_AUTO_DIRECT_ROUTES}
CILIUM_BPF_MASQ=${CILIUM_BPF_MASQ}
METALLB_POOL_CIDRS=${METALLB_POOL_CIDRS}
METALLB_NAMESPACE=${METALLB_NAMESPACE}
EOF
chmod 0644 /etc/environment.d/99-provision.conf
EOSH

  # Drop the minion postinstall payload
  cat >>"$out" <<'EOSH'
install -d -m0755 /root/darksite
cat >/root/darksite/postinstall-minion.sh <<'EOMINION'
EOSH
  local tmp; tmp="$(mktemp)"; emit_postinstall_minion "$tmp"; cat "$tmp" >>"$out"; rm -f "$tmp"
  cat >>"$out" <<'EOSH'
EOMINION
perl -0777 -pe 's/\r\n/\n/g; s/\r/\n/g' -i /root/darksite/postinstall-minion.sh
sed -i '1s|.*|#!/usr/bin/env bash|' /root/darksite/postinstall-minion.sh
chmod +x /root/darksite/postinstall-minion.sh
/usr/bin/env bash /root/darksite/postinstall-minion.sh
EOSH
  chmod +x "$out"
}

# ----------------- Proxmox: ensure master enrollment seed -----------------
ensure_master_enrollment_seed(){
  # Ensure the master VM exports a minimal /srv/wg/hub.env and enables enrollment
  local vmid="$1"
  pmx_guest_exec "$vmid" /bin/bash -lc "$(cat <<'EOS'
set -euo pipefail
. /etc/environment.d/99-provision.conf 2>/dev/null || true
mkdir -p /srv/wg
if [ ! -s /srv/wg/hub.env ]; then
  cat > /srv/wg/hub.env <<'EOF'
WG0_IP=${WG0_IP:-10.77.0.1/16}
WG1_IP=${WG1_IP:-10.78.0.1/16}
WG2_IP=${WG2_IP:-10.79.0.1/16}
WG3_IP=${WG3_IP:-10.80.0.1/16}
WG0_PORT=${WG0_PORT:-51820}
WG1_PORT=${WG1_PORT:-51821}
WG2_PORT=${WG2_PORT:-51822}
WG3_PORT=${WG3_PORT:-51823}
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}
HUB_LAN=${MASTER_LAN:-10.100.10.224}
WG0_PUB=
WG1_PUB=
WG2_PUB=
WG3_PUB=
EOF
  chmod 0644 /srv/wg/hub.env
fi
: > /srv/wg/ENROLL_ENABLED
EOS
)"
}

# ----------------- Build all role ISOs and harvest hub.env from master -----------------
build_all_isos(){
  log "[*] Building all ISOs into $BUILD_ROOT"
  mkdir -p "$BUILD_ROOT/hub" "$BUILD_ROOT/extras"

  # Stage any uploaded legacy scripts to the ISO payload extras dir (if present on host)
  for f in /mnt/data/cluster-deploy.sh /mnt/data/scc.sh /mnt/data/new.sh; do
    [[ -s "$f" ]] && cp -f "$f" "$BUILD_ROOT/extras/$(basename "$f")" || true
  done

  # 1) Master payload + ISO
  local master_payload master_iso
  master_payload="$(mktemp)"
  emit_postinstall_master "$master_payload"
  # Append logic to copy extras into guest
  {
    echo
    echo "# Extras (legacy) will be copied by ISO builder"
  } >>"$master_payload"

  master_iso="$BUILD_ROOT/master.iso"
  mk_iso "master" "$master_payload" "$master_iso" "$MASTER_LAN"
  log "[OK] master ISO: $master_iso"

  # 2) Temporarily boot the master to generate keys/hub.env, then capture it
  pmx_deploy "$MASTER_ID" "$MASTER_NAME" "$master_iso" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"
  wait_poweroff "$MASTER_ID" 1800
  # first boot from disk (postinstall triggers and reboots once more due to ZFS pivot)
  pmx "qm set $MASTER_ID --boot order=scsi0; qm start $MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  # remove the ISO and boot steady-state
  pmx "qm set $MASTER_ID --delete ide2; qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900
  ensure_master_enrollment_seed "$MASTER_ID"

  log "Fetching hub.env from master via QGA…"
  local DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "[OK] captured hub.env → $DEST"
  else
    err "Failed to retrieve hub.env via QGA"; exit 1
  fi

  # 3) Build minion role ISOs using the captured hub.env
  local pld iso
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "prom"    "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3"; iso="$BUILD_ROOT/prom.iso";    mk_iso "$PROM_NAME"    "$pld" "$iso" "$PROM_IP"; log "[OK] prom ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "graf"    "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3"; iso="$BUILD_ROOT/graf.iso";    mk_iso "$GRAF_NAME"    "$pld" "$iso" "$GRAF_IP"; log "[OK] graf ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "k8s"     "$K8S_WG0"  "$K8S_WG1"  "$K8S_WG2"  "$K8S_WG3";  iso="$BUILD_ROOT/k8s.iso";     mk_iso "$K8S_NAME"     "$pld" "$iso" "$K8S_IP";  log "[OK] k8s ISO:     $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "storage" "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3"; iso="$BUILD_ROOT/storage.iso"; mk_iso "$STOR_NAME"     "$pld" "$iso" "$STOR_IP"; log "[OK] storage ISO: $iso"
}

# ----------------- Proxmox fanout: deploy minions and finalize -----------------
proxmox_cluster(){
  # Build artifacts and prepare master (already power-cycled inside build_all_isos)
  build_all_isos

  # Deploy minions (each will: install, poweroff, we then switch to disk and let it complete)
  pmx_deploy "$PROM_ID" "$PROM_NAME" "$BUILD_ROOT/prom.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$PROM_ID" 2400; pmx "qm set $PROM_ID --boot order=scsi0; qm start $PROM_ID"; wait_poweroff "$PROM_ID" 2400; pmx "qm set $PROM_ID --delete ide2; qm start $PROM_ID"; pmx_wait_for_state "$PROM_ID" "running" 600

  pmx_deploy "$GRAF_ID" "$GRAF_NAME" "$BUILD_ROOT/graf.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$GRAF_ID" 2400; pmx "qm set $GRAF_ID --boot order=scsi0; qm start $GRAF_ID"; wait_poweroff "$GRAF_ID" 2400; pmx "qm set $GRAF_ID --delete ide2; qm start $GRAF_ID"; pmx_wait_for_state "$GRAF_ID" "running" 600

  pmx_deploy "$K8S_ID"  "$K8S_NAME"  "$BUILD_ROOT/k8s.iso"  "$K8S_MEM"    "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$K8S_ID"  2400; pmx "qm set $K8S_ID --boot order=scsi0; qm start $K8S_ID";  wait_poweroff "$K8S_ID"  2400; pmx "qm set $K8S_ID --delete ide2; qm start $K8S_ID";  pmx_wait_for_state "$K8S_ID"  "running" 600

  pmx_deploy "$STOR_ID" "$STOR_NAME" "$BUILD_ROOT/storage.iso" "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"
  wait_poweroff "$STOR_ID" 2400; pmx "qm set $STOR_ID --boot order=scsi0; qm start $STOR_ID"; wait_poweroff "$STOR_ID" 2400; pmx "qm set $STOR_ID --delete ide2; qm start $STOR_ID"; pmx_wait_for_state "$STOR_ID" "running" 600

  # Close enrollment on master so stray peers can't self-add
  log "Closing WireGuard enrollment on master…"
  pmx_guest_exec "$MASTER_ID" /bin/bash -lc "rm -f /srv/wg/ENROLL_ENABLED" || true

  log "Done. Master + minions deployed (ZFS pivot handled on first boot)."
}

# ----------------- Optional: Packer scaffold -----------------
emit_packer_scaffold(){
  mkdir -p "$PACKER_OUT"
  cat >"$PACKER_OUT/README.txt" <<'EOF'
Starter scaffold for building images with Packer.
Example debian-qemu.pkr.hcl included in comments below.

packer {
  required_plugins {
    qemu = { source = "github.com/hashicorp/qemu", version = ">= 1.1.0" }
  }
}
variable "iso_path" { type = string }
variable "vm_name"  { type = string  default = "debian-guest" }
source "qemu" "debian" {
  iso_url          = var.iso_path
  output_directory = "output-${var.vm_name}"
  headless         = true
  accelerator      = "kvm"
  cpus             = 2
  memory           = 2048
  disk_size        = "20G"
  ssh_username     = "root"
  ssh_password     = "root"
  ssh_timeout      = "30m"
  boot_wait        = "5s"
}
build {
  name    = var.vm_name
  sources = ["source.qemu.debian"]
  provisioner "shell" { inline = ["echo 'Hello from Packer'"] }
}
EOF
  log "[OK] packer scaffold at: $PACKER_OUT"
}

# ----------------- Optional: Firecracker quick-run scaffolding -----------------
_firecracker_require(){
  command -v firecracker >/dev/null 2>&1 || die "firecracker binary not found"
  [[ -c /dev/kvm ]] || die "/dev/kvm not present"
  command -v ip >/dev/null 2>&1 || die "iproute2 required"
}
emit_firecracker_scaffold(){
  install -d "$FIRECRACKER_OUT"
  cat >"$FIRECRACKER_OUT/extract-kernel-initrd.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
RAW_IMG="${1:-}"; OUT_DIR="${2:-.}"
[[ -n "$RAW_IMG" && -s "$RAW_IMG" ]] || { echo "usage: $0 <rootfs.raw> [outdir]" >&2; exit 2; }
mkdir -p "$OUT_DIR"
command -v guestmount >/dev/null || { echo "[X] apt install libguestfs-tools"; exit 1; }
mnt="$(mktemp -d)"; trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' EXIT
guestmount -a "$RAW_IMG" -i "$mnt"
cp -Lf "$mnt"/boot/vmlinuz* "$OUT_DIR/kernel"
cp -Lf "$mnt"/boot/initrd*  "$OUT_DIR/initrd"
echo "[OK] kernel/initrd -> $OUT_DIR"
EOF
  chmod +x "$FIRECRACKER_OUT/extract-kernel-initrd.sh"
  log "[OK] Firecracker scaffold in $FIRECRACKER_OUT"
}
_fc_make_nat_bridge(){
  local br="fcbr0" cidr="172.29.0.1/24"
  ip link show "$br" >/dev/null 2>&1 || { ip link add "$br" type bridge; ip addr add "$cidr" dev "$br"; ip link set "$br" up; }
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
  # basic NAT (host → guest Internet)
  if ! nft list ruleset | grep -q 'fcbr0'; then
    nft -f - <<'N'
flush ruleset
table inet nat {
  chain prerouting  { type nat hook prerouting  priority -100; }
  chain postrouting { type nat hook postrouting priority  100; oifname != "fcbr0" masquerade; }
}
N
  fi
}
_fc_run_one(){
  local name="$1" raw_img="$2" mem="${3:-4096}" vcpus="${4:-4}"
  local tap="tap_${name}" mac vm_dir sock logf cfg
  mac=$(printf "02:FC:%02X:%02X:%02X:%02X" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
  ip link show "$tap" >/dev/null 2>&1 || ip tuntap add dev "$tap" mode tap
  ip link set "$tap" master fcbr0; ip link set "$tap" up
  local kernel="$FIRECRACKER_OUT/kernel" initrd="$FIRECRACKER_OUT/initrd"
  [[ -s "$kernel" && -s "$initrd" ]] || "$FIRECRACKER_OUT/extract-kernel-initrd.sh" "$raw_img" "$FIRECRACKER_OUT"
  vm_dir="$FIRECRACKER_OUT/vm-$name"; mkdir -p "$vm_dir"
  sock="$vm_dir/fc.sock"; logf="$vm_dir/fc.log"; cfg="$vm_dir/fc.json"; rm -f "$sock"
  cat >"$cfg" <<EOF
{
  "boot-source": { "kernel_image_path": "$kernel", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off" },
  "drives": [{ "drive_id": "rootfs", "path_on_host": "$raw_img", "is_root_device": true, "is_read_only": false }],
  "machine-config": { "vcpu_count": $vcpus, "mem_size_mib": $mem, "smt": true },
  "network-interfaces": [{ "iface_id": "eth0", "guest_mac": "$mac", "host_dev_name": "$tap" }],
  "logger": { "log_path": "$logf", "level": "Info", "show_level": true, "show_log_origin": false }
}
EOF
  nohup firecracker --api-sock "$sock" --config-file "$cfg" >/dev/null 2>&1 &
  echo "[+] firecracker: $name (tap=$tap, sock=$sock)"
}
firecracker_flow(){
  _firecracker_require
  _fc_make_nat_bridge
  local roles=("master" "k8s" "prom" "graf" "storage")
  for r in "${roles[@]}"; do
    local img="$BUILD_ROOT/${r}.img"; [[ -s "$img" ]] || { warn "skip $r (missing $img)"; continue; }
    _fc_run_one "$r" "$img" 4096 4
  done
  log "[OK] Firecracker VMs launched on fcbr0"
}

# ----------------- TARGET switch (entrypoint) -----------------
case "$TARGET" in
  proxmox-cluster)
    proxmox_cluster
    ;;
  image-only)
    log "[*] Building role ISOs only…"
    MASTER_PAYLOAD="$(mktemp)"; emit_postinstall_master "$MASTER_PAYLOAD"
    MASTER_ISO="$BUILD_ROOT/master.iso"; mk_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"
    log "[OK] master ISO: $MASTER_ISO"

    # Provide a default hub.env to allow minion ISO builds without booting master
    mkdir -p "$BUILD_ROOT/hub"
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

    P="$(mktemp)"; emit_minion_wrapper "$P" "prom"    "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3"; mk_iso "$PROM_NAME" "$P" "$BUILD_ROOT/prom.iso"    "$PROM_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "graf"    "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3"; mk_iso "$GRAF_NAME" "$P" "$BUILD_ROOT/graf.iso"    "$GRAF_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "k8s"     "$K8S_WG0"  "$K8S_WG1"  "$K8S_WG2"  "$K8S_WG3";  mk_iso "$K8S_NAME" "$P" "$BUILD_ROOT/k8s.iso"     "$K8S_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "storage" "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3"; mk_iso "$STOR_NAME" "$P" "$BUILD_ROOT/storage.iso" "$STOR_IP"

    log "[DONE] ISOs in $BUILD_ROOT"
    ;;
  packer-scaffold)
    emit_packer_scaffold
    ;;
  firecracker-bundle)
    emit_firecracker_scaffold
    ;;
  firecracker)
    firecracker_flow
    ;;
  *)
    die "Unknown TARGET=$TARGET"
    ;;
esac
