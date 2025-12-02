#!/bin/bash
# =============================================================================
# Cluster Snapshot Manager — Interactive + CLI + Cluster Safe
# =============================================================================

set -euo pipefail
LOG_FILE="/var/log/cluster_vm_snapshot.log"
exec > >(tee -a "$LOG_FILE") 2>&1

NODES=("bhs-pve-1" "bhs-pve-2" "bhs-pve-3")

log() { echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') — $*"; }
error_exit() { echo "[ERROR] $1" | tee -a "$LOG_FILE"; exit 1; }
trap 'error_exit "Script failed unexpectedly."' ERR

usage() {
  echo ""
  echo "Usage: $0 -v <vmid> -a <snapshot|revert|delete> [-n <name>]"
  echo "Examples:"
  echo "  $0 -v 110 -a snapshot"
  echo "  $0 -v 110 -a revert -n snap_name"
  echo "  $0 -v 110 -a delete -n snap_name"
  exit 0
}

VMID=""
ACTION=""
SNAP_NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--vm) VMID="$2"; shift 2 ;;
    -a|--action) ACTION="$2"; shift 2 ;;
    -n|--name) SNAP_NAME="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) error_exit "Unknown option: $1" ;;
  esac
done

if [[ -n "$ACTION" ]]; then
  [[ "$VMID" =~ ^[0-9]+$ ]] || error_exit "VMID must be a number."
fi

# === INTERACTIVE ===
if [[ -z "$ACTION" ]]; then
  echo "[INTERACTIVE MODE] — no args given."
  read -rp "VM ID: " VMID
  [[ "$VMID" =~ ^[0-9]+$ ]] || error_exit "VMID must be a number."
fi

# === Find Node ===
FOUND_NODE=""
for NODE in "${NODES[@]}"; do
  if ssh root@$NODE "qm list | awk '{print \$1}' | grep -q \"^$VMID\$\""; then
    FOUND_NODE="$NODE"; break
  fi
done
[[ -z "$FOUND_NODE" ]] && error_exit "VM $VMID not found on any cluster node."

if [[ -z "$ACTION" ]]; then
  echo ""
  echo "====== VM $VMID CONFIG ======"
  ssh root@$FOUND_NODE "qm config $VMID"
fi

main_menu() {
  echo ""
  echo "Available actions: [1] snapshot | [2] revert | [3] delete | [4] list snapshots | [X] exit"
  read -rp "Select action number: " ACTION_NUM
  case "$ACTION_NUM" in
    1) ACTION="snapshot" ;;
    2) ACTION="revert" ;;
    3) ACTION="delete" ;;
    4)
      echo "Snapshots for VM $VMID:"
      ssh root@$FOUND_NODE "qm listsnapshot $VMID"
      ACTION="" ;;
    x|X) echo "Exiting."; exit 0 ;;
    *) echo "Invalid option."; ACTION="" ;;
  esac
}

# === MAIN INTERACTIVE LOOP ===
while true; do
  while [[ -z "$ACTION" ]]; do main_menu; done
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)

  if [[ "$ACTION" == "snapshot" ]]; then
    NAME="${SNAP_NAME:-snap_$TIMESTAMP}"
    ssh root@$FOUND_NODE "qm snapshot $VMID $NAME --description 'Snapshot on $TIMESTAMP'"
    echo "Snapshot '$NAME' created."
    [[ -n "$SNAP_NAME" ]] && exit 0
    ACTION=""

  elif [[ "$ACTION" == "revert" ]]; then
    SNAP_LIST_RAW=$(ssh root@$FOUND_NODE "qm listsnapshot $VMID | tail -n +2 | grep -v current | sed -E 's/^.*-> //' | awk '{print \$1}'")
    readarray -t SNAP_LIST <<< "$SNAP_LIST_RAW"
    if [[ ${#SNAP_LIST[@]} -eq 0 ]]; then echo "No snapshots."; ACTION=""; continue; fi

    if [[ -n "$SNAP_NAME" ]]; then
      TARGET="$SNAP_NAME"
    else
      echo "Snapshots:"
      for i in "${!SNAP_LIST[@]}"; do echo "  [$((i+1))] ${SNAP_LIST[$i]}"; done
      read -rp "Number to revert: " NUM
      [[ "$NUM" =~ ^[0-9]+$ ]] || { echo "[ERROR] Invalid number."; ACTION=""; continue; }
      TARGET="${SNAP_LIST[$((NUM-1))]}"
    fi

    STATUS=$(ssh root@$FOUND_NODE "qm status $VMID | awk '{print \$2}'")
    [[ "$STATUS" == "running" ]] && ssh root@$FOUND_NODE "qm shutdown $VMID"
    ssh root@$FOUND_NODE "qm rollback $VMID $TARGET"
    ssh root@$FOUND_NODE "qm start $VMID"
    echo "Reverted to '$TARGET'."
    ACTION=""

  elif [[ "$ACTION" == "delete" ]]; then
    SNAP_LIST_RAW=$(ssh root@$FOUND_NODE "qm listsnapshot $VMID | tail -n +2 | grep -v current | sed -E 's/^.*-> //' | awk '{print \$1}'")
    readarray -t SNAP_LIST <<< "$SNAP_LIST_RAW"
    if [[ ${#SNAP_LIST[@]} -eq 0 ]]; then echo "No snapshots."; ACTION=""; continue; fi

    if [[ -n "$SNAP_NAME" ]]; then
      TARGET="$SNAP_NAME"
    else
      echo "Snapshots:"
      for i in "${!SNAP_LIST[@]}"; do echo "  [$((i+1))] ${SNAP_LIST[$i]}"; done
      read -rp "Number to delete: " NUM
      [[ "$NUM" =~ ^[0-9]+$ ]] || { echo "[ERROR] Invalid number."; ACTION=""; continue; }
      TARGET="${SNAP_LIST[$((NUM-1))]}"
    fi

    ssh root@$FOUND_NODE "qm delsnapshot $VMID $TARGET"
    echo "Deleted '$TARGET'."
    ACTION=""
  fi
done
