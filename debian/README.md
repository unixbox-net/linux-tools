# FoundryBot

**One command lays the foundation.** `deploy.sh` (connected) installs the OS, wiring (network/storage), container runtime, and secure defaults using public Internet sources—then **hands off** so you can apply configuration with your tools (Ansible/Salt/Puppet/Chef/custom) or the optional `apply.py`. WireGuard devices are created and **keys generated**; **no peers are added** by default so you can drop into your own mesh cleanly.

`build.sh` similar to deploy, except ALL resources are "re-packed" into a darksite directory, this provides versioned fail safe 100% MTTR. IE: when AWS west blows up, export the image, convert to Azure and execute the build.sh, when its done MTTR is complete and your good to go.  No broken snapshots, failed backups/updates or upgrades or disaperaing repos, everything required is included in the .iso/image and it is completely agnostic/connected via a native l3 hub & spoke backplane.

## Scope & Expectations (read first)
- **Foundation first**: Phase‑1 builds OS + plumbing; Phase‑2 is your config (BYO or `apply.py`).
- **Tool‑agnostic**: no dependency on any CM system; `apply.py` is optional.
- **WG posture**: devices up, keys generated, **no peering** until you choose.
- **K8s‑ready, not K8s‑final**: runtime and prereqs are in place; cluster init is opt‑in.
- **Secure defaults**: nftables default‑deny, SSH key‑only, services bound to intended planes.
- **Rebuild > restore**: host OS is disposable; state/snapshots live on the storage plane.

## Requirements (builder + targets)
- Debian 12/13 build host with Internet egress (`qemu-utils`, `xorriso`, `ovmf`, optional `docker`).
- Access to your hypervisor/cloud (Proxmox, KVM, vSphere, AWS, etc.).
- SSH key for the admin user; minimal environment variables set (see below).

## Quick Start
```bash
# Prepare env (edit to suit)
export PROXMOX_HOST=192.0.2.10
export ISO_STORAGE=local
export VM_STORAGE=local-zfs
export ADMIN_USER=admin
export SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub 2>/dev/null || true)"

# Fabrics (examples)
export WG1_IP=10.78.0.1/16
export WG2_IP=10.79.0.1/16
export WG3_IP=10.80.0.1/16

# Build the foundation (Phase‑1)
bash ./deploy.sh
# Hand‑off: apply your configuration (BYO) or:
# sudo python3 ./apply.py   # optional reference config
```

## Targets & Exports (versatility at a glance)
- **KVM/QEMU**: boot self‑deploying ISO or import QCOW2.
- **Proxmox**: upload VM template(s) + Cloud‑Init seed automatically.
- **ESXi/vSphere**: convert to VMDK/OVA and import (govc/ovftool).
- **AWS AMI**: convert → upload → import snapshot → register AMI.
- **Azure**: convert to fixed VHD → upload → `az image create`.
- **GCP**: convert to `disk.raw` tarball → `gcloud compute images import`.
- **USB / Bare‑metal**: burn the self‑deploying ISO and boot.
- **PXE/iPXE**: serve kernel+initrd with your autoinstall/seed params.

### Minimal Examples
```bash
# KVM: ISO boot
virt-install --name base-01 --memory 8192 --vcpus 4 \
  --disk size=40,bus=virtio --cdrom out/images/base.iso --os-variant debian12 --graphics none --boot uefi

# Proxmox: push template + seed
ROLE=k8s-worker TARGET=proxmox-cluster ./deploy.sh

# ESXi: qcow2 → vmdk (import with govc/ovftool afterward)
qemu-img convert -p -O vmdk out/disks/base.qcow2 base.vmdk

# AWS: qcow2 → raw → S3 → import-snapshot → register-image
qemu-img convert -p -O raw out/disks/base.qcow2 base.raw

# USB burn
sudo dd if=out/images/base.iso of=/dev/sdX bs=4M status=progress oflag=sync
```



# Build / Execution Server

The **build/execution server** is the machine that runs `deploy.sh` or `build.sh`. It can be **any hardware or VM** on **any OS** that has **POSIX-compliant Bash**, `sudo`, and enough disk space. No hypervisor/vendor lock‑in and **no third‑party services are required**.

## Purpose
- Orchestrate Phase‑1 (**foundation build**) for targets (OS install, wiring, container runtime, secure defaults).
- Optionally produce a **fully self‑contained image** with every artifact needed to rebuild later—no Internet required.

## Requirements (minimal)
- **Platform:** *Any* HW/VM on Linux/*BSD/macOS with POSIX Bash  (Windows WSL works).  
- **Privileges:** `sudo` capable user.  
- **Network:** For `deploy.sh` mode, outbound Internet (HTTPS).  
- **Disk:** 50–200+ GB free (ISOs, qcow2/vmdk, caches); **more** if you embed snapshots/VM payloads with `build.sh`.

> **No third‑party requirements.** The scripts use standard OS tooling only; registries/repos are accessed directly in the online mode.

## Two Ways to Run
| Mode | Script | Connectivity | What it Produces | Typical Duration | When to use |
|---|---|---|---|---|---|
| **Online Foundation** | `deploy.sh` | Public Internet (normal package/registry pulls) | Base images/ISOs; K8s‑ready foundation | Fast (baseline) | Day‑to‑day builds; CI; quick labs |
| **Self‑Contained (Time‑capsule)** | `build.sh` | None required **after** build (artifacts embedded) | A **fully self‑contained** image bundle with **all** packages, kernels, repos, and **your captured VMs/services** | ~3× longer than `deploy.sh` | Compliance, air‑gap, long‑term DR, reproducible rebuilds years later |

### What “Self‑Contained” Means
Running `build.sh` **packages everything** needed to **rebuild the target from scratch** at the **exact state** of the last build, including:
- All OS packages, kernels, installers, and repo metadata needed for install
- Container images and ancillary binaries used by services
- **Optional snapshot of running VMs & their service data** to restore to the captured point‑in‑time

> If, a year from now, the server fails and your backup/snapshot is unavailable, the `build.sh` artifact can **fully rebuild** to the **last build point** without reaching the Internet.

## Quick Start (Execution Server)
```bash
# 1) Get the repo (or drop the release bundle)
git clone <YOUR_REPO_URL> foundry && cd foundry

# 2) Set your minimal environment (examples)
export ADMIN_USER=admin
export SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub 2>/dev/null || true)"
export PROXMOX_HOST=192.0.2.10
export ISO_STORAGE=local
export VM_STORAGE=local-zfs

# 3a) Fast online foundation (normal fetches from the Internet)
bash ./deploy.sh

# 3b) Self‑contained build (slow but captures EVERYTHING)
bash ./build.sh
```

## Expectations & Trade‑offs
- `deploy.sh` **fast**: retrieves from public services “normally,” produces lean base images; configuration remains your Phase‑2 task.  
- `build.sh` **slow (~3×)**: embeds all artifacts + (optionally) captured VMs/services; outputs a **portable time‑capsule** capable of full reconstruction without Internet.  
- Both modes generate WireGuard devices and **public keys only** (no peering). Post‑install configuration is **your** toolchain or `apply.py`.

## Disaster Recovery Flow (with `build.sh` artifact)
1. Boot the self‑deploying image from your archive (USB/ISO/template).  
2. Foundation installs with **embedded repos & images** (no external fetch).  
3. Captured VMs/services are restored to the **exact last build** state.  
4. Re‑apply any Phase‑2 policy (if you keep it in‑repo) or your CM stack.  

## Other Files
- `apply.py` finishes off the cluster install, updates wireguard and applys salt-states
- `clone.sh` automati clone and deployment tool for proxmox, multi target/multi nodes, ie: point and shoot

