# deploy.sh

> Build once, deploy everywhere — **Proxmox** · **AWS** · **Firecracker** · **Azure/Packer (scaffold)**

A single, hardened Bash build system that produces UEFI-only, Secure Boot–signed, TPM-aware **Debian 13** images with **ZFS-on-root** and **Boot Environments**. It can stand up a 5-node template (master · prometheus · grafana · k8s worker · storage) on Proxmox, or export cloud-ready images—complete with a WireGuard fabric, eBPF toolchain, and an offline darksite APT repo. No fragile middleware, no snowflake hosts: first-boot “pull” config makes every instance reproducible and disposable.

---

## Tagline / Capabilities

**Identity / Trust / Image**

- full-custody zero trust
- darksite images
- nftables + eBPF
- zfs-on-root
- native wireguard

**Boot & Trust**

- uefi secure boot  
- shim-signed grub  
- tpm 2.0 pcr attestation  
- mok auto-sign (dkms)  
- full custody  
- service avibility on first boot

**Image & Network**

- userland "pull"  
- immutable base image  
- tuf / in-toto bundles  
- nocloud autoinstall  
- nftables baseline  
- eBPF dataplane  
- k8s, docker, podman  
- native manangment fabric

**Ops & Observability**

- zfs boot environments  
- instant rollback  
- air-gapped & darksites  
- ansible/semaphore hooks (opt-in)  
- qemu/kvm  
- QEMU Guest Agent ready  
- Prometheus/Grafana ready

---

## Why?

Traditional image builders assemble userland on top of whatever the platform gives you. This builds **from the kernel up**: dracut + ukify + signed UKIs, ZFS root with Boot Environments, Secure Boot keys, TPM2 sealing, and deterministic packages from a darksite.

Result: trustworthy, repeatable, and self-healing images you can launch anywhere.

---

## Main features

- **Kernel-up build**: UEFI-only, Secure Boot (PK/KEK/DB), signed UKIs per-BE, TPM 2.0.
- **ZFS by default**: Root on ZFS, Boot Environments, apt pre/post snapshot hooks, Sanoid/Syncoid.
- **Darksite APT**: Reproducible package set with vendor tarballs + manifest (air-gap friendly).
- **WireGuard fabric**: Hub + minion autoprovision (wg0–wg3), optional TPM-sealed keys.
- **eBPF toolkit baked in**: bpftrace, BCC tools, perf, sysstat—ready for deep observability.
- **First-boot “pull”**: Zero-touch bootstrap; replace instead of repair for immutable-style ops.
- **Proxmox automation**: q35/OVMF, TPM v2, signed UKI; ISO upload + VM lifecycle + QGA harvesting.
- **AWS import**: qcow2→raw→S3→AMI with *UEFI boot* + *TPM v2* + optional UEFI var-store.
- **Firecracker & Packer scaffolds**: Auto-emit helpers (kernel/initrd extraction, qemu template).
- **Modes**: `proxmox-cluster`, `image-only`, `aws`, `packer-scaffold`, `firecracker-bundle`.

---

## Special abilities

- **Early install path**: Minimal ext4 to get on disk, auto-converts to ZFS on first boot, signs UKI, reboots clean.
- **Boot-env aware kernel updates**: Post-inst hook builds/signs UKIs per BE; roll back with one command.
- **Hub/minion seeding**: Master auto-generates `hub.env`; minions self-wire via wrapper overlays.
- **Policy-as-defaults**: nftables locked by default, SSH hardening, no password auth (toggleable for LAN).
- **Built-in telemetry**: Prometheus + node exporter + Grafana provisioning out-of-the-box.

---

## Quick synopsis

```bash
./build.sh <mode>

Modes:
  proxmox-cluster     # Build ISOs, deploy master + prom + graf + k8s + storage on Proxmox (UEFI+TPM)
  image-only          # Build role ISOs without deploying
  aws                 # Convert/upload, import-image, register UEFI+TPM AMI, create LT, launch
  packer-scaffold     # Emit a ready-to-edit Packer/QEMU template
  firecracker-bundle  # Extract kernel/initrd from rootfs and emit helper scripts

Key env:
  PROXMOX_HOST=10.x.x.x   ISO_ORIG=/path/debian-13-netinst.iso
  BUILD_ROOT=/root/builds  AWS_S3_BUCKET=my-bucket
```

## Quick Start

#1 - downalod and deploy proxmox, ssh-copy-id and ensure you can ssh root proxmox (TARGET MACHINE)
#2 - on your (BUILD MACHINE)
```bash
sudo apt-get update && sudo apt-get install -y \
  git curl ca-certificates \
  docker.io \
  debootstrap squashfs-tools xorriso syslinux-common isolinux dosfstools p7zip-full zstd \
  zfsutils-linux zfs-dkms \
  qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils ovmf cloud-image-utils \
  build-essential dkms make gcc \
  linux-headers-$(uname -r)
```
#3 - ./deploy.sh

by default the deploy script will use the public network to pull down and build the entire world, in this case
13 vm's in a hub&spoke configuration with 3 default built in wireguard l3 tunnels with built in api.

by default, only os, packages, configuraion and keys are generated. allowing for the "Blanks" to be consumed by existing tools. It also 
allows them to be cleanly intergrated into exsiting wireguard networks simply add the peer and keys.

I have included some sample commands you can use to easily manage your new infracrutre (keep in mind its WIP)
