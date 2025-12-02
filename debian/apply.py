#!/usr/bin/env python3
# WIP post install kubernetes setup
import subprocess
import json
import shutil
import time
import os
from pathlib import Path

WG_DIR = Path("/etc/wireguard")
PLANES = ["wg1", "wg2", "wg3"]
SALT_TARGET = "*"          # adjust if you want a subset
SYSTEMD_UNIT_TEMPLATE = "wg-quick@{iface}.service"


def run(cmd, **kwargs):
    """Run a command and return stdout (text)."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("check", True)
    return subprocess.run(cmd, stdout=subprocess.PIPE, **kwargs).stdout


def salt_cmd(target, shell_cmd):
    """
    Run a Salt cmd.run on all matching minions and return a dict:
        {minion_id: "output string"}

    We add --no-color and --static, and defensively extract the JSON
    payload between the first '{' and last '}' to avoid log noise.
    """
    out = run([
        "salt", target, "cmd.run", shell_cmd,
        "--out=json", "--static", "--no-color"
    ])
    out = out.strip()
    if not out:
        return {}

    # Strip anything before the first '{' and after the last '}'
    start = out.find("{")
    end = out.rfind("}")
    if start == -1 or end == -1 or end <= start:
        print(f"[WARN] Could not find JSON object in Salt output for cmd: {shell_cmd}")
        print(f"[WARN] Raw output was:\n{out}")
        return {}

    json_str = out[start:end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON decode failed for Salt output (cmd: {shell_cmd}): {e}")
        print(f"[WARN] Extracted JSON candidate was:\n{json_str}")
        return {}


def read_interface_block(conf_path):
    """
    Read only the [Interface] block from an existing wgX.conf,
    stopping at the first [Peer] (if any).
    Returns list of lines (without trailing newlines).
    """
    lines = []
    with open(conf_path, "r") as f:
        for line in f:
            if line.strip().startswith("[Peer]"):
                break
            lines.append(line.rstrip("\n"))
    return lines


def get_hub_ip(conf_path):
    """
    Parse the 'Address = 10.x.x.x/nn' line from the [Interface] section
    and return just the IP (no CIDR).
    """
    with open(conf_path, "r") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("Address"):
                # e.g. "Address    = 10.78.0.1/16"
                try:
                    _, rhs = stripped.split("=", 1)
                    addr = rhs.split("#", 1)[0].strip()
                    ip = addr.split("/", 1)[0].strip()
                    return ip
                except ValueError:
                    continue
    return None


def build_peers_for_plane(iface):
    """
    For a given interface (wg1, wg2, wg3):
      - ask all minions for IP on that interface
      - ask all minions for public key
    Returns list of dicts: {"minion": ..., "ip": ..., "pubkey": ...}
    """
    # Get IPv4 addr on that interface (one IP per minion)
    ip_cmd = f"ip -4 -o addr show dev {iface} 2>/dev/null | awk '{{print $4}}' | cut -d/ -f1"
    ips = salt_cmd(SALT_TARGET, ip_cmd)

    # Get public key for that interface
    pk_cmd = f"wg show {iface} public-key 2>/dev/null || true"
    pubkeys = salt_cmd(SALT_TARGET, pk_cmd)

    peers = []
    for minion, ip_out in sorted(ips.items()):
        ip = ip_out.strip()
        if not ip:
            continue  # no IP on this iface
        pubkey = pubkeys.get(minion, "").strip()
        if not pubkey:
            continue  # no public key
        peers.append({"minion": minion, "ip": ip, "pubkey": pubkey})
    return peers


def write_conf_for_plane(iface):
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        print(f"[WARN] {conf_path} does not exist, skipping {iface}")
        return

    # Backup existing config
    ts = time.strftime("%Y%m%d%H%M%S")
    backup_path = conf_path.with_suffix(conf_path.suffix + f".bak.{ts}")
    shutil.copy2(conf_path, backup_path)
    print(f"[INFO] Backed up {conf_path} -> {backup_path}")

    # Read interface block and hub IP
    iface_lines = read_interface_block(conf_path)
    hub_ip = get_hub_ip(conf_path)
    if not hub_ip:
        print(f"[WARN] Could not determine hub IP from {conf_path}, continuing anyway")

    # Gather peers via Salt
    peers = build_peers_for_plane(iface)
    if not peers:
        print(f"[WARN] No peers found for {iface}, leaving only [Interface]")
    else:
        print(f"[INFO] Found {len(peers)} peers for {iface}")

    # Write new config
    new_path = conf_path.with_suffix(conf_path.suffix + ".new")
    with open(new_path, "w") as f:
        # [Interface] block
        for line in iface_lines:
            f.write(line + "\n")
        f.write("\n")

        # [Peer] blocks
        for peer in peers:
            ip = peer["ip"]
            # Skip adding self (hub) if it shows up in Salt results
            if hub_ip and ip == hub_ip:
                continue

            f.write("[Peer]\n")
            f.write(f"# {peer['minion']} ({iface})\n")
            f.write(f"PublicKey = {peer['pubkey']}\n")
            f.write(f"AllowedIPs = {ip}/32\n")
            # Uncomment if you want keepalive from clients back to hub
            # f.write("PersistentKeepalive = 25\n")
            f.write("\n")

    # Replace original with new
    os.replace(new_path, conf_path)
    print(f"[INFO] Updated {conf_path}")


def restart_plane(iface):
    unit = SYSTEMD_UNIT_TEMPLATE.format(iface=iface)
    print(f"[INFO] Restarting {unit}")
    try:
        run(["systemctl", "restart", unit])
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to restart {unit}: {e}")


def main():
    for iface in PLANES:
        print(f"=== Processing {iface} ===")
        write_conf_for_plane(iface)
        restart_plane(iface)


if __name__ == "__main__":
    main()

