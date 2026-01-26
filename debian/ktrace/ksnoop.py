#!/usr/bin/env python3
"""
kube_socket_snapshot.py — Debian-friendly eBPF/BCC timed socket snapshot for Kubernetes nodes
===========================================================================================

This is a *metadata-only* snapshot tool:
- TCP state transitions (tracepoint sock:inet_sock_set_state)
- UDP send events (kprobe udp_sendmsg)
- UDP receive events (kretprobe udp_recvmsg)
- Optional TCP retransmits (tracepoint tcp:tcp_retransmit_skb)

Outputs (by default into ./out):
- kube_socket_snapshot.<node>.<ts>.events.jsonl
- kube_socket_snapshot.<node>.<ts>.summary.json
- kube_socket_snapshot.<node>.<ts>.node.json
- kube_socket_snapshot.<node>.<ts>.bundle.tgz

Optional “split logs” mode (recommended for big captures):
- ...tcp.jsonl / ...udp_send.jsonl / ...udp_recv.jsonl / ...retrans.jsonl

Debian 13 prerequisites (host):
  apt-get update
  apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) tar gzip
Often helpful if BCC compile complains:
  apt-get install -y clang llvm libelf-dev build-essential

Run:
  sudo ./kube_socket_snapshot.py --duration 60 --out-dir /var/log/kube-snap --split-logs
"""

import argparse
import json
import os
import re
import socket
import sys
import tarfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List, TextIO


# ---------------------------
# TCP state mapping
# ---------------------------

TCP_STATES: Dict[int, str] = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}

CLOSE_STATES = {"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "CLOSING"}
OPEN_HINT_STATES = {"SYN_SENT", "SYN_RECV", "ESTABLISHED"}


# ---------------------------
# Helpers
# ---------------------------

def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_stamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def ip_from_u32_be(v: int) -> str:
    # v is big-endian packed (network order)
    return ".".join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "0.0.0.0"


def parse_ports_csv(s: Optional[str]) -> Optional[set]:
    if not s:
        return None
    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError
            out.add(p)
        except ValueError:
            raise SystemExit(f"Invalid port in --ports: {part!r}")
    return out or None


def read_text(path: str, max_bytes: int = 256 * 1024) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def file_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False


def require_root() -> None:
    if os.geteuid() != 0:
        print("Error: run as root (sudo).", file=sys.stderr)
        sys.exit(1)


def sanity_check_environment() -> None:
    # We intentionally do NOT depend on libbpf headers like bpf/bpf_helpers.h.
    # This tool uses BCC-style programs and kernel UAPI headers that come with linux-headers.
    kver = os.uname().release
    hdr = f"/lib/modules/{kver}/build"
    if not file_exists(hdr):
        print(
            f"Warning: kernel build headers not found at {hdr}\n"
            f"Fix with: apt-get install -y linux-headers-{kver}",
            file=sys.stderr,
        )


# cgroup parsing: include dashes because real pod UIDs are UUID-like
CGROUP_POD_UID_RE = re.compile(r"pod([0-9a-fA-F\-]{8,})", re.IGNORECASE)
CGROUP_CONTAINER_RE = re.compile(r"([0-9a-fA-F]{32,64})", re.IGNORECASE)


def k8s_hints_from_pid(pid: int) -> Dict[str, str]:
    """
    Best-effort mapping using cgroup path hints.
    Returns:
      { "cgroup": "...", "pod_uid": "....", "container_hint": "...." }
    """
    raw = read_text(f"/proc/{pid}/cgroup").strip()
    if not raw:
        return {"cgroup": "-", "pod_uid": "-", "container_hint": "-"}

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    longest = max(lines, key=len) if lines else "-"

    pod_uid = "-"
    container_hint = "-"

    m = CGROUP_POD_UID_RE.search(raw)
    if m:
        pod_uid = m.group(1)[:64]

    m2 = CGROUP_CONTAINER_RE.search(raw)
    if m2:
        container_hint = m2.group(1)[:64]

    return {"cgroup": longest, "pod_uid": pod_uid, "container_hint": container_hint}


def role_cache_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    return (a, b) if a <= b else (b, a)


@dataclass
class Role:
    client: str
    server: str
    service_port: int
    confidence: str   # "low" | "med" | "high"
    last_seen: float


def infer_role_basic(src_ip: str, src_port: int, dst_ip: str, dst_port: int, old_state: str, new_state: str) -> Role:
    """
    Best-effort role inference. Avoid overconfidence unless we see SYN_SENT behavior.
    """
    now = time.time()

    # Strong: we see the active opener
    if new_state == "SYN_SENT" or (old_state == "SYN_SENT" and new_state == "ESTABLISHED"):
        return Role(
            client=f"{src_ip}:{src_port}",
            server=f"{dst_ip}:{dst_port}",
            service_port=dst_port,
            confidence="high",
            last_seen=now,
        )

    # Moderate: established without SYN visibility
    if new_state == "ESTABLISHED":
        # heuristic: lower port is more likely the service port
        if dst_port <= src_port:
            return Role(
                client=f"{src_ip}:{src_port}",
                server=f"{dst_ip}:{dst_port}",
                service_port=dst_port,
                confidence="med",
                last_seen=now,
            )
        return Role(
            client=f"{dst_ip}:{dst_port}",
            server=f"{src_ip}:{src_port}",
            service_port=src_port,
            confidence="med",
            last_seen=now,
        )

    # Close states: low confidence
    if new_state in CLOSE_STATES:
        if dst_port <= src_port:
            return Role(
                client=f"{src_ip}:{src_port}",
                server=f"{dst_ip}:{dst_port}",
                service_port=dst_port,
                confidence="low",
                last_seen=now,
            )
        return Role(
            client=f"{dst_ip}:{dst_port}",
            server=f"{src_ip}:{src_port}",
            service_port=src_port,
            confidence="low",
            last_seen=now,
        )

    # Default
    return Role(
        client=f"{src_ip}:{src_port}",
        server=f"{dst_ip}:{dst_port}",
        service_port=dst_port,
        confidence="low",
        last_seen=now,
    )


# ---------------------------
# CLI
# ---------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Kube Socket Snapshot (BCC): TCP state + UDP send/recv timed capture (JSONL bundle)."
    )
    p.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (default: 60).")
    p.add_argument("--out-dir", default="./out", help="Output directory (default: ./out).")
    p.add_argument("--node", default=socket.gethostname(), help="Node name label (default: hostname).")

    # Filters / modes
    p.add_argument("--ports", default=None, help="Comma-separated port allowlist (matches either src or dst).")
    p.add_argument("--comm", default=None, help="Only include events where comm contains this substring.")
    p.add_argument("--dns-only", action="store_true", help="Focus on DNS (UDP/TCP port 53).")
    p.add_argument("--ignore-loopback", action="store_true", help="Drop 127.0.0.1 / 0.0.0.0 noise.")
    p.add_argument("--include-retrans", action="store_true", help="Include tcp:tcp_retransmit_skb tracepoint.")
    p.add_argument("--split-logs", action="store_true", help="Write separate JSONL logs per event type.")

    # Output controls
    p.add_argument("--max-events", type=int, default=500000, help="Hard cap on events to write (safety).")
    p.add_argument("--flush-every", type=int, default=200, help="Flush JSONL every N events (default: 200).")

    # Role-cache controls
    p.add_argument("--role-cache-ttl", type=int, default=300, help="Seconds to keep TCP role cache (default: 300).")

    return p.parse_args()


# ---------------------------
# eBPF (BCC) program
# ---------------------------

# NOTE:
# - This is BCC-style C. No <bpf/bpf_helpers.h> dependency.
# - We avoid PT_REGS_PARMx macros to not trip CO-RE target issues.
# - kretprobe udp_recvmsg uses PT_REGS_RC(ctx), which is safe for BCC kretprobes.

BPF_PROGRAM_BASE = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

enum evt_type {
    EVT_TCP_STATE   = 1,
    EVT_UDP_SEND    = 2,
    EVT_UDP_RECV    = 3,
    EVT_TCP_RETRANS = 4,
};

struct data_t {
    u32 type;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    // Network (network order for IPs; ports host order)
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;

    // TCP-only
    u32 oldstate;
    u32 newstate;

    // UDP-only
    u32 bytes;
};

struct recv_args_t {
    struct sock *sk;
    struct msghdr *msg;
};

BPF_HASH(recv_args, u64, struct recv_args_t);
BPF_PERF_OUTPUT(events);

static __always_inline u32 get_ppid(void) {
    u32 ppid = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    }
    return ppid;
}

static __always_inline void fill_common(struct data_t *d) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    d->pid = pid_tgid >> 32;
    d->uid = bpf_get_current_uid_gid();
    d->ppid = get_ppid();
    bpf_get_current_comm(&d->comm, sizeof(d->comm));
}

// Tracepoint: sock:inet_sock_set_state
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->family != AF_INET)
        return 0;

    struct data_t data = {};
    fill_common(&data);
    data.type = EVT_TCP_STATE;

    // pack saddr/daddr (u8[4]) into u32 big-endian
    data.src_ip = ((u32)args->saddr[0] << 24) |
                  ((u32)args->saddr[1] << 16) |
                  ((u32)args->saddr[2] <<  8) |
                  ((u32)args->saddr[3]);
    data.dst_ip = ((u32)args->daddr[0] << 24) |
                  ((u32)args->daddr[1] << 16) |
                  ((u32)args->daddr[2] <<  8) |
                  ((u32)args->daddr[3]);

    data.src_port = ntohs(args->sport);
    data.dst_port = ntohs(args->dport);

    data.oldstate = args->oldstate;
    data.newstate = args->newstate;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// UDP send: tuple from sock fields; for unconnected sockets try msg->msg_name (sendto)
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    struct data_t data = {};
    fill_common(&data);
    data.type = EVT_UDP_SEND;
    data.bytes = (u32)len;

    __be32 saddr = 0, daddr = 0;
    u16 sport = 0;
    __be16 dport_be = 0;

    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);

    data.src_ip = saddr;
    data.src_port = sport;

    if (daddr != 0 && dport_be != 0) {
        // connected UDP
        data.dst_ip = daddr;
        data.dst_port = ntohs(dport_be);
    } else {
        // unconnected: try msg_name (sendto)
        void *namep = NULL;
        int namelen = 0;
        if (msg) {
            bpf_probe_read_kernel(&namep, sizeof(namep), &msg->msg_name);
            bpf_probe_read_kernel(&namelen, sizeof(namelen), &msg->msg_namelen);
        }
        if (namep != NULL && namelen >= (int)sizeof(struct sockaddr_in)) {
            struct sockaddr_in sin = {};
            if (bpf_probe_read_user(&sin, sizeof(sin), namep) == 0) {
                data.dst_ip = sin.sin_addr.s_addr;
                data.dst_port = ntohs(sin.sin_port);
            }
        }
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// UDP recv entry: stash args so kretprobe can read msg_name after kernel fills it
int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
{
    if (!sk)
        return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    struct recv_args_t a = {};
    a.sk = sk;
    a.msg = msg;
    recv_args.update(&id, &a);
    return 0;
}

// UDP recv return: return value is bytes; try msg_name (recvfrom) for remote
int kretprobe__udp_recvmsg(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct recv_args_t *ap = recv_args.lookup(&id);
    if (!ap)
        return 0;

    struct sock *sk = ap->sk;
    struct msghdr *msg = ap->msg;
    recv_args.delete(&id);

    if (!sk)
        return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct data_t data = {};
    fill_common(&data);
    data.type = EVT_UDP_RECV;
    data.bytes = (u32)ret;

    __be32 laddr = 0;
    u16 lport = 0;
    bpf_probe_read_kernel(&laddr, sizeof(laddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);

    // default: dst is local
    data.dst_ip = laddr;
    data.dst_port = lport;

    void *namep = NULL;
    int namelen = 0;
    if (msg) {
        bpf_probe_read_kernel(&namep, sizeof(namep), &msg->msg_name);
        bpf_probe_read_kernel(&namelen, sizeof(namelen), &msg->msg_namelen);
    }

    if (namep != NULL && namelen >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), namep) == 0) {
            data.src_ip = sin.sin_addr.s_addr;
            data.src_port = ntohs(sin.sin_port);
        }
    } else {
        // fallback: connected UDP
        __be32 raddr = 0;
        __be16 rport_be = 0;
        bpf_probe_read_kernel(&raddr, sizeof(raddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&rport_be, sizeof(rport_be), &sk->__sk_common.skc_dport);
        data.src_ip = raddr;
        data.src_port = ntohs(rport_be);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

BPF_PROGRAM_RETRANS = r"""
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    struct data_t data = {};
    fill_common(&data);
    data.type = EVT_TCP_RETRANS;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


# ---------------------------
# Output structures
# ---------------------------

@dataclass
class Files:
    events_jsonl: str
    summary_json: str
    node_json: str
    bundle_tgz: str
    tcp_jsonl: Optional[str] = None
    udp_send_jsonl: Optional[str] = None
    udp_recv_jsonl: Optional[str] = None
    retrans_jsonl: Optional[str] = None


def build_filenames(out_dir: str, node: str, split: bool) -> Files:
    ts = iso_stamp_for_filename()
    base = f"kube_socket_snapshot.{node}.{ts}"
    f = Files(
        events_jsonl=os.path.join(out_dir, f"{base}.events.jsonl"),
        summary_json=os.path.join(out_dir, f"{base}.summary.json"),
        node_json=os.path.join(out_dir, f"{base}.node.json"),
        bundle_tgz=os.path.join(out_dir, f"{base}.bundle.tgz"),
    )
    if split:
        f.tcp_jsonl = os.path.join(out_dir, f"{base}.tcp.jsonl")
        f.udp_send_jsonl = os.path.join(out_dir, f"{base}.udp_send.jsonl")
        f.udp_recv_jsonl = os.path.join(out_dir, f"{base}.udp_recv.jsonl")
        f.retrans_jsonl = os.path.join(out_dir, f"{base}.retrans.jsonl")
    return f


# ---------------------------
# Main
# ---------------------------

def main() -> None:
    require_root()
    if os.uname().sysname.lower() != "linux":
        print("Error: this tool requires Linux (eBPF/BCC).", file=sys.stderr)
        sys.exit(1)

    sanity_check_environment()
    args = parse_args()
    safe_mkdir(args.out_dir)
    files = build_filenames(args.out_dir, args.node, args.split_logs)

    ports_allow = parse_ports_csv(args.ports)
    if args.dns_only:
        ports_allow = {53}

    try:
        from bcc import BPF  # type: ignore
    except Exception:
        print(
            "Error: missing BCC python bindings.\n"
            "Install: apt-get install -y bpfcc-tools python3-bpfcc",
            file=sys.stderr,
        )
        sys.exit(1)

    # BPF program selection
    bpf_text = BPF_PROGRAM_BASE + (BPF_PROGRAM_RETRANS if args.include_retrans else "")

    # Write node metadata
    node_meta: Dict[str, Any] = {
        "tool": "kube_socket_snapshot",
        "version": "0.2",
        "ts_start": utc_ts(),
        "node": args.node,
        "uname": {
            "sysname": os.uname().sysname,
            "release": os.uname().release,
            "version": os.uname().version,
            "machine": os.uname().machine,
        },
        "args": {
            "duration": args.duration,
            "out_dir": args.out_dir,
            "ports": args.ports,
            "comm": args.comm,
            "dns_only": args.dns_only,
            "ignore_loopback": args.ignore_loopback,
            "include_retrans": args.include_retrans,
            "split_logs": args.split_logs,
            "max_events": args.max_events,
            "flush_every": args.flush_every,
            "role_cache_ttl": args.role_cache_ttl,
        },
        "notes": [
            "BCC-based (no libbpf CO-RE).",
            "IPv4 only in this build.",
            "UDP remote tuple is best-effort; recvfrom is often accurate via msg_name read.",
            "Pod mapping is best-effort using /proc/<pid>/cgroup hints.",
        ],
        "files": {
            "events_jsonl": files.events_jsonl,
            "summary_json": files.summary_json,
            "node_json": files.node_json,
            "bundle_tgz": files.bundle_tgz,
            "tcp_jsonl": files.tcp_jsonl,
            "udp_send_jsonl": files.udp_send_jsonl,
            "udp_recv_jsonl": files.udp_recv_jsonl,
            "retrans_jsonl": files.retrans_jsonl,
        },
    }
    with open(files.node_json, "w", encoding="utf-8") as f:
        json.dump(node_meta, f, indent=2)

    # Compile & load BPF
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Error: failed to compile/load BPF program: {e}", file=sys.stderr)
        print(
            "Hints:\n"
            "  - Ensure headers match running kernel: apt-get install -y linux-headers-$(uname -r)\n"
            "  - If clang/llvm missing: apt-get install -y clang llvm\n"
            "  - If libelf missing: apt-get install -y libelf-dev\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # Open output streams
    out_all = open(files.events_jsonl, "w", encoding="utf-8")
    out_tcp: Optional[TextIO] = open(files.tcp_jsonl, "w", encoding="utf-8") if files.tcp_jsonl else None
    out_us: Optional[TextIO] = open(files.udp_send_jsonl, "w", encoding="utf-8") if files.udp_send_jsonl else None
    out_ur: Optional[TextIO] = open(files.udp_recv_jsonl, "w", encoding="utf-8") if files.udp_recv_jsonl else None
    out_rt: Optional[TextIO] = open(files.retrans_jsonl, "w", encoding="utf-8") if files.retrans_jsonl else None

    def _close_all() -> None:
        for fh in (out_all, out_tcp, out_us, out_ur, out_rt):
            try:
                if fh:
                    fh.flush()
                    fh.close()
            except Exception:
                pass

    # Event & summary counters
    event_count = 0
    dropped_parse = 0

    top_comm = Counter()
    top_tuple = Counter()
    top_ports = Counter()

    tcp_state_transitions = Counter()
    tcp_state_by_comm = Counter()

    udp_sends_by_port = Counter()
    udp_recvs_by_port = Counter()
    udp_dns_sends_by_comm = Counter()
    udp_dns_recvs_by_comm = Counter()

    tcp_retrans_by_comm = Counter()

    # DNS best-effort “send without recv” heuristic
    dns_send_key = Counter()
    dns_recv_key = Counter()

    # TCP role cache
    role_cache: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Role] = {}

    def passes_filters(comm: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bool:
        if args.comm and args.comm not in comm:
            return False
        if args.ignore_loopback and (is_loopback(src_ip) or is_loopback(dst_ip)):
            return False
        if ports_allow is not None:
            if (src_port not in ports_allow) and (dst_port not in ports_allow):
                return False
        return True

    def write_jsonl(fh: TextIO, obj: Dict[str, Any]) -> None:
        fh.write(json.dumps(obj, sort_keys=False) + "\n")

    def write_event(obj: Dict[str, Any]) -> None:
        nonlocal event_count
        write_jsonl(out_all, obj)
        event_count += 1
        if event_count % max(1, args.flush_every) == 0:
            out_all.flush()
            for fh in (out_tcp, out_us, out_ur, out_rt):
                if fh:
                    fh.flush()

    def role_cache_get_or_set(src_ip: str, src_port: int, dst_ip: str, dst_port: int, old_s: str, new_s: str) -> Role:
        key = role_cache_key(src_ip, src_port, dst_ip, dst_port)
        now = time.time()

        # emergency pruning
        if len(role_cache) > 50000:
            for k in list(role_cache.keys())[:10000]:
                if now - role_cache[k].last_seen > args.role_cache_ttl:
                    del role_cache[k]

        r = role_cache.get(key)
        if r and (now - r.last_seen) <= args.role_cache_ttl:
            r.last_seen = now
            if new_s in OPEN_HINT_STATES and r.confidence != "high":
                nr = infer_role_basic(src_ip, src_port, dst_ip, dst_port, old_s, new_s)
                if nr.confidence == "high":
                    role_cache[key] = nr
                    return nr
            return r

        nr = infer_role_basic(src_ip, src_port, dst_ip, dst_port, old_s, new_s)
        if nr.confidence in ("high", "med"):
            role_cache[key] = nr
        return nr

    def handle_event(cpu: int, data: Any, size: int) -> None:
        nonlocal dropped_parse, event_count

        if event_count >= args.max_events:
            return

        try:
            e = b["events"].event(data)
        except Exception:
            dropped_parse += 1
            return

        evt_type = int(e.type)
        pid = int(e.pid)
        uid = int(e.uid)
        ppid = int(e.ppid)
        comm = e.comm.decode(errors="replace")

        src_ip = ip_from_u32_be(int(e.src_ip))
        dst_ip = ip_from_u32_be(int(e.dst_ip))
        src_port = int(e.src_port)
        dst_port = int(e.dst_port)

        if not passes_filters(comm, src_ip, dst_ip, src_port, dst_port):
            return

        k8s = k8s_hints_from_pid(pid)

        # Shared summary
        top_comm[comm] += 1
        tuple_s = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        top_tuple[tuple_s] += 1
        if dst_port:
            top_ports[dst_port] += 1
        if src_port:
            top_ports[src_port] += 1

        if evt_type == 1:  # TCP state
            old_s = TCP_STATES.get(int(e.oldstate), str(int(e.oldstate)))
            new_s = TCP_STATES.get(int(e.newstate), str(int(e.newstate)))
            tcp_state_transitions[f"{old_s}->{new_s}"] += 1
            tcp_state_by_comm[f"{comm}:{new_s}"] += 1

            role = role_cache_get_or_set(src_ip, src_port, dst_ip, dst_port, old_s, new_s)

            obj = {
                "ts": utc_ts(),
                "type": "tcp_state",
                "node": args.node,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "comm": comm,
                "tuple": tuple_s,
                "old_state": old_s,
                "new_state": new_s,
                "role": {
                    "client": role.client,
                    "server": role.server,
                    "service_port": role.service_port,
                    "confidence": role.confidence,
                },
                "k8s": k8s,
            }
            write_event(obj)
            if out_tcp:
                write_jsonl(out_tcp, obj)

        elif evt_type == 2:  # UDP send
            bytes_n = int(e.bytes)
            obj = {
                "ts": utc_ts(),
                "type": "udp_send",
                "node": args.node,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "comm": comm,
                "tuple": tuple_s,
                "bytes": bytes_n,
                "k8s": k8s,
            }
            write_event(obj)
            if out_us:
                write_jsonl(out_us, obj)

            if dst_port:
                udp_sends_by_port[dst_port] += 1
            if dst_port == 53:
                udp_dns_sends_by_comm[comm] += 1
                key = (k8s.get("pod_uid", "-"), k8s.get("container_hint", "-"), comm, dst_ip)
                dns_send_key[key] += 1

        elif evt_type == 3:  # UDP recv
            bytes_n = int(e.bytes)
            obj = {
                "ts": utc_ts(),
                "type": "udp_recv",
                "node": args.node,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "comm": comm,
                "tuple": tuple_s,
                "bytes": bytes_n,
                "k8s": k8s,
            }
            write_event(obj)
            if out_ur:
                write_jsonl(out_ur, obj)

            # src_port is remote port when msg_name is available (DNS replies show src_port=53)
            if src_port:
                udp_recvs_by_port[src_port] += 1
            if src_port == 53:
                udp_dns_recvs_by_comm[comm] += 1
                key = (k8s.get("pod_uid", "-"), k8s.get("container_hint", "-"), comm, src_ip)
                dns_recv_key[key] += 1

        elif evt_type == 4:  # retrans
            obj = {
                "ts": utc_ts(),
                "type": "tcp_retransmit",
                "node": args.node,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "comm": comm,
                "k8s": k8s,
            }
            write_event(obj)
            if out_rt:
                write_jsonl(out_rt, obj)
            tcp_retrans_by_comm[comm] += 1

        else:
            dropped_parse += 1

    # Perf buffer
    b["events"].open_perf_buffer(handle_event)

    print(f"[kube_socket_snapshot] node={args.node} duration={args.duration}s out={args.out_dir}")
    print(f"[kube_socket_snapshot] writing: {files.events_jsonl}")
    if args.split_logs:
        print("[kube_socket_snapshot] split logs enabled:")
        for p in (files.tcp_jsonl, files.udp_send_jsonl, files.udp_recv_jsonl, files.retrans_jsonl):
            if p:
                print(f"  - {p}")

    start = time.time()
    deadline = start + max(1, args.duration)

    try:
        while time.time() < deadline:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[kube_socket_snapshot] interrupted; finalizing...")
    finally:
        _close_all()

    node_meta["ts_end"] = utc_ts()
    node_meta["events_written"] = event_count
    node_meta["events_dropped_parse"] = dropped_parse
    with open(files.node_json, "w", encoding="utf-8") as f:
        json.dump(node_meta, f, indent=2)

    def top_n(counter: Counter, n: int = 20) -> List[Dict[str, Any]]:
        return [{"key": k, "count": v} for k, v in counter.most_common(n)]

    dns_suspects = []
    for (pod_uid, container_hint, comm, dns_ip), scount in dns_send_key.most_common(200):
        rcount = dns_recv_key.get((pod_uid, container_hint, comm, dns_ip), 0)
        if scount >= 10 and rcount == 0:
            dns_suspects.append({
                "pod_uid": pod_uid,
                "container_hint": (container_hint[:16] + "…") if container_hint not in ("-", "") and len(container_hint) > 16 else container_hint,
                "comm": comm,
                "dns_server_ip": dns_ip,
                "udp_dns_sends": scount,
                "udp_dns_recvs_from_server": rcount,
                "interpretation": "Many UDP DNS sends to this server but no UDP replies observed (heuristic). Check policy/routing/CoreDNS/NodeLocalDNS health.",
            })

    summary = {
        "tool": "kube_socket_snapshot",
        "version": "0.2",
        "node": args.node,
        "ts_start": node_meta["ts_start"],
        "ts_end": node_meta["ts_end"],
        "events_written": event_count,
        "events_dropped_parse": dropped_parse,
        "top": {
            "comm": top_n(top_comm, 30),
            "tuples": top_n(top_tuple, 30),
            "ports": top_n(top_ports, 30),
            "tcp_state_transitions": top_n(tcp_state_transitions, 40),
            "tcp_states_by_comm": top_n(tcp_state_by_comm, 40),
            "udp_sends_by_port": top_n(udp_sends_by_port, 30),
            "udp_recvs_by_port": top_n(udp_recvs_by_port, 30),
            "udp_dns_sends_by_comm": top_n(udp_dns_sends_by_comm, 30),
            "udp_dns_recvs_by_comm": top_n(udp_dns_recvs_by_comm, 30),
            "tcp_retrans_by_comm": top_n(tcp_retrans_by_comm, 30),
            "dns_suspects": dns_suspects[:50],
        },
        "files": node_meta["files"],
    }

    with open(files.summary_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Bundle everything
    bundle_members = [
        files.events_jsonl,
        files.summary_json,
        files.node_json,
    ]
    if files.tcp_jsonl:
        bundle_members.append(files.tcp_jsonl)
    if files.udp_send_jsonl:
        bundle_members.append(files.udp_send_jsonl)
    if files.udp_recv_jsonl:
        bundle_members.append(files.udp_recv_jsonl)
    if files.retrans_jsonl and args.include_retrans:
        bundle_members.append(files.retrans_jsonl)

    try:
        with tarfile.open(files.bundle_tgz, "w:gz") as tar:
            for p in bundle_members:
                if p and os.path.exists(p):
                    tar.add(p, arcname=os.path.basename(p))
    except Exception as e:
        print(f"[kube_socket_snapshot] warning: failed to create bundle: {e}", file=sys.stderr)
    else:
        print(f"[kube_socket_snapshot] bundle written: {files.bundle_tgz}")

    print(f"[kube_socket_snapshot] summary written: {files.summary_json}")
    print(f"[kube_socket_snapshot] events written: {files.events_jsonl}")


if __name__ == "__main__":
    main()
