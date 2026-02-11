#!/usr/bin/env python3
"""
dns_snoop.py — DNS-focused socket snoop (BETA)

Goal:
- Make DNS troubleshooting “plain and boring” by showing:
  - Which process is generating DNS traffic
  - Which resolver(s) it targets
  - Query/response rates and basic health signals
  - TCP fallback/DoT/DoH visibility (optional)

What this script does (BETA):
- eBPF/BCC metadata capture for:
  - UDP/53 send + recv (best-effort) with PID/UID/COMM, 4-tuple, bytes
  - TCP state transitions (your original tracepoint) for TCP/53, 853, 443 (and all TCP if you want)
  - tcp_v4_connect return code (errno) to spot connection failures (useful for DoT/DoH/TCP fallback)
- Userspace aggregation:
  - Per-process and per-upstream resolver stats (qps-ish)
  - “Outstanding” estimate: sent - received per (pid, resolver)
  - Simple anomaly triggers
- Optional: launch tcpdump in parallel (you can always run tcpdump manually too)

Limitations (BETA / honest):
- IPv4 only
- UDP recv path is “best effort” across kernel variants; connected UDP is most reliable
- No deep DNS payload parsing yet (QNAME/QTYPE/RCODE). This is the next step once your
  baseline correlation is stable and you decide your privacy/compliance stance.

Requires:
- Linux + BCC (python3-bcc)
- root (or CAP_BPF/CAP_SYS_ADMIN depending on distro/kernel lockdown)

"""

import argparse
import os
import sys
import time
import signal
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
from typing import Any, Dict, Tuple, Optional, List

# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DNS Snoop (BCC/eBPF) — DNS metadata + health signals")
    p.add_argument("--iface", default=None, help="Interface hint for tcpdump (optional)")
    p.add_argument("--pid", type=int, default=None, help="Filter by PID")
    p.add_argument("--comm", type=str, default=None, help="Filter by process name (substring match)")
    p.add_argument("--resolver", type=str, default=None, help="Filter by resolver IPv4 (destination IP)")
    p.add_argument("--port", type=int, default=53, help="DNS port to focus on (default: 53)")
    p.add_argument("--show-tcp", action="store_true", help="Also show TCP state transitions (useful for TCP fallback/DoT/DoH)")
    p.add_argument("--tcp-ports", default="53,853,443", help="Comma-separated TCP ports to highlight (default: 53,853,443)")
    p.add_argument("--interval", type=float, default=2.0, help="Summary print interval seconds (default: 2.0)")
    p.add_argument("--top", type=int, default=10, help="How many rows to show in summaries (default: 10)")
    p.add_argument("--log-file", default=os.environ.get("DNS_SNOOP_LOG", "/var/log/dns_snoop.log"),
                   help="Log file path (default: /var/log/dns_snoop.log or $DNS_SNOOP_LOG)")
    p.add_argument("--json", action="store_true", help="Emit event lines as JSON-ish dicts (stdout)")
    p.add_argument("--quiet-events", action="store_true", help="Don’t print per-event lines; only summaries")
    p.add_argument("--tcpdump", action="store_true", help="Launch a parallel tcpdump tailored for DNS (optional)")
    p.add_argument("--tcpdump-seconds", type=int, default=0,
                   help="If set (>0), auto-stop tcpdump after N seconds")
    p.add_argument("--tcpdump-extra", default="",
                   help="Extra raw tcpdump args (e.g. '-vv -s 0'). Use carefully.")
    p.add_argument("--anomaly-outstanding", type=int, default=200,
                   help="Trigger anomaly note if outstanding (sent-recv) per resolver exceeds this (default: 200)")
    p.add_argument("--anomaly-qps", type=int, default=300,
                   help="Trigger anomaly note if per-pid DNS sends in last interval exceed this (default: 300)")
    return p.parse_args()


# --------------------------------------------------------------------------------------
# BPF program (UDP + TCP helpers)
# --------------------------------------------------------------------------------------

BPF_PROGRAM = r"""
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ 0x85
#endif
#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0xa5
#endif

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16

enum proto_t {
    PROTO_UDP = 17,
    PROTO_TCP = 6,
};

enum dir_t {
    DIR_TX = 1,
    DIR_RX = 2,
};

struct dns_evt_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;

    u32 bytes;
    u8  proto;   // 17 UDP, 6 TCP
    u8  dir;     // 1 TX, 2 RX

    // TCP extras
    s32 tcp_state;   // newstate if available (or 0)
    s32 tcp_errno;   // connect() errno (0 ok, negative or positive depending)
};

BPF_PERF_OUTPUT(dns_events);
BPF_PERF_OUTPUT(tcp_events);
BPF_PERF_OUTPUT(tcp_conn_events);

// Safe-ish read of ppid
static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (task && task->real_parent) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    }
    return ppid;
}

static __always_inline int fill_inet4(struct dns_evt_t *e, struct sock *sk) {
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;

    // Common inet_sock fields
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    e->src_ip = saddr;
    e->dst_ip = daddr;
    e->src_port = sport;
    e->dst_port = ntohs(dport);
    return 0;
}

// -------------------- UDP TX --------------------
// kprobe: udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    if (!sk) return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    struct dns_evt_t e = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = pid_tgid >> 32;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    fill_inet4(&e, sk);

    e.bytes = (u32)len;
    e.proto = PROTO_UDP;
    e.dir = DIR_TX;

    dns_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// -------------------- UDP RX (best effort) --------------------
// kprobe: udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    if (!sk) return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    struct dns_evt_t e = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = pid_tgid >> 32;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // For connected UDP sockets, skc_daddr/dport usually reflect the peer.
    // For unconnected sockets, this can be 0; userspace will filter and still
    // count bytes/port-based where possible.
    fill_inet4(&e, sk);

    e.bytes = (u32)len;
    e.proto = PROTO_UDP;
    e.dir = DIR_RX;

    dns_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// -------------------- TCP connect errno --------------------
// kprobe/kretprobe: tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
BPF_HASH(connectsock, u64, struct sock*);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 tid = bpf_get_current_pid_tgid();
    connectsock.update(&tid, &sk);
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    struct sock **skpp = connectsock.lookup(&tid);
    if (!skpp) return 0;

    struct sock *sk = *skpp;
    connectsock.delete(&tid);
    if (!sk) return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    int ret = PT_REGS_RC(ctx); // 0 ok, -errno on failure

    struct dns_evt_t e = {};
    e.pid = tid >> 32;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    fill_inet4(&e, sk);
    e.proto = PROTO_TCP;
    e.dir = DIR_TX;
    e.tcp_errno = ret;

    tcp_conn_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// -------------------- TCP state transitions (your original) --------------------
// Tracepoint: sock:inet_sock_set_state
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->family != AF_INET)
        return 0;

    struct dns_evt_t e = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = pid_tgid >> 32;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // args->saddr/daddr are __u8[4] on many modern kernels; pack to u32
    e.src_ip = ((u32)args->saddr[0] << 24) |
               ((u32)args->saddr[1] << 16) |
               ((u32)args->saddr[2] <<  8) |
               ((u32)args->saddr[3]);
    e.dst_ip = ((u32)args->daddr[0] << 24) |
               ((u32)args->daddr[1] << 16) |
               ((u32)args->daddr[2] <<  8) |
               ((u32)args->daddr[3]);

    e.src_port = ntohs(args->sport);
    e.dst_port = ntohs(args->dport);
    e.proto = PROTO_TCP;
    e.dir = DIR_TX;
    e.tcp_state = args->newstate;

    tcp_events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


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


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def format_ip_kernel_order(ip_u32: int) -> str:
    # ip_u32 from skc_* fields is usually native-endian. For AF_INET fields, bcc gives host order
    # often as little-endian; we normalize by treating as packed 32-bit and extracting bytes.
    # This matches typical BCC examples.
    return ".".join(str((ip_u32 >> s) & 0xFF) for s in (0, 8, 16, 24))

def format_ip_network_packed(ip_u32: int) -> str:
    # For tracepoint packed as big-endian in our packing above:
    return ".".join(str((ip_u32 >> s) & 0xFF) for s in (24, 16, 8, 0))

def now_ts() -> str:
    return datetime.now().strftime("%b %d %Y %H:%M:%S.%f")[:-3]


def safe_open_log(path: str) -> str:
    try:
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("dns_snoop log\n" + "=" * 80 + "\n")
        return path
    except PermissionError:
        fallback = "./dns_snoop.log"
        with open(fallback, "a") as f:
            f.write("dns_snoop log (fallback)\n" + "=" * 80 + "\n")
        return fallback


@dataclass
class CounterWindow:
    # Rolling small window for “qps-ish” anomaly notes
    sent: int = 0
    recv: int = 0
    ts_start: float = field(default_factory=time.time)

    def reset_if_needed(self, interval: float) -> None:
        if time.time() - self.ts_start >= interval:
            self.sent = 0
            self.recv = 0
            self.ts_start = time.time()


# --------------------------------------------------------------------------------------
# tcpdump integration (optional)
# --------------------------------------------------------------------------------------

def launch_tcpdump(iface: Optional[str], port: int, extra: str, seconds: int) -> Optional[subprocess.Popen]:
    # Minimal sane default filter: DNS over UDP/TCP for port
    flt = f"(udp port {port} or tcp port {port})"
    cmd = ["tcpdump"]
    if iface:
        cmd += ["-i", iface]
    # Make output useful but not insane; user can override with --tcpdump-extra
    cmd += ["-nn", "-tt"]
    if extra.strip():
        cmd += extra.strip().split()
    cmd += [flt]

    try:
        p = subprocess.Popen(cmd, stdout=sys.stderr, stderr=sys.stderr, preexec_fn=os.setsid)
    except FileNotFoundError:
        print("[dns-snoop] tcpdump not found in PATH.", file=sys.stderr)
        return None

    if seconds > 0:
        def killer():
            time.sleep(seconds)
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                pass
        import threading
        threading.Thread(target=killer, daemon=True).start()

    print(f"[dns-snoop] tcpdump launched: {' '.join(cmd)}", file=sys.stderr)
    return p


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

def main() -> None:
    if os.uname().sysname.lower() != "linux":
        print("This tool requires Linux (eBPF/BCC).", file=sys.stderr)
        sys.exit(1)

    args = parse_args()

    try:
        from bcc import BPF
    except ImportError:
        print("Error: python3-bcc (BCC bindings) not available.", file=sys.stderr)
        sys.exit(1)

    log_file = safe_open_log(args.log_file)

    # Highlight TCP ports
    tcp_ports: List[int] = []
    try:
        tcp_ports = [int(x.strip()) for x in args.tcp_ports.split(",") if x.strip()]
    except Exception:
        tcp_ports = [53, 853, 443]

    # Optionally run tcpdump alongside
    tcpdump_proc: Optional[subprocess.Popen] = None
    if args.tcpdump:
        tcpdump_proc = launch_tcpdump(args.iface, args.port, args.tcpdump_extra, args.tcpdump_seconds)

    # Compile and attach BPF
    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        print(f"[dns-snoop] Failed to compile BPF program: {e}", file=sys.stderr)
        sys.exit(1)

    # Aggregation structures
    # Keys:
    #  - per_pid: pid -> stats
    #  - per_pid_resolver: (pid, resolver_ip) -> stats
    per_pid = defaultdict(lambda: {"sent": 0, "recv": 0})
    per_pid_comm: Dict[int, str] = {}
    per_pid_uid: Dict[int, int] = {}
    per_pid_ppid: Dict[int, int] = {}

    per_pid_resolver = defaultdict(lambda: {"sent": 0, "recv": 0, "bytes_tx": 0, "bytes_rx": 0})
    resolver_totals = defaultdict(lambda: {"sent": 0, "recv": 0, "bytes_tx": 0, "bytes_rx": 0})

    # For anomaly heuristics (short rolling window)
    win_by_pid = defaultdict(CounterWindow)
    win_interval = max(1.0, float(args.interval))

    # Recent event de-dup (avoid spam in bursty kernels)
    recent_events = deque(maxlen=5000)

    # Track TCP connect errno stats
    tcp_connect_errs = defaultdict(int)  # (pid, dst_ip, dst_port, errno) -> count
    tcp_state_hits = defaultdict(int)    # (pid, dst_ip, dst_port, state) -> count

    def passes_filters(pid: int, comm: str, dst_ip: str) -> bool:
        if args.pid is not None and pid != args.pid:
            return False
        if args.comm and args.comm.lower() not in comm.lower():
            return False
        if args.resolver and dst_ip != args.resolver:
            return False
        return True

    def log_line(s: str) -> None:
        try:
            with open(log_file, "a") as f:
                f.write(s + "\n")
        except Exception:
            pass

    # ------------------- Event handlers -------------------

    def handle_dns_event(cpu: int, data: Any, size: int) -> None:
        e = b["dns_events"].event(data)

        pid = int(e.pid)
        comm = e.comm.decode(errors="ignore").strip("\x00")
        uid = int(e.uid)
        ppid = int(e.ppid)

        # inet_sock fields for UDP often yield src_ip in “host-ish” byte order.
        src_ip = format_ip_kernel_order(int(e.src_ip))
        dst_ip = format_ip_kernel_order(int(e.dst_ip))

        src_port = int(e.src_port)
        dst_port = int(e.dst_port)
        bytes_ = int(e.bytes)
        direction = "TX" if int(e.dir) == 1 else "RX"

        # Focus on DNS port (default 53) but allow:
        # - TX to dst_port == args.port
        # - RX from src/dst port == args.port (best effort)
        port_focus = int(args.port)
        is_dnsish = (dst_port == port_focus) or (src_port == port_focus)

        if not is_dnsish:
            return

        if not passes_filters(pid, comm, dst_ip):
            return

        # Skip invalid (common for unconnected UDP recv)
        # but still allow if one side has :53 (so we see something)
        if dst_ip == "0.0.0.0" and dst_port != port_focus and src_port != port_focus:
            return

        # De-dup key
        key = (pid, src_ip, src_port, dst_ip, dst_port, direction, bytes_)
        if key in recent_events:
            return
        recent_events.append(key)

        per_pid_comm[pid] = comm
        per_pid_uid[pid] = uid
        per_pid_ppid[pid] = ppid

        # Heuristics: treat resolver as the peer on port 53
        # TX: resolver is dst_ip:dst_port
        # RX: resolver is src_ip:src_port (if src_port==53), else dst if dst_port==53
        if direction == "TX":
            resolver_ip = dst_ip
            resolver_port = dst_port
            per_pid[pid]["sent"] += 1
            win = win_by_pid[pid]
            win.reset_if_needed(win_interval)
            win.sent += 1
            per_pid_resolver[(pid, resolver_ip)]["sent"] += 1
            per_pid_resolver[(pid, resolver_ip)]["bytes_tx"] += bytes_
            resolver_totals[resolver_ip]["sent"] += 1
            resolver_totals[resolver_ip]["bytes_tx"] += bytes_
        else:
            if src_port == port_focus:
                resolver_ip = src_ip
                resolver_port = src_port
            else:
                resolver_ip = dst_ip
                resolver_port = dst_port
            per_pid[pid]["recv"] += 1
            win = win_by_pid[pid]
            win.reset_if_needed(win_interval)
            win.recv += 1
            per_pid_resolver[(pid, resolver_ip)]["recv"] += 1
            per_pid_resolver[(pid, resolver_ip)]["bytes_rx"] += bytes_
            resolver_totals[resolver_ip]["recv"] += 1
            resolver_totals[resolver_ip]["bytes_rx"] += bytes_

        outstanding = per_pid_resolver[(pid, resolver_ip)]["sent"] - per_pid_resolver[(pid, resolver_ip)]["recv"]

        entry = {
            "ts": now_ts(),
            "type": "dns-meta",
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "comm": comm,
            "dir": direction,
            "proto": "UDP",
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "bytes": bytes_,
            "resolver": f"{resolver_ip}:{resolver_port}",
            "outstanding_est": outstanding,
        }

        if not args.quiet_events:
            if args.json:
                print(entry)
            else:
                print(f"[{entry['ts']}] UDP/{direction} {comm}({pid}) {entry['src']} -> {entry['dst']} bytes={bytes_} "
                      f"resolver={entry['resolver']} outstanding~{outstanding}")

        # Log
        log_line(str(entry))

    def handle_tcp_connect(cpu: int, data: Any, size: int) -> None:
        e = b["tcp_conn_events"].event(data)
        pid = int(e.pid)
        comm = e.comm.decode(errors="ignore").strip("\x00")

        src_ip = format_ip_kernel_order(int(e.src_ip))
        dst_ip = format_ip_kernel_order(int(e.dst_ip))
        src_port = int(e.src_port)
        dst_port = int(e.dst_port)

        if dst_port not in tcp_ports:
            return
        if not passes_filters(pid, comm, dst_ip):
            return

        ret = int(e.tcp_errno)  # 0 ok, -errno
        tcp_connect_errs[(pid, dst_ip, dst_port, ret)] += 1

        if not args.quiet_events:
            print(f"[{now_ts()}] TCP/connect {comm}({pid}) {src_ip}:{src_port} -> {dst_ip}:{dst_port} ret={ret}")

        log_line(str({
            "ts": now_ts(),
            "type": "tcp-connect",
            "pid": pid,
            "comm": comm,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "ret": ret,
        }))

    def handle_tcp_state(cpu: int, data: Any, size: int) -> None:
        if not args.show_tcp:
            return

        e = b["tcp_events"].event(data)
        pid = int(e.pid)
        comm = e.comm.decode(errors="ignore").strip("\x00")

        # These are packed big-endian style from our tracepoint packing
        src_ip = format_ip_network_packed(int(e.src_ip))
        dst_ip = format_ip_network_packed(int(e.dst_ip))
        src_port = int(e.src_port)
        dst_port = int(e.dst_port)

        if dst_port not in tcp_ports and src_port not in tcp_ports:
            return
        if not passes_filters(pid, comm, dst_ip):
            return

        st = int(e.tcp_state)
        st_str = TCP_STATES.get(st, f"STATE_{st}")
        tcp_state_hits[(pid, dst_ip, dst_port, st)] += 1

        if not args.quiet_events:
            print(f"[{now_ts()}] TCP/state {comm}({pid}) {src_ip}:{src_port} -> {dst_ip}:{dst_port} {st_str}")

        log_line(str({
            "ts": now_ts(),
            "type": "tcp-state",
            "pid": pid,
            "comm": comm,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "state": st_str,
        }))

    # Attach perf buffers
    b["dns_events"].open_perf_buffer(handle_dns_event)
    b["tcp_conn_events"].open_perf_buffer(handle_tcp_connect)
    b["tcp_events"].open_perf_buffer(handle_tcp_state)

    # ------------------- Summary printer -------------------

    def print_summary() -> None:
        ts = now_ts()

        # Build top talkers by PID
        rows = []
        for pid, st in per_pid.items():
            comm = per_pid_comm.get(pid, "?")
            uid = per_pid_uid.get(pid, -1)
            sent = st["sent"]
            recv = st["recv"]
            rows.append((sent, recv, pid, uid, comm))
        rows.sort(reverse=True)

        # Resolver health totals
        rrows = []
        for rip, st in resolver_totals.items():
            sent = st["sent"]
            recv = st["recv"]
            out = sent - recv
            rrows.append((out, sent, recv, rip, st["bytes_tx"], st["bytes_rx"]))
        rrows.sort(reverse=True)

        # Anomaly notes
        anomaly_notes = []
        for pid, w in win_by_pid.items():
            w.reset_if_needed(win_interval)
            if w.sent >= args.anomaly_qps:
                anomaly_notes.append(f"PID {pid} ({per_pid_comm.get(pid,'?')}): high send rate ~{w.sent}/{int(win_interval)}s")
        for (pid, rip), st in per_pid_resolver.items():
            out = st["sent"] - st["recv"]
            if out >= args.anomaly_outstanding:
                anomaly_notes.append(f"PID {pid} ({per_pid_comm.get(pid,'?')}) -> {rip}: outstanding~{out}")

        print("\n" + "=" * 100)
        print(f"[{ts}] DNS SUMMARY  (port {args.port})  log={log_file}")
        if anomaly_notes:
            print("ANOMALIES:")
            for n in anomaly_notes[:20]:
                print(f"  - {n}")
        else:
            print("ANOMALIES: none")

        print("\nTOP PIDs (by DNS sends):")
        print(f"{'SENT':>8} {'RECV':>8} {'PID':>7} {'UID':>7}  COMM")
        for sent, recv, pid, uid, comm in rows[: args.top]:
            print(f"{sent:8d} {recv:8d} {pid:7d} {uid:7d}  {comm}")

        print("\nRESOLVERS (by outstanding = sent-recv):")
        print(f"{'OUT':>8} {'SENT':>8} {'RECV':>8} {'RESOLVER':>16} {'TX_BYTES':>10} {'RX_BYTES':>10}")
        for out, sent, recv, rip, txb, rxb in rrows[: args.top]:
            print(f"{out:8d} {sent:8d} {recv:8d} {rip:16s} {txb:10d} {rxb:10d}")

        if args.show_tcp:
            print("\nTCP CONNECT ERRORS (DoT/DoH/TCP fallback hints):")
            # show top error tuples by count
            cerrs = sorted(((c, k) for k, c in tcp_connect_errs.items()), reverse=True)[: args.top]
            if not cerrs:
                print("  none")
            else:
                for count, (pid, dip, dport, ret) in cerrs:
                    print(f"  count={count} pid={pid} comm={per_pid_comm.get(pid,'?')} dst={dip}:{dport} ret={ret}")

        print("=" * 100 + "\n")

    # ------------------- Loop -------------------

    print(f"[dns-snoop] Running. port={args.port} show_tcp={args.show_tcp} tcpdump={bool(tcpdump_proc)} log={log_file}")
    last_summary = time.time()

    try:
        while True:
            b.perf_buffer_poll(timeout=200)
            if time.time() - last_summary >= args.interval:
                print_summary()
                last_summary = time.time()
    except KeyboardInterrupt:
        print("\n[dns-snoop] stopping...")
    finally:
        if tcpdump_proc is not None:
            try:
                os.killpg(os.getpgid(tcpdump_proc.pid), signal.SIGTERM)
            except Exception:
                pass


if __name__ == "__main__":
    main()
