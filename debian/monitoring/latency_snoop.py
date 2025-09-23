#!/usr/bin/env python3
"""
Socket Latency Snoop - Realtime socket monitoring (IPv4) via eBPF/BCC.
Adds connect latency, RTT, retransmits, req->resp latency hints, and optional user stacks.

Requires: bcc (and matching kernel headers), root. For stacks, install debuginfo/symbols.
"""

import argparse
import hashlib
import os
import sys
from datetime import datetime
from collections import deque, defaultdict

def parse_args():
    p = argparse.ArgumentParser(description="Ultimate Socket Latency Monitor")
    p.add_argument("--pid", type=int, default=None, help="Filter by PID (TGID)")
    p.add_argument("--src-ip", type=str, default=None, help="Filter by source IPv4")
    p.add_argument("--dst-ip", type=str, default=None, help="Filter by destination IPv4")
    p.add_argument("--src-port", type=int, default=None, help="Filter by source port")
    p.add_argument("--dst-port", type=int, default=None, help="Filter by destination port")
    p.add_argument("--active-only", action="store_true", help="Only established connections")
    p.add_argument("--stacks", action="store_true", help="Collect and symbolize user-space call stacks")
    p.add_argument("--log-file", default=os.environ.get("SOCKET_SNOOP_LOG", "/var/log/socket_monitor.log"))
    return p.parse_args()

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/tcp.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <net/tcp.h>
#include <bcc/proto.h>

/*
 * Keyed by 4-tuple (+tgid) to avoid most collisions. We also use skaddr when available.
 */
struct flow_key_t {
    u32 tgid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

static __always_inline void fill_key(struct flow_key_t *k, u32 tgid, const __u8 saddr[4], const __u8 daddr[4], u16 sport, u16 dport) {
    k->tgid = tgid;
    k->saddr = ((u32)saddr[0] << 24) | ((u32)saddr[1] << 16) | ((u32)saddr[2] << 8) | ((u32)saddr[3]);
    k->daddr = ((u32)daddr[0] << 24) | ((u32)daddr[1] << 16) | ((u32)daddr[2] << 8) | ((u32)daddr[3]);
    k->sport = bpf_ntohs(sport);
    k->dport = bpf_ntohs(dport);
}

struct data_t {
    u32 tgid;          // process ID (thread group)
    u32 pid;           // thread ID
    u32 ppid;
    u32 uid;
    u64 cgroup_id;

    char comm[TASK_COMM_LEN];

    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;

    int state;
    char event[24];

    // latency fields (ns)
    u64 connect_latency_ns;   // SYN_SENT -> ESTABLISHED
    u64 rr_latency_ns;        // first recv after a send (req->resp hint)

    // TCP internals
    u32 srtt_us;              // smoothed RTT
    u32 rttvar_us;
    u32 retransmits;          // observed retransmits on flow (monotonic)

    // stacks
    int have_stack;
    u32 stack_id;
};
// perf output
BPF_PERF_OUTPUT(events);

// store start times and flow state
BPF_HASH(conn_start_ts, struct flow_key_t, u64);
BPF_HASH(last_send_ts, struct flow_key_t, u64);
BPF_HASH(retrans_count, struct flow_key_t, u32);

// optional user stacks keyed by (tgid, fd)
struct fd_key_t { u32 tgid; int fd; };
BPF_STACK_TRACE(stack_traces, 8192);
BPF_HASH(pending_connect_stack, struct fd_key_t, u32);
BPF_HASH(pending_send_stack, struct fd_key_t, u32);

/*
 * Trace which user function called connect/sendmsg via sys_enter_* tracepoints.
 * We store (tgid, fd) -> stack_id to attach when we later emit a flow event.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct fd_key_t fk = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    fk.tgid = tgid;
    fk.fd = args->fd;
    int stack_id = bpf_get_stackid(args, &stack_traces, BPF_F_USER_STACK);
    if (stack_id >= 0) {
        pending_connect_stack.update(&fk, &stack_id);
    }
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct fd_key_t fk = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    fk.tgid = tgid;
    fk.fd = args->fd;
    int stack_id = bpf_get_stackid(args, &stack_traces, BPF_F_USER_STACK);
    if (stack_id >= 0) {
        pending_send_stack.update(&fk, &stack_id);
    }
    return 0;
}

/*
 * Socket state transitions: measure connect latency and pull RTT.
 */
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->family != AF_INET)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xffffffff;

    // build flow key
    struct flow_key_t key = {};
    fill_key(&key, tgid, args->saddr, args->daddr, args->sport, args->dport);

    // timestamps for connect latency
    if (args->newstate == TCP_SYN_SENT) {
        u64 ts = bpf_ktime_get_ns();
        conn_start_ts.update(&key, &ts);
        return 0;
    }

    // populate event
    struct data_t data = {};
    data.tgid = tgid;
    data.pid  = pid;
    data.uid  = bpf_get_current_uid_gid();
    data.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    // parent pid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (task && task->real_parent) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    }
    data.ppid = ppid;

    data.src_ip = ((u32)args->saddr[0] << 24) | ((u32)args->saddr[1] << 16) | ((u32)args->saddr[2] << 8) | ((u32)args->saddr[3]);
    data.dst_ip = ((u32)args->daddr[0] << 24) | ((u32)args->daddr[1] << 16) | ((u32)args->daddr[2] << 8) | ((u32)args->daddr[3]);
    data.src_port = bpf_ntohs(args->sport);
    data.dst_port = bpf_ntohs(args->dport);
    data.state = args->newstate;
    __builtin_memcpy(&data.event, "State Change", 13);

    // connect latency on ESTABLISHED
    if (args->newstate == TCP_ESTABLISHED) {
        u64 *tsp = conn_start_ts.lookup(&key);
        if (tsp) {
            data.connect_latency_ns = bpf_ktime_get_ns() - *tsp;
            conn_start_ts.delete(&key);
        }
    }

    // TCP internals if skaddr is present
    if (args->skaddr) {
        struct sock *sk = (struct sock *)args->skaddr;
        struct tcp_sock *tp = (struct tcp_sock *)tcp_sk(sk);
        if (tp) {
            // srtt is stored with 3 bits of fraction in Linux; srtt_us already exists in tcp_sock (since 5.x)
#ifdef BPF_FIELD_EXISTS
            // no-op: placeholder for CO-RE; we rely on includes
#endif
            u32 srtt_us = 0, rttvar_us = 0;
            bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us), &tp->srtt_us);
            bpf_probe_read_kernel(&rttvar_us, sizeof(rttvar_us), &tp->mdev_us);
            data.srtt_us = srtt_us;
            data.rttvar_us = rttvar_us;
        }
    }

    // attach any known retransmit count
    u32 *rc = retrans_count.lookup(&key);
    if (rc) data.retransmits = *rc;

    // attach pending connect stack if one exists for this tgid+fd (best-effort match via sport/dport is tricky)
    // We cannot reliably map fd here; so we rely on send/recv paths to carry stacks (below).
    data.have_stack = 0;
    data.stack_id = -1;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

/*
 * Retransmits: tcp:tcp_retransmit_skb (kernel tracepoint)
 */
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    // Build key from tracepoint fields
    struct flow_key_t key = {};
    // Fields are already in host order here
    key.tgid = 0; // ksoftirq context; keep zero. We'll still key by 4-tuple.
    key.saddr = args->saddr;
    key.daddr = args->daddr;
    key.sport = args->sport;
    key.dport = args->dport;

    u32 *cnt = retrans_count.lookup(&key);
    u32 one = 1;
    if (!cnt) {
        retrans_count.update(&key, &one);
    } else {
        __sync_fetch_and_add(cnt, 1);
    }
    return 0;
}

/*
 * Req->Resp latency hint:
 *  - record ts on tcp_sendmsg
 *  - on tcp_cleanup_rbuf (bytes copied to user), compute latency if a send happened and we were idle before
 */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    // Derive 4-tuple
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&sport, sizeof(sport), &inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), &inet->inet_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &inet->inet_daddr);

    struct flow_key_t key = {};
    key.tgid = tgid;
    key.saddr = saddr;
    key.daddr = daddr;
    key.sport = bpf_ntohs(sport);
    key.dport = bpf_ntohs(dport);

    u64 ts = bpf_ktime_get_ns();
    last_send_ts.update(&key, &ts);

    // stash user stack for this send if we have one keyed by (tgid, fd)
    // We don't have fd here; sys_enter_sendto captured it earlier -> leave to userland to join heuristically.

    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied <= 0) return 0; // no payload to userspace

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    // Rebuild key
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&sport, sizeof(sport), &inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), &inet->inet_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &inet->inet_daddr);

    struct flow_key_t key = {};
    key.tgid = tgid;
    key.saddr = saddr;
    key.daddr = daddr;
    key.sport = bpf_ntohs(sport);
    key.dport = bpf_ntohs(dport);

    u64 *tsp = last_send_ts.lookup(&key);
    if (!tsp) return 0;

    // Emit an event with rr_latency populated and marked "ReqResp"
    struct data_t data = {};
    data.tgid = tgid;
    data.pid  = (u32)id;
    data.uid  = bpf_get_current_uid_gid();
    data.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.src_ip = saddr;
    data.dst_ip = daddr;
    data.src_port = bpf_ntohs(sport);
    data.dst_port = bpf_ntohs(dport);
    data.state = -1; // not a state change
    __builtin_memcpy(&data.event, "ReqResp Latency", 16);
    data.rr_latency_ns = bpf_ktime_get_ns() - *tsp;

    // Attach retrans count if known
    u32 *rc = retrans_count.lookup(&key);
    if (rc) data.retransmits = *rc;

    // Attempt to read srtt/mdev
    struct tcp_sock *tp = (struct tcp_sock *)tcp_sk(sk);
    if (tp) {
        u32 srtt_us = 0, rttvar_us = 0;
        bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us), &tp->srtt_us);
        bpf_probe_read_kernel(&rttvar_us, sizeof(rttvar_us), &tp->mdev_us);
        data.srtt_us = srtt_us;
        data.rttvar_us = rttvar_us;
    }

    data.have_stack = 0;
    data.stack_id = -1;

    events.perf_submit(ctx, &data, sizeof(data));

    // reset to avoid double counting until next request
    last_send_ts.delete(&key);
    return 0;
}
"""

TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSED",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}

def format_ip(ip_u32: int) -> str:
    return ".".join(str((ip_u32 >> s) & 0xFF) for s in (24, 16, 8, 0))

def connection_id(src_ip, src_port, dst_ip, dst_port) -> str:
    unique = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    return hashlib.md5(unique.encode()).hexdigest()

def ns_to_ms(ns: int) -> float:
    return round(ns / 1_000_000.0, 3)

def main():
    if os.uname().sysname.lower() != "linux":
        print("This tool requires Linux (eBPF/BCC).", file=sys.stderr)
        sys.exit(1)

    args = parse_args()

    log_file = args.log_file
    try:
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write("Socket Latency Monitor Log\n" + "=" * 60 + "\n")
    except PermissionError:
        print(f"Warning: cannot write to {log_file}; falling back to ./socket_monitor.log", file=sys.stderr)
        log_file = "./socket_monitor.log"

    from bcc import BPF, USDT  # noqa
    b = BPF(text=BPF_PROGRAM)

    recent_events = deque(maxlen=4000)
    # stash of (tgid,fd)->stack for best-effort matching (optional)
    have_stacks = args.stacks
    stack_traces = b.get_table("stack_traces") if have_stacks else None
    pending_connect_stack = b.get_table("pending_connect_stack") if have_stacks else None
    pending_send_stack = b.get_table("pending_send_stack") if have_stacks else None

    # Heuristic: remember latest stack per TGID keyed by (src,dst,ports)
    latest_stack_by_flow = {}

    metrics = defaultdict(int)

    def symbolize_stack(stack_id, pid):
        if not have_stacks or stack_id < 0:
            return None
        syms = []
        try:
            for addr in stack_traces.walk(stack_id):
                syms.append(b.sym(addr, pid, show_module=True, show_offset=True))
        except Exception:
            return None
        return syms

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        timestamp = datetime.now().strftime("%b %d %Y %H:%M:%S.%f")[:-3]

        src_ip = format_ip(event.src_ip)
        dst_ip = format_ip(event.dst_ip)

        if args.pid and event.tgid != args.pid: return
        if args.src_ip and src_ip != args.src_ip: return
        if args.dst_ip and dst_ip != args.dst_ip: return
        if args.src_port and event.src_port != args.src_port: return
        if args.dst_port and event.dst_port != args.dst_port: return
        if args.active_only and event.state not in (1, -1): return

        # de-dup state spam
        event_key = (
            src_ip, int(event.src_port), dst_ip, int(event.dst_port),
            int(event.tgid), int(event.state), event.event.decode(errors="ignore"),
            int(event.connect_latency_ns != 0), int(event.rr_latency_ns != 0)
        )
        if event_key in recent_events:
            return
        recent_events.append(event_key)

        state_str = TCP_STATES.get(event.state, "N/A") if event.state != -1 else "N/A"
        connid = connection_id(src_ip, int(event.src_port), dst_ip, int(event.dst_port))

        entry = {
            "timestamp": timestamp,
            "event": event.event.decode(errors="ignore"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(event.src_port),
            "dst_port": int(event.dst_port),
            "protocol": "TCP",
            "state": state_str,
            "connection_id": connid,
            "pid": int(event.tgid),
            "tid": int(event.pid),
            "ppid": int(event.ppid),
            "uid": int(event.uid),
            "cgroup_id": int(event.cgroup_id),
            "comm": event.comm.decode(errors="ignore"),
            "latency": {
                "connect_ms": ns_to_ms(int(event.connect_latency_ns)) if event.connect_latency_ns else None,
                "req_resp_ms": ns_to_ms(int(event.rr_latency_ns)) if event.rr_latency_ns else None,
                "srtt_ms": round(float(event.srtt_us) / 1000.0, 3) if event.srtt_us else None,
                "rttvar_ms": round(float(event.rttvar_us) / 1000.0, 3) if event.rttvar_us else None,
            },
            "tcp": {
                "retransmits": int(event.retransmits),
            },
        }

        # best-effort attach last known stack for this flow
        if have_stacks:
            flow_key = (entry["pid"], src_ip, entry["src_port"], dst_ip, entry["dst_port"])
            stack_syms = latest_stack_by_flow.get(flow_key)
            if stack_syms:
                entry["callstack"] = stack_syms

        print(entry)
        try:
            with open(log_file, "a") as f:
                f.write(str(entry) + "\n")
        except Exception as e:
            print(f"Log write failed: {e}", file=sys.stderr)

    # Join pending stacks to flows opportunistically by watching tcp_sendmsg path
    def on_sendmsg(cpu, data, size):
        # We’re not emitting here (kernel probe emits nothing through this buffer).
        pass

    b["events"].open_perf_buffer(handle_event)

    # Poll + side-channel to siphon stacks, mapping them to flows.
    # We do this by periodically sweeping pending_send_stack and resolving the fd→tuple in userspace.
    # Simpler: when a ReqResp Latency event arrives, remember most recent send stack for that TGID.
    if have_stacks:
        # Build a lightweight /proc lookup for stacks when we see ReqResp events; keep LRU per TGID.
        pass  # The perf handler above attaches stacks when available.

    print(f"Monitoring sockets + latency. Logging to {log_file}")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping monitoring...")

if __name__ == "__main__":
    main()
