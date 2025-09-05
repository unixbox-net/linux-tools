#!/usr/bin/env python3
"""
Socket Snoop - Realtime socket monitoring (IPv4) via eBPF/BCC.
Requires: bcc & matching kernel headers.
"""

import argparse
import hashlib
import os
import sys
from datetime import datetime
from collections import deque
from bcc import BPF

def parse_args():
    p = argparse.ArgumentParser(description="Enhanced Socket Monitoring Script")
    p.add_argument("--pid", type=int, default=None, help="Filter by PID")
    p.add_argument("--src-ip", type=str, default=None, help="Filter by source IPv4")
    p.add_argument("--dst-ip", type=str, default=None, help="Filter by destination IPv4")
    p.add_argument("--src-port", type=int, default=None, help="Filter by source port")
    p.add_argument("--dst-port", type=int, default=None, help="Filter by destination port")
    p.add_argument("--active-only", action="store_true", help="Only established connections")
    p.add_argument("--log-file", default=os.environ.get("SOCKET_SNOOP_LOG", "/var/log/socket_monitor.log"))
    return p.parse_args()

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/tcp.h>
#include <linux/sched.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    int state;
    char event[16];
    u32 uid;
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    // Only IPv4 for now
    if (args->family != AF_INET)
        return 0;

    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Safely read parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (task != NULL && task->real_parent != NULL) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    }
    data.ppid = ppid;

    // For inet_sock_set_state, saddr/daddr are IPv4 in network byte order
    data.src_ip = args->saddr;
    data.dst_ip = args->daddr;
    data.src_port = ntohs(args->sport);
    data.dst_port = ntohs(args->dport);
    data.state = args->newstate;

    __builtin_strncpy(data.event, "State Change", sizeof(data.event));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

TCP_STATES = {
    1: "Connection Established",
    2: "Connection Opening (SYN_SENT)",
    3: "Connection Opening (SYN_RECV)",
    4: "Connection Closing (FIN_WAIT1)",
    5: "Connection Closing (FIN_WAIT2)",
    6: "Connection Closed (TIME_WAIT)",
    7: "Connection Closed",
    8: "Connection Closing (CLOSE_WAIT)",
    9: "Connection Closing (LAST_ACK)",
    10: "Listening for Connections",
    11: "Connection Closing (CLOSING)",
}

def format_ip(ip_u32: int) -> str:
    return ".".join(str((ip_u32 >> (8 * shift)) & 0xFF) for shift in (0,1,2,3))[::-1].split('.')[::-1] and \
        ".".join(str((ip_u32 >> shift) & 0xFF) for shift in (0,8,16,24)[::-1])

# Clear, correct implementation (keeping the old trick above defensive)
def format_ip(ip_u32: int) -> str:  # noqa: F811  (shadow intentionally)
    return ".".join(str((ip_u32 >> s) & 0xFF) for s in (24, 16, 8, 0))

def connection_id(src_ip, src_port, dst_ip, dst_port) -> str:
    unique = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    return hashlib.md5(unique.encode()).hexdigest()

def main():
    if os.uname().sysname.lower() != "linux":
        print("This tool requires Linux (eBPF/BCC).", file=sys.stderr)
        sys.exit(1)

    args = parse_args()

    # Prepare logging
    log_file = args.log_file
    try:
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write("Enhanced Socket Monitoring Log\n" + "=" * 60 + "\n")
    except PermissionError:
        print(f"Warning: cannot write to {log_file}; falling back to ./socket_monitor.log", file=sys.stderr)
        log_file = "./socket_monitor.log"

    b = BPF(text=BPF_PROGRAM)

    metrics = {
        "active_connections": 0,
        "closing_connections": 0,
        "closed_connections": 0,
    }

    recent_events = deque(maxlen=2000)   # bounded cache

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        state_str = TCP_STATES.get(event.state, "UNKNOWN STATE")
        timestamp = datetime.now().strftime("%b %d %Y %H:%M:%S.%f")[:-3]

        src_ip = format_ip(event.src_ip)
        dst_ip = format_ip(event.dst_ip)

        # Filters
        if args.pid and event.pid != args.pid:
            return
        if args.src_ip and src_ip != args.src_ip:
            return
        if args.dst_ip and dst_ip != args.dst_ip:
            return
        if args.src_port and event.src_port != args.src_port:
            return
        if args.dst_port and event.dst_port != args.dst_port:
            return
        if args.active_only and event.state != 1:
            return

        # Metrics
        if event.state == 1:
            metrics["active_connections"] += 1
        elif event.state in (4,5,8,9,11):
            metrics["closing_connections"] += 1
        elif event.state in (6,7):
            if metrics["active_connections"] > 0:
                metrics["active_connections"] -= 1
            metrics["closed_connections"] += 1

        event_key = (src_ip, event.src_port, dst_ip, event.dst_port, event.pid, event.state)
        if event_key in recent_events:
            return
        recent_events.append(event_key)

        entry = {
            "timestamp": timestamp,
            "event": event.event.decode(errors="ignore"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(event.src_port),
            "dst_port": int(event.dst_port),
            "protocol": "TCP",
            "state": state_str,
            "connection_id": connection_id(src_ip, int(event.src_port), dst_ip, int(event.dst_port)),
            "metrics": dict(metrics),
            "pid": int(event.pid),
            "ppid": int(event.ppid),
            "uid": int(event.uid),
            "comm": event.comm.decode(errors="ignore"),
        }

        print(entry)
        try:
            with open(log_file, "a") as f:
                f.write(str(entry) + "\n")
        except Exception as e:
            print(f"Log write failed: {e}", file=sys.stderr)

    b["events"].open_perf_buffer(handle_event)
    print(f"Monitoring socket connections. Logging to {log_file}")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping monitoring...")

if __name__ == "__main__":
    main()
