#!/usr/bin/env python3
"""
# Socket Snoop - Realtime Socket Monitoring, @OR(ϵ)SOURCES

## Overview

The Socket Monitoring Tool is a powerful and lightweight solution designed for system administrators who need real-time insights into socket-level network activity on their systems. By leveraging eBPF, this tool provides detailed logs of connection states, including source and destination IP addresses, ports, process IDs (PIDs), and associated commands (COMM), as well as TCP state transitions. Socket_snoop is a poerful addition to tcpdump.

```plaintext
FEATURES:
- Captures TCP state changes (inet_sock_set_state tracepoint).
- Monitors key TCP connection states like SYN_SENT, FIN_WAIT, and TIME_WAIT.
- Tracks TCP retransmissions (tcp_retransmit_skb tracepoint), a key indicator of network issues.
- Logs the process ID (PID) and command name (COMM) associated with each connection.
- Logs connection details (source/destination IP and port, process ID, and state) to /var/log/socket_monitor.log.
- Skips noisy or invalid entries, like connections with IP 0.0.0.0.
- Maps TCP states to human-readable descriptions.
- Formats IP addresses for readability.
- Uses perf_buffer for real-time event handling.
- Can run continuously and provide live updates via the console and log file.
- Real-Time Logging: Captures and logs socket connections as they occur.
- Detailed Insights: Provides source and destination IP addresses, ports, PIDs, command names, and TCP states.
- Formatted Output: Logs are time-stamped and categorized (e.g., Opened Connection, Closed Connection, Established Connection).
- Lightweight and Efficient: Runs efficiently using eBPF without significant performance overhead.

BENEFITS:
- Simplifies network monitoring by highlighting key details often buried in more complex tools.
- Reduces the need for deep packet analysis with tools like tcpdump or wireshark.
- Enhances operational awareness for system administrators managing critical infrastructure.

LIMITATIONS:
- IP4 only (wip)
- Need to add Dynamic Filters / pid/ip/ports
- Enhance Error Handling
- Perfomance Tuning
```
## Use Cases

Security Monitoring: Detect suspicious or unauthorized network activity.
Performance Debugging: Identify network latency or dropped connections by observing TCP states.
Audit Logging: Maintain a comprehensive record of all socket-level network interactions.
Real-Time Monitoring: Observe live network activity without the complexity of tools like tcpdump or wireshark. In addition, no network frames are captured so it's perfect for high security networks.
"""

import argparse
import hashlib
import os
import sys
from datetime import datetime
from collections import deque

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
    if (args->family != AF_INET)
        return 0;

    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // parent PID (verifier-safe)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (task && task->real_parent) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    }
    data.ppid = ppid;

    // Debian 13 (BCC 0.31) uses __u8[4] for saddr/daddr in this tracepoint
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
    return ".".join(str((ip_u32 >> s) & 0xFF) for s in (24, 16, 8, 0))

def connection_id(src_ip, src_port, dst_ip, dst_port) -> str:
    unique = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    return hashlib.md5(unique.encode()).hexdigest()

def main():
    if os.uname().sysname.lower() != "linux":
        print("This tool requires Linux (eBPF/BCC).", file=sys.stderr)
        sys.exit(1)

    args = parse_args()

    log_file = args.log_file
    try:
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write("Enhanced Socket Monitoring Log\n" + "=" * 60 + "\n")
    except PermissionError:
        print(f"Warning: cannot write to {log_file}; falling back to ./socket_monitor.log", file=sys.stderr)
        log_file = "./socket_monitor.log"

    from bcc import BPF   # lazy import so tests don’t need bcc
    b = BPF(text=BPF_PROGRAM)

    metrics = {
        "active_connections": 0,
        "closing_connections": 0,
        "closed_connections": 0,
    }
    recent_events = deque(maxlen=2000)

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        state_str = TCP_STATES.get(event.state, "UNKNOWN STATE")
        timestamp = datetime.now().strftime("%b %d %Y %H:%M:%S.%f")[:-3]

        src_ip = format_ip(event.src_ip)
        dst_ip = format_ip(event.dst_ip)

        if args.pid and event.pid != args.pid: return
        if args.src_ip and src_ip != args.src_ip: return
        if args.dst_ip and dst_ip != args.dst_ip: return
        if args.src_port and event.src_port != args.src_port: return
        if args.dst_port and event.dst_port != args.dst_port: return
        if args.active_only and event.state != 1: return

        if event.state == 1:
            metrics["active_connections"] += 1
        elif event.state in (4,5,8,9,11):
            metrics["closing_connections"] += 1
        elif event.state in (6,7):
            if metrics["active_connections"] > 0:
                metrics["active_connections"] -= 1
            metrics["closed_connections"] += 1

        event_key = (src_ip, int(event.src_port), dst_ip, int(event.dst_port),
                     int(event.pid), int(event.state))
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
