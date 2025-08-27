import os
from datetime import datetime
from bcc import BPF
import argparse
import hashlib

# 
# apt install bpfcc-tools linux-headers-$(uname -r) gcc python3-pip
# pip install bcc
# pip install numba
# pip install pytest
# Parse command-line arguments
parser = argparse.ArgumentParser(description="Enhanced Socket Monitoring Script")
parser.add_argument("--pid", type=int, help="Filter by Process ID (PID)", default=None)
parser.add_argument("--src-ip", type=str, help="Filter by Source IP address", default=None)
parser.add_argument("--dst-ip", type=str, help="Filter by Destination IP address", default=None)
parser.add_argument("--src-port", type=int, help="Filter by Source Port", default=None)
parser.add_argument("--dst-port", type=int, help="Filter by Destination Port", default=None)
parser.add_argument("--active-only", action="store_true", help="Monitor active connections only", default=False)
args = parser.parse_args()

# Enhanced BPF Code
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    u32 ppid; // Parent PID
    char comm[TASK_COMM_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    int state;  // TCP state
    char event[16]; // Event type (e.g., retransmit, reset)
    u32 uid; // User ID
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    // Convert saddr and daddr from __u8 arrays to u32 integers
    data.src_ip = ((u32)args->saddr[0] << 24) |
                  ((u32)args->saddr[1] << 16) |
                  ((u32)args->saddr[2] << 8) |
                  ((u32)args->saddr[3]);
    data.dst_ip = ((u32)args->daddr[0] << 24) |
                  ((u32)args->daddr[1] << 16) |
                  ((u32)args->daddr[2] << 8) |
                  ((u32)args->daddr[3]);

    data.src_port = ntohs(args->sport);
    data.dst_port = ntohs(args->dport);
    data.state = args->newstate;

    __builtin_strncpy(data.event, "State Change", sizeof(data.event));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Log file setup
log_file = "/var/log/socket_monitor.log"
if not os.path.exists(log_file):
    with open(log_file, "w") as f:
        f.write("Enhanced Socket Monitoring Log\n")
        f.write("=" * 60 + "\n")

# Format IP address
def format_ip(ip):
    return ".".join(map(str, [(ip >> (8 * i)) & 0xFF for i in reversed(range(4))]))

# Generate a unique connection ID
def generate_connection_id(src_ip, src_port, dst_ip, dst_port):
    unique_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    return hashlib.md5(unique_str.encode()).hexdigest()

# TCP state mapping
tcp_states = {
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

# Lifecycle metrics
metrics = {
    "active_connections": 0,
    "closing_connections": 0,
    "closed_connections": 0,
}

# Handle events
recent_events = set()

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    state_str = tcp_states.get(event.state, "UNKNOWN STATE")
    timestamp = datetime.now().strftime("%b %d %Y %H:%M:%S.%f")[:-3]

    src_ip = format_ip(event.src_ip)
    dst_ip = format_ip(event.dst_ip)

    # Apply filters
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
    if args.active_only and event.state != 1:  # Monitor only active connections
        return

    # Generate connection ID
    connection_id = generate_connection_id(src_ip, event.src_port, dst_ip, event.dst_port)

    # Update metrics based on state
    if event.state == 1:  # Connection Established
        metrics["active_connections"] += 1
    elif event.state in [4, 5, 8, 9, 11]:  # Connection Closing
        metrics["closing_connections"] += 1
    elif event.state in [6, 7]:  # Connection Closed
        if metrics["active_connections"] > 0:
            metrics["active_connections"] -= 1
        metrics["closed_connections"] += 1

    # Construct a unique key for this event
    event_key = (src_ip, event.src_port, dst_ip, event.dst_port, event.pid, event.state)

    # Check if the event is already logged
    if event_key in recent_events:
        return

    # Add to cache
    recent_events.add(event_key)

    # Remove old events from cache to prevent memory bloat
    if len(recent_events) > 1000:
        recent_events.pop()

    # Log the event
    log_entry = {
        "timestamp": timestamp,
        "event": event.event.decode(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": "TCP",
        "state": state_str,
        "connection_id": connection_id,
        "metrics": metrics.copy(),
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "comm": event.comm.decode(),
    }

    print(log_entry)
    with open(log_file, "a") as f:
        f.write(str(log_entry) + "\n")

# Attach perf buffer
b["events"].open_perf_buffer(handle_event)

print(f"Monitoring socket connections with enhanced metrics. Logs will be written to {log_file}")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopping monitoring...")
