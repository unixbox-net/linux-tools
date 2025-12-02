# socketsnoop/socketsnoop.py
import os, json, hashlib, argparse
from datetime import datetime
from collections import deque
from bcc import BPF

# -------- args --------
p = argparse.ArgumentParser(description="eBPF socket state monitor (IPv4)")
p.add_argument("--pid", type=int)
p.add_argument("--src-ip")
p.add_argument("--dst-ip")
p.add_argument("--src-port", type=int)
p.add_argument("--dst-port", type=int)
p.add_argument("--active-only", action="store_true")
args = p.parse_args()

# -------- output --------
LOG_FILE = os.environ.get("LOG_FILE", "/out/bpf/socketsnoop.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# -------- BPF (no deep kernel headers) --------
bpf_code = r"""
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char comm[16];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    int state;
    u32 uid;
};

BPF_PERF_OUTPUT(events);

// AF_INET constant (avoid pulling linux/socket.h)
#define AF_INET 2

static __inline u16 bswap16(u16 x) {
    return (x << 8) | (x >> 8);
}

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    // Kernel exposes these fields via tracefs; BCC autogenerates the struct
    if (args->family != AF_INET)
        return 0;

    struct data_t ev = {};
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    // saddr/daddr are 4-byte arrays in network order
    ev.src_ip = ((u32)args->saddr[0] << 24) |
                ((u32)args->saddr[1] << 16) |
                ((u32)args->saddr[2] << 8)  |
                ((u32)args->saddr[3]);
    ev.dst_ip = ((u32)args->daddr[0] << 24) |
                ((u32)args->daddr[1] << 16) |
                ((u32)args->daddr[2] << 8)  |
                ((u32)args->daddr[3]);

    ev.src_port = bswap16(args->sport);
    ev.dst_port = bswap16(args->dport);
    ev.state = args->newstate;

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
""";

b = BPF(text=bpf_code)

def ip4str(ip):
    return ".".join(str((ip >> (8*i)) & 0xff) for i in (3,2,1,0))

tcp_states = {
    1:"ESTABLISHED",2:"SYN_SENT",3:"SYN_RECV",4:"FIN_WAIT1",5:"FIN_WAIT2",
    6:"TIME_WAIT",7:"CLOSED",8:"CLOSE_WAIT",9:"LAST_ACK",10:"LISTEN",11:"CLOSING"
}

metrics = {"active_connections":0,"closing_connections":0,"closed_connections":0}
recent = deque(maxlen=2000); seen=set()

def keytuple(sip,sp,dip,dp,pid,state):
    return (sip,sp,dip,dp,pid,state)

def handle(cpu, data, size):
    ev = b["events"].event(data)
    ts = datetime.utcnow().isoformat(timespec="milliseconds")+"Z"

    sip = ip4str(ev.src_ip); dip = ip4str(ev.dst_ip)

    # filters
    if args.pid and ev.pid != args.pid: return
    if args.src_ip and sip != args.src_ip: return
    if args.dst_ip and dip != args.dst_ip: return
    if args.src_port and ev.src_port != args.src_port: return
    if args.dst_port and ev.dst_port != args.dst_port: return
    if args.active_only and ev.state != 1: return  # only ESTABLISHED

    kt = keytuple(sip, ev.src_port, dip, ev.dst_port, ev.pid, ev.state)
    if kt in seen: return
    recent.append(kt); seen.add(kt)
    if len(recent)==recent.maxlen:
        old = recent[0]; seen.discard(old)

    st = tcp_states.get(ev.state, f"STATE_{ev.state}")
    cid = hashlib.md5(f"{sip}:{ev.src_port}->{dip}:{ev.dst_port}".encode()).hexdigest()

    row = {
        "timestamp": ts,
        "event": "State Change",
        "protocol": "TCP",
        "state": st,
        "src_ip": sip, "src_port": int(ev.src_port),
        "dst_ip": dip, "dst_port": int(ev.dst_port),
        "connection_id": cid,
        "pid": int(ev.pid),
        "uid": int(ev.uid),
        "comm": ev.comm.decode(errors="ignore"),
        "metrics": dict(metrics),
    }

    # update metrics after emitting (so numbers represent pre-change counters)
    if ev.state == 1: metrics["active_connections"] += 1
    elif ev.state in (4,5,8,9,11): metrics["closing_connections"] += 1
    elif ev.state in (6,7):
        if metrics["active_connections"]>0: metrics["active_connections"] -= 1
        metrics["closed_connections"] += 1

    print(json.dumps(row, ensure_ascii=False), flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False)+"\n")

b["events"].open_perf_buffer(handle)
print(f"[socketsnoop] writing to {LOG_FILE}", flush=True)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("[socketsnoop] stopping...", flush=True)

