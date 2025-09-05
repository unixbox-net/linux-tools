#!/usr/bin/env bash
set -euo pipefail

# Run this from the REPO ROOT.
# It will create/update files under debian/monitoring and CI scaffolding.

ROOT="$(pwd)"
MON="debian/monitoring"

echo "==> Ensuring directories exist..."
mkdir -p "$MON"/{tests,systemd,scripts} .github/workflows

# If old name exists, rename it (no overwrite)
if [[ -f "$MON/socket-snoop.py" && ! -f "$MON/socket_snoop.py" ]]; then
  echo "==> Renaming socket-snoop.py -> socket_snoop.py"
  git mv "$MON/socket-snoop.py" "$MON/socket_snoop.py" 2>/dev/null || mv "$MON/socket-snoop.py" "$MON/socket_snoop.py"
fi

echo "==> Writing $MON/socket_snoop.py"
cat > "$MON/socket_snoop.py" <<'PY'
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (task != NULL && task->real_parent != NULL) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    }
    data.ppid = ppid;

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
PY
chmod +x "$MON/socket_snoop.py"

echo "==> Writing $MON/Makefile"
cat > "$MON/Makefile" <<'MK'
SHELL := /bin/bash
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: help setup venv deps test run docker clean

help:
	@echo "make setup      - install system deps (Debian/Ubuntu)"
	@echo "make venv       - create Python venv"
	@echo "make deps       - install pip deps"
	@echo "make test       - run unit tests"
	@echo "make run        - run the monitor"
	@echo "make docker     - build Docker image"
	@echo "make clean      - remove venv and caches"

setup:
	./scripts/install-deps-debian.sh

venv:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

deps: venv
	$(PIP) install -r requirements.txt

test: deps
	$(PY) -m pytest -q

run: deps
	sudo $(PY) socket_snoop.py

docker:
	docker build -t socket-snoop:latest .

clean:
	rm -rf $(VENV) .pytest_cache __pycache__
MK

echo "==> Writing $MON/requirements.txt"
cat > "$MON/requirements.txt" <<'REQ'
pytest>=7.0
REQ

echo "==> Writing $MON/scripts/install-deps-debian.sh"
cat > "$MON/scripts/install-deps-debian.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if ! command -v apt-get >/dev/null; then
  echo "This installer is for Debian/Ubuntu." >&2
  exit 1
fi
sudo apt-get update
sudo apt-get install -y \
  bpfcc-tools libbpfcc-dev python3-bpfcc \
  linux-headers-$(uname -r) \
  clang llvm make gcc build-essential \
  python3 python3-venv python3-pip
echo "System deps installed."
SH
chmod +x "$MON/scripts/install-deps-debian.sh"

echo "==> Writing $MON/tests/test_helpers.py"
cat > "$MON/tests/test_helpers.py" <<'PY'
from socket_snoop import format_ip, connection_id  # type: ignore

def test_format_ip():
    assert format_ip(0x7F000001) == "127.0.0.1"
    assert format_ip(0xC0A80101) == "192.168.1.1"

def test_connection_id_stable():
    a = connection_id("10.0.0.1", 1234, "10.0.0.2", 80)
    b = connection_id("10.0.0.1", 1234, "10.0.0.2", 80)
    assert a == b
    assert len(a) == 32
PY

echo "==> Writing $MON/systemd/socket-snoop.service"
cat > "$MON/systemd/socket-snoop.service" <<'UNIT'
[Unit]
Description=Socket Snoop eBPF monitor
After=network.target
Wants=network.target

[Service]
Type=simple
# Replace /opt/socket-snoop with your absolute repo path
ExecStart=/usr/bin/env bash -lc '/opt/socket-snoop/.venv/bin/python /opt/socket-snoop/debian/monitoring/socket_snoop.py --log-file=/var/log/socket_monitor.log'
User=root
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

echo "==> Writing $MON/Dockerfile"
cat > "$MON/Dockerfile" <<'DOCK'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    bpfcc-tools libbpfcc-dev python3-bpfcc \
    python3 python3-pip python3-venv \
    clang llvm make gcc \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt /app/
RUN python3 -m venv /app/.venv && /app/.venv/bin/pip install --upgrade pip && /app/.venv/bin/pip install -r requirements.txt
COPY . /app/
CMD ["/app/.venv/bin/python", "/app/socket_snoop.py"]
# Run with:
# docker run --rm -it --privileged \
#   --pid=host --net=host \
#   -v /lib/modules:/lib/modules:ro \
#   -v /usr/src:/usr/src:ro \
#   -v /sys:/sys:ro -v /var/log:/var/log \
#   socket-snoop:latest
DOCK

echo "==> Writing .github/workflows/ci.yml"
cat > ".github/workflows/ci.yml" <<'YML'
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"
      - name: Install bcc python bindings (non-root)
        run: sudo apt-get update && sudo apt-get install -y python3-bpfcc
      - name: Install deps & run tests
        working-directory: debian/monitoring
        run: |
          python3 -m venv .venv
          .venv/bin/pip install -r requirements.txt
          .venv/bin/pytest -q
YML

echo "==> Writing .gitignore additions"
{
  echo ".venv/"
  echo "__pycache__/"
  echo "*.pyc"
  echo "*.log"
  echo ".pytest_cache/"
  echo "dist/"
  echo "build/"
} >> ".gitignore"

echo "==> Done. Suggested next steps:"
echo "    git add -A"
echo "    git commit -m 'monitoring: repo bootstrap (script, Makefile, tests, CI, Docker, systemd)'"
echo "    git push"

