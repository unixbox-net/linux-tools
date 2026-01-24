# ktrace

`ktrace` is a **Kubernetes-first eBPF CO‑RE snapshot collector** that captures *metadata-only* socket activity on a node
and writes an **AI-friendly forensic bundle** (JSONL + summary + node metadata).

It is designed for *real-world cluster debugging*, where pod-level dashboards (including common CNI tooling) don’t tell you
what is happening **on the host kernel fast path**.

> **No payloads are captured.** This is not tcpdump.
> It records socket + process metadata (tuples, states, bytes, latency), and best-effort Kubernetes attribution.

---

## Why ktrace exists

Typical incidents that are hard to solve quickly with pod-only metrics:

- “DNS is broken” (usually UDP)
- “Pods can’t reach the API server”
- “Works on one node, fails on another”
- “Intermittent timeouts / flapping readiness”
- “Policy says allow, but traffic still fails”
- “Is this policy, routing, conntrack/NAT, or host pressure?”

`ktrace` answers **what the kernel is doing**:

- Is TCP reaching **ESTABLISHED**, or stuck retrying SYN?
- Are we accumulating **CLOSE_WAIT** (application not closing sockets)?
- Are UDP DNS requests going out but **no replies** being observed?
- Which process / pod is the top talker?
- Can we correlate flows to **conntrack/NAT** (Service VIP / SNAT debugging)?
- Can we measure **connect() latency** without payloads?

---

## What ktrace captures (beta → production-grade path)

### Socket events (metadata only)

1) **TCP state changes** (`kprobe/tcp_set_state`)
- old_state → new_state
- 5‑tuple where available
- PID/TGID/PPID, UID/GID, comm
- netns/mntns/pidns/userns inode IDs
- seccomp mode + effective capabilities (optional but enabled by default)
- cgroup ID and best-effort Kubernetes identity (Pod UID, container ID, namespace/pod/container when resolvable)

2) **UDP send/recv** (`kprobe/udp_sendmsg`, `kprobe+kretprobe/udp_recvmsg`)
- best-effort tuples for both connected and unconnected UDP sockets
- bytes
- strong enough to detect “DNS sends but no DNS replies” patterns

3) **connect() latency (optional)** (`tracepoint/syscalls/sys_enter_connect`, `sys_exit_connect`)
- duration + result (errno)
- destination IP/port (v4/v6)
- helps classify slow or failing connects without payload

4) **TCP retransmits (optional)** (`tracepoint/tcp/tcp_retransmit_skb`)
- pid/comm attribution counts
- correlates with loss/pressure symptoms

### Correlation/enrichment (user-space; no API-server required)

- **CRI/containerd/CRIO mapping (optional / auto)**
  - resolves container ID → `namespace/pod/container` from CRI labels
  - no `kubectl`, no API calls

- **Kubelet pod-dir hints (best-effort)**
  - uses `/var/lib/kubelet/pods/<uid>/` as a fallback hint source

- **Conntrack correlation (optional)**
  - reads `/proc/net/nf_conntrack` (or `/proc/net/ip_conntrack`) snapshot periodically
  - annotates flows with conntrack state + reply tuple (NAT clue)

- **DNS RTT heuristic (user-space)**
  - pairs UDP sends to `:53` with UDP receives from `:53` (best-effort)
  - provides approximate RTT without parsing payload

---

## Security model / best practices

- **No payload capture** (metadata only).
- Intended to run **on-demand** (30–120s) as a forensic snapshot, not a permanent high-volume daemon.
- Includes guardrails:
  - event sampling (`--sample`)
  - port allowlist (`--ports`), DNS-only (`--dns-only`)
  - hard caps (`--max-events`, `--max-bytes`)
  - bounded caches (role cache, DNS pairing cache, CRI cache)
  - ringbuf drop counters + summary reporting

---

## Output bundle

By default `ktrace` writes:

```
out/
  ktrace.<node>.<ts>.events.jsonl
  ktrace.<node>.<ts>.summary.json
  ktrace.<node>.<ts>.node.json
  ktrace.<node>.<ts>.bundle.tgz
```

### Example event (TCP state)

```json
{
  "ts":"2026-01-24T21:57:54.326Z",
  "type":"tcp_state",
  "node":"etcd-1",
  "comm":"kubelet",
  "pid":928,
  "uid":0,
  "tuple":"192.168.122.60:24801 -> 192.168.18.69:6443",
  "old_state":"SYN_SENT",
  "new_state":"ESTABLISHED",
  "ns":{"net":4026532001,"mnt":4026531840,"pid":4026531836,"user":4026531837},
  "sec":{"seccomp_mode":2,"caps_eff":"0x00000000_00000000"},
  "k8s":{"pod_uid":"-","namespace":"-","pod":"-","container":"-","container_id":"-"},
  "conntrack":{"state":"ESTABLISHED","reply":"192.168.18.69:6443 -> 192.168.122.60:24801"}
}
```

---

## Build & run

### Runtime requirements (node)

- Linux kernel with BPF enabled
- **BTF** available at `/sys/kernel/btf/vmlinux` (common on modern distros)
- Run as root (or with sufficient caps: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` depending on kernel)

> Node does **not** need `bcc-tools` / Python.

### Build requirements (builder host)

- Go 1.22+
- clang/llvm
- bpftool
- libelf + zlib dev headers (for bpftool/clang toolchains)

#### Generate vmlinux.h + BPF skeleton

```bash
make generate
```

#### Build

```bash
make build
# or
make build-static
```

---


## Quickstart recipes

### 1) DNS investigation snapshot (recommended first)

```bash
sudo ./dist/ktrace \
  --duration=60s \
  --dns-only=true \
  --with-conntrack=true \
  --with-cri=true \
  --out-dir=./out
```

What you get:
- UDP send/recv to port 53
- DNS RTT heuristic where replies are observed
- A `dns_suspects` list in the summary for “sends but no receives” patterns

### 2) Service VIP / SNAT / conntrack debugging

```bash
sudo ./dist/ktrace \
  --duration=90s \
  --ports=80,443,6443 \
  --with-conntrack=true \
  --with-cri=true \
  --out-dir=./out
```

What you get:
- TCP state transitions to/from the selected ports
- conntrack reply tuple annotation (best-effort) for NAT clues

### 3) Slow connect() triage (metadata-only latency)

```bash
sudo ./dist/ktrace \
  --duration=60s \
  --with-connect-latency=true \
  --ports=443,6443 \
  --with-cri=true \
  --out-dir=./out
```

What you get:
- connect() duration + errno (no payload)
- enough to separate “connect is slow/failing” from “TLS/app-layer is slow”


## Kubernetes usage

`ktrace` is best as an **on-demand snapshot**:

- DaemonSet (privileged + hostPID) runs for `--duration 60`, writes hostPath bundle, exits/sleeps.
- An AI controller (or human) collects the bundle and analyzes it.

See `deploy/daemonset.yaml`.

---

## Notes / limitations

- This repo is intentionally “production grade” in safety posture, but still a **snapshot tool**:
  - It classifies failure modes and pinpoints suspects.
  - It will not explain TLS failures or DNS payload correctness (no payload).

- For deep app-level latency you can add extra probes (future).

---

## License

Apache-2.0 — see `LICENSE`.
