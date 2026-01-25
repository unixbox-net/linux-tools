// SPDX-License-Identifier: Apache-2.0
// ktrace.bpf.c - eBPF CO-RE program for ktrace
//
// Design goals:
// - metadata-only socket events
// - Kubernetes-friendly attribution (pid/comm, cgroup id, ns inode ids, caps/seccomp)
// - bounded filters (dns-only, port allowlist, sampling)
// - guardrails (ringbuf drop counters)

#include "vmlinux.h"

// Required for PT_REGS_PARMn() helpers used by <bpf/bpf_tracing.h>
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/*
 * CO-RE / vmlinux.h build note
 * ---------------------------
 *
 * This BPF program is compiled using a generated vmlinux.h (BTF types),
 * which already contains many kernel type definitions and constants.
 *
 * On Fedora (and many other distros), including userspace kernel headers
 * like <linux/in.h>, <linux/socket.h>, etc. *in addition* to vmlinux.h
 * can cause a storm of "redefinition" errors (posix_types, IPPROTO_*,
 * sockaddr_storage, etc.).
 *
 * Therefore: avoid including linux headers here. Instead we provide
 * Therefore: avoid including linux headers here. Rely on vmlinux.h/BTF types only.
 */

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif


char LICENSE[] SEC("license") = "GPL";
__u32 VERSION SEC("version") = 1;

#define KTRACE_ADDR_LEN 16
#define KTRACE_COMM_LEN 16
#define KTRACE_PORT_ALLOW_MAX 8

enum ktrace_evt_type {
    EVT_TCP_STATE   = 1,
    EVT_UDP_SEND    = 2,
    EVT_UDP_RECV    = 3,
    EVT_CONNECT_LAT = 4,
    EVT_TCP_RETRANS = 5,
};

struct ktrace_config {
    __u32 sample_rate;               // 1 = capture all; N = 1/N
    __u32 dns_only;                  // 1 = only events with port 53
    __u16 port_allow[KTRACE_PORT_ALLOW_MAX];
    __u16 port_allow_len;            // number of valid ports in port_allow
    __u8  enable_ns;                 // include namespace inode IDs
    __u16 _pad;
};

struct ktrace_event {
    __u64 ts_ns;

    __u32 type;

    __u32 pid;
    __u32 tgid;
    __u32 ppid;

    __u32 uid;
    __u32 gid;

    __u32 netns;
    __u32 mntns;
    __u32 pidns;
    __u32 userns;
    __u32 fd;                        // only used for connect()

    __u64 cgroup_id;
    __u32 _pad2;

    char comm[KTRACE_COMM_LEN];

    __u8  af;                        // AF_INET / AF_INET6
    __u8  proto;                     // IPPROTO_TCP / IPPROTO_UDP
    __u16 sport;
    __u16 dport;
    __u16 _pad3;

    __u8  saddr[KTRACE_ADDR_LEN];
    __u8  daddr[KTRACE_ADDR_LEN];

    __u32 tcp_oldstate;
    __u32 tcp_newstate;

    __u32 bytes;                     // udp bytes, 0 otherwise
    __s32 ret;                       // connect() return value

    __u64 latency_ns;                // connect latency
};

// config_map[0] holds struct ktrace_config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ktrace_config);
} config_map SEC(".maps");

// stats_map provides simple counters
// keys:
// 0 emitted
// 1 ringbuf_drop
// 2 filtered
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB (tune as needed)
} events SEC(".maps");


// connect start map (keyed by pid_tgid; best-effort one in-flight connect per thread)
struct connect_start_t {
    __u64 ts_ns;
    __u8  af;
    __u8  _pad0;
    __u16 dport;
    __u32 fd;
    __u8  daddr[KTRACE_ADDR_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct connect_start_t);
} connect_start SEC(".maps");

// udp recv args map (pid_tgid -> sock + msg + addrlen_ptr)
struct udp_recv_args_t {
    struct sock *sk;
    struct msghdr *msg;
    int *addrlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct udp_recv_args_t);
} udp_recv_args SEC(".maps");

static __always_inline struct ktrace_config *cfg_get(void) {
    __u32 k = 0;
    return bpf_map_lookup_elem(&config_map, &k);
}

static __always_inline void stat_inc(__u32 key) {
    __u64 *v = bpf_map_lookup_elem(&stats_map, &key);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline bool ports_match_allowlist(__u16 sport, __u16 dport, struct ktrace_config *cfg) {
    if (!cfg) return true;
    if (cfg->port_allow_len == 0) return true;

#pragma unroll
    for (int i = 0; i < KTRACE_PORT_ALLOW_MAX; i++) {
        if (i >= cfg->port_allow_len) break;
        __u16 p = cfg->port_allow[i];
        if (p == 0) continue;
        if (sport == p || dport == p) return true;
    }
    return false;
}

static __always_inline bool should_sample(struct ktrace_config *cfg) {
    if (!cfg) return true;
    __u32 r = cfg->sample_rate;
    if (r <= 1) return true;
    // 1/r sampling
    return (bpf_get_prandom_u32() % r) == 0;
}

static __always_inline void fill_comm(char comm[KTRACE_COMM_LEN]) {
    bpf_get_current_comm(comm, KTRACE_COMM_LEN);
}

static __always_inline __u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) return 0;
    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline void fill_ns_and_security(struct ktrace_event *e, struct ktrace_config *cfg) {
    if (!cfg) return;

    if (cfg->enable_ns) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        struct nsproxy *nsp = task ? BPF_CORE_READ(task, nsproxy) : 0;
        if (nsp) {
            struct net *net_ns = BPF_CORE_READ(nsp, net_ns);
            struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsp, mnt_ns);
            struct pid_namespace *pid_ns = BPF_CORE_READ(nsp, pid_ns_for_children);
            if (net_ns) e->netns = BPF_CORE_READ(net_ns, ns.inum);
            if (mnt_ns) e->mntns = BPF_CORE_READ(mnt_ns, ns.inum);
            if (pid_ns) e->pidns = BPF_CORE_READ(pid_ns, ns.inum);
        }
    }
    }
}

static __always_inline int submit_event(struct ktrace_event *e) {
    struct ktrace_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) {
        stat_inc(1);
        return 0;
    }
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    stat_inc(0);
    return 0;
}

static __always_inline void fill_addr4(__u8 out[KTRACE_ADDR_LEN], __be32 addr) {
    __builtin_memset(out, 0, KTRACE_ADDR_LEN);
    __builtin_memcpy(out, &addr, 4);
}

static __always_inline void fill_addr6(__u8 out[KTRACE_ADDR_LEN], struct in6_addr addr6) {
    __builtin_memcpy(out, &addr6, 16);
}

// ----------------------------
// TCP state changes
// ----------------------------

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(ktrace_tcp_set_state, struct sock *sk, int newstate)
{
    struct ktrace_config *cfg = cfg_get();
    if (!should_sample(cfg)) {
        stat_inc(2);
        return 0;
    }
    if (!sk) {
        stat_inc(2);
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        stat_inc(2);
        return 0;
    }

    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __be16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 dport = bpf_ntohs(dport_be);

    // dns-only filter
    if (cfg && cfg->dns_only) {
        if (sport != 53 && dport != 53) {
            stat_inc(2);
            return 0;
        }
    }
    // ports allowlist filter
    if (!ports_match_allowlist(sport, dport, cfg)) {
        stat_inc(2);
        return 0;
    }

    struct ktrace_event e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.type = EVT_TCP_STATE;

    __u64 id = bpf_get_current_pid_tgid();
    e.pid = (__u32)id;
    e.tgid = (__u32)(id >> 32);
    e.ppid = get_ppid();

    __u64 ug = bpf_get_current_uid_gid();
    e.uid = (__u32)ug;
    e.gid = (__u32)(ug >> 32);

    fill_comm(e.comm);

    e.cgroup_id = bpf_get_current_cgroup_id();

    e.af = (__u8)family;
    e.proto = IPPROTO_TCP;
    e.sport = sport;
    e.dport = dport;

    // old state is current sk_state on entry; new is arg
    __u8 old = BPF_CORE_READ(sk, __sk_common.skc_state);
    e.tcp_oldstate = (__u32)old;
    e.tcp_newstate = (__u32)newstate;

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        fill_addr4(e.saddr, saddr);
        fill_addr4(e.daddr, daddr);
    } else {
        struct in6_addr s6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr d6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        fill_addr6(e.saddr, s6);
        fill_addr6(e.daddr, d6);
    }

    fill_ns_and_security(&e, cfg);
    return submit_event(&e);
}

// ----------------------------
// UDP send
// ----------------------------

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(ktrace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct ktrace_config *cfg = cfg_get();
    if (!should_sample(cfg)) {
        stat_inc(2);
        return 0;
    }
    if (!sk) {
        stat_inc(2);
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        stat_inc(2);
        return 0;
    }

    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = 0;

    // for connected UDP sockets, skc_dport is set
    __be16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport_be);

    // if unconnected, try msg->msg_name
    if (dport == 0 && msg) {
        void *name = BPF_CORE_READ(msg, msg_name);
        if (name) {
            __u16 fam = 0;
            bpf_probe_read_user(&fam, sizeof(fam), name);
            if (fam == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), name);
                dport = bpf_ntohs(sin.sin_port);
            } else if (fam == AF_INET6) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), name);
                dport = bpf_ntohs(sin6.sin6_port);
            }
        }
    }

    // dns-only filter
    if (cfg && cfg->dns_only) {
        if (sport != 53 && dport != 53) {
            stat_inc(2);
            return 0;
        }
    }
    if (!ports_match_allowlist(sport, dport, cfg)) {
        stat_inc(2);
        return 0;
    }

    struct ktrace_event e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.type = EVT_UDP_SEND;

    __u64 id = bpf_get_current_pid_tgid();
    e.pid = (__u32)id;
    e.tgid = (__u32)(id >> 32);
    e.ppid = get_ppid();

    __u64 ug = bpf_get_current_uid_gid();
    e.uid = (__u32)ug;
    e.gid = (__u32)(ug >> 32);

    fill_comm(e.comm);

    e.cgroup_id = bpf_get_current_cgroup_id();
    e.af = (__u8)family;
    e.proto = IPPROTO_UDP;
    e.sport = sport;
    e.dport = dport;
    e.bytes = (__u32)len;

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        // For unconnected UDP, daddr may be 0; that's expected.
        fill_addr4(e.saddr, saddr);
        fill_addr4(e.daddr, daddr);
    } else {
        struct in6_addr s6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr d6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        fill_addr6(e.saddr, s6);
        fill_addr6(e.daddr, d6);
    }

    // If destination address is unknown (unconnected), attempt msg->msg_name for IP too
    if (msg) {
        void *name = BPF_CORE_READ(msg, msg_name);
        if (name) {
            __u16 fam = 0;
            bpf_probe_read_user(&fam, sizeof(fam), name);
            if (fam == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), name);
                fill_addr4(e.daddr, sin.sin_addr.s_addr);
                e.dport = bpf_ntohs(sin.sin_port);
                e.af = AF_INET;
            } else if (fam == AF_INET6) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), name);
                fill_addr6(e.daddr, sin6.sin6_addr);
                e.dport = bpf_ntohs(sin6.sin6_port);
                e.af = AF_INET6;
            }
        }
    }

    fill_ns_and_security(&e, cfg);
    return submit_event(&e);
}

// ----------------------------
// UDP recv (entry + return)
// ----------------------------

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(ktrace_udp_recvmsg_enter, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct udp_recv_args_t args = {
        .sk = sk,
        .msg = msg,
        .addrlen = addr_len,
    };
    bpf_map_update_elem(&udp_recv_args, &id, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(ktrace_udp_recvmsg_exit, int ret)
{
    struct ktrace_config *cfg = cfg_get();
    if (!should_sample(cfg)) {
        stat_inc(2);
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    struct udp_recv_args_t *ap = bpf_map_lookup_elem(&udp_recv_args, &id);
    if (!ap) {
        stat_inc(2);
        return 0;
    }

    struct sock *sk = ap->sk;
    struct msghdr *msg = ap->msg;
    bpf_map_delete_elem(&udp_recv_args, &id);

    if (!sk) {
        stat_inc(2);
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        stat_inc(2);
        return 0;
    }

    // ret is number of bytes, or negative errno
    if (ret <= 0) {
        // still could emit if you want, but default is ignore
        stat_inc(2);
        return 0;
    }

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_num); // local port
    __u16 sport = 0; // remote port best-effort

    // For connected UDP sockets, skc_dport is set
    __be16 sport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    sport = bpf_ntohs(sport_be);

    // If unconnected, attempt msg->msg_name remote address/port
    __u8 src_tmp[KTRACE_ADDR_LEN] = {};
    if (msg) {
        void *name = BPF_CORE_READ(msg, msg_name);
        if (name) {
            __u16 fam = 0;
            bpf_probe_read_user(&fam, sizeof(fam), name);
            if (fam == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), name);
                fill_addr4(src_tmp, sin.sin_addr.s_addr);
                sport = bpf_ntohs(sin.sin_port);
                family = AF_INET;
            } else if (fam == AF_INET6) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), name);
                fill_addr6(src_tmp, sin6.sin6_addr);
                sport = bpf_ntohs(sin6.sin6_port);
                family = AF_INET6;
            }
        }
    }

    // dns-only filter
    if (cfg && cfg->dns_only) {
        if (sport != 53 && dport != 53) {
            stat_inc(2);
            return 0;
        }
    }
    if (!ports_match_allowlist(sport, dport, cfg)) {
        stat_inc(2);
        return 0;
    }

    struct ktrace_event e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.type = EVT_UDP_RECV;

    e.pid = (__u32)id;
    e.tgid = (__u32)(id >> 32);
    e.ppid = get_ppid();

    __u64 ug = bpf_get_current_uid_gid();
    e.uid = (__u32)ug;
    e.gid = (__u32)(ug >> 32);

    fill_comm(e.comm);

    e.cgroup_id = bpf_get_current_cgroup_id();
    e.af = (__u8)family;
    e.proto = IPPROTO_UDP;
    e.sport = sport;
    e.dport = dport;
    e.bytes = (__u32)ret;

    if (family == AF_INET) {
        // local addr
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        fill_addr4(e.daddr, daddr);

        // remote addr (connected) or from msg_name
        if (sport_be != 0) {
            __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            fill_addr4(e.saddr, saddr);
        } else {
            __builtin_memcpy(e.saddr, src_tmp, KTRACE_ADDR_LEN);
        }
    } else {
        struct in6_addr d6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        fill_addr6(e.daddr, d6);

        if (sport_be != 0) {
            struct in6_addr s6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
            fill_addr6(e.saddr, s6);
        } else {
            __builtin_memcpy(e.saddr, src_tmp, KTRACE_ADDR_LEN);
        }
    }

    fill_ns_and_security(&e, cfg);
    return submit_event(&e);
}

// ----------------------------
// connect() latency
// ----------------------------

SEC("tracepoint/syscalls/sys_enter_connect")
int ktrace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct ktrace_config *cfg = cfg_get();
    if (!should_sample(cfg)) {
        stat_inc(2);
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    void *uservaddr = (void *)ctx->args[1];

    if (!uservaddr) {
        stat_inc(2);
        return 0;
    }

    __u16 fam = 0;
    bpf_probe_read_user(&fam, sizeof(fam), uservaddr);
    if (fam != AF_INET && fam != AF_INET6) {
        stat_inc(2);
        return 0;
    }

    struct connect_start_t st = {};
    st.ts_ns = bpf_ktime_get_ns();
    st.af = (__u8)fam;
    st.fd = (__u32)fd;

    if (fam == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uservaddr);
        st.dport = bpf_ntohs(sin.sin_port);
        __builtin_memset(st.daddr, 0, KTRACE_ADDR_LEN);
        __builtin_memcpy(st.daddr, &sin.sin_addr.s_addr, 4);
    } else {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr);
        st.dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(st.daddr, &sin6.sin6_addr, 16);
    }

    // optional filters
    if (cfg && cfg->dns_only) {
        if (st.dport != 53) {
            stat_inc(2);
            return 0;
        }
    }
    if (!ports_match_allowlist(0, st.dport, cfg)) {
        stat_inc(2);
        return 0;
    }

    bpf_map_update_elem(&connect_start, &pid_tgid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int ktrace_sys_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    struct ktrace_config *cfg = cfg_get();
    if (!should_sample(cfg)) {
        stat_inc(2);
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_start_t *st = bpf_map_lookup_elem(&connect_start, &pid_tgid);
    if (!st) {
        stat_inc(2);
        return 0;
    }

    // copy and delete early to avoid leaks
    struct connect_start_t local = {};
    __builtin_memcpy(&local, st, sizeof(local));
    bpf_map_delete_elem(&connect_start, &pid_tgid);

    struct ktrace_event e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.type = EVT_CONNECT_LAT;

    e.pid = (__u32)pid_tgid;
    e.tgid = (__u32)(pid_tgid >> 32);
    e.ppid = get_ppid();

    __u64 ug = bpf_get_current_uid_gid();
    e.uid = (__u32)ug;
    e.gid = (__u32)(ug >> 32);

    fill_comm(e.comm);
    e.cgroup_id = bpf_get_current_cgroup_id();

    e.af = local.af;
    e.fd = local.fd;
    e.dport = local.dport;
    __builtin_memcpy(e.daddr, local.daddr, KTRACE_ADDR_LEN);

    e.ret = (int)ctx->ret;
    if (local.ts_ns != 0) {
        __u64 now = bpf_ktime_get_ns();
        e.latency_ns = now - local.ts_ns;
    }

    fill_ns_and_security(&e, cfg);
    return submit_event(&e);
}

// ----------------------------
// TCP retransmit (optional attach)
// ---------------------------- tracepoint (optional attach)
// ----------------------------

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(ktrace_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb)
{
    struct ktrace_config *cfg = cfg_get();
    if (!should_sample(cfg)) {
        stat_inc(2);
        return 0;
    }
    if (!sk) {
        stat_inc(2);
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        stat_inc(2);
        return 0;
    }

    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __be16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 dport = bpf_ntohs(dport_be);

    // dns-only filter (unlikely for retrans, but keep consistent)
    if (cfg && cfg->dns_only) {
        if (sport != 53 && dport != 53) {
            stat_inc(2);
            return 0;
        }
    }
    if (!ports_match_allowlist(sport, dport, cfg)) {
        stat_inc(2);
        return 0;
    }

    struct ktrace_event e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.type = EVT_TCP_RETRANS;

    __u64 id = bpf_get_current_pid_tgid();
    e.pid = (__u32)id;
    e.tgid = (__u32)(id >> 32);
    e.ppid = get_ppid();

    __u64 ug = bpf_get_current_uid_gid();
    e.uid = (__u32)ug;
    e.gid = (__u32)(ug >> 32);

    fill_comm(e.comm);
    e.cgroup_id = bpf_get_current_cgroup_id();

    e.af = (__u8)family;
    e.proto = IPPROTO_TCP;
    e.sport = sport;
    e.dport = dport;

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        fill_addr4(e.saddr, saddr);
        fill_addr4(e.daddr, daddr);
    } else {
        struct in6_addr s6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr d6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        fill_addr6(e.saddr, s6);
        fill_addr6(e.daddr, d6);
    }

    fill_ns_and_security(&e, cfg);
    return submit_event(&e);
}
