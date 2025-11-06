from bcc import BPF
import ctypes as ct
import socket
from struct import pack, unpack
from kubernetes.client import Configuration, ApiClient, CoreV1Api
from kubernetes.config import load_kube_config
from kubernetes.watch import Watch
import threading
import json
import os

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#define MAX_CONN_TRACK 655336
struct ipv4_tuple_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 proto;
};
BPF_HASH(conntrack, struct ipv4_tuple_t, int, MAX_CONN_TRACK);
int trace_k8s_policy(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid();
    struct ipv4_tuple_t tpl = {};
    tpl.proto = sk->sk_protocol;
    struct inet_sock *inet = (struct inet_sock *)sk;
    // get source and destination address/port
    tpl.saddr = inet->inet_saddr;
    tpl.daddr = inet->inet_daddr;
    tpl.sport = ntohs(inet->inet_sport);
    tpl.dport = ntohs(inet->inet_dport);
    int ret = 1;
    struct ipv4_tuple_t *tp = conntrack.lookup(&tpl);
    if (tp != NULL) {
        // already seen this connection, drop it
        return 0;
    }
    conntrack.update(&tpl, &ret);
    
    bpf_trace_printk("New Connection: %x:%d -> %x:%d\\n", tpl.saddr, tpl.sport, tpl.daddr, tpl.dport);
    return 0;
}
"""

def get_network_policies(namespace="default"):
    """
    Fetches all network policies from a given namespace and extracts the rules into a list of tuples (pod_selector, pod_selector, [allowed IP blocks])
    
    Args:
        namespace (str): The Kubernetes namespace to fetch network policies from. Default is "default".
        
    Returns:
        List[Tuple[Dict[str, str], Dict[str, str], List[Dict[str, str]]]: A list of tuples containing the rules for each network policy.
    """
    load_kube_config()
    c = Configuration().get_default_copy()
    core_v1 = CoreV1Api(ApiClient(configuration=c))
    policies = []
    w = Watch()
    for policy in w.stream(core_v1.list_namespaced_network_policy, namespace=namespace):
        spec = policy['object'].spec
        pod_selector = spec.pod_selector.match_labels
        policy_types = spec.policy_types or ["Ingress", "Egress"]
        rules = []
        for rule in spec.ingress:
            # extract allowed IP blocks
            new_rule = {'from': [], 'ports': []}
            if rule.from_ is not None:
                for f in rule.from_:
                    new_rule['from'].append(f.pod_selector.match_labels)
            if rule.ports is not None:
                for p in rule.ports:
                    port = {'port': p.port, 'protocol': p.protocol}
                    new_rule['ports'].append(port)
            rules.append(new_rule)
        policies.append((pod_selector, policy_types, rules))
    return policies

def is_allowed(policies, src_labels, dst_labels, src_ip, dst_ip, proto, sport, dport):
    """
    Checks if a connection between two pods is allowed by the given network policies.
    
    Args:
        policies (List[Tuple[Dict[str, str], Dict[str, str], List[Dict[str, str]]]): The list of network policy rules to check against.
        src_labels (Dict[str, str]): The source pod's labels.
        dst_labels (Dict[str, str]: The destination pod's labels.
        src_ip (str): The source IP address.
        dst_ip (str): The destination IP address.
        proto (int): The IP protocol (TCP/UDP).
        sport (int): The source port.
        dport (int): The destination port.
    
    Returns:
        bool: True if the connection is allowed, False otherwise.
    """
    for pod_selector, policy_types, rules in policies:
        # check if both pods are selected by this network policy
        src_match = all(src_labels.get(k) == v for k, v in pod_selector.items())
        dst_match = all(dst_labels.get(k) == v for k, v in pod_selector.items())
        if not (src_match or dst_match):
            continue
        # check policy types
        if "Ingress" in policy_types and src_match:
            for rule in rules:
                from_match = any(dst_labels.get(k) == v for k, v in f.items())
                ports_match = any(p['port'] == sport and p['protocol'] == proto for p in rule['ports'])
                if from_match and ports_match:
                    return True
        elif "Egress" in policy_types and dst_match:
            for rule in rules:
                to_match = any(src_labels.get(k) == v for k, v in f.items())
                ports_match = any(p['port'] == dport and p['protocol'] == proto for p in rule['ports'])
                if to_match and ports_match:
                    return True
    return False

def monitor_network_policies():
    """
    Monitors Kubernetes network policies and updates the eBPF program on changes.
    
    Returns:
        None
    """
    policies = []
    def update_policies():
        nonlocal policies
        policies = get_network_policies()
        print(f"Updated network policies with {len(policies)} rules")
    update_policies()
    threading.Timer(10, update_policies).start() # update every 10 seconds
    
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_k8s_policy")
    ip_to_pod = {}
    
    def get_pod_info(ip):
        if ip not in ip_to_pod:
            load_kube_config()
            c = Configuration().get_default_copy()
            core_v1 = CoreV1Api(ApiClient(configuration=c))
            pods = core_v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                pod_ip = pod.status.pod_ip
                if pod_ip is not None:
                    ip_to_pod[pack("I", int(socket.inet_aton(pod_ip).encode('hex'), 16))] = pod
        return ip_to_pod.get(pack("I", int(socket.inet_aton(ip).encode('hex'), 16), None)
    
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            _, saddr, daddr, sport, dport, proto = msg.split(" ")
            saddr, daddr, sport, dport, proto = int(saddr, 16), int(daddr, 16), int(sport), int(proto)
            src_pod, dst_pod = get_pod_info(socket.inet_ntoa(pack('I', saddr)), get_pod_info(socket.inet_ntoa(pack('I', daddr))
            if src_pod and dst_pod:
                allowed = is_allowed(policies, src_pod.metadata.labels, dst_pod.metadata.labels, socket.inet_ntoa(pack('I', saddr)), socket.inet_ntoa(pack('I', daddr), sport, dport, proto)
                if not allowed:
                    b.trace_print(f"Connection from {src_pod.metadata.name} ({socket.inet_ntoa(pack('I', saddr)}) to {dst_pod.metadata.name} ({socket.inet_ntoa(pack('I', daddr)}) not allowed by policy")
        except KeyboardInterrupt:
            break
