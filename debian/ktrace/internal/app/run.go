package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/kubedos/ktrace/internal/bpf"
	"github.com/kubedos/ktrace/internal/enrich"
	"github.com/kubedos/ktrace/internal/output"
	"github.com/kubedos/ktrace/internal/summary"
	"github.com/kubedos/ktrace/internal/util"
)

const (
	evtTCPState   = 1
	evtUDPSend    = 2
	evtUDPRecv    = 3
	evtConnectLat = 4
	evtTCPRetrans = 5
)

type bpfConfig struct {
	SampleRate     uint32
	DNSOnly        uint32
	PortAllow      [8]uint16
	PortAllowLen   uint16
	EnableNS       uint8
	EnableSecurity uint8
	Pad            uint16
}

type bpfEvent struct {
	TsNs uint64
	Type uint32

	Pid  uint32
	Tgid uint32
	Ppid uint32

	Uid uint32
	Gid uint32

	Netns  uint32
	Mntns  uint32
	Pidns  uint32
	Userns uint32

	SeccompMode uint32
	Fd          uint32

	CgroupId uint64

	CapEff [2]uint32
	Pad2   uint32

	Comm [16]byte

	Af    uint8
	Proto uint8
	Sport uint16
	Dport uint16
	Pad3  uint16

	Saddr [16]byte
	Daddr [16]byte

	TcpOldstate uint32
	TcpNewstate uint32

	Bytes uint32
	Ret   int32

	LatencyNs uint64
}

func Run(ctx context.Context, opts Options) (Result, error) {
	if runtime.GOOS != "linux" {
		return Result{}, errors.New("ktrace requires Linux")
	}
	if opts.Duration <= 0 {
		opts.Duration = 60 * time.Second
	}
	if opts.MaxEvents == 0 {
		opts.MaxEvents = 500000
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 250 * 1024 * 1024
	}
	if opts.Sample == 0 {
		opts.Sample = 1
	}

	node := opts.Node
	if node == "" {
		h, _ := os.Hostname()
		node = h
	}

	files, err := output.Build(opts.OutDir, node)
	if err != nil {
		return Result{}, err
	}

	// Remove memlock rlimit (required for older kernels; harmless otherwise)
	if err := rlimit.RemoveMemlock(); err != nil {
		return Result{}, fmt.Errorf("rlimit memlock: %w", err)
	}

	// Load BPF objects (CO-RE). This requires BTF.
	var objs bpf.KtraceObjects
	if err := bpf.LoadKtraceObjects(&objs, nil); err != nil {
		return Result{}, fmt.Errorf("load BPF objects failed: %w (is /sys/kernel/btf/vmlinux present?)", err)
	}
	defer objs.Close()

	// Build in-kernel config.
	ports, err := parsePortsCSV(opts.PortsCSV)
	if err != nil {
		return Result{}, err
	}
	if opts.DNSOnly {
		ports = []uint16{53}
	}

	cfg := bpfConfig{
		SampleRate:     opts.Sample,
		DNSOnly:        boolToU32(opts.DNSOnly),
		EnableNS:       boolToU8(opts.EnableNS),
		EnableSecurity: boolToU8(opts.EnableSecurity),
	}
	// port allowlist is capped to 8 for kernel-side filtering
	if len(ports) > 8 {
		cfg.PortAllowLen = 8
		for i := 0; i < 8; i++ {
			cfg.PortAllow[i] = ports[i]
		}
	} else {
		cfg.PortAllowLen = uint16(len(ports))
		for i := 0; i < len(ports); i++ {
			cfg.PortAllow[i] = ports[i]
		}
	}

	// Update config map entry 0.
	if err := objs.ConfigMap.Put(uint32(0), cfg); err != nil {
		return Result{}, fmt.Errorf("update config map: %w", err)
	}

	// Attach programs
	links := make([]link.Link, 0, 8)
	attach := func(l link.Link, err error) error {
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	if err := attach(link.Kprobe("tcp_set_state", objs.KtraceTcpSetState, nil)); err != nil {
		return Result{}, fmt.Errorf("attach kprobe tcp_set_state: %w", err)
	}
	if err := attach(link.Kprobe("udp_sendmsg", objs.KtraceUdpSendmsg, nil)); err != nil {
		return Result{}, fmt.Errorf("attach kprobe udp_sendmsg: %w", err)
	}
	if err := attach(link.Kprobe("udp_recvmsg", objs.KtraceUdpRecvmsgEnter, nil)); err != nil {
		return Result{}, fmt.Errorf("attach kprobe udp_recvmsg: %w", err)
	}
	if err := attach(link.Kretprobe("udp_recvmsg", objs.KtraceUdpRecvmsgExit, nil)); err != nil {
		return Result{}, fmt.Errorf("attach kretprobe udp_recvmsg: %w", err)
	}

	if opts.WithConnectLat {
		// Syscall tracepoints exist on most distros.
		if err := attach(link.Tracepoint("syscalls", "sys_enter_connect", objs.KtraceSysEnterConnect, nil)); err != nil {
			return Result{}, fmt.Errorf("attach tracepoint sys_enter_connect: %w", err)
		}
		if err := attach(link.Tracepoint("syscalls", "sys_exit_connect", objs.KtraceSysExitConnect, nil)); err != nil {
			return Result{}, fmt.Errorf("attach tracepoint sys_exit_connect: %w", err)
		}
	}

	if opts.WithRetrans {
		if err := attach(link.Kprobe("tcp_retransmit_skb", objs.KtraceTcpRetransmitSkb, nil)); err != nil {
			return Result{}, fmt.Errorf("attach kprobe tcp_retransmit_skb: %w", err)
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return Result{}, fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	// Wall-clock converter
	ktimeConv, err := util.NewKTimeToWall()
	if err != nil {
		return Result{}, fmt.Errorf("clock: %w", err)
	}

	// Output writers
	jw, err := output.NewJSONLWriter(files.EventsJSONL, opts.MaxBytes, opts.MaxEvents, 200)
	if err != nil {
		return Result{}, err
	}
	defer jw.Close()

	// Enrichers
	var ct *enrich.ConntrackTable
	if opts.WithConntrack {
		ct = enrich.NewConntrackTable()
		_ = ct.Refresh() // best-effort
	}

	var cri *enrich.CRIResolver
	if opts.WithCRI && len(opts.CRIEndpoints) > 0 {
		if r, err := enrich.NewCRIResolver(opts.CRIEndpoints, 2*time.Second); err == nil {
			cri = r
			defer cri.Close()
		}
	}

	// Counters for summary
	topComm := summary.Counter{}
	topTuple := summary.Counter{}
	topPorts := summary.Counter{}
	tcpTransitions := summary.Counter{}
	eventTypes := summary.Counter{}

	// DNS pairing heuristic (user-space)
	type dnsKey struct {
		pid     uint32
		sport   uint16
		server  string
		family  string
		podHint string
	}
	dnsOutstanding := make(map[dnsKey]time.Time, 20000)
	dnsSendsByPod := summary.Counter{}
	dnsRecvsByPod := summary.Counter{}

	// Start conntrack refresher
	stopCT := make(chan struct{})
	if ct != nil && opts.ConntrackEvery > 0 {
		go func() {
			t := time.NewTicker(opts.ConntrackEvery)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					_ = ct.Refresh()
				case <-stopCT:
					return
				}
			}
		}()
	}
	defer close(stopCT)

	// Node metadata (start)
	nodeMeta, _ := buildNodeMeta(opts, node)
	nodeMeta["ts_start"] = time.Now().UTC().Format(time.RFC3339Nano)

	_ = writeJSON(files.NodeJSON, nodeMeta)

	if !opts.Quiet {
		fmt.Printf("[ktrace] node=%s duration=%s out=%s\n", node, opts.Duration.String(), opts.OutDir)
		fmt.Printf("[ktrace] events=%s\n", files.EventsJSONL)
	}

	deadline := time.Now().Add(opts.Duration)

	var (
		parseDrops uint64
		limitHit   bool
	)
	for time.Now().Before(deadline) {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			// transient read error
			continue
		}
		var ev bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			parseDrops++
			continue
		}

		wall := ktimeConv.ToUTC(ev.TsNs)
		ts := wall.Format("2006-01-02T15:04:05.000Z07:00")
		comm := strings.TrimRight(string(ev.Comm[:]), "\x00")

		afStr := "unknown"
		familyCT := ""
		switch ev.Af {
		case util.AF_INET:
			afStr = "ipv4"
			familyCT = "ipv4"
		case util.AF_INET6:
			afStr = "ipv6"
			familyCT = "ipv6"
		}

		srcIP := util.FormatIP(ev.Af, ev.Saddr)
		dstIP := util.FormatIP(ev.Af, ev.Daddr)
		if opts.IgnoreLoopback && (util.IsLoopback(srcIP) || util.IsLoopback(dstIP)) {
			continue
		}
		if opts.CommSubstr != "" && !strings.Contains(comm, opts.CommSubstr) {
			continue
		}
		// user-space port filter (supports >8 ports)
		if len(ports) > 8 {
			if !portAllowed(ports, ev.Sport, ev.Dport) {
				continue
			}
		}

		// Kubernetes hints
		cgh := enrich.HintsFromPID(int(ev.Pid))
		k8sNS, k8sPod, k8sContainer, k8sPodUID, k8sContainerID := "-", "-", "-", "-", "-"
		if cgh.PodUID != "-" {
			k8sPodUID = cgh.PodUID
		}
		if cgh.ContainerID != "-" {
			k8sContainerID = cgh.ContainerID
		}

		if cri != nil && k8sContainerID != "-" {
			if ident, ok := cri.ResolveContainer(k8sContainerID); ok {
				k8sNS = ident.Namespace
				k8sPod = ident.Pod
				k8sContainer = ident.Container
				if ident.PodUID != "-" && ident.PodUID != "" {
					k8sPodUID = ident.PodUID
				}
			}
		} else if k8sPodUID != "-" {
			if meta := enrich.PodMetaFromKubeletDir(k8sPodUID); meta.Found {
				k8sNS = meta.Namespace
				k8sPod = meta.Pod
			}
		}

		k8sHintKey := k8sNS + "/" + k8sPod + "/" + k8sContainer
		if k8sHintKey == "-/-/-" {
			k8sHintKey = comm
		}

		// Basic counters
		eventTypes.Inc(evtTypeName(ev.Type), 1)
		topComm.Inc(comm, 1)
		if ev.Sport != 0 {
			topPorts.Inc(fmt.Sprintf("%d", ev.Sport), 1)
		}
		if ev.Dport != 0 {
			topPorts.Inc(fmt.Sprintf("%d", ev.Dport), 1)
		}

		tuple := util.Tuple(srcIP, ev.Sport, dstIP, ev.Dport)
		if ev.Type == evtConnectLat {
			// connect latency events only have dst IP/port; build a tuple-like string
			tuple = fmt.Sprintf("?:? -> %s:%d", dstIP, ev.Dport)
		}
		topTuple.Inc(tuple, 1)

		// conntrack annotation (best-effort)
		var ctObj map[string]any
		if ct != nil && (ev.Proto == unix.IPPROTO_TCP || ev.Proto == unix.IPPROTO_UDP) && srcIP != "" && dstIP != "" && ev.Sport != 0 && ev.Dport != 0 {
			protoCT := "tcp"
			if ev.Proto == unix.IPPROTO_UDP {
				protoCT = "udp"
			}
			if ent, ok := ct.Lookup(familyCT, protoCT, srcIP, ev.Sport, dstIP, ev.Dport); ok {
				ctObj = map[string]any{
					"state":   ent.State,
					"timeout": ent.Timeout,
					"reply":   fmt.Sprintf("%s:%d -> %s:%d", ent.Reply.SrcIP, ent.Reply.SrcPort, ent.Reply.DstIP, ent.Reply.DstPort),
				}
			}
		}

		// DNS RTT heuristic (user-space; best-effort)
		var dnsObj map[string]any
		if ev.Type == evtUDPSend && ev.Dport == 53 {
			key := dnsKey{
				pid:     ev.Pid,
				sport:   ev.Sport,
				server:  dstIP,
				family:  afStr,
				podHint: k8sHintKey,
			}
			dnsOutstanding[key] = wall
			// guardrail: cap outstanding DNS map
			if len(dnsOutstanding) > 50000 {
				cutoff := wall.Add(-30 * time.Second)
				for k, t0 := range dnsOutstanding {
					if t0.Before(cutoff) {
						delete(dnsOutstanding, k)
					}
				}
				// still too big? drop arbitrary entries
				for k := range dnsOutstanding {
					if len(dnsOutstanding) <= 50000 {
						break
					}
					delete(dnsOutstanding, k)
				}
			}
			dnsSendsByPod.Inc(k8sHintKey, 1)
		}
		if ev.Type == evtUDPRecv && ev.Sport == 53 {
			key := dnsKey{
				pid:     ev.Pid,
				sport:   ev.Dport, // local port
				server:  srcIP,    // server sending reply
				family:  afStr,
				podHint: k8sHintKey,
			}
			if t0, ok := dnsOutstanding[key]; ok {
				rtt := wall.Sub(t0).Seconds() * 1000.0
				delete(dnsOutstanding, key)
				dnsObj = map[string]any{
					"rtt_ms": rtt,
				}
			}
			dnsRecvsByPod.Inc(k8sHintKey, 1)
		}

		// TCP transition counter
		if ev.Type == evtTCPState {
			old := tcpStates[ev.TcpOldstate]
			if old == "" {
				old = fmt.Sprintf("%d", ev.TcpOldstate)
			}
			newS := tcpStates[ev.TcpNewstate]
			if newS == "" {
				newS = fmt.Sprintf("%d", ev.TcpNewstate)
			}
			tcpTransitions.Inc(old+"->"+newS, 1)
		}

		// Build JSON event object
		obj := map[string]any{
			"ts":   ts,
			"type": evtTypeName(ev.Type),
			"node": node,

			"pid":  ev.Pid,
			"tgid": ev.Tgid,
			"ppid": ev.Ppid,

			"uid":  ev.Uid,
			"gid":  ev.Gid,
			"comm": comm,

			"af":    afStr,
			"proto": protoName(ev.Proto),
		}

		// ns + security fields
		if opts.EnableNS {
			obj["ns"] = map[string]any{
				"net":  ev.Netns,
				"mnt":  ev.Mntns,
				"pid":  ev.Pidns,
				"user": ev.Userns,
			}
		}
		if opts.EnableSecurity {
			obj["sec"] = map[string]any{
				"seccomp_mode": ev.SeccompMode,
				"caps_eff":     fmt.Sprintf("0x%08x_%08x", ev.CapEff[1], ev.CapEff[0]),
			}
		}

		obj["cgroup"] = map[string]any{
			"id":   ev.CgroupId,
			"path": cgh.CGroupLine,
		}
		obj["k8s"] = map[string]any{
			"pod_uid":      k8sPodUID,
			"namespace":    k8sNS,
			"pod":          k8sPod,
			"container":    k8sContainer,
			"container_id": shorten(k8sContainerID, 16),
		}

		// event-type specifics
		switch ev.Type {
		case evtTCPState:
			old := tcpStates[ev.TcpOldstate]
			if old == "" {
				old = fmt.Sprintf("%d", ev.TcpOldstate)
			}
			newS := tcpStates[ev.TcpNewstate]
			if newS == "" {
				newS = fmt.Sprintf("%d", ev.TcpNewstate)
			}
			obj["tuple"] = tuple
			obj["old_state"] = old
			obj["new_state"] = newS
		case evtUDPSend, evtUDPRecv:
			obj["tuple"] = tuple
			obj["bytes"] = ev.Bytes
		case evtConnectLat:
			obj["dst"] = fmt.Sprintf("%s:%d", dstIP, ev.Dport)
			obj["fd"] = ev.Fd
			obj["ret"] = ev.Ret
			if ev.LatencyNs > 0 {
				obj["latency_ms"] = float64(ev.LatencyNs) / 1e6
			}
		case evtTCPRetrans:
			obj["tuple"] = tuple
		default:
			obj["tuple"] = tuple
		}

		if ctObj != nil {
			obj["conntrack"] = ctObj
		}
		if dnsObj != nil {
			obj["dns"] = dnsObj
		}

		// write
		if !limitHit {
			if err := jw.Write(obj); err != nil {
				if errors.Is(err, output.ErrLimitReached) {
					limitHit = true
				} else {
					return Result{}, err
				}
			}
		}
	}

	// Close writer
	eventsWritten, bytesWritten := jw.Stats()

	// Read stats_map
	emitted, ringDrops, filtered := readStats(&objs)

	// Node meta (end)
	nodeMeta["ts_end"] = time.Now().UTC().Format(time.RFC3339Nano)
	nodeMeta["events_written"] = eventsWritten
	nodeMeta["bytes_written"] = bytesWritten
	nodeMeta["events_dropped_parse"] = parseDrops
	nodeMeta["bpf_stats"] = map[string]any{
		"emitted":     emitted,
		"ringbuf_drop": ringDrops,
		"filtered":    filtered,
	}

	_ = writeJSON(files.NodeJSON, nodeMeta)

	// DNS suspects (many sends, no recvs) heuristic
	dnsSuspects := make([]map[string]any, 0, 20)
	for _, kv := range summary.TopN(dnsSendsByPod, 50) {
		sends := kv.Count
		recvs := dnsRecvsByPod[kv.Key]
		if sends >= 20 && recvs == 0 {
			ns, pod, container := splitK8sKey(kv.Key)
			dnsSuspects = append(dnsSuspects, map[string]any{
				"namespace": ns,
				"pod":       pod,
				"container": container,
				"udp_sends": sends,
				"udp_recvs": recvs,
				"interpretation": "Many DNS sends but no DNS receives observed (heuristic). Check CoreDNS/NodeLocalDNS, policy/routing, and node-level drops.",
			})
		}
	}

	summaryObj := map[string]any{
		"tool":    "ktrace",
		"version": "0.9.0",
		"node":    node,
		"ts_start": nodeMeta["ts_start"],
		"ts_end":   nodeMeta["ts_end"],

		"events_written": eventsWritten,
		"bytes_written":  bytesWritten,
		"parse_drops":    parseDrops,
		"bpf_stats":      nodeMeta["bpf_stats"],

		"top": map[string]any{
			"event_types":     summary.TopN(eventTypes, 20),
			"comm":            summary.TopN(topComm, 30),
			"tuples":          summary.TopN(topTuple, 30),
			"ports":           summary.TopN(topPorts, 30),
			"tcp_transitions": summary.TopN(tcpTransitions, 30),
		},
		"dns_suspects": dnsSuspects,
	}

	if err := writeJSON(files.SummaryJSON, summaryObj); err != nil {
		return Result{}, err
	}

	// Bundle
	items := []output.BundleItem{
		{Path: files.EventsJSONL},
		{Path: files.SummaryJSON},
		{Path: files.NodeJSON},
	}
	if err := output.WriteBundleTGZ(files.BundleTGZ, items); err != nil {
		return Result{}, err
	}

	return Result{
		EventsJSONL: files.EventsJSONL,
		SummaryJSON: files.SummaryJSON,
		NodeJSON:    files.NodeJSON,
		BundleTGZ:   files.BundleTGZ,
	}, nil
}

func evtTypeName(t uint32) string {
	switch t {
	case evtTCPState:
		return "tcp_state"
	case evtUDPSend:
		return "udp_send"
	case evtUDPRecv:
		return "udp_recv"
	case evtConnectLat:
		return "connect_latency"
	case evtTCPRetrans:
		return "tcp_retrans"
	default:
		return fmt.Sprintf("unknown_%d", t)
	}
}

func protoName(p uint8) string {
	switch p {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func portAllowed(allow []uint16, sport, dport uint16) bool {
	for _, p := range allow {
		if p == sport || p == dport {
			return true
		}
	}
	return false
}

func shorten(s string, n int) string {
	if s == "" || s == "-" {
		return "-"
	}
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func buildNodeMeta(opts Options, node string) (map[string]any, error) {
	var uts unix.Utsname
	_ = unix.Uname(&uts)

	uname := map[string]any{
		"sysname":  charsToString(uts.Sysname[:]),
		"release":  charsToString(uts.Release[:]),
		"version":  charsToString(uts.Version[:]),
		"machine":  charsToString(uts.Machine[:]),
		"nodename": charsToString(uts.Nodename[:]),
	}

	return map[string]any{
		"tool":    "ktrace",
		"version": "0.9.0",
		"node":    node,
		"args": map[string]any{
			"duration":            opts.Duration.String(),
			"out_dir":             opts.OutDir,
			"ports":               opts.PortsCSV,
			"comm":                opts.CommSubstr,
			"dns_only":            opts.DNSOnly,
			"ignore_loopback":     opts.IgnoreLoopback,
			"sample":              opts.Sample,
			"max_events":          opts.MaxEvents,
			"max_bytes":           opts.MaxBytes,
			"with_conntrack":      opts.WithConntrack,
			"conntrack_every":     opts.ConntrackEvery.String(),
			"with_cri":            opts.WithCRI,
			"cri_endpoints":       opts.CRIEndpoints,
			"with_retrans":        opts.WithRetrans,
			"with_connect_latency": opts.WithConnectLat,
			"enable_ns":           opts.EnableNS,
			"enable_security":     opts.EnableSecurity,
		},
		"uname": uname,
		"notes": []string{
			"Metadata-only capture (no payloads).",
			"Conntrack correlation is best-effort (proc snapshot).",
			"CRI mapping is best-effort and does not contact the Kubernetes API server.",
		},
	}, nil
}

func charsToString(ca []int8) string {
	out := make([]byte, 0, len(ca))
	for _, c := range ca {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func writeJSON(path string, obj any) error {
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readStats(objs *bpf.KtraceObjects) (emitted, ringDrops, filtered uint64) {
	var v uint64
	if err := objs.StatsMap.Lookup(uint32(0), &v); err == nil {
		emitted = v
	}
	v = 0
	if err := objs.StatsMap.Lookup(uint32(1), &v); err == nil {
		ringDrops = v
	}
	v = 0
	if err := objs.StatsMap.Lookup(uint32(2), &v); err == nil {
		filtered = v
	}
	return
}

func splitK8sKey(key string) (ns, pod, container string) {
	parts := strings.Split(key, "/")
	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	return "-", key, "-"
}
