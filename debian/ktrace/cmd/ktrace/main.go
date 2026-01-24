package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kubedos/ktrace/internal/app"
)

func main() {
	var (
		duration        = flag.Duration("duration", 60*time.Second, "Capture duration (e.g. 30s, 2m).")
		outDir          = flag.String("out-dir", "./out", "Output directory.")
		node            = flag.String("node", "", "Node name label (default: hostname).")
		portsCSV        = flag.String("ports", "", "Comma-separated port allowlist (max 8 for in-kernel filter; unlimited user-space). Matches src or dst port.")
		commSubstr      = flag.String("comm", "", "Only include events where comm contains this substring (user-space filter).")
		dnsOnly         = flag.Bool("dns-only", false, "Focus on DNS (port 53).")
		ignoreLoopback  = flag.Bool("ignore-loopback", true, "Drop loopback tuples (127.0.0.0/8, ::1) to reduce noise.")
		sample          = flag.Uint("sample", 1, "Sampling factor: 1 = all events, N = ~1/N events (in-kernel).")
		maxEvents       = flag.Uint("max-events", 500000, "Hard cap on events written (guardrail).")
		maxBytes        = flag.Uint64("max-bytes", 250*1024*1024, "Hard cap on bytes written to JSONL (guardrail).")
		withConntrack   = flag.Bool("with-conntrack", true, "Annotate events with conntrack state (best-effort) by reading /proc/net/nf_conntrack.")
		conntrackEvery  = flag.Duration("conntrack-every", 5*time.Second, "Conntrack refresh interval (best-effort).")
		withCRI         = flag.Bool("with-cri", true, "Resolve container/pod identity via CRI labels (no API server).")
		criEndpoints    = flag.String("cri-endpoints", "unix:///run/containerd/containerd.sock,unix:///var/run/containerd/containerd.sock,unix:///run/crio/crio.sock", "Comma-separated CRI endpoints to try.")
		withRetrans     = flag.Bool("with-retrans", false, "Enable tcp_retransmit_skb probe (extra detail).")
		withConnectLat  = flag.Bool("with-connect-latency", false, "Enable connect() latency events (extra detail).")
		enableNS        = flag.Bool("enable-ns", true, "Include namespace inode IDs (netns/mntns/pidns/userns).")
		enableSecurity  = flag.Bool("enable-security", true, "Include seccomp mode + effective caps (best-effort).")
		quiet           = flag.Bool("quiet", false, "Reduce console output (recommended for automation).")
	)

	flag.Parse()

	opts := app.Options{
		Duration:       *duration,
		OutDir:         *outDir,
		Node:           *node,
		PortsCSV:       *portsCSV,
		CommSubstr:     *commSubstr,
		DNSOnly:        *dnsOnly,
		IgnoreLoopback: *ignoreLoopback,
		Sample:         uint32(*sample),
		MaxEvents:      uint64(*maxEvents),
		MaxBytes:       *maxBytes,
		WithConntrack:  *withConntrack,
		ConntrackEvery: *conntrackEvery,
		WithCRI:        *withCRI,
		CRIEndpoints:   splitCSV(*criEndpoints),
		WithRetrans:    *withRetrans,
		WithConnectLat: *withConnectLat,
		EnableNS:       *enableNS,
		EnableSecurity: *enableSecurity,
		Quiet:          *quiet,
	}

	ctx := context.Background()
	res, err := app.Run(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ktrace error:", err)
		os.Exit(1)
	}

	if !opts.Quiet {
		fmt.Println("[ktrace] done")
	}
	fmt.Println("events:", res.EventsJSONL)
	fmt.Println("summary:", res.SummaryJSON)
	fmt.Println("node:", res.NodeJSON)
	fmt.Println("bundle:", res.BundleTGZ)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
