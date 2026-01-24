package enrich

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ConntrackEntry struct {
	Family    string // ipv4/ipv6
	Proto     string // tcp/udp/...
	State     string // ESTABLISHED, ...
	Timeout   int    // seconds (best-effort)
	Orig      Flow
	Reply     Flow
	RawSuffix string // optional tag data (ASSURED, mark=..., ...)
}

type Flow struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

func (f Flow) Key(proto string, family string) string {
	// key format stable for map lookups; keep it simple
	return family + "|" + proto + "|" + f.SrcIP + "|" + itoa(int(f.SrcPort)) + ">" + f.DstIP + "|" + itoa(int(f.DstPort))
}

type ConntrackTable struct {
	mu   sync.RWMutex
	m    map[string]ConntrackEntry // keys for both orig and reply direction
	last time.Time
}

func NewConntrackTable() *ConntrackTable {
	return &ConntrackTable{m: make(map[string]ConntrackEntry, 200000)}
}

func (t *ConntrackTable) Lookup(family, proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16) (ConntrackEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	key := family + "|" + proto + "|" + srcIP + "|" + itoa(int(srcPort)) + ">" + dstIP + "|" + itoa(int(dstPort))
	v, ok := t.m[key]
	return v, ok
}

func (t *ConntrackTable) LastRefresh() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.last
}

func (t *ConntrackTable) Refresh() error {
	path := "/proc/net/nf_conntrack"
	if _, err := os.Stat(path); err != nil {
		path = "/proc/net/ip_conntrack"
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tmp := make(map[string]ConntrackEntry, 200000)

	sc := bufio.NewScanner(f)
	// conntrack lines can be long; raise scanner buffer
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 512*1024)

	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		ent, ok := parseConntrackLine(ln)
		if !ok {
			continue
		}
		tmp[ent.Orig.Key(ent.Proto, ent.Family)] = ent
		// also index reverse direction for lookups
		tmp[ent.Reply.Key(ent.Proto, ent.Family)] = ent
	}
	if err := sc.Err(); err != nil {
		return err
	}

	t.mu.Lock()
	t.m = tmp
	t.last = time.Now()
	t.mu.Unlock()
	return nil
}

func parseConntrackLine(ln string) (ConntrackEntry, bool) {
	// tokenization
	toks := strings.Fields(ln)
	if len(toks) < 8 {
		return ConntrackEntry{}, false
	}

	family := toks[0] // ipv4/ipv6
	if family != "ipv4" && family != "ipv6" {
		return ConntrackEntry{}, false
	}

	// locate proto token (tcp/udp/icmp/...)
	proto := ""
	protoIdx := -1
	for i, t := range toks {
		switch t {
		case "tcp", "udp", "icmp", "icmpv6":
			proto = t
			protoIdx = i
			break
		}
		if protoIdx != -1 {
			break
		}
	}
	if protoIdx == -1 {
		return ConntrackEntry{}, false
	}

	// parse timeout and optional state after proto token
	timeout := 0
	state := "-"
	i := protoIdx + 1
	// skip proto number if present
	if i < len(toks) && isNumber(toks[i]) {
		i++
	}
	if i < len(toks) && isNumber(toks[i]) {
		timeout, _ = strconv.Atoi(toks[i])
		i++
	}
	if i < len(toks) && !strings.Contains(toks[i], "=") && !isNumber(toks[i]) && !strings.HasPrefix(toks[i], "[") {
		state = toks[i]
		i++
	}

	// parse kv pairs; we only care about first two src/dst/sport/dport sets
	var (
		orig Flow
		rep  Flow
		seen int // 0..8 fields
	)

	// We parse in order and fill orig then reply.
	for ; i < len(toks); i++ {
		t := toks[i]
		if !strings.Contains(t, "=") {
			continue
		}
		kv := strings.SplitN(t, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "src":
			if seen < 4 {
				orig.SrcIP = v
			} else if seen < 8 {
				rep.SrcIP = v
			}
		case "dst":
			if seen < 4 {
				orig.DstIP = v
			} else if seen < 8 {
				rep.DstIP = v
			}
		case "sport":
			p, err := strconv.Atoi(v)
			if err != nil {
				continue
			}
			if seen < 4 {
				orig.SrcPort = uint16(p)
			} else if seen < 8 {
				rep.SrcPort = uint16(p)
			}
		case "dport":
			p, err := strconv.Atoi(v)
			if err != nil {
				continue
			}
			if seen < 4 {
				orig.DstPort = uint16(p)
			} else if seen < 8 {
				rep.DstPort = uint16(p)
			}
		}

		// Advance "seen" when we have a complete orig or reply set:
		// This is a heuristic: increment each time we see src/dst/sport/dport (order varies).
		if k == "dport" {
			if seen < 4 {
				seen = 4
			} else if seen < 8 {
				seen = 8
				break
			}
		}
	}

	if orig.SrcIP == "" || orig.DstIP == "" {
		return ConntrackEntry{}, false
	}

	// Remaining suffix for debugging
	suffix := ""
	if idx := strings.Index(ln, " ["); idx >= 0 {
		suffix = ln[idx:]
	} else {
		// keep a small tail for marks etc
		if len(ln) > 200 {
			suffix = ln[len(ln)-200:]
		}
	}

	return ConntrackEntry{
		Family:    family,
		Proto:     proto,
		State:     state,
		Timeout:   timeout,
		Orig:      orig,
		Reply:     rep,
		RawSuffix: suffix,
	}, true
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

var ErrConntrackUnavailable = errors.New("conntrack proc file unavailable")
