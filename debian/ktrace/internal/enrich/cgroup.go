package enrich

import (
	"os"
	"regexp"
	"strings"
)

var (
	rePodUID     = regexp.MustCompile(`pod([0-9a-f]{8,})`)
	reContainer  = regexp.MustCompile(`([0-9a-f]{32,64})`)
	reContainerd = regexp.MustCompile(`cri-containerd-([0-9a-f]{32,64})\.scope`)
)

type CGroupHints struct {
	CGroupLine  string // representative cgroup line
	PodUID      string // full (best-effort)
	PodUIDShort string // first 8
	ContainerID string // full (best-effort)
}

func HintsFromPID(pid int) CGroupHints {
	b, err := os.ReadFile(procPath(pid, "cgroup"))
	if err != nil || len(b) == 0 {
		return CGroupHints{CGroupLine: "-", PodUID: "-", PodUIDShort: "-", ContainerID: "-"}
	}
	raw := string(b)

	lines := []string{}
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		lines = append(lines, ln)
	}
	longest := "-"
	for _, ln := range lines {
		if len(ln) > len(longest) {
			longest = ln
		}
	}

	podUID := "-"
	if m := rePodUID.FindStringSubmatch(raw); len(m) == 2 {
		podUID = strings.ToLower(m[1])
	}

	containerID := "-"
	if m := reContainerd.FindStringSubmatch(raw); len(m) == 2 {
		containerID = strings.ToLower(m[1])
	} else if m := reContainer.FindStringSubmatch(raw); len(m) == 2 {
		containerID = strings.ToLower(m[1])
	}

	podShort := "-"
	if podUID != "-" && len(podUID) >= 8 {
		podShort = podUID[:8]
	}

	return CGroupHints{
		CGroupLine:  longest,
		PodUID:      podUID,
		PodUIDShort: podShort,
		ContainerID: containerID,
	}
}

func procPath(pid int, file string) string {
	return "/proc/" + itoa(pid) + "/" + file
}

// tiny itoa to avoid fmt in hot path
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [32]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
