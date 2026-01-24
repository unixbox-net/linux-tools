package enrich

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// KubeletPodMeta is best-effort metadata derived from /var/lib/kubelet/pods/<uid>/...
// This is a fallback when CRI mapping is disabled or unavailable.
//
// NOTE: kubelet on some setups may not store a pod.yaml; this is intentionally best-effort.
type KubeletPodMeta struct {
	Namespace string
	Pod       string
	Found     bool
	Source    string
}

var (
	reMetaName      = regexp.MustCompile(`(?m)^\s*name:\s*([^\s#]+)\s*$`)
	reMetaNamespace = regexp.MustCompile(`(?m)^\s*namespace:\s*([^\s#]+)\s*$`)
)

func PodMetaFromKubeletDir(podUID string) KubeletPodMeta {
	if podUID == "" || podUID == "-" {
		return KubeletPodMeta{Namespace: "-", Pod: "-", Found: false}
	}

	base := filepath.Join("/var/lib/kubelet/pods", podUID)

	// Common filenames (not guaranteed)
	candidates := []string{
		filepath.Join(base, "pod.yaml"),
		filepath.Join(base, "pod.yml"),
		filepath.Join(base, "pod.json"),
		filepath.Join(base, "pod"),
	}

	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 {
			continue
		}
		ns, name := parseMetaHeuristic(string(b))
		if ns != "" || name != "" {
			return KubeletPodMeta{
				Namespace: firstNonEmpty(ns, "-"),
				Pod:       firstNonEmpty(name, "-"),
				Found:     true,
				Source:    p,
			}
		}
	}

	// As a last resort: scan a small number of short text files for metadata
	entries, err := os.ReadDir(base)
	if err != nil {
		return KubeletPodMeta{Namespace: "-", Pod: "-", Found: false}
	}
	scanned := 0
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if scanned >= 10 {
			break
		}
		p := filepath.Join(base, ent.Name())
		// Only scan small-ish files to avoid heavy IO
		fi, err := ent.Info()
		if err != nil || fi.Size() > 256*1024 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		scanned++
		ns, name := parseMetaHeuristic(string(b))
		if ns != "" || name != "" {
			return KubeletPodMeta{
				Namespace: firstNonEmpty(ns, "-"),
				Pod:       firstNonEmpty(name, "-"),
				Found:     true,
				Source:    p,
			}
		}
	}

	return KubeletPodMeta{Namespace: "-", Pod: "-", Found: false}
}

func parseMetaHeuristic(s string) (namespace, name string) {
	// Try to focus on "metadata:" section if present (YAML); otherwise fallback to first match.
	if i := strings.Index(s, "\nmetadata:"); i >= 0 {
		// take a window after metadata
		window := s[i:]
		if len(window) > 4096 {
			window = window[:4096]
		}
		if m := reMetaName.FindStringSubmatch(window); len(m) == 2 {
			name = strings.TrimSpace(m[1])
		}
		if m := reMetaNamespace.FindStringSubmatch(window); len(m) == 2 {
			namespace = strings.TrimSpace(m[1])
		}
	}
	if name == "" {
		if m := reMetaName.FindStringSubmatch(s); len(m) == 2 {
			name = strings.TrimSpace(m[1])
		}
	}
	if namespace == "" {
		if m := reMetaNamespace.FindStringSubmatch(s); len(m) == 2 {
			namespace = strings.TrimSpace(m[1])
		}
	}
	return namespace, name
}

func firstNonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
