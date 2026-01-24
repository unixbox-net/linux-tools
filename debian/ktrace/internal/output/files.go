package output

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Files struct {
	EventsJSONL string
	SummaryJSON string
	NodeJSON    string
	BundleTGZ   string
	Base        string
}

func Build(outDir, node string) (Files, error) {
	if node == "" {
		h, _ := os.Hostname()
		node = h
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	base := fmt.Sprintf("ktrace.%s.%s", node, ts)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Files{}, err
	}

	return Files{
		Base:        base,
		EventsJSONL: filepath.Join(outDir, base+".events.jsonl"),
		SummaryJSON: filepath.Join(outDir, base+".summary.json"),
		NodeJSON:    filepath.Join(outDir, base+".node.json"),
		BundleTGZ:   filepath.Join(outDir, base+".bundle.tgz"),
	}, nil
}
