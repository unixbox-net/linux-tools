package app

import (
	"fmt"
	"strconv"
	"strings"
)

func parsePortsCSV(csv string) ([]uint16, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	parts := strings.Split(csv, ",")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}
