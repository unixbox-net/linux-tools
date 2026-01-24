package summary

import (
	"sort"
)

type Counter map[string]uint64

func (c Counter) Inc(key string, n uint64) {
	if key == "" {
		key = "-"
	}
	c[key] += n
}

type KV struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

func TopN(c Counter, n int) []KV {
	if n <= 0 {
		return nil
	}
	out := make([]KV, 0, len(c))
	for k, v := range c {
		out = append(out, KV{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
