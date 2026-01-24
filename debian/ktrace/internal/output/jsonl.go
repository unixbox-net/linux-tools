package output

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
)

var ErrLimitReached = errors.New("output limit reached")

type JSONLWriter struct {
	f        *os.File
	w        *bufio.Writer
	maxBytes uint64
	maxEvts  uint64

	bytes uint64
	evts  uint64

	flushEvery uint64
}

func NewJSONLWriter(path string, maxBytes, maxEvents uint64, flushEvery uint64) (*JSONLWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &JSONLWriter{
		f:          f,
		w:          bufio.NewWriterSize(f, 1<<20),
		maxBytes:   maxBytes,
		maxEvts:    maxEvents,
		flushEvery: max(1, flushEvery),
	}, nil
}

func (j *JSONLWriter) Write(obj any) error {
	if j.evts >= j.maxEvts || j.bytes >= j.maxBytes {
		return ErrLimitReached
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	// +1 newline
	if j.bytes+uint64(len(b))+1 > j.maxBytes {
		return ErrLimitReached
	}
	if _, err := j.w.Write(b); err != nil {
		return err
	}
	if err := j.w.WriteByte('\n'); err != nil {
		return err
	}

	j.evts++
	j.bytes += uint64(len(b)) + 1

	if j.evts%j.flushEvery == 0 {
		return j.w.Flush()
	}
	return nil
}

func (j *JSONLWriter) Stats() (events uint64, bytes uint64) {
	return j.evts, j.bytes
}

func (j *JSONLWriter) Close() error {
	_ = j.w.Flush()
	return j.f.Close()
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
