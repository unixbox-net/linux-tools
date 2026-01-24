package util

import (
	"time"

	"golang.org/x/sys/unix"
)

// KTimeToWall converts bpf_ktime_get_ns timestamps to UTC wall time.
//
// bpf_ktime_get_ns() is based on ktime_get_ns() (monotonic since boot).
// CLOCK_MONOTONIC is the closest userland clock source.
//
// This is "good enough" for forensic snapshots and allows correlating
// events with logs.
type KTimeToWall struct {
	baseMonoNs uint64
	baseWall   time.Time
}

func NewKTimeToWall() (*KTimeToWall, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, err
	}
	baseMono := uint64(ts.Nano())
	baseWall := time.Now().UTC()
	return &KTimeToWall{baseMonoNs: baseMono, baseWall: baseWall}, nil
}

func (c *KTimeToWall) ToUTC(ktimeNs uint64) time.Time {
	if ktimeNs <= c.baseMonoNs {
		return c.baseWall
	}
	d := time.Duration(ktimeNs - c.baseMonoNs)
	return c.baseWall.Add(d)
}
