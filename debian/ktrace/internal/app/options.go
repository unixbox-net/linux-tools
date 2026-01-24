package app

import "time"

type Options struct {
	Duration time.Duration
	OutDir   string
	Node     string

	// user-space filters
	PortsCSV   string
	CommSubstr string

	// in-kernel / output filters
	DNSOnly        bool
	IgnoreLoopback bool
	Sample         uint32

	// guardrails
	MaxEvents uint64
	MaxBytes  uint64

	// enrichments
	WithConntrack  bool
	ConntrackEvery time.Duration

	WithCRI      bool
	CRIEndpoints []string

	WithRetrans    bool
	WithConnectLat bool

	EnableNS       bool
	EnableSecurity bool

	Quiet bool
}

type Result struct {
	EventsJSONL string
	SummaryJSON string
	NodeJSON    string
	BundleTGZ   string
}
