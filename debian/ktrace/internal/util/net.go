package util

import (
	"fmt"
	"net"
)

const (
	AF_INET  = 2
	AF_INET6 = 10
)

func FormatIP(af uint8, addr [16]byte) string {
	switch af {
	case AF_INET:
		return net.IP(addr[:4]).String()
	case AF_INET6:
		// net.IP will compress appropriately.
		return net.IP(addr[:16]).String()
	default:
		// fallback: try IPv4
		return net.IP(addr[:4]).String()
	}
}

func IsLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func Tuple(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	return fmt.Sprintf("%s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
}
