// Package network reasons about security-group style rules: which port ranges
// are exposed to the internet and with what protocol.
package network

import (
	"net"
	"strings"
)

// isInternetCIDR reports whether a CIDR necessarily reaches the public
// internet: the literal 0.0.0.0/0 and ::/0 ranges, "any"/"*" strings, and
// other wide IPv4 prefixes (up to /8) that are not wholly private. Narrow
// ranges such as a /16 or a specific host are internal by construction.
func isInternetCIDR(cidr string) bool {
	c := strings.TrimSpace(cidr)
	if c == "" || c == "any" || c == "*" {
		return true
	}
	_, ipnet, err := net.ParseCIDR(c)
	if err != nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 32 {
		if ones > 8 {
			return false
		}
		return !privateBlock(ipnet.IP)
	}
	if bits == 128 {
		return ones == 0
	}
	return false
}

// privateBlock reports whether the address lives in a private/reserved IPv4
// block, so wide prefixes inside RFC1918 space are never called internet.
func privateBlock(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 10, v4[0] == 127:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	case v4[0] == 169 && v4[1] == 254:
		return true
	}
	return false
}

// InternetReachable reports whether any CIDR in the rule list can reach the
// public internet.
func InternetReachable(cidrs []string) bool {
	for _, c := range cidrs {
		if isInternetCIDR(c) {
			return true
		}
	}
	return false
}

// ExposedToInternet reports whether the rule permits the given port from the
// internet. It ignores source ports and only looks at the destination range.
func ExposedToInternet(cidrs []string, fromPort, toPort, want int) (bool, int) {
	if !InternetReachable(cidrs) {
		return false, 0
	}
	if portInRange(fromPort, toPort, want) {
		return true, 1
	}
	return false, 0
}

func portInRange(from, to, want int) bool {
	if from <= 0 {
		from = want
	}
	if to <= 0 {
		to = want
	}
	return want >= from && want <= to
}

// IsAdminPort reports whether the port is a commonly internet-exposed
// administrative port (SSH, RDP, database consoles).
func IsAdminPort(p int) bool {
	switch p {
	case 22, 3389, 5900, 23, 6379, 5432, 3306:
		return true
	}
	return false
}

// AdminPortInRange reports the first known admin port inside a destination
// range (inclusive). Ranges with no admin port report false. Scan distance is
// bounded so absurdly wide ranges cannot stall linear iteration.
func AdminPortInRange(from, to int) (int, bool) {
	if from <= 0 {
		from = 1
	}
	if to <= 0 {
		to = 65535
	}
	if to-from > 4096 {
		for _, p := range adminPorts {
			if p >= from && p <= to {
				return p, true
			}
		}
		return 0, false
	}
	for p := from; p <= to; p++ {
		if IsAdminPort(p) {
			return p, true
		}
	}
	return 0, false
}

var adminPorts = []int{22, 3389, 5900, 23, 6379, 5432, 3306}
