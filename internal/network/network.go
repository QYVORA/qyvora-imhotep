// Package network reasons about security-group style rules: which port ranges
// are exposed to the internet and with what protocol.
package network

import (
	"net"
	"strings"
)

// isInternetCIDR reports whether a CIDR necessarily reaches the public
// internet (either literally 0.0.0.0/0 or a wide unspecified range such as
// ::/0). Non-IP notation like "any" is treated as internet.
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
	return ones == 0 && bits > 0
}

// ExposedToInternet reports whether the rule permits the given port from the
// internet. It ignores source ports and only looks at the destination range.
func ExposedToInternet(cidrs []string, fromPort, toPort, want int) (bool, int) {
	for _, c := range cidrs {
		if !isInternetCIDR(c) {
			continue
		}
		if portInRange(fromPort, toPort, want) {
			return true, 1
		}
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
