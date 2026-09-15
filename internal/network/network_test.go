package network_test

import (
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/network"
)

func TestInternetCIDRDetection(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "any", ""} {
		exposed, _ := network.ExposedToInternet([]string{cidr}, 22, 22, 22)
		if !exposed {
			t.Errorf("expected %q exposed (want 22)", cidr)
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24"} {
		exposed, _ := network.ExposedToInternet([]string{cidr}, 22, 22, 22)
		if exposed {
			t.Errorf("expected %q NOT exposed", cidr)
		}
	}
}

func TestPortRangeLogic(t *testing.T) {
	exposed, _ := network.ExposedToInternet([]string{"0.0.0.0/0"}, 20, 30, 22)
	if !exposed {
		t.Error("port 22 inside range 20-30 should be exposed")
	}
	exposed, _ = network.ExposedToInternet([]string{"0.0.0.0/0"}, 20, 21, 22)
	if exposed {
		t.Error("port 22 outside range 20-21 should not be exposed")
	}
}

func TestAdminPorts(t *testing.T) {
	for _, p := range []int{22, 3389, 5432, 6379, 3306, 23} {
		if !network.IsAdminPort(p) {
			t.Errorf("port %d should be admin", p)
		}
	}
	for _, p := range []int{80, 443, 8080} {
		if network.IsAdminPort(p) {
			t.Errorf("port %d must not be admin", p)
		}
	}
}
