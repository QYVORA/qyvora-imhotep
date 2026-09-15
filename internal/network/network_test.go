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

func TestWideCIDRsAreInternet(t *testing.T) {
	for _, cidr := range []string{"128.0.0.0/1", "192.0.0.0/2"} {
		exposed, _ := network.ExposedToInternet([]string{cidr}, 22, 22, 22)
		if !exposed {
			t.Errorf("expected wide %q exposed", cidr)
		}
	}
}

func TestRFC1918WidePrefixNotInternet(t *testing.T) {
	exposed, _ := network.ExposedToInternet([]string{"10.0.0.0/8"}, 22, 22, 22)
	if exposed {
		t.Error("10.0.0.0/8 is private and must not be flagged as internet")
	}
}

func TestAdminPortInRange(t *testing.T) {
	if p, ok := network.AdminPortInRange(20, 25); !ok || p != 22 {
		t.Errorf("range 20-25 should find 22, got (%d, %v)", p, ok)
	}
	if _, ok := network.AdminPortInRange(1, 1); ok {
		t.Error("range 1-1 must not contain an admin port")
	}
	if p, ok := network.AdminPortInRange(0, 0); !ok || p != 22 {
		t.Errorf("0-0 (single forwarded port) should fall back to 22, got (%d, %v)", p, ok)
	}
	if p, ok := network.AdminPortInRange(8000, 9000); ok {
		t.Errorf("range 8000-9000 contains no admin port, got %d", p)
	}
	if p, ok := network.AdminPortInRange(1, 65535); !ok {
		t.Error("full range must contain admin ports")
	} else if p != 22 {
		t.Errorf("first admin port in full range should be 22, got %d", p)
	}
}
