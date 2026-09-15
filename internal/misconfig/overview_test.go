package misconfig_test

import (
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
	"github.com/QYVORA/qyvora-imhotep/internal/misconfig"
)

func TestBuildCountsAssetsOnce(t *testing.T) {
	s := &cloud.Snapshot{
		Provider: cloud.ProviderAWS,
		Buckets:  []cloud.Bucket{{Name: "b", PublicRead: true}},
		Policies: []cloud.Policy{{Name: "p", Identity: "x"}},
		Groups:   []cloud.Group{{Name: "g"}},
		Networks: []cloud.Network{{
			Name: "n",
			Rules: []cloud.Rule{{
				Direction: "ingress", FromPort: 22, ToPort: 22,
				CIDRs: []string{"0.0.0.0/0"},
			}},
		}},
		DBs:      []cloud.Database{{Name: "d", PubliclyAccessible: true, Encrypted: true}},
		Computes: []cloud.Compute{{Name: "c", PubliclyExposed: true}},
	}
	ov := misconfig.Build(s)
	want := 6 // 1 bucket + 1 policy + 1 group + 1 network + 1 db + 1 compute
	if ov.TotalAssets != want {
		t.Errorf("TotalAssets = %d, want %d (assets must each be counted once)", ov.TotalAssets, want)
	}
	if len(ov.ExposedStorage) != 1 {
		t.Errorf("ExposedStorage = %d, want 1", len(ov.ExposedStorage))
	}
	if len(ov.InternetAdminPorts) != 1 {
		t.Errorf("InternetAdminPorts = %d, want 1", len(ov.InternetAdminPorts))
	}
	if len(ov.PublicDatabases) != 1 {
		t.Errorf("PublicDatabases = %d, want 1", len(ov.PublicDatabases))
	}
}

func TestBuildWideCIDRFlagsAdminPort(t *testing.T) {
	s := &cloud.Snapshot{
		Provider: cloud.ProviderAWS,
		Networks: []cloud.Network{{
			Name: "wide",
			Rules: []cloud.Rule{{
				Direction: "ingress", FromPort: 3389, ToPort: 3389,
				CIDRs: []string{"128.0.0.0/1"},
			}},
		}},
	}
	ov := misconfig.Build(s)
	if len(ov.InternetAdminPorts) != 1 {
		t.Errorf("wide CIDR /1 must flag the admin port, got %d entries", len(ov.InternetAdminPorts))
	}
}

func TestBuildPrivateRangeNeverFlagsAdminPort(t *testing.T) {
	s := &cloud.Snapshot{
		Provider: cloud.ProviderAWS,
		Networks: []cloud.Network{{
			Name: "internal",
			Rules: []cloud.Rule{{
				Direction: "ingress", FromPort: 22, ToPort: 22,
				CIDRs: []string{"10.0.0.0/8"},
			}},
		}},
	}
	ov := misconfig.Build(s)
	if len(ov.InternetAdminPorts) != 0 {
		t.Errorf("private /8 must not flag admin ports, got %d", len(ov.InternetAdminPorts))
	}
}
