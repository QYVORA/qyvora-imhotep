// Package misconfig aggregates multi-resource configuration signals into an
// overview used by reports: how many assets each posture class covers, and
// which network/service exposure combinations exist. It produces no findings
// on its own; rule authors consume the aggregate.
package misconfig

import (
	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
)

// Overview summarizes a snapshot's configuration surface for reporting.
type Overview struct {
	Provider            cloud.Provider `json:"provider"`
	Region              string         `json:"region"`
	ScopeID             string         `json:"scope_id"`
	TotalAssets         int            `json:"total_assets"`
	ExposedStorage      []string       `json:"exposed_storage,omitempty"`
	UnencryptedStorage  []string       `json:"unencrypted_storage,omitempty"`
	WildcardPolicies    []string       `json:"wildcard_policies,omitempty"`
	InternetAdminPorts  []string       `json:"internet_admin_ports,omitempty"`
	PublicDatabases     []string       `json:"public_databases,omitempty"`
	PrivilegedManifests []string       `json:"privileged_manifests,omitempty"`
}

// Build computes the aggregate overview. Exposed information is derived only
// from snapshot data and never from live probing.
func Build(s *cloud.Snapshot) Overview {
	o := Overview{
		Provider: s.Provider,
		Region:   s.Region,
		ScopeID:  s.ScopeID,
	}
	for i := range s.Buckets {
		b := &s.Buckets[i]
		o.TotalAssets++
		if b.PublicRead || b.PublicWrite {
			o.ExposedStorage = append(o.ExposedStorage, b.Name)
		}
		if !b.Encrypted {
			o.UnencryptedStorage = append(o.UnencryptedStorage, b.Name)
		}
	}
	for i := range s.Policies {
		p := &s.Policies[i]
		o.TotalAssets++
		for _, st := range p.Statements {
			if isWildcard(st) {
				o.WildcardPolicies = append(o.WildcardPolicies, p.Name)
				break
			}
		}
	}
	o.TotalAssets += len(s.Groups) + len(s.Networks) + len(s.DBs) + len(s.Computes)
	for i := range s.Networks {
		o.TotalAssets++
		for _, r := range s.Networks[i].Rules {
			if adminToInternet(r.CIDRs, r.FromPort, r.ToPort) {
				o.InternetAdminPorts = append(o.InternetAdminPorts, s.Networks[i].Name)
				break
			}
		}
	}
	for i := range s.DBs {
		d := &s.DBs[i]
		o.TotalAssets++
		if d.PubliclyAccessible {
			o.PublicDatabases = append(o.PublicDatabases, d.Name)
		}
	}
	return o
}

func isWildcard(st cloud.Statement) bool {
	for _, a := range st.Actions {
		if a == "*" {
			for _, r := range st.Resources {
				if r == "*" {
					return true
				}
			}
		}
	}
	return false
}

func adminToInternet(cidrs []string, from, to int) bool {
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" || c == "any" {
			if from <= 0 || to <= 0 {
				return true
			}
			for p := from; p <= to && p-from <= 20; p++ {
				switch p {
				case 22, 23, 3389, 5900, 5432, 3306, 6379:
					return true
				}
			}
		}
	}
	return false
}
