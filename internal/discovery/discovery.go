// Package discovery enumerates the assets in a cloud snapshot into a flat,
// provider-neutral list used for events, counts and reporting. It is the
// "Asset Discovery" stage of the assessment pipeline.
package discovery

import (
	"fmt"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
)

// Asset is one discovered resource in provider-neutral form.
type Asset struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"` // bucket|policy|group|network|database|compute|manifest|config
	Provider cloud.Provider `json:"provider"`
	Name     string         `json:"name"`
	Region   string         `json:"region,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// Discovery walks a snapshot and yields its assets.
type Discovery struct {
	assets []Asset
}

// Run enumerates every asset in s.
func (d *Discovery) Run(s *cloud.Snapshot) []Asset {
	d.assets = d.assets[:0]
	if s == nil {
		return nil
	}
	for i := range s.Buckets {
		b := &s.Buckets[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("bucket:%s", b.Name), Type: "bucket",
			Provider: b.Provider, Name: b.Name, Region: b.Region,
			Extra: map[string]any{"public_read": b.PublicRead, "public_write": b.PublicWrite, "encrypted": b.Encrypted},
		})
	}
	for i := range s.Policies {
		p := &s.Policies[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("policy:%s:%s", p.Scope, p.Name), Type: "policy",
			Provider: s.Provider, Name: p.Name,
			Extra: map[string]any{"identity": p.Identity, "scope": p.Scope},
		})
	}
	for i := range s.Groups {
		g := &s.Groups[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("group:%s", g.Name), Type: "group",
			Provider: s.Provider, Name: g.Name,
			Extra: map[string]any{"members": len(g.Members), "policies": len(g.Policies)},
		})
	}
	for i := range s.Networks {
		n := &s.Networks[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("network:%s", n.Name), Type: "network",
			Provider: s.Provider, Name: n.Name, Extra: map[string]any{"rules": len(n.Rules)},
		})
	}
	for i := range s.DBs {
		db := &s.DBs[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("database:%s", db.Name), Type: "database",
			Provider: s.Provider, Name: db.Name,
			Extra: map[string]any{"publicly_accessible": db.PubliclyAccessible},
		})
	}
	for i := range s.Computes {
		c := &s.Computes[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("compute:%s", c.Name), Type: "compute",
			Provider: s.Provider, Name: c.Name,
			Extra: map[string]any{"runtime": c.Runtime, "publicly_exposed": c.PubliclyExposed},
		})
	}
	for i := range s.Manifests {
		m := &s.Manifests[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("manifest:%s", m.Name), Type: "manifest",
			Provider: s.Provider, Name: m.Name, Extra: map[string]any{"kind": m.Kind},
		})
	}
	for i := range s.Configs {
		c := &s.Configs[i]
		d.assets = append(d.assets, Asset{
			ID: fmt.Sprintf("config:%s", c.Name), Type: "config",
			Provider: s.Provider, Name: c.Name, Extra: map[string]any{"kind": c.Kind},
		})
	}
	return d.assets
}
