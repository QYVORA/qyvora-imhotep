// Package cloud implements the provider-neutral cloud snapshot model. A
// snapshot is a JSON document describing an account/subscription/project's
// configuration surface offline; live provider collection is deliberately not
// implemented, so every assessment analyzes snapshots (or the built-in
// simulation) instead of contacting a control plane.
package cloud

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SchemaVersion is the snapshot document schema this build reads and writes.
const SchemaVersion = "qyvora.imhotep.snapshot.v1"

// Provider identifies a cloud provider scope.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
	ProviderNone  Provider = ""
)

// ParseProvider normalizes a provider name, returning None for unknown values.
func ParseProvider(s string) Provider {
	switch Provider(strings.ToLower(strings.TrimSpace(s))) {
	case ProviderAWS, ProviderAzure, ProviderGCP:
		return Provider(strings.ToLower(strings.TrimSpace(s)))
	default:
		return ProviderNone
	}
}

// Snapshot is the full offline configuration surface of one cloud scope.
type Snapshot struct {
	Schema    string      `json:"schema"`
	Provider  Provider    `json:"provider"`
	Region    string      `json:"region,omitempty"`
	ScopeID   string      `json:"scope_id,omitempty"`
	Label     string      `json:"label,omitempty"`
	Buckets   []Bucket    `json:"buckets,omitempty"`
	Policies  []Policy    `json:"policies,omitempty"`
	Groups    []Group     `json:"groups,omitempty"`
	Networks  []Network   `json:"networks,omitempty"`
	DBs       []Database  `json:"databases,omitempty"`
	Computes  []Compute   `json:"computes,omitempty"`
	Manifests []Manifest  `json:"manifests,omitempty"`
	Configs   []RawConfig `json:"configs,omitempty"`
}

// Bucket is an object store and its exposure posture.
type Bucket struct {
	Name        string            `json:"name"`
	Provider    Provider          `json:"provider"`
	Region      string            `json:"region,omitempty"`
	PublicRead  bool              `json:"public_read"`
	PublicWrite bool              `json:"public_write"`
	Encrypted   bool              `json:"encrypted"`
	Policy      json.RawMessage   `json:"policy,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Statement is one effect-bearing policy statement (provider-neutral).
type Statement struct {
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Principal string   `json:"principal,omitempty"` // "" = any
}

// Policy is an IAM policy attached to an identity or resource.
type Policy struct {
	ARN        string      `json:"arn,omitempty"`
	Name       string      `json:"name,omitempty"`
	Scope      string      `json:"scope,omitempty"` // user/role/group/service-account
	Identity   string      `json:"identity,omitempty"`
	Raw        string      `json:"raw"` // original policy JSON blob
	Version    string      `json:"version,omitempty"`
	Statements []Statement `json:"statements,omitempty"`
}

// Group models an identity group carrying policy memberships.
type Group struct {
	Name     string   `json:"name"`
	Members  []string `json:"members,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

// Rule is one firewall rule with a CIDR and port range.
type Rule struct {
	Direction string   `json:"direction"`
	Protocol  string   `json:"protocol"` // tcp/udp/icmp/any
	FromPort  int      `json:"from_port"`
	ToPort    int      `json:"to_port"`
	CIDRs     []string `json:"cidrs,omitempty"`
}

// Network is a security group / network security rule set.
type Network struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Database is a managed database and its exposure.
type Database struct {
	Name               string `json:"name"`
	Engine             string `json:"engine"`
	PubliclyAccessible bool   `json:"publicly_accessible"`
	Encrypted          bool   `json:"encrypted"`
	Port               int    `json:"port,omitempty"`
}

// Compute is a serverless/function/VM resource. Environment values are never
// emitted to output; they are only scanned in memory for secret detection.
type Compute struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"` // ec2/function/appservice...
	Runtime         string   `json:"runtime,omitempty"`
	PubliclyExposed bool     `json:"publicly_exposed,omitempty"`
	Environment     []string `json:"environment,omitempty"`
}

// Manifest is a raw container orchestration/build manifest.
type Manifest struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // docker/k8s/compose
	Content string `json:"content"`
}

// RawConfig is any other configuration blob scanned for secrets and
// interesting paths (terraform, .env, cloud-init, service configs).
type RawConfig struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

// Load parses a snapshot from r, rejecting documents that do not declare the
// snapshot schema.
func Load(r io.Reader) (*Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(r)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing snapshot: %w", err)
	}
	if s.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported snapshot schema %q (want %s)", s.Schema, SchemaVersion)
	}
	if s.Provider = ParseProvider(string(s.Provider)); s.Provider == ProviderNone {
		return nil, fmt.Errorf("snapshot declares no supported provider (aws|azure|gcp)")
	}
	normalize(&s)
	return &s, nil
}

// LoadFile loads a snapshot from a file path.
func LoadFile(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// normalize fills per-asset provider from the snapshot-level provider when a
// resource does not declare its own.
func normalize(s *Snapshot) {
	p := s.Provider
	for i := range s.Buckets {
		if ParseProvider(string(s.Buckets[i].Provider)) == ProviderNone {
			s.Buckets[i].Provider = p
		}
	}
	for i := range s.Networks {
		if s.Networks[i].Name == "" {
			s.Networks[i].Name = "unnamed"
		}
	}
}

// AssetCounts returns per-category inventory counts, used by reports.
type AssetCounts struct {
	Buckets   int `json:"buckets"`
	Policies  int `json:"policies"`
	Groups    int `json:"groups"`
	Networks  int `json:"networks"`
	DBs       int `json:"databases"`
	Computes  int `json:"computes"`
	Manifests int `json:"manifests"`
	Configs   int `json:"configs"`
}

// Counts computes the inventory counts of a snapshot.
func (s *Snapshot) Counts() AssetCounts {
	return AssetCounts{
		Buckets:   len(s.Buckets),
		Policies:  len(s.Policies),
		Groups:    len(s.Groups),
		Networks:  len(s.Networks),
		DBs:       len(s.DBs),
		Computes:  len(s.Computes),
		Manifests: len(s.Manifests),
		Configs:   len(s.Configs),
	}
}

// Validate runs structural sanity checks on a parsed snapshot.
func (s *Snapshot) Validate() []string {
	var problems []string
	if s.Schema != SchemaVersion {
		problems = append(problems, "missing snapshot schema version")
	}
	if ParseProvider(string(s.Provider)) == ProviderNone {
		problems = append(problems, "missing snapshot provider")
	}
	if s.ScopeID == "" {
		problems = append(problems, "missing scope_id (account/subscription/project identifier)")
	}
	return problems
}
