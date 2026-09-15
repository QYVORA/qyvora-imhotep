package cloud

import (
	"encoding/json"
	"time"
)

// SimulationOptions tunes the deterministic demo dataset.
type SimulationOptions struct {
	// SeedPolicies controls how many IAM policies are generated.
	SeedPolicies int
}

// Simulate returns a deterministic sample snapshot exercising every analysis
// path: safe and exposed storage, wildcard IAM, open security groups, a
// publicly accessible database, privileged containers, and one redacted
// hardcoded secret. Secrets shown here are clearly fake and never real.
func Simulate(opts SimulationOptions) *Snapshot {
	if opts.SeedPolicies <= 0 {
		opts.SeedPolicies = 3
	}
	s := &Snapshot{
		Schema:   SchemaVersion,
		Provider: ProviderAWS,
		Region:   "us-east-1",
		ScopeID:  "acme-000000000000",
		Label:    "acme-demo (deterministic simulation data)",

		Buckets: []Bucket{
			{
				Name: "acme-public-assets", Provider: ProviderAWS, Region: "us-east-1",
				PublicRead: true, PublicWrite: false, Encrypted: true,
			},
			{
				Name: "acme-backups", Provider: ProviderAWS, Region: "us-east-1",
				PublicRead: false, PublicWrite: false, Encrypted: false,
			},
		},
		Policies: []Policy{
			{
				Name: "wildcard-admin", Scope: "role", Identity: "deploy-bot",
				Raw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*"}]}`,
				Statements: []Statement{
					{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}},
				},
			},
			{
				Name: "readonly-s3", Scope: "user", Identity: "billing-svc",
				Raw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::acme-billing/*"]}]}`,
				Statements: []Statement{
					{Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::acme-billing/*"}},
				},
			},
			{
				Name: "AdministratorAccess", Scope: "user", Identity: "legacy-root",
				Raw: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*"}]}`,
				Statements: []Statement{
					{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}},
				},
			},
		},
		Groups: []Group{
			{Name: "engineers", Members: []string{"alice", "bob"}, Policies: []string{"wildcard-admin"}},
		},
		Networks: []Network{
			{
				Name: "web-sg",
				Rules: []Rule{
					{Direction: "ingress", Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"0.0.0.0/0"}},
					{Direction: "ingress", Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}},
				},
			},
		},
		DBs: []Database{
			{Name: "orders-prod", Engine: "postgres", PubliclyAccessible: true, Encrypted: true, Port: 5432},
		},
		Computes: []Compute{
			{Name: "order-api", Kind: "function", Runtime: "nodejs18.x",
				PubliclyExposed: true,
				Environment:     []string{"DB_PASSWORD=supersecretfakepass123", "NODE_ENV=production"}},
		},
		Manifests: []Manifest{
			{
				Name: "web-deploy", Kind: "k8s",
				Content: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: nginx:latest\n        securityContext:\n          privileged: true\n      hostNetwork: true\n",
			},
			{
				Name: "api-image", Kind: "docker",
				Content: "FROM node:18\nUSER root\nWORKDIR /app\nCOPY . .\nCMD [\"npm\",\"start\"]\n",
			},
		},
		Configs: []RawConfig{
			{Name: "api-env", Kind: "env", Content: "DB_PASSWORD=supersecretfakepass123\nAPI_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAfake\n"},
		},
	}
	return s
}

// Marshal renders a snapshot as indented JSON.
func Marshal(s *Snapshot) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// TimestampedLabel appends a timestamp so generated example files are
// distinguishable; the dataset itself stays deterministic.
func TimestampedLabel(s *Snapshot, now time.Time) {
	if s.Label != "" && now.IsZero() {
		return
	}
	if now.IsZero() {
		_ = now
		return
	}
	s.Label = s.Label + " @" + now.UTC().Format("2006-01-02T15:04:05Z")
}
