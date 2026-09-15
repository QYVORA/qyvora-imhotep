// Package builtin registers the imhotep rule set. Every rule reads only the
// provided analysis Env — snapshot configuration, inventory overview and
// discovery list — and produces machine-readable findings with attached
// evidence. Nothing here performs live probing.
package builtin

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-imhotep/internal/analysis"
	"github.com/QYVORA/qyvora-imhotep/internal/containers"
	"github.com/QYVORA/qyvora-imhotep/internal/events"
	"github.com/QYVORA/qyvora-imhotep/internal/iam"
	"github.com/QYVORA/qyvora-imhotep/internal/network"
	"github.com/QYVORA/qyvora-imhotep/internal/rules"
	"github.com/QYVORA/qyvora-imhotep/internal/secrets"
	"github.com/QYVORA/qyvora-imhotep/internal/storage"
	"github.com/QYVORA/qyvora-imhotep/pkg/models"
)

// All returns the rules implicit in a stock assessment.
func All() []rules.Rule {
	return []rules.Rule{
		&wildcardAction{},
		&wildcardResource{},
		&publicReadBucket{},
		&publicWriteBucket{},
		&unencryptedStorage{},
		&internetAdminPort{},
		&publicDatabase{},
		&privilegedContainer{},
		&hostNetworkPod{},
		&latestImageTag{},
		&runsAsRoot{},
		&hardcodedSecret{},
	}
}

// metadata assembles a rule Meta with sane defaults for this rule set.
func metadata(id, name, category, description, recommendation string, sev models.Severity) rules.Meta {
	return rules.Meta{
		ID:                id,
		Name:              name,
		Category:          category,
		Description:       description,
		DefaultSeverity:   sev,
		DefaultConfidence: models.ConfidenceObserved,
		Recommendation:    recommendation,
	}
}

// newFinding fills the derived fields of a finding uniformly.
func newFinding(m rules.Meta, env *analysis.Env, objects []string, attrs map[string]string, ev ...models.Evidence) *models.Finding {
	return &models.Finding{
		RuleID:         m.ID,
		Title:          m.Name,
		Category:       m.Category,
		Description:    m.Description,
		Recommendation: m.Recommendation,
		Severity:       m.DefaultSeverity,
		Confidence:     m.DefaultConfidence,
		Status:         models.StatusDetected,
		State:          models.StateObserved,
		Objects:        objects,
		Attributes:     attrs,
		Evidence:       ev,
		Timestamp:      models.Now(),
	}
}

// ---------------------------------------------------------------------------
// IAM

type wildcardAction struct{}

func (r *wildcardAction) Meta() rules.Meta {
	return metadata("IAM-001", "Wildcard action granted", "iam",
		"An IAM policy grants '*' on at least one action, allowing any task.",
		"Replace '*' actions with the minimum set the identity actually performs.",
		models.SeverityHigh)
}

func (r *wildcardAction) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Policies {
		p := &env.Snapshot.Policies[i]
		for _, st := range p.Statements {
			if iam.IsWildcardAction(st) {
				ev := env.AddEvidence(models.EvidenceConfiguration, "snapshot:"+string(p.Scope), p.Name,
					targetName(env, p.Name), "policy grants wildcard action")
				if env.Events != nil {
					env.Events.Info(events.PolicyAnalyzed, map[string]any{
						"policy": p.Name, "identity": p.Identity, "wildcard_action": true,
					})
				}
				sink.Add(newFinding(r.Meta(), env, []string{p.Scope + ":" + p.Name},
					map[string]string{"identity": p.Identity, "action": "*"}, ev))
			}
		}
	}
	return nil
}

type wildcardResource struct{}

func (r *wildcardResource) Meta() rules.Meta {
	return metadata("IAM-002", "Wildcard resource scope", "iam",
		"An IAM policy applies to '*' resources, widening blast radius beyond the identity's needs.",
		"Scope resources to the specific ARNs the identity must reach.",
		models.SeverityHigh)
}

func (r *wildcardResource) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Policies {
		p := &env.Snapshot.Policies[i]
		for _, st := range p.Statements {
			if iam.IsWildcardResource(st) {
				ev := env.AddEvidence(models.EvidenceConfiguration, "snapshot:"+string(p.Scope), p.Name,
					targetName(env, p.Name), "policy scopes to wildcard resource")
				sink.Add(newFinding(r.Meta(), env, []string{p.Scope + ":" + p.Name},
					map[string]string{"identity": p.Identity, "resource": "*"}, ev))
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Storage

type publicReadBucket struct{}

func (r *publicReadBucket) Meta() rules.Meta {
	return metadata("STG-001", "Publicly readable storage", "storage",
		"An object store permits unauthenticated reads, exposing bucket contents to the internet.",
		"Remove public-read ACLs/policies and encrypt in transit; require identity-based access.",
		models.SeverityHigh)
}

func (r *publicReadBucket) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Buckets {
		b := &env.Snapshot.Buckets[i]
		ex := storage.AnalyzeBucket(b)
		if ex.PublicRead {
			ev := env.AddEvidence(models.EvidenceConfiguration, "snapshot:"+string(b.Provider), "bucket:"+b.Name,
				targetName(env, b.Name), strings.Join(ex.Reasons, "; "))
			attrs := map[string]string{"reason": strings.Join(ex.Reasons, "; ")}
			sink.Add(newFinding(r.Meta(), env, []string{b.Name}, attrs, ev))
		}
	}
	return nil
}

type publicWriteBucket struct{}

func (r *publicWriteBucket) Meta() rules.Meta {
	return metadata("STG-002", "Publicly writable storage", "storage",
		"An object store permits unauthenticated writes, allowing anyone to plant or tamper with objects.",
		"Revoke public-write and rely on authenticated principals for all writes.",
		models.SeverityCritical)
}

func (r *publicWriteBucket) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Buckets {
		b := &env.Snapshot.Buckets[i]
		ex := storage.AnalyzeBucket(b)
		if ex.PublicWrite {
			ev := env.AddEvidence(models.EvidenceConfiguration, "snapshot:"+string(b.Provider), "bucket:"+b.Name,
				targetName(env, b.Name), "public-write enabled")
			sink.Add(newFinding(r.Meta(), env, []string{b.Name},
				map[string]string{"reason": strings.Join(ex.Reasons, "; ")}, ev))
		}
	}
	return nil
}

type unencryptedStorage struct{}

func (r *unencryptedStorage) Meta() rules.Meta {
	return metadata("STG-003", "Unencrypted storage at rest", "storage",
		"An object store does not report server-side encryption at rest.",
		"Enable default encryption on every object store.",
		models.SeverityMedium)
}

func (r *unencryptedStorage) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Buckets {
		b := &env.Snapshot.Buckets[i]
		if b.Encrypted {
			continue
		}
		ev := env.AddEvidence(models.EvidenceAttribute, "snapshot:"+string(b.Provider), "bucket:"+b.Name,
			targetName(env, b.Name), "encrypted=false")
		sink.Add(newFinding(r.Meta(), env, []string{b.Name}, nil, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Network

type internetAdminPort struct{}

func (r *internetAdminPort) Meta() rules.Meta {
	return metadata("NET-001", "Administrative port exposed to the internet", "network",
		"A security group exposes an administrative/database port to 0.0.0.0/0 or any.",
		"Restrict administrative ports to trusted troup CIDRs or a bastion.",
		models.SeverityHigh)
}

func (r *internetAdminPort) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Networks {
		ng := &env.Snapshot.Networks[i]
		for _, rl := range ng.Rules {
			if rl.Direction != "" && !strings.EqualFold(rl.Direction, "ingress") {
				continue
			}
			if rl.FromPort == rl.ToPort && network.IsAdminPort(rl.ToPort) {
				if exposed, _ := network.ExposedToInternet(rl.CIDRs, rl.FromPort, rl.ToPort, rl.ToPort); exposed {
					ev := env.AddEvidence(models.EvidenceConfiguration, "snapshot:aws", "network:"+ng.Name,
						targetName(env, ng.Name), "port "+itoa(rl.ToPort)+" reachable from "+strings.Join(rl.CIDRs, ","))
					sink.Add(newFinding(r.Meta(), env, []string{ng.Name},
						map[string]string{"port": itoa(rl.ToPort), "protocol": rl.Protocol, "cidr": strings.Join(rl.CIDRs, ",")}, ev))
				}
			}
		}
	}
	return nil
}

type publicDatabase struct{}

func (r *publicDatabase) Meta() rules.Meta {
	return metadata("NET-002", "Publicly accessible database", "network",
		"A managed database is marked publicly accessible.",
		"Move databases to private endpoints with identity-based access.",
		models.SeverityCritical)
}

func (r *publicDatabase) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.DBs {
		d := &env.Snapshot.DBs[i]
		if !d.PubliclyAccessible {
			continue
		}
		ev := env.AddEvidence(models.EvidenceAttribute, "snapshot:"+string(env.Snapshot.Provider), "database:"+d.Name,
			targetName(env, d.Name), "publicly_accessible=true")
		sink.Add(newFinding(r.Meta(), env, []string{d.Name}, map[string]string{"engine": d.Engine, "port": itoa(d.Port)}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Containers

type privilegedContainer struct{}

func (r *privilegedContainer) Meta() rules.Meta {
	return metadata("CNT-001", "Privileged container capability", "containers",
		"A container manifest runs with privileged capability or host userns.",
		"Remove privileged flags and grant only the capabilities the workload needs.",
		models.SeverityHigh)
}

func (r *privilegedContainer) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	return scanManifests(envAny.(*analysis.Env), sink, "privileged", r.Meta(),
		"manifest requests privileged capability")
}

type hostNetworkPod struct{}

func (r *hostNetworkPod) Meta() rules.Meta {
	return metadata("CNT-002", "Host network namespace", "containers",
		"A pod joins the host network namespace, exposing host services to the pod.",
		"Remove hostNetwork and expose services via dedicated ingress.",
		models.SeverityMedium)
}

func (r *hostNetworkPod) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	return scanManifests(envAny.(*analysis.Env), sink, "host_network", r.Meta(),
		"manifest joins host network")
}

type latestImageTag struct{}

func (r *latestImageTag) Meta() rules.Meta {
	return metadata("CNT-003", "Immutability-breaking image tag", "containers",
		"An image reference uses ':latest' or no tag/digest, defeating supply-chain pinning.",
		"Pin images to digests or strict version tags.",
		models.SeverityLow)
}

func (r *latestImageTag) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	return scanManifests(envAny.(*analysis.Env), sink, "latest_tag", r.Meta(),
		"image reference lacks a pinned digest")
}

type runsAsRoot struct{}

func (r *runsAsRoot) Meta() rules.Meta {
	return metadata("CNT-004", "Container runs as root", "containers",
		"A container manifest runs with root privileges (USER root / runAsUser 0).",
		"Run with least-privilege UID and read-only filesystems; drop capabilities.",
		models.SeverityMedium)
}

func (r *runsAsRoot) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	return scanManifests(envAny.(*analysis.Env), sink, "runs_as_root", r.Meta(),
		"manifest runs as root")
}

func scanManifests(env *analysis.Env, sink *rules.Sink, kind string, m rules.Meta, reason string) error {
	for i := range env.Snapshot.Manifests {
		mf := &env.Snapshot.Manifests[i]
		for _, flag := range containers.Inspect(mf.Kind, mf.Content) {
			if flag.Kind != kind {
				continue
			}
			ev := env.AddEvidence(models.EvidenceArtifact, "manifest:"+mf.Kind, mf.Name,
				targetName(env, mf.Name), reason+" (line "+itoa(flag.Line)+")")
			sink.Add(newFinding(m, env, []string{mf.Name},
				map[string]string{"line": itoa(flag.Line), "kind": mf.Kind}, ev))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Secrets

type hardcodedSecret struct{}

func (r *hardcodedSecret) Meta() rules.Meta {
	return metadata("SEC-001", "Hardcoded secret material", "secrets",
		"Configuration surfaces contain secret-shaped values (API keys, tokens, passwords, private keys).",
		"Move secrets to a managed vault and rotate anything exposed; remove from manifests/configs.",
		models.SeverityCritical)
}

func (r *hardcodedSecret) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for i := range env.Snapshot.Configs {
		c := &env.Snapshot.Configs[i]
		for _, m := range secrets.Scan(c.Name, c.Content) {
			ev := env.AddEvidence(models.EvidenceFile, "config:"+c.Kind, c.Name,
				targetName(env, c.Name), "secret candidate "+m.Kind+" line "+itoa(m.Line))
			if env.Events != nil {
				env.Events.Info(events.SecretDetected, map[string]any{
					"kind": m.Kind, "source": c.Name, "line": m.Line,
				})
			}
			sink.Add(newFinding(r.Meta(), env, []string{c.Name},
				map[string]string{"kind": m.Kind, "line": itoa(m.Line)}, ev))
		}
	}
	for i := range env.Snapshot.Computes {
		c := &env.Snapshot.Computes[i]
		for _, entry := range c.Environment {
			for _, m := range secrets.Scan(c.Name, entry+"\n") {
				ev := env.AddEvidence(models.EvidenceAttribute, "compute:"+c.Kind, "env:"+c.Name,
					targetName(env, c.Name), "secret candidate "+m.Kind+" in environment")
				if env.Events != nil {
					env.Events.Info(events.SecretDetected, map[string]any{
						"kind": m.Kind, "source": "compute:" + c.Name,
					})
				}
				sink.Add(newFinding(r.Meta(), env, []string{c.Name},
					map[string]string{"kind": m.Kind, "location": "environment"}, ev))
			}
		}
	}
	return nil
}

func targetName(env *analysis.Env, name string) string {
	if env == nil || env.Snapshot == nil {
		return name
	}
	return name + "@" + string(env.Snapshot.Provider)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
