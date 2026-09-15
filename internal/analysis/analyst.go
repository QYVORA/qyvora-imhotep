// Package analysis wires the assessment into pipeline stages: provider
// detection, asset discovery, configuration inventory, rule analysis and risk
// calculation. Env is the shared state handed to every rule.
package analysis

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
	"github.com/QYVORA/qyvora-imhotep/internal/discovery"
	"github.com/QYVORA/qyvora-imhotep/internal/errors"
	"github.com/QYVORA/qyvora-imhotep/internal/events"
	"github.com/QYVORA/qyvora-imhotep/internal/evidence"
	"github.com/QYVORA/qyvora-imhotep/internal/misconfig"
	"github.com/QYVORA/qyvora-imhotep/internal/pipeline"
	"github.com/QYVORA/qyvora-imhotep/internal/risk"
	"github.com/QYVORA/qyvora-imhotep/internal/rules"
	"github.com/QYVORA/qyvora-imhotep/pkg/models"
)

// Env is the environment passed to every rule during one assessment.
type Env struct {
	Snapshot *cloud.Snapshot
	Overview misconfig.Overview
	Assets   []discovery.Asset
	Events   *events.Stream
	Store    *evidence.Store
	Config   map[string]any
}

// AddEvidence records an observation backing a finding, hashed and stored.
func (e *Env) AddEvidence(kind models.EvidenceKind, source, sourceID, target, data string) models.Evidence {
	ev := models.Evidence{
		Kind:     kind,
		Source:   source,
		SourceID: sourceID,
		Target:   target,
		Data:     data,
		State:    models.StateObserved,
	}
	if e.Store != nil {
		e.Store.Add(ev)
	}
	ev.Hash = models.HashContent(ev.Data)
	return ev
}

// Stages returns the full offline/simulation assessment pipeline.
func Stages(reg *rules.Registry, cfg map[string]any, maxAssets int) []pipeline.Stage {
	return []pipeline.Stage{
		{
			ID: "provider", Name: "Provider detection",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				snap, err := currentSnapshot(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.ProviderDetected, map[string]any{
						"provider": string(snap.Provider),
						"scope_id": snap.ScopeID,
						"region":   snap.Region,
					})
				}
				return nil
			},
		},
		{
			ID: "discovery", Name: "Asset discovery",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				snap, err := currentSnapshot(step)
				if err != nil {
					return err
				}
				var disc discovery.Discovery
				assets := disc.Run(snap)
				emitted := 0
				for _, a := range assets {
					if emitted >= maxAssets {
						break
					}
					if step.Events != nil {
						step.Events.Info(events.AssetDiscovered, map[string]any{
							"type": a.Type, "id": a.ID, "provider": string(a.Provider),
						})
					}
					emitted++
				}
				step.Result.Assets = len(assets)
				if step.Events != nil {
					step.Events.Info(events.AssetDiscovered, map[string]any{"total": len(assets), "reported": emitted})
				}
				return nil
			},
		},
		{
			ID: "inventory", Name: "Configuration inventory",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				snap, err := currentSnapshot(step)
				if err != nil {
					return err
				}
				ov := misconfig.Build(snap)
				if step.Events != nil {
					step.Events.Info(events.StorageAnalyzed, map[string]any{
						"exposed": ov.ExposedStorage, "unencrypted": ov.UnencryptedStorage,
					})
					step.Events.Info(events.PolicyAnalyzed, map[string]any{
						"wildcard": ov.WildcardPolicies,
					})
					step.Events.Info(events.NetworkAnalyzed, map[string]any{
						"internet_admin_ports": ov.InternetAdminPorts,
					})
				}
				step.Result.Summary = ovSummary(ov)
				return nil
			},
		},
		{
			ID: "analysis", Name: "Rule analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				if reg == nil {
					return nil
				}
				snap, err := currentSnapshot(step)
				if err != nil {
					return err
				}
				var disc discovery.Discovery
				env := &Env{
					Snapshot: snap,
					Overview: misconfig.Build(snap),
					Assets:   disc.Run(snap),
					Events:   step.Events,
					Store:    step.Evidence,
					Config:   cfg,
				}
				sink := rules.NewSink()
				if err := reg.Run(ctx, env, sink); err != nil {
					return err
				}
				for _, f := range sink.List() {
					if step.Target != nil {
						f.TargetID = step.Target.ID
					}
					step.Result.Findings = append(step.Result.Findings, *f)
					if step.Events != nil {
						step.Events.Info(events.FindingDiscovered, map[string]any{
							"rule_id": f.RuleID, "title": f.Title, "severity": string(f.Severity),
							"objects": f.Objects,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "risk", Name: "Risk calculation",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				var assessor risk.Assessor
				score, level := assessor.Assess(ctx, headings(step.Result.Findings))
				step.Result.Score = score
				step.Result.Level = level
				step.Result.Evidence = step.Evidence.List()
				if step.Events != nil {
					step.Events.Info(events.RiskCalculated, map[string]any{
						"score": score, "level": level, "findings": len(step.Result.Findings),
					})
				}
				return nil
			},
		},
	}
}

// Execute stages builds a Result shell ready for a pipeline run.
func Execute(stages func() []pipeline.Stage, step *pipeline.Step) error {
	if step == nil || step.Events == nil {
		return errors.NewExitError(1, "pipeline execution requires an event stream")
	}
	eng := pipeline.New(stages()...)
	if err := eng.Run(context.Background(), step); err != nil {
		return err
	}
	return nil
}

func headings(fs []models.Finding) []*models.Finding {
	out := make([]*models.Finding, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

func ovSummary(ov misconfig.Overview) string {
	n := ov.TotalAssets
	s := "scope=" + redactScope(ov.ScopeID)
	if n == 0 {
		return s + " no assets inventoried"
	}
	return s + " assets=" + itoa(n) +
		" wildcard_policies=" + itoa(len(ov.WildcardPolicies)) +
		" exposed_storage=" + itoa(len(ov.ExposedStorage)) +
		" unencrypted_storage=" + itoa(len(ov.UnencryptedStorage)) +
		" internet_admin_ports=" + itoa(len(ov.InternetAdminPorts)) +
		" public_databases=" + itoa(len(ov.PublicDatabases))
}

// redactScope hides everything after the third segment of a scope id so
// account identifiers never leak into reports accidentally.
func redactScope(scope string) string {
	if scope == "" {
		return "unknown"
	}
	const visible = 3
	segs := 0
	last := 0
	for i := 0; i < len(scope); i++ {
		if scope[i] == '-' {
			segs++
			if segs == visible {
				last = i + 1
			}
		}
	}
	if segs < visible || last == 0 {
		return scope
	}
	return scope[:last] + strings.Repeat("X", len(scope)-last)
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

func currentSnapshot(step *pipeline.Step) (*cloud.Snapshot, error) {
	if step == nil || step.Target == nil {
		return nil, errors.NewExitError(1, "assessment requires a snapshot or simulation target")
	}
	if step.Sim {
		return cloud.Simulate(cloud.SimulationOptions{}), nil
	}
	if step.Target.Type != models.TargetSnapshot {
		return nil, errors.NewExitError(1, "unsupported target: live provider collection is not implemented; provide a snapshot file")
	}
	snap, err := cloud.LoadFile(step.Target.Value)
	if err != nil {
		return nil, errors.WrapExitError(1, "loading snapshot", err)
	}
	return snap, nil
}
