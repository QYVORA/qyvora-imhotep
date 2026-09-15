package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/analysis"
	"github.com/QYVORA/qyvora-imhotep/internal/events"
	"github.com/QYVORA/qyvora-imhotep/internal/evidence"
	"github.com/QYVORA/qyvora-imhotep/internal/pipeline"
	"github.com/QYVORA/qyvora-imhotep/internal/rules"
	"github.com/QYVORA/qyvora-imhotep/internal/rules/builtin"
	"github.com/QYVORA/qyvora-imhotep/pkg/models"
)

// TestSimulationPipelineProducesFindings runs the full analysis pipeline over
// the deterministic simulation and verifies that every known hazard ships a
// finding.
func TestSimulationPipelineProducesFindings(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	var evBuf bytes.Buffer
	stream := events.NewStream(&evBuf)
	mgr := evidence.New("")
	step := &pipeline.Step{
		Target:   &models.Target{ID: "sim", Type: models.TargetSimulation},
		Sim:      true,
		Events:   stream,
		Evidence: mgr,
		Result: &models.Result{
			ID: "run", Framework: "imhotep", Target: &models.Target{ID: "sim"}, Sim: true,
		},
	}

	stages := analysis.Stages(reg, map[string]any{}, 1000)
	eng := pipeline.New(stages...)
	if err := eng.Run(context.Background(), step); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	found := map[string]bool{}
	for _, f := range step.Result.Findings {
		found[f.RuleID] = true
	}
	expected := []string{"IAM-001", "IAM-002", "STG-001", "STG-003",
		"NET-001", "NET-002", "CNT-001", "CNT-002", "CNT-003", "CNT-004", "SEC-001"}
	for _, id := range expected {
		if !found[id] {
			t.Errorf("expected finding %s in simulation", id)
		}
	}
	if mgr.Len() == 0 {
		t.Error("simulation produced no evidence")
	}
	if step.Result.Score <= 0 {
		t.Errorf("expected positive risk score, got %d", step.Result.Score)
	}
	if step.Result.Assets == 0 {
		t.Error("discovery found no assets")
	}

	// Event stream must be valid JSONL with the shared envelope.
	for _, line := range bytes.Split(bytes.TrimSpace(evBuf.Bytes()), []byte("\n")) {
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid event line %q: %v", line, err)
		}
		if ev["framework"] != "imhotep" {
			t.Errorf("event framework = %v", ev["framework"])
		}
	}
}

// TestSnapshotPipelineAcceptsFileTarget exercises the file-path path with a
// raw snapshot document.
func TestSnapshotPipelineAcceptsFileTarget(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	doc := `{"schema":"qyvora.imhotep.snapshot.v1","provider":"azure","scope_id":"acme-sub-1",
	  "buckets":[{"name":"blob-logs","public_read":false,"public_write":true,"encrypted":true}]}`
	path := writeTemp(t, doc)

	step := &pipeline.Step{
		Target:   &models.Target{ID: "snap", Type: models.TargetSnapshot, Value: path},
		Events:   events.NewStream(&bytes.Buffer{}),
		Evidence: evidence.New(""),
		Result:   &models.Result{ID: "run", Framework: "imhotep", Target: &models.Target{ID: "snap"}},
	}
	stages := analysis.Stages(reg, map[string]any{}, 1000)
	if err := pipeline.New(stages...).Run(context.Background(), step); err != nil {
		t.Fatalf("snapshot run: %v", err)
	}
	var got bool
	for _, f := range step.Result.Findings {
		if f.RuleID == "STG-002" {
			got = true
		}
	}
	if !got {
		t.Error("expected STG-002 for public-write bucket in snapshot")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/snapshot.json"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
