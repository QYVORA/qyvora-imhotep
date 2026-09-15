package cloud_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
)

func TestLoadValidSnapshot(t *testing.T) {
	doc := `{"schema":"qyvora.imhotep.snapshot.v1","provider":"aws","scope_id":"acme-1",
	  "buckets":[{"name":"b","public_read":true}]}`
	s, err := cloud.Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if s.Provider != cloud.ProviderAWS {
		t.Errorf("provider = %s", s.Provider)
	}
	if len(s.Buckets) != 1 || s.Buckets[0].Provider != cloud.ProviderAWS {
		t.Errorf("bucket not normalized to provider: %+v", s.Buckets)
	}
	if c := s.Counts().Buckets; c != 1 {
		t.Errorf("bucket count = %d", c)
	}
}

func TestLoadRejectsUnknownSchema(t *testing.T) {
	doc := `{"schema":"other","provider":"aws"}`
	if _, err := cloud.Load(strings.NewReader(doc)); err == nil {
		t.Error("expected error for unsupported schema")
	}
}

func TestLoadRejectsUnknownProvider(t *testing.T) {
	doc := `{"schema":"qyvora.imhotep.snapshot.v1","provider":"oracle"}`
	if _, err := cloud.Load(strings.NewReader(doc)); err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, []byte(`{"schema":"qyvora.imhotep.snapshot.v1","provider":"gcp","scope_id":"p1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := cloud.LoadFile(path)
	if err != nil {
		t.Fatalf("load file: %v", err)
	}
	if s.Provider != cloud.ProviderGCP {
		t.Errorf("provider = %s", s.Provider)
	}
}

func TestSimulateIsDeterministicAndComplete(t *testing.T) {
	a := cloud.Simulate(cloud.SimulationOptions{})
	b := cloud.Simulate(cloud.SimulationOptions{})
	if len(a.Buckets) != len(b.Buckets) || a.ScopeID != b.ScopeID {
		t.Error("simulation is not deterministic")
	}
	if len(a.Policies) != 3 {
		t.Errorf("policies = %d", len(a.Policies))
	}
	if c := a.Counts(); c.Manifests != 2 || c.Configs != 1 || c.Networks != 1 {
		t.Errorf("unexpected counts: %+v", c)
	}
	if m := a.Provider; m != cloud.ProviderAWS {
		t.Errorf("provider = %s", m)
	}
	ra, _ := cloud.Marshal(a)
	rb, _ := cloud.Marshal(b)
	if string(ra) != string(rb) {
		t.Error("simulation JSON not byte-identical")
	}
}
