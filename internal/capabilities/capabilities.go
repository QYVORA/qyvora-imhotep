// Package capabilities exposes the machine-readable tool contract so
// automation and humans can read what this framework actually implements,
// without trusting prose.
package capabilities

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-imhotep/internal/events"
	"github.com/QYVORA/qyvora-imhotep/internal/output"
	"github.com/QYVORA/qyvora-imhotep/internal/version"
	"github.com/QYVORA/qyvora-imhotep/pkg/models"
)

// Command describes one CLI command surface.
type Command struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	OutputModes []string `json:"output_modes"`
	Sim         bool     `json:"sim_support"`
}

// Capability lists one implemented capability area.
type Capability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Implemented bool   `json:"implemented"`
	Live        bool   `json:"live"` // requires a live cloud provider
	Note        string `json:"note,omitempty"`
}

// Document is the full machine-readable contract of this framework build.
type Document struct {
	Framework      string         `json:"framework"`
	Version        string         `json:"version"`
	ExitCodes      map[string]int `json:"exit_codes"`
	OutputFormats  []string       `json:"output_formats"`
	EventVerbs     []string       `json:"event_verbs"`
	SeverityLevels []string       `json:"severity_levels"`
	Confidence     []string       `json:"confidence_levels"`
	Authorized     string         `json:"authorization_model"`
	Capabilities   []Capability   `json:"capabilities"`
	Commands       []Command      `json:"commands"`
}

// Report is the summary returned to the CLI.
type Report struct {
	Doc     Document
	Printer *output.Printer
}

// Build assembles the capability document for this build.
func Build() Document {
	return Document{
		Framework: version.Framework,
		Version:   version.Version,
		ExitCodes: map[string]int{
			"success": 0, "runtime": 1, "usage": 2, "interrupted": 130,
		},
		OutputFormats: []string{"terminal", "json", "yaml", "markdown", "html"},
		EventVerbs: []string{
			events.ScanStarted, events.ScanCompleted, events.StageStarted,
			events.StageCompleted, events.FindingDiscovered,
			events.EvidenceCollected, events.ProviderDetected,
			events.PolicyAnalyzed, events.StorageAnalyzed,
			events.NetworkAnalyzed, events.ContainerAnalyzed,
			events.SecretDetected, events.MisconfigDetected,
			events.RiskCalculated, events.ReportGenerated,
		},
		SeverityLevels: []string{
			"critical", "high", "medium", "low", "informational",
		},
		Confidence: []string{
			"confirmed", "observed", "probable", "possible", "unknown", "not_observed",
		},
		Authorized: "offline snapshot/simulation analysis requires no authorization; " +
			"live provider collection is not implemented and is refused",
		Capabilities: []Capability{
			{ID: "cloud.snapshot", Name: "offline cloud snapshot analysis", Implemented: true, Live: false},
			{ID: "cloud.iam", Name: "identity and access policy analysis", Implemented: true, Live: false},
			{ID: "cloud.storage", Name: "storage exposure analysis", Implemented: true, Live: false},
			{ID: "cloud.network", Name: "network configuration analysis", Implemented: true, Live: false},
			{ID: "cloud.containers", Name: "container and kubernetes analysis", Implemented: true, Live: false},
			{ID: "cloud.secrets", Name: "secret exposure detection", Implemented: true, Live: false},
			{ID: "cloud.misconfig", Name: "misconfiguration detection", Implemented: true, Live: false},
			{ID: "cloud.live", Name: "live provider API collection", Implemented: false, Live: true,
				Note: "snapshot-driven analysis only; provider SDKs are not wired up"},
		},
		Commands: []Command{
			{Name: "assess", Summary: "run the full analysis pipeline", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "snapshot", Summary: "generate a deterministic sample cloud snapshot", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "report", Summary: "render the latest assessment report", OutputModes: []string{"terminal", "markdown", "json", "yaml", "html"}, Sim: true},
			{Name: "findings", Summary: "inspect the latest assessment findings", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "evidence", Summary: "inspect the latest assessment evidence", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "providers", Summary: "list supported cloud providers and their status", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "target", Summary: "manage assessment targets", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "capabilities", Summary: "print this machine-readable contract", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: false},
		},
	}
}

// Render prints the document in the active format.
func Render(p *output.Printer) {
	p.Print(Build())
}

// RenderCapabilities prints capability rows.
func RenderCapabilities(p *output.Printer) {
	doc := Build()
	rows := make([][]string, 0, len(doc.Capabilities))
	for _, c := range doc.Capabilities {
		rows = append(rows, []string{c.ID, boolStr(c.Implemented), boolStr(c.Live)})
	}
	p.PrintTable([]string{"capability", "implemented", "live"}, rows)
}

// RenderProviders prints the supported cloud providers and their status.
func RenderProviders(p *output.Printer) {
	type provider struct {
		Provider    string `json:"provider"`
		Live        bool   `json:"live"`
		Implemented bool   `json:"implemented"`
		Note        string `json:"note,omitempty"`
	}
	providers := []provider{
		{Provider: "aws", Live: true, Implemented: false, Note: "snapshot only"},
		{Provider: "azure", Live: true, Implemented: false, Note: "snapshot only"},
		{Provider: "gcp", Live: true, Implemented: false, Note: "snapshot only"},
	}
	p.Print(providers)
}

// RenderCommands prints the command table.
func RenderCommands(p *output.Printer) {
	doc := Build()
	rows := make([][]string, 0, len(doc.Commands))
	for _, c := range doc.Commands {
		rows = append(rows, []string{c.Name, c.Summary, strings.Join(c.OutputModes, ","), boolStr(c.Sim)})
	}
	p.PrintTable([]string{"command", "summary", "formats", "sim"}, rows)
}

// RenderJSON is a convenience for tests: it JSON-encodes the document.
func RenderJSON(doc Document) ([]byte, error) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding capabilities: %w", err)
	}
	return data, nil
}

// SortCapabilities orders capabilities by ID for deterministic output.
func SortCapabilities(doc Document) {
	sort.Slice(doc.Capabilities, func(i, j int) bool { return doc.Capabilities[i].ID < doc.Capabilities[j].ID })
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var _ = models.StateObserved // keep models import meaningful for future use
