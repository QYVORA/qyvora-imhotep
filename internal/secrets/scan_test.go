package secrets_test

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/secrets"
)

func TestScanDetectsKinds(t *testing.T) {
	content := `DB_PASSWORD=supersecretvalue123
AKIAIOSFODNN7EXAMPLE
token: ghp_123456789012345678901234567890123456
-----BEGIN PRIVATE KEY-----
eyJhbGciOi.eyJzdWIiOi.eyJhdWQiOi
AIza01234567890123456789012345678901234567890
API_KEY=7F6RSgPxZ (short should not match: ok)
`
	matches := secrets.Scan("env", content)
	kinds := map[string]bool{}
	for _, m := range matches {
		kinds[m.Kind] = true
	}
	for _, want := range []string{"generic-secret", "aws-access-key-id", "github-token", "private-key", "jwt", "google-api-key"} {
		if !kinds[want] {
			t.Errorf("missing kind %s in %v", want, kinds)
		}
	}
	for _, m := range matches {
		if strings.Contains(m.Key, "supersecretvalue") {
			t.Errorf("secret value leaked into match: %+v", m)
		}
	}
}

func TestScanReportsLineNumbers(t *testing.T) {
	content := "safe line\npassword: hunter22longenough\n"
	matches := secrets.Scan("cfg", content)
	if len(matches) != 1 {
		t.Fatalf("matches = %d (%+v)", len(matches), matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("line = %d, want 2", matches[0].Line)
	}
}

func TestScanDoesNotMatchShortValues(t *testing.T) {
	matches := secrets.Scan("cfg", "password: abc\n")
	for _, m := range matches {
		if m.Kind == "generic-secret" {
			t.Errorf("short value matched as secret: %+v", m)
		}
	}
}

func TestScanDeduplicates(t *testing.T) {
	content := "secret: abcdefghijklmno\n"
	matches := secrets.Scan("cfg", content)
	if len(matches) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(matches))
	}
}
