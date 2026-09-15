// Package secrets performs deterministic secret scanning over configuration
// content. It reports only the kind, key name and line number — never the
// secret material itself — so downstream findings and evidence are always safe
// to emit. Live secret exfiltration is out of scope; this package only
// inspects text buffers handed to it.
package secrets

import (
	"bufio"
	"regexp"
	"sort"
	"strings"
)

// Match is one detected secret candidate. Value is intentionally absent.
type Match struct {
	Kind string `json:"kind"`
	Key  string `json:"key,omitempty"`
	Line int    `json:"line"`
	File string `json:"file"`
}

type rule struct {
	kind   string
	regex  *regexp.Regexp
	hasKey bool // regex exposes the key name in capture group 1
}

var rules = []rule{
	{
		kind:   "aws-access-key-id",
		regex:  regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
		hasKey: false,
	},
	{
		kind:   "aws-secret-access-key",
		regex:  regexp.MustCompile(`(?i)\baws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[a-z0-9/+=]{20,}`),
		hasKey: false,
	},
	{
		kind:   "github-token",
		regex:  regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`),
		hasKey: false,
	},
	{
		kind: "generic-secret",
		// Key separated from a long value by '=' or ':', with an optional
		// connector before the key (api_key, DB_PASSWORD). Values shorter than
		// 12 characters are ignored to keep false positives low.
		regex:  regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(api[_-]?key|secret|password|passwd|client[_-]?secret|client[_-]?token|token|access[_-]?token|access[_-]?key|pwd)[=:]\s*["']?[a-z0-9._\-+/=]{12,}`),
		hasKey: true,
	},
	{
		kind:   "private-key",
		regex:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		hasKey: false,
	},
	{
		kind:   "jwt",
		regex:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`),
		hasKey: false,
	},
	{
		kind:   "google-api-key",
		regex:  regexp.MustCompile(`(?i)\bAIza[0-9A-Za-z_-]{35}`),
		hasKey: false,
	},
}

// Scan inspects content line by line and returns unique matches, one per rule
// per line. Detected values are discarded; only the metadata is kept.
func Scan(file, content string) []Match {
	var out []Match
	sc := bufio.NewScanner(strings.NewReader(content))
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		for _, r := range rules {
			idx := r.regex.FindStringIndex(text)
			if idx == nil {
				continue
			}
			var key string
			if r.hasKey {
				if sub := r.regex.FindStringSubmatchIndex(text); len(sub) >= 4 {
					key = text[sub[2]:sub[3]]
				}
			} else {
				key = extractKey(text, idx[0])
			}
			out = append(out, Match{Kind: r.kind, Key: key, Line: line, File: file})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Line != out[b].Line {
			return out[a].Line < out[b].Line
		}
		return out[a].Kind < out[b].Kind
	})
	return dedup(out)
}

func extractKey(text string, at int) string {
	if at < 0 || at > len(text) {
		return ""
	}
	prefix := text[:at]
	if i := strings.LastIndexAny(prefix, "=:"); i >= 0 {
		key := strings.Trim(strings.TrimSpace(prefix[:i]), `"'`)
		if key != "" && len(key) <= 80 {
			return key
		}
	}
	return ""
}

func dedup(in []Match) []Match {
	seen := map[Match]bool{}
	out := make([]Match, 0, len(in))
	for _, m := range in {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}
