// Package containers inspects raw container manifests (Dockerfiles, Kubernetes
// YAML, compose files) for risky posture: privileged containers, host
// networking, latest/label-less images, and non-scratch roots. Detection is
// deliberately conservative: it matches manifest idioms with line references
// and never executes anything.
package containers

import (
	"bufio"
	"strings"
)

// Flag is one risky posture indicator found in a manifest.
type Flag struct {
	Kind string `json:"kind"` // privileged|host_network|latest_tag|runs_as_root
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Inspect scans manifest content and returns posture flags with line numbers.
func Inspect(kind, content string) []Flag {
	var flags []Flag
	sc := bufio.NewScanner(strings.NewReader(content))
	line := 0
	// Dockerfile directives may be written as "KEY value" with mixed case.
	for sc.Scan() {
		line++
		raw := sc.Text()
		trim := strings.TrimSpace(raw)
		lower := strings.ToLower(trim)
		switch {
		case strings.Contains(lower, "privileged: true") || strings.HasPrefix(lower, "privileged"):
			flags = append(flags, Flag{Kind: "privileged", Line: line, Text: trim})
		case strings.HasPrefix(lower, "userns-mode=host"):
			flags = append(flags, Flag{Kind: "privileged", Line: line, Text: trim})
		case strings.Contains(lower, "hostnetwork: true"):
			flags = append(flags, Flag{Kind: "host_network", Line: line, Text: trim})
		case strings.Contains(lower, "hostnetwork:") && strings.Contains(lower, "true"):
			flags = append(flags, Flag{Kind: "host_network", Line: line, Text: trim})
		case strings.Contains(lower, "user root") || strings.Contains(lower, "runasuser: 0") || strings.Contains(lower, "runasuser: 0"):
			flags = append(flags, Flag{Kind: "runs_as_root", Line: line, Text: trim})
		case includesLatestTag(lower):
			flags = append(flags, Flag{Kind: "latest_tag", Line: line, Text: trim})
		}
	}
	return flags
}

func includesLatestTag(s string) bool {
	fields := strings.Fields(s)
	for i, tok := range fields {
		lower := strings.ToLower(tok)
		var img string
		switch {
		case lower == "image:" && i+1 < len(fields):
			// YAML/TOML form: image: nginx:latest
			img = strings.Trim(fields[i+1], `"'`)
		case strings.HasPrefix(lower, "image:"):
			img = strings.Trim(lower[len("image:"):], `"'`)
		case strings.HasPrefix(lower, "from") && (i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "--")):
			// Dockerfile: FROM node:18 / FROM nginx
			img = strings.Trim(strings.ToLower(fields[i+1]), `"'`)
		}
		if img == "" {
			continue
		}
		if !strings.Contains(img, ":") {
			return true // no tag means latest pinned nowhere
		}
		if strings.HasSuffix(img, ":latest") {
			return true
		}
	}
	return false
}

func containsProtocol(kind, want string) bool { return strings.Contains(strings.ToLower(kind), want) }

// IsDocker reports whether the manifest kind is a Dockerfile-family document.
func IsDocker(kind string) bool { return containsProtocol(kind, "docker") }
