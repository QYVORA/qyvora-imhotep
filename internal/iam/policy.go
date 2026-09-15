// Package iam parses IAM policy documents into provider-neutral statements so
// rules can reason about allowed actions and resources. It understands the
// AWS IAM policy JSON shape and the common Azure/GCP equivalents.
package iam

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
)

// ParsePolicy parses a raw policy JSON blob into statements. Documents that
// declare zero actionable statements are rejected.
func ParsePolicy(raw string) (cloud.Policy, error) {
	var doc struct {
		Version   string `json:"Version"`
		Statement any    `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return cloud.Policy{}, fmt.Errorf("policy is not valid JSON: %w", err)
	}
	p := cloud.Policy{Version: doc.Version, Raw: raw}
	stmts, err := toStatements(doc.Statement)
	if err != nil {
		return cloud.Policy{}, err
	}
	p.Statements = stmts
	return p, nil
}

func toStatements(st any) ([]cloud.Statement, error) {
	switch v := st.(type) {
	case []any:
		out := make([]cloud.Statement, 0, len(v))
		for _, item := range v {
			stmt, err := toStatement(item)
			if err != nil {
				return nil, err
			}
			out = append(out, stmt)
		}
		return out, nil
	case map[string]any:
		stmt, err := toStatement(v)
		if err != nil {
			return nil, err
		}
		return []cloud.Statement{stmt}, nil
	case nil:
		return nil, fmt.Errorf("policy has no Statement")
	default:
		return nil, fmt.Errorf("policy Statement has unsupported shape")
	}
}

func toStatement(item any) (cloud.Statement, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return cloud.Statement{}, fmt.Errorf("statement entry is not an object")
	}
	s := cloud.Statement{}
	if e, ok := m["Effect"].(string); ok {
		s.Effect = e
	}
	s.Actions = toStrings(m["Action"])
	s.Resources = toStrings(m["Resource"])
	switch p := m["Principal"].(type) {
	case string:
		s.Principal = p
		s.Anonymous = strings.TrimSpace(p) == "*"
	case map[string]any:
		// A principal map names explicit principals; only an all-wildcard
		// form ("*"/"*" or AWS:"*") denotes unauthenticated access. Treating
		// every map as "*" mis-flagged account-scoped policies as public.
		s.Principal = strings.Join(principalKeys(p), ",")
		s.Anonymous = principalIsWildcard(p)
	}
	return s, nil
}

func principalKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// principalIsWildcard reports whether the principal map grants the access to
// everyone ({"*": "*"} or {"AWS": "*"} style).
func principalIsWildcard(m map[string]any) bool {
	if len(m) != 1 {
		return false
	}
	for k, v := range m {
		if k != "*" && !strings.EqualFold(k, "AWS") {
			return false
		}
		sv, ok := v.(string)
		if !ok || strings.TrimSpace(sv) != "*" {
			return false
		}
	}
	return true
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" || t == "*" {
			return []string{t}
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// IsWildcardAction reports whether the statement allows every action.
func IsWildcardAction(s cloud.Statement) bool {
	for _, a := range s.Actions {
		if strings.TrimSpace(a) == "*" {
			return true
		}
	}
	return false
}

// IsWildcardResource reports whether the statement applies to every resource.
func IsWildcardResource(s cloud.Statement) bool {
	for _, r := range s.Resources {
		if strings.TrimSpace(r) == "*" {
			return true
		}
	}
	return false
}

// Allows reports whether any statement allows the given action on the given
// resource (exact match or wildcard).
func Allows(stmts []cloud.Statement, action, resource string) bool {
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if matchesList(s.Actions, action) && matchesList(s.Resources, resource) {
			return true
		}
	}
	return false
}

func matchesList(list []string, want string) bool {
	for _, item := range list {
		if strings.TrimSpace(item) == "*" || strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}

// IsDenyAll reports whether any statement explicitly denies the given action.
func IsDenyAll(stmts []cloud.Statement) bool {
	for _, s := range stmts {
		if strings.EqualFold(s.Effect, "Deny") && IsWildcardAction(s) && IsWildcardResource(s) {
			return true
		}
	}
	return false
}
