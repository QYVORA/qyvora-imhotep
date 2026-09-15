package iam_test

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/iam"
)

func TestParsePolicyWithListStatements(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]},
		{"Effect":"Allow","Action":["*"],"Resource":["*"]}
	]}`
	p, err := iam.ParsePolicy(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Statements) != 2 {
		t.Fatalf("statements = %d", len(p.Statements))
	}
	if iam.IsWildcardAction(p.Statements[1]) != true {
		t.Error("statement[1] should be wildcard action")
	}
	if iam.IsWildcardResource(p.Statements[1]) != true {
		t.Error("statement[1] should be wildcard resource")
	}
	if iam.IsWildcardAction(p.Statements[0]) {
		t.Error("statement[0] must not be wildcard")
	}
	if !iam.Allows(p.Statements, "s3:GetObject", "arn:aws:s3:::b/x") {
		t.Error("Allows should match s3:GetObject")
	}
}

func TestParsePolicySingleStatementObject(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`
	p, err := iam.ParsePolicy(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Statements) != 1 {
		t.Fatalf("statements = %d", len(p.Statements))
	}
	if !iam.IsDenyAll(p.Statements) {
		t.Error("expected deny-all")
	}
}

func TestParsePolicyRejectsNonJSON(t *testing.T) {
	if _, err := iam.ParsePolicy("not-json{"); err == nil {
		t.Error("expected parse error")
	}
}

func TestParsePolicyRejectsMissingStatement(t *testing.T) {
	if _, err := iam.ParsePolicy(`{"Version":"2012-10-17"}`); err == nil {
		t.Error("expected error for missing Statement")
	}
}

func TestPrincipalMapAccountARNIsNotAnonymous(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"*","Resource":"*"}}`
	p, err := iam.ParsePolicy(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	st := p.Statements[0]
	if st.Anonymous {
		t.Error("account ARN principal must not be anonymous")
	}
	if !strings.Contains(st.Principal, "AWS") {
		t.Errorf("principal rendering lost the key: %q", st.Principal)
	}
}

func TestPrincipalStringWildcardIsAnonymous(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"Get","Resource":"*"}}`
	p, err := iam.ParsePolicy(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Statements[0].Anonymous {
		t.Error("string \"*\" principal must be anonymous")
	}
}

func TestPrincipalWildcardMapIsAnonymous(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"*":"*"},"Action":"Get","Resource":"*"}}`
	p, err := iam.ParsePolicy(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Statements[0].Anonymous {
		t.Error("{\"*\":\"*\"} principal must be anonymous")
	}
}
