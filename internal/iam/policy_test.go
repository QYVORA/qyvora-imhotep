package iam_test

import (
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
