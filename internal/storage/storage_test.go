package storage_test

import (
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
	"github.com/QYVORA/qyvora-imhotep/internal/storage"
)

func TestBucketPublicViaPolicy(t *testing.T) {
	b := cloud.Bucket{
		Name: "b", PublicRead: false,
		Policy: []byte(`{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}`),
	}
	ex := storage.AnalyzeBucket(&b)
	if !ex.PublicRead {
		t.Error("expected public read from policy")
	}
	if ex.PublicWrite {
		t.Error("must not flag write from read policy")
	}
	if len(ex.Reasons) == 0 {
		t.Error("expected reasons")
	}
}

func TestBucketFlagWins(t *testing.T) {
	b := cloud.Bucket{Name: "b", PublicRead: true, PublicWrite: true}
	ex := storage.AnalyzeBucket(&b)
	if !ex.PublicRead || !ex.PublicWrite {
		t.Error("expected both flags from configuration")
	}
}

func TestBucketPolicyWithIdentifiedPrincipalNotPublic(t *testing.T) {
	b := cloud.Bucket{
		Name: "b",
		Policy: []byte(`{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"*","Resource":"*"}}`),
	}
	ex := storage.AnalyzeBucket(&b)
	// Principal is identity-based, not anonymous; treat as non-public.
	if ex.PublicRead {
		t.Error("identity principal must not be treated as public")
	}
}

func TestBucketPolicyServiceWildcardIsPublic(t *testing.T) {
	b := cloud.Bucket{
		Name: "b",
		Policy: []byte(`{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}}`),
	}
	ex := storage.AnalyzeBucket(&b)
	if !ex.PublicRead || !ex.PublicWrite {
		t.Errorf("service-wide wildcard must be public read+write: %+v", ex)
	}
}

func TestBucketPolicyAllWildcardActionIsPublic(t *testing.T) {
	b := cloud.Bucket{
		Name: "b",
		Policy: []byte(`{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`),
	}
	ex := storage.AnalyzeBucket(&b)
	if !ex.PublicRead || !ex.PublicWrite {
		t.Errorf("blanket wildcard policy must be public: %+v", ex)
	}
}

func TestBucketPolicyGlobActionIsPublic(t *testing.T) {
	b := cloud.Bucket{
		Name: "b",
		Policy: []byte(`{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":"*","Action":"s3:Get*","Resource":"arn:aws:s3:::b/*"}}`),
	}
	ex := storage.AnalyzeBucket(&b)
	if !ex.PublicRead {
		t.Error("glob read action must be flagged public-read")
	}
	if ex.PublicWrite {
		t.Error("glob read action must not be flagged public-write")
	}
}

func TestBucketPolicyAnonymousMapPrincipalIsPublic(t *testing.T) {
	b := cloud.Bucket{
		Name: "b",
		Policy: []byte(`{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}`),
	}
	ex := storage.AnalyzeBucket(&b)
	if !ex.PublicRead {
		t.Error("AWS:\"*\" principal map is unauthenticated and must be public")
	}
}
