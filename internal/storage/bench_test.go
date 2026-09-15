package storage_test

import (
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
	"github.com/QYVORA/qyvora-imhotep/internal/storage"
)

func BenchmarkAnalyzeBucket(b *testing.B) {
	bucket := &cloud.Bucket{
		Name: "data",
		Policy: []byte(`{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Principal":"*","Action":"s3:Get*","Resource":"arn:aws:s3:::data/*"},
			{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::data/uploads/*"}
		]}`),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if e := storage.AnalyzeBucket(bucket); e.PublicRead == false && e.PublicWrite == true {
			b.Fatalf("unexpected exposure %+v", e)
		}
	}
}

func BenchmarkAnalyzeBucketWideWildcard(b *testing.B) {
	bucket := &cloud.Bucket{
		Name:   "data",
		Policy: []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if e := storage.AnalyzeBucket(bucket); !e.PublicRead || !e.PublicWrite {
			b.Fatalf("blanket wildcard must be fully public: %+v", e)
		}
	}
}
