package iam_test

import (
	"fmt"
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/iam"
)

func BenchmarkParsePolicy(b *testing.B) {
	bucketPolicy := `{
		"Version":"2012-10-17",
		"Statement":[
			{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:ListBucket"],
			 "Resource":["arn:aws:s3:::data/*","arn:aws:s3:::data"]},
			{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:role/backup"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::data/*"}
		]
	}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := iam.ParsePolicy(bucketPolicy); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParsePolicyLarge(b *testing.B) {
	const statements = 50
	var body string
	for i := 0; i < statements; i++ {
		if i > 0 {
			body += ","
		}
		body += fmt.Sprintf(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/u%d"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::data/%d/*"}`, i, i)
	}
	raw := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%s]}`, body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := iam.ParsePolicy(raw); err != nil {
			b.Fatal(err)
		}
	}
}
