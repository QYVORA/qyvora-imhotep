package models_test

import (
	"testing"

	"github.com/QYVORA/qyvora-imhotep/pkg/models"
)

func BenchmarkRedactSecretDataRealSecrets(b *testing.B) {
	ev := []models.Evidence{
		{Data: "aws_access_key_id AKIAIOSFODNN7EXAMPLE aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{Data: "token ghp_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"},
		{Data: "BEGIN RSA PRIVATE KEY\nMIIEowIBAAKCAQEA\nEND RSA PRIVATE KEY"},
		{Data: "api_key=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"},
		{Data: "GET /health HTTP/1.1"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		models.RedactSecretData(ev)
	}
}

func BenchmarkRedactSecretDataClean(b *testing.B) {
	ev := make([]models.Evidence, 32)
	for i := range ev {
		ev[i].Data = "benign observation about endpoint routing during assessment"
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		models.RedactSecretData(ev)
	}
}
