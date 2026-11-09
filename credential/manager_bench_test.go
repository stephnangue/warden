package credential

import (
	"testing"
	"time"
)

// BenchmarkIssueCredentialHit measures the cache-hit path, which every gateway
// request with a warm credential takes.
func BenchmarkIssueCredentialHit(b *testing.B) {
	manager, configStore, _ := createTestManager(b)
	defer manager.Stop()

	configStore.AddSource(&CredSource{Name: "test-source", Type: SourceTypeLocal, Config: NewConfig(map[string]string{})})
	configStore.AddSpec(&CredSpec{Name: "test-spec", Type: TypeVaultToken, Source: "test-source", Config: NewConfig(map[string]string{})})

	ctx := createNamespaceContext()
	caller := Caller{TokenID: "token-bench", TokenTTL: time.Hour}
	if _, err := manager.IssueCredential(ctx, caller, "test-spec", nil); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := manager.IssueCredential(ctx, caller, "test-spec", nil); err != nil {
				b.Error(err) // FailNow may not run off the benchmark goroutine
				return
			}
		}
	})
}
