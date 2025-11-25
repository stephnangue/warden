package token

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
)

// BenchmarkGenerateToken_UserPass benchmarks token generation for user/pass
func BenchmarkGenerateToken_UserPass(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "benchuser",
		RoleName:     "admin",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.1",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.GenerateToken(USER_PASS, authData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateToken_AWSKeys benchmarks AWS access key generation
func BenchmarkGenerateToken_AWSKeys(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "benchuser",
		RoleName:     "s3-access",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "10.0.0.1",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.GenerateToken(AWS_ACCESS_KEYS, authData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResolveToken_CacheHit benchmarks token resolution with cache hits
func BenchmarkResolveToken_CacheHit(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "benchuser",
		RoleName:     "viewer",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.1",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	if err != nil {
		b.Fatal(err)
	}

	reqContext := map[string]string{
		"client_ip": "192.168.1.1",
	}

	// Warm up cache
	_, _, _ = store.ResolveToken(context.Background(),token.Data["username"], reqContext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := store.ResolveToken(context.Background(),token.Data["username"], reqContext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResolveToken_NoCache benchmarks token resolution without cache
func BenchmarkResolveToken_NoCache(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "benchuser",
		RoleName:     "viewer",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "192.168.1.1",
		},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	if err != nil {
		b.Fatal(err)
	}

	reqContext := map[string]string{
		"client_ip": "192.168.1.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := store.ResolveToken(context.Background(),token.Data["username"], reqContext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetToken_WithCache benchmarks token retrieval with cache
func BenchmarkGetToken_WithCache(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	authData := &AuthData{
		PrincipalID:  "benchuser",
		RoleName:     "admin",
		AuthDeadline: time.Now().Add(5 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{},
	}

	token, err := store.GenerateToken(USER_PASS, authData)
	if err != nil {
		b.Fatal(err)
	}

	tokenID := token.Data["username"]

	// Warm up cache
	_ = store.GetToken(tokenID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.GetToken(tokenID)
	}
}

// BenchmarkConcurrentGenerate benchmarks concurrent token generation
func BenchmarkConcurrentGenerate(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	b.RunParallel(func(pb *testing.PB) {
		authData := &AuthData{
			PrincipalID:  "benchuser",
			RoleName:     "concurrent",
			AuthDeadline: time.Now().Add(5 * time.Minute),
			ExpireAt:     time.Now().Add(1 * time.Hour),
			RequestContext: map[string]string{
				"client_ip": "192.168.1.1",
			},
		}

		for pb.Next() {
			_, err := store.GenerateToken(USER_PASS, authData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkConcurrentResolve benchmarks concurrent token resolution
func BenchmarkConcurrentResolve(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	// Pre-generate tokens
	tokens := make([]*Token, 100)
	for i := 0; i < 100; i++ {
		authData := &AuthData{
			PrincipalID:  "benchuser",
			RoleName:     "concurrent",
			AuthDeadline: time.Now().Add(5 * time.Minute),
			ExpireAt:     time.Now().Add(1 * time.Hour),
			RequestContext: map[string]string{
				"client_ip": "192.168.1.1",
			},
		}
		token, err := store.GenerateToken(USER_PASS, authData)
		if err != nil {
			b.Fatal(err)
		}
		tokens[i] = token
	}

	reqContext := map[string]string{
		"client_ip": "192.168.1.1",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			tokenID := tokens[i%len(tokens)].Data["username"]
			_, _, err := store.ResolveToken(context.Background(),tokenID, reqContext)
			if err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkMemoryUsage measures memory overhead
func BenchmarkMemoryUsage(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		authData := &AuthData{
			PrincipalID:  "benchuser",
			RoleName:     "memory",
			AuthDeadline: time.Now().Add(5 * time.Minute),
			ExpireAt:     time.Now().Add(1 * time.Hour),
			RequestContext: map[string]string{
				"client_ip": "192.168.1.1",
			},
		}

		token, err := store.GenerateToken(USER_PASS, authData)
		if err != nil {
			b.Fatal(err)
		}

		reqContext := map[string]string{
			"client_ip": "192.168.1.1",
		}
		_, _, err = store.ResolveToken(context.Background(),token.Data["username"], reqContext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHighLoad simulates high load scenario
func BenchmarkHighLoad(b *testing.B) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	config := DefaultConfig()

	store, err := NewRobustStore(log, config)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	// Pre-populate store
	tokens := make([]*Token, 10000)
	for i := 0; i < 10000; i++ {
		authData := &AuthData{
			PrincipalID:  "user",
			RoleName:     "highload",
			AuthDeadline: time.Now().Add(5 * time.Minute),
			ExpireAt:     time.Now().Add(1 * time.Hour),
			RequestContext: map[string]string{
				"client_ip": "192.168.1.1",
			},
		}
		token, err := store.GenerateToken(USER_PASS, authData)
		if err != nil {
			b.Fatal(err)
		}
		tokens[i] = token
	}

	reqContext := map[string]string{
		"client_ip": "192.168.1.1",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			tokenID := tokens[i%len(tokens)].Data["username"]
			_, _, _ = store.ResolveToken(context.Background(),tokenID, reqContext)
			i++
		}
	})
}

// BenchmarkStoreScaling measures performance at different store sizes
func BenchmarkStoreScaling(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(string(rune(size)), func(b *testing.B) {
			log := logger.NewZerologLogger(logger.DefaultConfig())
			config := DefaultConfig()

			store, err := NewRobustStore(log, config)
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()

			// Pre-populate
			tokens := make([]*Token, size)
			for i := 0; i < size; i++ {
				authData := &AuthData{
					PrincipalID:  "user",
					RoleName:     "scaling",
					AuthDeadline: time.Now().Add(5 * time.Minute),
					ExpireAt:     time.Now().Add(1 * time.Hour),
					RequestContext: map[string]string{},
				}
				token, err := store.GenerateToken(USER_PASS, authData)
				if err != nil {
					b.Fatal(err)
				}
				tokens[i] = token
			}

			reqContext := map[string]string{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tokenID := tokens[i%size].Data["username"]
				_, _, _ = store.ResolveToken(context.Background(),tokenID, reqContext)
			}
		})
	}
}