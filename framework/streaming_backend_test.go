package framework

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUnauthenticatedPath(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		testPath string
		expected bool
	}{
		// Wildcard patterns with +
		{
			name:     "matches PKI issuer pem with wildcard",
			paths:    []string{"v1/+/issuer/+/pem"},
			testPath: "role/terraform/gateway/v1/pki/issuer/abc123/pem",
			expected: true,
		},
		{
			name:     "matches PKI issuer der with wildcard",
			paths:    []string{"v1/+/issuer/+/der"},
			testPath: "role/terraform/gateway/v1/pki/issuer/abc123/der",
			expected: true,
		},
		{
			name:     "matches PKI ca/pem with wildcard",
			paths:    []string{"v1/+/ca/pem"},
			testPath: "role/terraform/gateway/v1/pki/ca/pem",
			expected: true,
		},
		{
			name:     "matches PKI ca with wildcard",
			paths:    []string{"v1/+/ca"},
			testPath: "role/terraform/gateway/v1/pki/ca",
			expected: true,
		},
		{
			name:     "matches PKI cert/ca with wildcard",
			paths:    []string{"v1/+/cert/ca"},
			testPath: "role/terraform/gateway/v1/pki/cert/ca",
			expected: true,
		},
		{
			name:     "does not match different path structure",
			paths:    []string{"v1/+/issuer/+/pem"},
			testPath: "role/terraform/gateway/v1/secret/data/mykey",
			expected: false,
		},
		{
			name:     "does not match partial path",
			paths:    []string{"v1/+/issuer/+/pem"},
			testPath: "role/terraform/gateway/v1/pki/issuer/abc123",
			expected: false,
		},

		// Gateway path without role prefix
		{
			name:     "matches gateway path without role prefix",
			paths:    []string{"v1/+/issuer/+/pem"},
			testPath: "gateway/v1/pki/issuer/abc123/pem",
			expected: true,
		},

		// Exact match patterns (radix tree)
		{
			name:     "matches exact path",
			paths:    []string{"v1/sys/health"},
			testPath: "role/terraform/gateway/v1/sys/health",
			expected: true,
		},
		{
			name:     "does not match partial exact path",
			paths:    []string{"v1/sys/health"},
			testPath: "role/terraform/gateway/v1/sys/health/extra",
			expected: false,
		},

		// Prefix match patterns (with *)
		{
			name:     "matches prefix pattern",
			paths:    []string{"v1/sys/*"},
			testPath: "role/terraform/gateway/v1/sys/health",
			expected: true,
		},
		{
			name:     "matches prefix pattern with deeper path",
			paths:    []string{"v1/sys/*"},
			testPath: "role/terraform/gateway/v1/sys/mounts/pki",
			expected: true,
		},

		// Multiple patterns
		{
			name: "matches one of multiple patterns",
			paths: []string{
				"v1/+/issuer/+/pem",
				"v1/+/ca/pem",
				"v1/+/crl",
			},
			testPath: "role/terraform/gateway/v1/pki/crl",
			expected: true,
		},

		// Empty config
		{
			name:     "returns false for empty paths",
			paths:    []string{},
			testPath: "role/terraform/gateway/v1/pki/issuer/abc/pem",
			expected: false,
		},

		// Nil TransparentConfig
		{
			name:     "returns false for nil config",
			paths:    nil,
			testPath: "role/terraform/gateway/v1/pki/issuer/abc/pem",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &StreamingBackend{
				UnauthenticatedPaths: tt.paths,
			}

			result := b.IsUnauthenticatedPath(tt.testPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsUnauthenticatedPath_PathsContainingKeywords(t *testing.T) {
	// Test edge cases where the Vault path itself contains keywords like
	// "role/", "gateway/", or "/gateway" that are also used in transparent mode prefixes
	vaultPaths := []string{
		"v1/+/issuer/+/pem",
		"v1/+/issuer/+/der",
		"v1/+/ca/pem",
		"v1/+/ca",
	}

	b := &StreamingBackend{
		UnauthenticatedPaths: vaultPaths,
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Vault mount named "role-secrets" (contains "role")
		{
			name:     "mount named role-secrets with issuer path",
			path:     "role/terraform/gateway/v1/role-secrets/issuer/abc123/pem",
			expected: true,
		},
		{
			name:     "mount named role-secrets with ca path",
			path:     "role/terraform/gateway/v1/role-secrets/ca/pem",
			expected: true,
		},

		// Vault mount named "gateway-pki" (contains "gateway")
		{
			name:     "mount named gateway-pki with issuer path",
			path:     "role/admin/gateway/v1/gateway-pki/issuer/def456/pem",
			expected: true,
		},
		{
			name:     "mount named gateway-pki with ca path",
			path:     "role/admin/gateway/v1/gateway-pki/ca",
			expected: true,
		},

		// Vault mount named "my-gateway" (ends with "gateway")
		{
			name:     "mount named my-gateway with issuer path",
			path:     "role/ops/gateway/v1/my-gateway/issuer/xyz789/der",
			expected: true,
		},

		// Vault mount path containing "/gateway/" segment
		{
			name:     "mount path with gateway segment",
			path:     "role/dev/gateway/v1/pki-gateway-prod/issuer/abc/pem",
			expected: true,
		},

		// Secret path containing "role" keyword
		{
			name:     "issuer ID containing role keyword",
			path:     "role/terraform/gateway/v1/pki/issuer/role-issuer-123/pem",
			expected: true,
		},

		// Secret path containing "gateway" keyword
		{
			name:     "issuer ID containing gateway keyword",
			path:     "role/terraform/gateway/v1/pki/issuer/gateway-issuer/der",
			expected: true,
		},

		// Multiple keywords in path
		{
			name:     "path with multiple keywords - role-gateway mount",
			path:     "role/terraform/gateway/v1/role-gateway/issuer/abc/pem",
			expected: true,
		},
		{
			name:     "path with multiple keywords - gateway in mount and issuer",
			path:     "role/terraform/gateway/v1/gateway-pki/issuer/gateway-root/pem",
			expected: true,
		},

		// Edge case: mount literally named "gateway"
		{
			name:     "mount literally named gateway",
			path:     "role/terraform/gateway/v1/gateway/issuer/abc/pem",
			expected: true,
		},
		{
			name:     "mount literally named gateway with ca",
			path:     "role/terraform/gateway/v1/gateway/ca/pem",
			expected: true,
		},

		// Edge case: mount literally named "role"
		{
			name:     "mount literally named role",
			path:     "role/terraform/gateway/v1/role/issuer/abc/pem",
			expected: true,
		},

		// Should NOT match - different operation even with keywords in path
		{
			name:     "mount named role-secrets but wrong operation",
			path:     "role/terraform/gateway/v1/role-secrets/sign/my-role",
			expected: false,
		},
		{
			name:     "mount named gateway-pki but wrong operation",
			path:     "role/terraform/gateway/v1/gateway-pki/issue/my-role",
			expected: false,
		},

		// Direct gateway paths (no role prefix) with keyword-containing mounts
		{
			name:     "gateway path with role-containing mount",
			path:     "gateway/v1/role-pki/issuer/abc/pem",
			expected: true,
		},
		{
			name:     "gateway path with gateway-containing mount",
			path:     "gateway/v1/gateway-internal/ca/pem",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := b.IsUnauthenticatedPath(tt.path)
			assert.Equal(t, tt.expected, result, "path: %s", tt.path)
		})
	}
}

func TestIsUnauthenticatedPath_VaultPKIPaths(t *testing.T) {
	// Test with the actual Vault PKI unauthenticated paths
	vaultPaths := []string{
		"v1/+/issuer/+/pem",
		"v1/+/issuer/+/der",
		"v1/+/issuer/+/json",
		"v1/+/ca/pem",
		"v1/+/ca",
		"v1/+/ca_chain",
		"v1/+/cert/ca",
		"v1/+/cert/ca_chain",
		"v1/+/crl",
		"v1/+/crl/pem",
	}

	b := &StreamingBackend{
		UnauthenticatedPaths: vaultPaths,
	}

	tests := []struct {
		path     string
		expected bool
	}{
		// Should match (unauthenticated)
		{"role/provisionner/gateway/v1/pki/issuer/abc123/pem", true},
		{"role/provisionner/gateway/v1/pki/issuer/abc123/der", true},
		{"role/provisionner/gateway/v1/pki/issuer/abc123/json", true},
		{"role/provisionner/gateway/v1/pki/ca/pem", true},
		{"role/provisionner/gateway/v1/pki/ca", true},
		{"role/provisionner/gateway/v1/pki/ca_chain", true},
		{"role/provisionner/gateway/v1/pki/cert/ca", true},
		{"role/provisionner/gateway/v1/pki/cert/ca_chain", true},
		{"role/provisionner/gateway/v1/pki/crl", true},
		{"role/provisionner/gateway/v1/pki/crl/pem", true},
		// Different mount point should also work
		{"role/terraform/gateway/v1/pki-int/issuer/def456/pem", true},
		{"role/admin/gateway/v1/root-ca/ca/pem", true},

		// Should NOT match (requires authentication)
		{"role/provisionner/gateway/v1/secret/data/mykey", false},
		{"role/provisionner/gateway/v1/pki/issue/my-role", false},
		{"role/provisionner/gateway/v1/pki/sign/my-role", false},
		{"role/provisionner/gateway/v1/sys/mounts", false},
		{"role/provisionner/gateway/v1/auth/token/lookup-self", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := b.IsUnauthenticatedPath(tt.path)
			assert.Equal(t, tt.expected, result, "path: %s", tt.path)
		})
	}
}

func TestMatchWildcardSegments(t *testing.T) {
	tests := []struct {
		name         string
		pathParts    []string
		patternParts []string
		isPrefix     bool
		expected     bool
	}{
		{
			name:         "exact match with wildcard",
			pathParts:    []string{"v1", "pki", "issuer", "abc", "pem"},
			patternParts: []string{"v1", "+", "issuer", "+", "pem"},
			isPrefix:     false,
			expected:     true,
		},
		{
			name:         "wildcard matches any segment",
			pathParts:    []string{"v1", "my-custom-mount", "issuer", "12345", "pem"},
			patternParts: []string{"v1", "+", "issuer", "+", "pem"},
			isPrefix:     false,
			expected:     true,
		},
		{
			name:         "length mismatch",
			pathParts:    []string{"v1", "pki", "issuer", "abc"},
			patternParts: []string{"v1", "+", "issuer", "+", "pem"},
			isPrefix:     false,
			expected:     false,
		},
		{
			name:         "segment mismatch",
			pathParts:    []string{"v1", "pki", "sign", "abc", "pem"},
			patternParts: []string{"v1", "+", "issuer", "+", "pem"},
			isPrefix:     false,
			expected:     false,
		},
		{
			name:         "prefix match",
			pathParts:    []string{"v1", "pki", "issuer", "abc", "pem", "extra"},
			patternParts: []string{"v1", "+", "issuer"},
			isPrefix:     true,
			expected:     true,
		},
		{
			name:         "prefix match too short",
			pathParts:    []string{"v1", "pki"},
			patternParts: []string{"v1", "+", "issuer"},
			isPrefix:     true,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchWildcardSegments(tt.pathParts, tt.patternParts, tt.isPrefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetUnauthenticatedPaths_ResetsCache(t *testing.T) {
	b := &StreamingBackend{
		UnauthenticatedPaths: []string{"v1/+/ca/pem"},
	}

	// Initialize the unauthPaths by calling IsUnauthenticatedPath
	result1 := b.IsUnauthenticatedPath("role/test/gateway/v1/pki/ca/pem")
	assert.True(t, result1, "should match initial pattern")

	// This should NOT match with the initial config
	result2 := b.IsUnauthenticatedPath("role/test/gateway/v1/pki/issuer/abc/pem")
	assert.False(t, result2, "should not match issuer pattern initially")

	// Now update UnauthenticatedPaths directly and call SetTransparentConfig to reset cache
	b.UnauthenticatedPaths = []string{"v1/+/ca/pem", "v1/+/issuer/+/pem"}
	b.SetTransparentConfig(&TransparentConfig{}) // This resets the unauthPaths cache

	// The issuer pattern should now match
	result3 := b.IsUnauthenticatedPath("role/test/gateway/v1/pki/issuer/abc/pem")
	assert.True(t, result3, "should match issuer pattern after config update")
}

func BenchmarkIsUnauthenticatedPath(b *testing.B) {
	backend := &StreamingBackend{
		UnauthenticatedPaths: []string{
			"v1/+/issuer/+/pem",
			"v1/+/issuer/+/der",
			"v1/+/issuer/+/json",
			"v1/+/ca/pem",
			"v1/+/ca",
			"v1/+/ca_chain",
			"v1/+/cert/ca",
			"v1/+/cert/ca_chain",
			"v1/+/crl",
			"v1/+/crl/pem",
		},
	}

	// Initialize
	backend.IsUnauthenticatedPath("warmup")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.IsUnauthenticatedPath("role/provisionner/gateway/v1/pki/issuer/abc123/pem")
	}
}

func BenchmarkIsUnauthenticatedPath_NoMatch(b *testing.B) {
	backend := &StreamingBackend{
		UnauthenticatedPaths: []string{
			"v1/+/issuer/+/pem",
			"v1/+/issuer/+/der",
			"v1/+/issuer/+/json",
			"v1/+/ca/pem",
			"v1/+/ca",
			"v1/+/ca_chain",
			"v1/+/cert/ca",
			"v1/+/cert/ca_chain",
			"v1/+/crl",
			"v1/+/crl/pem",
		},
	}

	// Initialize
	backend.IsUnauthenticatedPath("warmup")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.IsUnauthenticatedPath("role/provisionner/gateway/v1/secret/data/mykey")
	}
}
