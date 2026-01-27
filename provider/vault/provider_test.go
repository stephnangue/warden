package vault

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stretchr/testify/assert"
)

func TestTransparentModeProvider_ViaStreamingBackend(t *testing.T) {
	// Create a StreamingBackend with TransparentConfig (mimics what vaultBackend uses)
	sb := &framework.StreamingBackend{
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      true,
			AutoAuthPath: "auth/jwt/",
			DefaultRole:  "default-role",
		},
	}

	// Test IsTransparentMode
	t.Run("IsTransparentMode returns true when enabled", func(t *testing.T) {
		assert.True(t, sb.IsTransparentMode())
	})

	t.Run("IsTransparentMode returns false when disabled", func(t *testing.T) {
		sb2 := &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{
				Enabled: false,
			},
		}
		assert.False(t, sb2.IsTransparentMode())
	})

	t.Run("IsTransparentMode returns false when config is nil", func(t *testing.T) {
		sb3 := &framework.StreamingBackend{}
		assert.False(t, sb3.IsTransparentMode())
	})

	// Test GetAutoAuthPath
	t.Run("GetAutoAuthPath returns configured path", func(t *testing.T) {
		assert.Equal(t, "auth/jwt/", sb.GetAutoAuthPath())
	})

	t.Run("GetAutoAuthPath returns empty when config is nil", func(t *testing.T) {
		sb2 := &framework.StreamingBackend{}
		assert.Empty(t, sb2.GetAutoAuthPath())
	})
}

func TestGetTransparentRole_ViaStreamingBackend(t *testing.T) {
	sb := &framework.StreamingBackend{
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      true,
			AutoAuthPath: "auth/jwt/",
			DefaultRole:  "default-role",
		},
	}

	tests := []struct {
		name         string
		path         string
		expectedRole string
	}{
		{
			name:         "extracts role from standard path",
			path:         "role/terraform/gateway/v1/secret/data/foo",
			expectedRole: "terraform",
		},
		{
			name:         "extracts role from path with just gateway",
			path:         "role/myapp/gateway",
			expectedRole: "myapp",
		},
		{
			name:         "extracts role with complex path",
			path:         "role/ci-runner/gateway/v1/kv/data/config/database",
			expectedRole: "ci-runner",
		},
		{
			name:         "returns default role for non-matching path",
			path:         "gateway/v1/secret/data/foo",
			expectedRole: "default-role",
		},
		{
			name:         "returns default role for config path",
			path:         "config",
			expectedRole: "default-role",
		},
		{
			name:         "handles role with underscores",
			path:         "role/my_special_role/gateway/path",
			expectedRole: "my_special_role",
		},
		{
			name:         "handles role with hyphens",
			path:         "role/my-special-role/gateway/path",
			expectedRole: "my-special-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sb.GetTransparentRole(tt.path)
			assert.Equal(t, tt.expectedRole, result)
		})
	}
}

func TestGetTransparentRole_NoDefaultRole(t *testing.T) {
	sb := &framework.StreamingBackend{
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      true,
			AutoAuthPath: "auth/jwt/",
			DefaultRole:  "", // No default role
		},
	}

	t.Run("returns empty for non-matching path without default", func(t *testing.T) {
		result := sb.GetTransparentRole("gateway/v1/secret/data/foo")
		assert.Empty(t, result)
	})

	t.Run("still extracts role from matching path", func(t *testing.T) {
		result := sb.GetTransparentRole("role/terraform/gateway/v1/secret")
		assert.Equal(t, "terraform", result)
	})
}

func TestRewriteTransparentPath_ViaStreamingBackend(t *testing.T) {
	sb := &framework.StreamingBackend{
		TransparentConfig: &framework.TransparentConfig{
			Enabled: true,
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "rewrites role path to gateway",
			input:    "role/terraform/gateway/v1/secret/data/foo",
			expected: "gateway/v1/secret/data/foo",
		},
		{
			name:     "rewrites minimal role path",
			input:    "role/app/gateway",
			expected: "gateway",
		},
		{
			name:     "preserves non-matching paths",
			input:    "gateway/v1/secret/data/foo",
			expected: "gateway/v1/secret/data/foo",
		},
		{
			name:     "preserves config path",
			input:    "config",
			expected: "config",
		},
		{
			name:     "handles complex gateway paths",
			input:    "role/ci/gateway/v1/kv/data/a/b/c",
			expected: "gateway/v1/kv/data/a/b/c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sb.RewriteTransparentPath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultTransparentRolePattern(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		shouldMatch  bool
		expectedRole string
	}{
		{
			name:         "matches standard transparent path",
			path:         "role/terraform/gateway/v1/secret",
			shouldMatch:  true,
			expectedRole: "terraform",
		},
		{
			name:         "matches minimal transparent path",
			path:         "role/app/gateway",
			shouldMatch:  true,
			expectedRole: "app",
		},
		{
			name:        "does not match regular gateway",
			path:        "gateway/v1/secret",
			shouldMatch: false,
		},
		{
			name:        "does not match config",
			path:        "config",
			shouldMatch: false,
		},
		{
			name:        "does not match incomplete role path",
			path:        "role/terraform/config",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := framework.DefaultTransparentRolePattern.FindStringSubmatch(tt.path)
			if tt.shouldMatch {
				assert.NotNil(t, matches, "expected path to match: %s", tt.path)
				if len(matches) > 1 {
					assert.Equal(t, tt.expectedRole, matches[1])
				}
			} else {
				assert.Nil(t, matches, "expected path to not match: %s", tt.path)
			}
		})
	}
}

func TestSetTransparentConfig(t *testing.T) {
	sb := &framework.StreamingBackend{}

	// Initially no config
	assert.False(t, sb.IsTransparentMode())
	assert.Empty(t, sb.GetAutoAuthPath())

	// Set config
	sb.SetTransparentConfig(&framework.TransparentConfig{
		Enabled:      true,
		AutoAuthPath: "auth/oidc/",
		DefaultRole:  "admin",
	})

	// Now should be enabled
	assert.True(t, sb.IsTransparentMode())
	assert.Equal(t, "auth/oidc/", sb.GetAutoAuthPath())
	assert.Equal(t, "admin", sb.GetTransparentRole("config"))
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name: "X-Vault-Token header",
			headers: map[string]string{
				"X-Vault-Token": "hvs.test-token-123",
			},
			expected: "hvs.test-token-123",
		},
		{
			name: "Authorization Bearer token",
			headers: map[string]string{
				"Authorization": "Bearer my-warden-token",
			},
			expected: "my-warden-token",
		},
		{
			name: "X-Vault-Token takes precedence over Authorization",
			headers: map[string]string{
				"X-Vault-Token": "vault-token",
				"Authorization": "Bearer auth-token",
			},
			expected: "vault-token",
		},
		{
			name: "Authorization with lowercase bearer",
			headers: map[string]string{
				"Authorization": "bearer lowercase-token",
			},
			expected: "lowercase-token",
		},
		{
			name: "Authorization with mixed case BEARER",
			headers: map[string]string{
				"Authorization": "BEARER uppercase-token",
			},
			expected: "uppercase-token",
		},
		{
			name:     "no token present",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name: "Authorization without Bearer prefix",
			headers: map[string]string{
				"Authorization": "Basic sometoken",
			},
			expected: "",
		},
		{
			name: "empty X-Vault-Token falls back to Authorization",
			headers: map[string]string{
				"X-Vault-Token": "",
				"Authorization": "Bearer fallback-token",
			},
			expected: "fallback-token",
		},
		{
			name: "Authorization too short",
			headers: map[string]string{
				"Authorization": "Bear",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := extractToken(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}
