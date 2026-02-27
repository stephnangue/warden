package openai

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "X-Warden-Token header",
			headers:  map[string]string{"X-Warden-Token": "warden-token-123"},
			expected: "warden-token-123",
		},
		{
			name:     "Bearer token",
			headers:  map[string]string{"Authorization": "Bearer my-bearer-token"},
			expected: "my-bearer-token",
		},
		{
			name:     "X-Warden-Token takes priority over Bearer",
			headers:  map[string]string{"X-Warden-Token": "warden-token", "Authorization": "Bearer bearer-token"},
			expected: "warden-token",
		},
		{
			name:     "No token",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "Non-Bearer auth header ignored",
			headers:  map[string]string{"Authorization": "token ghp_abc123"},
			expected: "",
		},
		{
			name:     "Case insensitive Bearer",
			headers:  map[string]string{"Authorization": "bearer my-token"},
			expected: "my-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			result := extractToken(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{})
		assert.Equal(t, DefaultOpenAIURL, config.OpenAIURL)
		assert.Greater(t, config.MaxBodySize, int64(0))
		assert.Equal(t, DefaultOpenAITimeout, config.Timeout)
	})

	t.Run("custom values", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"openai_url": "https://openai.example.com",
			"timeout":    "60s",
		})
		assert.Equal(t, "https://openai.example.com", config.OpenAIURL)
		assert.Equal(t, 60.0, config.Timeout.Seconds())
	})

	t.Run("integer timeout", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"timeout": 45,
		})
		assert.Equal(t, 45.0, config.Timeout.Seconds())
	})

	t.Run("transparent mode settings", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"transparent_mode": true,
			"auto_auth_path":   "auth/jwt/",
			"default_role":     "reader",
		})
		assert.True(t, config.TransparentMode)
		assert.Equal(t, "auth/jwt/", config.AutoAuthPath)
		assert.Equal(t, "reader", config.DefaultRole)
	})
}

func TestValidateConfig(t *testing.T) {
	t.Run("empty config is valid", func(t *testing.T) {
		err := ValidateConfig(map[string]any{})
		assert.NoError(t, err)
	})

	t.Run("valid openai_url", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"openai_url": "https://api.openai.com",
		})
		assert.NoError(t, err)
	})

	t.Run("non-HTTPS openai_url rejected", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"openai_url": "http://api.openai.com",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "https://")
	})

	t.Run("invalid timeout format", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"timeout": "not-a-duration",
		})
		assert.Error(t, err)
	})

	t.Run("negative max_body_size", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": -1,
		})
		assert.Error(t, err)
	})

	t.Run("oversized max_body_size", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": 200000000, // 200MB
		})
		assert.Error(t, err)
	})

	t.Run("invalid transparent_mode type", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"transparent_mode": "yes",
		})
		assert.Error(t, err)
	})
}

func TestValidateOpenAIAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty is valid", "", false},
		{"valid HTTPS", "https://api.openai.com", false},
		{"valid custom", "https://openai.example.com", false},
		{"HTTP rejected", "http://api.openai.com", true},
		{"no scheme", "api.openai.com", true},
		{"no host", "https://", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOpenAIAddress(tc.addr)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
