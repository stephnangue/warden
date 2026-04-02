package github

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stretchr/testify/assert"
)

func TestExtractToken_Extended(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"X-Warden-Token", map[string]string{"X-Warden-Token": "wt"}, "wt"},
		{"Bearer token", map[string]string{"Authorization": "Bearer bt"}, "bt"},
		{"case insensitive Bearer", map[string]string{"Authorization": "bearer bt"}, "bt"},
		{"X-Warden-Token priority", map[string]string{"X-Warden-Token": "wt", "Authorization": "Bearer bt"}, "wt"},
		{"no token", map[string]string{}, ""},
		{"non-Bearer auth ignored", map[string]string{"Authorization": "Basic abc"}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.expected, extractToken(req))
		})
	}
}

func TestParseConfig_Full(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{})
		assert.Equal(t, DefaultGitHubURL, config.GitHubURL)
		assert.Equal(t, DefaultAPIVersion, config.APIVersion)
		assert.Equal(t, framework.DefaultMaxBodySize, config.MaxBodySize)
		assert.Equal(t, framework.DefaultTimeout, config.Timeout)
	})

	t.Run("custom values", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"github_url":  "https://github.example.com",
			"api_version": "2023-01-01",
			"timeout":     "60s",
		})
		assert.Equal(t, "https://github.example.com", config.GitHubURL)
		assert.Equal(t, "2023-01-01", config.APIVersion)
		assert.Equal(t, 60.0, config.Timeout.Seconds())
	})

	t.Run("integer timeout", func(t *testing.T) {
		config := parseConfig(map[string]any{"timeout": 45})
		assert.Equal(t, 45.0, config.Timeout.Seconds())
	})

	t.Run("float timeout", func(t *testing.T) {
		config := parseConfig(map[string]any{"timeout": 30.0})
		assert.Equal(t, 30.0, config.Timeout.Seconds())
	})

	t.Run("int64 max_body_size", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": int64(5242880)})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
	})

	t.Run("float max_body_size", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": 5242880.0})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
	})

	t.Run("string max_body_size", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": "5242880"})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
	})

	t.Run("auth settings", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		})
		assert.Equal(t, "auth/jwt/", config.AutoAuthPath)
		assert.Equal(t, "reader", config.DefaultAuthRole)
	})
}

func TestValidateConfig_Full(t *testing.T) {
	t.Run("empty config valid", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{}))
	})

	t.Run("valid github_url", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"github_url": "https://api.github.com"}))
	})

	t.Run("HTTP rejected", func(t *testing.T) {
		err := ValidateConfig(map[string]any{"github_url": "http://github.com"})
		assert.Error(t, err)
	})

	t.Run("invalid timeout", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": "bad"}))
	})

	t.Run("negative max_body_size", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": -1}))
	})

	t.Run("oversized max_body_size", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": 200000000}))
	})

	t.Run("invalid timeout type", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": []string{"bad"}}))
	})

	t.Run("negative timeout", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": -1}))
	})

	t.Run("negative timeout float", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"timeout": -1.0}))
	})

	t.Run("invalid max_body_size type", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": true}))
	})

	t.Run("int64 max_body_size", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"max_body_size": int64(1024)}))
	})

	t.Run("float64 max_body_size", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"max_body_size": 1024.0}))
	})

	t.Run("string max_body_size valid", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"max_body_size": "1024"}))
	})

	t.Run("string max_body_size invalid", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": "not-a-number"}))
	})

	t.Run("non-string auto_auth_path", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"auto_auth_path": 123}))
	})

	t.Run("non-string default_role", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"default_role": 123}))
	})

	t.Run("non-string api_version", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"api_version": 123}))
	})
}

func TestValidateGitHubAddress_Extended(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty is valid", "", false},
		{"valid HTTPS", "https://api.github.com", false},
		{"HTTP rejected", "http://github.com", true},
		{"no scheme", "github.com", true},
		{"no host", "https://", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGitHubAddress(tc.addr)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
