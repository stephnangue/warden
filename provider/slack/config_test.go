package slack

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

func TestParseConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{})
		assert.Equal(t, DefaultSlackURL, config.SlackURL)
		assert.Greater(t, config.MaxBodySize, int64(0))
		assert.Equal(t, DefaultSlackTimeout, config.Timeout)
	})

	t.Run("custom values", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"slack_url": "https://slack.example.com/api",
			"timeout":   "60s",
		})
		assert.Equal(t, "https://slack.example.com/api", config.SlackURL)
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

func TestValidateConfig(t *testing.T) {
	t.Run("empty config valid", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{}))
	})

	t.Run("valid slack_url", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"slack_url": "https://slack.com/api"}))
	})

	t.Run("HTTP rejected", func(t *testing.T) {
		err := ValidateConfig(map[string]any{"slack_url": "http://slack.com"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "https://")
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

	t.Run("negative timeout int", func(t *testing.T) {
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

	t.Run("string max_body_size", func(t *testing.T) {
		assert.NoError(t, ValidateConfig(map[string]any{"max_body_size": "1024"}))
	})

	t.Run("invalid string max_body_size", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"max_body_size": "not-a-number"}))
	})

	t.Run("non-string auto_auth_path", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"auto_auth_path": 123}))
	})

	t.Run("non-string default_role", func(t *testing.T) {
		assert.Error(t, ValidateConfig(map[string]any{"default_role": 123}))
	})
}

func TestValidateSlackAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty is valid", "", false},
		{"valid HTTPS", "https://slack.com/api", false},
		{"HTTP rejected", "http://slack.com", true},
		{"no scheme", "slack.com", true},
		{"no host", "https://", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSlackAddress(tc.addr)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
