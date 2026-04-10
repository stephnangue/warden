package framework

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ParseMaxBodySize ---

func TestParseMaxBodySize(t *testing.T) {
	tests := []struct {
		name     string
		conf     map[string]any
		expected int64
	}{
		{"missing key", map[string]any{}, DefaultMaxBodySize},
		{"int", map[string]any{"max_body_size": 5242880}, int64(5242880)},
		{"int64", map[string]any{"max_body_size": int64(5242880)}, int64(5242880)},
		{"float64", map[string]any{"max_body_size": float64(5242880)}, int64(5242880)},
		{"json.Number", map[string]any{"max_body_size": json.Number("5242880")}, int64(5242880)},
		{"string", map[string]any{"max_body_size": "5242880"}, int64(5242880)},
		{"zero returns default", map[string]any{"max_body_size": 0}, DefaultMaxBodySize},
		{"negative returns default", map[string]any{"max_body_size": -1}, DefaultMaxBodySize},
		{"invalid string returns default", map[string]any{"max_body_size": "abc"}, DefaultMaxBodySize},
		{"invalid json.Number returns default", map[string]any{"max_body_size": json.Number("abc")}, DefaultMaxBodySize},
		{"bool returns default", map[string]any{"max_body_size": true}, DefaultMaxBodySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseMaxBodySize(tt.conf))
		})
	}
}

// --- ParseTimeout ---

func TestParseTimeout(t *testing.T) {
	defaultTimeout := 30 * time.Second

	tests := []struct {
		name     string
		conf     map[string]any
		expected time.Duration
	}{
		{"missing key", map[string]any{}, defaultTimeout},
		{"string duration", map[string]any{"timeout": "60s"}, 60 * time.Second},
		{"string minutes", map[string]any{"timeout": "5m"}, 5 * time.Minute},
		{"int seconds", map[string]any{"timeout": 45}, 45 * time.Second},
		{"float64 seconds", map[string]any{"timeout": float64(90)}, 90 * time.Second},
		{"zero string returns default", map[string]any{"timeout": "0s"}, defaultTimeout},
		{"zero int returns default", map[string]any{"timeout": 0}, defaultTimeout},
		{"negative returns default", map[string]any{"timeout": -1}, defaultTimeout},
		{"invalid string returns default", map[string]any{"timeout": "invalid"}, defaultTimeout},
		{"bool returns default", map[string]any{"timeout": true}, defaultTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseTimeout(tt.conf, defaultTimeout))
		})
	}
}

// --- ParseTLSConfig ---

func TestParseTLSConfig(t *testing.T) {
	t.Run("missing both", func(t *testing.T) {
		skip, ca := ParseTLSConfig(map[string]any{})
		assert.False(t, skip)
		assert.Empty(t, ca)
	})

	t.Run("tls_skip_verify bool true", func(t *testing.T) {
		skip, _ := ParseTLSConfig(map[string]any{"tls_skip_verify": true})
		assert.True(t, skip)
	})

	t.Run("tls_skip_verify bool false", func(t *testing.T) {
		skip, _ := ParseTLSConfig(map[string]any{"tls_skip_verify": false})
		assert.False(t, skip)
	})

	t.Run("tls_skip_verify string true", func(t *testing.T) {
		skip, _ := ParseTLSConfig(map[string]any{"tls_skip_verify": "true"})
		assert.True(t, skip)
	})

	t.Run("tls_skip_verify string 1", func(t *testing.T) {
		skip, _ := ParseTLSConfig(map[string]any{"tls_skip_verify": "1"})
		assert.True(t, skip)
	})

	t.Run("tls_skip_verify string false", func(t *testing.T) {
		skip, _ := ParseTLSConfig(map[string]any{"tls_skip_verify": "false"})
		assert.False(t, skip)
	})

	t.Run("tls_skip_verify unsupported type ignored", func(t *testing.T) {
		skip, _ := ParseTLSConfig(map[string]any{"tls_skip_verify": 42})
		assert.False(t, skip)
	})

	t.Run("ca_data present", func(t *testing.T) {
		_, ca := ParseTLSConfig(map[string]any{"ca_data": "LS0tLS1CRUdJTi..."})
		assert.Equal(t, "LS0tLS1CRUdJTi...", ca)
	})

	t.Run("ca_data non-string ignored", func(t *testing.T) {
		_, ca := ParseTLSConfig(map[string]any{"ca_data": 123})
		assert.Empty(t, ca)
	})
}

// --- GetConfigString ---

func TestGetConfigString(t *testing.T) {
	tests := []struct {
		name         string
		conf         map[string]any
		key          string
		defaultValue string
		expected     string
	}{
		{"present", map[string]any{"url": "https://example.com"}, "url", "default", "https://example.com"},
		{"missing", map[string]any{}, "url", "default", "default"},
		{"empty string returns default", map[string]any{"url": ""}, "url", "default", "default"},
		{"non-string returns default", map[string]any{"url": 123}, "url", "default", "default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetConfigString(tt.conf, tt.key, tt.defaultValue))
		})
	}
}

// --- ValidateAllowedKeys ---

func TestValidateAllowedKeys(t *testing.T) {
	t.Run("all keys allowed", func(t *testing.T) {
		err := ValidateAllowedKeys(map[string]any{"a": 1, "b": 2}, "a", "b", "c")
		assert.NoError(t, err)
	})

	t.Run("unknown key", func(t *testing.T) {
		err := ValidateAllowedKeys(map[string]any{"a": 1, "unknown": 2}, "a", "b")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown")
		assert.Contains(t, err.Error(), "allowed:")
	})

	t.Run("empty config", func(t *testing.T) {
		err := ValidateAllowedKeys(map[string]any{}, "a", "b")
		assert.NoError(t, err)
	})

	t.Run("no allowed keys rejects any key", func(t *testing.T) {
		err := ValidateAllowedKeys(map[string]any{"a": 1})
		require.Error(t, err)
	})
}

// --- ValidateMaxBodySize ---

func TestValidateMaxBodySize(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]any
		wantErr bool
		errMsg  string
	}{
		{"missing is valid", map[string]any{}, false, ""},
		{"valid int", map[string]any{"max_body_size": 1024}, false, ""},
		{"valid int64", map[string]any{"max_body_size": int64(1024)}, false, ""},
		{"valid float64", map[string]any{"max_body_size": float64(1024)}, false, ""},
		{"valid json.Number", map[string]any{"max_body_size": json.Number("1024")}, false, ""},
		{"valid string", map[string]any{"max_body_size": "1024"}, false, ""},
		{"zero", map[string]any{"max_body_size": 0}, true, "greater than 0"},
		{"negative", map[string]any{"max_body_size": -1}, true, "greater than 0"},
		{"exceeds 100MB", map[string]any{"max_body_size": 200000000}, true, "must not exceed"},
		{"exactly 100MB", map[string]any{"max_body_size": MaxBodySizeLimit}, false, ""},
		{"invalid string", map[string]any{"max_body_size": "abc"}, true, "must be an integer"},
		{"invalid json.Number", map[string]any{"max_body_size": json.Number("abc")}, true, "must be an integer"},
		{"bool type", map[string]any{"max_body_size": true}, true, "must be an integer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMaxBodySize(tt.conf)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- ValidateTimeout ---

func TestValidateTimeout(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]any
		wantErr bool
		errMsg  string
	}{
		{"missing is valid", map[string]any{}, false, ""},
		{"valid string", map[string]any{"timeout": "30s"}, false, ""},
		{"valid minutes", map[string]any{"timeout": "5m"}, false, ""},
		{"valid int", map[string]any{"timeout": 30}, false, ""},
		{"valid float64", map[string]any{"timeout": float64(30)}, false, ""},
		{"zero string is valid", map[string]any{"timeout": "0s"}, false, ""},
		{"zero int is valid", map[string]any{"timeout": 0}, false, ""},
		{"negative int", map[string]any{"timeout": -1}, true, "greater than 0"},
		{"negative float", map[string]any{"timeout": float64(-1)}, true, "greater than 0"},
		{"invalid string", map[string]any{"timeout": "invalid"}, true, "invalid timeout format"},
		{"bool type", map[string]any{"timeout": true}, true, "must be a duration string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTimeout(tt.conf)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- ValidateTLSConfig ---

func TestValidateTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]any
		wantErr bool
		errMsg  string
	}{
		{"missing is valid", map[string]any{}, false, ""},
		{"tls_skip_verify bool", map[string]any{"tls_skip_verify": true}, false, ""},
		{"tls_skip_verify string true", map[string]any{"tls_skip_verify": "true"}, false, ""},
		{"tls_skip_verify string false", map[string]any{"tls_skip_verify": "false"}, false, ""},
		{"tls_skip_verify string 1", map[string]any{"tls_skip_verify": "1"}, false, ""},
		{"tls_skip_verify string 0", map[string]any{"tls_skip_verify": "0"}, false, ""},
		{"tls_skip_verify invalid string", map[string]any{"tls_skip_verify": "yes"}, true, "must be a boolean"},
		{"tls_skip_verify int", map[string]any{"tls_skip_verify": 1}, true, "must be a boolean"},
		{"ca_data empty string", map[string]any{"ca_data": ""}, false, ""},
		{"ca_data invalid base64", map[string]any{"ca_data": "not-base64!"}, true, "not valid base64"},
		{"ca_data non-string", map[string]any{"ca_data": 123}, true, "ca_data must be a string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTLSConfig(tt.conf)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- ValidateStringField ---

func TestValidateStringField(t *testing.T) {
	t.Run("missing is valid", func(t *testing.T) {
		err := ValidateStringField(map[string]any{}, "key")
		assert.NoError(t, err)
	})

	t.Run("string is valid", func(t *testing.T) {
		err := ValidateStringField(map[string]any{"key": "value"}, "key")
		assert.NoError(t, err)
	})

	t.Run("empty string is valid", func(t *testing.T) {
		err := ValidateStringField(map[string]any{"key": ""}, "key")
		assert.NoError(t, err)
	})

	t.Run("int is invalid", func(t *testing.T) {
		err := ValidateStringField(map[string]any{"key": 123}, "key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key must be a string")
	})

	t.Run("bool is invalid", func(t *testing.T) {
		err := ValidateStringField(map[string]any{"key": true}, "key")
		require.Error(t, err)
	})
}

// --- ValidateCommonConfig ---

func TestValidateCommonConfig(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		err := ValidateCommonConfig(map[string]any{})
		assert.NoError(t, err)
	})

	t.Run("all valid fields", func(t *testing.T) {
		err := ValidateCommonConfig(map[string]any{
			"max_body_size":  1024,
			"timeout":        "30s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		})
		assert.NoError(t, err)
	})

	t.Run("invalid max_body_size propagates", func(t *testing.T) {
		err := ValidateCommonConfig(map[string]any{"max_body_size": true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "max_body_size")
	})

	t.Run("invalid timeout propagates", func(t *testing.T) {
		err := ValidateCommonConfig(map[string]any{"timeout": "invalid"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout")
	})

	t.Run("non-string auto_auth_path", func(t *testing.T) {
		err := ValidateCommonConfig(map[string]any{"auto_auth_path": 123})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auto_auth_path must be a string")
	})

	t.Run("non-string default_role", func(t *testing.T) {
		err := ValidateCommonConfig(map[string]any{"default_role": true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "default_role must be a string")
	})
}
