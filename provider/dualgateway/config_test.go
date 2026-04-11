package dualgateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		spec    *ProviderSpec
		config  map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config with spec URL key",
			spec:    headerAuthSpec,
			config:  map[string]any{"test_url": "https://api.test.com", "timeout": "30s"},
			wantErr: false,
		},
		{
			name:    "valid config with different spec URL key",
			spec:    bearerAuthSpec,
			config:  map[string]any{"bearer_url": "https://api.bearer.com/1.0"},
			wantErr: false,
		},
		{
			name:    "unknown key rejected",
			spec:    headerAuthSpec,
			config:  map[string]any{"unknown": "value"},
			wantErr: true,
			errMsg:  "unknown configuration key",
		},
		{
			name:    "wrong spec URL key rejected",
			spec:    headerAuthSpec,
			config:  map[string]any{"bearer_url": "https://x.com"},
			wantErr: true,
			errMsg:  "unknown configuration key",
		},
		{
			name:    "max_body_size too large",
			spec:    headerAuthSpec,
			config:  map[string]any{"max_body_size": int64(200000000)},
			wantErr: true,
			errMsg:  "must not exceed",
		},
		{
			name:    "invalid timeout format",
			spec:    headerAuthSpec,
			config:  map[string]any{"timeout": "invalid"},
			wantErr: true,
			errMsg:  "invalid timeout format",
		},
		{
			name:    "empty config is valid",
			spec:    headerAuthSpec,
			config:  map[string]any{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.spec, tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	cfg := parseConfig(headerAuthSpec, map[string]any{})
	assert.Equal(t, "https://api.test.com", cfg.ProviderURL)
	assert.Equal(t, headerAuthSpec.DefaultTimeout, cfg.Timeout)
}

func TestParseConfig_CustomValues(t *testing.T) {
	cfg := parseConfig(headerAuthSpec, map[string]any{
		"test_url":      "https://custom.test.com",
		"max_body_size": int64(5242880),
		"timeout":       "60s",
	})
	assert.Equal(t, "https://custom.test.com", cfg.ProviderURL)
	assert.Equal(t, int64(5242880), cfg.MaxBodySize)
}

func TestValidateConfig_ExtraConfigKeys(t *testing.T) {
	spec := &ProviderSpec{
		Name: "extra", HelpText: "h", CredentialType: "c",
		DefaultURL: "https://x.com", URLConfigKey: "extra_url",
		DefaultTimeout:  30e9, UserAgent: "u",
		APIAuth:         APIAuthStrategy{HeaderName: "X", HeaderValueFormat: "%s", CredentialField: "k"},
		S3Endpoint:      func(_ map[string]any, r string) string { return r },
		ExtraConfigKeys: []string{"account_id", "zone"},
	}

	t.Run("extra keys accepted", func(t *testing.T) {
		err := validateConfig(spec, map[string]any{
			"account_id": "abc123",
			"zone":       "us-east-1",
		})
		assert.NoError(t, err)
	})

	t.Run("unknown key still rejected", func(t *testing.T) {
		err := validateConfig(spec, map[string]any{"bogus": "val"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown configuration key")
	})
}
