package vault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]any
		expected ProviderConfig
	}{
		{
			name: "all fields",
			config: map[string]any{
				"vault_address":   "https://vault.example.com:8200",
				"max_body_size":   int64(5242880),
				"timeout":         "60s",
				"tls_skip_verify": true,
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   5242880,
				Timeout:       60 * time.Second,
				TLSSkipVerify: true,
			},
		},
		{
			name:   "defaults",
			config: map[string]any{},
			expected: ProviderConfig{
				VaultAddress:  "",
				MaxBodySize:   DefaultMaxBodySize,
				Timeout:       DefaultTimeout,
				TLSSkipVerify: false,
			},
		},
		{
			name: "timeout as integer",
			config: map[string]any{
				"vault_address": "https://vault.example.com:8200",
				"timeout":       45,
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   DefaultMaxBodySize,
				Timeout:       45 * time.Second,
				TLSSkipVerify: false,
			},
		},
		{
			name: "max_body_size as int",
			config: map[string]any{
				"vault_address": "https://vault.example.com:8200",
				"max_body_size": 1000000,
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   1000000,
				Timeout:       DefaultTimeout,
				TLSSkipVerify: false,
			},
		},
		{
			name: "tls_skip_verify as string",
			config: map[string]any{
				"vault_address":   "https://vault.example.com:8200",
				"tls_skip_verify": "true",
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   DefaultMaxBodySize,
				Timeout:       DefaultTimeout,
				TLSSkipVerify: true,
			},
		},
		{
			name: "negative values use defaults",
			config: map[string]any{
				"vault_address": "https://vault.example.com:8200",
				"max_body_size": -1,
				"timeout":       -5,
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   DefaultMaxBodySize,
				Timeout:       DefaultTimeout,
				TLSSkipVerify: false,
			},
		},
		{
			name: "invalid timeout format uses default",
			config: map[string]any{
				"vault_address": "https://vault.example.com:8200",
				"timeout":       "invalid",
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   DefaultMaxBodySize,
				Timeout:       DefaultTimeout,
				TLSSkipVerify: false,
			},
		},
		{
			name: "max_body_size as float64",
			config: map[string]any{
				"vault_address": "https://vault.example.com:8200",
				"max_body_size": float64(10485760),
			},
			expected: ProviderConfig{
				VaultAddress:  "https://vault.example.com:8200",
				MaxBodySize:   10485760,
				Timeout:       DefaultTimeout,
				TLSSkipVerify: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseConfig(tt.config)
			assert.Equal(t, tt.expected.VaultAddress, result.VaultAddress)
			assert.Equal(t, tt.expected.MaxBodySize, result.MaxBodySize)
			assert.Equal(t, tt.expected.Timeout, result.Timeout)
			assert.Equal(t, tt.expected.TLSSkipVerify, result.TLSSkipVerify)
		})
	}
}
