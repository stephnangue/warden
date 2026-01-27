package vault

import (
	"context"
	"net/http"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
)

func TestHandleConfigRead(t *testing.T) {
	tests := []struct {
		name          string
		vaultAddress  string
		maxBodySize   int64
		timeout       time.Duration
		tlsSkipVerify bool
	}{
		{
			name:          "default values",
			vaultAddress:  "",
			maxBodySize:   DefaultMaxBodySize,
			timeout:       DefaultTimeout,
			tlsSkipVerify: false,
		},
		{
			name:          "custom values",
			vaultAddress:  "https://vault.example.com:8200",
			maxBodySize:   5242880,
			timeout:       60 * time.Second,
			tlsSkipVerify: true,
		},
		{
			name:          "minimal timeout",
			vaultAddress:  "https://localhost:8200",
			maxBodySize:   1024,
			timeout:       1 * time.Second,
			tlsSkipVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &vaultBackend{
				vaultAddress:  tt.vaultAddress,
				maxBodySize:   tt.maxBodySize,
				timeout:       tt.timeout,
				tlsSkipVerify: tt.tlsSkipVerify,
			}

			resp, err := b.handleConfigRead(context.Background(), nil, nil)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tt.vaultAddress, resp.Data["vault_address"])
			assert.Equal(t, tt.maxBodySize, resp.Data["max_body_size"])
			assert.Equal(t, tt.timeout.String(), resp.Data["timeout"])
			assert.Equal(t, tt.tlsSkipVerify, resp.Data["tls_skip_verify"])
		})
	}
}

func TestHandleConfigWrite(t *testing.T) {
	tests := []struct {
		name                  string
		initialVaultAddress   string
		initialMaxBodySize    int64
		initialTimeout        time.Duration
		initialTLSSkipVerify  bool
		fieldData             map[string]interface{}
		expectedVaultAddress  string
		expectedMaxBodySize   int64
		expectedTimeout       time.Duration
		expectedTLSSkipVerify bool
	}{
		{
			name:                 "update vault_address only",
			initialVaultAddress:  "",
			initialMaxBodySize:   DefaultMaxBodySize,
			initialTimeout:       DefaultTimeout,
			initialTLSSkipVerify: false,
			fieldData: map[string]interface{}{
				"vault_address": "https://vault.example.com:8200",
			},
			expectedVaultAddress:  "https://vault.example.com:8200",
			expectedMaxBodySize:   DefaultMaxBodySize,
			expectedTimeout:       DefaultTimeout,
			expectedTLSSkipVerify: false,
		},
		{
			name:                 "update multiple fields",
			initialVaultAddress:  "https://old.vault.com:8200",
			initialMaxBodySize:   DefaultMaxBodySize,
			initialTimeout:       DefaultTimeout,
			initialTLSSkipVerify: false,
			fieldData: map[string]interface{}{
				"vault_address": "https://new.vault.com:8200",
				"max_body_size": int64(5242880),
				"timeout":       60, // seconds
			},
			expectedVaultAddress:  "https://new.vault.com:8200",
			expectedMaxBodySize:   5242880,
			expectedTimeout:       60 * time.Second,
			expectedTLSSkipVerify: false,
		},
		{
			name:                 "update timeout only",
			initialVaultAddress:  "https://vault.example.com:8200",
			initialMaxBodySize:   DefaultMaxBodySize,
			initialTimeout:       30 * time.Second,
			initialTLSSkipVerify: false,
			fieldData: map[string]interface{}{
				"timeout": 120, // seconds
			},
			expectedVaultAddress:  "https://vault.example.com:8200",
			expectedMaxBodySize:   DefaultMaxBodySize,
			expectedTimeout:       120 * time.Second,
			expectedTLSSkipVerify: false,
		},
		{
			name:                 "update max_body_size only",
			initialVaultAddress:  "https://vault.example.com:8200",
			initialMaxBodySize:   DefaultMaxBodySize,
			initialTimeout:       DefaultTimeout,
			initialTLSSkipVerify: false,
			fieldData: map[string]interface{}{
				"max_body_size": int64(20971520), // 20MB
			},
			expectedVaultAddress:  "https://vault.example.com:8200",
			expectedMaxBodySize:   20971520,
			expectedTimeout:       DefaultTimeout,
			expectedTLSSkipVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &vaultBackend{
				vaultAddress:  tt.initialVaultAddress,
				maxBodySize:   tt.initialMaxBodySize,
				timeout:       tt.initialTimeout,
				tlsSkipVerify: tt.initialTLSSkipVerify,
				// No storage view - config won't be persisted
				StreamingBackend: &framework.StreamingBackend{
					TransparentConfig: &framework.TransparentConfig{},
				},
			}

			// Create field data with schema
			schema := map[string]*framework.FieldSchema{
				"vault_address": {
					Type: framework.TypeString,
				},
				"max_body_size": {
					Type: framework.TypeInt64,
				},
				"timeout": {
					Type: framework.TypeDurationSecond,
				},
				"tls_skip_verify": {
					Type: framework.TypeBool,
				},
			}

			fd := &framework.FieldData{
				Raw:    tt.fieldData,
				Schema: schema,
			}

			resp, err := b.handleConfigWrite(context.Background(), nil, fd)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "configuration updated", resp.Data["message"])

			// Verify backend state was updated
			assert.Equal(t, tt.expectedVaultAddress, b.vaultAddress)
			assert.Equal(t, tt.expectedMaxBodySize, b.maxBodySize)
			assert.Equal(t, tt.expectedTimeout, b.timeout)
			assert.Equal(t, tt.expectedTLSSkipVerify, b.tlsSkipVerify)
		})
	}
}

func TestHandleConfigWrite_TLSChange(t *testing.T) {
	// This test verifies that changing tls_skip_verify updates the transport
	b := &vaultBackend{
		vaultAddress:  "https://vault.example.com:8200",
		maxBodySize:   DefaultMaxBodySize,
		timeout:       DefaultTimeout,
		tlsSkipVerify: false,
		proxy: &httputil.ReverseProxy{
			Director:  func(req *http.Request) {},
			Transport: sharedTransport,
		},
		StreamingBackend: &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{},
		},
	}

	schema := map[string]*framework.FieldSchema{
		"tls_skip_verify": {
			Type: framework.TypeBool,
		},
	}

	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"tls_skip_verify": true,
		},
		Schema: schema,
	}

	resp, err := b.handleConfigWrite(context.Background(), nil, fd)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, b.tlsSkipVerify)
	// Transport should have been updated (different instance)
	assert.NotEqual(t, sharedTransport, b.proxy.Transport)
}

func TestPathConfig_Schema(t *testing.T) {
	b := &vaultBackend{}
	path := b.pathConfig()

	assert.Equal(t, "config", path.Pattern)
	assert.NotNil(t, path.Fields["vault_address"])
	assert.NotNil(t, path.Fields["max_body_size"])
	assert.NotNil(t, path.Fields["timeout"])
	assert.NotNil(t, path.Fields["tls_skip_verify"])

	// Check vault_address is required
	assert.True(t, path.Fields["vault_address"].Required)

	// Check types
	assert.Equal(t, framework.TypeString, path.Fields["vault_address"].Type)
	assert.Equal(t, framework.TypeInt64, path.Fields["max_body_size"].Type)
	assert.Equal(t, framework.TypeDurationSecond, path.Fields["timeout"].Type)
	assert.Equal(t, framework.TypeBool, path.Fields["tls_skip_verify"].Type)

	// Check operations
	assert.NotNil(t, path.Operations[logical.ReadOperation])
	assert.NotNil(t, path.Operations[logical.UpdateOperation])
}

func TestPathConfig_Defaults(t *testing.T) {
	b := &vaultBackend{}
	path := b.pathConfig()

	assert.Equal(t, DefaultMaxBodySize, path.Fields["max_body_size"].Default)
	assert.Equal(t, "30s", path.Fields["timeout"].Default)
	assert.Equal(t, false, path.Fields["tls_skip_verify"].Default)
}
