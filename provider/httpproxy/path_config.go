package httpproxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the provider.
func (b *proxyBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
		b.spec.URLConfigKey: {
			Type:        framework.TypeString,
			Description: "The upstream API base URL (default: " + b.spec.DefaultURL + ")",
			Default:     b.spec.DefaultURL,
		},
		"max_body_size": {
			Type:        framework.TypeInt64,
			Description: "Maximum request body size in bytes (default: 10MB, max: 100MB)",
			Default:     framework.DefaultMaxBodySize,
		},
		"timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "Request timeout duration (e.g., '120s', '5m')",
			Default:     b.spec.DefaultTimeout.String(),
		},
		"auto_auth_path": {
			Type:        framework.TypeString,
			Description: "Path to auth mount for implicit authentication (e.g., 'auth/jwt/', 'auth/cert/')",
		},
		"default_role": {
			Type:        framework.TypeString,
			Description: "Default role to use when not specified in URL path",
		},
		"tls_skip_verify": {
			Type:        framework.TypeBool,
			Description: "Skip TLS certificate verification (for dev/test clusters)",
			Default:     false,
		},
		"ca_data": {
			Type:        framework.TypeString,
			Description: "Base64-encoded PEM CA certificate for custom certificate authorities",
		},
	}

	// Merge extra config fields from spec
	for k, v := range b.spec.ExtraConfigFields {
		fields[k] = v
	}

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read " + b.spec.Name + " provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure " + b.spec.Name + " provider settings",
			},
		},
		HelpSynopsis:    "Configure " + b.spec.Name + " provider",
		HelpDescription: "This endpoint configures the " + b.spec.Name + " provider settings including API URL, body size limits, and timeouts.",
	}
}

// handleConfigRead handles reading the provider configuration.
func (b *proxyBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig
	data := map[string]any{
		b.spec.URLConfigKey: b.providerURL,
		"max_body_size":     b.MaxBodySize,
		"timeout":           b.Timeout.String(),
		"auto_auth_path":    tc.AutoAuthPath,
		"default_role":      tc.DefaultAuthRole,
		"tls_skip_verify":   b.tlsSkipVerify,
		"ca_data":           b.caData,
	}

	// Add extra fields from provider state
	if b.spec.OnConfigRead != nil {
		b.mu.RLock()
		extra := b.spec.OnConfigRead(b.extraState)
		b.mu.RUnlock()
		for k, v := range extra {
			data[k] = v
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       data,
	}, nil
}

// handleConfigWrite handles writing the provider configuration.
func (b *proxyBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Read tls_skip_verify before URL validation so HTTP can be conditionally allowed
	skipVerify := b.tlsSkipVerify
	if val, ok := d.GetOk("tls_skip_verify"); ok {
		skipVerify = val.(bool)
	}

	if val, ok := d.GetOk(b.spec.URLConfigKey); ok {
		addr := val.(string)
		if addr != "" {
			addr = strings.TrimRight(addr, "/")
			if err := ValidateURL(addr, b.spec.URLConfigKey, skipVerify); err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        logical.ErrBadRequest(err.Error()),
				}, nil
			}
			b.providerURL = addr
		}
	}

	if val, ok := d.GetOk("max_body_size"); ok {
		b.MaxBodySize = val.(int64)
	} else if b.MaxBodySize == 0 {
		b.MaxBodySize = framework.DefaultMaxBodySize
	}

	if val, ok := d.GetOk("timeout"); ok {
		b.Timeout = time.Duration(val.(int)) * time.Second
	} else if b.Timeout == 0 {
		b.Timeout = b.spec.DefaultTimeout
	}

	// Transparent mode settings
	tc := &framework.TransparentConfig{
		AutoAuthPath:    b.TransparentConfig.AutoAuthPath,
		DefaultAuthRole: b.TransparentConfig.DefaultAuthRole,
	}
	if val, ok := d.GetOk("auto_auth_path"); ok {
		tc.AutoAuthPath = val.(string)
	}
	if val, ok := d.GetOk("default_role"); ok {
		tc.DefaultAuthRole = val.(string)
	}

	if tc.AutoAuthPath == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required"),
		}, nil
	}

	b.StreamingBackend.SetTransparentConfig(tc)

	// Process TLS settings
	tlsChanged := false
	if val, ok := d.GetOk("tls_skip_verify"); ok {
		newSkip := val.(bool)
		if newSkip != b.tlsSkipVerify {
			b.tlsSkipVerify = newSkip
			tlsChanged = true
		}
	}
	if val, ok := d.GetOk("ca_data"); ok {
		newCA := val.(string)
		if newCA != b.caData {
			b.caData = newCA
			tlsChanged = true
		}
	}
	if tlsChanged {
		transport, err := NewTransportWithTLS(b.caData, b.tlsSkipVerify)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest(err.Error()),
			}, nil
		}
		b.Proxy.Transport = transport
	}

	// Process extra config fields
	if b.spec.OnConfigWrite != nil {
		b.mu.Lock()
		newState, err := b.spec.OnConfigWrite(d, b.extraState)
		if err != nil {
			b.mu.Unlock()
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest(err.Error()),
			}, nil
		}
		b.extraState = newState
		b.mu.Unlock()
	}

	// Persist config to storage
	if b.StorageView != nil {
		configData := map[string]any{
			b.spec.URLConfigKey: b.providerURL,
			"max_body_size":     b.MaxBodySize,
			"timeout":           b.Timeout.String(),
			"auto_auth_path":    tc.AutoAuthPath,
			"default_role":      tc.DefaultAuthRole,
			"tls_skip_verify":   b.tlsSkipVerify,
			"ca_data":           b.caData,
		}

		// Add extra state to persisted config
		if b.spec.OnConfigRead != nil {
			b.mu.RLock()
			for k, v := range b.spec.OnConfigRead(b.extraState) {
				configData[k] = v
			}
			b.mu.RUnlock()
		}

		entry, err := sdklogical.StorageEntryJSON("config", configData)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
		if err := b.StorageView.Put(ctx, entry); err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"message": "configuration updated",
		},
	}, nil
}
