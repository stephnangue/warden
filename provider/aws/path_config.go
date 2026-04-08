package aws

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the AWS provider
func (b *awsBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"proxy_domains": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of domains that should be proxied through the gateway",
			},
			"max_body_size": {
				Type:        framework.TypeInt,
				Description: "Maximum request body size in bytes (default: 10MB, max: 100MB)",
				Default:     framework.DefaultMaxBodySize,
			},
			"timeout": {
				Type:        framework.TypeDurationSecond,
				Description: "Request timeout duration (e.g., '30s', '5m')",
				Default:     "30s",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS certificate verification (not recommended for production)",
				Default:     false,
			},
			"ca_data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded PEM CA certificate for custom/self-signed CAs",
			},
			"auto_auth_path": {
				Type:        framework.TypeString,
				Description: "Path to auth mount for implicit authentication (e.g., 'auth/jwt/', 'auth/cert/')",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default auth role when not specified in access_key_id",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read AWS provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure AWS provider settings",
			},
		},
		HelpSynopsis:    "Configure AWS provider",
		HelpDescription: "This endpoint configures the AWS provider settings including proxy domains, body size limits, and timeouts.",
	}
}

// handleConfigRead handles reading the AWS provider configuration
func (b *awsBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"proxy_domains":   b.proxyDomains,
			"max_body_size":   b.MaxBodySize,
			"timeout":         b.Timeout.String(),
			"tls_skip_verify": b.tlsSkipVerify,
			"ca_data":         b.caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
		},
	}, nil
}

// handleConfigWrite handles writing the AWS provider configuration
func (b *awsBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Build config map from field data
	conf := make(map[string]any)

	// Apply values from request
	if val, ok := d.GetOk("proxy_domains"); ok {
		conf["proxy_domains"] = val
	}
	if val, ok := d.GetOk("max_body_size"); ok {
		conf["max_body_size"] = val
	}
	if val, ok := d.GetOk("timeout"); ok {
		conf["timeout"] = val
	}
	if val, ok := d.GetOk("tls_skip_verify"); ok {
		conf["tls_skip_verify"] = val
	}
	if val, ok := d.GetOk("ca_data"); ok {
		conf["ca_data"] = val
	}

	// Validate configuration
	if err := ValidateConfig(conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	// Apply configuration
	parsedConfig := parseConfig(conf)
	b.proxyDomains = parsedConfig.ProxyDomains
	b.MaxBodySize = parsedConfig.MaxBodySize
	b.Timeout = parsedConfig.Timeout

	// Update transport if TLS settings changed
	tlsChanged := b.tlsSkipVerify != parsedConfig.TLSSkipVerify || b.caData != parsedConfig.CAData
	b.tlsSkipVerify = parsedConfig.TLSSkipVerify
	b.caData = parsedConfig.CAData
	if tlsChanged {
		if b.tlsSkipVerify || b.caData != "" {
			transport, err := newTransportWithTLS(b.caData, b.tlsSkipVerify)
			if err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        logical.ErrBadRequest(err.Error()),
				}, nil
			}
			b.Proxy.Transport = transport
		} else {
			initTransport()
			b.Proxy.Transport = sharedTransport
		}
	}

	// Reinitialize processors with new config
	b.initializeProcessors()

	// Transparent mode settings — build config from current values + overrides
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

	// Validate: auto_auth_path is required
	if tc.AutoAuthPath == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required"),
		}, nil
	}

	b.StreamingBackend.SetTransparentConfig(tc)

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"proxy_domains":   b.proxyDomains,
			"max_body_size":   b.MaxBodySize,
			"timeout":         b.Timeout.String(),
			"tls_skip_verify": b.tlsSkipVerify,
			"ca_data":         b.caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
		})
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
