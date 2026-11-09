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
	tc := b.TransparentConfig()
	proxyDomains, skipVerify, caData := b.settings()
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"proxy_domains":   proxyDomains,
			"max_body_size":   b.MaxBodySize(),
			"timeout":         b.Timeout().String(),
			"tls_skip_verify": skipVerify,
			"ca_data":         caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
		},
	}, nil
}

// snapshotForMerge returns the running configuration in the shape parseConfig
// takes, as the base a config write overlays. A value never set is left out,
// so parseConfig gives it its default as before.
func (b *awsBackend) snapshotForMerge() map[string]any {
	proxyDomains, skipVerify, caData := b.settings()
	conf := map[string]any{
		"tls_skip_verify": skipVerify,
		"ca_data":         caData,
	}
	if proxyDomains != nil {
		conf["proxy_domains"] = proxyDomains
	}
	if maxBodySize := b.MaxBodySize(); maxBodySize > 0 {
		conf["max_body_size"] = maxBodySize
	}
	if timeout := b.Timeout(); timeout > 0 {
		conf["timeout"] = timeout.String()
	}
	return conf
}

// handleConfigWrite handles writing the AWS provider configuration.
//
// A write changes nothing until it has succeeded: every value is validated and
// built — the transport and the processors included — into locals, persisted,
// and only then applied, so a rejected write leaves the running configuration
// exactly as it was, and a storage failure leaves it matching storage.
func (b *awsBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// A write is a partial update: it starts from what the mount is running
	// and overlays only the keys the request names, so setting one key does
	// not reset the others to their defaults.
	conf := b.snapshotForMerge()

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

	parsedConfig := parseConfig(conf)

	// Build the transport now if TLS settings changed (compared against what
	// is running); it is installed only once the whole write has succeeded.
	_, oldSkipVerify, oldCAData := b.settings()
	tlsChanged := oldSkipVerify != parsedConfig.TLSSkipVerify || oldCAData != parsedConfig.CAData
	var transport http.RoundTripper
	if tlsChanged {
		if parsedConfig.TLSSkipVerify || parsedConfig.CAData != "" {
			custom, err := newTransportWithTLS(parsedConfig.CAData, parsedConfig.TLSSkipVerify)
			if err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        logical.ErrBadRequest(err.Error()),
				}, nil
			}
			transport = custom
		} else {
			initTransport()
			transport = sharedTransport
		}
	}

	// Transparent mode settings — build config from current values + overrides
	current := b.TransparentConfig()
	tc := &framework.TransparentConfig{
		AutoAuthPath:    current.AutoAuthPath,
		DefaultAuthRole: current.DefaultAuthRole,
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

	// The processors for the new domains, installed with the rest below.
	registry := newProcessorRegistry(parsedConfig.ProxyDomains, b.Logger)

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"proxy_domains":   parsedConfig.ProxyDomains,
			"max_body_size":   parsedConfig.MaxBodySize,
			"timeout":         parsedConfig.Timeout.String(),
			"tls_skip_verify": parsedConfig.TLSSkipVerify,
			"ca_data":         parsedConfig.CAData,
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

	// Apply. Nothing below can fail.
	b.setSettings(parsedConfig.ProxyDomains, parsedConfig.TLSSkipVerify, parsedConfig.CAData)
	b.SetMaxBodySize(parsedConfig.MaxBodySize)
	b.SetTimeout(parsedConfig.Timeout)
	if tlsChanged {
		b.SetTransport(transport)
	}
	b.processorRegistry.Store(registry)
	b.StreamingBackend.SetTransparentConfig(tc)

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"message": "configuration updated",
		},
	}, nil
}
