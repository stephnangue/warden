package alicloud

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func (b *alicloudBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
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
			"auto_auth_path": {
				Type:        framework.TypeString,
				Description: "Path to auth mount for implicit authentication (e.g., 'auth/jwt/', 'auth/cert/')",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default auth role when not specified in the request",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS verification when forwarding (insecure)",
			},
			"ca_data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded PEM CA certificate bundle for upstream TLS",
			},
			"proxy_domains": {
				Type:        framework.TypeStringSlice,
				Description: "Reverse-proxy DNS suffixes. Hosts of the form '<real>.aliyuncs.com.<proxy-domain>' are rewritten to '<real>.aliyuncs.com' before forwarding. Direct '*.aliyuncs.com' hosts are always accepted.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read Alicloud provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure Alicloud provider settings",
			},
		},
		HelpSynopsis:    "Configure Alicloud provider",
		HelpDescription: "Configures the Alicloud provider settings (timeouts, body size limits, transparent auth).",
	}
}

func (b *alicloudBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	tc := b.TransparentConfig()
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"max_body_size":   b.MaxBodySize(),
			"timeout":         b.Timeout().String(),
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
			"tls_skip_verify": b.tlsSkipVerify,
			"ca_data":         b.caData,
			"proxy_domains":   b.proxyDomains,
		},
	}, nil
}

// snapshotForMerge returns the running configuration in the shape parseConfig
// takes, as the base a config write overlays. A value never set is left out,
// so parseConfig gives it its default as before.
func (b *alicloudBackend) snapshotForMerge() map[string]any {
	b.mu.RLock()
	conf := map[string]any{
		"tls_skip_verify": b.tlsSkipVerify,
		"ca_data":         b.caData,
	}
	if b.proxyDomains != nil {
		conf["proxy_domains"] = b.proxyDomains
	}
	b.mu.RUnlock()
	if maxBodySize := b.MaxBodySize(); maxBodySize > 0 {
		conf["max_body_size"] = maxBodySize
	}
	if timeout := b.Timeout(); timeout > 0 {
		conf["timeout"] = timeout.String()
	}
	return conf
}

// handleConfigWrite handles writing the Alicloud provider configuration.
//
// A write changes nothing until it has succeeded: every value is validated and
// built — the transport included — into locals, persisted, and only then
// applied, so a rejected write leaves the running configuration exactly as it
// was, and a storage failure leaves it matching storage.
func (b *alicloudBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// A write is a partial update: it starts from what the mount is running
	// and overlays only the keys the request names, so setting one key does
	// not reset the others to their defaults.
	conf := b.snapshotForMerge()
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
	if val, ok := d.GetOk("proxy_domains"); ok {
		conf["proxy_domains"] = val
	}

	if err := ValidateConfig(conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	parsed := parseConfig(conf)

	b.mu.RLock()
	tc := &framework.TransparentConfig{
		AutoAuthPath:    b.TransparentConfig().AutoAuthPath,
		DefaultAuthRole: b.TransparentConfig().DefaultAuthRole,
	}
	b.mu.RUnlock()

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

	// Build the transport the TLS settings call for if they changed (compared
	// against what is running); it is installed only once the whole write has
	// succeeded. Without custom TLS it is the shared one, so clearing TLS stops
	// using the transport built for it.
	b.mu.RLock()
	tlsChanged := b.tlsSkipVerify != parsed.TLSSkipVerify || b.caData != parsed.CAData
	b.mu.RUnlock()
	var transport http.RoundTripper
	if tlsChanged {
		if parsed.TLSSkipVerify || parsed.CAData != "" {
			custom, err := newTransportWithTLS(parsed.CAData, parsed.TLSSkipVerify)
			if err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}, nil
			}
			transport = custom
		} else {
			initTransport()
			transport = sharedTransport
		}
	}

	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":   parsed.MaxBodySize,
			"timeout":         parsed.Timeout.String(),
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
			"tls_skip_verify": parsed.TLSSkipVerify,
			"ca_data":         parsed.CAData,
			"proxy_domains":   parsed.ProxyDomains,
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
	b.mu.Lock()
	b.tlsSkipVerify = parsed.TLSSkipVerify
	b.caData = parsed.CAData
	b.proxyDomains = parsed.ProxyDomains
	b.mu.Unlock()
	b.SetMaxBodySize(parsed.MaxBodySize)
	b.SetTimeout(parsed.Timeout)
	if tlsChanged {
		b.SetTransport(transport)
	}
	b.StreamingBackend.SetTransparentConfig(tc)

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"message": "configuration updated",
		},
	}, nil
}
