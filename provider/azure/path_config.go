package azure

import (
	"context"
	"net/http"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the Azure provider
func (b *azureBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"max_body_size": {
				Type:        framework.TypeInt64,
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
				Description: "Default role to use when not specified in URL path",
			},
			"user_auth_path": {
				Type:        framework.TypeString,
				Description: "Auth mount that authenticates the secondary (user) principal, marking this mount a protected resource (bearer/JWT format required)",
			},
			framework.HostAllowlistKey: {
				Type:        framework.TypeCommaStringSlice,
				Description: "Hosts the gateway forwards to, each with a leading dot: '.example.com' allows example.com and every host under it (default: the public cloud's Resource Manager, Graph, Key Vault, Storage, OpenAI, AI services and AI Foundry endpoints; an empty list restores the default)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read Azure provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure Azure provider settings",
			},
		},
		HelpSynopsis:    "Configure Azure provider",
		HelpDescription: "This endpoint configures the Azure provider settings including body size limits, timeouts, and authentication.",
	}
}

// handleConfigRead handles reading the Azure provider configuration
func (b *azureBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig()
	skipVerify, caData := b.tlsSettings()
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"max_body_size":   b.MaxBodySize(),
			"timeout":         b.Timeout().String(),
			"tls_skip_verify": skipVerify,
			"ca_data":         caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
			"user_auth_path":  tc.UserAuthPath,

			framework.HostAllowlistKey: b.hostAllowlist(),
		},
	}, nil
}

// handleConfigWrite handles writing the Azure provider configuration.
//
// A write changes nothing until it has succeeded: every value is validated and
// built — the transport included — into locals, persisted, and only then
// applied, so a rejected write leaves the running configuration exactly as it
// was, and a storage failure leaves it matching storage.
func (b *azureBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// For max_body_size: use provided value, or apply default if not yet set
	maxBodySize := b.MaxBodySize()
	if val, ok := d.GetOk("max_body_size"); ok {
		maxBodySize = val.(int64)
	} else if maxBodySize == 0 {
		maxBodySize = framework.DefaultMaxBodySize
	}

	// For timeout: use provided value, or apply default if not yet set. It is
	// the only bound on how long an upstream may take, so zero is refused.
	timeout := b.Timeout()
	if val, ok := d.GetOk("timeout"); ok {
		// TypeDurationSecond returns int (seconds)
		timeout = time.Duration(val.(int)) * time.Second
		if timeout <= 0 {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest("timeout must be at least 1s"),
			}, nil
		}
	} else if timeout == 0 {
		timeout = framework.DefaultTimeout
	}

	// Handle TLS settings, compared against what is running
	skipVerify, caData := b.tlsSettings()
	oldSkipVerify, oldCAData := skipVerify, caData
	if val, ok := d.GetOk("tls_skip_verify"); ok {
		skipVerify = val.(bool)
	}
	if val, ok := d.GetOk("ca_data"); ok {
		caData = val.(string)
	}

	// Build the transport now if TLS settings changed; it is installed only
	// once the whole write has succeeded.
	tlsChanged := skipVerify != oldSkipVerify || caData != oldCAData
	var transport http.RoundTripper
	if tlsChanged {
		if skipVerify || caData != "" {
			custom, err := newTransportWithTLS(caData, skipVerify)
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

	// Transparent mode settings — build new config from current values + overrides
	current := b.TransparentConfig()
	tc := &framework.TransparentConfig{
		AutoAuthPath:    current.AutoAuthPath,
		DefaultAuthRole: current.DefaultAuthRole,
		UserAuthPath:    current.UserAuthPath,
	}
	if val, ok := d.GetOk("auto_auth_path"); ok {
		tc.AutoAuthPath = val.(string)
	}
	if val, ok := d.GetOk("default_role"); ok {
		tc.DefaultAuthRole = val.(string)
	}
	if val, ok := d.GetOk("user_auth_path"); ok {
		tc.UserAuthPath = val.(string)
	}

	// Validate: auto_auth_path required
	if tc.AutoAuthPath == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required"),
		}, nil
	}

	// Refuse the removed user_auth_role. The bearer-format check on the user
	// auth mount is enforced at runtime (fail closed). The write stores no
	// user_auth_role, so it also removes one a stored config still names.
	if err := framework.RefuseUserAuthRole(d.Raw); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest(err.Error()),
		}, nil
	}

	allowedHosts := b.configuredHostAllowlist()
	if val, ok := d.GetOk(framework.HostAllowlistKey); ok {
		parsed, err := framework.ParseHostAllowlist(val)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest(err.Error()),
			}, nil
		}
		allowedHosts = parsed
	}

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":   maxBodySize,
			"timeout":         timeout.String(),
			"tls_skip_verify": skipVerify,
			"ca_data":         caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
			"user_auth_path":  tc.UserAuthPath,

			framework.HostAllowlistKey: allowedHosts,
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
	b.SetMaxBodySize(maxBodySize)
	b.SetTimeout(timeout)
	b.setTLSSettings(skipVerify, caData)
	b.setHostAllowlist(allowedHosts)
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
