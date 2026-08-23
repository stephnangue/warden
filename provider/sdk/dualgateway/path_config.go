package dualgateway

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition parameterized by the spec.
func (b *dualgatewayBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
		b.spec.URLConfigKey: {
			Type:        framework.TypeString,
			Description: b.spec.Name + " API base URL (default: " + b.spec.DefaultURL + ")",
			Default:     b.spec.DefaultURL,
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
			Description: "Skip TLS certificate verification (dev/test only).",
			Default:     false,
		},
		"ca_data": {
			Type:        framework.TypeString,
			Description: "Base64-encoded PEM CA certificate, for an upstream signed by a private authority.",
		},
	}

	// Add provider-specific extra fields
	if b.spec.ExtraConfigFields != nil {
		for k, v := range b.spec.ExtraConfigFields {
			fields[k] = v
		}
	} else {
		// Default: treat extra keys as TypeString
		for _, k := range b.spec.ExtraConfigKeys {
			fields[k] = &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: k,
			}
		}
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
func (b *dualgatewayBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig()
	b.mu.RLock()
	data := map[string]any{
		b.spec.URLConfigKey: b.providerURL,
		"max_body_size":     b.MaxBodySize(),
		"timeout":           b.Timeout().String(),
		"auto_auth_path":    tc.AutoAuthPath,
		"default_role":      tc.DefaultAuthRole,
		"tls_skip_verify":   b.tlsSkipVerify,
		"ca_data":           b.caData,
	}
	// Extra keys are reported as resolved, which is what the mount is actually
	// using. A partial write merges against extraRaw instead, so this staying
	// the resolved view costs nothing.
	for k, v := range b.extraState {
		data[k] = v
	}
	b.mu.RUnlock()

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       data,
	}, nil
}

// handleConfigWrite handles writing the provider configuration.
//
// The write is a partial update: it starts from what the mount is currently
// using and overlays only the keys the request actually named. Building the
// config from the request alone would resolve every unnamed key to its default,
// so setting a default role on a working mount would repoint it at the vendor's
// public endpoint and report success.
func (b *dualgatewayBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// A partial update is a read-modify-write, so two of them racing would lose
	// one writer's keys against the other's snapshot, and could leave live state
	// mixing both while storage records only one. Serialising the handler makes
	// each write see the previous one whole. It is not on any request path.
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	conf := b.snapshotForMerge()

	keys := []string{
		b.spec.URLConfigKey, "max_body_size", "timeout",
		"auto_auth_path", "default_role", "tls_skip_verify", "ca_data",
	}
	keys = append(keys, b.extraConfigKeys()...)
	for _, k := range keys {
		if val, ok := d.GetOk(k); ok {
			conf[k] = val
		}
	}

	// A mount serving only the non-transparent leg has no auto_auth_path and
	// must stay configurable, so absence is not the failure — clearing one that
	// was set is, since that silently takes transparent auth away from a mount
	// serving it. GetOk reports a present-but-empty value as set, which is what
	// separates the two.
	if val, ok := d.GetOk("auto_auth_path"); ok {
		if s, _ := val.(string); s == "" && b.TransparentConfig().AutoAuthPath != "" {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest("auto_auth_path cannot be cleared while transparent auth is configured"),
			}, nil
		}
	}

	if err := validateConfig(b.spec, conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest(err.Error()),
		}, nil
	}

	persistData, err := b.applyParsedConfig(conf)
	if err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest(err.Error()),
		}, nil
	}

	// Persist what this write resolved to, computed from the merged config
	// alone — not read back off the backend, where a concurrent writer could
	// tear it.
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", persistData)
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
