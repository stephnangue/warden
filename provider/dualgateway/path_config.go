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
	b.mu.RLock()
	tc := b.TransparentConfig
	data := map[string]any{
		b.spec.URLConfigKey: b.providerURL,
		"max_body_size":     b.MaxBodySize,
		"timeout":           b.Timeout.String(),
		"auto_auth_path":    tc.AutoAuthPath,
		"default_role":      tc.DefaultAuthRole,
	}
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
func (b *dualgatewayBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	conf := make(map[string]any)

	if val, ok := d.GetOk(b.spec.URLConfigKey); ok {
		conf[b.spec.URLConfigKey] = val
	}
	if val, ok := d.GetOk("max_body_size"); ok {
		conf["max_body_size"] = val
	}
	if val, ok := d.GetOk("timeout"); ok {
		conf["timeout"] = val
	}

	// Read extra config fields before validation
	for _, k := range b.spec.ExtraConfigKeys {
		if val, ok := d.GetOk(k); ok {
			conf[k] = val
		}
	}

	if err := validateConfig(b.spec, conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	parsed := parseConfig(b.spec, conf)

	// Read current transparent config under read lock
	b.mu.RLock()
	tc := &framework.TransparentConfig{
		AutoAuthPath:    b.TransparentConfig.AutoAuthPath,
		DefaultAuthRole: b.TransparentConfig.DefaultAuthRole,
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

	// All validation passed — apply changes under write lock
	b.mu.Lock()
	b.providerURL = parsed.ProviderURL
	b.MaxBodySize = parsed.MaxBodySize
	b.Timeout = parsed.Timeout
	if b.spec.OnConfigParsed != nil {
		b.extraState = b.spec.OnConfigParsed(conf)
	}
	b.mu.Unlock()

	b.StreamingBackend.SetTransparentConfig(tc)

	// Persist config to storage
	if b.StorageView != nil {
		b.mu.RLock()
		persistData := map[string]any{
			b.spec.URLConfigKey: b.providerURL,
			"max_body_size":     b.MaxBodySize,
			"timeout":           b.Timeout.String(),
			"auto_auth_path":    tc.AutoAuthPath,
			"default_role":      tc.DefaultAuthRole,
		}
		for k, v := range b.extraState {
			persistData[k] = v
		}
		b.mu.RUnlock()

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
