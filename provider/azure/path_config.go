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
			"transparent_mode": {
				Type:        framework.TypeBool,
				Description: "Enable transparent mode for implicit JWT authentication",
				Default:     false,
			},
			"auto_auth_path": {
				Type:        framework.TypeString,
				Description: "Path to JWT auth mount for transparent mode (e.g., 'auth/jwt/')",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default role to use when not specified in URL path",
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
		HelpDescription: "This endpoint configures the Azure provider settings including body size limits, timeouts, and transparent mode.",
	}
}

// handleConfigRead handles reading the Azure provider configuration
func (b *azureBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"transparent_mode": tc.Enabled,
			"auto_auth_path":   tc.AutoAuthPath,
			"default_role":     tc.DefaultRole,
		},
	}, nil
}

// handleConfigWrite handles writing the Azure provider configuration
func (b *azureBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// For max_body_size: use provided value, or apply default if not yet set
	if val, ok := d.GetOk("max_body_size"); ok {
		b.MaxBodySize = val.(int64)
	} else if b.MaxBodySize == 0 {
		b.MaxBodySize = framework.DefaultMaxBodySize
	}

	// For timeout: use provided value, or apply default if not yet set
	if val, ok := d.GetOk("timeout"); ok {
		// TypeDurationSecond returns int (seconds)
		b.Timeout = time.Duration(val.(int)) * time.Second
	} else if b.Timeout == 0 {
		b.Timeout = framework.DefaultTimeout
	}

	// Transparent mode settings — build new config from current values + overrides
	tc := &framework.TransparentConfig{
		Enabled:      b.TransparentConfig.Enabled,
		AutoAuthPath: b.TransparentConfig.AutoAuthPath,
		DefaultRole:  b.TransparentConfig.DefaultRole,
	}
	if val, ok := d.GetOk("transparent_mode"); ok {
		tc.Enabled = val.(bool)
	}
	if val, ok := d.GetOk("auto_auth_path"); ok {
		tc.AutoAuthPath = val.(string)
	}
	if val, ok := d.GetOk("default_role"); ok {
		tc.DefaultRole = val.(string)
	}

	// Validate: if transparent_mode enabled, auto_auth_path required
	if tc.Enabled && tc.AutoAuthPath == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required when transparent_mode is enabled"),
		}, nil
	}

	b.StreamingBackend.SetTransparentConfig(tc)

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"transparent_mode": tc.Enabled,
			"auto_auth_path":   tc.AutoAuthPath,
			"default_role":     tc.DefaultRole,
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
