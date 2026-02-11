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
			"allowed_hosts": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of allowed Azure hosts/domains to proxy requests to. Supports wildcards (e.g., '.vault.azure.net'). If not set, defaults to standard Azure endpoints.",
			},
			"max_body_size": {
				Type:        framework.TypeInt64,
				Description: "Maximum request body size in bytes (default: 10MB, max: 100MB)",
				Default:     DefaultMaxBodySize,
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
		HelpDescription: "This endpoint configures the Azure provider settings including allowed hosts, body size limits, timeouts, and transparent mode.",
	}
}

// handleConfigRead handles reading the Azure provider configuration
func (b *azureBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"allowed_hosts":    b.allowedHosts,
			"max_body_size":    b.maxBodySize,
			"timeout":          b.timeout.String(),
			"transparent_mode": b.transparentMode,
			"auto_auth_path":   b.autoAuthPath,
			"default_role":     b.defaultRole,
		},
	}, nil
}

// handleConfigWrite handles writing the Azure provider configuration
func (b *azureBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Apply values from request - framework already handles type conversion
	if val, ok := d.GetOk("allowed_hosts"); ok {
		b.allowedHosts = val.([]string)
	} else if len(b.allowedHosts) == 0 {
		b.allowedHosts = DefaultAllowedHosts
	}

	// For max_body_size: use provided value, or apply default if not yet set
	if val, ok := d.GetOk("max_body_size"); ok {
		b.maxBodySize = val.(int64)
	} else if b.maxBodySize == 0 {
		b.maxBodySize = DefaultMaxBodySize
	}

	// For timeout: use provided value, or apply default if not yet set
	if val, ok := d.GetOk("timeout"); ok {
		// TypeDurationSecond returns int (seconds)
		b.timeout = time.Duration(val.(int)) * time.Second
	} else if b.timeout == 0 {
		b.timeout = DefaultTimeout
	}

	// Transparent mode settings
	if val, ok := d.GetOk("transparent_mode"); ok {
		b.transparentMode = val.(bool)
	}

	if val, ok := d.GetOk("auto_auth_path"); ok {
		b.autoAuthPath = val.(string)
	}

	if val, ok := d.GetOk("default_role"); ok {
		b.defaultRole = val.(string)
	}

	// Validate: if transparent_mode enabled, auto_auth_path required
	if b.transparentMode && b.autoAuthPath == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required when transparent_mode is enabled"),
		}, nil
	}

	// Sync transparent config with framework
	b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
		Enabled:      b.transparentMode,
		AutoAuthPath: b.autoAuthPath,
		DefaultRole:  b.defaultRole,
	})

	// Persist config to storage
	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"allowed_hosts":    b.allowedHosts,
			"max_body_size":    b.maxBodySize,
			"timeout":          b.timeout.String(),
			"transparent_mode": b.transparentMode,
			"auto_auth_path":   b.autoAuthPath,
			"default_role":     b.defaultRole,
		})
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
		if err := b.storageView.Put(ctx, entry); err != nil {
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
