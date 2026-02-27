package mistral

import (
	"context"
	"net/http"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the Mistral provider
func (b *mistralBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"mistral_url": {
				Type:        framework.TypeString,
				Description: "The Mistral API base URL (default: https://api.mistral.ai)",
				Default:     DefaultMistralURL,
			},
			"max_body_size": {
				Type:        framework.TypeInt64,
				Description: "Maximum request body size in bytes (default: 10MB, max: 100MB)",
				Default:     framework.DefaultMaxBodySize,
			},
			"timeout": {
				Type:        framework.TypeDurationSecond,
				Description: "Request timeout duration (e.g., '120s', '5m')",
				Default:     "120s",
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
				Summary:  "Read Mistral provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure Mistral provider settings",
			},
		},
		HelpSynopsis:    "Configure Mistral provider",
		HelpDescription: "This endpoint configures the Mistral provider settings including API URL, body size limits, and timeouts.",
	}
}

// handleConfigRead handles reading the Mistral provider configuration
func (b *mistralBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"mistral_url":      b.mistralURL,
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"transparent_mode": tc.Enabled,
			"auto_auth_path":   tc.AutoAuthPath,
			"default_role":     tc.DefaultRole,
		},
	}, nil
}

// handleConfigWrite handles writing the Mistral provider configuration
func (b *mistralBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if val, ok := d.GetOk("mistral_url"); ok {
		addr := val.(string)
		if addr != "" {
			addr = strings.TrimRight(addr, "/")
			if err := validateMistralAddress(addr); err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        logical.ErrBadRequest(err.Error()),
				}, nil
			}
			b.mistralURL = addr
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
		b.Timeout = DefaultMistralTimeout
	}

	// Transparent mode settings
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
			"mistral_url":      b.mistralURL,
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
