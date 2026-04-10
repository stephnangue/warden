package scaleway

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the Scaleway provider
func (b *scalewayBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"scaleway_url": {
				Type:        framework.TypeString,
				Description: "Scaleway API base URL (default: https://api.scaleway.com)",
				Default:     DefaultScalewayURL,
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
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read Scaleway provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure Scaleway provider settings",
			},
		},
		HelpSynopsis:    "Configure Scaleway provider",
		HelpDescription: "This endpoint configures the Scaleway provider settings including API URL, body size limits, and timeouts.",
	}
}

// handleConfigRead handles reading the Scaleway provider configuration
func (b *scalewayBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"scaleway_url":   b.scalewayURL,
			"max_body_size":  b.MaxBodySize,
			"timeout":        b.Timeout.String(),
			"auto_auth_path": tc.AutoAuthPath,
			"default_role":   tc.DefaultAuthRole,
		},
	}, nil
}

// handleConfigWrite handles writing the Scaleway provider configuration
func (b *scalewayBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	conf := make(map[string]any)

	if val, ok := d.GetOk("scaleway_url"); ok {
		conf["scaleway_url"] = val
	}
	if val, ok := d.GetOk("max_body_size"); ok {
		conf["max_body_size"] = val
	}
	if val, ok := d.GetOk("timeout"); ok {
		conf["timeout"] = val
	}

	if err := ValidateConfig(conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	parsedConfig := parseConfig(conf)
	b.scalewayURL = parsedConfig.ScalewayURL
	b.MaxBodySize = parsedConfig.MaxBodySize
	b.Timeout = parsedConfig.Timeout

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

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"scaleway_url":   b.scalewayURL,
			"max_body_size":  b.MaxBodySize,
			"timeout":        b.Timeout.String(),
			"auto_auth_path": tc.AutoAuthPath,
			"default_role":   tc.DefaultAuthRole,
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
