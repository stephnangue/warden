package github

import (
	"context"
	"net/http"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the GitHub provider
func (b *githubBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"github_url": {
				Type:        framework.TypeString,
				Description: "The GitHub API base URL (default: https://api.github.com, for GHE: https://github.example.com/api/v3)",
				Default:     DefaultGitHubURL,
			},
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
			"api_version": {
				Type:        framework.TypeString,
				Description: "GitHub REST API version for X-GitHub-Api-Version header (default: 2022-11-28)",
				Default:     DefaultAPIVersion,
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
				Summary:  "Read GitHub provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure GitHub provider settings",
			},
		},
		HelpSynopsis:    "Configure GitHub provider",
		HelpDescription: "This endpoint configures the GitHub provider settings including API URL, body size limits, timeouts, and API version.",
	}
}

// handleConfigRead handles reading the GitHub provider configuration
func (b *githubBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"github_url":       b.githubURL,
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"api_version":      b.apiVersion,
			"transparent_mode": tc.Enabled,
			"auto_auth_path":   tc.AutoAuthPath,
			"default_role":     tc.DefaultRole,
		},
	}, nil
}

// handleConfigWrite handles writing the GitHub provider configuration
func (b *githubBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if val, ok := d.GetOk("github_url"); ok {
		addr := val.(string)
		if addr != "" {
			addr = strings.TrimRight(addr, "/")
			if err := validateGitHubAddress(addr); err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        logical.ErrBadRequest(err.Error()),
				}, nil
			}
			b.githubURL = addr
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
		b.Timeout = framework.DefaultTimeout
	}

	if val, ok := d.GetOk("api_version"); ok {
		ver := val.(string)
		if ver != "" {
			b.apiVersion = ver
		}
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
			"github_url":       b.githubURL,
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"api_version":      b.apiVersion,
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
