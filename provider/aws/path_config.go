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
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"proxy_domains": b.proxyDomains,
			"max_body_size": b.MaxBodySize,
			"timeout":       b.Timeout.String(),
		},
	}, nil
}

// handleConfigWrite handles writing the AWS provider configuration
func (b *awsBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Build config map from field data
	conf := make(map[string]any)

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

	// Validate configuration
	if err := ValidateConfig(conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	// Apply configuration
	parsedConfig := parseConfig(conf)
	b.proxyDomains = parsedConfig.ProxyDomains
	b.MaxBodySize = parsedConfig.MaxBodySize
	b.Timeout = parsedConfig.Timeout

	// Reinitialize processors with new config
	b.initializeProcessors()

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"proxy_domains": b.proxyDomains,
			"max_body_size": b.MaxBodySize,
			"timeout":       b.Timeout.String(),
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
