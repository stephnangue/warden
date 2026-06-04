package mcp_aws

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

func (b *mcpAWSBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"mcp_aws_url": {
				Type:        framework.TypeString,
				Description: "MCP endpoint base URL (default: " + DefaultMCPAWSURL + ")",
				Default:     DefaultMCPAWSURL,
			},
			"region": {
				Type:        framework.TypeString,
				Description: "SigV4 signing region. Optional when the URL host yields one via DNS-label inference; required otherwise (e.g. GovCloud, China partition, custom test hosts).",
			},
			"max_body_size": {
				Type:        framework.TypeInt64,
				Description: "Maximum request body size in bytes (default: 10MB, max: 100MB)",
				Default:     framework.DefaultMaxBodySize,
			},
			"timeout": {
				Type:        framework.TypeDurationSecond,
				Description: "Session timeout duration (default: 10m)",
				Default:     DefaultMCPAWSTimeout.String(),
			},
			"auto_auth_path": {
				Type:        framework.TypeString,
				Description: "Path to auth mount for implicit authentication (e.g., 'auth/jwt/'). Required.",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Fallback role when not specified by header or URL path.",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS certificate verification (dev/test only).",
				Default:     false,
			},
			"ca_data": {
				Type:        framework.TypeString,
				Description: "Base64-encoded PEM CA certificate for custom certificate authorities.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read mcp_aws provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure mcp_aws provider settings",
			},
		},
		HelpSynopsis:    "Configure mcp_aws provider",
		HelpDescription: "Configures the mcp_aws provider settings including upstream URL, signing region, timeouts, and implicit auth path.",
	}
}

func (b *mcpAWSBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	tc := b.TransparentConfig
	data := map[string]any{
		"region":          b.region,
		"max_body_size":   b.MaxBodySize,
		"timeout":         b.Timeout.String(),
		"auto_auth_path":  tc.AutoAuthPath,
		"default_role":    tc.DefaultAuthRole,
		"tls_skip_verify": b.tlsSkipVerify,
		"ca_data":         b.caData,
	}
	if b.upstreamURL != nil {
		data["mcp_aws_url"] = b.upstreamURL.String()
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: data}, nil
}

// handleConfigWrite merges incoming fields with the live config and applies.
// Always re-runs applyParsedConfig so the URL → region inference is reapplied
// — if an operator changes mcp_aws_url to a different-region host, the cached
// region must move with it.
//
// The persist data is the snapshot returned by applyParsedConfig — it captures
// what THIS write resolved to, computed from the merged config alone, so it
// cannot be torn by a concurrent writer racing in between resolution and Put.
func (b *mcpAWSBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	conf := b.snapshotForMerge()

	for _, k := range []string{
		"mcp_aws_url", "region", "max_body_size", "timeout",
		"auto_auth_path", "default_role", "tls_skip_verify", "ca_data",
	} {
		if val, ok := d.GetOk(k); ok {
			conf[k] = val
		}
	}

	// auto_auth_path is required. Reject before applying any other changes so
	// a partial-update can never silently disable transparent mode.
	if s, _ := conf["auto_auth_path"].(string); s == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required"),
		}, nil
	}

	if err := httpproxy.ValidateConfig(conf, "mcp_aws_url"); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest(err.Error()),
		}, nil
	}

	persist, err := b.applyParsedConfig(conf)
	if err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest(err.Error()),
		}, nil
	}

	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", persist)
		if err != nil {
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
		if err := b.StorageView.Put(ctx, entry); err != nil {
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"message": "configuration updated"},
	}, nil
}

// snapshotForMerge returns a copy of the backend's live config in the shape
// expected by httpproxy.ParseConfig, used as the merge base for partial
// updates. "region" is the raw operator-supplied configRegion (possibly
// empty) — never the resolved region — so a config-write that changes only
// mcp_aws_url correctly re-infers from the new host instead of carrying the
// stale resolved region forward.
func (b *mcpAWSBackend) snapshotForMerge() map[string]any {
	b.mu.RLock()
	tc := b.TransparentConfig
	conf := map[string]any{
		"region":          b.configRegion,
		"max_body_size":   b.MaxBodySize,
		"timeout":         b.Timeout.String(),
		"auto_auth_path":  tc.AutoAuthPath,
		"default_role":    tc.DefaultAuthRole,
		"tls_skip_verify": b.tlsSkipVerify,
		"ca_data":         b.caData,
	}
	if b.upstreamURL != nil {
		conf["mcp_aws_url"] = b.upstreamURL.String()
	}
	b.mu.RUnlock()
	return conf
}
