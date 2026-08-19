package core

import (
	"context"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathProtectedResource exposes the RFC 9728 protected-resource-metadata
// configuration. Like the OIDC issuer this is a single GLOBAL setting — the
// external base URL is a property of the deployment, not of a namespace — so it
// is root-namespace only. Everything per-resource is derived from the mount.
func (b *SystemBackend) pathProtectedResource() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "protected-resource/config",
			Fields: map[string]*framework.FieldSchema{
				"resource_url": {
					Type: framework.TypeString,
					Description: "External HTTPS base URL clients reach Warden at (e.g. https://warden.example.com). " +
						"Setting it enables metadata; clearing it disables. Each document's `resource` is this " +
						"joined with the mount's API path.",
				},
				"authorization_servers": {
					Type: framework.TypeCommaStringSlice,
					Description: "Override the authorization server(s) advertised to clients. Leave empty to derive " +
						"each mount's issuer from the auth method at its user_auth_path.",
				},
				"resource_documentation": {
					Type:        framework.TypeString,
					Description: "Optional human-facing documentation URL echoed in every document.",
				},
				"cache_ttl": {
					Type: framework.TypeString,
					Description: "Cache-Control max-age of a served document (default: 1h). Documents are derived " +
						"from live mount config, so this is a staleness budget.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleProtectedResourceConfigRead,
					Summary:  "Read the protected resource metadata configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleProtectedResourceConfigWrite,
					Summary:  "Configure protected resource metadata",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleProtectedResourceConfigWrite,
					Summary:  "Configure protected resource metadata",
				},
			},
			HelpSynopsis: "Configure RFC 9728 protected resource metadata.",
			HelpDescription: "Warden publishes, per opted-in mount, a metadata document naming the authorization " +
				"server a client should obtain a USER credential from. A mount opts in with user_auth_path; " +
				"the document is served at /.well-known/oauth-protected-resource<mount-api-path>. " +
				"Warden is a resource server only and never serves authorization-server metadata. " +
				"Writes are partial: an omitted field keeps its stored value.",
		},
	}
}

func (b *SystemBackend) handleProtectedResourceConfigRead(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx, "protected resource metadata"); !ok {
		return resp, nil
	}

	cfg, err := b.core.protectedResourceConfig(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if cfg == nil {
		cfg = &protectedResourceConfig{}
	}

	return &logical.Response{
		Data: map[string]any{
			"enabled":                cfg.enabled(),
			"resource_url":           cfg.ResourceURL,
			"authorization_servers":  cfg.AuthorizationServers,
			"resource_documentation": cfg.ResourceDocumentation,
			"cache_ttl":              int64(cfg.cacheTTL().Seconds()),
		},
	}, nil
}

func (b *SystemBackend) handleProtectedResourceConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx, "protected resource metadata"); !ok {
		return resp, nil
	}

	// Load-modify-save under the config mutex so two concurrent partial updates
	// cannot lost-update each other. A read failure must NOT fall through to an
	// empty prior: that would turn a partial update into a destructive overwrite.
	b.core.protectedResourceMu.Lock()
	defer b.core.protectedResourceMu.Unlock()

	storage := NewBarrierView(b.core.barrier, protectedResourceStorePrefix)
	prior, err := loadProtectedResourceConfig(ctx, storage)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	cfg := &protectedResourceConfig{}
	if prior != nil {
		*cfg = *prior
	}

	if v, ok := d.GetOk("resource_url"); ok {
		cfg.ResourceURL = v.(string)
	}
	if v, ok := d.GetOk("authorization_servers"); ok {
		cfg.AuthorizationServers = v.([]string)
	}
	if v, ok := d.GetOk("resource_documentation"); ok {
		cfg.ResourceDocumentation = v.(string)
	}
	if v, ok := d.GetOk("cache_ttl"); ok {
		cfg.CacheTTL = v.(string)
	}

	// Validate the merged result, not the delta: a partial update must not be
	// able to leave a stored config that would fail validation as a whole.
	if cfg.ResourceURL != "" {
		if err := validateExternalHTTPSURL(cfg.ResourceURL, "resource_url",
			"clients fetch it over the public internet"); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
		}
	}
	for _, as := range cfg.AuthorizationServers {
		if err := validateExternalHTTPSURL(as, "authorization_servers",
			"a client redirects a user's browser there"); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
		}
	}
	if cfg.ResourceDocumentation != "" {
		if err := validateExternalHTTPSURL(cfg.ResourceDocumentation, "resource_documentation",
			"it is published to clients"); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
		}
	}
	if cfg.CacheTTL != "" {
		if _, err := time.ParseDuration(cfg.CacheTTL); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(
				"cache_ttl must be a duration string (e.g. '1h', '15m')")), nil
		}
	}

	if err := saveProtectedResourceConfig(ctx, storage, cfg); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		Data: map[string]any{
			"enabled":                cfg.enabled(),
			"resource_url":           cfg.ResourceURL,
			"authorization_servers":  cfg.AuthorizationServers,
			"resource_documentation": cfg.ResourceDocumentation,
			"cache_ttl":              int64(cfg.cacheTTL().Seconds()),
		},
	}, nil
}
