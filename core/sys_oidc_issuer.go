package core

import (
	"context"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathOIDCIssuer exposes the OIDC issuer configuration. The issuer is a single
// GLOBAL trust root shared by every namespace, so — unlike credential sources —
// this path is writable/readable only in the ROOT namespace. A child-namespace
// admin must not be able to rewrite the issuer URL, or keys.
func (b *SystemBackend) pathOIDCIssuer() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "oidc-issuer/config",
			Fields: map[string]*framework.FieldSchema{
				"enabled": {
					Type:        framework.TypeBool,
					Description: "Enable the OIDC issuer (Workload Identity Federation).",
				},
				"issuer_url": {
					Type:        framework.TypeString,
					Description: "Public HTTPS URL upstreams fetch discovery/JWKS from and the `iss` claim of minted assertions.",
				},
				"assertion_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lifetime of a minted identity assertion (default 5m).",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleOIDCIssuerConfigRead,
					Summary:  "Read the OIDC issuer configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleOIDCIssuerConfigWrite,
					Summary:  "Configure the OIDC issuer",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleOIDCIssuerConfigWrite,
					Summary:  "Configure the OIDC issuer",
				},
			},
			HelpSynopsis: "Configure Warden as an OIDC issuer for Workload Identity Federation",
			HelpDescription: "Root-namespace-only. Enables the issuer and sets the public issuer URL and " +
				"assertion TTL. Cross-tenant isolation is enforced by the namespace-scoped `sub` claim " +
				"(wid:{namespaceID}:{mountAccessor}:{principalID}); upstream trust policies MUST condition " +
				"on `sub` (or `warden_namespace`), never on `aud` alone.",
		},
	}
}

// requireRootNamespace returns an error response unless the request is in the
// root namespace.
func (b *SystemBackend) requireRootNamespace(ctx context.Context) (*logical.Response, bool) {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return logical.ErrorResponse(logical.ErrBadRequest("no namespace in context")), false
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrorResponse(logical.ErrForbidden("the OIDC issuer is global and can only be configured in the root namespace")), false
	}
	return nil, true
}

func (b *SystemBackend) handleOIDCIssuerConfigRead(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx); !ok {
		return resp, nil
	}

	storage := NewBarrierView(b.core.barrier, oidcIssuerStorePrefix)
	cfg, err := loadIssuerConfig(ctx, storage)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if cfg == nil {
		return b.respondSuccess(map[string]any{"enabled": false}), nil
	}

	data := map[string]any{
		"enabled":       cfg.Enabled,
		"issuer_url":    cfg.IssuerURL,
		"assertion_ttl": int64(cfg.assertionTTL().Seconds()),
		"ready":         b.core.oidcIssuer != nil && b.core.oidcIssuer.Ready(),
	}
	return b.respondSuccess(data), nil
}

func (b *SystemBackend) handleOIDCIssuerConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx); !ok {
		return resp, nil
	}

	enabled := d.Get("enabled").(bool)
	issuerURL := strings.TrimSpace(d.Get("issuer_url").(string))
	ttlSec, _ := d.Get("assertion_ttl").(int)

	if enabled {
		if issuerURL == "" {
			return logical.ErrorResponse(logical.ErrBadRequest("issuer_url is required when the issuer is enabled")), nil
		}
		if !strings.HasPrefix(issuerURL, "https://") {
			return logical.ErrorResponse(logical.ErrBadRequest("issuer_url must be https:// (AWS/GCP/Azure require HTTPS OIDC providers)")), nil
		}
	}

	cfg := &issuerConfig{
		Enabled:   enabled,
		IssuerURL: issuerURL,
	}
	if ttlSec > 0 {
		cfg.TTL = (time.Duration(ttlSec) * time.Second).String()
	}

	storage := NewBarrierView(b.core.barrier, oidcIssuerStorePrefix)
	if err := saveIssuerConfig(ctx, storage, cfg); err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Activate the change: reload the issuer from the just-written config. On the
	// active node this generates and persists a signing key on first enable.
	if err := b.core.setupOIDCIssuer(ctx, b.core.Standby()); err != nil {
		return logical.ErrorResponse(err), nil
	}

	b.logger.Info("oidc issuer configured", logger.Bool("enabled", enabled), logger.String("issuer_url", issuerURL))

	return b.respondSuccess(map[string]any{
		"enabled":    enabled,
		"issuer_url": issuerURL,
		"ready":      b.core.oidcIssuer != nil && b.core.oidcIssuer.Ready(),
	}), nil
}
