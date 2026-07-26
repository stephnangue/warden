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
				"key_rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: "Signing-key rotation cadence. 0 disables automatic rotation.",
				},
				"jwks_cache_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Cache-Control max-age of the published JWKS; also the minimum time a new signing key is pre-published before it signs. Default 1m.",
				},
				"retired_key_grace": {
					Type:        framework.TypeDurationSecond,
					Description: "Safety margin kept beyond the assertion TTL before a retired key is pruned from the JWKS (retired keys stay verifiable for assertion_ttl + this). Default 1h.",
				},
				"publisher": {
					Type:        framework.TypeMap,
					Description: "Optional publisher pushing discovery+JWKS to a bucket/CDN. Keys: type (local_file|http_put|s3), dir, base_url, auth_header, auth_value, bucket, region, prefix, access_key_id, secret_access_key. Cache-Control is derived from jwks_cache_ttl.",
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
			HelpDescription: "Root-namespace-only. Enables the issuer and sets the public issuer URL, " +
				"assertion TTL, signing-key rotation timings, and publisher. A write REPLACES the whole " +
				"config; omitted fields revert to defaults, except masked secrets (publisher auth_value / " +
				"secret_access_key) which are carried forward when omitted. Cross-tenant isolation is " +
				"enforced by the namespace-scoped `sub` claim (wid:{namespaceID}:{mountAccessor}:{principalID}); " +
				"upstream trust policies MUST condition on `sub` (or `warden_namespace`), never on `aud` alone.",
		},
	}
}

// oidcIssuerReady reports whether the issuer is configured and has an active key.
func oidcIssuerReady(c *Core) bool {
	iss := c.OIDCIssuer()
	return iss != nil && iss.Ready()
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
		"enabled":             cfg.Enabled,
		"issuer_url":          cfg.IssuerURL,
		"assertion_ttl":       int64(cfg.assertionTTL().Seconds()),
		"key_rotation_period": int64(cfg.keyRotationPeriod().Seconds()),
		"jwks_cache_ttl":      int64(cfg.jwksCacheTTL().Seconds()),
		"retired_key_grace":   int64(cfg.retiredKeyGrace().Seconds()),
		"ready":               oidcIssuerReady(b.core),
	}
	if cfg.Publisher.Type != "" {
		data["publisher"] = maskedPublisher(cfg.Publisher)
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
	rotationSec, _ := d.Get("key_rotation_period").(int)
	cacheTTLSec, _ := d.Get("jwks_cache_ttl").(int)
	graceSec, _ := d.Get("retired_key_grace").(int)
	publisherRaw, _ := d.Get("publisher").(map[string]any)

	if enabled {
		if issuerURL == "" {
			return logical.ErrorResponse(logical.ErrBadRequest("issuer_url is required when the issuer is enabled")), nil
		}
		if !strings.HasPrefix(issuerURL, "https://") {
			return logical.ErrorResponse(logical.ErrBadRequest("issuer_url must be https:// (AWS/GCP/Azure require HTTPS OIDC providers)")), nil
		}
	}

	storage := NewBarrierView(b.core.barrier, oidcIssuerStorePrefix)
	prior, _ := loadIssuerConfig(ctx, storage)

	cfg := &issuerConfig{
		Enabled:   enabled,
		IssuerURL: issuerURL,
		Publisher: parsePublisherConfig(publisherRaw, prior),
	}
	if ttlSec > 0 {
		cfg.TTL = (time.Duration(ttlSec) * time.Second).String()
	}
	if rotationSec > 0 {
		cfg.KeyRotationPeriod = (time.Duration(rotationSec) * time.Second).String()
	}
	if cacheTTLSec > 0 {
		cfg.JWKSCacheTTL = (time.Duration(cacheTTLSec) * time.Second).String()
	}
	if graceSec > 0 {
		cfg.RetiredKeyGrace = (time.Duration(graceSec) * time.Second).String()
	}

	// A rotation cadence must comfortably outlast the JWKS cache TTL, otherwise the
	// pre-published next key would not have been cacheable for a full period before
	// it signs — this guarantees the rotation-time propagation floor is a no-op in
	// the steady state. (The published JWKS Cache-Control max-age is derived from
	// the same value, so a cached JWKS is always refreshed before a new key signs.)
	if p := cfg.keyRotationPeriod(); p > 0 && p <= cfg.jwksCacheTTL() {
		return logical.ErrorResponse(logical.ErrBadRequestf("key_rotation_period (%s) must exceed jwks_cache_ttl (%s)", p, cfg.jwksCacheTTL())), nil
	}

	// Validate the publisher builds BEFORE persisting, so an invalid config can
	// never be stored (a persisted-but-invalid publisher would otherwise degrade
	// every subsequent unseal to endpoint-only with a warning).
	if _, err := newJWKSPublisher(cfg.Publisher, ""); err != nil {
		return logical.ErrorResponse(logical.ErrBadRequestf("invalid publisher config: %v", err)), nil
	}

	if err := saveIssuerConfig(ctx, storage, cfg); err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Activate the change: reload the issuer from the just-written config. On the
	// active node this generates and persists a signing key on first enable, and
	// builds the publisher (a misconfigured publisher fails here).
	if err := b.core.setupOIDCIssuer(ctx, b.core.Standby()); err != nil {
		return logical.ErrorResponse(err), nil
	}
	// Surface a publish failure at config time (unseal only warns).
	if !b.core.Standby() {
		if err := b.core.publishOIDC(ctx); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequestf("issuer configured but publishing failed: %v", err)), nil
		}
	}

	b.logger.Info("oidc issuer configured", logger.Bool("enabled", enabled), logger.String("issuer_url", issuerURL))

	return b.respondSuccess(map[string]any{
		"enabled":    enabled,
		"issuer_url": issuerURL,
		"ready":      oidcIssuerReady(b.core),
	}), nil
}

// parsePublisherConfig normalizes the request "publisher" map into a
// publisherConfig. Sensitive fields (auth_value, secret_access_key) that come in
// empty or masked are preserved from prior when the publisher type is unchanged,
// so an update need not re-send secrets that were masked on read.
func parsePublisherConfig(raw map[string]any, prior *issuerConfig) publisherConfig {
	get := func(k string) string {
		if v, ok := raw[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	pc := publisherConfig{
		Type:            get("type"),
		Dir:             get("dir"),
		BaseURL:         get("base_url"),
		Autheader:       get("auth_header"),
		AuthValue:       get("auth_value"),
		Bucket:          get("bucket"),
		Region:          get("region"),
		Prefix:          get("prefix"),
		AccessKeyID:     get("access_key_id"),
		SecretAccessKey: get("secret_access_key"),
	}
	if prior != nil && prior.Publisher.Type == pc.Type {
		if pc.AuthValue == "" || pc.AuthValue == maskValue {
			pc.AuthValue = prior.Publisher.AuthValue
		}
		if pc.SecretAccessKey == "" || pc.SecretAccessKey == maskValue {
			pc.SecretAccessKey = prior.Publisher.SecretAccessKey
		}
	}
	return pc
}

// maskedPublisher renders a publisher config for read, masking secrets.
func maskedPublisher(pc publisherConfig) map[string]any {
	m := map[string]any{"type": pc.Type}
	if pc.Dir != "" {
		m["dir"] = pc.Dir
	}
	if pc.BaseURL != "" {
		m["base_url"] = pc.BaseURL
	}
	if pc.Autheader != "" {
		m["auth_header"] = pc.Autheader
	}
	if pc.AuthValue != "" {
		m["auth_value"] = maskValue
	}
	if pc.Bucket != "" {
		m["bucket"] = pc.Bucket
	}
	if pc.Region != "" {
		m["region"] = pc.Region
	}
	if pc.Prefix != "" {
		m["prefix"] = pc.Prefix
	}
	if pc.AccessKeyID != "" {
		m["access_key_id"] = pc.AccessKeyID
	}
	if pc.SecretAccessKey != "" {
		m["secret_access_key"] = maskValue
	}
	return m
}
