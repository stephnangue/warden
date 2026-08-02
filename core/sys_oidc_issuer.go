package core

import (
	"context"
	"fmt"
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
					Description: "Optional publisher pushing discovery+JWKS to a bucket/CDN. Keys: type (local_file|http_put|s3|azure_blob), dir, base_url, auth_header, auth_value, bucket, region, prefix, access_key_id, secret_access_key, account_name, container, account_key, endpoint. Cache-Control is derived from jwks_cache_ttl.",
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
				"assertion TTL, signing-key rotation timings, and publisher. A write is a PARTIAL update: " +
				"only the fields present in the request change; omitted fields keep their current values. " +
				"Clear or disable a field by setting it explicitly (e.g. key_rotation_period=0). Cross-tenant isolation is " +
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

	storage := NewBarrierView(b.core.barrier, oidcIssuerStorePrefix)
	prior, _ := loadIssuerConfig(ctx, storage)

	// Partial update: start from the current config (or an empty one on first
	// write) and overlay ONLY the fields the request actually set, so changing one
	// setting never silently reverts the others to their defaults. A field is
	// cleared/disabled by setting it explicitly (e.g. key_rotation_period=0).
	cfg := &issuerConfig{}
	if prior != nil {
		*cfg = *prior
	}
	if v, ok := d.GetOk("enabled"); ok {
		cfg.Enabled = v.(bool)
	}
	if v, ok := d.GetOk("issuer_url"); ok {
		cfg.IssuerURL = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("assertion_ttl"); ok {
		cfg.TTL = (time.Duration(v.(int)) * time.Second).String()
	}
	if v, ok := d.GetOk("key_rotation_period"); ok {
		cfg.KeyRotationPeriod = (time.Duration(v.(int)) * time.Second).String()
	}
	if v, ok := d.GetOk("jwks_cache_ttl"); ok {
		cfg.JWKSCacheTTL = (time.Duration(v.(int)) * time.Second).String()
	}
	if v, ok := d.GetOk("retired_key_grace"); ok {
		cfg.RetiredKeyGrace = (time.Duration(v.(int)) * time.Second).String()
	}
	if v, ok := d.GetOk("publisher"); ok {
		// Field-level merge over the current publisher: unset fields keep their
		// value, a type switch clears the old type's fields, and a field set for
		// the wrong type is rejected rather than silently ignored.
		merged, err := mergePublisherConfig(cfg.Publisher, v.(map[string]any))
		if err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
		}
		cfg.Publisher = merged
	}

	// Validate the MERGED result (not just the request), so enabling without
	// re-supplying an already-stored issuer_url still passes.
	if cfg.Enabled {
		if cfg.IssuerURL == "" {
			return logical.ErrorResponse(logical.ErrBadRequest("issuer_url is required when the issuer is enabled")), nil
		}
		if !strings.HasPrefix(cfg.IssuerURL, "https://") {
			return logical.ErrorResponse(logical.ErrBadRequest("issuer_url must be https:// (AWS/GCP/Azure require HTTPS OIDC providers)")), nil
		}
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

	b.logger.Info("oidc issuer configured", logger.Bool("enabled", cfg.Enabled), logger.String("issuer_url", cfg.IssuerURL))

	return b.respondSuccess(map[string]any{
		"enabled":    cfg.Enabled,
		"issuer_url": cfg.IssuerURL,
		"ready":      oidcIssuerReady(b.core),
	}), nil
}

// publisherFieldOwners maps each type-specific publisher field to the publisher
// type(s) it belongs to. A field set for any other type is a misconfiguration
// (e.g. `dir` under an s3 publisher would be silently ignored). A field may be
// shared by more than one type (e.g. `prefix` for both s3 and azure_blob).
var publisherFieldOwners = map[string][]string{
	"dir":               {"local_file"},
	"base_url":          {"http_put"},
	"auth_header":       {"http_put"},
	"auth_value":        {"http_put"},
	"bucket":            {"s3"},
	"region":            {"s3"},
	"prefix":            {"s3", "azure_blob"},
	"access_key_id":     {"s3"},
	"secret_access_key": {"s3"},
	"account_name":      {"azure_blob"},
	"container":         {"azure_blob"},
	"account_key":       {"azure_blob"},
	"endpoint":          {"azure_blob"},
}

// ownedBy reports whether field is valid for the given publisher type.
func ownedBy(owners []string, typ string) bool {
	for _, o := range owners {
		if o == typ {
			return true
		}
	}
	return false
}

// mergePublisherConfig overlays the request "publisher" map onto the prior
// publisher config (a field-level partial update, matching the top-level config
// semantics), and returns an error when a request explicitly sets a field that
// does not belong to the selected type. The type is carried forward from prior
// when the request omits it; changing the type drops the previous type's fields
// so no inert leftovers remain. Masked/empty secrets are preserved from prior
// when the type is unchanged, so an update need not re-send them.
func mergePublisherConfig(prior publisherConfig, raw map[string]any) (publisherConfig, error) {
	get := func(k string) (string, bool) {
		if v, ok := raw[k].(string); ok {
			return strings.TrimSpace(v), true
		}
		return "", false
	}

	effType := prior.Type
	if t, ok := get("type"); ok && t != "" {
		effType = t
	}

	// Reject fields the request explicitly set that belong to another type.
	for field, owners := range publisherFieldOwners {
		if v, ok := get(field); ok && v != "" && v != maskValue && !ownedBy(owners, effType) {
			return publisherConfig{}, fmt.Errorf(
				"publisher field %q is only valid for type(s) %s, not %q", field, strings.Join(owners, "|"), effType)
		}
	}

	// Keep the prior fields only when the type is unchanged; a type change starts
	// fresh so the previous type's fields are cleared rather than lingering inert.
	pc := publisherConfig{Type: effType}
	if effType == prior.Type {
		pc = prior
		pc.Type = effType
	}

	// Overlay provided fields owned by the effective type (foreign ones already
	// errored above; a provided-empty value is a no-op for a non-owned field).
	if v, ok := get("dir"); ok {
		pc.Dir = v
	}
	if v, ok := get("base_url"); ok {
		pc.BaseURL = v
	}
	if v, ok := get("auth_header"); ok {
		pc.Autheader = v
	}
	if v, ok := get("bucket"); ok {
		pc.Bucket = v
	}
	if v, ok := get("region"); ok {
		pc.Region = v
	}
	if v, ok := get("prefix"); ok {
		pc.Prefix = v
	}
	if v, ok := get("access_key_id"); ok {
		pc.AccessKeyID = v
	}
	if v, ok := get("account_name"); ok {
		pc.AccountName = v
	}
	if v, ok := get("container"); ok {
		pc.Container = v
	}
	if v, ok := get("endpoint"); ok {
		pc.Endpoint = v
	}
	// Secrets: overlay only a real value; an omitted/empty/masked secret keeps the
	// prior one (carried via pc=prior when the type is unchanged).
	if v, ok := get("auth_value"); ok && v != "" && v != maskValue {
		pc.AuthValue = v
	}
	if v, ok := get("secret_access_key"); ok && v != "" && v != maskValue {
		pc.SecretAccessKey = v
	}
	if v, ok := get("account_key"); ok && v != "" && v != maskValue {
		pc.AccountKey = v
	}

	return pc, nil
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
	if pc.AccountName != "" {
		m["account_name"] = pc.AccountName
	}
	if pc.Container != "" {
		m["container"] = pc.Container
	}
	if pc.AccountKey != "" {
		m["account_key"] = maskValue
	}
	if pc.Endpoint != "" {
		m["endpoint"] = pc.Endpoint
	}
	return m
}
