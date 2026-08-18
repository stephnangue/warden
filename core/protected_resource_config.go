package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// protectedResourceStorePrefix is the barrier-view prefix for the protected
	// resource metadata configuration. Written through a barrier view, so it is
	// encrypted at rest.
	protectedResourceStorePrefix = "core/protected-resource/"

	// protectedResourceConfigPath is the storage key (within that view) of the
	// configuration.
	protectedResourceConfigPath = "config"

	// defaultPRMCacheTTL is how long a client or CDN may cache a served metadata
	// document when the config does not override it. The document is derived from
	// live mount state, so this is a staleness budget, not just a performance knob.
	defaultPRMCacheTTL = time.Hour
)

// protectedResourceConfig is the persisted, barrier-encrypted configuration
// backing RFC 9728 metadata. Only genuinely global fields live here; everything
// per-resource is derived from the mount at request time.
//
// The feature is off until ResourceURL is set: without an external base URL
// there is no way to name the resource, so the metadata endpoint 404s.
type protectedResourceConfig struct {
	Version int `json:"version"`

	// ResourceURL is the external HTTPS base clients reach Warden at. Its
	// presence is the master switch. The `resource` field of each document is
	// this joined with the mount's API path, so it must be the address clients
	// actually use — never a request's Host header, which a client controls.
	ResourceURL string `json:"resource_url"`

	// AuthorizationServers overrides the issuer derived from the mount's
	// user_auth_path. Set it only when the derived value is wrong — a proxy in
	// front of the IdP, or an issuer that differs from its discovery URL.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// ResourceDocumentation is an optional human-facing URL echoed in every
	// document, for clients that surface it to an operator on a failed flow.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`

	// CacheTTL is the Cache-Control max-age of a served document. Empty ->
	// defaultPRMCacheTTL.
	CacheTTL string `json:"cache_ttl,omitempty"`
}

// cacheTTL returns the configured document cache lifetime, or the default when
// unset or unparseable. Lenient by design: a bad duration must not take the
// endpoint down, and the default is safe.
func (c *protectedResourceConfig) cacheTTL() time.Duration {
	if c == nil {
		return defaultPRMCacheTTL
	}
	return parseDurationOr(c.CacheTTL, defaultPRMCacheTTL)
}

// enabled reports whether metadata may be served at all.
func (c *protectedResourceConfig) enabled() bool {
	return c != nil && c.ResourceURL != ""
}

// loadProtectedResourceConfig reads the config, returning (nil, nil) when none
// is set.
func loadProtectedResourceConfig(ctx context.Context, storage sdklogical.Storage) (*protectedResourceConfig, error) {
	entry, err := storage.Get(ctx, protectedResourceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("protected resource: read config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var cfg protectedResourceConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, fmt.Errorf("protected resource: unmarshal config: %w", err)
	}
	return &cfg, nil
}

// saveProtectedResourceConfig writes the config (barrier-encrypted).
func saveProtectedResourceConfig(ctx context.Context, storage sdklogical.Storage, cfg *protectedResourceConfig) error {
	cfg.Version = 1
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("protected resource: marshal config: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: protectedResourceConfigPath, Value: data})
}
