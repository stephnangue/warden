package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// oidcIssuerConfigPath is the storage key (within the issuer barrier view) of the
// issuer configuration.
const oidcIssuerConfigPath = "config"

// defaultAssertionTTL is the lifetime of a minted identity assertion when the
// config does not override it. Short by design: the assertion is exchanged for
// an upstream credential immediately and never reused.
const defaultAssertionTTL = 5 * time.Minute

// issuerConfig is the persisted, barrier-encrypted configuration of the OIDC
// issuer. The issuer is disabled by default (no config, or Enabled=false), so the
// warden_identity mint path fails closed until an operator enables it.
type issuerConfig struct {
	Version   int    `json:"version"`
	Enabled   bool   `json:"enabled"`
	IssuerURL string `json:"issuer_url"`    // public `iss` URL upstreams fetch from
	TTL       string `json:"assertion_ttl"` // duration string; empty -> defaultAssertionTTL

	// KeyRotationPeriod, when > 0, rotates the signing key on that cadence (with a
	// retired-key grace window so in-flight assertions keep verifying). Empty/0
	// disables automatic rotation.
	KeyRotationPeriod string `json:"key_rotation_period,omitempty"`

	// JWKSCacheTTL is the Cache-Control max-age of the published/served JWKS — how
	// long a verifier or CDN may cache it. It doubles as the propagation floor: a
	// freshly published next key must be in the JWKS at least this long before it
	// may start signing. Empty -> defaultJWKSCacheTTL.
	JWKSCacheTTL string `json:"jwks_cache_ttl,omitempty"`

	// RetiredKeyGrace is the safety margin kept BEYOND a minted assertion's TTL
	// before a retired key is pruned from the JWKS (a retired key therefore stays
	// verifiable for assertion_ttl + retired_key_grace). Empty -> defaultRetiredKeyGrace.
	RetiredKeyGrace string `json:"retired_key_grace,omitempty"`

	// Publisher, when set, pushes the public discovery + JWKS documents to an
	// external surface (bucket/CDN) so IssuerURL need not be Warden's own address.
	Publisher publisherConfig `json:"publisher,omitempty"`
}

const (
	// defaultJWKSCacheTTL is the published JWKS Cache-Control max-age (and the
	// next-key pre-publication floor) when unset.
	defaultJWKSCacheTTL = time.Minute
	// defaultRetiredKeyGrace is the retired-key retention margin beyond assertion TTL.
	defaultRetiredKeyGrace = time.Hour
)

func parseDurationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// keyRotationPeriod parses the configured rotation cadence; 0 disables rotation.
func (c *issuerConfig) keyRotationPeriod() time.Duration {
	if c.KeyRotationPeriod == "" {
		return 0
	}
	d, err := time.ParseDuration(c.KeyRotationPeriod)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

func (c *issuerConfig) jwksCacheTTL() time.Duration {
	return parseDurationOr(c.JWKSCacheTTL, defaultJWKSCacheTTL)
}

func (c *issuerConfig) retiredKeyGrace() time.Duration {
	return parseDurationOr(c.RetiredKeyGrace, defaultRetiredKeyGrace)
}

// assertionTTL parses the configured TTL, falling back to the default.
func (c *issuerConfig) assertionTTL() time.Duration {
	if c.TTL == "" {
		return defaultAssertionTTL
	}
	d, err := time.ParseDuration(c.TTL)
	if err != nil || d <= 0 {
		return defaultAssertionTTL
	}
	return d
}

// loadIssuerConfig reads the issuer config, returning (nil, nil) when none is set.
func loadIssuerConfig(ctx context.Context, storage sdklogical.Storage) (*issuerConfig, error) {
	entry, err := storage.Get(ctx, oidcIssuerConfigPath)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: read config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var cfg issuerConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, fmt.Errorf("oidc issuer: unmarshal config: %w", err)
	}
	return &cfg, nil
}

// saveIssuerConfig writes the issuer config (barrier-encrypted).
func saveIssuerConfig(ctx context.Context, storage sdklogical.Storage, cfg *issuerConfig) error {
	cfg.Version = 1
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("oidc issuer: marshal config: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcIssuerConfigPath, Value: data})
}
