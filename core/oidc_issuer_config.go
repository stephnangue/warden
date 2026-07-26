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
	// JWKS overlap so in-flight assertions keep verifying). Empty/0 disables
	// automatic rotation.
	KeyRotationPeriod string `json:"key_rotation_period,omitempty"`

	// KeyActivationDelay is how long a newly staged key is published before it
	// starts signing, so verifiers fetch it first. It should exceed the cache TTL
	// the operator sets on the published JWKS. Empty -> defaultKeyActivationDelay.
	KeyActivationDelay string `json:"key_activation_delay,omitempty"`

	// KeyOverlap is the margin kept beyond a minted assertion's TTL before a
	// retired key is pruned from the JWKS. Empty -> defaultKeyOverlap.
	KeyOverlap string `json:"key_overlap,omitempty"`

	// Publisher, when set, pushes the public discovery + JWKS documents to an
	// external surface (bucket/CDN) so IssuerURL need not be Warden's own address.
	Publisher publisherConfig `json:"publisher,omitempty"`
}

const (
	// defaultKeyActivationDelay is the stage->activate wait when unset.
	defaultKeyActivationDelay = time.Minute
	// defaultKeyOverlap is the retired-key retention margin beyond assertion TTL.
	defaultKeyOverlap = time.Hour
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

func (c *issuerConfig) keyActivationDelay() time.Duration {
	return parseDurationOr(c.KeyActivationDelay, defaultKeyActivationDelay)
}

func (c *issuerConfig) keyOverlap() time.Duration {
	return parseDurationOr(c.KeyOverlap, defaultKeyOverlap)
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
