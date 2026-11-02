package core

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// How a namespace treats a caller whose native identity no entity claims, or
// who presents none (unknown_aliases).
const (
	// unknownAliasesObserve admits them as before; the default.
	unknownAliasesObserve = "observe"

	// unknownAliasesDeny refuses them, and a claimed caller whose entity is
	// not governed, unless their mount is exempt.
	unknownAliasesDeny = "deny"
)

// identityConfig is a namespace's identity verdict settings, as stored and as
// published on its nsIndex. Immutable once published; a nil *identityConfig
// reads as the defaults, which is what a namespace that never wrote one has.
type identityConfig struct {
	// UnknownAliases is one of the unknownAliases* modes.
	UnknownAliases string `json:"unknown_aliases"`

	// ExemptMounts are the accessors of the auth mounts whose callers are
	// never refused for an unknown or ungoverned native identity, sorted and
	// without repeats.
	ExemptMounts []string `json:"exempt_mounts"`
}

// mode returns the unknown_aliases mode, the default for a nil config.
func (c *identityConfig) mode() string {
	if c == nil || c.UnknownAliases == "" {
		return unknownAliasesObserve
	}
	return c.UnknownAliases
}

// exempt reports whether the auth mount with accessor is exempt. It does not
// allocate.
func (c *identityConfig) exempt(accessor string) bool {
	if c == nil {
		return false
	}
	_, ok := slices.BinarySearch(c.ExemptMounts, accessor)
	return ok
}

// isDefault reports whether c changes nothing from the defaults, so a write of
// it removes the stored config.
func (c *identityConfig) isDefault() bool {
	return c.mode() == unknownAliasesObserve && len(c.ExemptMounts) == 0
}

// clone returns a copy of c that shares nothing with it, the defaults for nil.
func (c *identityConfig) clone() *identityConfig {
	if c == nil {
		return &identityConfig{UnknownAliases: unknownAliasesObserve}
	}
	return &identityConfig{UnknownAliases: c.mode(), ExemptMounts: slices.Clone(c.ExemptMounts)}
}

// parseUnknownAliases checks a mode.
func parseUnknownAliases(s string) (string, error) {
	switch s {
	case unknownAliasesObserve, unknownAliasesDeny:
		return s, nil
	}
	return "", logical.ErrBadRequestf("unknown_aliases must be %q or %q, got %q",
		unknownAliasesObserve, unknownAliasesDeny, s)
}

// Storage layout, beside the groups and entities:
//
//	{namespace-uuid}/config -> JSON-encoded storedIdentityConfig
//
// Absent while the namespace keeps the defaults.
const identityConfigSegment = "config"

func identityConfigKey(nsUUID string) string { return nsUUID + "/" + identityConfigSegment }

const storedIdentityConfigVersion = 1

type storedIdentityConfig struct {
	Version int             `json:"version"`
	Config  *identityConfig `json:"config"`
}

// IdentityConfig returns a copy of the identity config of the namespace in
// ctx, the defaults when it has none.
func (s *IdentityStore) IdentityConfig(ctx context.Context) (*identityConfig, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	return s.namespaceIndex(ns.ID).config.clone(), nil
}

// SetIdentityConfig makes cfg the identity config of the namespace in ctx:
// stored and published under the next generation, so every cached membership
// computes again on its next request. A config equal to the defaults removes
// the stored one. cfg is normalized in place; the store keeps its own copy.
func (s *IdentityStore) SetIdentityConfig(ctx context.Context, cfg *identityConfig) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ErrNamespaceNotInContext
	}
	if cfg == nil {
		cfg = &identityConfig{}
	}
	mode, err := parseUnknownAliases(cfg.mode())
	if err != nil {
		return err
	}
	cfg.UnknownAliases = mode
	cfg.ExemptMounts = slices.Compact(slices.Sorted(slices.Values(cfg.ExemptMounts)))
	for _, acc := range cfg.ExemptMounts {
		if !validAccessor(acc) {
			return logical.ErrBadRequest("every exempt mount names an auth mount")
		}
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		var published *identityConfig
		if cfg.isDefault() {
			if err := s.storage.Delete(ctx, identityConfigKey(ns.UUID)); err != nil {
				return fmt.Errorf("failed to delete the identity config: %w", err)
			}
		} else {
			published = cfg.clone()
			data, err := json.Marshal(&storedIdentityConfig{Version: storedIdentityConfigVersion, Config: published})
			if err != nil {
				return fmt.Errorf("failed to marshal the identity config: %w", err)
			}
			if err := s.storage.Put(ctx, &sdklogical.StorageEntry{Key: identityConfigKey(ns.UUID), Value: data}); err != nil {
				return fmt.Errorf("failed to write the identity config: %w", err)
			}
		}
		s.publishConfigLocked(ns.ID, published)
		return nil
	}()
	if err != nil {
		return err
	}
	s.logger.Info("set identity config",
		logger.String("namespace", ns.Path),
		logger.String("unknown_aliases", cfg.mode()),
		logger.Int("exempt_mounts", len(cfg.ExemptMounts)))
	return nil
}

// publishConfigLocked makes cfg (nil for the defaults) the namespace's config
// under the next generation, keeping its groups and entities as published.
// Caller holds mu.
func (s *IdentityStore) publishConfigLocked(nsID string, cfg *identityConfig) {
	snap := s.snapshot.Load()
	cur := snap.namespace(nsID)
	var next *nsIndex
	if len(cur.groupsByName) > 0 || cur.entities.count() > 0 || cfg != nil {
		n := *cur
		n.gen = s.gen.Add(1)
		n.config = cfg
		next = &n
	}
	s.snapshot.Store(snap.withNamespace(nsID, next))
}

// loadConfigLocked reads the stored identity config of a namespace, nil when it
// has none. A record that does not decode or validate is logged and read as the
// defaults: refusing callers on a config nobody can read would be worse than
// admitting them as an unconfigured namespace does. Caller holds mu.
func (s *IdentityStore) loadConfigLocked(ctx context.Context, ns *namespace.Namespace) (*identityConfig, error) {
	entry, err := s.storage.Get(ctx, identityConfigKey(ns.UUID))
	if err != nil {
		return nil, fmt.Errorf("failed to read the identity config of namespace %q: %w", ns.Path, err)
	}
	if entry == nil {
		return nil, nil
	}
	var stored storedIdentityConfig
	err = json.Unmarshal(entry.Value, &stored)
	if err == nil && stored.Version != storedIdentityConfigVersion {
		err = fmt.Errorf("unknown storage version %d", stored.Version)
	}
	if err == nil && stored.Config == nil {
		err = fmt.Errorf("record holds no config")
	}
	if err == nil {
		_, err = parseUnknownAliases(stored.Config.mode())
	}
	if err != nil {
		s.logger.Warn("ignoring an identity config that cannot be loaded; the namespace uses the defaults",
			logger.String("namespace", ns.Path), logger.Err(err))
		return nil, nil
	}
	cfg := stored.Config.clone()
	slices.Sort(cfg.ExemptMounts)
	if cfg.isDefault() {
		return nil, nil
	}
	return cfg, nil
}
