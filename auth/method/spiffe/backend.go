// Package spiffe implements the SPIFFE auth method: a first-class relying party
// that authenticates workloads presenting either a SPIFFE X.509-SVID (a TLS
// client certificate) or a SPIFFE JWT-SVID (a bearer token) against per-trust-
// domain bundles. Both SVID types are accepted on one mount and issue the single
// spiffe_role token type. The trust-domain store, federation, and SVID
// verification are provided by the shared auth/spiffe substrate.
package spiffe

import (
	"context"
	"fmt"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// SPIFFEAuthConfig is the mount-level configuration. Trust domains are managed
// via the trust-domain/ paths, not here.
type SPIFFEAuthConfig struct {
	TokenTTL    time.Duration `json:"token_ttl" default:"1h"`
	DefaultRole string        `json:"default_role,omitempty"`

	// BoundAudiences are the audiences a JWT-SVID must carry for the mount to
	// admit it, any one of them. Stored, read back and validated (no empty
	// entry), but not used yet: logins still verify a JWT-SVID against the
	// role's bound_audiences. From the cutover to mount-level admission it is
	// the audience every JWT-SVID is verified against.
	BoundAudiences []string `json:"bound_audiences,omitempty"`

	// MaxAge bounds a credential's age at admission, from its issue time:
	// one older, or without an issue time (an X.509-SVID has none), is not
	// admitted. Zero is unset. Stored, read back and validated (not
	// negative), but not used by role logins; the role-free admission
	// enforces it, through helper.CheckMaxAge.
	MaxAge time.Duration `json:"max_age,omitempty"`

	// Facts: entity_kind, and the SVID fields the mount publishes under other
	// names beyond its built-in facts. Compiled in buildSPIFFEConfig. A config
	// write refuses facts that do not compile, so they are never stored; ones
	// that still fail at load (the mount table's, or storage written under
	// looser rules) are installed with a nil naming: the mount answers no
	// fact, so nothing that reads facts can match it.
	helper.FactsConfig
}

type spiffeAuthBackend struct {
	*framework.Backend
	config   *SPIFFEAuthConfig
	configMu sync.RWMutex
	// configWriteMu serializes config writes and the storage load: a write
	// merges onto the live config, so two racing would lose one writer's keys.
	configWriteMu sync.Mutex
	logger        *logger.GatedLogger
	storageView   sdklogical.Storage

	// spiffe holds the SPIFFE substrate (trust-domain store, verification set,
	// federation refresh loop).
	spiffe *spiffelib.Manager

	// mountFacts holds the naming in force and is shared by pointer with
	// every admission this mount produces. installConfig publishes it under
	// configMu together with the config it was compiled from, so a reader
	// holding configMu sees the two agree (a nil config, the defaults, goes
	// with the default naming Factory publishes); admissions and FactNames
	// load it without a lock and see one published naming, whole.
	mountFacts *logical.MountFacts
}

var _ logical.Factory = Factory

// Factory creates a new SPIFFE auth backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &spiffeAuthBackend{
		logger:      conf.Logger,
		storageView: conf.StorageView,
		mountFacts:  &logical.MountFacts{},
	}
	// A spiffe mount admits without any config (every key has a default), so
	// until one is installed it answers its built-in facts as an agent mount.
	// Published before b is shared, so no lock is needed.
	b.mountFacts.Publish(defaultNaming())
	b.spiffe = spiffelib.NewManager(conf.StorageView, conf.Logger)

	b.Backend = &framework.Backend{
		Help:         spiffeAuthHelp,
		BackendType:  "spiffe",
		BackendClass: logical.ClassAuth,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"introspect/roles",
			},
		},
		Paths: append([]*framework.Path{
			b.pathLogin(),
			b.pathConfig(),
			b.pathRole(),
			b.pathRoleList(),
			b.pathIntrospect(),
		}, b.spiffe.Paths()...),
	}

	// Stop the federation refresh loop on unmount/seal (step-down is covered by
	// the active context passed to Initialize).
	b.Backend.Clean = func(context.Context) { b.spiffe.Stop() }

	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	if len(conf.Config) > 0 {
		if err := b.setupSPIFFEConfig(ctx, conf.Config); err != nil {
			return nil, fmt.Errorf("failed to setup spiffe config: %w", err)
		}
	}

	return b, nil
}

// setupSPIFFEConfig builds conf and installs it. It serves the mount table's
// config when the mount is set up and the stored config when it is loaded,
// which a failure here would turn into a failed mount (and, at unseal, a
// failed unseal). Facts that do not compile are therefore logged and installed
// as a nil naming, which answers no fact: closed for every reader of facts,
// while logins and the config itself keep working.
func (b *spiffeAuthBackend) setupSPIFFEConfig(_ context.Context, conf map[string]any) error {
	config, err := buildSPIFFEConfig(conf)
	if err != nil {
		return err
	}
	if err := config.FactsConfig.Err(); err != nil {
		b.logger.Error(helper.FactsDoNotCompileLog, logger.Err(err))
	}
	b.installConfig(config)
	return nil
}

// installConfig makes config the live configuration and publishes its naming
// (nil when it does not compile, which answers no fact) in the same critical
// section. It cannot fail.
func (b *spiffeAuthBackend) installConfig(config *SPIFFEAuthConfig) {
	b.configMu.Lock()
	b.config = config
	b.mountFacts.Publish(config.Naming())
	b.configMu.Unlock()
}

// buildSPIFFEConfig parses conf, without touching the backend.
func buildSPIFFEConfig(conf map[string]any) (*SPIFFEAuthConfig, error) {
	config, err := mapToSPIFFEAuthConfig(conf)
	if err != nil {
		return nil, err
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = time.Hour
	}
	// Facts that do not compile are kept on the config, not returned: the
	// caller decides whether to refuse them or fail closed.
	config.CompileFields(spiffeBuiltinFacts())
	return config, nil
}

// normalizedSPIFFEConfig is config in the form storage holds, so a restart
// parses consistent types.
func normalizedSPIFFEConfig(config *SPIFFEAuthConfig) map[string]any {
	return map[string]any{
		"token_ttl":       config.TokenTTL.String(),
		"default_role":    config.DefaultRole,
		"bound_audiences": config.BoundAudiences,
		"max_age":         config.MaxAge.String(),
		"entity_kind":     config.EntityKind,
		"facts":           config.Facts,
	}
}

// loadConfig installs the persisted config, if any. It holds configWriteMu:
// the mount is routed before it is initialized, so a config write can already
// be under way, and loading storage over it would undo it.
func (b *spiffeAuthBackend) loadConfig(ctx context.Context) error {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	entry, err := b.storageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry == nil {
		return nil
	}
	var configMap map[string]any
	if err := entry.DecodeJSON(&configMap); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if err := b.setupSPIFFEConfig(ctx, configMap); err != nil {
		return fmt.Errorf("failed to setup spiffe config from storage: %w", err)
	}
	return nil
}

// Initialize loads persisted config and — since every mount of this type is a
// SPIFFE relying party — loads the trust-domain bundles (fail closed) and starts
// the federation refresh loop. Runs active-node only (ctx is the active context).
func (b *spiffeAuthBackend) Initialize(ctx context.Context) error {
	if b.storageView == nil {
		return nil
	}

	if err := b.loadConfig(ctx); err != nil {
		return err
	}

	// Fail closed: if the bundles cannot be loaded, the mount must not serve logins.
	if err := b.spiffe.RebuildBundleSet(ctx); err != nil {
		return fmt.Errorf("failed to load SPIFFE trust bundles: %w", err)
	}
	b.spiffe.StartFederationRefresh(ctx)
	return nil
}

// SensitiveConfigFields returns the config fields to mask. Trust-domain bundles
// live in the substrate store, not in config, so nothing here is masked.
func (b *spiffeAuthBackend) SensitiveConfigFields() []string { return nil }

const spiffeAuthHelp = `
The SPIFFE auth method authenticates workloads that present a SPIFFE SVID.

It accepts both SVID types on a single mount:
  - X.509-SVID: a TLS client certificate (direct mTLS or a trusted forwarding
    header), verified against the trust domain's X.509 authorities.
  - JWT-SVID:   a bearer JWT, verified against the trust domain's JWT authorities
    with a mandatory audience.

Trust is anchored per trust domain via bundles registered under trust-domain/,
which may be static or fetched via SPIFFE Federation. Roles bind a trust domain
to a set of token policies and optionally constrain the allowed SPIFFE IDs.

Configuration:
  POST /auth/{mount}/trust-domain/:name - Register a trust domain bundle
  POST /auth/{mount}/role/:name         - Create a role bound to a trust domain
  POST /auth/{mount}/login              - Authenticate with an X.509-SVID or JWT-SVID

The mount's entity_kind and facts name what it admits; bound_audiences is
stored for mount-level audience binding and not used by logins yet; max_age
bounds a credential's age at the role-free admission, not at role logins.
`
