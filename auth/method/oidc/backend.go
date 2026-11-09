// Package oidc is the auth method human operators sign in with: the OIDC
// authorization code flow with PKCE against their identity provider, driven
// by the warden CLI from a loopback redirect. A login issues a ticket token
// (logical.TokenTypeTicket): a self-contained session that core decodes on
// every request and that takes its role per request from the virtual groups
// matching the ID token's claims. The mount is called only to log in.
//
// The pending login lives in the OAuth state parameter, sealed with the
// mount's logical.Sealer, so the mount keeps no server-side state: an
// unauthenticated caller cannot fill memory, and a login survives a failover.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	capoidc "github.com/hashicorp/cap/oidc"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var (
	// errNotConfigured refuses a login on a mount with no configuration.
	errNotConfigured = errors.New("the oidc auth method is not configured")
	// errConfigInvalid refuses a login on a mount whose stored configuration
	// fails validation, or whose facts do not compile.
	errConfigInvalid = errors.New("the oidc auth method's configuration is invalid; rewrite it")
)

// oidcAuthBackend is the oidc auth method.
type oidcAuthBackend struct {
	*framework.Backend
	logger      *logger.GatedLogger
	storageView sdklogical.Storage
	sealer      logical.Sealer

	// configMu guards config and provider. The provider is built from the
	// config it sits beside; it is nil until built, which a login does on
	// first use when the identity provider was unreachable at load.
	configMu sync.RWMutex
	config   *oidcConfig
	provider *liveProvider

	// configWriteMu serializes config writes and the storage load: a write
	// merges onto the live config, so two racing would lose one writer's keys.
	configWriteMu sync.Mutex

	// mountFacts holds the naming in force and is shared by pointer with
	// every admission this mount produces, and so with every ticket it
	// issues: core reads it on each request a ticket makes.
	mountFacts *logical.MountFacts

	// newAssertion builds the client assertion of a private_key_jwt
	// exchange; tests replace it.
	newAssertion func(cfg *oidcConfig, tokenURL string) (string, error)
}

// liveProvider is a cap provider, what discovery told about it, and the
// logins using it. A provider replaced by a config write is retired: it is
// released (Done) once its last login finishes, never under one.
type liveProvider struct {
	*capoidc.Provider
	tokenURL string

	mu      sync.Mutex
	users   int
	retired bool
}

// acquire counts a login using p. Callers hold the backend's configMu, so no
// login acquires a provider after it is retired.
func (p *liveProvider) acquire() {
	p.mu.Lock()
	p.users++
	p.mu.Unlock()
}

// release ends a login's use of p, releasing p if it is retired and that was
// its last login.
func (p *liveProvider) release() {
	p.mu.Lock()
	p.users--
	done := p.retired && p.users == 0
	p.mu.Unlock()
	if done {
		p.Done()
	}
}

// retire marks p replaced, releasing it now if no login uses it.
func (p *liveProvider) retire() {
	p.mu.Lock()
	p.retired = true
	done := p.users == 0
	p.mu.Unlock()
	if done {
		p.Done()
	}
}

var _ logical.Factory = Factory

// Factory creates an oidc auth backend. It needs the mount's sealer, which
// core gives every auth mount: without it no login state can be sealed.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	if conf.Sealer == nil {
		return nil, errors.New("the oidc auth method needs a sealer, which only core provides")
	}
	b := &oidcAuthBackend{
		logger:       conf.Logger,
		storageView:  conf.StorageView,
		sealer:       conf.Sealer,
		mountFacts:   &logical.MountFacts{},
		newAssertion: newClientAssertion,
	}
	b.Backend = &framework.Backend{
		Help:         oidcAuthHelp,
		BackendType:  "oidc",
		BackendClass: logical.ClassAuth,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"auth_url", "callback"},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathAuthURL(),
			b.pathCallback(),
			// The mount admits no bearer: a ticket is admitted by core, and
			// the mount is never an auto_auth_path target.
			helper.AdmitPath(func(context.Context, *logical.Request, time.Time) (*logical.Admission, error) {
				return nil, nil
			}),
		},
		Clean: b.cleanup,
	}
	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Initialize loads the stored configuration. A configuration that fails
// validation is installed as invalid (readable, rewritable, refusing every
// login), and an identity provider that cannot be reached is not an error:
// the first login builds the provider. Either way the mount loads.
func (b *oidcAuthBackend) Initialize(ctx context.Context) error {
	if b.storageView == nil {
		return nil
	}
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	entry, err := b.storageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry == nil {
		return nil
	}
	var cfg oidcConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		b.logger.Error("oidc auth mount config is invalid; no login succeeds until it is rewritten", logger.Err(err))
		cfg.invalid = err
		b.installConfig(&cfg, nil)
		return nil
	}
	if err := cfg.FactsConfig.Err(); err != nil {
		b.logger.Error(helper.FactsDoNotCompileLog, logger.Err(err))
	}
	p, err := cfg.newProvider(ctx)
	if err != nil {
		b.logger.Warn("identity provider not reachable at load; the first login retries", logger.Err(err))
		p = nil
	}
	b.installConfig(&cfg, p)
	return nil
}

// installConfig makes cfg the live configuration, with its provider (nil when
// not built yet), and publishes its naming in the same critical section. The
// provider it replaces is retired.
func (b *oidcAuthBackend) installConfig(cfg *oidcConfig, p *liveProvider) {
	b.configMu.Lock()
	old := b.provider
	b.config = cfg
	b.provider = p
	b.mountFacts.Publish(cfg.Naming())
	b.configMu.Unlock()
	if old != nil {
		old.retire()
	}
}

// live returns the configuration in force and its provider, building the
// provider when it was not built at load, and the function the login calls
// when it is done with the provider. errNotConfigured when there is no
// configuration, errConfigInvalid when it is not usable.
func (b *oidcAuthBackend) live(ctx context.Context) (*oidcConfig, *liveProvider, func(), error) {
	b.configMu.RLock()
	cfg, p := b.config, b.provider
	if p != nil {
		p.acquire()
	}
	b.configMu.RUnlock()
	switch {
	case cfg == nil:
		return nil, nil, nil, errNotConfigured
	case cfg.invalid != nil || cfg.Naming() == nil:
		if p != nil {
			p.release()
		}
		return nil, nil, nil, errConfigInvalid
	case p != nil:
		return cfg, p, p.release, nil
	}

	built, err := cfg.newProvider(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	built.acquire()
	b.configMu.Lock()
	switch {
	case b.config != cfg:
		// A write replaced the config meanwhile: the provider serves this
		// login only, and is released after it.
		b.configMu.Unlock()
		built.retire()
	case b.provider != nil:
		// Another login built one first: use it, drop ours.
		p = b.provider
		p.acquire()
		b.configMu.Unlock()
		built.release()
		built.retire()
		return cfg, p, p.release, nil
	default:
		b.provider = built
		b.configMu.Unlock()
	}
	return cfg, built, built.release, nil
}

func (b *oidcAuthBackend) cleanup(context.Context) {
	b.configMu.Lock()
	p := b.provider
	b.provider = nil
	b.configMu.Unlock()
	if p != nil {
		p.retire()
	}
}

const oidcAuthHelp = `
The oidc auth method signs human operators in with their identity provider:
the OpenID Connect authorization code flow with PKCE, driven by the warden CLI
(warden login) from a loopback redirect.

A login issues a ticket token: a self-contained session, encrypted under
Warden's key, carrying the person's identity and the ID token claims the mount
maps. It carries no role: each request asks for one, and virtual groups over
those claims grant it. The session lasts session_ttl and cannot be revoked
before; disabling the mount ends every session it issued.

Configuration:
  POST /auth/{mount}/config     - Configure the identity provider and claims
  GET  /auth/{mount}/config     - Read the configuration (secrets are never returned)
Login (warden login drives both):
  POST /auth/{mount}/auth_url   - Start a login: the authorization URL and state
  POST /auth/{mount}/callback   - Finish it: exchange the code, issue the ticket
`
