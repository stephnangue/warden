package remotesign

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/logger"
)

// Payload keys of a transit capability, beyond the shared ones.
const (
	transitCapTokenKey     = "vault_token"
	transitCapAddressKey   = "vault_address"
	transitCapNamespaceKey = "vault_namespace"
	transitCapMountKey     = "transit_mount"
	transitCapKeyNameKey   = "transit_key"
	transitCapVersionKey   = "transit_key_version"
)

// TransitCapability is what a transit capability carries: a token that may sign with
// one key, where to present it, and the exact key version it was checked against.
type TransitCapability struct {
	Token     string
	Address   string
	Namespace string // optional
	Mount     string
	Ref       KeyRef // KeyName, a concrete Version, and Alg
	ExpiresAt time.Time
}

// EncodeTransitCapability is the payload a producer writes for c. It is exactly what
// DecodeCapability reads back, so the two ends cannot disagree on a name. Values are
// strings throughout: payloads are flattened to strings when stored.
func EncodeTransitCapability(c TransitCapability) map[string]interface{} {
	out := map[string]interface{}{
		CapabilityBackendKey:   BackendTypeTransit,
		transitCapTokenKey:     c.Token,
		transitCapAddressKey:   c.Address,
		transitCapMountKey:     c.Mount,
		transitCapKeyNameKey:   c.Ref.KeyName,
		transitCapVersionKey:   c.Ref.Version,
		CapabilityAlgKey:       c.Ref.Alg,
		CapabilityExpiresAtKey: c.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if c.Namespace != "" {
		out[transitCapNamespaceKey] = c.Namespace
	}
	return out
}

// transitCoords is a decoded transit capability, less what KeyRef holds.
type transitCoords struct {
	token     string
	address   string
	namespace string
	mount     string
}

type transitCodec struct{}

func (transitCodec) reserved() []string {
	return []string{
		transitCapTokenKey, transitCapAddressKey, transitCapNamespaceKey,
		transitCapMountKey, transitCapKeyNameKey, transitCapVersionKey,
	}
}

func (transitCodec) decode(data map[string]string) (any, KeyRef, error) {
	c := transitCoords{namespace: data[transitCapNamespaceKey]}
	var ref KeyRef
	for _, f := range []struct {
		key string
		dst *string
	}{
		{transitCapTokenKey, &c.token},
		{transitCapAddressKey, &c.address},
		{transitCapMountKey, &c.mount},
		{transitCapKeyNameKey, &ref.KeyName},
		{transitCapVersionKey, &ref.Version},
	} {
		if *f.dst = data[f.key]; *f.dst == "" {
			return nil, KeyRef{}, missingCapabilityKey(f.key)
		}
	}
	// The producer always writes the concrete version it resolved, never "latest", so
	// anything else is a stale or foreign payload.
	if _, err := transitVersion(ref.Version); err != nil {
		return nil, KeyRef{}, fmt.Errorf("%w: unusable key version %q", ErrCapabilityIncomplete, ref.Version)
	}
	return c, ref, nil
}

// classify decides whether a refused signature should cost the capability its place.
func (transitCodec) classify(err error) error {
	var respErr *api.ResponseError
	if !errors.As(err, &respErr) {
		// Unreachable, timed out, or failed before any answer. The capability is
		// probably fine; replacing it would not help and would evict something usable.
		return fmt.Errorf("failed to sign with the capability: %w", err)
	}
	signErr := &SignError{Status: respErr.StatusCode, Err: err}
	switch respErr.StatusCode {
	case http.StatusForbidden, http.StatusUnauthorized:
		// The token was refused: expired, or revoked under us.
		return fmt.Errorf("%w: %w", ErrCapabilityRejected, signErr)
	case http.StatusBadRequest:
		// Most often the pinned version fell below the key's minimum after a rotation,
		// which a new capability resolves by pinning the new version. A genuine fault
		// fails the same way on the retry and surfaces then.
		return fmt.Errorf("%w: %w", ErrCapabilityRejected, signErr)
	}
	// The store itself is unwell. Its answer stays readable, but a new capability
	// would be refused the same way.
	return fmt.Errorf("failed to sign with the capability: %w", signErr)
}

func (transitCodec) newPool(opts CapabilityOptions, log *logger.GatedLogger) capabilityPool {
	var transport http.RoundTripper
	if opts.HTTPClient != nil {
		transport = opts.HTTPClient.Transport
	}
	return &transitPool{transport: transport, log: log}
}

// transitPool keeps one token-less base client per store address and namespace. Each
// signature clones it and sets its own token on the clone, so the pool shares
// connections while no capability's token ever touches another's client.
type transitPool struct {
	transport http.RoundTripper // nil keeps the client default
	log       *logger.GatedLogger
	clients   sync.Map // address + "\x00" + namespace -> *pooledTransitClient
}

// pooledTransitClient is a base client and the http.Client it was built on. The clones
// share that http.Client, so closing its idle connections reaches theirs too.
type pooledTransitClient struct {
	client *api.Client
	http   *http.Client
}

func (p *transitPool) open(coords any) (SigningBackend, error) {
	c, ok := coords.(transitCoords)
	if !ok {
		return nil, fmt.Errorf("remotesign: not a transit capability")
	}
	base, err := p.base(c)
	if err != nil {
		return nil, err
	}
	client, err := base.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("remotesign: cannot prepare a signing client: %w", err)
	}
	client.SetToken(c.token)
	// Timeout 0 inherits the caller's deadline: the capability serves this signature.
	return NewTransitClientBackend(client, c.mount, 0, p.log)
}

func (p *transitPool) base(c transitCoords) (*api.Client, error) {
	key := c.address + "\x00" + c.namespace
	if v, ok := p.clients.Load(key); ok {
		return v.(*pooledTransitClient).client, nil
	}
	cfg := api.DefaultConfig()
	cfg.Address = c.address
	// DefaultConfig reads the process environment, and two of the values it picks up
	// would redirect this client away from the capability it is about to spend. An
	// agent address is preferred over Address when a request is built, so a stray one
	// would send the token somewhere the payload never named; a namespace would scope
	// the signing call to a tenant the capability was not minted for. Both are cleared
	// unconditionally — the payload is the only authority here.
	cfg.AgentAddress = ""
	if p.transport != nil {
		// Only the transport is taken from the consumer. Redirect handling stays the
		// client's own: it refuses to let the HTTP layer follow any redirect, and
		// itself follows at most one from the store, never from https to http.
		cfg.HttpClient.Transport = p.transport
	}
	built, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("remotesign: cannot reach the signing backend at %q: %w", c.address, err)
	}
	built.SetToken("")
	built.SetNamespace(c.namespace)
	// A loser of a first-use race drops its client unused; it opened no connections.
	v, _ := p.clients.LoadOrStore(key, &pooledTransitClient{client: built, http: cfg.HttpClient})
	return v.(*pooledTransitClient).client, nil
}

// closeIdle closes the idle connections of every pooled client, and with them those of
// the per-signature clones, which share each base client's http.Client.
func (p *transitPool) closeIdle() {
	p.clients.Range(func(_, v any) bool {
		v.(*pooledTransitClient).http.CloseIdleConnections()
		return true
	})
}
