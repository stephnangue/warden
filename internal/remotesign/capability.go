package remotesign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/logger"
)

// A signing capability is permission to sign with a key rather than the key itself:
// a short-lived credential scoped to one key, plus the coordinates naming that key.
// A producer mints one as a flat string map; a consumer decodes it and asks the store
// to sign. Both ends meet here, so the key names below are the whole contract between
// them — and, since capabilities are cached and chained, a released wire format.

// Payload keys every backend's capability carries.
const (
	CapabilityBackendKey   = "kms_backend"
	CapabilityAlgKey       = "signing_alg"
	CapabilityKidKey       = "kid"
	CapabilityExpiresAtKey = "token_expires_at"
)

var (
	// ErrCapabilityIncomplete marks a payload missing a coordinate, or carrying one
	// that cannot be used. Producers write every coordinate together, so this means a
	// payload from something else or from an older producer — a fresh one can fix it.
	ErrCapabilityIncomplete = errors.New("signing capability is incomplete")
	// ErrCapabilityRejected marks a capability the store refused to sign with: its
	// credential expired or was revoked, or its pinned version was retired. Minting a
	// new capability is the fix.
	ErrCapabilityRejected = errors.New("signing capability was refused")
	// ErrCapabilityUnsupported marks a backend this build cannot drive. A fresh
	// payload names the same backend, so nothing is gained by fetching one.
	ErrCapabilityUnsupported = errors.New("unsupported signing backend")
)

// The sentinels above carry no package prefix: they describe the capability, and are
// only ever seen wrapped in the consuming driver's own error.

// Capability is a decoded signing capability. The backend's own coordinates (its
// address, its credential) are held opaquely, so a consumer needs no knowledge of the
// store behind a capability to sign with it.
type Capability struct {
	Backend string
	Ref     KeyRef
	Kid     string
	// ExpiresAt is when the capability's credential expires, when the producer said.
	// Zero means it did not; a spent capability is then found by the store refusing it.
	ExpiresAt time.Time

	coords any
}

// SignError carries the HTTP status a store answered a refused signature with, in a
// form any caller can read through HTTPStatus whatever client produced the original
// error. The original stays in the chain.
type SignError struct {
	Status int
	Err    error
}

func (e *SignError) Error() string   { return e.Err.Error() }
func (e *SignError) HTTPStatus() int { return e.Status }
func (e *SignError) Unwrap() error   { return e.Err }

// capabilityCodec is what one backend implements to take part in capabilities. The
// codec itself is stateless; anything with a lifetime (pooled connections) lives in
// the pool it creates, which belongs to one consumer.
type capabilityCodec interface {
	// decode reads the backend's coordinates and key reference out of a payload. It
	// fills KeyName and Version; the shared fields are read by the caller. Failures
	// wrap ErrCapabilityIncomplete.
	decode(data map[string]string) (coords any, ref KeyRef, err error)
	// reserved lists the backend's own payload keys.
	reserved() []string
	// classify maps a failed signature to what a caller should do about it: it wraps
	// ErrCapabilityRejected where a new capability would help, and surfaces the
	// store's status as a *SignError.
	classify(err error) error
	// newPool creates the per-consumer state the codec signs through.
	newPool(opts CapabilityOptions, log *logger.GatedLogger) capabilityPool
}

// capabilityPool is one consumer's connection state for one backend.
type capabilityPool interface {
	// open returns a backend that signs with the capability's credential. The
	// credential must land only on what open returns, never on shared state:
	// concurrent callers hold different capabilities. Nor may it come from anywhere
	// but the capability — not the process environment, not a credentials file — or a
	// stray variable would sign in place of the capability it was handed. This runs
	// once per signature, so it should reuse pooled clients rather than build them.
	open(coords any) (SigningBackend, error)
	// closeIdle drops idle pooled connections. It must be safe alongside open and
	// in-flight signatures.
	closeIdle()
}

// capabilityCodecs is every backend that can appear in a capability. Fixed at init
// and only read afterwards.
var capabilityCodecs = map[string]capabilityCodec{
	BackendTypeTransit: transitCodec{},
}

// DecodeCapability reads a capability payload. It does no I/O.
//
// A missing or unusable coordinate wraps ErrCapabilityIncomplete; a backend this build
// does not know wraps ErrCapabilityUnsupported.
func DecodeCapability(data map[string]string) (*Capability, error) {
	backend := data[CapabilityBackendKey]
	if backend == "" {
		return nil, missingCapabilityKey(CapabilityBackendKey)
	}
	codec, ok := capabilityCodecs[backend]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrCapabilityUnsupported, backend)
	}
	coords, ref, err := codec.decode(data)
	if err != nil {
		return nil, err
	}

	alg := data[CapabilityAlgKey]
	if alg == "" {
		return nil, missingCapabilityKey(CapabilityAlgKey)
	}
	// Refused now rather than at signing time: by then it would surface as a signing
	// failure no refetch is asked to repair, although a fresh payload is exactly what
	// could name an alg this build can sign.
	if _, ok := algParamsByAlg[alg]; !ok {
		return nil, fmt.Errorf("%w: signing algorithm %q is not one this build can sign with", ErrCapabilityIncomplete, alg)
	}
	ref.Alg = alg

	c := &Capability{Backend: backend, Ref: ref, Kid: data[CapabilityKidKey], coords: coords}
	// Optional, and lenient: an unreadable expiry only costs the preflight, and the
	// store still refuses a spent credential.
	if raw := data[CapabilityExpiresAtKey]; raw != "" {
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			c.ExpiresAt = ts
		}
	}
	return c, nil
}

// ReservedCapabilityKeys is every payload key a backend's capability is built from,
// shared and backend-specific. A producer that lets an operator add arbitrary keys to
// a payload must refuse these: a passthrough named like a coordinate would replace it.
// kid and client_id are not reserved; they reach the payload through that passthrough.
// Nil for an unknown backend.
func ReservedCapabilityKeys(backend string) map[string]struct{} {
	codec, ok := capabilityCodecs[backend]
	if !ok {
		return nil
	}
	out := map[string]struct{}{
		CapabilityBackendKey: {}, CapabilityAlgKey: {}, CapabilityExpiresAtKey: {},
	}
	for _, k := range codec.reserved() {
		out[k] = struct{}{}
	}
	return out
}

// CapabilityOptions is a consumer's transport configuration, shared by every backend.
type CapabilityOptions struct {
	// HTTPClient, when set, lends its Transport — and with it the consumer's CA and
	// proxy settings — to signing requests. Only the Transport is taken: a backend
	// keeps its own timeout and redirect handling, which decide where a capability's
	// credential is sent and so are not the consumer's to widen. Nil leaves each
	// backend's default transport in place.
	HTTPClient *http.Client
}

// CapabilitySigners signs with decoded capabilities, pooling connections per backend
// so each signature costs one round trip and no connection setup. One belongs to one
// consumer; it is safe for concurrent use.
type CapabilitySigners struct {
	// pools is built in the constructor and only read afterwards, so it needs no lock.
	pools map[string]capabilityPool
}

// NewCapabilitySigners builds signers for every known backend. log may be nil.
func NewCapabilitySigners(log *logger.GatedLogger, opts CapabilityOptions) *CapabilitySigners {
	pools := make(map[string]capabilityPool, len(capabilityCodecs))
	for name, codec := range capabilityCodecs {
		pools[name] = codec.newPool(opts, log)
	}
	return &CapabilitySigners{pools: pools}
}

// SignJWS signs header and claims as a compact JWS with the capability's key. The
// alg comes from the capability, as SignCompactJWS always takes it from its argument.
//
// A refusal the store answered wraps ErrCapabilityRejected when a new capability would
// help, and exposes the store's status through SignError either way. An unreachable
// store wraps no sentinel: a new capability cannot mend a network.
func (s *CapabilitySigners) SignJWS(ctx context.Context, c *Capability, header map[string]string, claims map[string]interface{}) (string, error) {
	if c == nil {
		return "", errors.New("remotesign: no signing capability")
	}
	pool, ok := s.pools[c.Backend]
	codec := capabilityCodecs[c.Backend]
	if !ok || codec == nil {
		return "", fmt.Errorf("%w %q", ErrCapabilityUnsupported, c.Backend)
	}
	backend, err := pool.open(c.coords)
	if err != nil {
		return "", err
	}
	defer backend.Close()

	// No cached public key and no per-call timeout: the capability is used for this
	// one signature, and the caller's context bounds it.
	signer := NewSigner(backend, c.Ref, nil, 0)
	jws, err := SignCompactJWS(ctx, signer, c.Ref.Alg, header, claims)
	if err != nil {
		return "", codec.classify(err)
	}
	return jws, nil
}

// Close drops every pool's idle connections. Signing may continue afterwards; the
// pools reconnect on demand.
func (s *CapabilitySigners) Close() {
	for _, p := range s.pools {
		p.closeIdle()
	}
}

func missingCapabilityKey(key string) error {
	return fmt.Errorf("%w: it has no %q", ErrCapabilityIncomplete, key)
}
