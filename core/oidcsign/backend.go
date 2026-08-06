// Package oidcsign provides remote signing backends for the OIDC issuer's
// signing keys, so an operator can hold the private key in an external KMS (e.g.
// an OpenBao/Vault transit engine) where it never leaves the KMS. Warden keeps
// only a handle plus the public key and asks the KMS to sign each assertion.
//
// The package has no dependency on the core package: a Backend produces a
// crypto.Signer (Signer) that drops into the issuer's signingKey.key seam, and
// signing/verification flow through the standard crypto.Signer / crypto.PublicKey
// interfaces. Cloud KMS and PKCS#11/HSM backends can be added by implementing
// Backend without touching the issuer.
package oidcsign

import (
	"context"
	"crypto"
	"errors"
	"io"
	"time"
)

// ErrRotationUnsupported is returned by a Backend whose keys are provisioned and
// rotated out-of-band (e.g. an HSM referenced by label): NewVersion is not a
// programmatic operation there, and the caller degrades to operator-managed
// rotation. The transit backend supports rotation and never returns this.
var ErrRotationUnsupported = errors.New("oidcsign: backend does not support programmatic key rotation")

// KeyRef names one immutable key version in the backend. Alg is carried so a
// stateless Sign call can select the signing parameters (hash, and PKCS#1 v1.5
// vs the KMS default) without inspecting key material.
type KeyRef struct {
	KeyName string
	Version int
	Alg     string // JWS alg, e.g. "RS256" / "ES256"
}

// KeyInfo is a provisioned key version and its public half.
type KeyInfo struct {
	Ref       KeyRef
	Public    crypto.PublicKey // *rsa.PublicKey or *ecdsa.PublicKey
	CreatedAt time.Time        // KMS-side creation time; anchors rotation scheduling
}

// Backend provisions and signs with keys whose private half never leaves the KMS.
//
// Create/rotate are optional capabilities: a backend whose keys are provisioned
// out-of-band (HSM/KMIP) implements EnsureKey as "adopt an existing key by
// reference" and may return ErrRotationUnsupported from NewVersion.
type Backend interface {
	// Type is the persisted discriminator, e.g. "transit".
	Type() string
	// EnsureKey ensures alg's key exists (idempotent) and returns its latest version.
	EnsureKey(ctx context.Context, alg string) (KeyInfo, error)
	// NewVersion rotates alg's key and returns the new latest version, or
	// ErrRotationUnsupported for out-of-band-managed backends.
	NewVersion(ctx context.Context, alg string) (KeyInfo, error)
	// PublicKey fetches one specific version's public key.
	PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error)
	// Sign signs an already-hashed digest with the exact version in ref, honoring
	// the crypto.Signer contract: RSA -> PKCS#1 v1.5 raw bytes; ECDSA -> ASN.1 DER.
	Sign(ctx context.Context, ref KeyRef, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	// Close releases resources (e.g. stops token renewal).
	Close()
}

// algParams maps a JWS alg to the backend-neutral signing parameters. Duplicated
// from the core alg table by value (these are standard wire constants) to keep
// this package free of a core import.
type algParams struct {
	transitKeyType string      // transit key type, e.g. "rsa-2048"
	hashName       string      // transit hash_algorithm, e.g. "sha2-256"
	hash           crypto.Hash // the digest the caller must have used
	isRSA          bool
}

var algParamsByAlg = map[string]algParams{
	"RS256": {transitKeyType: "rsa-2048", hashName: "sha2-256", hash: crypto.SHA256, isRSA: true},
	"RS384": {transitKeyType: "rsa-3072", hashName: "sha2-384", hash: crypto.SHA384, isRSA: true},
	"ES256": {transitKeyType: "ecdsa-p256", hashName: "sha2-256", hash: crypto.SHA256, isRSA: false},
	"ES384": {transitKeyType: "ecdsa-p384", hashName: "sha2-384", hash: crypto.SHA384, isRSA: false},
}

// Signer adapts one (Backend, KeyRef) pair to crypto.Signer, so it drops into the
// issuer's signingKey.key. It holds no private key material — Sign reaches the
// backend. A nil backend makes it verification-only (Public works; Sign fails
// closed), used for retired remote keys after a cutover or once the stanza is
// removed.
type Signer struct {
	backend     Backend
	backendType string // persisted discriminator, retained even when backend is nil
	ref         KeyRef
	pub         crypto.PublicKey
	timeout     time.Duration
	ctx         context.Context // optional request-scoped context bound via WithContext
}

// NewSigner builds a signing-capable Signer bound to a live backend.
func NewSigner(backend Backend, ref KeyRef, pub crypto.PublicKey, timeout time.Duration) *Signer {
	bt := ""
	if backend != nil {
		bt = backend.Type()
	}
	return &Signer{backend: backend, backendType: bt, ref: ref, pub: pub, timeout: timeout}
}

// NewVerifyingSigner builds a verification-only Signer (no live backend): Public
// works, Sign fails closed. Used to reconstruct a retired remote key after a
// cutover, or when the signer stanza has been removed — it keeps the key in the
// JWKS so its in-flight assertions still verify. backendType is retained so the
// key re-serializes as remote.
func NewVerifyingSigner(backendType string, ref KeyRef, pub crypto.PublicKey) *Signer {
	return &Signer{backendType: backendType, ref: ref, pub: pub}
}

// Public returns the cached public key (never a KMS round-trip).
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Ref returns the backend key reference this signer is bound to.
func (s *Signer) Ref() KeyRef { return s.ref }

// BackendType returns the backend discriminator ("transit"), retained even for a
// verification-only signer so it round-trips through storage as a remote key.
func (s *Signer) BackendType() string { return s.backendType }

// CanSign reports whether this signer has a live backend (vs verification-only).
func (s *Signer) CanSign() bool { return s.backend != nil }

// Sign signs an already-hashed digest by asking the backend, under a per-call
// timeout bounded further by any context bound via WithContext.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.backend == nil {
		return nil, errors.New("oidcsign: no signing backend for this key (verification-only)")
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	return s.backend.Sign(ctx, s.ref, digest, opts)
}

// WithContext returns a shallow copy bound to ctx, so the mint request's
// deadline/cancellation reaches the backend round-trip. Implements the optional
// interface signJWT type-asserts.
func (s *Signer) WithContext(ctx context.Context) crypto.Signer {
	cp := *s
	cp.ctx = ctx
	return &cp
}
