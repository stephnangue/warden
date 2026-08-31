package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/internal/remotesign"
	"github.com/stephnangue/warden/logger"
)

// oidcIssuerStorePrefix is the barrier-view prefix under which the issuer's
// signing keys are stored. Everything written through a barrier view is
// encrypted at rest, so the private keys are sealed.
const oidcIssuerStorePrefix = "core/oidc-issuer/"

// oidcKeySetPath is the storage key (within the barrier view) of the issuer's
// keyset (active plus retired-but-unexpired keys).
const oidcKeySetPath = "keyset"

// storedSigningKey is the barrier-encrypted storage format of one signing key.
// Exactly one of KeyPKCS8 (a local in-process key) or Remote (an external-KMS
// handle) is set.
type storedSigningKey struct {
	Kid       string           `json:"kid"`
	Alg       string           `json:"alg"`
	KeyPKCS8  string           `json:"key_pkcs8,omitempty"` // local key: base64(std) PKCS#8 DER (RSA or ECDSA)
	Remote    *storedRemoteKey `json:"remote,omitempty"`    // external KMS handle; no private material
	CreatedAt time.Time        `json:"created_at"`
	RetiredAt time.Time        `json:"retired_at,omitempty"`
}

// storedRemoteKey is the storage format of a KMS-backed key: a handle plus the
// cached PKIX PEM public key, so unseal and JWKS never need a KMS round-trip. No
// private key material is stored.
type storedRemoteKey struct {
	Backend      string `json:"backend"` // e.g. "transit"
	KeyName      string `json:"key_name"`
	KeyVersion   int    `json:"key_version"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// storedAlgKeyset is one algorithm's stored active + pre-published next + retired
// keys.
type storedAlgKeyset struct {
	Active  storedSigningKey   `json:"active"`
	Next    storedSigningKey   `json:"next"`
	Retired []storedSigningKey `json:"retired,omitempty"`
}

// storedKeySet is the versioned keyset: one storedAlgKeyset per signing algorithm,
// keyed by JWS alg.
type storedKeySet struct {
	Version int                        `json:"version"`
	Keysets map[string]storedAlgKeyset `json:"keysets"`
}

func toStored(sk *signingKey) (storedSigningKey, error) {
	out := storedSigningKey{Kid: sk.kid, Alg: sk.alg, CreatedAt: sk.createdAt, RetiredAt: sk.retiredAt}
	// A KMS-backed key has no exportable private material — persist only its handle
	// and cached public key.
	if rs, ok := sk.key.(*remotesign.Signer); ok {
		pemStr, err := remotesign.MarshalPublicKeyPEM(rs.Public())
		if err != nil {
			return storedSigningKey{}, fmt.Errorf("oidc issuer: %w", err)
		}
		ref := rs.Ref()
		out.Remote = &storedRemoteKey{
			Backend:      rs.BackendType(),
			KeyName:      ref.KeyName,
			KeyVersion:   ref.Version,
			PublicKeyPEM: pemStr,
		}
		return out, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(sk.key)
	if err != nil {
		return storedSigningKey{}, fmt.Errorf("oidc issuer: marshal signing key: %w", err)
	}
	out.KeyPKCS8 = base64.StdEncoding.EncodeToString(der)
	return out, nil
}

// fromStored reconstructs a signing key. For a remote key it builds a
// signing-capable signer when backend matches the stored backend type, otherwise
// a verification-only signer so the key still verifies its in-flight assertions in
// the JWKS. The verification-only case arises on the active node after a
// remote->local cutover (the signer stanza was removed, so backend is nil) or for
// retired keys left behind by a previously-configured backend. backend may be nil.
func fromStored(s storedSigningKey, backend remotesign.Backend, timeout time.Duration) (*signingKey, error) {
	if s.Remote != nil {
		pub, err := remotesign.ParsePublicKeyPEM(s.Remote.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("oidc issuer: %w", err)
		}
		// The kid is a pure function of the public key; a mismatch means the stored
		// handle and public key disagree (corruption or tampering).
		kid, err := signingKeyID(pub)
		if err != nil {
			return nil, err
		}
		if kid != s.Kid {
			return nil, fmt.Errorf("oidc issuer: stored remote key kid mismatch (stored %q, computed %q)", s.Kid, kid)
		}
		ref := remotesign.KeyRef{KeyName: s.Remote.KeyName, Version: s.Remote.KeyVersion, Alg: s.Alg}
		var signer crypto.Signer
		if backend != nil && backend.Type() == s.Remote.Backend {
			signer = remotesign.NewSigner(backend, ref, pub, timeout)
		} else {
			signer = remotesign.NewVerifyingSigner(s.Remote.Backend, ref, pub)
		}
		return &signingKey{key: signer, alg: s.Alg, kid: s.Kid, createdAt: s.CreatedAt, retiredAt: s.RetiredAt}, nil
	}

	der, err := base64.StdEncoding.DecodeString(s.KeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: decode stored key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: parse stored key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("oidc issuer: stored signing key is not a crypto.Signer (%T)", parsed)
	}
	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return nil, fmt.Errorf("oidc issuer: unsupported stored signing key type %T", parsed)
	}
	return &signingKey{key: signer, alg: s.Alg, kid: s.Kid, createdAt: s.CreatedAt, retiredAt: s.RetiredAt}, nil
}

// persistKeySet writes the per-algorithm keyset map to storage (barrier-encrypted).
// Every algorithm's keyset requires both an active and a next key: the issuer
// always keeps a pre-published next ready to promote, so a keyset missing either
// is invalid.
func persistKeySet(ctx context.Context, storage sdklogical.Storage, keysets map[string]*algKeyset) error {
	if len(keysets) == 0 {
		return fmt.Errorf("oidc issuer: cannot persist an empty keyset")
	}
	set := storedKeySet{Version: 4, Keysets: make(map[string]storedAlgKeyset, len(keysets))}
	for alg, ks := range keysets {
		if ks == nil || ks.active == nil {
			return fmt.Errorf("oidc issuer: cannot persist %s keyset with no active key", alg)
		}
		if ks.next == nil {
			return fmt.Errorf("oidc issuer: cannot persist %s keyset with no next key", alg)
		}
		storedActive, err := toStored(ks.active)
		if err != nil {
			return err
		}
		storedNext, err := toStored(ks.next)
		if err != nil {
			return err
		}
		sk := storedAlgKeyset{Active: storedActive, Next: storedNext}
		for _, r := range ks.retired {
			sr, err := toStored(r)
			if err != nil {
				return err
			}
			sk.Retired = append(sk.Retired, sr)
		}
		set.Keysets[alg] = sk
	}
	data, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("oidc issuer: marshal keyset: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcKeySetPath, Value: data})
}

// loadKeySet reads the per-algorithm keyset map from storage. It returns (nil, nil)
// when none has been persisted yet, so the caller can decide to generate the keys.
// backend (and its per-call timeout) reconstructs signing-capable remote keys; pass
// nil to reconstruct any remote keys as verification-only.
func loadKeySet(ctx context.Context, storage sdklogical.Storage, backend remotesign.Backend, timeout time.Duration, log *logger.GatedLogger) (map[string]*algKeyset, error) {
	entry, err := storage.Get(ctx, oidcKeySetPath)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: read keyset: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var set storedKeySet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return nil, fmt.Errorf("oidc issuer: unmarshal keyset: %w", err)
	}
	// Fail loudly on an unrecognized version rather than silently regenerating over
	// (and destroying) an existing keyset. No pre-v4 migration is written: the
	// feature is not yet released, so a stale keyset is cleared and re-created by
	// hand, not migrated.
	if set.Version != 4 {
		return nil, fmt.Errorf("oidc issuer: unsupported keyset version %d (expected 4)", set.Version)
	}
	keysets := make(map[string]*algKeyset, len(set.Keysets))
	for alg, sk := range set.Keysets {
		active, err := fromStored(sk.Active, backend, timeout)
		if err != nil {
			return nil, err
		}
		next, err := fromStored(sk.Next, backend, timeout)
		if err != nil {
			return nil, err
		}
		ks := &algKeyset{active: active, next: next}
		for _, sr := range sk.Retired {
			r, err := fromStored(sr, backend, timeout)
			if err != nil {
				// A retired key only verifies soon-to-expire assertions; a corrupt one
				// must not brick unseal (unlike active/next, which fail loud above).
				// Drop it — a mismatched key could not verify anything anyway.
				if log != nil {
					log.Warn("oidc issuer: dropping unreadable retired signing key", logger.String("alg", alg), logger.String("kid", sr.Kid), logger.Err(err))
				}
				continue
			}
			ks.retired = append(ks.retired, r)
		}
		keysets[alg] = ks
	}
	return keysets, nil
}
