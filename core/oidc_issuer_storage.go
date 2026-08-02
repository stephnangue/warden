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
)

// oidcIssuerStorePrefix is the barrier-view prefix under which the issuer's
// signing keys are stored. Everything written through a barrier view is
// encrypted at rest, so the private keys are sealed.
const oidcIssuerStorePrefix = "core/oidc-issuer/"

// oidcKeySetPath is the storage key (within the barrier view) of the issuer's
// keyset (active plus retired-but-unexpired keys).
const oidcKeySetPath = "keyset"

// storedSigningKey is the barrier-encrypted storage format of one signing key.
type storedSigningKey struct {
	Kid       string    `json:"kid"`
	Alg       string    `json:"alg"`
	KeyPKCS8  string    `json:"key_pkcs8"` // base64(std) PKCS#8 DER (RSA or ECDSA)
	CreatedAt time.Time `json:"created_at"`
	RetiredAt time.Time `json:"retired_at,omitempty"`
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
	der, err := x509.MarshalPKCS8PrivateKey(sk.key)
	if err != nil {
		return storedSigningKey{}, fmt.Errorf("oidc issuer: marshal signing key: %w", err)
	}
	return storedSigningKey{
		Kid:       sk.kid,
		Alg:       sk.alg,
		KeyPKCS8:  base64.StdEncoding.EncodeToString(der),
		CreatedAt: sk.createdAt,
		RetiredAt: sk.retiredAt,
	}, nil
}

func fromStored(s storedSigningKey) (*signingKey, error) {
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
	set := storedKeySet{Version: 3, Keysets: make(map[string]storedAlgKeyset, len(keysets))}
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
func loadKeySet(ctx context.Context, storage sdklogical.Storage) (map[string]*algKeyset, error) {
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
	// (and destroying) an existing keyset. No pre-v3 migration is written: the
	// feature is not yet released, so a stale keyset is cleared and re-created by
	// hand, not migrated.
	if set.Version != 3 {
		return nil, fmt.Errorf("oidc issuer: unsupported keyset version %d (expected 3)", set.Version)
	}
	keysets := make(map[string]*algKeyset, len(set.Keysets))
	for alg, sk := range set.Keysets {
		active, err := fromStored(sk.Active)
		if err != nil {
			return nil, err
		}
		next, err := fromStored(sk.Next)
		if err != nil {
			return nil, err
		}
		ks := &algKeyset{active: active, next: next}
		for _, sr := range sk.Retired {
			r, err := fromStored(sr)
			if err != nil {
				return nil, err
			}
			ks.retired = append(ks.retired, r)
		}
		keysets[alg] = ks
	}
	return keysets, nil
}
