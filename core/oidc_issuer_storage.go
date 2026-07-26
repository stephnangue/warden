package core

import (
	"context"
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

// storedSigningKey is the barrier-encrypted storage format of one RSA signing key.
type storedSigningKey struct {
	Kid       string    `json:"kid"`
	Alg       string    `json:"alg"`
	KeyPKCS8  string    `json:"key_pkcs8"` // base64(std) PKCS#8 DER of the RSA private key
	CreatedAt time.Time `json:"created_at"`
	RetiredAt time.Time `json:"retired_at,omitempty"`
}

// storedKeySet is the versioned keyset: the active signing key plus retired keys
// still published in the JWKS so in-flight assertions verify.
type storedKeySet struct {
	Version int                `json:"version"`
	Active  storedSigningKey   `json:"active"`
	Retired []storedSigningKey `json:"retired,omitempty"`
}

func toStored(sk *signingKey) (storedSigningKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(sk.key)
	if err != nil {
		return storedSigningKey{}, fmt.Errorf("oidc issuer: marshal signing key: %w", err)
	}
	return storedSigningKey{
		Kid:       sk.kid,
		Alg:       oidcSigningAlg,
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
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("oidc issuer: stored signing key is not RSA")
	}
	return &signingKey{key: rsaKey, kid: s.Kid, createdAt: s.CreatedAt, retiredAt: s.RetiredAt}, nil
}

// persistKeySet writes the active + retired keys to storage (barrier-encrypted).
func persistKeySet(ctx context.Context, storage sdklogical.Storage, active *signingKey, retired []*signingKey) error {
	if active == nil {
		return fmt.Errorf("oidc issuer: cannot persist a keyset with no active key")
	}
	storedActive, err := toStored(active)
	if err != nil {
		return err
	}
	set := storedKeySet{Version: 1, Active: storedActive}
	for _, r := range retired {
		sr, err := toStored(r)
		if err != nil {
			return err
		}
		set.Retired = append(set.Retired, sr)
	}
	data, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("oidc issuer: marshal keyset: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcKeySetPath, Value: data})
}

// loadKeySet reads the keyset from storage. It returns (nil, nil, nil) when none
// has been persisted yet, so the caller can decide to generate a key.
func loadKeySet(ctx context.Context, storage sdklogical.Storage) (active *signingKey, retired []*signingKey, err error) {
	entry, err := storage.Get(ctx, oidcKeySetPath)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc issuer: read keyset: %w", err)
	}
	if entry == nil {
		return nil, nil, nil
	}
	var set storedKeySet
	if err := json.Unmarshal(entry.Value, &set); err != nil {
		return nil, nil, fmt.Errorf("oidc issuer: unmarshal keyset: %w", err)
	}
	active, err = fromStored(set.Active)
	if err != nil {
		return nil, nil, err
	}
	for _, sr := range set.Retired {
		r, err := fromStored(sr)
		if err != nil {
			return nil, nil, err
		}
		retired = append(retired, r)
	}
	return active, retired, nil
}
