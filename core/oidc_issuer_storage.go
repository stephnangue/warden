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
// signing key is stored. Everything written through a barrier view is encrypted
// at rest, so the private key is sealed.
const oidcIssuerStorePrefix = "core/oidc-issuer/"

// oidcSigningKeyPath is the storage key (within the barrier view) of the active
// signing key.
const oidcSigningKeyPath = "signing-key"

// storedSigningKey is the versioned, barrier-encrypted storage format of the
// issuer's RSA signing key.
type storedSigningKey struct {
	Version   int       `json:"version"`
	Kid       string    `json:"kid"`
	Alg       string    `json:"alg"`
	KeyPKCS8  string    `json:"key_pkcs8"` // base64(std) PKCS#8 DER of the RSA private key
	CreatedAt time.Time `json:"created_at"`
}

// persistSigningKey writes sk to storage (barrier-encrypted). The caller holds a
// barrier view (e.g. NewBarrierView(c.barrier, oidcIssuerStorePrefix)).
func persistSigningKey(ctx context.Context, storage sdklogical.Storage, sk *signingKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(sk.key)
	if err != nil {
		return fmt.Errorf("oidc issuer: marshal signing key: %w", err)
	}
	stored := storedSigningKey{
		Version:   1,
		Kid:       sk.kid,
		Alg:       oidcSigningAlg,
		KeyPKCS8:  base64.StdEncoding.EncodeToString(der),
		CreatedAt: sk.createdAt,
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("oidc issuer: marshal stored key: %w", err)
	}
	return storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcSigningKeyPath, Value: data})
}

// loadSigningKey reads the signing key from storage. It returns (nil, nil) when
// no key has been persisted yet, so the caller can decide to generate one.
func loadSigningKey(ctx context.Context, storage sdklogical.Storage) (*signingKey, error) {
	entry, err := storage.Get(ctx, oidcSigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: read signing key: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var stored storedSigningKey
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("oidc issuer: unmarshal stored key: %w", err)
	}
	der, err := base64.StdEncoding.DecodeString(stored.KeyPKCS8)
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
	return &signingKey{key: rsaKey, kid: stored.Kid, createdAt: stored.CreatedAt}, nil
}
