package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/stephnangue/warden/internal/remotesign"
)

// oidcKeySource abstracts where the issuer's signing keys come from: local
// in-process generation (the default) or an external KMS that holds the private
// key and signs remotely. Only the active node calls these — key generation and
// rotation are single-writer.
type oidcKeySource interface {
	// bootstrap returns a fresh active key and its pre-published next key for alg.
	bootstrap(ctx context.Context, alg string) (active, next *signingKey, err error)
	// nextKey returns a fresh pre-published next key for alg (rotation).
	nextKey(ctx context.Context, alg string) (*signingKey, error)
	// remote reports whether this source produces KMS-backed keys, so setup can
	// detect a change of key location against what is stored.
	remote() bool
}

// localKeySource generates RSA/ECDSA keys in process (the default). The private
// key lives in Warden's memory and is stored barrier-encrypted.
type localKeySource struct{}

func (localKeySource) bootstrap(_ context.Context, alg string) (*signingKey, *signingKey, error) {
	active, err := generateSigningKey(alg)
	if err != nil {
		return nil, nil, err
	}
	next, err := generateSigningKey(alg)
	if err != nil {
		return nil, nil, err
	}
	return active, next, nil
}

func (localKeySource) nextKey(_ context.Context, alg string) (*signingKey, error) {
	return generateSigningKey(alg)
}

func (localKeySource) remote() bool { return false }

// remoteKeySource provisions and signs with keys held in an external KMS: the
// active/next/retired model maps onto KMS key versions, and the private key never
// enters Warden. active/next are two distinct versions of the alg's key.
type remoteKeySource struct {
	backend remotesign.Backend
	timeout time.Duration
}

func (r remoteKeySource) bootstrap(ctx context.Context, alg string) (*signingKey, *signingKey, error) {
	// EnsureKey adopts (or creates) the key and returns its latest version as the
	// active key; NewVersion pre-publishes the successor.
	activeInfo, err := r.backend.EnsureKey(ctx, alg)
	if err != nil {
		return nil, nil, err
	}
	active, err := r.newRemoteSigningKey(activeInfo)
	if err != nil {
		return nil, nil, err
	}
	nextInfo, err := r.backend.NewVersion(ctx, alg)
	if err != nil {
		return nil, nil, err
	}
	next, err := r.newRemoteSigningKey(nextInfo)
	if err != nil {
		return nil, nil, err
	}
	return active, next, nil
}

func (r remoteKeySource) nextKey(ctx context.Context, alg string) (*signingKey, error) {
	info, err := r.backend.NewVersion(ctx, alg)
	if err != nil {
		return nil, err
	}
	return r.newRemoteSigningKey(info)
}

func (r remoteKeySource) remote() bool { return true }

// newRemoteSigningKey wraps a provisioned KMS key version as a signingKey. The kid
// is the RFC 7638 thumbprint of the public key — identical to a local key's kid
// and stable across restarts — and createdAt is the KMS-side creation time, so the
// rotation scheduler's anchor survives restarts.
func (r remoteKeySource) newRemoteSigningKey(info remotesign.KeyInfo) (*signingKey, error) {
	kid, err := signingKeyID(info.Public)
	if err != nil {
		return nil, err
	}
	signer := remotesign.NewSigner(r.backend, info.Ref, info.Public, r.timeout)
	return &signingKey{key: signer, alg: info.Ref.Alg, kid: kid, createdAt: info.CreatedAt}, nil
}

// isRemoteSigningKey reports whether a signing key is KMS-backed.
func isRemoteSigningKey(sk *signingKey) bool {
	if sk == nil {
		return false
	}
	_, ok := sk.key.(*remotesign.Signer)
	return ok
}

// oidcKeySetSourceMismatch reports whether any supported algorithm's active key
// cannot sign under the configured source, meaning the key location changed and a
// cutover is needed.
func oidcKeySetSourceMismatch(keysets map[string]*algKeyset, wantRemote bool) bool {
	for _, alg := range oidcSupportedAlgs {
		ks := keysets[alg]
		if ks == nil || ks.active == nil {
			continue
		}
		if oidcActiveKeyNeedsCutover(ks.active, wantRemote) {
			return true
		}
	}
	return false
}

// oidcActiveKeyNeedsCutover reports whether an active key must be replaced because
// it cannot sign under the configured source. For a local config, any remote key
// must go. For a remote config, a local key must go — AND a remote key that cannot
// sign (a different or removed backend left it verification-only) must go too, so
// adding a second backend type later cannot silently install an unusable key.
func oidcActiveKeyNeedsCutover(active *signingKey, wantRemote bool) bool {
	rs, isRemote := active.key.(*remotesign.Signer)
	if !wantRemote {
		return isRemote
	}
	if !isRemote {
		return true
	}
	return !rs.CanSign()
}

// retireOIDCKeysetsForCutover moves every supported algorithm's active and next
// keys into retired (stamped now) so they keep verifying in-flight assertions
// through the grace window, leaving each keyset incomplete so fresh keys are
// provisioned from the newly configured source. Unsupported (stray) algorithms are
// left untouched, matching the rest of the issuer's key management.
func retireOIDCKeysetsForCutover(keysets map[string]*algKeyset) {
	now := time.Now()
	for _, alg := range oidcSupportedAlgs {
		ks := keysets[alg]
		if ks == nil {
			continue
		}
		retired := append([]*signingKey(nil), ks.retired...)
		for _, k := range []*signingKey{ks.active, ks.next} {
			if k == nil {
				continue
			}
			kk := *k
			kk.retiredAt = now
			retired = append(retired, &kk)
		}
		keysets[alg] = &algKeyset{retired: retired}
	}
}

// signingKeyID computes the stable RFC 7638 JWK thumbprint kid for a public key,
// matching the kid generateSigningKey assigns to a local key of the same public
// half, so a key keeps its kid whether held locally or remotely.
func signingKeyID(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsaThumbprint(k), nil
	case *ecdsa.PublicKey:
		return ecThumbprint(k)
	default:
		return "", fmt.Errorf("oidc issuer: unsupported public key type %T", pub)
	}
}
