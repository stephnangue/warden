package drivers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/remotesign"
)

// kmsCapabilitySkew is how far ahead of a capability's expiry it is treated as already
// spent. Building and sending an assertion is not instantaneous, and a capability that
// expires mid-flight fails at the token endpoint as an opaque client-auth error rather
// than as the expiry it is.
const kmsCapabilitySkew = 10 * time.Second

// signAssertionWithCapability signs the client assertion with a key the capability
// names but Warden cannot read.
//
// Errors are mapped deliberately. Anything meaning "this capability is spent" carries
// ErrChainedSecretRejected, so the minting layer discards the cached one and mints a
// fresh capability — the same self-healing a rotated secret gets. Anything meaning "the
// KMS is unreachable" carries no sentinel at all: a refetch cannot mend a network, and
// evicting a perfectly good capability would turn a blip into a stampede.
func (d *TokenExchangeDriver) signAssertionWithCapability(ctx context.Context, m *kmsSignerMaterial, claims map[string]interface{}) (string, error) {
	// Cheaper than discovering the same thing from a refused signature, and it keeps a
	// spent capability distinguishable from a broken one.
	if !m.expiresAt.IsZero() && time.Now().Add(kmsCapabilitySkew).After(m.expiresAt) {
		return "", fmt.Errorf("token_exchange: the fetched signing capability expired at %s: %w",
			m.expiresAt.Format(time.RFC3339), credential.ErrChainedSecretRejected)
	}

	client, err := d.kmsClient(m)
	if err != nil {
		return "", err
	}
	backend, err := remotesign.NewTransitClientBackend(client, m.mount, 0, d.logger)
	if err != nil {
		return "", fmt.Errorf("token_exchange: %w", err)
	}
	defer backend.Close()

	header := map[string]string{}
	if m.kid != "" {
		header["kid"] = m.kid
	}
	signer := remotesign.NewSigner(backend,
		remotesign.KeyRef{KeyName: m.keyName, Version: m.keyVersion, Alg: m.alg}, nil, 0)

	assertion, err := remotesign.SignCompactJWS(ctx, signer, m.alg, header, claims)
	if err != nil {
		return "", classifyCapabilitySignError(err)
	}
	return assertion, nil
}

// classifyCapabilitySignError decides whether a failed signature should cost the
// capability its place in the cache.
func classifyCapabilitySignError(err error) error {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusForbidden, http.StatusUnauthorized:
			// The token was rejected: expired, or revoked under us. A fresh capability
			// is exactly the fix.
			return fmt.Errorf("token_exchange: the signing capability was refused: %w", credential.ErrChainedSecretRejected)
		case http.StatusBadRequest:
			// Most often the pinned version has fallen below the key's minimum after a
			// rotation, which re-minting resolves by picking up the new version. A
			// genuine configuration fault fails the same way on the retry and surfaces
			// then — one extra fetch, and the manager retries only once.
			return fmt.Errorf("token_exchange: the signing request was refused (%w): %w", err, credential.ErrChainedSecretRejected)
		}
	}
	// Unreachable, timed out, or the KMS itself is unwell. The capability is probably
	// fine; refetching would not help and would evict something still usable.
	return fmt.Errorf("token_exchange: failed to sign the client assertion remotely: %w", err)
}

// kmsClient returns a client for the capability's address, cloned from a pooled base so
// the connection pool is shared while the token stays per-request. The token must never
// land on a shared client: concurrent mints hold different capabilities, and one
// overwriting another's token would sign with the wrong key or none.
func (d *TokenExchangeDriver) kmsClient(m *kmsSignerMaterial) (*api.Client, error) {
	key := m.address + "\x00" + m.namespace
	base, ok := d.kmsClients.Load(key)
	if !ok {
		cfg := api.DefaultConfig()
		cfg.Address = m.address
		// DefaultConfig reads the process environment, and two of the values it picks
		// up would redirect this client away from the capability it is about to spend.
		// An agent address is preferred over Address when the request is built, so a
		// stray one would send the token somewhere the payload never named; a namespace
		// would scope the signing call to a tenant the capability was not minted for.
		// Both are cleared unconditionally — the payload is the only authority here.
		cfg.AgentAddress = ""
		built, err := api.NewClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("token_exchange: cannot reach the signing backend at %q: %w", m.address, err)
		}
		built.SetToken("")
		built.SetNamespace(m.namespace)
		base, _ = d.kmsClients.LoadOrStore(key, built)
	}

	client, err := base.(*api.Client).CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("token_exchange: cannot prepare a signing client: %w", err)
	}
	client.SetToken(m.token)
	return client, nil
}
