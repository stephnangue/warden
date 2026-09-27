package drivers

import (
	"context"
	"errors"
	"fmt"
	"time"

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
func (d *TokenExchangeDriver) signAssertionWithCapability(ctx context.Context, c *remotesign.Capability, claims map[string]interface{}) (string, error) {
	// Cheaper than discovering the same thing from a refused signature, and it keeps a
	// spent capability distinguishable from a broken one.
	if !c.ExpiresAt.IsZero() && time.Now().Add(kmsCapabilitySkew).After(c.ExpiresAt) {
		return "", fmt.Errorf("token_exchange: the fetched signing capability expired at %s: %w",
			c.ExpiresAt.Format(time.RFC3339), credential.ErrChainedSecretRejected)
	}

	header := map[string]string{}
	if c.Kid != "" {
		header["kid"] = c.Kid
	}
	assertion, err := d.capSigners.SignJWS(ctx, c, header, claims)
	if err != nil {
		return "", capabilityError(err)
	}
	return assertion, nil
}

// capabilityError adds the chaining sentinel a capability failure calls for, keeping
// the original in the chain so the store's status stays readable. A backend this build
// cannot drive gets no sentinel: refetching yields the same backend.
func capabilityError(err error) error {
	switch {
	case errors.Is(err, remotesign.ErrCapabilityIncomplete):
		return fmt.Errorf("token_exchange: %w: %w", err, credential.ErrChainedSecretIncomplete)
	case errors.Is(err, remotesign.ErrCapabilityRejected):
		return fmt.Errorf("token_exchange: %w: %w", err, credential.ErrChainedSecretRejected)
	}
	return fmt.Errorf("token_exchange: %w", err)
}
