package credential

import (
	"context"
	"time"
)

// Credential-chaining config keys. A consuming source/spec that needs a standing
// secret does not store it; it names another cred spec whose minted credential IS
// that secret ("secret_spec"), and Warden mints that spec as the same caller at
// use time, extracts the material, and hands it to the consuming driver.
const (
	// ConfigSecretSpec names a cred spec that yields the secret material. It may sit
	// on the consuming spec (spec-level, wins) or its source (source-level).
	ConfigSecretSpec = "secret_spec"

	// ConfigSecretField names which key of the referenced credential's Data carries
	// the single secret value. Optional: a single-key payload auto-detects, and a
	// typed referenced credential can fall back to its primary field.
	ConfigSecretField = "secret_field"

	// MaxSecretChainDepth bounds chaining: a referenced secret-spec may not itself
	// chain (one hop only). This also breaks any config-drift reference cycle rather
	// than letting the recursive mint recurse unboundedly.
	MaxSecretChainDepth = 1
)

// SecretMaterial carries the referenced secret-spec's minted data to a consuming
// driver's MintFromSecret. Data is the full key/value map (so a multi-secret driver
// can read several named keys directly); Field is the resolved single-secret key
// (may be empty when the consumer reads Data directly).
type SecretMaterial struct {
	Data  map[string]string
	Field string
}

// Secret returns the selected single secret value (Data[Field]), or "" when no
// field was resolved. Multi-secret consumers ignore this and read Data by name.
func (m SecretMaterial) Secret() string {
	if m.Field == "" {
		return ""
	}
	return m.Data[m.Field]
}

// Caller carries the requesting principal through the mint pipeline so a chained
// mint can re-mint a referenced secret-spec AS that caller (same tokenID for cache
// scoping, same identity for the assertion). Built by core; the credential package
// never derives it from caller-supplied input.
type Caller struct {
	// TokenID is the session token the minted credential is bound to and cached under.
	TokenID string
	// TokenTTL bounds a dynamic credential's cache/lease lifetime.
	TokenTTL time.Duration
	// ResolveInputs builds ExchangeInputs for an arbitrary spec name as this caller
	// (a nil result means the spec does not request exchange). Set only by core; it
	// is nil on non-request code paths, in which case a chained secret-spec that
	// needs exchange fails closed at mint time.
	ResolveInputs func(ctx context.Context, specName string) (*ExchangeInputs, error)

	// User is the secondary (user) principal for per-user credential chaining, or
	// nil for an agent-only request. It is identity for scoping only — never an
	// authorizer — and carries just the user token id, the one datum the manager
	// (this package) needs and cannot reach across the import boundary. The user's
	// identity (wardenSubject) and login-derived metadata are NOT duplicated here:
	// core reads them from the request's user token entry at the point of use (the
	// warden_user assertion claim and the audit stamp). Built by core.
	User *UserContext
}

// UserContext identifies the secondary (user) principal to the mint pipeline. It
// deliberately carries only the token id and TTL, NOT a *logical.TokenEntry: the
// logical package already imports credential (logical.Request.Credential is a
// *credential.Credential), so a token entry on a credential type would form a
// credential→logical→credential import cycle. Anything richer about the user
// (identity subject, metadata) is read by core from the request's user token entry
// where it is consumed (the warden_user assertion claim), not projected here.
type UserContext struct {
	// TokenID is the user token's ID — the per-user credential-cache dimension,
	// mirroring the agent's Caller.TokenID (both principals keyed by token id, not
	// identity, so the entry is bound to the token lifecycle: revoking or
	// re-logging-in the user yields a new id and thus a fresh mint).
	TokenID string

	// TokenTTL is the user token's remaining lifetime, mirroring the agent's
	// Caller.TokenTTL. The manager bounds the chained credential's cache/lease
	// duration by it alongside the agent's TokenTTL, so revoking or expiring EITHER
	// principal evicts the entry and stops new mints. Zero means "no bound from the
	// user side".
	TokenTTL time.Duration
}

// chainDepthCtxKey carries the current secret_spec recursion depth on the context.
type chainDepthCtxKey struct{}

// withChainDepth returns a context carrying the given chain depth.
func withChainDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, chainDepthCtxKey{}, depth)
}

// chainDepth reads the current secret_spec recursion depth (0 when unset).
func chainDepth(ctx context.Context) int {
	if d, ok := ctx.Value(chainDepthCtxKey{}).(int); ok {
		return d
	}
	return 0
}
