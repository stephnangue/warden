package credential

import (
	"errors"
	"fmt"
)

var (
	// ErrTypeNotFound is returned when a credential type is not found in the registry
	ErrTypeNotFound = errors.New("credential type not found")

	// ErrTypeAlreadyRegistered is returned when attempting to register a duplicate credential type
	ErrTypeAlreadyRegistered = errors.New("credential type already registered")

	// ErrAssertionProfileNotFound is returned when an assertion profile is not found in the registry
	ErrAssertionProfileNotFound = errors.New("assertion profile not found")

	// ErrAssertionProfileAlreadyRegistered is returned when attempting to register a duplicate assertion profile
	ErrAssertionProfileAlreadyRegistered = errors.New("assertion profile already registered")

	// ErrAssertionProfileNameReserved is returned when attempting to register an
	// assertion profile under a name that collides with a sibling spec-config value
	// (an exchange grant, a *_token_source value, or a token-type/typ value).
	ErrAssertionProfileNameReserved = errors.New("assertion profile name is reserved")

	// ErrAssertionProfileInvalid is returned when a profile is structurally unfit to
	// register — currently, an empty typ header.
	ErrAssertionProfileInvalid = errors.New("invalid assertion profile")

	// ErrDriverNotFound is returned when a driver is not found in the registry
	ErrDriverNotFound = errors.New("driver not found")

	// ErrDriverAlreadyRegistered is returned when attempting to register a duplicate driver factory
	ErrDriverAlreadyRegistered = errors.New("driver factory already registered")

	// ErrInvalidCredential is returned when credential validation fails
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrRevocationFailed is returned when credential revocation fails
	ErrRevocationFailed = errors.New("credential revocation failed")

	// ErrDriverCreationFailed is returned when driver creation failed
	ErrDriverCreationFailed = errors.New("driver creation failed")

	// ErrDriverConfigChanged is returned when a driver was built from a source
	// config that stopped being current before the instance could be installed.
	// The caller re-reads the source and tries again; it is not surfaced to users.
	ErrDriverConfigChanged = errors.New("source config changed while building driver")

	// ErrCredentialManagerStopped is returned when a driver is requested from a
	// credential manager that has stopped, as it does when the node stops being
	// active.
	ErrCredentialManagerStopped = errors.New("credential manager stopped")

	// ErrCredentialNotFound is returned when a credential is not found in storage
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrSpecAlreadyExists is returned when attempting to register a spec that already exists
	ErrSpecAlreadyExists = errors.New("credential spec already exists")

	// ErrSourceAlreadyExists is returned when attempting to register a source that already exists
	ErrSourceAlreadyExists = errors.New("credential source already exists")

	// ErrRefreshTokenRejected is returned when an OAuth2 provider rejects the
	// refresh token (RFC 6749 invalid_grant). It signals the minting layer that
	// the sealed token may have been rotated by another node, so it should
	// re-read the latest spec and retry the refresh once.
	ErrRefreshTokenRejected = errors.New("oauth2 refresh token rejected")

	// ErrUserRequired is returned (wrapped) when a spec needs a USER principal
	// and the request carried none. It is a sentinel rather than a status because
	// this package cannot import logical — that would cycle — so the HTTP status
	// is attached where the error surfaces: GetErrorCode maps it to 401, and the
	// request handler pairs that with a WWW-Authenticate challenge pointing at
	// the mount's protected resource metadata.
	//
	// 401 rather than 400 because it is exactly the "you need to authenticate,
	// here is where" case: a client that can acquire a user identity should be
	// able to, retry, and succeed. A malformed spec is a different failure.
	ErrUserRequired = errors.New("a user principal is required but none was presented")

	// ErrReservedPrincipal is returned (wrapped) when a user principal begins with
	// WardenSubjectPrefix. That prefix names agents: a delegation assertion carries
	// the user's raw principal as its sub, and a verifier that binds agents by a
	// "wid:<namespace>:" sub prefix would read such a user as an agent — of any
	// namespace, since the prefix does not depend on where the user logged in.
	// Like ErrUserRequired it is a sentinel so core attaches the status: 403, since
	// the identity was verified and is refused, and presenting it again cannot
	// succeed.
	ErrReservedPrincipal = errors.New("the user principal uses the reserved agent subject prefix " + WardenSubjectPrefix)

	// ErrChainedSecretRejected is returned (wrapped) by a chained-secret consuming
	// driver when the downstream rejects the fetched secret — e.g. an OAuth
	// invalid_client, or a 401 from a resource. It signals the manager that a
	// cached chained secret may be stale (rotated at the source): the manager
	// evicts the cache entry and retries the mint once. A consuming driver wraps
	// it via fmt.Errorf("...: %w", credential.ErrChainedSecretRejected).
	ErrChainedSecretRejected = errors.New("chained secret rejected by downstream")

	// ErrChainedSecretIncomplete is returned (wrapped) by a chained-secret consuming
	// driver when the fetched payload is missing something the driver needs — a half
	// of a client credential, say — and so cannot be spent at all. Unlike
	// ErrChainedSecretRejected nothing downstream refused it; the material never
	// reached a request.
	//
	// It evicts for the same reason a rejection does, and this is the case where the
	// distinction matters: a cached payload that predates the key it now has to carry
	// would otherwise fail every mint for the whole of secret_cache_ttl, with the one
	// mechanism that could recover it never firing. Refetching costs a single read and
	// answers the question the cache cannot — whether the payload has since been
	// completed at the source.
	ErrChainedSecretIncomplete = errors.New("chained secret material is incomplete")

	// ErrUserChallenge is returned (wrapped, through UserChallengeError) when the
	// upstream refused to act for the user until the user does something: re-acquire
	// a token that satisfies a claims challenge (MFA, Conditional Access), or
	// present a token that is still usable. Like ErrUserRequired it is a sentinel so
	// the HTTP status is attached where the error surfaces: GetErrorCode maps it to
	// 401 and the request handler renders the challenge into WWW-Authenticate.
	//
	// 401 rather than the 403 an upstream 4xx otherwise becomes: the client can fix
	// this by authenticating the user again, and should be told so.
	ErrUserChallenge = errors.New("the user must re-authenticate")
)

// User challenge codes. They are the only values a challenge may carry as its
// WWW-Authenticate error, so nothing an upstream wrote can reach the header.
const (
	// UserChallengeInsufficientClaims asks the client to re-acquire the user's token
	// satisfying Claims (RFC 6750 §3.1 extension used by Entra claims challenges).
	UserChallengeInsufficientClaims = "insufficient_claims"

	// UserChallengeInvalidToken says the user's token cannot be used at all —
	// expired, revoked, or minted for the wrong audience.
	UserChallengeInvalidToken = "invalid_token"
)

// UserChallengeError carries what the user has to do. Code is one of the
// UserChallenge* constants. Claims is the claims request the user's next token
// must satisfy, as compact JSON re-marshalled by the driver (never an upstream
// string copied through). TenantID names the tenant the client re-authenticates
// in, and AuthorizationURI the authorize endpoint it re-authenticates at — both
// built by the driver from validated config, never from the upstream's answer.
// Interaction marks an invalid_token challenge that a silent token refresh will
// not clear: the user must sign in interactively (Entra's interaction_required
// with no claims request). Cause is the upstream failure, kept for logs and status.
type UserChallengeError struct {
	Code             string
	Claims           string
	TenantID         string
	AuthorizationURI string
	Interaction      bool
	Cause            error
}

func (e *UserChallengeError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("%s (%s)", ErrUserChallenge, e.Code)
	}
	return fmt.Sprintf("%s (%s): %v", ErrUserChallenge, e.Code, e.Cause)
}

// Unwrap exposes both the sentinel and the upstream failure, so errors.Is finds
// ErrUserChallenge and UpstreamStatus still finds the upstream's status.
func (e *UserChallengeError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrUserChallenge}
	}
	return []error{ErrUserChallenge, e.Cause}
}
