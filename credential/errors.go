package credential

import "errors"

var (
	// ErrTypeNotFound is returned when a credential type is not found in the registry
	ErrTypeNotFound = errors.New("credential type not found")

	// ErrTypeAlreadyRegistered is returned when attempting to register a duplicate credential type
	ErrTypeAlreadyRegistered = errors.New("credential type already registered")

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
)
