package logical

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
)

type Backend interface {
	// HandleRequest is used to handle a request and generate a response.
	// The backends must check the operation type and handle appropriately.
	HandleRequest(context.Context, *Request) (*Response, error)

	// Cleanup is invoked during an unmount of a backend to allow it to
	// handle any cleanup like connection closing or releasing of file handles.
	Cleanup(context.Context)

	// Setup is used to set up the backend based on the provided backend
	// configuration.
	Setup(context.Context, *BackendConfig) error

	// Initialize is used to initialize a backend after it has been mounted.
	Initialize(context.Context) error

	// Config is the opaque user configuration provided when mounting
	Config() map[string]any

	// Return the backend type
	Type() string

	// Return the backend class
	Class() BackendClass

	HandleExistenceCheck(ctx context.Context, req *Request) (checkFound bool, exists bool, err error)

	// SpecialPaths is a list of paths that are special in some way.
	// See PathType for the types of special paths. The key is the type
	// of the special path, and the value is a list of paths for this type.
	// This is not a regular expression but is an exact match. If the path
	// ends in '*' then it is a prefix-based match. The '*' can only appear
	// at the end.
	SpecialPaths() *Paths

	// ExtractTokens extracts the two principals a request may carry (just
	// extraction, no validation). Each provider has its own way to pass them.
	//
	//   agent — the primary principal's credential, which authorizes the
	//           request. "" means either no credential at all or "the TLS
	//           client certificate is the agent"; the distinction is resolved
	//           downstream by the core, which reads the cert from the request
	//           context.
	//   user  — the secondary, identity-only principal's credential, or "".
	//
	// userLeg reports whether this is a streaming gateway request on a mount
	// with an effective user_auth_path. When userLeg is false an implementation
	// MUST return user == "" and MUST resolve agent exactly as it did before
	// the user leg existed, including its own channel precedence.
	//
	// One sanctioned exception to that byte-identity rule: Authorization scheme
	// names are now matched case-insensitively everywhere, per RFC 7235, where
	// several providers previously compared them exactly. This widens what is
	// accepted (a lowercase "bearer"/"apikey"/"splunk" now resolves) and never
	// narrows it, so no request that worked before stops working.
	ExtractTokens(r *http.Request, userLeg bool) (agent, user string)
}

// BackendClass is the class of backend that is being implemented
type BackendClass uint32

// The these are the class of backends that can be derived from
// logical.Backend
const (
	ClassUnknown  BackendClass = 0 // This is also the zero-value for BackendClass
	ClassProvider BackendClass = 1
	ClassAuth     BackendClass = 2
	ClassSystem   BackendClass = 3
)

// Stringer implementation
func (b BackendClass) String() string {
	switch b {
	case ClassProvider:
		return "provider"
	case ClassAuth:
		return "auth"
	case ClassSystem:
		return "system"
	}

	return "unknown"
}

// BackendConfig is provided to the factory to initialize the backend
type BackendConfig struct {
	StorageView sdklogical.Storage

	// Logger should be used by the backend for logging
	Logger *logger.GatedLogger

	// Config is the opaque user configuration provided when mounting
	Config map[string]any

	// BackendUUID is a unique identifier provided to this backend
	BackendUUID string

	// RegisterShutdownHook registers a function to be called during application
	// shutdown (preSeal). The key ensures idempotency — registering the same key
	// multiple times only keeps one hook. Use this for process-level cleanup like
	// shared transport shutdown that must not run on individual unmount.
	RegisterShutdownHook func(key string, fn func())
}

// Factory is the factory function to create a logical backend.
type Factory func(context.Context, *BackendConfig) (Backend, error)

// SensitiveFieldsProvider can be implemented by backends to declare which config fields
// contain sensitive data that should be masked in API responses.
type SensitiveFieldsProvider interface {
	SensitiveConfigFields() []string
}

// TransparentModeProvider is implemented by providers that perform implicit authentication.
// Clients send requests with JWTs or TLS certificates directly — no explicit login step.
// Warden performs implicit authentication via a bound auth method.
type TransparentModeProvider interface {
	// IsTransparentMode returns whether the provider has an auth path configured
	IsTransparentMode() bool

	// GetAutoAuthPath returns the auth mount path for implicit authentication (e.g., "auth/jwt/")
	GetAutoAuthPath() string

	// GetAuthRole returns the role encoded in this request by the client —
	// typically a URL path segment (streaming backends) or a query parameter
	// (access backends). Excludes the X-Warden-Role header (which the caller
	// applies as a uniform override across all transparent providers) and the
	// mount-level default_role (returned by GetDefaultAuthRole). Returns ""
	// if the client did not encode a role.
	GetAuthRole(path string, req *Request) string

	// GetDefaultAuthRole returns the mount-level default_role config value.
	// Applied by core role-resolution only when GetAuthRole and any
	// TransparentAuthRoleExtractor hook both returned "". Returns "" if unset.
	GetDefaultAuthRole() string

	// IsUnauthenticatedPath checks if a request can be served without
	// authentication. Used for read-only endpoints that clients may access
	// without sending tokens (e.g., PKI certificate PEM files) and for
	// protocol probes that need to reach the upstream to negotiate auth
	// (e.g., Git smart-HTTP's initial /info/refs request, which expects the
	// upstream's WWW-Authenticate header so the client knows to retry with
	// credentials).
	//
	// The request is passed so backends carrying multiple protocols on the
	// same mount can inspect headers (e.g., presence of Authorization) and
	// decide per-request whether to bypass auth, rather than only per-path.
	// Implementations that don't need per-request behaviour ignore the
	// argument and return a static path-based decision.
	//
	// When this returns true the core sets req.StreamUnauthenticated, which
	// short-circuits CheckToken, audit emission, credential minting, and
	// implicit auth. The request reaches the streaming handler with
	// req.Credential == nil — handlers that previously assumed a credential
	// is always present must guard accordingly.
	IsUnauthenticatedPath(r *http.Request, path string) bool

	// IsTransparentPath checks if the given path (relative to mount) should trigger
	// transparent authentication. Streaming backends match gateway paths;
	// access backends match access/ paths.
	IsTransparentPath(path string) bool
}

// UserAuthConfigProvider is implemented by transparent providers that additionally
// authenticate a secondary, per-request USER principal from a second request header
// (secondary transparent authentication). It is deliberately kept separate from
// TransparentModeProvider so that adding per-user auth does not force every
// transparent provider (and every test fake) to implement it: a provider that does
// not opt in simply does not satisfy this interface, and req.User stays nil (feature
// off, request unchanged).
type UserAuthConfigProvider interface {
	// GetUserAuthPath returns the auth mount path that authenticates user
	// credentials (e.g., "auth/user-jwt/"), or "" when per-user auth is not
	// configured — in which case the feature is off and the request is unchanged.
	GetUserAuthPath() string

	// GetUserAuthRole returns the role used to authenticate the user credential,
	// or "" to fall back to the user auth mount's own default_role.
	GetUserAuthRole() string
}

// AuthorizationServerProvider is implemented by auth methods that can name the
// OAuth authorization server issuing the credentials they accept. It exists so
// the protected-resource metadata endpoint can derive `authorization_servers`
// from the auth mount an operator already configured, instead of asking them to
// restate the issuer.
//
// It is an interface rather than a concrete type assertion because auth backends
// are unexported in their own packages and reached only as logical.Backend.
type AuthorizationServerProvider interface {
	// AuthorizationServerURL returns the issuer URL a client should run OAuth
	// against, and whether one could be determined. ok is false when the mount
	// verifies tokens without knowing an issuer — a static-key or bare-JWKS
	// configuration — in which case there is nothing a client could discover
	// and the metadata endpoint must not guess.
	AuthorizationServerURL() (string, bool)
}

// TransparentAuthRoleExtractor can be implemented by providers that extract
// the auth role from protocol-specific request data (Authorization headers,
// Basic Auth username, etc.) rather than the URL path. Used by SigV4-compatible
// providers (AWS, Alibaba Cloud) where the role is embedded in the Authorization
// header's Credential field, and by Git-over-HTTPS where the role is the Basic
// Auth username. Returns the extracted role, or "" if the request carries no
// extractable role (caller falls back to default_role).
type TransparentAuthRoleExtractor interface {
	GetAuthRoleFromRequest(r *http.Request) string
}

// StreamBodyParser can be implemented by streaming backends that want the core
// to parse the request body into req.Data before policy evaluation, even for
// streaming requests. By default, streaming requests skip body parsing to avoid
// buffering large payloads. Backends that need req.Data for ACL/policy checks
// (e.g., Vault) should implement this interface and return true.
//
// The request is passed so backends carrying multiple protocols on the same
// mount can inspect the path/headers and disable parsing for the subset of
// requests where parsing would be wasteful or harmful (e.g. binary upload
// protocols). Implementations that don't need per-request behaviour ignore
// the argument and return a static per-backend value.
//
// When enabled, the core parses application/json and application/x-www-form-urlencoded
// bodies (up to maxRequestBodySize), restores the body for the provider to re-read,
// and populates req.Data before CheckToken runs.
type StreamBodyParser interface {
	ShouldParseStreamBody(r *http.Request) bool
}
