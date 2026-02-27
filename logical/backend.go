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

    // ExtractToken extracts token value from request (just extraction, no validation).
    // Returns empty string if no token found.
	// Each provider has it own way to pass token.
	// This will be used by the core to extract the provided token.
    ExtractToken(r *http.Request) string
}

// BackendClass is the class of backend that is being implemented
type BackendClass uint32

// The these are the class of backends that can be derived from
// logical.Backend
const (
	ClassUnknown    BackendClass = 0 // This is also the zero-value for BackendClass
	ClassProvider   BackendClass = 1
	ClassAuth       BackendClass = 2
	ClassSystem     BackendClass = 3
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

	// ValidTokenTypes is the list of valid token types that can be used by auth backends
	ValidTokenTypes []string

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

// TransparentModeProvider can be implemented by providers that support transparent mode,
// enabling loginless operation where clients send requests with JWTs directly.
// Warden performs implicit authentication via a bound auth method.
type TransparentModeProvider interface {
	// IsTransparentMode returns whether transparent mode is enabled for this provider
	IsTransparentMode() bool

	// GetAutoAuthPath returns the auth mount path for implicit authentication (e.g., "auth/jwt/")
	GetAutoAuthPath() string

	// GetTransparentRole extracts the role name from the request path
	// For path pattern /role/{role}/gateway/*, returns the role
	// Returns empty string if path doesn't match transparent pattern
	GetTransparentRole(path string) string

	// IsUnauthenticatedPath checks if a path can be accessed without authentication
	// in transparent mode. Used for read-only endpoints that clients may access
	// without sending tokens (e.g., PKI certificate PEM files).
	IsUnauthenticatedPath(path string) bool
}

// StreamBodyParser can be implemented by streaming backends that want the core
// to parse the request body into req.Data before policy evaluation, even for
// streaming requests. By default, streaming requests skip body parsing to avoid
// buffering large payloads. Backends that need req.Data for ACL/policy checks
// (e.g., Vault) should implement this interface and return true.
//
// When enabled, the core parses application/json and application/x-www-form-urlencoded
// bodies (up to maxRequestBodySize), restores the body for the provider to re-read,
// and populates req.Data before CheckToken runs.
type StreamBodyParser interface {
	ShouldParseStreamBody() bool
}