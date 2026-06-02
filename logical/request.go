package logical

import (
	"net/http"

	"github.com/stephnangue/warden/credential"
)

// Operation is an enum that is used to specify the type
// of request being made
type Operation string

const (
	// The operations below are called per path
	CreateOperation Operation = "create"
	ReadOperation   Operation = "read"
	UpdateOperation Operation = "update"
	PatchOperation  Operation = "patch"
	DeleteOperation Operation = "delete"
	ListOperation   Operation = "list"
	ScanOperation   Operation = "scan"

	HelpOperation        Operation = "help"
	ResolveRoleOperation Operation = "resolve-role"
	HeaderOperation      Operation = "header"

	// The operations below are called globally, the path is less relevant.
	RevokeOperation   Operation = "revoke"
	RenewOperation    Operation = "renew"
	RollbackOperation Operation = "rollback"
)

// Request is a struct that stores the some parameters and context of a request
// being made to Warden. It is used to abstract the details of the higher level
// request protocol from the handlers.
type Request struct {
	// Operation is the requested operation type
	Operation Operation `json:"operation" structs:"operation" mapstructure:"operation"`

	// Request data is an opaque map that must have string keys.
	Data map[string]any `json:"map" structs:"data" mapstructure:"data"`

	// Path is the full path of the request
	Path string `json:"path" structs:"path" mapstructure:"path"`

	// MountPoint is provided so that a logical backend can generate
	// paths relative to itself. The `Path` is effectively the client
	// request path with the MountPoint trimmed off.
	MountPoint string `json:"mount_point" structs:"mount_point" mapstructure:"mount_point"`

	// MountType is provided so that a logical backend can make decisions
	// based on the specific mount type (e.g., if a mount type has different
	// aliases, generating different defaults depending on the alias)
	MountType string `json:"mount_type" structs:"mount_type" mapstructure:"mount_type"`

	MountClass string `json:"mount_class" structs:"mount_class" mapstructure:"mount_class"`

	// MountAccessor is provided so that identities returned by the authentication
	// backends can be tied to the mount it belongs to.
	MountAccessor string `json:"mount_accessor" structs:"mount_accessor" mapstructure:"mount_accessor"`

	// HTTPRequest, if set, can be used to access fields from the HTTP request
	// that generated this logical.Request object, such as the request body.
	HTTPRequest *http.Request `json:"-"`

	// ResponseWriter if set can be used to stream a response value to the http
	// request that generated this logical.Request object.
	ResponseWriter http.ResponseWriter `json:"-"`

	// Credential (for providers)
	Credential *credential.Credential

	// Authentication
	ClientToken string
	// ClientTokenAccessor is provided to the core so that the it can get
	// logged as part of request audit logging.
	ClientTokenAccessor string

	// logged as part of request audit logging.
	ClientTokenID string

	tokenEntry *TokenEntry

	// Request metadata
	ClientIP  string
	RequestID string

	// Whether the request is unauthenticated, as in, had no client token
	// attached. Useful in some situations where the client token is not made
	// accessible.
	Unauthenticated bool `json:"unauthenticated" structs:"unauthenticated" mapstructure:"unauthenticated"`

	// Streamed indicates this is a streaming request where the backend should
	// write directly to ResponseWriter rather than returning a Response.
	// Set by core routing when the path matches a streaming path.
	Streamed bool `json:"-"`

	// Transparent indicates this request came through transparent mode
	// (JWT-based implicit authentication). Credentials for transparent
	// requests are cache-only, not persisted to storage.
	Transparent bool `json:"-"`

	// StreamUnauthenticated marks this streaming request for upstream
	// pass-through without Warden authentication. Set by core when a
	// TransparentModeProvider's IsUnauthenticatedPath returns true —
	// either path-only (the static UnauthenticatedPaths list, e.g. Vault
	// PKI certificate PEM files) or request-aware (a provider hook that
	// inspects headers, e.g. Git smart-HTTP's first probe with no
	// Authorization header). Works regardless of whether transparent
	// mode is enabled.
	//
	// When true the core skips CheckToken, audit emission, credential
	// minting, and implicit auth. The streaming handler still runs but
	// receives req.Credential == nil, so handlers that previously assumed
	// a credential is always present must guard accordingly (see e.g.
	// the httpproxy gateway handler's StreamUnauthenticated guard).
	StreamUnauthenticated bool `json:"-"`

	// AuditPath is the normalized path used for audit logging. For streaming requests,
	// this is the path relative to the mount point (e.g., "role/operator/gateway/v1/...")
	// without the mount prefix. This field is set once before routing and remains
	// unchanged, ensuring consistent path logging between request and response audit entries.
	AuditPath string `json:"-"`

	// UpstreamURL is the target URL for proxied streaming requests (for audit logging).
	// Set by streaming handlers before forwarding the request to the upstream service.
	UpstreamURL string `json:"-"`

	// MCPDescriptor is populated by the core handler when the routed
	// backend opts into MCPPolicyEnforced and accepts the request for
	// MCP body-based policy enforcement. Nil for all other requests.
	// Read-only after extraction; the audit layer treats it as a
	// deep-copy field via MCPRequestDescriptor.Clone.
	MCPDescriptor *MCPRequestDescriptor `json:"-"`
}

func (r *Request) TokenEntry() *TokenEntry {
	return r.tokenEntry
}

func (r *Request) SetTokenEntry(te *TokenEntry) {
	r.tokenEntry = te
}
