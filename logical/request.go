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
	CreateOperation         Operation = "create"
	ReadOperation           Operation = "read"
	UpdateOperation         Operation = "update"
	PatchOperation          Operation = "patch"
	DeleteOperation         Operation = "delete"
	ListOperation           Operation = "list"
	ScanOperation           Operation = "scan"
	HelpOperation           Operation = "help"
	ResolveRoleOperation    Operation = "resolve-role"
	HeaderOperation         Operation = "header"

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
    Credential     *credential.Credential

    // Authentication
    ClientToken     string
	// ClientTokenAccessor is provided to the core so that the it can get
	// logged as part of request audit logging.
	ClientTokenAccessor string 

	// logged as part of request audit logging.
	ClientTokenID   string

    tokenEntry      *TokenEntry

    // Request metadata
    ClientIP       string
    RequestID      string

	// Whether the request is unauthenticated, as in, had no client token
	// attached. Useful in some situations where the client token is not made
	// accessible.
	Unauthenticated bool `json:"unauthenticated" structs:"unauthenticated" mapstructure:"unauthenticated"`

	// Streamed indicates this is a streaming request where the backend should
	// write directly to ResponseWriter rather than returning a Response.
	// Set by core routing when the path matches a streaming path.
	Streamed bool `json:"-"`
}

func (r *Request) TokenEntry() *TokenEntry {
	return r.tokenEntry
}

func (r *Request) SetTokenEntry(te *TokenEntry) {
	r.tokenEntry = te
}
