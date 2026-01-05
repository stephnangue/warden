package logical

import "net/http"

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

	// OriginalPath is the original and unmodified path of the request
	// AWS provider for example needs the original path for sigV4 verification
	OriginalPath string `json:"original_path" structs:"original_path" mapstructure:"original_path"`

	// MountPoint is provided so that a logical backend can generate
	// paths relative to itself. The `Path` is effectively the client
	// request path with the MountPoint trimmed off.
	MountPoint string `json:"mount_point" structs:"mount_point" mapstructure:"mount_point"`

	// MountType is provided so that a logical backend can make decisions
	// based on the specific mount type (e.g., if a mount type has different
	// aliases, generating different defaults depending on the alias)
	MountType string `json:"mount_type" structs:"mount_type" mapstructure:"mount_type"`

	// MountAccessor is provided so that identities returned by the authentication
	// backends can be tied to the mount it belongs to.
	MountAccessor string `json:"mount_accessor" structs:"mount_accessor" mapstructure:"mount_accessor"`

	// HTTPRequest, if set, can be used to access fields from the HTTP request
	// that generated this logical.Request object, such as the request body.
	HTTPRequest *http.Request `json:"-"`

	// ResponseWriter if set can be used to stream a response value to the http
	// request that generated this logical.Request object.
	ResponseWriter http.ResponseWriter `json:"-"`
}