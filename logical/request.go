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

	// User is the secondary, per-request principal — the human on whose behalf the
	// agent acts — resolved by secondary transparent authentication from a second
	// request header when the provider/namespace configures user_auth_path. It is
	// IDENTITY-ONLY: it never authorizes the request (the primary/agent token entry
	// alone does that) and is never SetTokenEntry'd. It scopes per-user credential
	// chaining: the assertion's user level, the per-user credential-cache
	// dimension, and audit attribution. Nil when the feature is unconfigured, which
	// keeps the request byte-identical to before.
	User *UserPrincipal `json:"-"`

	// TokenMetadata carries the authenticating token's verified, login-derived
	// Metadata into policy evaluation so token_metadata conditions can match
	// against it. Set from the token entry at the policy-check seam; never
	// compiled into the cached CBP, so a CBP shared across tokens with the
	// same policy set is still matched against each token's own metadata.
	//
	// Shared with the token entry it came from, which may share it further (a
	// cached token's metadata, or a membership rendered for every request of
	// one credential): read only.
	TokenMetadata map[string]string

	// roleGrant is the role this request runs under when its token takes its
	// role per request (an admission token), and hasRoleGrant says whether it
	// is set. Held by value, so resolving a grant allocates nothing; read it
	// through RoleGrant.
	roleGrant    RoleGrant
	hasRoleGrant bool

	// Discovery records how a request on an identity path was admitted
	// without a service token: the mounts that admitted the credential, how
	// many roles their groups grant it, or that it ran anonymously. For the
	// audit only; never disclosed to the caller. Nil on every other request.
	Discovery *DiscoveryAdmission `json:"-"`

	// SponsoredBy names the group a request on a sponsor path acted through
	// ("group:<name>"): the entity's sponsor, or for an accept (and a read by
	// one of its members) the pending handover. Set by the sponsor handlers on
	// success only; for the audit. Empty on every other request.
	SponsoredBy string `json:"-"`

	// RequestedRole is the role a transparent or ticket-admitted request asks
	// for (X-Warden-Role, the role/<name>/ segment, ?role=, the provider's
	// default_role), set by core alongside Transparent or TicketAdmitted and
	// never from client input directly. Empty when the request named none, or
	// is neither.
	RequestedRole string `json:"-"`

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

	// TicketAdmitted indicates core admitted the ticket token this request
	// presents, on this request: its seal was checked, so the request may ask
	// for a role (RequestedRole) as a transparent one does. Only core's ticket
	// hook sets it; it says nothing about transparent mode.
	TicketAdmitted bool `json:"-"`

	// Internal marks a request core builds and routes in process, never one
	// that arrived over HTTP. Paths that hand back in-process values (an auth
	// mount's introspect/admit returns a *Admission) refuse a request without
	// it. Only core sets it, on requests it routes itself; the HTTP layer
	// never does, and it is not decoded from JSON.
	Internal bool `json:"-"`

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

	// MCPListFilter is set by the policy layer when an allowed MCP list
	// request (tools/list, resources/list, prompts/list, skills/list,
	// resources/directory/read) should have its response filtered to the
	// items the caller may actually use. Nil for every other request; a
	// gateway that sees nil streams the response through verbatim. See
	// MCPListFilter.
	MCPListFilter *MCPListFilter `json:"-"`

	// MCPListFilters is MCPListFilter for an in-process MCP server
	// (MCPInProcessServer): one filter per list method the body calls, keyed
	// by the lowercased method, so every list call of a batch is filtered.
	// Nil when no list call needs filtering.
	MCPListFilters map[string]*MCPListFilter `json:"-"`
}

func (r *Request) TokenEntry() *TokenEntry {
	return r.tokenEntry
}

func (r *Request) SetTokenEntry(te *TokenEntry) {
	r.tokenEntry = te
}

// RoleGrant returns the role grant core resolved for this request, or nil when
// none is set: the request's token carries its role itself, or no token was
// checked. The grant lives inside r, so the pointer is valid as long as r is,
// and it is r's goroutine's to read.
func (r *Request) RoleGrant() *RoleGrant {
	if r == nil || !r.hasRoleGrant {
		return nil
	}
	return &r.roleGrant
}

// SetRoleGrant stores g as the request's role grant and returns it in place.
// Core calls it, and ClearRoleGrant, from one place: where it resolves the
// grant. Neither allocates.
func (r *Request) SetRoleGrant(g RoleGrant) *RoleGrant {
	r.roleGrant, r.hasRoleGrant = g, true
	return &r.roleGrant
}

// ClearRoleGrant removes the request's role grant.
func (r *Request) ClearRoleGrant() {
	r.roleGrant, r.hasRoleGrant = RoleGrant{}, false
}

// UserPrincipal is a request's secondary (user) principal: a first-class Warden
// TokenEntry resolved from a second request header via the existing auth methods,
// exactly as the primary/agent credential is. It carries both the validated token
// entry — the source of the user's identity and login-derived metadata — and the
// raw user credential, which the token-exchange driver forwards verbatim as an
// RFC 8693 subject_token. It is identity-only: it is never the request's primary
// principal and never authorizes the request on its own.
type UserPrincipal struct {
	// TokenEntry is the validated user token entry — the source of the user's
	// identity and its login-derived Metadata.
	TokenEntry *TokenEntry

	// RawToken is the raw user credential as presented in the request header,
	// retained so the token-exchange driver can forward it as an RFC 8693
	// subject_token. It is a bearer secret: kept off audit serialization and
	// stripped from every upstream-forwarding header list.
	RawToken string
}
