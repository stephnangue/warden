package audit

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// LogEntry represents a single audit log entry
type LogEntry struct {
	Type      string    `json:"type"` // "request" or "response"
	Timestamp time.Time `json:"timestamp"`

	// Request information (always present)
	Request *Request `json:"request"`

	// Response information (only for response entries)
	Response *Response `json:"response,omitempty"`

	// Authentication context
	Auth *Auth `json:"auth,omitempty"`

	// Error from the operation (if any)
	Error string `json:"error,omitempty"`
}

// Request contains audit information about the request
type Request struct {
	// Identifiers
	ID        string `json:"id"`        // Request ID
	Operation string `json:"operation"` // create, read, update, delete, list, stream

	// Path information
	Path       string `json:"path"`                  // Full request path
	MountPoint string `json:"mount_point,omitempty"` // Mount point prefix
	MountType  string `json:"mount_type,omitempty"`  // Backend type (vault, aws, jwt)
	MountClass string `json:"mount_class,omitempty"` // provider, auth, system, audit

	// HTTP details. Headers and the body are not fields of the entry: they
	// carry the caller's credentials, and after routing the credentials minted
	// for the upstream. A policy condition still records the values it read
	// from the body, under auth.policy_results.condition.inputs.
	Method   string `json:"method"` // GET, POST, PUT, DELETE
	ClientIP string `json:"client_ip"`

	// Namespace context
	NamespaceID   string `json:"namespace_id,omitempty"`
	NamespacePath string `json:"namespace_path,omitempty"`

	// Flags
	Unauthenticated bool `json:"unauthenticated,omitempty"`
	Streamed        bool `json:"streamed,omitempty"`
	Transparent     bool `json:"transparent,omitempty"`
}

// Response contains audit information about the response
type Response struct {
	// HTTP response. Headers and the body are not fields of the entry, as for
	// the request: a login's body holds the token it issued.
	StatusCode    int    `json:"status_code"`
	StatusMessage string `json:"status_message,omitempty"`

	// Mount context (from response)
	MountClass string `json:"mount_class,omitempty"`

	// Flags
	Streamed bool `json:"streamed,omitempty"`

	// Warnings
	Warnings []string `json:"warnings,omitempty"`

	// Credential issued (if any) - for provider requests
	Credential *Credential `json:"credential,omitempty"`

	// Auth result (for login responses)
	AuthResult *AuthResult `json:"auth_result,omitempty"`

	// UpstreamURL is the target URL for proxied streaming requests
	UpstreamURL string `json:"upstream_url,omitempty"`
}

// Auth contains authentication context for the request
type Auth struct {
	// Token information (hash-based ID, safe to log)
	TokenID       string `json:"token_id,omitempty"`
	TokenAccessor string `json:"token_accessor,omitempty"`
	TokenType     string `json:"token_type,omitempty"`

	// Principal/Identity
	PrincipalID string `json:"principal_id,omitempty"`
	RoleName    string `json:"role_name,omitempty"`

	// MountAccessor is the accessor of the auth mount that admitted the
	// credential; empty for a token no mount issued (root).
	MountAccessor string `json:"mount_accessor,omitempty"`

	// AliasName is the native identity the credential presented, as the
	// admitting mount derived it (its alias_name_source). Salted like
	// PrincipalID; omittable.
	AliasName string `json:"alias_name,omitempty"`

	// EntityKind is the kind of entity the admitting mount admits (agent or
	// human).
	EntityKind string `json:"entity_kind,omitempty"`

	// RoleGrantedBy names the group that granted RoleName ("group:<name>")
	// when the token takes its role per request; empty for a token that
	// carries its role itself.
	RoleGrantedBy string `json:"role_granted_by,omitempty"`

	// RoleDeniedReason says why no role was granted (e.g. "not assumable");
	// set only on a refused grant, so at most one of it and RoleGrantedBy is.
	RoleDeniedReason string `json:"role_denied_reason,omitempty"`

	// Groups are the caller's groups, sorted, when the token takes its role
	// per request. Operator-chosen names, not salted.
	Groups []string `json:"groups,omitempty"`

	// SponsoredBy names the sponsor group a request on a sponsor path acted
	// through ("group:<name>"): the entity's sponsor, or the pending handover
	// a member accepted. Set on success only.
	SponsoredBy string `json:"sponsored_by,omitempty"`

	// Policies
	Policies      []string       `json:"policies,omitempty"`
	PolicyResults *PolicyResults `json:"policy_results,omitempty"`

	// Token lifecycle
	TokenTTL  int64 `json:"token_ttl,omitempty"`  // Seconds remaining
	ExpiresAt int64 `json:"expires_at,omitempty"` // Unix timestamp

	// AuthTime is when the person behind the credential last authenticated
	// to its identity provider (Unix timestamp), when the credential records
	// it (a ticket does).
	AuthTime int64 `json:"auth_time,omitempty"`

	// Namespace binding
	NamespaceID   string `json:"namespace_id,omitempty"`
	NamespacePath string `json:"namespace_path,omitempty"`

	// Creation context
	CreatedByIP string `json:"created_by_ip,omitempty"`

	// Actor chain — the verified RFC 8693 "act" delegation chain from the
	// authenticated token (the JWT "act" claim per RFC 8693 §4.1). Like every
	// field at this level, it describes the AGENT; the user token's own chain is
	// User.Actors.
	Actors []ActorRef `json:"actors,omitempty"`

	// User is the secondary (user) principal the agent acted for, captured by
	// secondary transparent authentication. Present only when a user credential
	// was resolved for the request; nil otherwise. Identity only — the raw user
	// credential is never logged.
	User *UserAttribution `json:"user,omitempty"`

	// Discovery is how a request on a discovery endpoint was admitted without
	// a service token; nil on every other request.
	Discovery *DiscoveryAuth `json:"discovery,omitempty"`
}

// DiscoveryAuth records how a discovery request was admitted: the auth
// mounts that admitted the presented credential and the roles granted there,
// or that it ran anonymously.
type DiscoveryAuth struct {
	AdmittedBy   []AdmittedMount `json:"admitted_by,omitempty"`
	RolesGranted int             `json:"roles_granted"`
	Anonymous    bool            `json:"anonymous,omitempty"`
	// CredentialUnverified: an anonymous request presented a credential that
	// was neither checked nor used.
	CredentialUnverified bool `json:"credential_unverified,omitempty"`
}

// AdmittedMount is one auth mount that admitted a discovery credential.
type AdmittedMount struct {
	Mount       string `json:"mount"`
	PrincipalID string `json:"principal_id,omitempty"`
	// AliasName is the native identity the credential presented there,
	// salted like PrincipalID.
	AliasName string `json:"alias_name,omitempty"`
}

// UserAttribution records the secondary (user) principal in an audit entry so a
// per-user credential mint is attributable to the human it was performed for. It
// carries identity only — the raw user credential is never logged.
type UserAttribution struct {
	// Subject is the user's raw principal (their auth-method subject, e.g. the
	// JWT sub) — the same value a default-profile delegation assertion carries as
	// its top-level sub.
	Subject string `json:"subject,omitempty"`
	// TokenID is the user token's hash-based ID (safe to log).
	TokenID string `json:"token_id,omitempty"`
	// NamespaceID is the user token's namespace.
	NamespaceID string `json:"namespace_id,omitempty"`
	// NamespacePath is the user token's namespace path, as the agent's
	// Auth.NamespacePath records the agent's: the stored path, so empty (and
	// omitted) for the root namespace. A delegation assertion's warden_namespace
	// carries the same path, rendered "root" for the root namespace.
	NamespacePath string `json:"namespace_path,omitempty"`
	// RoleName is the auth role the user's token was validated under (the mount's
	// user auth role) — the warden_role a delegation assertion carries for the user.
	RoleName string `json:"role_name,omitempty"`
	// Actors is the user token's OWN verified RFC 8693 "act" chain, outermost
	// first — who handled the user's token before the agent presented it. A
	// delegation assertion nests it under the agent as prior actors. Distinct from
	// Auth.Actors, which is the agent token's chain.
	Actors []ActorRef `json:"actors,omitempty"`
}

// ActorRef identifies one party in an RFC 8693 "act" delegation chain. Every actor
// is cryptographically attested by an IdP (the JWT "act" claim), so there is no
// unverified variant.
type ActorRef struct {
	Subject string `json:"subject"`
	// Issuer is the act layer's "iss", recorded only when the inbound layer carried
	// one — the context Subject is interpreted in.
	Issuer string `json:"issuer,omitempty"`
}

// PolicyResults captures which policies granted access
type PolicyResults struct {
	Allowed          bool     `json:"allowed"`
	GrantingPolicies []string `json:"granting_policies,omitempty"`

	// MCPDecision carries the decision an MCP-shaped request reached,
	// populated on both outcomes: a contract was consulted and allowed or
	// denied the call, or no contract was in scope at all and the request
	// was refused with no_mcp_policy. The absence case is the one worth
	// recording loudest — it is an operator misconfiguration, not a caller
	// overstepping.
	//
	// nil for everything else: every non-MCP provider, and the body-less
	// verbs an MCP mount serves alongside its JSON-RPC POSTs. The field is
	// omitempty so those records stay byte-identical to today's output.
	MCPDecision *logical.MCPDecision `json:"mcp_decision,omitempty"`

	// MCPClient carries the client's self-description, taken from the
	// request body's _meta. It sits beside MCPDecision rather than on it
	// because it decided nothing: it is unverified, unauthenticated and
	// trivially forged, useful for telling one agent build from another in
	// a log and for nothing else. Never gate on it.
	MCPClient *MCPClientInfo `json:"mcp_client,omitempty"`

	// Condition carries the path-level CEL condition decision when a condition
	// was evaluated for a non-MCP request (the MCP per-call condition is
	// recorded on MCPDecision.Condition instead). nil when none applied.
	Condition *logical.ConditionResult `json:"condition,omitempty"`
}

// MCPClientInfo is a client's self-reported identity. Control characters are
// stripped and each field length-capped at extraction, so a caller cannot
// use it to inject line breaks into an audit record or to grow one without
// bound.
type MCPClientInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// AuthResult contains authentication result from login operations. A login
// admits a credential and carries no role and no credential spec: the role a
// request runs under is recorded on that request's Auth.
type AuthResult struct {
	TokenType   string   `json:"token_type"`
	PrincipalID string   `json:"principal_id"`
	Policies    []string `json:"policies"`
	TokenTTL    int64    `json:"token_ttl"` // Seconds
}

// Credential contains audit information about a credential that was issued
type Credential struct {
	// Identity
	CredentialID string `json:"credential_id"` // UUID

	// Type information
	Type     string `json:"type"`               // aws_access_keys, vault_token, github_token
	Category string `json:"category,omitempty"` // database, cloud_iam, oauth, etc.

	// Lifecycle
	LeaseTTL int64  `json:"lease_ttl,omitempty"` // Seconds (0 for static)
	LeaseID  string `json:"lease_id,omitempty"`  // For revocation tracking
	TokenID  string `json:"token_id"`            // Session token this is bound to

	// Source information
	SourceName string `json:"source_name,omitempty"`
	SourceType string `json:"source_type,omitempty"` // local, hvault, aws
	SpecName   string `json:"spec_name,omitempty"`   // Which spec created this

	// Flags
	Revocable bool `json:"revocable"`

	// Credential data (sensitive - will be HMAC salted by the format layer)
	// Contains the actual credential values like access_key, secret_key, password, etc.
	Data map[string]string `json:"data,omitempty"`

	// Metadata holds non-secret, descriptive attributes (e.g. the forwarded
	// token's subject). Logged in clear by default; salt-able per key via
	// salt_fields (response.credential.metadata[.key]).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// EntryType defines the type of audit entry
type EntryType string

const (
	EntryTypeRequest  EntryType = "request"
	EntryTypeResponse EntryType = "response"
)

// Clone creates a deep copy of the LogEntry to avoid data races
func (e *LogEntry) Clone() *LogEntry {
	if e == nil {
		return nil
	}

	// Every struct is copied by value first, then each of its reference fields
	// (slices, maps, pointers) is copied anew, so devices writing the same
	// entry share nothing. Copying by value is what keeps a field added later
	// from being lost: a field-by-field copy once dropped the user principal,
	// and then auth_time, from every written entry, because the JSON formatter
	// clones before serialising. TestCloneKeepsEverythingSharesNothing pins it.
	clone := *e

	if e.Request != nil {
		req := *e.Request
		clone.Request = &req
	}

	if e.Response != nil {
		resp := *e.Response
		resp.Warnings = slices.Clone(e.Response.Warnings)
		if c := e.Response.Credential; c != nil {
			cred := *c
			cred.Data = maps.Clone(c.Data)
			cred.Metadata = maps.Clone(c.Metadata)
			resp.Credential = &cred
		}
		if ar := e.Response.AuthResult; ar != nil {
			result := *ar
			result.Policies = slices.Clone(ar.Policies)
			resp.AuthResult = &result
		}
		clone.Response = &resp
	}

	if e.Auth != nil {
		auth := *e.Auth
		auth.Policies = slices.Clone(e.Auth.Policies)
		auth.Groups = slices.Clone(e.Auth.Groups)
		auth.Actors = slices.Clone(e.Auth.Actors)
		if d := e.Auth.Discovery; d != nil {
			dc := *d
			dc.AdmittedBy = slices.Clone(d.AdmittedBy)
			auth.Discovery = &dc
		}
		if pr := e.Auth.PolicyResults; pr != nil {
			results := *pr
			results.GrantingPolicies = slices.Clone(pr.GrantingPolicies)
			results.MCPDecision = pr.MCPDecision.Clone()
			results.Condition = pr.Condition.Clone()
			if mc := pr.MCPClient; mc != nil {
				mcCopy := *mc
				results.MCPClient = &mcCopy
			}
			auth.PolicyResults = &results
		}
		if u := e.Auth.User; u != nil {
			user := *u
			user.Actors = slices.Clone(u.Actors)
			auth.User = &user
		}
		clone.Auth = &auth
	}

	return &clone
}

// Format defines the serialization format for audit logs
type Format interface {
	// FormatRequest formats a request entry
	FormatRequest(ctx context.Context, entry *LogEntry) ([]byte, error)

	// FormatResponse formats a response entry
	FormatResponse(ctx context.Context, entry *LogEntry) ([]byte, error)

	// Name returns the format name
	Name() string
}

// Sink is the interface for audit log destinations
type Sink interface {
	// Write writes the formatted entry to the sink
	Write(ctx context.Context, entry []byte) error

	// Close closes the sink and releases resources
	Close() error

	// Name returns the sink name
	Name() string

	// Type returns the sink type (file, syslog, socket, etc.)
	Type() string
}

// Device represents an audit device that combines a format and sink
type Device interface {
	// LogRequest logs a request
	LogRequest(ctx context.Context, entry *LogEntry) error

	// LogResponse logs a response
	LogResponse(ctx context.Context, entry *LogEntry) error

	// LogTestRequest logs a test request to verify the device is working correctly
	LogTestRequest(ctx context.Context) error

	// Close closes the device
	Close() error

	// Name returns the device name
	Name() string

	// Enabled returns whether the device is enabled
	Enabled() bool

	// SetEnabled sets the enabled state
	SetEnabled(enabled bool)

	logical.Backend
}

// FilterFunc is a function that filters audit entries
type FilterFunc func(entry *LogEntry) bool

// SaltFunc is a function that salts sensitive data
type SaltFunc func(ctx context.Context, data string) (string, error)

// DeviceConfig contains configuration for an audit device
type DeviceConfig struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Class       string                 `json:"class,omitempty"`
	Description string                 `json:"description,omitempty"`
	Accessor    string                 `json:"accessor,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
	Enabled     bool                   `json:"enabled"`
	Format      string                 `json:"format"`
	Prefix      string                 `json:"prefix,omitempty"`
	HMACKey     string                 `json:"hmac_key,omitempty"`

	// Filtering options
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	IncludePaths []string `json:"include_paths,omitempty"`

	// Performance options
	BufferSize  int           `json:"buffer_size,omitempty"`
	FlushPeriod time.Duration `json:"flush_period,omitempty"`

	// Warnings name what the factory changed in the operator's configuration
	// to keep the device safe. Reported through WarningReporter.
	Warnings []string `json:"-"`
}

// WarningReporter is implemented by a device whose factory changed its
// configuration. Core logs the warnings with the device's mount path, at
// enable and at every unseal: factories have no logger of their own.
type WarningReporter interface {
	Warnings() []string
}

// AuditManager manages audit devices
type AuditManager interface {
	// RegisterDevice registers a new audit device
	RegisterDevice(name string, device Device) error

	// UnregisterDevice unregisters an audit device
	UnregisterDevice(name string) error

	// GetDevice returns a device by name
	GetDevice(name string) (Device, error)

	// ListDevices returns all registered devices
	ListDevices() []string

	// LogRequest logs a request to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogRequest(ctx context.Context, entry *LogEntry) (bool, error)

	// LogResponse logs a response to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogResponse(ctx context.Context, entry *LogEntry) (bool, error)

	// Unregister all registered audit devices
	Reset(ctx context.Context) error

	// Close closes all devices
	Close() error
}

type AuditAccess interface {
	// LogRequest logs a request to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogRequest(ctx context.Context, entry *LogEntry) (bool, error)

	// LogResponse logs a response to all enabled devices
	// Returns (continue, error) where continue is true if at least one device succeeded
	LogResponse(ctx context.Context, entry *LogEntry) (bool, error)
}

type Factory interface {
	Type() string
	Class() string
	Create(ctx context.Context,
		mountPath string,
		description string,
		accessor string,
		config map[string]any) (Device, error)
	Initialize(logger *logger.GatedLogger) error
}

// ConfigValidator is implemented by a factory that can check a device
// configuration before the device is enabled. Core refuses a new device whose
// configuration it rejects; a stored one is still loaded, through Create.
type ConfigValidator interface {
	ValidateConfig(config map[string]any) error
}
