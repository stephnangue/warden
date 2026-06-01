package logical

import (
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// Auth is the resulting authentication information that is part of
// Response for auth backends. It's also attached to Request objects and
// defines the authentication used for the request. This value is audit logged.
type Auth struct {
	// Policies is the list of policies that the authenticated user
	// is associated with.
	Policies []string `json:"policies" mapstructure:"policies" structs:"policies"`

	// Credential spec as a result of the authentification if any
	CredentialSpec string

	// ClientToken is the token that is generated for the authentication.
	ClientToken string `json:"client_token" mapstructure:"client_token" structs:"client_token"`

	// Accessor is the identifier for the ClientToken. This can be used
	// to perform management functionalities (especially revocation) when
	// ClientToken in the audit logs are obfuscated. Accessor can be used
	// to revoke a ClientToken and to lookup the capabilities of the ClientToken,
	// both without actually knowing the ClientToken.
	TokenAccessor string `json:"token_accessor" mapstructure:"token_accessor" structs:"token_accessor"`

	// TokenType is the type of token being requested
	TokenType string `json:"token_type"`

	// PolicyResults is the set of policies that grant the token access to the
	// requesting path.
	PolicyResults *sdklogical.PolicyResults `json:"policy_results"`

	// MCPDecision carries the MCP-specific policy decision when an mcp { }
	// block was consulted during CBP evaluation. nil when no such block
	// applied (every non-MCP request, plus MCP-mount requests whose bound
	// policies contain no mcp block). Flows through buildAuditAuth into
	// audit.PolicyResults.MCPDecision and is also consumed by the
	// deny-response path to populate the WWW-Authenticate header and the
	// OAuth-shaped 403 body.
	MCPDecision *MCPDecision

	PrincipalID string

	RoleName string

	TokenTTL time.Duration

	NamespaceID string // Namespace UUID

	NamespacePath string // Namespace path

	ClientIP string

	// Actors is the on-behalf-of chain attached by ingestion paths
	// (X-Warden-On-Behalf-Of header or JWT "act" claim). Flows
	// through buildAuditAuth into the audit log; not used for policy
	// decisions.
	Actors []ActorRef
}

// MCPDecision records the outcome of evaluating an mcp { } policy block
// against a request. Populated on every branch (allow and deny) so the
// audit layer can render the decision unconditionally. The JSON tags
// double as the wire shape exposed in audit records under
// auth.policy_results.mcp_decision.
type MCPDecision struct {
	// Method is the value of the Mcp-Method header on the request.
	// Empty when the header was missing (paired with
	// RuleType=missing_method_header).
	Method string `json:"method"`

	// Name is the value of the Mcp-Name header. Empty for name-less
	// methods (tools/list, notifications, etc.) and when the request
	// was rejected before the name gate ran.
	Name string `json:"name,omitempty"`

	// Decision is "allow" or "deny". Always populated when an mcp { }
	// block was consulted.
	Decision string `json:"decision"`

	// MatchedRule is the pattern from the policy (allow- or deny-list
	// entry) that fired. For a literal match it equals the request's
	// name/method/param value; for a wildcard match it carries the
	// pattern (e.g. "delete_*"). Empty when no list entry matched
	// (deny via not-in-allow-list) and when the deny reason is a
	// sentinel like missing_method_header.
	MatchedRule string `json:"matched_rule"`

	// RuleType records which gate produced the decision. Domain:
	// allowed_methods, denied_methods, allowed_tools, denied_tools,
	// allowed_resources, allowed_prompts, allowed_params,
	// denied_params, or the sentinel missing_method_header.
	RuleType string `json:"rule_type"`

	// ParamName is the Mcp-Param-{Name} header's name (lowercase,
	// hyphens preserved), populated only when RuleType is
	// allowed_params or denied_params.
	ParamName string `json:"param_name,omitempty"`

	// ParamValue is the header value the policy compared against,
	// base64-decoded if the source header was an RFC 2047
	// encoded-word. Populated only for param-related decisions.
	ParamValue string `json:"param_value,omitempty"`
}

// Clone returns a deep copy of the MCPDecision. Safe to call on a nil
// receiver (returns nil).
func (d *MCPDecision) Clone() *MCPDecision {
	if d == nil {
		return nil
	}
	clone := *d
	return &clone
}

// ActorRef identifies a subject in the on-behalf-of chain. Verified
// is true when the actor was cryptographically attested by an IdP
// (e.g. JWT "act" claim per RFC 8693 §4.1) and false for self-reported
// subjects from request headers.
type ActorRef struct {
	Subject  string
	Verified bool
}

// AuthData contains the authentication data used to generate a token.
type AuthData struct {
	PrincipalID    string    // Principal identifier
	RoleName       string    // Associated role
	ExpireAt       time.Time // Token expiration
	CredentialSpec string
	Policies       []string
	ClientIP       string
	TokenValue     string // External token value (e.g., JWT for transparent mode)

	// MountAccessor is the stable identifier of the auth mount that
	// issued this login. Transparent token types include it in the cache
	// key so two mounts of the same auth type with overlapping role
	// names + the same credential cannot share a cache entry.
	MountAccessor string

	// Actors carries the verified on-behalf-of chain extracted at login
	// (e.g. JWT "act" claim) so it can be persisted onto the issued
	// TokenEntry for transparent-mode cache reuse.
	Actors []ActorRef
}
