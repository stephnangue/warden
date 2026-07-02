package logical

import (
	"strings"
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

	// Condition carries the path-level CEL condition decision when a
	// path-level condition was evaluated during CBP evaluation. nil when the
	// matched permission had no path-level condition. Flows through
	// buildAuditAuth into audit.PolicyResults.Condition.
	Condition *ConditionResult

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

	// Metadata is a set of verified, login-derived attributes the auth
	// method extracted from the authenticated identity (e.g. JWT claims,
	// certificate fields, service-account attributes). It is persisted onto
	// the issued token and consulted by token_metadata policy conditions.
	// Never caller-supplied — only an auth method writes it.
	Metadata map[string]string
}

// MCPDecision records the outcome of evaluating an mcp { } policy block
// against a request. Populated on every branch (allow and deny) so the
// audit layer can render the decision unconditionally. The JSON tags
// double as the wire shape exposed in audit records under
// auth.policy_results.mcp_decision.
//
// All string fields are CTL-stripped by core.sanitizeMCPDecision before
// the struct leaves the policy layer, so adversary-controlled body
// bytes cannot inject log content or break the WWW-Authenticate
// quoted-string.
type MCPDecision struct {
	// Method is the lowercased JSON-RPC method from the parsed
	// request body. Empty for structural denies that bail before the
	// body's method was extracted (missing_body, malformed_jsonrpc,
	// duplicate_key, oversized_body, batch_empty, malformed_params).
	Method string `json:"method"`

	// Name is the lowercased name-bearing field from the JSON-RPC
	// body — params.name for tools/call and prompts/get, params.uri
	// for resources/read. Empty for methods without a name
	// (tools/list, initialize, notifications) and for any deny
	// produced before the name gate ran.
	Name string `json:"name,omitempty"`

	// Decision is "allow" or "deny". Always populated when an mcp { }
	// block was consulted.
	Decision string `json:"decision"`

	// MatchedRule is the pattern from the policy (allow- or deny-list
	// entry) that fired. For a literal match it equals the request's
	// name/method/param value; for a wildcard match it carries the
	// pattern (e.g. "delete_*"). Empty when no list entry matched
	// (deny via not-in-allow-list) and for structural-failure denies.
	MatchedRule string `json:"matched_rule"`

	// RuleType records which gate produced the decision. Domain:
	//   gate-driven: allowed_methods, denied_methods, allowed_tools,
	//     denied_tools, allowed_resources, denied_resources,
	//     allowed_prompts, denied_prompts, allowed_params,
	//     denied_params
	//   structural failure (body could not be evaluated):
	//     missing_body, malformed_jsonrpc, duplicate_key,
	//     oversized_body, batch_empty, malformed_params
	//   legacy sentinel (kept for back-compat with pre-Phase-4
	//   audit records; never emitted on the production path):
	//     missing_method_header
	RuleType string `json:"rule_type"`

	// ParamName is the tools/call argument key whose value triggered
	// a param-gate deny. Lowercased, hyphens preserved. Populated
	// only when RuleType is allowed_params or denied_params.
	ParamName string `json:"param_name,omitempty"`

	// ParamValue is the request value the policy compared against —
	// for body-authoritative enforcement this is the tools/call
	// argument value rendered to its matcher-comparable string form.
	// Populated only for param-related decisions.
	ParamValue string `json:"param_value,omitempty"`

	// BatchIndex stamps the offset of the deciding call within a
	// JSON-RPC batch body. Nil for single-message bodies and for any
	// structural deny produced before the body's calls were
	// evaluated (missing_body / malformed_jsonrpc / duplicate_key /
	// oversized_body / batch_empty). Purely informational — does
	// NOT participate in the strongest-reason ranking that selects
	// which set's deny surfaces on a multi-set deny.
	BatchIndex *int `json:"batch_index,omitempty"`

	// Condition carries the CEL condition decision when an mcp{} condition
	// was evaluated for this call. Populated when RuleType is "condition" or
	// "condition_error"; nil when no condition applied.
	Condition *ConditionResult `json:"condition,omitempty"`
}

// Clone returns a deep copy of the MCPDecision. Safe to call on a nil
// receiver (returns nil).
func (d *MCPDecision) Clone() *MCPDecision {
	if d == nil {
		return nil
	}
	clone := *d
	if d.BatchIndex != nil {
		idx := *d.BatchIndex
		clone.BatchIndex = &idx
	}
	clone.Condition = d.Condition.Clone()
	return &clone
}

// ConditionResult is the audited outcome of evaluating a CEL condition. It is
// recorded at both audit sites — PolicyResults.Condition (path-level) and
// MCPDecision.Condition (per-call) — and carries enough to explain a decision
// without sub-expression tracing: the operator-authored expression, the
// referenced input values, and (on a fail-closed error) a sanitized category.
//
// Hygiene: Expression is operator-authored and safe to log. Inputs values may
// be adversary-influenced and are CTL-stripped here; secret-bearing keys are
// redacted/salted by the audit format layer. ErrorKind is a category, never a
// raw eval-error string or adversary value.
type ConditionResult struct {
	// Decision is "allow" or "deny".
	Decision string `json:"decision"`

	// Expression is the CEL text that decided (the deciding condition on an
	// OR-merge across policies).
	Expression string `json:"expression,omitempty"`

	// ErrorKind is a sanitized category for a fail-closed eval error
	// (e.g. "no_such_key", "type_mismatch", "cost_exceeded"); empty for a
	// clean allow/deny.
	ErrorKind string `json:"error_kind,omitempty"`

	// Inputs maps the expression's referenced variables to their CTL-stripped
	// values so a denial is self-explanatory. Sensitive keys are
	// redacted/salted by the audit format layer.
	Inputs map[string]string `json:"inputs,omitempty"`
}

// Clone returns a deep copy of the ConditionResult. Safe to call on a nil
// receiver (returns nil).
func (c *ConditionResult) Clone() *ConditionResult {
	if c == nil {
		return nil
	}
	clone := *c
	if c.Inputs != nil {
		clone.Inputs = make(map[string]string, len(c.Inputs))
		for k, v := range c.Inputs {
			clone.Inputs[k] = v
		}
	}
	return &clone
}

// Sanitize CTL-strips string fields so adversary-influenced input values
// cannot inject control characters into audit records. Redaction/salting of
// sensitive Inputs keys is applied separately by the audit format layer.
func (c *ConditionResult) Sanitize() {
	if c == nil {
		return
	}
	c.Decision = stripControlChars(c.Decision)
	c.Expression = stripControlChars(c.Expression)
	c.ErrorKind = stripControlChars(c.ErrorKind)
	if c.Inputs != nil {
		cleaned := make(map[string]string, len(c.Inputs))
		for k, v := range c.Inputs {
			cleaned[stripControlChars(k)] = stripControlChars(v)
		}
		c.Inputs = cleaned
	}
}

// stripControlChars removes C0 control characters and DEL.
func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
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

	// Metadata carries verified, login-derived identity attributes the auth
	// method extracted (e.g. mapped JWT claims). Persisted onto the issued
	// TokenEntry and consulted by token_metadata policy conditions.
	Metadata map[string]string
}
