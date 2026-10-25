package audit

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/stephnangue/warden/logical"
)

// JSONFormat implements the Format interface for JSON output
type JSONFormat struct {
	prefix string
	saltFn SaltFunc

	// The configured field paths, split once at construction.
	omitPaths [][]string
	saltPaths [][]string
}

// NewJSONFormat creates a new JSON format
func NewJSONFormat(opts ...JSONFormatOption) *JSONFormat {
	f := &JSONFormat{}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// JSONFormatOption is a functional option for JSONFormat
type JSONFormatOption func(*JSONFormat)

// WithPrefix sets a prefix for each log line
func WithPrefix(prefix string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.prefix = prefix
	}
}

// WithSaltFunc sets a salt function for sensitive data
func WithSaltFunc(fn SaltFunc) JSONFormatOption {
	return func(f *JSONFormat) {
		f.saltFn = fn
	}
}

// WithOmitFields sets fields to omit from output
func WithOmitFields(fields []string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.omitPaths = splitFieldPaths(fields)
	}
}

// WithSaltFields sets fields to salt in the output
func WithSaltFields(fields []string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.saltPaths = splitFieldPaths(fields)
	}
}

// splitFieldPaths splits each dot-separated path once, so formatting an entry
// splits nothing.
func splitFieldPaths(fields []string) [][]string {
	out := make([][]string, 0, len(fields))
	for _, p := range fields {
		out = append(out, strings.Split(p, "."))
	}
	return out
}

// FormatRequest formats a request entry as JSON
func (f *JSONFormat) FormatRequest(ctx context.Context, entry *LogEntry) ([]byte, error) {
	// Clone the entry to avoid data races when logging to multiple devices in parallel
	entry = entry.Clone()
	entry.Type = string(EntryTypeRequest)
	return f.format(ctx, entry)
}

// FormatResponse formats a response entry as JSON
func (f *JSONFormat) FormatResponse(ctx context.Context, entry *LogEntry) ([]byte, error) {
	// Clone the entry to avoid data races when logging to multiple devices in parallel
	entry = entry.Clone()
	entry.Type = string(EntryTypeResponse)
	return f.format(ctx, entry)
}

// format salts, then omits, the configured fields of entry, this device's own
// clone, and encodes it.
func (f *JSONFormat) format(ctx context.Context, entry *LogEntry) ([]byte, error) {
	if f.saltFn != nil {
		// A path that fails is skipped so the others are still salted. Paths
		// are checked when the device is created.
		for _, parts := range f.saltPaths {
			_ = f.saltField(ctx, entry, parts)
		}
	}
	for _, parts := range f.omitPaths {
		_ = omitField(entry, parts)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	if f.prefix != "" {
		return append([]byte(f.prefix), data...), nil
	}

	return data, nil
}

// Name returns the format name
func (f *JSONFormat) Name() string {
	return "json"
}

var (
	// errUnknownFieldPath: the path names no field of an audit entry.
	errUnknownFieldPath = errors.New("matches no audit field")
	// errNotSaltable: the path names a group of fields, which only omission
	// takes whole.
	errNotSaltable = errors.New("names a group of fields: salt the fields inside it")
	// errNeverLogged: the path names a request or response header or body,
	// which no entry records.
	errNeverLogged = errors.New("request and response headers and bodies are not fields of an audit entry")
)

// checkFieldPath reports whether path names a field that a salt path (salt)
// or an omit path can act on. It runs the walkers formatting uses, so the
// paths they accept and the paths accepted here cannot drift apart.
func checkFieldPath(salt bool, path string) error {
	probe := &LogEntry{
		Auth: &Auth{PolicyResults: &PolicyResults{
			Condition: &logical.ConditionResult{Inputs: map[string]string{}},
		}},
		Request: &Request{},
		Response: &Response{
			Credential: &Credential{Data: map[string]string{}, Metadata: map[string]string{}},
			AuthResult: &AuthResult{},
		},
	}
	parts := strings.Split(path, ".")
	if salt {
		f := &JSONFormat{saltFn: func(_ context.Context, s string) (string, error) { return s, nil }}
		return f.saltField(context.Background(), probe, parts)
	}
	return omitField(probe, parts)
}

// leaf refuses segments after a field that has none below it.
func leaf(rest []string) error {
	if len(rest) > 0 {
		return errUnknownFieldPath
	}
	return nil
}

// mapKey reads the segments after a map field: none names the whole map, one
// names a key.
// An empty key (a trailing dot) names nothing: it would match no value and
// leave the operator believing one salted.
func mapKey(rest []string) (key string, whole bool, err error) {
	switch {
	case len(rest) == 0:
		return "", true, nil
	case len(rest) == 1 && rest[0] != "":
		return rest[0], false, nil
	}
	return "", false, errUnknownFieldPath
}

// neverLogged reports whether name is a request or response field that used
// to record headers or a body. Omitting one is accepted and does nothing, so
// configurations written for earlier releases stay valid.
func neverLogged(name string) bool {
	return name == "headers" || name == "data"
}

// salt replaces a non-empty value with its salted form.
func (f *JSONFormat) salt(ctx context.Context, v *string) error {
	if *v == "" {
		return nil
	}
	salted, err := f.saltFn(ctx, *v)
	if err != nil {
		return err
	}
	*v = salted
	return nil
}

// saltMap salts one key of m, or every key when rest names the whole map.
func (f *JSONFormat) saltMap(ctx context.Context, m map[string]string, rest []string) error {
	key, whole, err := mapKey(rest)
	if err != nil {
		return err
	}
	if whole {
		for k, v := range m {
			if err := f.salt(ctx, &v); err != nil {
				return err
			}
			m[k] = v
		}
		return nil
	}
	if v, ok := m[key]; ok {
		if err := f.salt(ctx, &v); err != nil {
			return err
		}
		m[key] = v
	}
	return nil
}

// saltField salts the field parts names.
// Examples: "auth.token_id", "request.client_ip", "response.credential.data"
func (f *JSONFormat) saltField(ctx context.Context, entry *LogEntry, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch name {
	case "auth", "request", "response":
		if len(rest) == 0 {
			return errNotSaltable
		}
	default:
		return errUnknownFieldPath
	}
	switch name {
	case "auth":
		return f.saltAuthField(ctx, entry.Auth, rest)
	case "request":
		return f.saltRequestField(ctx, entry.Request, rest)
	default:
		return f.saltResponseField(ctx, entry.Response, rest)
	}
}

// saltAuthField salts a field within the Auth structure
func (f *JSONFormat) saltAuthField(ctx context.Context, auth *Auth, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch name {
	case "token_id", "token_accessor", "principal_id", "created_by_ip":
		if err := leaf(rest); err != nil {
			return err
		}
	case "policy_results":
		if len(rest) == 0 {
			return errNotSaltable
		}
		var pr *PolicyResults
		if auth != nil {
			pr = auth.PolicyResults
		}
		return f.saltPolicyResultsField(ctx, pr, rest)
	default:
		return errUnknownFieldPath
	}
	if auth == nil {
		return nil
	}

	switch name {
	case "token_id":
		return f.salt(ctx, &auth.TokenID)
	case "token_accessor":
		return f.salt(ctx, &auth.TokenAccessor)
	case "created_by_ip":
		return f.salt(ctx, &auth.CreatedByIP)
	}
	// principal_id. The principals a discovery request was admitted as are the
	// same identity: left in clear beside the salted one, they would undo it.
	if err := f.salt(ctx, &auth.PrincipalID); err != nil {
		return err
	}
	if d := auth.Discovery; d != nil {
		for i := range d.AdmittedBy {
			if err := f.salt(ctx, &d.AdmittedBy[i].PrincipalID); err != nil {
				return err
			}
		}
	}
	return nil
}

// saltPolicyResultsField salts a field within the PolicyResults structure
func (f *JSONFormat) saltPolicyResultsField(ctx context.Context, pr *PolicyResults, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch name {
	case "granting_policies":
		if err := leaf(rest); err != nil {
			return err
		}
		if pr == nil {
			return nil
		}
		for i := range pr.GrantingPolicies {
			if err := f.salt(ctx, &pr.GrantingPolicies[i]); err != nil {
				return err
			}
		}
		return nil
	case "condition":
		// "...condition.inputs" salts every referenced-input value;
		// "...condition.inputs.<dotted-key>" salts one (the input map keys are
		// themselves dotted, e.g. agent.metadata.env, so rejoin the tail).
		if len(rest) == 0 {
			return errNotSaltable
		}
		if rest[0] != "inputs" || slices.Contains(rest[1:], "") {
			return errUnknownFieldPath
		}
		if pr == nil || pr.Condition == nil {
			return nil
		}
		if len(rest) == 1 {
			return f.saltMap(ctx, pr.Condition.Inputs, nil)
		}
		return f.saltMap(ctx, pr.Condition.Inputs, []string{strings.Join(rest[1:], ".")})
	}
	return errUnknownFieldPath
}

// saltRequestField salts a field within the Request structure
func (f *JSONFormat) saltRequestField(ctx context.Context, request *Request, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case neverLogged(name):
		return errNeverLogged
	case name != "client_ip":
		return errUnknownFieldPath
	}
	if err := leaf(rest); err != nil {
		return err
	}
	if request == nil {
		return nil
	}
	return f.salt(ctx, &request.ClientIP)
}

// saltResponseField salts a field within the Response structure
func (f *JSONFormat) saltResponseField(ctx context.Context, response *Response, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case neverLogged(name):
		return errNeverLogged
	case name != "credential" && name != "auth_result":
		return errUnknownFieldPath
	case len(rest) == 0:
		return errNotSaltable
	}
	if name == "credential" {
		var cred *Credential
		if response != nil {
			cred = response.Credential
		}
		return f.saltCredentialField(ctx, cred, rest)
	}
	var authResult *AuthResult
	if response != nil {
		authResult = response.AuthResult
	}
	return f.saltAuthResultField(ctx, authResult, rest)
}

// saltCredentialField salts a field within the Credential structure
func (f *JSONFormat) saltCredentialField(ctx context.Context, cred *Credential, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch name {
	case "data", "metadata":
		// Data holds the issued secret values; metadata logs in clear unless
		// salted (response.credential.metadata salts every key, .subject one).
		if _, _, err := mapKey(rest); err != nil {
			return err
		}
		if cred == nil {
			return nil
		}
		if name == "data" {
			return f.saltMap(ctx, cred.Data, rest)
		}
		return f.saltMap(ctx, cred.Metadata, rest)
	case "credential_id", "lease_id", "token_id":
		if err := leaf(rest); err != nil {
			return err
		}
	default:
		return errUnknownFieldPath
	}
	if cred == nil {
		return nil
	}
	switch name {
	case "credential_id":
		return f.salt(ctx, &cred.CredentialID)
	case "lease_id":
		return f.salt(ctx, &cred.LeaseID)
	default:
		return f.salt(ctx, &cred.TokenID)
	}
}

// saltAuthResultField salts a field within the AuthResult structure
func (f *JSONFormat) saltAuthResultField(ctx context.Context, authResult *AuthResult, parts []string) error {
	if parts[0] != "principal_id" {
		return errUnknownFieldPath
	}
	if err := leaf(parts[1:]); err != nil {
		return err
	}
	if authResult == nil {
		return nil
	}
	return f.salt(ctx, &authResult.PrincipalID)
}

// The omit leaves of each structure: the field's JSON name, and how to clear
// it. A field with fields of its own below it that can be omitted one by one
// is handled beside its table instead.
var (
	omitAuthLeaves = map[string]func(*Auth){
		"token_id":           func(a *Auth) { a.TokenID = "" },
		"token_accessor":     func(a *Auth) { a.TokenAccessor = "" },
		"token_type":         func(a *Auth) { a.TokenType = "" },
		"principal_id":       omitPrincipalID,
		"role_name":          func(a *Auth) { a.RoleName = "" },
		"role_granted_by":    func(a *Auth) { a.RoleGrantedBy = "" },
		"role_denied_reason": func(a *Auth) { a.RoleDeniedReason = "" },
		"groups":             func(a *Auth) { a.Groups = nil },
		"policies":           func(a *Auth) { a.Policies = nil },
		"token_ttl":          func(a *Auth) { a.TokenTTL = 0 },
		"expires_at":         func(a *Auth) { a.ExpiresAt = 0 },
		"namespace_id":       func(a *Auth) { a.NamespaceID = "" },
		"namespace_path":     func(a *Auth) { a.NamespacePath = "" },
		"created_by_ip":      func(a *Auth) { a.CreatedByIP = "" },
		"actors":             func(a *Auth) { a.Actors = nil },
		"user":               func(a *Auth) { a.User = nil },
		"discovery":          func(a *Auth) { a.Discovery = nil },
	}
	omitPolicyResultsLeaves = map[string]func(*PolicyResults){
		"allowed":           func(p *PolicyResults) { p.Allowed = false },
		"granting_policies": func(p *PolicyResults) { p.GrantingPolicies = nil },
		"mcp_decision":      func(p *PolicyResults) { p.MCPDecision = nil },
		"mcp_client":        func(p *PolicyResults) { p.MCPClient = nil },
	}
	omitRequestLeaves = map[string]func(*Request){
		"id":              func(r *Request) { r.ID = "" },
		"operation":       func(r *Request) { r.Operation = "" },
		"path":            func(r *Request) { r.Path = "" },
		"mount_point":     func(r *Request) { r.MountPoint = "" },
		"mount_type":      func(r *Request) { r.MountType = "" },
		"mount_class":     func(r *Request) { r.MountClass = "" },
		"method":          func(r *Request) { r.Method = "" },
		"client_ip":       func(r *Request) { r.ClientIP = "" },
		"namespace_id":    func(r *Request) { r.NamespaceID = "" },
		"namespace_path":  func(r *Request) { r.NamespacePath = "" },
		"unauthenticated": func(r *Request) { r.Unauthenticated = false },
		"streamed":        func(r *Request) { r.Streamed = false },
		"transparent":     func(r *Request) { r.Transparent = false },
	}
	omitResponseLeaves = map[string]func(*Response){
		"status_code":    func(r *Response) { r.StatusCode = 0 },
		"status_message": func(r *Response) { r.StatusMessage = "" },
		"mount_class":    func(r *Response) { r.MountClass = "" },
		"streamed":       func(r *Response) { r.Streamed = false },
		"warnings":       func(r *Response) { r.Warnings = nil },
		"upstream_url":   func(r *Response) { r.UpstreamURL = "" },
	}
	omitCredentialLeaves = map[string]func(*Credential){
		"credential_id": func(c *Credential) { c.CredentialID = "" },
		"type":          func(c *Credential) { c.Type = "" },
		"category":      func(c *Credential) { c.Category = "" },
		"lease_ttl":     func(c *Credential) { c.LeaseTTL = 0 },
		"lease_id":      func(c *Credential) { c.LeaseID = "" },
		"token_id":      func(c *Credential) { c.TokenID = "" },
		"source_name":   func(c *Credential) { c.SourceName = "" },
		"source_type":   func(c *Credential) { c.SourceType = "" },
		"spec_name":     func(c *Credential) { c.SpecName = "" },
		"revocable":     func(c *Credential) { c.Revocable = false },
	}
	omitAuthResultLeaves = map[string]func(*AuthResult){
		"token_type":   func(a *AuthResult) { a.TokenType = "" },
		"principal_id": func(a *AuthResult) { a.PrincipalID = "" },
		"policies":     func(a *AuthResult) { a.Policies = nil },
		"token_ttl":    func(a *AuthResult) { a.TokenTTL = 0 },
	}
)

// omitPrincipalID clears the principal and the principals a discovery request
// was admitted as, the same identity.
func omitPrincipalID(a *Auth) {
	a.PrincipalID = ""
	if d := a.Discovery; d != nil {
		for i := range d.AdmittedBy {
			d.AdmittedBy[i].PrincipalID = ""
		}
	}
}

// omitLeaf clears the leaf name of target, looked up in leaves.
func omitLeaf[T any](leaves map[string]func(*T), target *T, name string, rest []string) error {
	omit, ok := leaves[name]
	if !ok {
		return errUnknownFieldPath
	}
	if err := leaf(rest); err != nil {
		return err
	}
	if target != nil {
		omit(target)
	}
	return nil
}

// omitField omits the field parts names.
// Examples: "auth", "request.client_ip", "response.credential"
func omitField(entry *LogEntry, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch name {
	case "auth":
		if len(rest) == 0 {
			entry.Auth = nil
			return nil
		}
		return omitAuthField(entry.Auth, rest)
	case "request":
		if len(rest) == 0 {
			entry.Request = nil
			return nil
		}
		if neverLogged(rest[0]) {
			return nil
		}
		return omitLeaf(omitRequestLeaves, entry.Request, rest[0], rest[1:])
	case "response":
		if len(rest) == 0 {
			entry.Response = nil
			return nil
		}
		return omitResponseField(entry.Response, rest)
	case "error":
		if err := leaf(rest); err != nil {
			return err
		}
		entry.Error = ""
		return nil
	}
	return errUnknownFieldPath
}

// omitAuthField omits a field within the Auth structure
func omitAuthField(auth *Auth, parts []string) error {
	name, rest := parts[0], parts[1:]
	if name != "policy_results" {
		return omitLeaf(omitAuthLeaves, auth, name, rest)
	}
	if len(rest) == 0 {
		if auth != nil {
			auth.PolicyResults = nil
		}
		return nil
	}
	var pr *PolicyResults
	if auth != nil {
		pr = auth.PolicyResults
	}
	return omitPolicyResultsField(pr, rest)
}

// omitPolicyResultsField omits a field within the PolicyResults structure
func omitPolicyResultsField(pr *PolicyResults, parts []string) error {
	name, rest := parts[0], parts[1:]
	if name != "condition" {
		return omitLeaf(omitPolicyResultsLeaves, pr, name, rest)
	}
	// Mirrors the salt paths, whose "inputs" keys are themselves dotted
	// (agent.metadata.env): every salt path must also be omittable, for a
	// device with no HMAC key to drop what it cannot hash.
	switch {
	case len(rest) == 0:
		if pr != nil {
			pr.Condition = nil
		}
	case rest[0] != "inputs" || slices.Contains(rest[1:], ""):
		return errUnknownFieldPath
	case pr == nil || pr.Condition == nil:
	case len(rest) == 1:
		pr.Condition.Inputs = nil
	default:
		delete(pr.Condition.Inputs, strings.Join(rest[1:], "."))
	}
	return nil
}

// omitResponseField omits a field within the Response structure
func omitResponseField(response *Response, parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case neverLogged(name):
		return nil
	case name == "credential":
		var cred *Credential
		if response != nil {
			cred = response.Credential
		}
		if len(rest) == 0 {
			if response != nil {
				response.Credential = nil
			}
			return nil
		}
		return omitCredentialField(cred, rest)
	case name == "auth_result":
		var authResult *AuthResult
		if response != nil {
			authResult = response.AuthResult
		}
		if len(rest) == 0 {
			if response != nil {
				response.AuthResult = nil
			}
			return nil
		}
		return omitLeaf(omitAuthResultLeaves, authResult, rest[0], rest[1:])
	}
	return omitLeaf(omitResponseLeaves, response, name, rest)
}

// omitCredentialField omits a field within the Credential structure
func omitCredentialField(cred *Credential, parts []string) error {
	name, rest := parts[0], parts[1:]
	if name != "data" && name != "metadata" {
		return omitLeaf(omitCredentialLeaves, cred, name, rest)
	}
	key, whole, err := mapKey(rest)
	if err != nil {
		return err
	}
	if cred == nil {
		return nil
	}
	switch {
	case name == "data" && whole:
		cred.Data = nil
	case name == "data":
		delete(cred.Data, key)
	case whole:
		cred.Metadata = nil
	default:
		delete(cred.Metadata, key)
	}
	return nil
}
