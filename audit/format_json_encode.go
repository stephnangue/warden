package audit

import (
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/stephnangue/warden/logical"
)

// jsonEncoder appends an audit entry to buf, byte for byte as encoding/json
// writes it: the entry is a released format, and this encoder exists only to
// write it without reflection and without allocating.
//
// It names every field of every structure an entry holds, in the order and
// under the rules of the structure's json tags. A field added to a structure
// and not here would be missing from every entry written:
// TestEncoderMatchesEncodingJSON fails for it, and for any rule this encoder
// applies differently.
type jsonEncoder struct {
	buf []byte
}

// open starts an object and end closes it.
func (e *jsonEncoder) open() { e.buf = append(e.buf, '{') }
func (e *jsonEncoder) end()  { e.buf = append(e.buf, '}') }

// key starts a member of the object being written: its name, after a comma
// unless it is the object's first. No value ends with an opening brace, so a
// buffer that ends with one holds an object with no member yet.
func (e *jsonEncoder) key(name string) {
	if e.buf[len(e.buf)-1] != '{' {
		e.buf = append(e.buf, ',')
	}
	e.buf = append(e.buf, '"')
	e.buf = append(e.buf, name...)
	e.buf = append(e.buf, '"', ':')
}

// null writes the value of a pointer, slice or map that is nil and whose
// field is not omitted when empty.
func (e *jsonEncoder) null() { e.buf = append(e.buf, "null"...) }

// The members below come in two forms: one always written, and one with the
// Omit suffix for a field tagged omitempty, left out when its value is the
// zero one, or a slice or map with nothing in it.

func (e *jsonEncoder) str(name, v string) {
	e.key(name)
	e.buf = appendJSONString(e.buf, v)
}

func (e *jsonEncoder) strOmit(name, v string) {
	if v != "" {
		e.str(name, v)
	}
}

func (e *jsonEncoder) num(name string, v int64) {
	e.key(name)
	e.buf = strconv.AppendInt(e.buf, v, 10)
}

func (e *jsonEncoder) numOmit(name string, v int64) {
	if v != 0 {
		e.num(name, v)
	}
}

func (e *jsonEncoder) flag(name string, v bool) {
	e.key(name)
	e.buf = strconv.AppendBool(e.buf, v)
}

func (e *jsonEncoder) flagOmit(name string, v bool) {
	if v {
		e.flag(name, v)
	}
}

// strs writes a list of strings: null for a nil one, [] for an empty one.
func (e *jsonEncoder) strs(name string, v []string) {
	e.key(name)
	if v == nil {
		e.null()
		return
	}
	e.buf = append(e.buf, '[')
	for i, s := range v {
		if i > 0 {
			e.buf = append(e.buf, ',')
		}
		e.buf = appendJSONString(e.buf, s)
	}
	e.buf = append(e.buf, ']')
}

func (e *jsonEncoder) strsOmit(name string, v []string) {
	if len(v) > 0 {
		e.strs(name, v)
	}
}

// strMapOmit writes a map of strings with its keys in byte order, or nothing
// for a map that holds none.
func (e *jsonEncoder) strMapOmit(name string, m map[string]string) {
	if len(m) == 0 {
		return
	}
	// The keys of most maps fit here, and sorting them allocates nothing.
	var few [16]string
	keys := few[:0]
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	// A key is data, unlike a field's name: it is escaped as a value is.
	e.key(name)
	e.open()
	for i, k := range keys {
		if i > 0 {
			e.buf = append(e.buf, ',')
		}
		e.buf = appendJSONString(e.buf, k)
		e.buf = append(e.buf, ':')
		e.buf = appendJSONString(e.buf, m[k])
	}
	e.end()
}

// entry writes a whole entry. It fails as encoding/json does, for a
// timestamp whose year has no four-digit form.
func (e *jsonEncoder) entry(entry *LogEntry) error {
	e.open()
	e.str("type", entry.Type)

	e.key("timestamp")
	e.buf = append(e.buf, '"')
	var err error
	if e.buf, err = entry.Timestamp.AppendText(e.buf); err != nil {
		return err
	}
	e.buf = append(e.buf, '"')

	e.key("request")
	e.request(entry.Request)
	if entry.Response != nil {
		e.key("response")
		e.response(entry.Response)
	}
	if entry.Auth != nil {
		e.key("auth")
		e.auth(entry.Auth)
	}
	e.strOmit("error", entry.Error)
	e.end()
	return nil
}

func (e *jsonEncoder) request(r *Request) {
	if r == nil {
		e.null()
		return
	}
	e.open()
	e.str("id", r.ID)
	e.str("operation", r.Operation)
	e.str("path", r.Path)
	e.strOmit("mount_point", r.MountPoint)
	e.strOmit("mount_type", r.MountType)
	e.strOmit("mount_class", r.MountClass)
	e.str("method", r.Method)
	e.str("client_ip", r.ClientIP)
	e.strOmit("namespace_id", r.NamespaceID)
	e.strOmit("namespace_path", r.NamespacePath)
	e.flagOmit("unauthenticated", r.Unauthenticated)
	e.flagOmit("streamed", r.Streamed)
	e.flagOmit("transparent", r.Transparent)
	e.end()
}

func (e *jsonEncoder) response(r *Response) {
	e.open()
	e.num("status_code", int64(r.StatusCode))
	e.strOmit("status_message", r.StatusMessage)
	e.strOmit("mount_class", r.MountClass)
	e.flagOmit("streamed", r.Streamed)
	e.strsOmit("warnings", r.Warnings)
	if r.Credential != nil {
		e.key("credential")
		e.credential(r.Credential)
	}
	if r.AuthResult != nil {
		e.key("auth_result")
		e.authResult(r.AuthResult)
	}
	e.strOmit("upstream_url", r.UpstreamURL)
	e.end()
}

func (e *jsonEncoder) credential(c *Credential) {
	e.open()
	e.str("credential_id", c.CredentialID)
	e.str("type", c.Type)
	e.strOmit("category", c.Category)
	e.numOmit("lease_ttl", c.LeaseTTL)
	e.strOmit("lease_id", c.LeaseID)
	e.str("token_id", c.TokenID)
	e.strOmit("source_name", c.SourceName)
	e.strOmit("source_type", c.SourceType)
	e.strOmit("spec_name", c.SpecName)
	e.flag("revocable", c.Revocable)
	e.strMapOmit("data", c.Data)
	e.strMapOmit("metadata", c.Metadata)
	e.end()
}

func (e *jsonEncoder) authResult(a *AuthResult) {
	e.open()
	e.str("token_type", a.TokenType)
	e.str("principal_id", a.PrincipalID)
	e.strs("policies", a.Policies)
	e.num("token_ttl", a.TokenTTL)
	e.end()
}

func (e *jsonEncoder) auth(a *Auth) {
	e.open()
	e.strOmit("token_id", a.TokenID)
	e.strOmit("token_accessor", a.TokenAccessor)
	e.strOmit("token_type", a.TokenType)
	e.strOmit("principal_id", a.PrincipalID)
	e.strOmit("role_name", a.RoleName)
	e.strOmit("mount_accessor", a.MountAccessor)
	e.strOmit("alias_name", a.AliasName)
	e.strOmit("entity_kind", a.EntityKind)
	e.strOmit("role_granted_by", a.RoleGrantedBy)
	e.strOmit("role_group_type", a.RoleGroupType)
	e.strOmit("role_denied_reason", a.RoleDeniedReason)
	e.strsOmit("groups", a.Groups)
	e.strOmit("sponsored_by", a.SponsoredBy)
	e.strOmit("entity_id", a.EntityID)
	e.strOmit("entity_name", a.EntityName)
	e.strOmit("governed_by", a.GovernedBy)
	e.strOmit("identity_status", a.IdentityStatus)
	e.strsOmit("policies", a.Policies)
	if a.PolicyResults != nil {
		e.key("policy_results")
		e.policyResults(a.PolicyResults)
	}
	e.numOmit("token_ttl", a.TokenTTL)
	e.numOmit("expires_at", a.ExpiresAt)
	e.numOmit("auth_time", a.AuthTime)
	e.strOmit("dpop_jkt", a.DPoPJKT)
	e.strOmit("proof_id", a.ProofID)
	e.strOmit("namespace_id", a.NamespaceID)
	e.strOmit("namespace_path", a.NamespacePath)
	e.strOmit("created_by_ip", a.CreatedByIP)
	e.actorsOmit("actors", a.Actors)
	if u := a.User; u != nil {
		e.key("user")
		e.open()
		e.strOmit("subject", u.Subject)
		e.strOmit("token_id", u.TokenID)
		e.strOmit("namespace_id", u.NamespaceID)
		e.strOmit("namespace_path", u.NamespacePath)
		e.actorsOmit("actors", u.Actors)
		e.end()
	}
	if d := a.Discovery; d != nil {
		e.key("discovery")
		e.discovery(d)
	}
	e.end()
}

func (e *jsonEncoder) actorsOmit(name string, actors []ActorRef) {
	if len(actors) == 0 {
		return
	}
	e.key(name)
	e.buf = append(e.buf, '[')
	for i := range actors {
		if i > 0 {
			e.buf = append(e.buf, ',')
		}
		e.open()
		e.str("subject", actors[i].Subject)
		e.strOmit("issuer", actors[i].Issuer)
		e.end()
	}
	e.buf = append(e.buf, ']')
}

func (e *jsonEncoder) discovery(d *DiscoveryAuth) {
	e.open()
	if len(d.AdmittedBy) > 0 {
		e.key("admitted_by")
		e.buf = append(e.buf, '[')
		for i := range d.AdmittedBy {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			m := &d.AdmittedBy[i]
			e.open()
			e.str("mount", m.Mount)
			e.strOmit("principal_id", m.PrincipalID)
			e.strOmit("alias_name", m.AliasName)
			e.strOmit("entity_id", m.EntityID)
			e.end()
		}
		e.buf = append(e.buf, ']')
	}
	e.num("roles_granted", int64(d.RolesGranted))
	e.flagOmit("anonymous", d.Anonymous)
	e.flagOmit("credential_unverified", d.CredentialUnverified)
	e.end()
}

func (e *jsonEncoder) policyResults(p *PolicyResults) {
	e.open()
	e.flag("allowed", p.Allowed)
	e.strsOmit("granting_policies", p.GrantingPolicies)
	e.strOmit("denying_policy", p.DenyingPolicy)
	if d := p.MCPDecision; d != nil {
		e.key("mcp_decision")
		e.mcpDecision(d)
	}
	if c := p.MCPClient; c != nil {
		e.key("mcp_client")
		e.open()
		e.strOmit("name", c.Name)
		e.strOmit("version", c.Version)
		e.end()
	}
	if c := p.Condition; c != nil {
		e.key("condition")
		e.condition(c)
	}
	e.end()
}

func (e *jsonEncoder) mcpDecision(d *logical.MCPDecision) {
	e.open()
	e.str("method", d.Method)
	e.strOmit("name", d.Name)
	e.str("decision", d.Decision)
	e.strOmit("policy_name", d.PolicyName)
	e.str("matched_rule", d.MatchedRule)
	e.str("rule_type", d.RuleType)
	e.strOmit("param_name", d.ParamName)
	e.strOmit("param_value", d.ParamValue)
	// A pointer: an index of zero is written, only none is left out.
	if d.BatchIndex != nil {
		e.num("batch_index", int64(*d.BatchIndex))
	}
	if c := d.Condition; c != nil {
		e.key("condition")
		e.condition(c)
	}
	e.end()
}

func (e *jsonEncoder) condition(c *logical.ConditionResult) {
	e.open()
	e.str("decision", c.Decision)
	e.strOmit("expression", c.Expression)
	e.strOmit("error_kind", c.ErrorKind)
	e.flagOmit("user_absent", c.UserAbsent)
	e.strMapOmit("inputs", c.Inputs)
	e.end()
}

const lowerHex = "0123456789abcdef"

// appendJSONString appends s as a JSON string, escaped as encoding/json
// escapes one. Beyond what JSON requires (quotes, the backslash and control
// characters), that is the characters a browser could take for markup and
// the two line separators JavaScript does not allow in a string. A byte that
// is not UTF-8 becomes the replacement character. FuzzAppendJSONString holds
// it to that.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if b >= 0x20 && b != '"' && b != '\\' && b != '<' && b != '>' && b != '&' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch b {
			case '"', '\\':
				dst = append(dst, '\\', b)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', lowerHex[b>>4], lowerHex[b&0xF])
			}
			i++
			start = i
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Not UTF-8: one replacement character per byte, as it is and
			// not as its escape.
			dst = append(dst, s[start:i]...)
			dst = utf8.AppendRune(dst, utf8.RuneError)
			start = i + size
		case r == 0x2028 || r == 0x2029:
			// The line and paragraph separators.
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', lowerHex[r&0xF])
			start = i + size
		}
		i += size
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}
