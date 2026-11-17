package audit

import (
	"context"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/stephnangue/warden/logical"
)

// jsonEncoder appends an audit entry to buf, byte for byte as encoding/json
// writes it: the entry is a released format, and this encoder exists only to
// write it without reflection and without allocating.
//
// It applies the device's redaction as it writes. A field the device omits is
// written as encoding/json writes its zero value, which for most is not at
// all; a field it salts is written salted. The entry is only read: the device
// after this one is handed the same.
//
// It names every field of every structure an entry holds, in the order and
// under the rules of the structure's json tags. A field added to a structure
// and not here would be missing from every entry written:
// TestEncoderMatchesEncodingJSON fails for it, and for any rule this encoder
// applies differently.
type jsonEncoder struct {
	buf []byte
	red *redaction
	// ctx is handed to a salt function of the caller's.
	ctx context.Context
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

// omits reports whether the device omits f.
func (e *jsonEncoder) omits(f field) bool { return e.red.omit.has(f) }

// salted appends the salted form of v, which is not empty, as a JSON string.
// Under the device's key it allocates nothing. A salt function of the
// caller's that fails gives the empty string: what was to be hidden is not
// written in clear for it.
func (e *jsonEncoder) salted(v string) {
	if h := e.red.hmac; h != nil {
		// A salted value is a prefix and hex digits: nothing to escape.
		e.buf = append(e.buf, '"')
		e.buf = h.AppendSalt(e.buf, v)
		e.buf = append(e.buf, '"')
		return
	}
	s, err := e.red.saltFn(e.ctx, v)
	if err != nil {
		s = ""
	}
	e.buf = appendJSONString(e.buf, s)
}

// The members below come in two forms: one always written, and one with the
// Omit suffix for a field tagged omitempty, left out when its value is the
// zero one, or a slice or map with nothing in it.
//
// Those named after a kind of value alone (str, num, flag) write a member
// that no path reaches, under the name they are given. Those with Field in
// their name write a field of the entry a device can redact, under the name
// fieldNames has for it.

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

func (e *jsonEncoder) flag(name string, v bool) {
	e.key(name)
	e.buf = strconv.AppendBool(e.buf, v)
}

func (e *jsonEncoder) flagOmit(name string, v bool) {
	if v {
		e.flag(name, v)
	}
}

// strField writes a string field that is always written: empty when the
// device omits it.
func (e *jsonEncoder) strField(f field, v string) {
	if e.omits(f) {
		v = ""
	}
	e.key(fieldNames[f])
	if v != "" && e.red.salt.has(f) {
		e.salted(v)
		return
	}
	e.buf = appendJSONString(e.buf, v)
}

// strFieldOmit writes a string field left out when empty: when it is, when
// the device omits it, and when its salted form is.
func (e *jsonEncoder) strFieldOmit(f field, v string) {
	if v == "" || e.omits(f) {
		return
	}
	if !e.red.salt.has(f) {
		e.str(fieldNames[f], v)
		return
	}
	before := len(e.buf)
	e.key(fieldNames[f])
	value := len(e.buf)
	e.salted(v)
	if len(e.buf) == value+len(`""`) {
		e.buf = e.buf[:before]
	}
}

func (e *jsonEncoder) numField(f field, v int64) {
	if e.omits(f) {
		v = 0
	}
	e.num(fieldNames[f], v)
}

func (e *jsonEncoder) numFieldOmit(f field, v int64) {
	if v != 0 && !e.omits(f) {
		e.num(fieldNames[f], v)
	}
}

func (e *jsonEncoder) flagField(f field, v bool) {
	e.flag(fieldNames[f], v && !e.omits(f))
}

func (e *jsonEncoder) flagFieldOmit(f field, v bool) {
	if v && !e.omits(f) {
		e.flag(fieldNames[f], v)
	}
}

// strsField writes a list of strings that is always written: null for a nil
// one or one the device omits, [] for an empty one. A device that salts the
// field salts each element that is not empty.
func (e *jsonEncoder) strsField(f field, v []string) {
	e.key(fieldNames[f])
	if v == nil || e.omits(f) {
		e.null()
		return
	}
	salt := e.red.salt.has(f)
	e.buf = append(e.buf, '[')
	for i, s := range v {
		if i > 0 {
			e.buf = append(e.buf, ',')
		}
		if salt && s != "" {
			e.salted(s)
		} else {
			e.buf = appendJSONString(e.buf, s)
		}
	}
	e.buf = append(e.buf, ']')
}

func (e *jsonEncoder) strsFieldOmit(f field, v []string) {
	if len(v) > 0 && !e.omits(f) {
		e.strsField(f, v)
	}
}

// strMapOmit writes a map of strings with its keys in byte order, without
// those rule omits and with the values it salts salted. A map left with no
// key is not written: it is empty once redacted, as one that held none.
func (e *jsonEncoder) strMapOmit(name string, m map[string]string, rule *mapRule) {
	if len(m) == 0 || (rule != nil && rule.omitAll) {
		return
	}
	// The keys of most maps fit here, and sorting them allocates nothing.
	var few [16]string
	keys := few[:0]
	for k := range m {
		if !rule.omits(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
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
		if v := m[k]; v != "" && rule.salts(k) {
			e.salted(v)
		} else {
			e.buf = appendJSONString(e.buf, v)
		}
	}
	e.end()
}

// entry writes a whole entry, as one of the given type. It fails as
// encoding/json does, for a timestamp whose year has no four-digit form.
func (e *jsonEncoder) entry(entry *LogEntry, entryType string) error {
	e.open()
	e.str("type", entryType)

	e.key("timestamp")
	e.buf = append(e.buf, '"')
	var err error
	if e.buf, err = entry.Timestamp.AppendText(e.buf); err != nil {
		return err
	}
	e.buf = append(e.buf, '"')

	// Always written: null for an entry with no request, or a device that
	// omits it.
	e.key(fieldNames[fRequest])
	if entry.Request == nil || e.omits(fRequest) {
		e.null()
	} else {
		e.request(entry.Request)
	}
	if entry.Response != nil && !e.omits(fResponse) {
		e.key(fieldNames[fResponse])
		e.response(entry.Response)
	}
	if entry.Auth != nil && !e.omits(fAuth) {
		e.key(fieldNames[fAuth])
		e.auth(entry.Auth)
	}
	if !e.omits(fError) {
		e.strOmit(fieldNames[fError], entry.Error)
	}
	e.end()
	return nil
}

func (e *jsonEncoder) request(r *Request) {
	e.open()
	e.strField(fRequestID, r.ID)
	e.strField(fRequestOperation, r.Operation)
	e.strField(fRequestPath, r.Path)
	e.strFieldOmit(fRequestMountPoint, r.MountPoint)
	e.strFieldOmit(fRequestMountType, r.MountType)
	e.strFieldOmit(fRequestMountClass, r.MountClass)
	e.strField(fRequestMethod, r.Method)
	e.strField(fRequestClientIP, r.ClientIP)
	e.strFieldOmit(fRequestNamespaceID, r.NamespaceID)
	e.strFieldOmit(fRequestNamespacePath, r.NamespacePath)
	e.flagFieldOmit(fRequestUnauthenticated, r.Unauthenticated)
	e.flagFieldOmit(fRequestStreamed, r.Streamed)
	e.flagFieldOmit(fRequestTransparent, r.Transparent)
	e.end()
}

func (e *jsonEncoder) response(r *Response) {
	e.open()
	e.numField(fResponseStatusCode, int64(r.StatusCode))
	e.strFieldOmit(fResponseStatusMessage, r.StatusMessage)
	e.strFieldOmit(fResponseMountClass, r.MountClass)
	e.flagFieldOmit(fResponseStreamed, r.Streamed)
	e.strsFieldOmit(fResponseWarnings, r.Warnings)
	if r.Credential != nil && !e.omits(fResponseCredential) {
		e.key(fieldNames[fResponseCredential])
		e.credential(r.Credential)
	}
	if r.AuthResult != nil && !e.omits(fResponseAuthResult) {
		e.key(fieldNames[fResponseAuthResult])
		e.authResult(r.AuthResult)
	}
	e.strFieldOmit(fResponseUpstreamURL, r.UpstreamURL)
	e.end()
}

func (e *jsonEncoder) credential(c *Credential) {
	e.open()
	e.strField(fCredentialID, c.CredentialID)
	e.strField(fCredentialType, c.Type)
	e.strFieldOmit(fCredentialCategory, c.Category)
	e.numFieldOmit(fCredentialLeaseTTL, c.LeaseTTL)
	e.strFieldOmit(fCredentialLeaseID, c.LeaseID)
	e.strField(fCredentialTokenID, c.TokenID)
	e.strFieldOmit(fCredentialSourceName, c.SourceName)
	e.strFieldOmit(fCredentialSourceType, c.SourceType)
	e.strFieldOmit(fCredentialSpecName, c.SpecName)
	e.flagField(fCredentialRevocable, c.Revocable)
	e.strMapOmit("data", c.Data, &e.red.credentialData)
	e.strMapOmit("metadata", c.Metadata, &e.red.credentialMetadata)
	e.end()
}

func (e *jsonEncoder) authResult(a *AuthResult) {
	e.open()
	e.strField(fAuthResultTokenType, a.TokenType)
	e.strField(fAuthResultPrincipalID, a.PrincipalID)
	e.strsField(fAuthResultPolicies, a.Policies)
	e.numField(fAuthResultTokenTTL, a.TokenTTL)
	e.end()
}

func (e *jsonEncoder) auth(a *Auth) {
	e.open()
	e.strFieldOmit(fAuthTokenID, a.TokenID)
	e.strFieldOmit(fAuthTokenAccessor, a.TokenAccessor)
	e.strFieldOmit(fAuthTokenType, a.TokenType)
	e.strFieldOmit(fAuthPrincipalID, a.PrincipalID)
	e.strFieldOmit(fAuthRoleName, a.RoleName)
	e.strFieldOmit(fAuthMountAccessor, a.MountAccessor)
	e.strFieldOmit(fAuthAliasName, a.AliasName)
	e.strFieldOmit(fAuthEntityKind, a.EntityKind)
	e.strFieldOmit(fAuthRoleGrantedBy, a.RoleGrantedBy)
	e.strFieldOmit(fAuthRoleGroupType, a.RoleGroupType)
	e.strFieldOmit(fAuthRoleDeniedReason, a.RoleDeniedReason)
	e.strsFieldOmit(fAuthGroups, a.Groups)
	e.strFieldOmit(fAuthSponsoredBy, a.SponsoredBy)
	e.strFieldOmit(fAuthEntityID, a.EntityID)
	e.strFieldOmit(fAuthEntityName, a.EntityName)
	e.strFieldOmit(fAuthGovernedBy, a.GovernedBy)
	e.strFieldOmit(fAuthIdentityStatus, a.IdentityStatus)
	e.strsFieldOmit(fAuthPolicies, a.Policies)
	if a.PolicyResults != nil && !e.omits(fAuthPolicyResults) {
		e.key(fieldNames[fAuthPolicyResults])
		e.policyResults(a.PolicyResults)
	}
	e.numFieldOmit(fAuthTokenTTL, a.TokenTTL)
	e.numFieldOmit(fAuthExpiresAt, a.ExpiresAt)
	e.numFieldOmit(fAuthAuthTime, a.AuthTime)
	e.strFieldOmit(fAuthDPoPJKT, a.DPoPJKT)
	e.strFieldOmit(fAuthProofID, a.ProofID)
	e.strFieldOmit(fAuthNamespaceID, a.NamespaceID)
	e.strFieldOmit(fAuthNamespacePath, a.NamespacePath)
	e.strFieldOmit(fAuthCreatedByIP, a.CreatedByIP)
	if !e.omits(fAuthActors) {
		e.actorsOmit(fieldNames[fAuthActors], a.Actors)
	}
	if u := a.User; u != nil && !e.omits(fAuthUser) {
		e.key(fieldNames[fAuthUser])
		e.open()
		e.strOmit("subject", u.Subject)
		e.strOmit("token_id", u.TokenID)
		e.strOmit("namespace_id", u.NamespaceID)
		e.strOmit("namespace_path", u.NamespacePath)
		e.actorsOmit("actors", u.Actors)
		e.end()
	}
	if d := a.Discovery; d != nil && !e.omits(fAuthDiscovery) {
		e.key(fieldNames[fAuthDiscovery])
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
			// The principal and the alias a mount admitted are the caller's,
			// as those of the entry are: omitted and salted with them. Left
			// in clear beside a salted one, they would undo it.
			e.strFieldOmit(fAuthPrincipalID, m.PrincipalID)
			e.strFieldOmit(fAuthAliasName, m.AliasName)
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
	e.flagField(fPolicyAllowed, p.Allowed)
	e.strsFieldOmit(fPolicyGrantingPolicies, p.GrantingPolicies)
	e.strFieldOmit(fPolicyDenyingPolicy, p.DenyingPolicy)
	if d := p.MCPDecision; d != nil && !e.omits(fPolicyMCPDecision) {
		e.key(fieldNames[fPolicyMCPDecision])
		e.mcpDecision(d)
	}
	if c := p.MCPClient; c != nil && !e.omits(fPolicyMCPClient) {
		e.key(fieldNames[fPolicyMCPClient])
		e.open()
		e.strOmit("name", c.Name)
		e.strOmit("version", c.Version)
		e.end()
	}
	if c := p.Condition; c != nil && !e.omits(fPolicyCondition) {
		e.key(fieldNames[fPolicyCondition])
		e.condition(c, &e.red.conditionInputs)
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
		// No path reaches the inputs of a call's condition: they are written
		// as they are.
		e.key("condition")
		e.condition(c, nil)
	}
	e.end()
}

// condition writes a condition's decision, with what inputs asks of its
// inputs: the device's rule for the condition of a path, none for a call's.
func (e *jsonEncoder) condition(c *logical.ConditionResult, inputs *mapRule) {
	e.open()
	e.str("decision", c.Decision)
	e.strOmit("expression", c.Expression)
	e.strOmit("error_kind", c.ErrorKind)
	e.flagOmit("user_absent", c.UserAbsent)
	e.strMapOmit("inputs", c.Inputs, inputs)
	e.end()
}

const lowerHex = "0123456789abcdef"

// plainASCII holds, for each ASCII byte, whether a JSON string holds it as it
// is: every one but the control characters, the quote, the backslash, and
// the three a browser could take for markup.
var plainASCII = func() (plain [utf8.RuneSelf]bool) {
	for b := 0x20; b < utf8.RuneSelf; b++ {
		plain[b] = true
	}
	for _, b := range []byte{'"', '\\', '<', '>', '&'} {
		plain[b] = false
	}
	return plain
}()

// appendJSONString appends s as a JSON string, escaped as encoding/json
// escapes one. Beyond what JSON requires (quotes, the backslash and control
// characters), that is the characters a browser could take for markup and
// the two line separators JavaScript does not allow in a string. A byte that
// is not UTF-8 becomes the replacement character. FuzzAppendJSONString holds
// it to that.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')

	// Most of what an entry holds is identifiers and paths, with nothing to
	// escape: those are copied in one go.
	i := 0
	for i < len(s) && s[i] < utf8.RuneSelf && plainASCII[s[i]] {
		i++
	}
	if i == len(s) {
		dst = append(dst, s...)
		return append(dst, '"')
	}

	start := 0
	for i < len(s) {
		if b := s[i]; b < utf8.RuneSelf {
			if plainASCII[b] {
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
