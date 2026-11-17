package audit

import (
	"slices"
	"strings"
)

// field identifies a field of an audit entry that a device can omit, and for
// some salt. The fields of a structure are numbered together, in the order
// the structure declares them.
type field uint8

const (
	// The entry itself. Its type and timestamp identify it, and are always
	// written.
	fRequest field = iota
	fResponse
	fAuth
	fError

	// Request.
	fRequestID
	fRequestOperation
	fRequestPath
	fRequestMountPoint
	fRequestMountType
	fRequestMountClass
	fRequestMethod
	fRequestClientIP
	fRequestNamespaceID
	fRequestNamespacePath
	fRequestUnauthenticated
	fRequestStreamed
	fRequestTransparent

	// Response.
	fResponseStatusCode
	fResponseStatusMessage
	fResponseMountClass
	fResponseStreamed
	fResponseWarnings
	fResponseCredential
	fResponseAuthResult
	fResponseUpstreamURL

	// Credential. Its data and metadata are maps, with rules of their own.
	fCredentialID
	fCredentialType
	fCredentialCategory
	fCredentialLeaseTTL
	fCredentialLeaseID
	fCredentialTokenID
	fCredentialSourceName
	fCredentialSourceType
	fCredentialSpecName
	fCredentialRevocable

	// AuthResult.
	fAuthResultTokenType
	fAuthResultPrincipalID
	fAuthResultPolicies
	fAuthResultTokenTTL

	// Auth.
	fAuthTokenID
	fAuthTokenAccessor
	fAuthTokenType
	fAuthPrincipalID
	fAuthRoleName
	fAuthMountAccessor
	fAuthAliasName
	fAuthEntityKind
	fAuthRoleGrantedBy
	fAuthRoleGroupType
	fAuthRoleDeniedReason
	fAuthGroups
	fAuthSponsoredBy
	fAuthEntityID
	fAuthEntityName
	fAuthGovernedBy
	fAuthIdentityStatus
	fAuthPolicies
	fAuthPolicyResults
	fAuthTokenTTL
	fAuthExpiresAt
	fAuthAuthTime
	fAuthDPoPJKT
	fAuthProofID
	fAuthNamespaceID
	fAuthNamespacePath
	fAuthCreatedByIP
	fAuthActors
	fAuthUser
	fAuthDiscovery

	// PolicyResults. The inputs of its condition are a map.
	fPolicyAllowed
	fPolicyGrantingPolicies
	fPolicyDenyingPolicy
	fPolicyMCPDecision
	fPolicyMCPClient
	fPolicyCondition

	numFields
)

// fieldNames is the name each field is written under, and the segment that
// names it in a salt or omit path. The encoder and the paths read it here, so
// a path cannot name one field and redact another.
var fieldNames = [numFields]string{
	fRequest:  "request",
	fResponse: "response",
	fAuth:     "auth",
	fError:    "error",

	fRequestID:              "id",
	fRequestOperation:       "operation",
	fRequestPath:            "path",
	fRequestMountPoint:      "mount_point",
	fRequestMountType:       "mount_type",
	fRequestMountClass:      "mount_class",
	fRequestMethod:          "method",
	fRequestClientIP:        "client_ip",
	fRequestNamespaceID:     "namespace_id",
	fRequestNamespacePath:   "namespace_path",
	fRequestUnauthenticated: "unauthenticated",
	fRequestStreamed:        "streamed",
	fRequestTransparent:     "transparent",

	fResponseStatusCode:    "status_code",
	fResponseStatusMessage: "status_message",
	fResponseMountClass:    "mount_class",
	fResponseStreamed:      "streamed",
	fResponseWarnings:      "warnings",
	fResponseCredential:    "credential",
	fResponseAuthResult:    "auth_result",
	fResponseUpstreamURL:   "upstream_url",

	fCredentialID:         "credential_id",
	fCredentialType:       "type",
	fCredentialCategory:   "category",
	fCredentialLeaseTTL:   "lease_ttl",
	fCredentialLeaseID:    "lease_id",
	fCredentialTokenID:    "token_id",
	fCredentialSourceName: "source_name",
	fCredentialSourceType: "source_type",
	fCredentialSpecName:   "spec_name",
	fCredentialRevocable:  "revocable",

	fAuthResultTokenType:   "token_type",
	fAuthResultPrincipalID: "principal_id",
	fAuthResultPolicies:    "policies",
	fAuthResultTokenTTL:    "token_ttl",

	fAuthTokenID:          "token_id",
	fAuthTokenAccessor:    "token_accessor",
	fAuthTokenType:        "token_type",
	fAuthPrincipalID:      "principal_id",
	fAuthRoleName:         "role_name",
	fAuthMountAccessor:    "mount_accessor",
	fAuthAliasName:        "alias_name",
	fAuthEntityKind:       "entity_kind",
	fAuthRoleGrantedBy:    "role_granted_by",
	fAuthRoleGroupType:    "role_group_type",
	fAuthRoleDeniedReason: "role_denied_reason",
	fAuthGroups:           "groups",
	fAuthSponsoredBy:      "sponsored_by",
	fAuthEntityID:         "entity_id",
	fAuthEntityName:       "entity_name",
	fAuthGovernedBy:       "governed_by",
	fAuthIdentityStatus:   "identity_status",
	fAuthPolicies:         "policies",
	fAuthPolicyResults:    "policy_results",
	fAuthTokenTTL:         "token_ttl",
	fAuthExpiresAt:        "expires_at",
	fAuthAuthTime:         "auth_time",
	fAuthDPoPJKT:          "dpop_jkt",
	fAuthProofID:          "proof_id",
	fAuthNamespaceID:      "namespace_id",
	fAuthNamespacePath:    "namespace_path",
	fAuthCreatedByIP:      "created_by_ip",
	fAuthActors:           "actors",
	fAuthUser:             "user",
	fAuthDiscovery:        "discovery",

	fPolicyAllowed:          "allowed",
	fPolicyGrantingPolicies: "granting_policies",
	fPolicyDenyingPolicy:    "denying_policy",
	fPolicyMCPDecision:      "mcp_decision",
	fPolicyMCPClient:        "mcp_client",
	fPolicyCondition:        "condition",
}

// fieldGroup is the fields of one structure: first to last, both included.
type fieldGroup struct{ first, last field }

var (
	requestFields    = fieldGroup{fRequestID, fRequestTransparent}
	responseFields   = fieldGroup{fResponseStatusCode, fResponseUpstreamURL}
	credentialFields = fieldGroup{fCredentialID, fCredentialRevocable}
	authResultFields = fieldGroup{fAuthResultTokenType, fAuthResultTokenTTL}
	authFields       = fieldGroup{fAuthTokenID, fAuthDiscovery}
	policyFields     = fieldGroup{fPolicyAllowed, fPolicyCondition}
)

// named returns the field of the group that name names.
func (g fieldGroup) named(name string) (field, bool) {
	for f := g.first; f <= g.last; f++ {
		if fieldNames[f] == name {
			return f, true
		}
	}
	return 0, false
}

// fieldSet is a set of fields.
type fieldSet [2]uint64

func (s *fieldSet) add(f field)      { s[f/64] |= 1 << (f % 64) }
func (s *fieldSet) has(f field) bool { return s[f/64]&(1<<(f%64)) != 0 }

// saltable are the fields a salt path can name: identifiers and addresses,
// whose salted form still tells two values apart. The fields beside them
// describe the request, and are kept or omitted.
var saltable = func() (s fieldSet) {
	for _, f := range []field{
		fRequestClientIP,
		fCredentialID, fCredentialLeaseID, fCredentialTokenID,
		fAuthResultPrincipalID,
		fAuthTokenID, fAuthTokenAccessor, fAuthPrincipalID, fAuthAliasName, fAuthCreatedByIP,
		fPolicyGrantingPolicies, fPolicyDenyingPolicy,
	} {
		s.add(f)
	}
	return s
}()

// mapRule is what a device's paths ask of a map: of all of it, or of the keys
// they name.
type mapRule struct {
	omitAll, saltAll   bool
	omitKeys, saltKeys []string
}

// omits and salts report what the rule asks for key. A map with no rule, the
// receiver nil, is written as it is.
func (m *mapRule) omits(key string) bool {
	return m != nil && (m.omitAll || slices.Contains(m.omitKeys, key))
}

func (m *mapRule) salts(key string) bool {
	return m != nil && (m.saltAll || slices.Contains(m.saltKeys, key))
}

// add records what a path that ends in the map (whole), or at one of its
// keys, asks of it.
func (m *mapRule) add(salt bool, key string, whole bool) {
	switch {
	case salt && whole:
		m.saltAll = true
	case salt:
		m.saltKeys = append(m.saltKeys, key)
	case whole:
		m.omitAll = true
	default:
		m.omitKeys = append(m.omitKeys, key)
	}
}

// redaction is what a device's salt and omit paths ask of every entry it
// writes: the fields to omit, the fields to salt, and the same for each map.
// It is compiled from the paths when the device is created and only read
// after, by the encoder as it writes: an entry is neither copied nor changed
// to be redacted, so every device is handed the same one.
//
// A field in both sets is omitted. A value is salted once however many paths
// reach it.
type redaction struct {
	omit, salt fieldSet

	credentialData     mapRule
	credentialMetadata mapRule
	conditionInputs    mapRule

	// How a value is salted: under the device's key, or by a function of the
	// caller's. With neither, no path salts anything.
	hmac   *HMACer
	saltFn SaltFunc
}

// canSalt reports whether the redaction has what it takes to salt a value.
func (r *redaction) canSalt() bool {
	return r.hmac != nil || r.saltFn != nil
}

// compile adds to the redaction what path asks: to salt what it names, or to
// omit it. A path that names no field of an entry is refused, with the
// reason, and adds nothing. Validating a path is compiling it, so the paths a
// device accepts and the paths it applies cannot drift apart.
func (r *redaction) compile(salt bool, path string) error {
	parts := strings.Split(path, ".")
	if salt {
		return r.compileSalt(parts)
	}
	return r.compileOmit(parts)
}

// leafOf records a path that ends at a field of group: parts is the field's
// name, and nothing after it. A salt path may only name a saltable one.
func (r *redaction) leafOf(group fieldGroup, salt bool, parts []string) error {
	f, ok := group.named(parts[0])
	if !ok || (salt && !saltable.has(f)) {
		return errUnknownFieldPath
	}
	if err := leaf(parts[1:]); err != nil {
		return err
	}
	if salt {
		r.salt.add(f)
	} else {
		r.omit.add(f)
	}
	return nil
}

// inputsOf records a path into the inputs of a condition, rest being what
// follows "condition". The input keys are themselves dotted
// (agent.metadata.env), so the segments after "inputs" are one key.
func (r *redaction) inputsOf(salt bool, rest []string) error {
	if rest[0] != "inputs" || slices.Contains(rest[1:], "") {
		return errUnknownFieldPath
	}
	r.conditionInputs.add(salt, strings.Join(rest[1:], "."), len(rest) == 1)
	return nil
}

// mapOf records a path into the data or the metadata of a credential, rest
// being what follows the map's name.
func (r *redaction) mapOf(name string, salt bool, rest []string) error {
	key, whole, err := mapKey(rest)
	if err != nil {
		return err
	}
	rule := &r.credentialData
	if name == "metadata" {
		rule = &r.credentialMetadata
	}
	rule.add(salt, key, whole)
	return nil
}

// compileOmit records an omit path.
// Examples: "auth", "request.client_ip", "response.credential"
func (r *redaction) compileOmit(parts []string) error {
	name, rest := parts[0], parts[1:]
	switch name {
	case "auth":
		if len(rest) == 0 {
			r.omit.add(fAuth)
			return nil
		}
		return r.omitAuth(rest)
	case "request":
		if len(rest) == 0 {
			r.omit.add(fRequest)
			return nil
		}
		if neverLogged(rest[0]) {
			return nil
		}
		return r.leafOf(requestFields, false, rest)
	case "response":
		if len(rest) == 0 {
			r.omit.add(fResponse)
			return nil
		}
		return r.omitResponse(rest)
	case "error":
		if err := leaf(rest); err != nil {
			return err
		}
		r.omit.add(fError)
		return nil
	}
	return errUnknownFieldPath
}

// omitAuth records an omit path within the Auth structure.
func (r *redaction) omitAuth(parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case name != "policy_results":
		return r.leafOf(authFields, false, parts)
	case len(rest) == 0:
		r.omit.add(fAuthPolicyResults)
		return nil
	case rest[0] != "condition":
		return r.leafOf(policyFields, false, rest)
	case len(rest) == 1:
		r.omit.add(fPolicyCondition)
		return nil
	}
	// Mirrors the salt paths: every salt path must also be omittable, for a
	// device with no HMAC key to drop what it cannot hash.
	return r.inputsOf(false, rest[1:])
}

// omitResponse records an omit path within the Response structure.
func (r *redaction) omitResponse(parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case neverLogged(name):
		return nil
	case name == "credential" && len(rest) == 0:
		r.omit.add(fResponseCredential)
		return nil
	case name == "credential" && (rest[0] == "data" || rest[0] == "metadata"):
		return r.mapOf(rest[0], false, rest[1:])
	case name == "credential":
		return r.leafOf(credentialFields, false, rest)
	case name == "auth_result" && len(rest) == 0:
		r.omit.add(fResponseAuthResult)
		return nil
	case name == "auth_result":
		return r.leafOf(authResultFields, false, rest)
	}
	return r.leafOf(responseFields, false, parts)
}

// compileSalt records a salt path.
// Examples: "auth.token_id", "request.client_ip", "response.credential.data"
func (r *redaction) compileSalt(parts []string) error {
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
		return r.saltAuth(rest)
	case "request":
		if neverLogged(rest[0]) {
			return errNeverLogged
		}
		return r.leafOf(requestFields, true, rest)
	default:
		return r.saltResponse(rest)
	}
}

// saltAuth records a salt path within the Auth structure.
func (r *redaction) saltAuth(parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case name != "policy_results":
		return r.leafOf(authFields, true, parts)
	case len(rest) == 0:
		return errNotSaltable
	case rest[0] != "condition":
		return r.leafOf(policyFields, true, rest)
	case len(rest) == 1:
		return errNotSaltable
	}
	// "...condition.inputs" salts every referenced-input value;
	// "...condition.inputs.<dotted-key>" salts one.
	return r.inputsOf(true, rest[1:])
}

// saltResponse records a salt path within the Response structure.
func (r *redaction) saltResponse(parts []string) error {
	name, rest := parts[0], parts[1:]
	switch {
	case neverLogged(name):
		return errNeverLogged
	case name != "credential" && name != "auth_result":
		return errUnknownFieldPath
	case len(rest) == 0:
		return errNotSaltable
	case name == "auth_result":
		return r.leafOf(authResultFields, true, rest)
	case rest[0] == "data" || rest[0] == "metadata":
		// Data holds the issued secret values; metadata logs in clear unless
		// salted (response.credential.metadata salts every key, .subject one).
		return r.mapOf(rest[0], true, rest[1:])
	}
	return r.leafOf(credentialFields, true, rest)
}
