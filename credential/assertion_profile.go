package credential

// This file is the assertion-profile surface. An assertion profile names the CLAIM
// SHAPE of a warden_identity assertion, so the shape is a pluggable, named decision
// instead of a literal in the issuer.
//
// Naming rule for any new profile: snake_case single tokens, like every sibling
// enum (warden_identity, jwt_bearer, sts_assume_role); NAME THE SHAPE by default;
// use a vendor name ONLY when the profile is source-pinned to that vendor via
// AssertionProfileSourcePinned. That rule is what stops a future contributor adding
// "github" for what is really a packed-subject shape.

import (
	"fmt"
	"slices"
	"time"
)

// ConfigAssertionProfile is the spec-config key selecting the claim shape of a
// warden_identity assertion. Absent/empty means DefaultAssertionProfileName, for
// every source type — the profile is never derived from the source.
//
// Deriving it would be an upgrade-time outage: a profile's whole job can be to
// change `sub`, and an AWS IAM trust policy binds on `sub`, so every existing spec
// would start presenting a subject its trust policy does not match with nothing in
// the spec config having changed. It is also consistent with its siblings —
// assertion_resource, assertion_metadata_claims and assertion_user_claims are all
// opt-in, precisely because they change what crosses a trust boundary, and the
// claim SHAPE is the largest such change there is.
//
// Valid only when subject_token_source or actor_token_source is warden_identity.
const ConfigAssertionProfile = "assertion_profile"

// DefaultAssertionProfileName is the profile an unset ConfigAssertionProfile
// selects. It reproduces the historical claim set exactly.
const DefaultAssertionProfileName = "default"

// reservedAssertionProfileNames are names that can never be registered as a
// profile: sibling values, in spec or source config, that already name an assertion
// or token shape, so an operator could confuse one with a profile. Register rejects
// them at startup, so the reservation fires when a builtin is added, not only when
// an operator writes one.
//
// Unexported, with IsReservedAssertionProfileName as the only read path: an exported
// map would let any importer delete("id_jag") before NewCore and quietly un-reserve
// it.
//
// The list is literal on purpose and cannot be derived from the constants it
// mirrors: the exchange grant values are unexported in package drivers, and drivers
// imports credential, not the reverse. Drift is guarded by tests that iterate the
// SAME slices the validators use — tokenExchangeGrants in drivers, and
// subjectTokenSources / actorTokenSources here — so a value added to a validator
// fails a test until it is reserved too.
//
// Source-type names (aws, gcp, azure, ...) are deliberately NOT reserved: a
// source-pinned profile shares its source's name on purpose. Nor are client-auth
// methods like private_key_jwt: a client-assertion shape is a plausible future
// profile in its own right.
var reservedAssertionProfileNames = map[string]struct{}{
	// Empty is not a name.
	"": {},

	// token_exchange `grant` values. id_jag in particular already means the shipped
	// two-leg Cross-App Access exchange; an assertion_profile=id_jag would be two
	// unrelated features spelled identically in one spec config.
	"rfc8693":    {},
	"jwt_bearer": {},
	"id_jag":     {},

	// *_token_source values.
	SourceAgentIdentity:  {},
	SourceUserIdentity:   {},
	SourceWardenIdentity: {},
	SourceNone:           {},

	// Anything that looks like a typ / token-type value. typ IS profile-controlled,
	// so a profile name must not imply a header the profile may not actually set.
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"jwt":           {},
	"saml2":         {},
	"at_jwt":        {},
}

// IsReservedAssertionProfileName reports whether name can never be registered as an
// assertion profile.
func IsReservedAssertionProfileName(name string) bool {
	_, reserved := reservedAssertionProfileNames[name]
	return reserved
}

// AssertionProfileName returns the spec's configured profile name, defaulting to
// DefaultAssertionProfileName when unset.
func AssertionProfileName(config Config) string {
	if p := config.Get(ConfigAssertionProfile); p != "" {
		return p
	}
	return DefaultAssertionProfileName
}

// AssertionIdentity is the resolved identity a profile renders into claims. It is a
// plain struct rather than a token entry so profiles stay pure and this package
// does not import logical (which imports credential).
type AssertionIdentity struct {
	// PrincipalID is the raw principal — never the composite subject. It can carry
	// delimiters (a SPIFFE ID holds colons), which is why WardenSubject puts it last.
	PrincipalID string
	// RoleName is the auth role the principal logged in under. It CAN be empty: a
	// root token carries no role, so a profile must define what it renders rather
	// than assume a value.
	RoleName string
	// NamespaceID is the namespace's stable ID, Warden-generated and delimiter-free.
	NamespaceID string
	// NamespacePath is the namespace's path. Sound to use alongside NamespaceID only
	// because a namespace cannot be renamed, so path and ID move together.
	NamespacePath string
	// MountAccessor identifies the auth mount, Warden-generated and delimiter-free.
	MountAccessor string
}

// WardenSubject builds the globally-unique subject of a minted assertion:
// "wid:{namespaceID}:{mountAccessor}:{principalID}". namespaceID and the mount
// accessor are Warden-generated and delimiter-free; the possibly-delimiter-bearing
// principal (e.g. a SPIFFE ID) is the trailing segment, so the value is
// unambiguous and an operator can bind a role to a mount with a `sub` StringLike
// prefix "wid:{nsID}:{accessor}:*".
func (id AssertionIdentity) WardenSubject() string {
	return fmt.Sprintf("wid:%s:%s:%s", id.NamespaceID, id.MountAccessor, id.PrincipalID)
}

// AssertionRequest carries everything a profile renders into claims. It is a struct
// rather than positional arguments so a later profile that needs to know which slot
// it fills (subject vs actor) is an additive field, not a signature change.
//
// The three time fields and JTI are computed by the ISSUER, not the profile. A
// profile formats them; it does not choose them. That is what lets the issuer's
// post-render guard compare them exactly.
type AssertionRequest struct {
	// Issuer is the `iss` a profile must emit verbatim.
	Issuer string
	// Identity is the principal the assertion asserts.
	Identity AssertionIdentity
	// Audience is the `aud` — the upstream the assertion is minted for.
	Audience string
	// IssuedAt, NotBefore and ExpiresAt are issuer-computed. NotBefore already
	// carries the issuer's clock-skew leeway. Emit them as int64 Unix seconds.
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	// JTI is the issuer-generated token identifier.
	JTI string
	// Metadata is the projected login metadata. READ-ONLY to the profile: it is
	// shared with the driver templating path.
	Metadata map[string]string
	// Resource is the resolved resource name, empty when suppressed or underivable.
	Resource string
	// UserClaims is the projected user claim map, always carrying "sub" when
	// non-empty. READ-ONLY to the profile, for the same reason as Metadata.
	UserClaims map[string]string
}

// AssertionProfile renders an AssertionRequest into the claim set of a
// warden_identity assertion.
//
// A profile controls CLAIMS and the `typ` header, nothing else. Audience, TTL and
// signing algorithm keep their existing homes. More generally: a profile may NARROW
// a security property, never WIDEN one — AssertionProfileSourcePinned is an instance
// of that rule, and it is why TTL is not profile-settable (the issuer derives the
// retired-signing-key pruning cutoff from the assertion TTL, so a profile that
// lengthened it would let an assertion outlive the key that signed it).
type AssertionProfile interface {
	// Name is the value an operator writes in ConfigAssertionProfile.
	Name() string
	// Typ is the JOSE `typ` header. Must be non-empty.
	Typ() string
	// Claims renders the claim set.
	//
	// Claims MUST be pure: a fresh map on every call, no shared state, and it must
	// never mutate req.Metadata or req.UserClaims — those maps are shared with the
	// request's assertion setup and the driver templating path. It can run
	// concurrently for one spec, so purity is load-bearing, not stylistic.
	//
	// TYPES ARE PART OF THE CONTRACT, because the issuer's post-render guard
	// compares exactly: the time claims (iat, nbf, exp) must be int64 Unix seconds
	// — what time.Time.Unix() returns — and iss, sub, aud and jti must be string.
	Claims(req AssertionRequest) (map[string]any, error)
	// ValidateSpec runs at spec-create and spec-update. Config only, no I/O.
	//
	// Its job is to reject an assertion_* key whose SOLE effect is a claim this
	// profile never emits. It must NOT reject assertion_user_claims or
	// assertion_metadata_claims even when the profile drops those claims: both also
	// drive {{user.*}} / {{agent.*}} request templating, so rejecting them would
	// break specs that do not care about the assertion at all.
	ValidateSpec(config Config) error
}

// AssertionProfileSourcePinned is an optional capability: a profile shaped for one
// vendor's verifier declares the source types it may be used with, so pairing it
// with an unrelated source fails at spec-create instead of minting a token that
// upstream cannot bind. Discovered by type assertion, like ExchangeMinter.
//
// The pin is ONE-DIRECTIONAL: a pinned profile requires one of its source types,
// but a source of that type never requires the profile. ConfigAssertionProfile is
// not mandatory on any spec.
type AssertionProfileSourcePinned interface {
	SourceTypes() []string
}

// ValidateAssertionProfileConfig validates a spec's ConfigAssertionProfile against
// the registry: that the named profile exists, that a source-pinned profile is
// paired with a source type it supports, and that the profile accepts the rest of
// the spec's assertion_* keys.
//
// A nil registry returns nil, mirroring the credentialTypeRegistry nil guard in the
// core config store — a test or bootstrap without registries can persist a spec, and
// mint-time resolution still fails closed on a name this build does not have.
//
// sourceType is a parameter rather than something re-derived here, following
// ValidateSecretSelection: the pin is checked in one place instead of making core
// resolve the profile a second time to type-assert it. It is stable once checked —
// a source's type is immutable and a spec's source cannot change on update.
func ValidateAssertionProfileConfig(reg *AssertionProfileRegistry, config Config, sourceType string) error {
	if reg == nil {
		return nil
	}

	name := AssertionProfileName(config)
	profile, err := reg.Resolve(name)
	if err != nil {
		// Prefixed with the field, like every sibling assertion_* rejection, so an
		// operator's 400 names the key they got wrong.
		return fmt.Errorf("field '%s': %w", ConfigAssertionProfile, err)
	}

	if pinned, ok := profile.(AssertionProfileSourcePinned); ok {
		allowed := pinned.SourceTypes()
		if !slices.Contains(allowed, sourceType) {
			return fmt.Errorf("field '%s': profile '%s' requires a source of type %v, but the source is '%s'",
				ConfigAssertionProfile, name, allowed, sourceType)
		}
	}

	return profile.ValidateSpec(config)
}
