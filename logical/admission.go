package logical

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/stephnangue/warden/helper/selector"
)

// Entity kinds a mount admits, answered as the built-in fact "kind".
const (
	EntityKindAgent = "agent"
	EntityKindHuman = "human"
)

// ParseEntityKind checks a mount's entity kind: "" is EntityKindAgent, the
// default; EntityKindAgent and EntityKindHuman pass; anything else is an error.
func ParseEntityKind(s string) (string, error) {
	switch s {
	case "":
		return EntityKindAgent, nil
	case EntityKindAgent, EntityKindHuman:
		return s, nil
	}
	return "", fmt.Errorf("entity kind %q is not %q or %q", s, EntityKindAgent, EntityKindHuman)
}

// Admission is what an auth mount verified about one credential. The auth
// method builds a fresh one for each login and core completes it in
// LoginCreateToken (it sets MountPath, MountAccessor and AliasName) before the
// token is stored; from then on its exported fields are never written.
//
// One *Admission is shared by pointer: the token store keeps it on the stored
// TokenEntry, and every per-request copy of that entry holds the same pointer.
// Readers on any number of goroutines need no lock: the exported fields do not
// change after LoginCreateToken, and the one field that does, the cached
// membership, is an atomic pointer to an immutable Membership, replaced whole
// (LoadMembership, CompareAndSwapMembership). An Admission must not be copied
// by value.
type Admission struct {
	// MountPath is the admitting mount's path relative to its namespace
	// ("auth/jwt/", never "ns1/auth/jwt/"), answered as the fact "mount". Only
	// core sets it, when it completes the admission (a login, or a discovery
	// admission); an auth method leaves it empty.
	MountPath string

	// MountAccessor is the admitting mount's accessor, set with MountPath.
	// With AliasName it keys the native identity: a mount disabled and enabled
	// again is a new accessor, and so a new trust root.
	MountAccessor string

	// AliasName is the native identity the credential presents: the first
	// value of the fact the mount names as its alias source (MountNaming
	// AliasSource), derived by DeriveAlias when core completes the admission,
	// under the naming in force then. Empty when the mount names no source or
	// the credential carries no usable value; an empty alias never fails a
	// login.
	AliasName string

	// Facts are the raw verified facts, keyed by the names the credential
	// carries (claims, certificate or service-account fields). They are never
	// renamed: names reach them only through the mount's Mapping.
	Facts selector.Facts

	// PrincipalID is the principal a login with this credential would be
	// issued for, derived as that auth method's login derives it (the JWT's
	// user_claim, the certificate's principal field, the service account's
	// username, the SPIFFE ID). Set by the auth method that builds the
	// admission.
	PrincipalID string

	// Mount is the admitting mount's live naming, shared with every other
	// admission of that mount, so a mapping edit reaches cached admissions.
	Mount *MountFacts

	// IssuedAt is when the credential was issued, when it says so; zero
	// otherwise.
	IssuedAt time.Time

	// AudienceBound reports that the credential's audience was checked
	// against the mount's bound_audiences when it was admitted. It records
	// what that admission verified, so a later config edit neither grants nor
	// withdraws it for a credential already admitted.
	AudienceBound bool

	// Bytes estimates the memory Facts retains (the decoded claims, or the
	// strings of a table), set by the auth method that builds the admission.
	// The token cache counts it in the cost of the entry that holds it.
	Bytes int64

	// membership caches the groups and roles computed for this admission.
	// It lives here so the cached token entry and every per-request copy share
	// it: a recompute on one request is seen by the next.
	membership atomic.Pointer[Membership]
}

// LoadMembership returns the cached membership, or nil when none has been
// computed (or a is nil). It does not allocate.
func (a *Admission) LoadMembership() *Membership {
	if a == nil {
		return nil
	}
	return a.membership.Load()
}

// CompareAndSwapMembership caches next if the cached membership is still old,
// and reports whether it did. Two requests that computed a membership from the
// same snapshot and naming race benignly: their results are equal, and either
// may win. Two that straddled a group's valid_until may differ, one still
// holding the group the other dropped; whichever is kept, its ValidUntil is no
// later than that instant, so the first request past it computes again: the
// race heals itself.
func (a *Admission) CompareAndSwapMembership(old, next *Membership) bool {
	if a == nil {
		return false
	}
	return a.membership.CompareAndSwap(old, next)
}

// Membership is what an admission's verified facts earn it in its namespace:
// the groups one of whose rules matches, and the roles those groups grant. It is
// computed from one group snapshot (Gen) and one mount naming (Naming), and is
// immutable once built; a change to either, or the passing of ValidUntil,
// makes the next request compute a new one.
type Membership struct {
	// Gen is the generation of the namespace's group snapshot it was computed
	// from.
	Gen uint64

	// Naming is the mount naming it was computed from; pointer identity is the
	// mapping generation.
	Naming *MountNaming

	// ValidUntil is the earliest valid_until among the matched groups that set
	// one, after which that group stops granting; zero when none does. The
	// membership holds while now <= ValidUntil.
	ValidUntil time.Time

	// Groups are the names of the matched groups, sorted. Never nil, and shared:
	// callers must not modify it.
	Groups []string

	// Roles maps each granted role name to the group that grants it: the first
	// granting group in name order. Nil when no role is granted.
	Roles map[string]GroupGrant

	// Metadata are the mount's mapped facts rendered as strings, under Naming.
	// Nil when nothing is rendered.
	Metadata map[string]string
}

// GroupGrant names the group a role is granted through.
type GroupGrant struct {
	Group string // the group's name
	Label string // GroupLabel(Group), built once when the group is compiled
}

// ErrAdmissionNotSerializable is MarshalJSON's refusal: an admission carries
// verified facts, which never leave the process.
var ErrAdmissionNotSerializable = errors.New("an admission is in-process only and is never serialized")

// MarshalJSON refuses to encode the admission, so a response, log or audit
// entry that carried one by mistake fails to encode rather than disclose the
// facts. Every struct field holding an admission is also tagged json:"-".
func (a *Admission) MarshalJSON() ([]byte, error) {
	return nil, ErrAdmissionNotSerializable
}

// Size returns the admission's byte estimate for cache accounting: Bytes,
// or 0 for a nil admission or a negative estimate.
func (a *Admission) Size() int64 {
	if a == nil || a.Bytes < 0 {
		return 0
	}
	return a.Bytes
}

// MountFacts is owned by one auth mount and shared by pointer with every
// admission the mount produces. Readers load the naming in force without a
// lock. A published MountNaming is never modified, so a reader sees either the
// old naming or the new one, whole.
type MountFacts struct {
	current atomic.Pointer[MountNaming]
}

// Publish makes n the naming in force. Only the owning mount calls it, from the
// one place it installs a configuration (a config write, setup, load).
func (m *MountFacts) Publish(n *MountNaming) {
	m.current.Store(n)
}

// Load returns the naming in force, or nil when m is nil or the mount has not
// published one.
func (m *MountFacts) Load() *MountNaming {
	if m == nil {
		return nil
	}
	return m.current.Load()
}

// MountNaming is how one mount configuration names its facts: the canonical
// names it answers, the kind of entity it admits, and the fact its native
// identities (aliases) are taken from. It is immutable once published.
type MountNaming struct {
	Mapping *selector.Mapping // built-in and mapped fact names
	Kind    string            // EntityKindAgent or EntityKindHuman

	// AliasSource is the fact name, visible under Mapping, whose first value
	// is an admission's alias: the native identity the identity store keys
	// entities by, with the mount accessor. Empty when the mount names none,
	// and then no admission of the mount carries an alias.
	AliasSource string
}

// NewMountNaming returns a naming for mapping and kind, which ParseEntityKind
// checks: an empty kind is EntityKindAgent and an unknown one is an error, so a
// naming built here always has a valid Kind.
func NewMountNaming(mapping *selector.Mapping, kind string) (*MountNaming, error) {
	k, err := ParseEntityKind(kind)
	if err != nil {
		return nil, err
	}
	return &MountNaming{Mapping: mapping, Kind: k}, nil
}

// FactsProvider is implemented by auth backends that admit credentials as
// facts. Backends are reached through the router as logical.Backend, like
// AuthorizationServerProvider. Core consults it only to warn: when a group is
// written (about a fact name no mount produces) and when a provider
// configuration is read (about an auth path naming a mount of the wrong
// kind), never on the request path.
type FactsProvider interface {
	// FactNames returns every fact name the mount answers, built-in and
	// mapped, under its current configuration.
	FactNames() []string
	// EntityKind returns the kind of entity the mount admits under its
	// current configuration (EntityKindAgent or EntityKindHuman), or "" when
	// it publishes no naming.
	EntityKind() string
}

// CredentialFormat names the credential a transparent auth method admits, which
// tells core where in a request to find it.
type CredentialFormat string

const (
	// CredentialFormatJWT is a JWT bearer, verified against the mount's keys.
	CredentialFormatJWT CredentialFormat = "jwt"
	// CredentialFormatKubernetesJWT is a Kubernetes service account JWT bearer,
	// verified by a TokenReview. It travels as CredentialFormatJWT does.
	CredentialFormatKubernetesJWT CredentialFormat = "k8s_sa_jwt"
	// CredentialFormatCert is a TLS client certificate, from the connection or
	// a trusted proxy's forwarding header.
	CredentialFormatCert CredentialFormat = "cert"
	// CredentialFormatSPIFFE is either SVID: a JWT-SVID bearer, or else an
	// X.509-SVID client certificate.
	CredentialFormatSPIFFE CredentialFormat = "spiffe"
)

// CredentialFormatProvider is implemented by auth methods that admit a
// credential presented with each request (transparent authentication). Core
// asks it on the request path, through the backend the router already returned
// with the mount, to take the credential from the request; an auth method that
// does not implement it does not support transparent authentication. The
// format is fixed per auth method: it never depends on configuration.
type CredentialFormatProvider interface {
	CredentialFormat() CredentialFormat
}

// Lookup answers the canonical fact name against naming n: "mount" from the
// admission, "kind" from n, and any other name through n's Mapping into Facts.
// A name the mapping does not answer is invisible and yields an empty Cursor,
// as does a nil admission or naming. An empty MountPath or Kind is absent too;
// NewMountNaming never yields an empty Kind, so only a hand-built MountNaming
// has one. Callers load n once (Mount.Load()) and pass it to every lookup of
// one evaluation, so all of them see one naming. Lookup does not allocate.
func (a *Admission) Lookup(n *MountNaming, name string) selector.Cursor {
	if a == nil || n == nil {
		return selector.Cursor{}
	}
	switch name {
	case selector.NameMount:
		if a.MountPath == "" {
			return selector.Cursor{}
		}
		return selector.One(a.MountPath)
	case selector.NameKind:
		if n.Kind == "" {
			return selector.Cursor{}
		}
		return selector.One(n.Kind)
	}
	if a.Facts == nil {
		return selector.Cursor{}
	}
	key, ok := n.Mapping.Resolve(name)
	if !ok {
		return selector.Cursor{}
	}
	return a.Facts.Lookup(key)
}

// MaxAliasNameBytes bounds an alias. A longer value yields no alias.
const MaxAliasNameBytes = 512

// DeriveAlias returns the alias the admission presents under naming n: the
// first value of n.AliasSource, rendered by selector.FormatScalar. It is ""
// when a or n is nil, n names no source, the fact is absent, or the value is
// empty, longer than MaxAliasNameBytes, not valid UTF-8, or holds a control
// character: such a value cannot name a native identity, and an alias that
// cannot be derived never fails a login.
func (a *Admission) DeriveAlias(n *MountNaming) string {
	if a == nil || n == nil || n.AliasSource == "" {
		return ""
	}
	cur := a.Lookup(n, n.AliasSource)
	v, ok := cur.Next()
	if !ok {
		return ""
	}
	var buf [64]byte
	s := string(selector.FormatScalar(buf[:0], v))
	if !ValidAliasName(s) {
		return ""
	}
	return s
}

// ValidAliasName reports whether s can name a native identity: non-empty, at
// most MaxAliasNameBytes, valid UTF-8 and free of control characters.
func ValidAliasName(s string) bool {
	if s == "" || len(s) > MaxAliasNameBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// RenderMetadata renders the facts n maps (not the built-ins, unless mapped to
// themselves) as token metadata: each value through selector.FormatScalar, the
// values of a multi-valued fact joined with commas. A fact the admission does
// not carry is left out. It returns nil when nothing is rendered.
func (a *Admission) RenderMetadata(n *MountNaming) map[string]string {
	if a == nil || n == nil {
		return nil
	}
	var out map[string]string
	var buf []byte
	for _, name := range n.Mapping.Mapped() {
		cur := a.Lookup(n, name)
		// Probe a copy: a present fact may render as "", an absent one is skipped.
		if probe := cur; !hasValue(&probe) {
			continue
		}
		buf = selector.AppendValues(buf[:0], &cur, ',')
		if out == nil {
			out = make(map[string]string, len(n.Mapping.Mapped()))
		}
		out[name] = string(buf)
	}
	return out
}

func hasValue(c *selector.Cursor) bool {
	_, ok := c.Next()
	return ok
}
