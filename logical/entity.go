package logical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// EntityState is an entity's lifecycle state.
type EntityState string

const (
	// EntityStateActive is an entity in service.
	EntityStateActive EntityState = "active"

	// EntityStateSuspended is the reversible kill switch: the entity and its
	// native identities stay as they are, and it can be made active again.
	EntityStateSuspended EntityState = "suspended"

	// EntityStateRetired is final. The record stays, read-only, for audit; it
	// keeps its aliases, so its native identities stay bound to it, and they
	// may be moved to another entity.
	EntityStateRetired EntityState = "retired"
)

// ParseEntityState checks a state: "" is EntityStateActive, the default; the
// three states pass; anything else is an error.
func ParseEntityState(s string) (EntityState, error) {
	switch st := EntityState(s); st {
	case "":
		return EntityStateActive, nil
	case EntityStateActive, EntityStateSuspended, EntityStateRetired:
		return st, nil
	}
	return "", fmt.Errorf("unknown entity state %q: one of %q, %q, %q",
		s, EntityStateActive, EntityStateSuspended, EntityStateRetired)
}

// GovernedByWarden is the governed_by value of an entity governed by Warden
// itself: named, with a sponsor and a description, and linked to no directory.
const GovernedByWarden = "warden"

// Bounds on an entity.
const (
	MaxEntityDescriptionBytes = 1024
	MaxEntitySponsors         = 16
	MaxEntitySponsorBytes     = 256
	MaxEntityAliases          = 32
	MaxEntityProfileBytes     = 256

	// MaxEntitiesPerNamespace bounds the entities of one namespace: every
	// entity and every alias is held in memory on the active node.
	MaxEntitiesPerNamespace = 50000
)

// AgentProfile describes an agent entity. It is descriptive data for listings
// and policy conditions; nothing is enforced on it.
type AgentProfile struct {
	Purpose   string `json:"purpose,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

// EntityAlias is one native identity an entity claims: the name a credential
// presents through the auth mount with MountAccessor (the mount's
// alias_name_source). A native identity belongs to at most one entity of its
// namespace.
type EntityAlias struct {
	MountAccessor string    `json:"mount_accessor"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"created_at"`
}

// Entity is an identity of record in Warden: one accountable agent, the native
// identities (aliases) it presents through any number of auth mounts, the
// humans accountable for it (sponsors) and its lifecycle state.
//
// An *Entity published by the identity store is never written again: a write
// builds a new value and publishes it, so any number of readers share one
// without a lock. Code that wants to change an entity works on Clone().
type Entity struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"` // EntityKindAgent (v1); fixed at creation
	Description string            `json:"description,omitempty"`
	Sponsors    []string          `json:"sponsors,omitempty"` // sorted, deduplicated
	State       EntityState       `json:"state"`
	Profile     *AgentProfile     `json:"profile,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Aliases     []EntityAlias     `json:"aliases,omitempty"` // sorted by (MountAccessor, Name)
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// GovernedBy returns what governs the entity, derived from its fields and never
// written: GovernedByWarden when it has at least one sponsor and a
// description, "" (ungoverned) otherwise.
func (e *Entity) GovernedBy() string {
	if e == nil || len(e.Sponsors) == 0 || strings.TrimSpace(e.Description) == "" {
		return ""
	}
	return GovernedByWarden
}

// UngovernedReason says what an ungoverned entity lacks, or "" for a governed
// one.
func (e *Entity) UngovernedReason() string {
	switch {
	case e == nil:
		return ""
	case len(e.Sponsors) == 0 && strings.TrimSpace(e.Description) == "":
		return "no sponsor and no description"
	case len(e.Sponsors) == 0:
		return "no sponsor"
	case strings.TrimSpace(e.Description) == "":
		return "no description"
	}
	return ""
}

// Clone returns a deep copy of e, or nil for a nil entity. Its slices have no
// spare capacity, so an append to one always allocates.
func (e *Entity) Clone() *Entity {
	if e == nil {
		return nil
	}
	out := *e
	out.Sponsors = slices.Clip(slices.Clone(e.Sponsors))
	out.Aliases = slices.Clip(slices.Clone(e.Aliases))
	out.Metadata = maps.Clone(e.Metadata)
	if e.Profile != nil {
		p := *e.Profile
		out.Profile = &p
	}
	return &out
}

// Hash identifies the entity's content: its name, kind, description, sponsors,
// state, profile, metadata and aliases. A writer that read an entity passes
// its hash back to make the write conditional on nothing having changed since.
// The ID and the timestamps are not part of it.
func (e *Entity) Hash() string {
	h := sha256.New()
	// Length-prefixed, so no choice of values can make two different entities
	// serialize to the same bytes.
	field := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	field(e.Name)
	field(e.Kind)
	field(e.Description)
	fmt.Fprintf(h, "%d:", len(e.Sponsors))
	for _, s := range e.Sponsors {
		field(s)
	}
	field(string(e.State))
	if e.Profile == nil {
		field("")
	} else {
		field("profile")
		field(e.Profile.Purpose)
		field(e.Profile.Runtime)
		field(e.Profile.Publisher)
	}
	keys := slices.Sorted(maps.Keys(e.Metadata))
	fmt.Fprintf(h, "%d:", len(keys))
	for _, k := range keys {
		field(k)
		field(e.Metadata[k])
	}
	fmt.Fprintf(h, "%d:", len(e.Aliases))
	for _, a := range e.Aliases {
		field(a.MountAccessor)
		field(a.Name)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FindAlias returns the index of the alias (accessor, name) in e.Aliases, or
// -1.
func (e *Entity) FindAlias(accessor, name string) int {
	return slices.IndexFunc(e.Aliases, func(a EntityAlias) bool {
		return a.MountAccessor == accessor && a.Name == name
	})
}

// SortAliases orders aliases by (MountAccessor, Name), the order an entity
// keeps them in.
func SortAliases(aliases []EntityAlias) {
	slices.SortFunc(aliases, func(a, b EntityAlias) int {
		if c := strings.Compare(a.MountAccessor, b.MountAccessor); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// ValidSponsor reports whether s can name a sponsor: non-empty, at most
// MaxEntitySponsorBytes, valid UTF-8, without spaces or control characters (a
// UPN or an email address in v1).
func ValidSponsor(s string) bool {
	if s == "" || len(s) > MaxEntitySponsorBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
