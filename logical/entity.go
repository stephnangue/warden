package logical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
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
// itself: with an accepted sponsor and a description, and linked to no
// directory.
const GovernedByWarden = "warden"

// Bounds on an entity.
const (
	MaxEntityDescriptionBytes = 1024
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

// SponsorType says what a sponsor entry names. One type exists; the tag is
// there so another can be added later, with a storage version bump.
type SponsorType string

// SponsorTypeGroup names a virtual group of humans, by namespace and group ID.
const SponsorTypeGroup SponsorType = "group"

// SponsorActor is who proposed or accepted a sponsor: the native identity of
// the human (its mount's accessor and its alias), which stays unambiguous when
// two mounts map the same principal, and the principal beside them for
// reading. A token no mount issued (root, a service token) has the principal
// alone.
type SponsorActor struct {
	MountAccessor string `json:"mount_accessor,omitempty"`
	Alias         string `json:"alias,omitempty"`
	Principal     string `json:"principal"`
}

// EntitySponsor is a team accountable for an entity: the entity's sponsor once
// a member of the team accepted it (AcceptedAt set), a proposed handover
// before.
type EntitySponsor struct {
	Type SponsorType `json:"type"`

	// Namespace is the ID of the group's namespace: the entity's, or one of
	// its ancestors'.
	Namespace string `json:"namespace"`

	// GroupID is the group's ID, so a group deleted and created again under
	// the same name is never taken for the one the entry names.
	GroupID string `json:"group_id"`

	// Group is the group's name.
	Group string `json:"group"`

	AddedBy    SponsorActor `json:"added_by"`
	AddedAt    time.Time    `json:"added_at"`
	AcceptedBy SponsorActor `json:"accepted_by,omitzero"`
	AcceptedAt time.Time    `json:"accepted_at,omitzero"`
}

// Same reports whether s and o name the same team: both nil, or the same
// group of the same namespace.
func (s *EntitySponsor) Same(o *EntitySponsor) bool {
	if s == nil || o == nil {
		return s == o
	}
	return s.Namespace == o.Namespace && s.GroupID == o.GroupID
}

// clone returns a copy of s, or nil.
func (s *EntitySponsor) clone() *EntitySponsor {
	if s == nil {
		return nil
	}
	out := *s
	return &out
}

// Entity is an identity of record in Warden: one accountable agent, the native
// identities (aliases) it presents through any number of auth mounts, the
// team accountable for it (its sponsor) and its lifecycle state.
//
// An *Entity published by the identity store is never written again: a write
// builds a new value and publishes it, so any number of readers share one
// without a lock. Code that wants to change an entity works on Clone().
type Entity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // EntityKindAgent (v1); fixed at creation
	Description string `json:"description,omitempty"`

	// Sponsor is the accepted sponsor, which counts toward governance;
	// PendingSponsor a proposed handover, which never does. They never name
	// the same group.
	Sponsor        *EntitySponsor `json:"sponsor,omitempty"`
	PendingSponsor *EntitySponsor `json:"pending_sponsor,omitempty"`

	State     EntityState       `json:"state"`
	Profile   *AgentProfile     `json:"profile,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Aliases   []EntityAlias     `json:"aliases,omitempty"` // sorted by (MountAccessor, Name)
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// GovernedBy returns what governs the entity, derived from its fields and never
// written: GovernedByWarden when it has an accepted sponsor and a
// description, "" (ungoverned) otherwise. A pending handover changes nothing.
func (e *Entity) GovernedBy() string {
	if e == nil || e.Sponsor == nil || strings.TrimSpace(e.Description) == "" {
		return ""
	}
	return GovernedByWarden
}

// UngovernedReason says what an ungoverned entity lacks, or "" for a governed
// one.
func (e *Entity) UngovernedReason() string {
	if e == nil {
		return ""
	}
	var missing []string
	if e.Sponsor == nil {
		reason := "no sponsor"
		if p := e.PendingSponsor; p != nil {
			reason += fmt.Sprintf(" (handover to group %q pending)", p.Group)
		}
		missing = append(missing, reason)
	}
	if strings.TrimSpace(e.Description) == "" {
		missing = append(missing, "no description")
	}
	return strings.Join(missing, " and ")
}

// Clone returns a deep copy of e, or nil for a nil entity. Its slices have no
// spare capacity, so an append to one always allocates.
func (e *Entity) Clone() *Entity {
	if e == nil {
		return nil
	}
	out := *e
	out.Sponsor = e.Sponsor.clone()
	out.PendingSponsor = e.PendingSponsor.clone()
	out.Aliases = slices.Clip(slices.Clone(e.Aliases))
	out.Metadata = maps.Clone(e.Metadata)
	if e.Profile != nil {
		p := *e.Profile
		out.Profile = &p
	}
	return &out
}

// Hash identifies the entity's content: its name, kind, description, sponsor
// and pending handover (who proposed and accepted each, not when), state,
// profile, metadata and aliases. A writer that read an entity passes its hash
// back to make the write conditional on nothing having changed since. The ID
// and the timestamps are not part of it.
func (e *Entity) Hash() string {
	h := sha256.New()
	// Length-prefixed, so no choice of values can make two different entities
	// serialize to the same bytes.
	field := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	field(e.Name)
	field(e.Kind)
	field(e.Description)
	actor := func(a SponsorActor) {
		field(a.MountAccessor)
		field(a.Alias)
		field(a.Principal)
	}
	for _, s := range []*EntitySponsor{e.Sponsor, e.PendingSponsor} {
		if s == nil {
			field("")
			continue
		}
		field("sponsor")
		field(string(s.Type))
		field(s.Namespace)
		field(s.GroupID)
		field(s.Group)
		actor(s.AddedBy)
		actor(s.AcceptedBy)
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
