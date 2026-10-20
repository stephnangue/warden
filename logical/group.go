package logical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"
)

// GroupType names where a group's membership lives. It is set when the group
// is created and never changes: a group has exactly one membership source.
type GroupType string

const (
	// GroupTypeVirtual groups hold no members: membership is computed from the
	// facts an auth mount verified about the caller's credential, through the
	// group's selectors, so members cannot be listed.
	GroupTypeVirtual GroupType = "virtual"

	// GroupTypeInternal groups list their members explicitly. Reserved: not
	// accepted yet.
	GroupTypeInternal GroupType = "internal"

	// GroupTypeDirectory groups take their membership from a directory.
	// Reserved: not accepted yet.
	GroupTypeDirectory GroupType = "directory"
)

// ParseGroupType returns the GroupType s names, or an error for a name that
// is no group type. It does not say whether the type can be created yet.
func ParseGroupType(s string) (GroupType, error) {
	switch t := GroupType(s); t {
	case GroupTypeVirtual, GroupTypeInternal, GroupTypeDirectory:
		return t, nil
	}
	return "", fmt.Errorf("unknown group type %q: one of %q, %q, %q",
		s, GroupTypeVirtual, GroupTypeInternal, GroupTypeDirectory)
}

// Bounds on a group. The selector-level bounds (names per rule, values per
// name, name and value length) are the selector package's.
const (
	MaxGroupDescriptionBytes = 1024
	MaxGroupRoles            = 64
	MaxGroupSelectors        = 16

	// MaxGroupsPerNamespace bounds the groups of one namespace. Each group write
	// rebuilds the namespace's index, and a group change makes every cached
	// admission of the namespace recompute its membership on its next request,
	// which in the worst case (every group's rules list the admission's mount)
	// evaluates every group. Measured (core/identity_groups_bench_test.go,
	// Apple M4 Pro): a rule evaluated to its last fact costs about 110 ns, so
	// 8000 one-rule groups recompute in about 0.9 ms, and a group write at that
	// size takes about 1.2 ms.
	MaxGroupsPerNamespace = 8000

	// MaxSelectorsPerNamespace bounds the selectors of all the groups of one
	// namespace together. A recompute's worst case is proportional to the rules
	// it evaluates, not to the groups, so this, not MaxGroupsPerNamespace, holds
	// it under about a millisecond when groups carry several rules.
	MaxSelectorsPerNamespace = 8000
)

// Selector is one rule of a virtual group: a fact name mapped to the values it
// may take. Every name must yield a value matching one of its values (AND
// across names, any-of within a name); a value holding an unescaped '*' or '?'
// is a glob. Every rule of a virtual group names "mount", the auth mounts it
// trusts.
type Selector map[string][]string

// Clone returns a deep copy of s, or nil for a nil selector.
func (s Selector) Clone() Selector {
	if s == nil {
		return nil
	}
	out := make(Selector, len(s))
	for k, v := range s {
		out[k] = slices.Clip(slices.Clone(v))
	}
	return out
}

// Group grants namespace roles to its members. Roles lists the roles membership
// grants, by bare name; a name with no role behind it grants nothing until the
// role exists. How a caller becomes a member depends on Type: a virtual group
// matches the caller's verified facts against Selectors and, when MaxAge is
// set, requires a credential issued no longer than MaxAge ago.
//
// A *Group published by the group store is never written again: a write builds
// a new value and publishes it, so any number of readers share one without a
// lock. Code that wants to change a group works on Clone().
type Group struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        GroupType         `json:"type"`
	Description string            `json:"description,omitempty"`
	Roles       []string          `json:"roles"` // sorted, deduplicated
	Selectors   []Selector        `json:"selectors,omitempty"`
	MaxAge      time.Duration     `json:"max_age,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Clone returns a deep copy of g, or nil for a nil group. Its slices have no
// spare capacity, so an append to one always allocates and never writes into
// memory another copy could see.
func (g *Group) Clone() *Group {
	if g == nil {
		return nil
	}
	out := *g
	out.Roles = slices.Clip(slices.Clone(g.Roles))
	if g.Selectors != nil {
		out.Selectors = make([]Selector, len(g.Selectors))
		for i, s := range g.Selectors {
			out.Selectors[i] = s.Clone()
		}
	}
	out.Metadata = maps.Clone(g.Metadata)
	return &out
}

// Hash identifies the group's content: two groups with the same name, type,
// roles, selectors, max_age and metadata hash alike, whenever they were
// written. A writer that read a group passes its hash back to make the write
// conditional on nothing having changed since. The ID and the timestamps are
// not part of it.
func (g *Group) Hash() string {
	h := sha256.New()
	// Length-prefixed, so no choice of values can make two different groups
	// serialize to the same bytes.
	field := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	list := func(vs []string) {
		fmt.Fprintf(h, "%d:", len(vs))
		for _, v := range vs {
			field(v)
		}
	}
	field(g.Name)
	field(string(g.Type))
	field(g.Description)
	list(g.Roles)
	fmt.Fprintf(h, "%d:", len(g.Selectors))
	for _, s := range g.Selectors {
		names := slices.Sorted(maps.Keys(s))
		fmt.Fprintf(h, "%d:", len(names))
		for _, name := range names {
			field(name)
			list(s[name])
		}
	}
	fmt.Fprintf(h, "%d;", int64(g.MaxAge))
	keys := slices.Sorted(maps.Keys(g.Metadata))
	fmt.Fprintf(h, "%d:", len(keys))
	for _, k := range keys {
		field(k)
		field(g.Metadata[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GroupLabel is how audit names the group that granted a role: "group:<name>".
func GroupLabel(name string) string { return "group:" + name }
