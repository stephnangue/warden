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

// Bounds on a group. The bounds inside a rule (selectors per rule, values per
// selector, name and value length) are the selector package's.
const (
	MaxGroupDescriptionBytes = 1024
	MaxGroupRoles            = 64
	MaxGroupRules            = 16

	// MaxGroupsPerNamespace bounds the groups of one namespace. Each group write
	// rebuilds the namespace's index, and a recompute in which every group
	// matches lists every group and fills a role map. Measured
	// (core/identity_groups_bench_test.go, Apple M4 Pro): a group write at
	// 8000 groups takes about 1.2 ms; 8000 groups all matching, with the two
	// selectors per rule MaxSelectorsPerNamespace then allows, recompute in
	// about 0.8 ms (1.3 MB, 56 allocations).
	MaxGroupsPerNamespace = 8000

	// MaxSelectorsPerNamespace bounds the selectors ("mount" included) across
	// every rule of every group of one namespace. A group change makes every
	// cached admission of the namespace recompute its membership on its next
	// request, and the worst case (every rule lists the admission's mount and
	// fails only on its last selector) looks up and compares every selector
	// once: about 60 ns a selector when each matches after an exact value and
	// a glob, so 16000 selectors recompute in about 0.96 ms. That assumes a
	// selector's values short-circuit on the first match, as any-of values do;
	// a selector whose every one of up to selector.MaxRuleValues globs must be
	// tried costs more.
	MaxSelectorsPerNamespace = 16000
)

// GroupRule is one rule of a virtual group: a set of selectors, each a fact
// name mapped to the values it may take. Every selector must find a value
// matching one of its values (AND across selectors, any-of within one); a
// value holding an unescaped '*' or '?' is a glob. Every rule of a virtual
// group includes a "mount" selector, the auth mounts it trusts.
type GroupRule map[string][]string

// Clone returns a deep copy of r, or nil for a nil rule.
func (r GroupRule) Clone() GroupRule {
	if r == nil {
		return nil
	}
	out := make(GroupRule, len(r))
	for k, v := range r {
		out[k] = slices.Clip(slices.Clone(v))
	}
	return out
}

// SelectorCount returns the number of selectors across g's rules, "mount"
// included: what MaxSelectorsPerNamespace counts.
func (g *Group) SelectorCount() int {
	n := 0
	for _, r := range g.Rules {
		n += len(r)
	}
	return n
}

// Group grants namespace roles to its members. Roles lists the roles membership
// grants, by bare name; a name with no role behind it grants nothing until the
// role exists. How a caller becomes a member depends on Type: a virtual group
// matches the caller's verified facts against its Rules and, when MaxAge is
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
	Rules       []GroupRule       `json:"rules,omitempty"`
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
	if g.Rules != nil {
		out.Rules = make([]GroupRule, len(g.Rules))
		for i, r := range g.Rules {
			out.Rules[i] = r.Clone()
		}
	}
	out.Metadata = maps.Clone(g.Metadata)
	return &out
}

// Hash identifies the group's content: two groups with the same name, type,
// roles, rules, max_age and metadata hash alike, whenever they were
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
	fmt.Fprintf(h, "%d:", len(g.Rules))
	for _, r := range g.Rules {
		names := slices.Sorted(maps.Keys(r))
		fmt.Fprintf(h, "%d:", len(names))
		for _, name := range names {
			field(name)
			list(r[name])
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
