package core

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// mountGlob is a virtual group's mount pattern in the mount index (nsIndex),
// with the index into virtualGroups of the group that names it.
type mountGlob struct {
	glob  *selector.Glob
	group int32
}

// groupEntry is a published group, the hash it was stored with, and what
// granting and matching need, built once when the group is written or loaded
// (compileGroup). Immutable.
type groupEntry struct {
	*logical.Group
	hash string

	// grants are the roles the group grants, each with its label built once.
	grants []groupGrant

	// rules are a virtual group's rules, compiled; nil for every other type,
	// whose membership is not decided by rules.
	rules *groupRules

	// validUntil is Group.ValidUntil as endNanos encodes it, for the static
	// membership computation.
	validUntil int64
}

// groupRules is what matching a virtual group needs, compiled from its rules.
type groupRules struct {
	// compiled are compiled from Group.Rules, index-aligned.
	compiled []*selector.Rule

	// selectors is the number of selectors across the rules.
	selectors int

	// exactMounts and mountGlobs are the group's mount values across its rules:
	// exact paths, deduplicated, and compiled patterns.
	exactMounts []string
	mountGlobs  []*selector.Glob
}

// selectors returns the number of selectors across e's rules: 0 for a group
// without rules.
func (e *groupEntry) selectors() int {
	if e.rules == nil {
		return 0
	}
	return e.rules.selectors
}

type groupGrant struct {
	role  string
	grant logical.GroupGrant
}

// compileGroup compiles g's grants and, for a virtual group, its rules. It
// reads g but keeps no reference to it: the caller sets Group and hash on the
// result before publishing it. An error names the rule at fault.
func compileGroup(g *logical.Group) (*groupEntry, error) {
	cg := &groupEntry{grants: make([]groupGrant, len(g.Roles)), validUntil: endNanos(g.ValidUntil)}
	label := logical.GroupLabel(g.Name)
	for i, role := range g.Roles {
		cg.grants[i] = groupGrant{role: role, grant: logical.GroupGrant{Group: g.Name, Label: label, Type: g.Type}}
	}
	if g.Type != logical.GroupTypeVirtual {
		return cg, nil
	}
	rules, err := compileRules(g.Rules)
	if err != nil {
		return nil, err
	}
	cg.rules = rules
	return cg, nil
}

// compileRules compiles a virtual group's rules, each of which must name the
// mounts it trusts. An error names the rule at fault.
func compileRules(in []logical.GroupRule) (*groupRules, error) {
	out := &groupRules{compiled: make([]*selector.Rule, len(in))}
	for i, rule := range in {
		mounts, ok := rule[selector.NameMount]
		if !ok {
			return nil, fmt.Errorf(`rules[%d]: every rule must include a "mount" selector listing the auth mounts it trusts (e.g. "auth/kubernetes/")`, i)
		}
		r, err := selector.Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		out.compiled[i] = r
		out.selectors += len(r.Names())
		for _, v := range mounts {
			if selector.IsPattern(v) {
				gl, err := selector.CompileGlob(v)
				if err != nil {
					return nil, fmt.Errorf("rules[%d]: mount %q: %w", i, v, err)
				}
				out.mountGlobs = append(out.mountGlobs, gl)
				continue
			}
			lit, err := selector.Unescape(v)
			if err != nil {
				return nil, fmt.Errorf("rules[%d]: mount %q: %w", i, v, err)
			}
			if !slices.Contains(out.exactMounts, lit) {
				out.exactMounts = append(out.exactMounts, lit)
			}
		}
	}
	return out, nil
}

// endNever is the instant, in unix nanoseconds, of a membership or group that
// never ends. Not 0: that is a real instant (the epoch), already past, and a
// membership ending then must read as expired.
const endNever = math.MaxInt64

// endNanos encodes the end t of a membership or a group for the member index:
// endNever for no end, an instant before what unix nanoseconds can hold as long
// expired, and one after it (writes refuse those, so only a record stored
// otherwise has one) as the last instant they can hold.
func endNanos(t time.Time) int64 {
	switch {
	case t.IsZero():
		return endNever
	case t.Before(minEnd):
		return math.MinInt64
	case t.After(maxEnd):
		return endNever - 1
	}
	return t.UnixNano()
}

// minEnd and maxEnd are the instants unix nanoseconds can hold.
var (
	minEnd = time.Unix(0, math.MinInt64).UTC()
	maxEnd = time.Unix(0, endNever-1).UTC()
)

// memberRef is one static group membership of an entity: the group, and when
// the membership ends, in unix nanoseconds (endNever for never). 16 bytes.
type memberRef struct {
	group *groupEntry
	until int64
}

// memberIndex maps an entity ID to the static groups that list it, sorted by
// group name, with the counts the caps check and usage reports. Immutable
// once published: every publish that changes a static group builds a new one
// (with), and an entity write or a virtual group write shares it by pointer.
// Neither the map nor any of its slices is ever written after it is built,
// which is what lets every nsIndex that shares one read it without a lock.
//
// An ID no entity holds any more (a member deleted since) keeps its entry
// until its groups are next written: no lookup ever reaches it, since entity
// IDs are never reused.
type memberIndex struct {
	byEntity map[string][]memberRef
	groups   int // static groups
	members  int // memberships across every static group, expired ones included
}

// emptyMemberIndex is the member index of a namespace without static groups.
var emptyMemberIndex = &memberIndex{}

// buildMemberIndex builds the member index of the static groups of byName,
// in full: what Load does.
func buildMemberIndex(byName map[string]*groupEntry) *memberIndex {
	var static []*groupEntry
	for _, cg := range byName {
		if cg.Type == logical.GroupTypeStatic {
			static = append(static, cg)
		}
	}
	if len(static) == 0 {
		return emptyMemberIndex
	}
	// Each entity's groups come out sorted by name, as a membership lists them.
	slices.SortFunc(static, func(a, b *groupEntry) int { return strings.Compare(a.Name, b.Name) })
	mi := &memberIndex{byEntity: map[string][]memberRef{}, groups: len(static)}
	for _, cg := range static {
		mi.members += len(cg.Members)
		for _, m := range cg.Members {
			mi.byEntity[m.ID] = append(mi.byEntity[m.ID], memberRef{group: cg, until: endNanos(m.Until)})
		}
	}
	return mi
}

// with returns the member index after a write that replaces group old with
// next: a create has no old, a delete no next. A write that touches no static
// group returns mi itself. Otherwise it copies the map (one entry per entity
// listed) and rebuilds only the entries of old's and next's members: every
// ref to old is removed, members kept included, since old carries the roles
// and valid_until the write replaces, and a ref to next is inserted at next's
// name position. mi is left as it was; untouched entries are shared.
func (mi *memberIndex) with(old, next *groupEntry) *memberIndex {
	isStatic := func(g *groupEntry) bool { return g != nil && g.Type == logical.GroupTypeStatic }
	if !isStatic(old) && !isStatic(next) {
		return mi
	}
	out := &memberIndex{byEntity: make(map[string][]memberRef, len(mi.byEntity)), groups: mi.groups, members: mi.members}
	for id, refs := range mi.byEntity {
		out.byEntity[id] = refs
	}
	if isStatic(old) {
		out.groups--
		out.members -= len(old.Members)
		for _, m := range old.Members {
			refs := slices.DeleteFunc(slices.Clone(out.byEntity[m.ID]), func(r memberRef) bool { return r.group == old })
			if len(refs) == 0 {
				delete(out.byEntity, m.ID)
			} else {
				out.byEntity[m.ID] = slices.Clip(refs)
			}
		}
	}
	if isStatic(next) {
		out.groups++
		out.members += len(next.Members)
		for _, m := range next.Members {
			cur := out.byEntity[m.ID]
			i, _ := slices.BinarySearchFunc(cur, next.Name, func(r memberRef, name string) int { return strings.Compare(r.group.Name, name) })
			refs := make([]memberRef, 0, len(cur)+1)
			refs = append(append(append(refs, cur[:i]...), memberRef{group: next, until: endNanos(m.Until)}), cur[i:]...)
			out.byEntity[m.ID] = refs
		}
	}
	if out.groups == 0 {
		return emptyMemberIndex
	}
	return out
}

// indexGroups builds the indexes of g's virtual groups: virtualGroups,
// selectors, byMount and mountGlobs. Called once, by buildNSIndex, before g
// is published.
func (g *nsIndex) indexGroups() {
	g.byMount = map[string][]int32{}
	g.virtualGroups = make([]*groupEntry, 0, len(g.groupsByName))
	for _, cg := range g.groupsByName {
		if cg.rules != nil {
			g.virtualGroups = append(g.virtualGroups, cg)
			g.selectors += cg.rules.selectors
		}
	}
	slices.SortFunc(g.virtualGroups, func(a, b *groupEntry) int { return strings.Compare(a.Name, b.Name) })
	for i, cg := range g.virtualGroups {
		idx := int32(i)
		for _, m := range cg.rules.exactMounts {
			g.byMount[m] = append(g.byMount[m], idx)
		}
		for _, gl := range cg.rules.mountGlobs {
			g.mountGlobs = append(g.mountGlobs, mountGlob{glob: gl, group: idx})
		}
	}
}

// candidates returns the indexes into virtualGroups of the groups with a rule
// naming mountPath, exactly or by a pattern, ascending and without repeats.
// When no pattern matches it returns the index's own slice, which callers must
// not modify; otherwise a fresh one.
func (g *nsIndex) candidates(mountPath string) []int32 {
	exact := g.byMount[mountPath]
	var out []int32
	for i := range g.mountGlobs {
		mg := &g.mountGlobs[i]
		if !mg.glob.Match(mountPath) {
			continue
		}
		if out == nil {
			out = make([]int32, 0, len(exact)+4)
			out = append(out, exact...)
		}
		out = append(out, mg.group)
	}
	if out == nil {
		return exact
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// listing returns the names of the groups that list role, sorted.
func (g *nsIndex) listing(role string) []string {
	var out []string
	for name, cg := range g.groupsByName {
		if slices.Contains(cg.Roles, role) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
