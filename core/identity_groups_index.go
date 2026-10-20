package core

import (
	"fmt"
	"slices"
	"strings"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// groupSnapshot is one published state of every namespace's groups, keyed by
// namespace ID (the ID tokens carry). Immutable once published.
type groupSnapshot struct {
	byNS map[string]*nsGroups
}

// emptyGroupSnapshot is what an unloaded store serves.
var emptyGroupSnapshot = &groupSnapshot{}

// emptyNSGroups is what a snapshot answers for a namespace with no groups:
// generation 0 and nothing to match. The store's generation counter starts
// above 0, so a membership computed against it is told apart from one computed
// against real groups, and stays valid exactly while the namespace has none.
var emptyNSGroups = &nsGroups{byName: map[string]*compiledGroup{}}

// namespace returns the groups of namespace nsID, or emptyNSGroups when it has
// none. It takes no lock and does not allocate.
func (s *groupSnapshot) namespace(nsID string) *nsGroups {
	if g := s.byNS[nsID]; g != nil {
		return g
	}
	return emptyNSGroups
}

// withNamespace returns a snapshot in which namespace nsID holds g, or nothing
// when g is nil. s is left as it was; other namespaces are shared by pointer.
func (s *groupSnapshot) withNamespace(nsID string, g *nsGroups) *groupSnapshot {
	byNS := make(map[string]*nsGroups, len(s.byNS)+1)
	for k, v := range s.byNS {
		byNS[k] = v
	}
	if g != nil {
		byNS[nsID] = g
	} else {
		delete(byNS, nsID)
	}
	return &groupSnapshot{byNS: byNS}
}

// nsGroups is one namespace's groups, compiled and indexed. Immutable once
// published: a write builds a new one.
//
// The mount index serves compute. A virtual rule always names the mounts it
// trusts, so only the groups with a rule naming the admission's mount can
// match it. byMount holds every exact mount value; mountGlobs every mount
// pattern ("**" included). compute looks the admission's mount up in the map,
// tries each pattern, and evaluates only the groups found. The index only
// narrows: a group found is matched rule by rule in full, "mount" included, so
// a group whose one rule lists the mount and whose other rule does not is
// still decided by its rules.
type nsGroups struct {
	// gen is the store's publish counter at this publish. A membership computed
	// from another generation is recomputed.
	gen uint64

	byName map[string]*compiledGroup

	// names is the number of fact names across every rule of every group,
	// "mount" included: what a worst-case recompute evaluates.
	names int

	// selecting are the virtual groups, sorted by name.
	selecting []*compiledGroup

	// byMount maps an exact mount value to the indexes into selecting of the
	// groups that name it, ascending and without repeats.
	byMount map[string][]int32

	// mountGlobs are the groups' mount patterns, each with the index into
	// selecting of the group that names it, in ascending group order.
	mountGlobs []mountGlob
}

type mountGlob struct {
	glob  *selector.Glob
	group int32
}

// compiledGroup is a published group with what matching needs, built once
// when the group is written or loaded. Immutable.
type compiledGroup struct {
	*logical.Group
	hash string

	// rules are compiled from Group.Selectors, index-aligned.
	rules []*selector.Rule

	// names is the number of fact names across rules.
	names int

	// grants are the roles the group grants, each with its label built once.
	grants []groupGrant

	// exactMounts and mountGlobs are the group's mount values across its rules:
	// exact paths, deduplicated, and compiled patterns.
	exactMounts []string
	mountGlobs  []*selector.Glob
}

type groupGrant struct {
	role  string
	grant logical.GroupGrant
}

// compileGroup compiles g's selectors and grants. It reads g but keeps no
// reference to it: the caller sets Group and hash on the result before
// publishing it. An error names the selector at fault.
func compileGroup(g *logical.Group) (*compiledGroup, error) {
	cg := &compiledGroup{
		rules:  make([]*selector.Rule, len(g.Selectors)),
		grants: make([]groupGrant, len(g.Roles)),
	}
	label := logical.GroupLabel(g.Name)
	for i, role := range g.Roles {
		cg.grants[i] = groupGrant{role: role, grant: logical.GroupGrant{Group: g.Name, Label: label}}
	}
	for i, s := range g.Selectors {
		mounts, ok := s[selector.NameMount]
		if !ok {
			return nil, fmt.Errorf(`selectors[%d]: "mount" is required: list the auth mounts this rule trusts (e.g. "auth/kubernetes/")`, i)
		}
		r, err := selector.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("selectors[%d]: %w", i, err)
		}
		cg.rules[i] = r
		cg.names += len(r.Names())
		for _, v := range mounts {
			if selector.IsPattern(v) {
				gl, err := selector.CompileGlob(v)
				if err != nil {
					return nil, fmt.Errorf("selectors[%d]: mount %q: %w", i, v, err)
				}
				cg.mountGlobs = append(cg.mountGlobs, gl)
				continue
			}
			lit, err := selector.Unescape(v)
			if err != nil {
				return nil, fmt.Errorf("selectors[%d]: mount %q: %w", i, v, err)
			}
			if !slices.Contains(cg.exactMounts, lit) {
				cg.exactMounts = append(cg.exactMounts, lit)
			}
		}
	}
	return cg, nil
}

// buildNSGroups indexes byName into a namespace snapshot at generation gen,
// taking ownership of byName. It returns nil for an empty map, which the
// snapshot then serves as emptyNSGroups.
func buildNSGroups(byName map[string]*compiledGroup, gen uint64) *nsGroups {
	if len(byName) == 0 {
		return nil
	}
	g := &nsGroups{gen: gen, byName: byName, byMount: map[string][]int32{}}
	g.selecting = make([]*compiledGroup, 0, len(byName))
	for _, cg := range byName {
		g.names += cg.names
		if cg.Type == logical.GroupTypeVirtual {
			g.selecting = append(g.selecting, cg)
		}
	}
	slices.SortFunc(g.selecting, func(a, b *compiledGroup) int { return strings.Compare(a.Name, b.Name) })
	for i, cg := range g.selecting {
		idx := int32(i)
		for _, m := range cg.exactMounts {
			g.byMount[m] = append(g.byMount[m], idx)
		}
		for _, gl := range cg.mountGlobs {
			g.mountGlobs = append(g.mountGlobs, mountGlob{glob: gl, group: idx})
		}
	}
	return g
}

// candidates returns the indexes into selecting of the groups with a rule
// naming mountPath, exactly or by a pattern, ascending and without repeats.
// When no pattern matches it returns the index's own slice, which callers must
// not modify; otherwise a fresh one.
func (g *nsGroups) candidates(mountPath string) []int32 {
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
func (g *nsGroups) listing(role string) []string {
	var out []string
	for name, cg := range g.byName {
		if slices.Contains(cg.Roles, role) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
