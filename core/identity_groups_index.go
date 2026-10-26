package core

import (
	"fmt"
	"slices"
	"strings"

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
	cg := &groupEntry{grants: make([]groupGrant, len(g.Roles))}
	label := logical.GroupLabel(g.Name)
	for i, role := range g.Roles {
		cg.grants[i] = groupGrant{role: role, grant: logical.GroupGrant{Group: g.Name, Label: label}}
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

// indexGroups builds the mount index of g's groups: virtualGroups, selectors,
// byMount and mountGlobs. Called once, by buildNSIndex, before g is published.
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
