package core

import (
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// matchCtx binds one admission to the naming in force for one compute. It is
// the selector.Source rules match against: every lookup of one compute sees
// the same naming. One is allocated per compute (compute allocates anyway);
// the steady state never builds one.
type matchCtx struct {
	adm *logical.Admission
	n   *logical.MountNaming
}

var _ selector.Source = (*matchCtx)(nil)

// Lookup implements selector.Source.
func (mc *matchCtx) Lookup(name string) selector.Cursor { return mc.adm.Lookup(mc.n, name) }

// noGroups is the Groups of a membership that matched no group: shared, never
// modified, and non-nil so readers can range over it or test it with
// slices.Contains without a nil check.
var noGroups = []string{}

// testHookRuleMatch, when set, runs before every rule match compute performs.
// Nil outside tests, which set it before starting any goroutine that computes
// and clear it after the last one returns.
var testHookRuleMatch func()

// membership returns adm's membership under the namespace groups gs at now.
// The cached one is returned while it was computed from gs's generation and
// the mount's naming in force, and none of its groups has aged out; otherwise
// a new one is computed and cached. The fast path takes one atomic load of the
// naming and one of the cache, does not allocate, and matches nothing.
//
// Safe for concurrent use: two requests that both find the cache stale compute
// equal memberships from the same inputs, and the compare-and-swap keeps one;
// each returns what it computed.
func membership(adm *logical.Admission, gs *nsGroups, now time.Time) *logical.Membership {
	n := adm.Mount.Load()
	m := adm.LoadMembership()
	if m != nil && m.Gen == gs.gen && m.Naming == n &&
		(m.ValidUntil.IsZero() || !now.After(m.ValidUntil)) {
		return m
	}
	next := compute(adm, n, gs, now)
	adm.CompareAndSwapMembership(m, next)
	return next
}

// compute builds adm's membership from scratch: the groups among gs's virtual
// groups whose rules name adm's mount (through the mount index) and match its
// facts under naming n, the roles they grant, and the mount's facts rendered
// as metadata under n. It never reads or writes the cache.
func compute(adm *logical.Admission, n *logical.MountNaming, gs *nsGroups, now time.Time) *logical.Membership {
	return computeOver(adm, n, gs, now, gs.candidates(adm.MountPath), false)
}

// computeOver evaluates the groups of gs.selecting at the indexes in cands, in
// order (ascending, so the groups come out sorted by name), or every group
// when all is set. The full scan exists to measure and test the index against.
func computeOver(adm *logical.Admission, n *logical.MountNaming, gs *nsGroups, now time.Time, cands []int32, all bool) *logical.Membership {
	m := &logical.Membership{
		Gen:      gs.gen,
		Naming:   n,
		Groups:   noGroups,
		Metadata: adm.RenderMetadata(n),
	}
	count := len(cands)
	if all {
		count = len(gs.selecting)
	}
	if count == 0 {
		return m
	}

	mc := &matchCtx{adm: adm, n: n}
	var groups []string
	for i := range count {
		idx := i
		if !all {
			idx = int(cands[i])
		}
		g := gs.selecting[idx]

		// A group with max_age admits only a credential that says when it was
		// issued, for max_age after that; the bound is inclusive.
		var until time.Time
		if g.MaxAge > 0 {
			if adm.IssuedAt.IsZero() {
				continue
			}
			until = adm.IssuedAt.Add(g.MaxAge)
			if now.After(until) {
				continue
			}
		}
		if !matchesAny(g, mc) {
			continue
		}

		groups = append(groups, g.Name)
		if !until.IsZero() && (m.ValidUntil.IsZero() || until.Before(m.ValidUntil)) {
			m.ValidUntil = until
		}
		for _, gr := range g.grants {
			if _, ok := m.Roles[gr.role]; ok {
				continue
			}
			if m.Roles == nil {
				m.Roles = make(map[string]logical.GroupGrant, len(g.grants))
			}
			m.Roles[gr.role] = gr.grant
		}
	}
	if groups != nil {
		m.Groups = groups
	}
	return m
}

// matchesAny reports whether any of g's rules matches mc.
func matchesAny(g *compiledGroup, mc *matchCtx) bool {
	for _, r := range g.rules {
		if h := testHookRuleMatch; h != nil {
			h()
		}
		if r.Match(mc) {
			return true
		}
	}
	return false
}
