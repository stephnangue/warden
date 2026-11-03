package core

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stephnangue/warden/logical"
)

// benchStaticGroup returns the static group name of m members, granting two
// roles, drawn round-robin from a pool of MaxEntitiesPerNamespace entity IDs
// starting at first.
func benchStaticGroup(tb testing.TB, name string, m, first int) *groupEntry {
	tb.Helper()
	g := &logical.Group{Name: name, Type: logical.GroupTypeStatic, Roles: []string{"deploy", "read"}}
	g.Members = make([]logical.GroupMember, m)
	for j := range m {
		g.Members[j] = logical.GroupMember{ID: fmt.Sprintf("e%06d", (first+j)%logical.MaxEntitiesPerNamespace)}
	}
	cg, err := compileGroup(g)
	if err != nil {
		tb.Fatal(err)
	}
	cg.Group, cg.hash = g, g.Hash()
	return cg
}

// benchStaticGroups builds n static groups of m members each. Members are
// drawn round-robin from the pool, so the namespace lists min(n*m, pool)
// entities, each by about n*m/pool groups.
func benchStaticGroups(tb testing.TB, n, m int) map[string]*groupEntry {
	tb.Helper()
	byName := make(map[string]*groupEntry, n)
	for i := range n {
		cg := benchStaticGroup(tb, fmt.Sprintf("s%05d", i), m, i*m)
		byName[cg.Name] = cg
	}
	return byName
}

// retained returns the heap the value build returns keeps alive, measured
// across two collections.
func retained(build func() any) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := build()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(v)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// staticShapes are namespaces at MaxStaticMembersPerNamespace, from a few full
// groups to the most groups, and one far past it, the size the caps allowed
// before the namespace-wide one.
var staticShapes = []struct{ groups, members int }{
	{100, 100},
	{logical.MaxStaticMembersPerNamespace / logical.MaxStaticGroupMembers, logical.MaxStaticGroupMembers},
	{1000, logical.MaxStaticMembersPerNamespace / 1000},
	{logical.MaxStaticGroupsPerNamespace, logical.MaxStaticMembersPerNamespace / logical.MaxStaticGroupsPerNamespace},
	{logical.MaxStaticGroupsPerNamespace, logical.MaxStaticGroupMembers},
}

// BenchmarkStaticMemberIndexBuild measures the full build of the member index,
// what Load does once per namespace, and reports what the index retains
// (index-MB) for the memberships it holds (refs).
func BenchmarkStaticMemberIndexBuild(b *testing.B) {
	for _, tc := range staticShapes {
		byName := benchStaticGroups(b, tc.groups, tc.members)
		b.Run(fmt.Sprintf("groups=%d/members=%d", tc.groups, tc.members), func(b *testing.B) {
			heap := retained(func() any { return buildMemberIndex(byName) })
			b.ReportAllocs()
			for b.Loop() {
				buildMemberIndex(byName)
			}
			b.ReportMetric(float64(heap)/(1<<20), "index-MB")
			b.ReportMetric(float64(tc.groups*tc.members), "refs")
		})
	}
}

// BenchmarkStaticGroupWrite measures what a group write does under the store
// lock beyond storage, in a namespace of each shape: clone the name map,
// update the member index for the one group written, and rebuild the virtual
// index. "static" rewrites one static group with a full new member list;
// "virtual" writes a virtual group, which shares the member index.
func BenchmarkStaticGroupWrite(b *testing.B) {
	for _, tc := range staticShapes {
		byName := benchStaticGroups(b, tc.groups, tc.members)
		gs := buildNSIndex(byName, nil, nil, nil, 1)
		old := byName["s00000"]
		next := benchStaticGroup(b, "s00000", tc.members, 7)
		virtual := benchGroup(b, "v00000", "auth/m0/", 1)
		publish := func(prev, cg *groupEntry) *nsIndex {
			names := make(map[string]*groupEntry, len(gs.groupsByName)+1)
			for k, v := range gs.groupsByName {
				names[k] = v
			}
			names[cg.Name] = cg
			return buildNSIndex(names, gs.members.with(prev, cg), nil, nil, 2)
		}
		b.Run(fmt.Sprintf("groups=%d/members=%d/static", tc.groups, tc.members), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				publish(old, next)
			}
		})
		b.Run(fmt.Sprintf("groups=%d/members=%d/virtual", tc.groups, tc.members), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if publish(nil, virtual).members != gs.members {
					b.Fatal("a virtual write rebuilt the member index")
				}
			}
		})
	}
}

// BenchmarkStaticMembership measures a claimed caller's membership
// computation when k static groups list its entity, each granting two roles,
// one shared by all: the per-claimed-caller part of a recompute after an
// identity publish.
func BenchmarkStaticMembership(b *testing.B) {
	now := time.Now()
	for _, k := range []int{1, 10, 100, 1000, logical.MaxStaticGroupsPerNamespace} {
		byName := make(map[string]*groupEntry, k)
		for i := range k {
			g := &logical.Group{Name: fmt.Sprintf("s%05d", i), Type: logical.GroupTypeStatic,
				Roles: []string{"deploy", fmt.Sprintf("role-%05d", i)}, Members: []logical.GroupMember{{ID: "e1"}}}
			cg, err := compileGroup(g)
			if err != nil {
				b.Fatal(err)
			}
			cg.Group, cg.hash = g, g.Hash()
			byName[g.Name] = cg
		}
		refs := buildMemberIndex(byName).byEntity["e1"]
		b.Run(fmt.Sprintf("groups=%d", k), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				m := &logical.Membership{Groups: noGroups}
				staticMembership(m, refs, now)
				if len(m.Groups) != k {
					b.Fatal("a membership is missing")
				}
			}
		})
	}
}
