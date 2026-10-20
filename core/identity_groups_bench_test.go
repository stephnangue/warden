package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// benchGroup returns a virtual group named name whose rules each list mount
// and require repo to be one the bench admission never carries, so every rule
// is evaluated in full and fails on its last name.
func benchGroup(tb testing.TB, name, mount string, rules int) *compiledGroup {
	tb.Helper()
	g := &logical.Group{Name: name, Type: logical.GroupTypeVirtual, Roles: []string{"deploy", "read"}}
	for i := range rules {
		g.Selectors = append(g.Selectors, logical.Selector{
			"mount": {mount},
			"ref":   {"refs/heads/main"},
			"repo":  {fmt.Sprintf("acme/%s-%d", name, i)},
		})
	}
	cg, err := compileGroup(g)
	if err != nil {
		tb.Fatal(err)
	}
	cg.Group, cg.hash = g, g.Hash()
	return cg
}

// benchGroups builds n groups. spread > 1 distributes them over that many
// mounts (auth/m0/ … ), with the bench admission's mount auth/m0/ getting 1/spread
// of them; spread == 1 puts every group on auth/m0/, the worst case for the
// index.
func benchGroups(tb testing.TB, n, rules, spread int) map[string]*compiledGroup {
	byName := make(map[string]*compiledGroup, n)
	for i := range n {
		name := fmt.Sprintf("g%05d", i)
		byName[name] = benchGroup(tb, name, fmt.Sprintf("auth/m%d/", i%spread), rules)
	}
	return byName
}

func benchAdmission(tb testing.TB) *logical.Admission {
	tb.Helper()
	mapping, err := selector.CompileMapping([]string{"sub", "iss", "aud"}, map[string]string{
		"repository": "repo",
		"ref":        "ref",
	})
	if err != nil {
		tb.Fatal(err)
	}
	naming, err := logical.NewMountNaming(mapping, "")
	if err != nil {
		tb.Fatal(err)
	}
	mf := &logical.MountFacts{}
	mf.Publish(naming)
	return &logical.Admission{
		MountPath: "auth/m0/",
		Facts: selector.NewClaims(map[string]any{
			"sub":        "agent-1",
			"repository": "acme/other",
			"ref":        "refs/heads/main",
		}),
		Mount:    mf,
		IssuedAt: time.Now(),
	}
}

// BenchmarkGroupCompute measures one membership computation for one admission
// against n groups: through the mount index with the groups spread over ten
// mounts, through the index when every group lists the admission's mount (the
// index's worst case), and a full scan of the spread groups. Every evaluated
// rule fails on its last name.
func BenchmarkGroupCompute(b *testing.B) {
	adm := benchAdmission(b)
	naming := adm.Mount.Load()
	now := time.Now()
	for _, rules := range []int{1, logical.MaxGroupSelectors} {
		// The sizes asked about, plus the most groups of that many rules the
		// caps allow.
		capped := min(logical.MaxGroupsPerNamespace, logical.MaxSelectorsPerNamespace/rules)
		for _, n := range []int{100, 1000, capped, 10000} {
			spread := buildNSGroups(benchGroups(b, n, rules, 10), 1)
			worst := buildNSGroups(benchGroups(b, n, rules, 1), 1)
			b.Run(fmt.Sprintf("rules=%d/groups=%d/index", rules, n), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					compute(adm, naming, spread, now)
				}
			})
			b.Run(fmt.Sprintf("rules=%d/groups=%d/index-worst", rules, n), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					compute(adm, naming, worst, now)
				}
			})
			b.Run(fmt.Sprintf("rules=%d/groups=%d/fullscan", rules, n), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					computeOver(adm, naming, spread, now, nil, true)
				}
			})
		}
	}
}

// BenchmarkGroupPublish measures what a write does under the store lock beyond
// storage: clone the namespace's name map and rebuild its index.
func BenchmarkGroupPublish(b *testing.B) {
	for _, n := range []int{100, 1000, logical.MaxGroupsPerNamespace, 10000} {
		byName := benchGroups(b, n, 1, 10)
		cg := benchGroup(b, "g00000", "auth/m0/", 1)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				next := make(map[string]*compiledGroup, len(byName)+1)
				for k, v := range byName {
					next[k] = v
				}
				next[cg.Name] = cg
				buildNSGroups(next, 2)
			}
		})
	}
}

// BenchmarkGroupWrite measures a whole group update through the store, in a
// namespace already holding n groups: validation (compile, role and mount
// checks), the storage write and the publish.
func BenchmarkGroupWrite(b *testing.B) {
	for _, n := range []int{100, 1000, logical.MaxGroupsPerNamespace, 10000} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			c := createTestCore(&testing.T{})
			ctx := rootCtx()
			s := c.identityStore
			// Seeded directly, so the namespace can be filled past the cap.
			byName := benchGroups(b, n-1, 1, 10)
			target := benchGroup(b, "target", "auth/m0/", 1)
			target.ID = "target-id"
			byName[target.Name] = target
			s.mu.Lock()
			s.maxGroups, s.maxSelectors = 2*n, 2*n
			if err := s.persistGroup(ctx, namespace.RootNamespaceUUID, target); err != nil {
				b.Fatal(err)
			}
			s.publishLocked(namespace.RootNamespaceID, byName)
			s.mu.Unlock()
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				i++
				if _, err := s.UpdateGroup(ctx, &logical.Group{
					Name: "target", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
					Selectors: []logical.Selector{{"mount": {"auth/m0/"}, "repo": {fmt.Sprintf("acme/x%d", i)}}},
				}, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMembershipSteadyState measures the cached path every request of an
// admitted credential takes once its membership is computed.
func BenchmarkMembershipSteadyState(b *testing.B) {
	adm := benchAdmission(b)
	gs := buildNSGroups(benchGroups(b, 1000, 1, 10), 1)
	now := time.Now()
	membership(adm, gs, now)
	b.ReportAllocs()
	for b.Loop() {
		membership(adm, gs, now)
	}
}
