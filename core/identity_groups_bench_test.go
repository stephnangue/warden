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
func benchGroup(tb testing.TB, name, mount string, rules int) *groupEntry {
	tb.Helper()
	g := &logical.Group{Name: name, Type: logical.GroupTypeVirtual, Roles: []string{"deploy", "read"}}
	for i := range rules {
		g.Rules = append(g.Rules, logical.GroupRule{
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
func benchGroups(tb testing.TB, n, rules, spread int) map[string]*groupEntry {
	byName := make(map[string]*groupEntry, n)
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
	for _, rules := range []int{1, logical.MaxGroupRules} {
		// The sizes asked about, plus the most groups of that many rules the
		// caps allow (each bench rule has three selectors).
		capped := min(logical.MaxVirtualGroupsPerNamespace, logical.MaxSelectorsPerNamespace/(3*rules))
		for _, n := range []int{100, 1000, capped, 10000} {
			spread := buildNSIndex(benchGroups(b, n, rules, 10), nil, 1)
			worst := buildNSIndex(benchGroups(b, n, rules, 1), nil, 1)
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

// wideNames is how many selectors a wide rule has besides "mount": the most a
// rule may have, all naming facts that sort after "mount" so it is evaluated
// first.
const wideNames = 31

// wideFact is the canonical name of the i-th wide fact.
func wideFact(i int) string { return fmt.Sprintf("x%02d", i) }

// wideAdmission carries every wide fact, mapped from a claim of its own.
func wideAdmission(tb testing.TB) *logical.Admission {
	tb.Helper()
	facts := make(map[string]string, wideNames)
	claims := make(map[string]any, wideNames)
	for i := range wideNames {
		facts[fmt.Sprintf("c%02d", i)] = wideFact(i)
		claims[fmt.Sprintf("c%02d", i)] = fmt.Sprintf("val-%02d", i)
	}
	mapping, err := selector.CompileMapping(nil, facts)
	if err != nil {
		tb.Fatal(err)
	}
	naming, err := logical.NewMountNaming(mapping, "")
	if err != nil {
		tb.Fatal(err)
	}
	mf := &logical.MountFacts{}
	mf.Publish(naming)
	return &logical.Admission{MountPath: "auth/m0/", Facts: selector.NewClaims(claims), Mount: mf}
}

// wideGroups builds n groups of one rule with the most selectors a rule may
// have, all on the admission's mount. Each selector lists an exact value that
// fails and a glob that matches, so it is compared twice; the last selector
// matches only when match is set, so without it every rule fails on its last
// selector.
func wideGroups(tb testing.TB, n int, match bool) *nsIndex {
	tb.Helper()
	byName := make(map[string]*groupEntry, n)
	for i := range n {
		s := logical.GroupRule{"mount": {"auth/m0/"}}
		for j := range wideNames {
			s[wideFact(j)] = []string{"nomatch", "val-*"}
		}
		if !match {
			s[wideFact(wideNames-1)] = []string{"nomatch", "zzz-*"}
		}
		g := &logical.Group{Name: fmt.Sprintf("g%05d", i), Type: logical.GroupTypeVirtual,
			Roles: []string{fmt.Sprintf("role-%05d", i)}, Rules: []logical.GroupRule{s}}
		cg, err := compileGroup(g)
		if err != nil {
			tb.Fatal(err)
		}
		cg.Group, cg.hash = g, g.Hash()
		byName[g.Name] = cg
	}
	return buildNSIndex(byName, nil, 1)
}

// BenchmarkGroupComputeWide measures the worst case per selector: every group
// lists the admission's mount, and its one rule has the most selectors a rule
// may (32, "mount" included), every one matching but the last. selectors is
// the namespace's total, which MaxSelectorsPerNamespace bounds.
func BenchmarkGroupComputeWide(b *testing.B) {
	adm := wideAdmission(b)
	naming := adm.Mount.Load()
	now := time.Now()
	perRule := wideNames + 1
	capped := logical.MaxSelectorsPerNamespace / perRule
	for _, n := range []int{100, 250, capped, 1000} {
		gs := wideGroups(b, n, false)
		b.Run(fmt.Sprintf("groups=%d/selectors=%d", n, n*perRule), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if m := compute(adm, naming, gs, now); len(m.Groups) != 0 {
					b.Fatal("a wide rule matched")
				}
			}
		})
	}
}

// BenchmarkGroupComputeAllMatch measures a recompute in which every group
// matches, so the membership lists every group and grants every role (one
// each): the most a recompute allocates. Rules have one to three selectors;
// at MaxVirtualGroupsPerNamespace groups the selector cap allows two per rule.
func BenchmarkGroupComputeAllMatch(b *testing.B) {
	adm := benchAdmission(b)
	naming := adm.Mount.Load()
	now := time.Now()
	for _, tc := range []struct {
		n         int
		selectors int
	}{
		{1000, 3}, {logical.MaxVirtualGroupsPerNamespace, 3},
		{1000, 1}, {logical.MaxVirtualGroupsPerNamespace, 1},
		// The most selectors 8000 groups may hold together.
		{logical.MaxVirtualGroupsPerNamespace, logical.MaxSelectorsPerNamespace / logical.MaxVirtualGroupsPerNamespace},
	} {
		n := tc.n
		byName := make(map[string]*groupEntry, n)
		for i := range n {
			s := logical.GroupRule{"mount": {"auth/m0/"}}
			if tc.selectors >= 2 {
				s["ref"] = []string{"refs/heads/main"}
			}
			if tc.selectors >= 3 {
				s["repo"] = []string{"acme/*"}
			}
			g := &logical.Group{Name: fmt.Sprintf("g%05d", i), Type: logical.GroupTypeVirtual,
				Roles: []string{fmt.Sprintf("role-%05d", i)}, Rules: []logical.GroupRule{s}}
			cg, err := compileGroup(g)
			if err != nil {
				b.Fatal(err)
			}
			cg.Group, cg.hash = g, g.Hash()
			byName[g.Name] = cg
		}
		gs := buildNSIndex(byName, nil, 1)
		b.Run(fmt.Sprintf("selectors=%d/groups=%d", tc.selectors, n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if m := compute(adm, naming, gs, now); len(m.Groups) != n || len(m.Roles) != n {
					b.Fatal("not every group matched")
				}
			}
		})
	}
}

// BenchmarkGroupPublish measures what a write does under the store lock beyond
// storage: clone the namespace's name map and rebuild its index.
func BenchmarkGroupPublish(b *testing.B) {
	for _, n := range []int{100, 1000, logical.MaxVirtualGroupsPerNamespace, 10000} {
		byName := benchGroups(b, n, 1, 10)
		cg := benchGroup(b, "g00000", "auth/m0/", 1)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				next := make(map[string]*groupEntry, len(byName)+1)
				for k, v := range byName {
					next[k] = v
				}
				next[cg.Name] = cg
				buildNSIndex(next, nil, 2)
			}
		})
	}
}

// BenchmarkGroupWrite measures a whole group update through the store, in a
// namespace already holding n groups: validation (compile, role and mount
// checks), the storage write and the publish.
func BenchmarkGroupWrite(b *testing.B) {
	for _, n := range []int{100, 1000, logical.MaxVirtualGroupsPerNamespace, 10000} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			c := createTestCore(b)
			ctx := rootCtx()
			s := c.identityStore
			// Seeded directly, so the namespace can be filled past the cap.
			byName := benchGroups(b, n-1, 1, 10)
			target := benchGroup(b, "target", "auth/m0/", 1)
			target.ID = "target-id"
			byName[target.Name] = target
			s.mu.Lock()
			s.maxVirtualGroups.Store(int64(2 * n))
			s.maxSelectors.Store(int64(8 * n))
			if err := s.persistGroup(ctx, namespace.RootNamespaceUUID, target); err != nil {
				b.Fatal(err)
			}
			s.publishGroupsLocked(namespace.RootNamespaceID, byName)
			s.mu.Unlock()
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				i++
				if _, err := s.UpdateGroup(ctx, &logical.Group{
					Name: "target", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
					Rules: []logical.GroupRule{{"mount": {"auth/m0/"}, "repo": {fmt.Sprintf("acme/x%d", i)}}},
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
	gs := buildNSIndex(benchGroups(b, 1000, 1, 10), nil, 1)
	now := time.Now()
	membership(adm, gs, now)
	b.ReportAllocs()
	for b.Loop() {
		membership(adm, gs, now)
	}
}
