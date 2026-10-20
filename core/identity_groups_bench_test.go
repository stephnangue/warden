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
		// caps allow (each bench rule names three facts).
		capped := min(logical.MaxGroupsPerNamespace, logical.MaxSelectorNamesPerNamespace/(3*rules))
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

// wideNames is how many facts a wide rule names besides "mount": the most a
// rule may name, all sorting after "mount" so it is evaluated first.
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

// wideGroups builds n groups of one rule naming the most facts a rule may,
// all on the admission's mount. Each fact lists an exact value that fails and
// a glob that matches, so it is compared twice; the last fact matches only
// when match is set, so without it every rule fails on its last name.
func wideGroups(tb testing.TB, n int, match bool) *nsGroups {
	tb.Helper()
	byName := make(map[string]*compiledGroup, n)
	for i := range n {
		s := logical.Selector{"mount": {"auth/m0/"}}
		for j := range wideNames {
			s[wideFact(j)] = []string{"nomatch", "val-*"}
		}
		if !match {
			s[wideFact(wideNames-1)] = []string{"nomatch", "zzz-*"}
		}
		g := &logical.Group{Name: fmt.Sprintf("g%05d", i), Type: logical.GroupTypeVirtual,
			Roles: []string{fmt.Sprintf("role-%05d", i)}, Selectors: []logical.Selector{s}}
		cg, err := compileGroup(g)
		if err != nil {
			tb.Fatal(err)
		}
		cg.Group, cg.hash = g, g.Hash()
		byName[g.Name] = cg
	}
	return buildNSGroups(byName, 1)
}

// BenchmarkGroupComputeWide measures the worst case per fact name: every
// group lists the admission's mount, and its one rule names the most facts a
// rule may (32, "mount" included), every one matching but the last. total is
// the namespace's fact names, which MaxSelectorNamesPerNamespace bounds.
func BenchmarkGroupComputeWide(b *testing.B) {
	adm := wideAdmission(b)
	naming := adm.Mount.Load()
	now := time.Now()
	perRule := wideNames + 1
	capped := logical.MaxSelectorNamesPerNamespace / perRule
	for _, n := range []int{100, 250, capped, 1000} {
		gs := wideGroups(b, n, false)
		b.Run(fmt.Sprintf("groups=%d/names=%d", n, n*perRule), func(b *testing.B) {
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
// each): the most a recompute allocates. Rules name one to three facts; at
// MaxGroupsPerNamespace groups the fact-name cap allows two per rule.
func BenchmarkGroupComputeAllMatch(b *testing.B) {
	adm := benchAdmission(b)
	naming := adm.Mount.Load()
	now := time.Now()
	for _, tc := range []struct {
		n     int
		facts int
	}{
		{1000, 3}, {logical.MaxGroupsPerNamespace, 3},
		{1000, 1}, {logical.MaxGroupsPerNamespace, 1},
		// The most names 8000 groups may hold together.
		{logical.MaxGroupsPerNamespace, logical.MaxSelectorNamesPerNamespace / logical.MaxGroupsPerNamespace},
	} {
		n := tc.n
		byName := make(map[string]*compiledGroup, n)
		for i := range n {
			s := logical.Selector{"mount": {"auth/m0/"}}
			if tc.facts >= 2 {
				s["ref"] = []string{"refs/heads/main"}
			}
			if tc.facts >= 3 {
				s["repo"] = []string{"acme/*"}
			}
			g := &logical.Group{Name: fmt.Sprintf("g%05d", i), Type: logical.GroupTypeVirtual,
				Roles: []string{fmt.Sprintf("role-%05d", i)}, Selectors: []logical.Selector{s}}
			cg, err := compileGroup(g)
			if err != nil {
				b.Fatal(err)
			}
			cg.Group, cg.hash = g, g.Hash()
			byName[g.Name] = cg
		}
		gs := buildNSGroups(byName, 1)
		b.Run(fmt.Sprintf("facts=%d/groups=%d", tc.facts, n), func(b *testing.B) {
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
			c := createTestCore(b)
			ctx := rootCtx()
			s := c.identityStore
			// Seeded directly, so the namespace can be filled past the cap.
			byName := benchGroups(b, n-1, 1, 10)
			target := benchGroup(b, "target", "auth/m0/", 1)
			target.ID = "target-id"
			byName[target.Name] = target
			s.mu.Lock()
			s.maxGroups, s.maxNames = 2*n, 8*n
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
