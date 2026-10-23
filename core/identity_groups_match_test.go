package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNS compiles groups into a namespace snapshot at generation gen.
func testNS(t testing.TB, gen uint64, groups ...*logical.Group) *nsGroups {
	t.Helper()
	byName := make(map[string]*compiledGroup, len(groups))
	for _, g := range groups {
		if g.Type == "" {
			g.Type = logical.GroupTypeVirtual
		}
		cg, err := compileGroup(g)
		require.NoError(t, err)
		cg.Group, cg.hash = g, g.Hash()
		byName[g.Name] = cg
	}
	gs := buildNSGroups(byName, gen)
	if gs == nil {
		return emptyNSGroups
	}
	return gs
}

func rule(kv ...any) logical.GroupRule {
	s := logical.GroupRule{}
	for i := 0; i < len(kv); i += 2 {
		s[kv[i].(string)] = kv[i+1].([]string)
	}
	return s
}

// noEnd is a group's valid_until when it has none.
var noEnd time.Time

func group(name string, roles []string, validUntil time.Time, rules ...logical.GroupRule) *logical.Group {
	return &logical.Group{Name: name, Roles: roles, ValidUntil: validUntil, Rules: rules}
}

// groupAdmission admits claims through a jwt-like mount at mountPath that maps
// "repository" to "repo" and identity-maps "sub", with entity kind kind.
func groupAdmission(t testing.TB, mountPath, kind string, claims map[string]any, issuedAt time.Time) *logical.Admission {
	t.Helper()
	mf := &logical.MountFacts{}
	mf.Publish(testNaming(t, kind, map[string]string{"repository": "repo", "sub": "sub"}))
	return &logical.Admission{
		MountPath: mountPath,
		Facts:     selector.NewClaims(claims),
		Mount:     mf,
		IssuedAt:  issuedAt,
	}
}

func testNaming(t testing.TB, kind string, facts map[string]string) *logical.MountNaming {
	t.Helper()
	m, err := selector.CompileMapping([]string{"sub", "iss", "aud"}, facts)
	require.NoError(t, err)
	n, err := logical.NewMountNaming(m, kind)
	require.NoError(t, err)
	return n
}

// countMatches counts the rule matches compute performs while the test runs.
func countMatches(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	testHookRuleMatch = func() { n.Add(1) }
	t.Cleanup(func() { testHookRuleMatch = nil })
	return &n
}

func TestCompute_Rules(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	iat := now.Add(-10 * time.Minute)
	claims := map[string]any{"sub": "agent-1", "repository": "acme/infra", "unmapped": "x"}
	jwt := "auth/jwt/"

	cases := []struct {
		name   string
		mount  string
		kind   string
		iat    time.Time
		groups []*logical.Group
		want   []string
	}{
		{"exact match", jwt, "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "repo", []string{"acme/infra"})),
		}, []string{"g"}},
		{"glob value", jwt, "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "repo", []string{"acme/*"})),
		}, []string{"g"}},
		{"AND across names fails on one", jwt, "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "repo", []string{"acme/infra"}, "sub", []string{"other"})),
		}, nil},
		{"any-of within a name", jwt, "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "sub", []string{"other", "agent-1"})),
		}, []string{"g"}},
		{"OR across rules", jwt, "", iat, []*logical.Group{
			group("g", nil, noEnd,
				rule("mount", []string{jwt}, "sub", []string{"nope"}),
				rule("mount", []string{jwt}, "repo", []string{"acme/infra"})),
		}, []string{"g"}},
		{"mount pin excludes another mount", "auth/other/", "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "sub", []string{"agent-1"})),
		}, nil},
		{"mount pin lists several", "auth/other/", "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt, "auth/other/"}, "sub", []string{"agent-1"})),
		}, []string{"g"}},
		{"unmapped claim is invisible", jwt, "", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "unmapped", []string{"x"})),
		}, nil},
		{"kind agent", jwt, "agent", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "kind", []string{"agent"})),
		}, []string{"g"}},
		{"kind human excluded", jwt, "human", iat, []*logical.Group{
			group("g", nil, noEnd, rule("mount", []string{jwt}, "kind", []string{"agent"})),
		}, nil},
		{"valid_until exactly now grants", jwt, "", iat, []*logical.Group{
			group("g", nil, now, rule("mount", []string{jwt}, "sub", []string{"agent-1"})),
		}, []string{"g"}},
		{"valid_until 1ns past refuses", jwt, "", iat, []*logical.Group{
			group("g", nil, now.Add(-time.Nanosecond), rule("mount", []string{jwt}, "sub", []string{"agent-1"})),
		}, nil},
		{"valid_until ahead grants", jwt, "", iat, []*logical.Group{
			group("g", nil, now.Add(time.Hour), rule("mount", []string{jwt}, "sub", []string{"agent-1"})),
		}, []string{"g"}},
		{"no issue time is no concern of groups", jwt, "", time.Time{}, []*logical.Group{
			group("g", nil, now.Add(time.Hour), rule("mount", []string{jwt}, "sub", []string{"agent-1"})),
		}, []string{"g"}},
		{"groups come out sorted", jwt, "", iat, []*logical.Group{
			group("zeta", nil, noEnd, rule("mount", []string{jwt}, "sub", []string{"agent-1"})),
			group("alpha", nil, noEnd, rule("mount", []string{"**"}, "sub", []string{"agent-1"})),
			group("mid", nil, noEnd, rule("mount", []string{"auth/*/"}, "sub", []string{"agent-1"})),
		}, []string{"alpha", "mid", "zeta"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adm := groupAdmission(t, tc.mount, tc.kind, claims, tc.iat)
			gs := testNS(t, 7, tc.groups...)
			m := compute(adm, adm.Mount.Load(), gs, now)
			if tc.want == nil {
				assert.Empty(t, m.Groups)
				assert.NotNil(t, m.Groups, "Groups is never nil")
			} else {
				assert.Equal(t, tc.want, m.Groups)
			}
			assert.Equal(t, uint64(7), m.Gen)
			assert.Same(t, adm.Mount.Load(), m.Naming)

			full := computeOver(adm, adm.Mount.Load(), gs, now, nil, true)
			assert.Equal(t, m.Groups, full.Groups, "the index agrees with a full scan")
		})
	}
}

func TestCompute_GrantsAndValidUntil(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})
	match := rule("mount", []string{"auth/jwt/"}, "sub", []string{"a"})
	gs := testNS(t, 1,
		group("b-ten", []string{"deploy", "read"}, now.Add(10*time.Minute), match),
		group("a-five", []string{"read"}, now.Add(5*time.Minute), match),
		group("c-none", []string{"write"}, noEnd, match),
		group("d-miss", []string{"admin"}, now.Add(time.Minute), rule("mount", []string{"auth/jwt/"}, "sub", []string{"z"})),
		group("e-past", []string{"old"}, now.Add(-time.Minute), match),
	)
	m := compute(adm, adm.Mount.Load(), gs, now)

	assert.Equal(t, []string{"a-five", "b-ten", "c-none"}, m.Groups, "a group past its valid_until is not matched")
	assert.Equal(t, now.Add(5*time.Minute), m.ValidUntil,
		"the earliest valid_until among matched groups; an unmatched group's does not count")
	assert.NotContains(t, m.Roles, "old")
	require.Len(t, m.Roles, 3)
	assert.Equal(t, logical.GroupGrant{Group: "a-five", Label: "group:a-five"}, m.Roles["read"],
		"a role two groups grant is credited to the first by name")
	assert.Equal(t, "group:b-ten", m.Roles["deploy"].Label)
	assert.Equal(t, "group:c-none", m.Roles["write"].Label)
	assert.NotContains(t, m.Roles, "admin")

	// The labels are the compiled group's own strings, built once.
	cg := gs.byName["b-ten"]
	assert.Equal(t, unsafe.StringData(cg.grants[0].grant.Label), unsafe.StringData(m.Roles["deploy"].Label))

	// No valid_until among the matched groups: no bound.
	m = compute(adm, adm.Mount.Load(), testNS(t, 1, group("c", nil, noEnd, match)), now)
	assert.True(t, m.ValidUntil.IsZero())
	assert.Nil(t, m.Roles)
}

func TestCompute_MetadataFromNamingInForce(t *testing.T) {
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "agent-1", "repository": "acme/infra", "env": "prod"}, time.Time{})
	n1 := adm.Mount.Load()
	m := compute(adm, n1, emptyNSGroups, time.Now())
	assert.Equal(t, map[string]string{"repo": "acme/infra", "sub": "agent-1"}, m.Metadata)

	n2 := testNaming(t, "", map[string]string{"env": "environment"})
	m = compute(adm, n2, emptyNSGroups, time.Now())
	assert.Equal(t, map[string]string{"environment": "prod"}, m.Metadata, "rendered under the naming passed in")
	assert.Same(t, n2, m.Naming)
}

// TestCompute_AllocationsDoNotGrowWithRules: compute allocates a fixed amount
// (one matchCtx, the membership) however many rules it evaluates.
func TestCompute_AllocationsDoNotGrowWithRules(t *testing.T) {
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})
	n := adm.Mount.Load()
	miss := func(count int) *nsGroups {
		groups := make([]*logical.Group, count)
		for i := range groups {
			groups[i] = group(fmt.Sprintf("g%03d", i), nil, noEnd, rule("mount", []string{"auth/jwt/"}, "sub", []string{"nope"}))
		}
		return testNS(t, 1, groups...)
	}
	small, large := miss(5), miss(200)
	now := time.Now()
	a := testing.AllocsPerRun(100, func() { compute(adm, n, small, now) })
	b := testing.AllocsPerRun(100, func() { compute(adm, n, large, now) })
	assert.Equal(t, a, b)
}

func TestMountIndex(t *testing.T) {
	now := time.Now()
	gs := testNS(t, 1,
		group("exact", nil, noEnd, rule("mount", []string{"auth/k8s/"}, "sub", []string{"a"})),
		group("glob", nil, noEnd, rule("mount", []string{"auth/k8s-*/"}, "sub", []string{"a"})),
		group("any", nil, noEnd, rule("mount", []string{"**"}, "sub", []string{"a"})),
		group("two-rules", nil, noEnd,
			rule("mount", []string{"auth/jwt/"}, "sub", []string{"a"}),
			rule("mount", []string{"auth/k8s/", "auth/k8s/"}, "sub", []string{"a"})),
		group("escaped", nil, noEnd, rule("mount", []string{`auth/we\*ird/`}, "sub", []string{"a"})),
	)
	names := func(mount string) []string {
		var out []string
		for _, i := range gs.candidates(mount) {
			out = append(out, gs.selecting[i].Name)
		}
		return out
	}
	assert.Equal(t, []string{"any", "exact", "two-rules"}, names("auth/k8s/"), "sorted, without repeats")
	assert.Equal(t, []string{"any", "glob"}, names("auth/k8s-prod/"))
	assert.Equal(t, []string{"any", "two-rules"}, names("auth/jwt/"))
	assert.Equal(t, []string{"any", "escaped"}, names("auth/we*ird/"), "an escaped value is exact")
	assert.Equal(t, []string{"any"}, names("auth/added-later/"),
		`a mount enabled after the group is reached by "**" alone`)

	// A mount enabled after the group was written matches the groups that name
	// it: the index is keyed by the values the group lists, not by mounts.
	adm := groupAdmission(t, "auth/k8s-new/", "", map[string]any{"sub": "a"}, time.Time{})
	m := compute(adm, adm.Mount.Load(), gs, now)
	assert.Equal(t, []string{"any", "glob"}, m.Groups)

	// The index only narrows: a found group is decided by its rules in full.
	adm = groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})
	m = compute(adm, adm.Mount.Load(), gs, now)
	assert.Equal(t, []string{"any", "two-rules"}, m.Groups)

	// The index's own slice is returned when no pattern adds to it.
	plain := testNS(t, 1, group("e", nil, noEnd, rule("mount", []string{"auth/k8s/"}, "sub", []string{"a"})))
	assert.Equal(t, unsafe.SliceData(plain.byMount["auth/k8s/"]), unsafe.SliceData(plain.candidates("auth/k8s/")))
	assert.Empty(t, plain.candidates("auth/none/"))
}

// TestMountIndex_AgreesWithFullScan checks the index against a full scan over
// a namespace mixing exact, glob and "**" mounts, for several admissions.
func TestMountIndex_AgreesWithFullScan(t *testing.T) {
	mounts := []string{"auth/a/", "auth/b/", "auth/c-1/", "auth/c-2/", "auth/d/x/"}
	patterns := [][]string{{"auth/a/"}, {"auth/b/", "auth/a/"}, {"auth/c-*/"}, {"auth/*/"}, {"**"}, {"auth/d/**"}, {"auth/?/"}}
	var groups []*logical.Group
	for i := range 60 {
		groups = append(groups, group(fmt.Sprintf("g%02d", i), []string{"r"}, noEnd,
			rule("mount", patterns[i%len(patterns)], "sub", []string{fmt.Sprint(i % 3)})))
	}
	gs := testNS(t, 1, groups...)
	now := time.Now()
	for _, mount := range append(mounts, "auth/zzz/") {
		for _, sub := range []string{"0", "1", "2"} {
			adm := groupAdmission(t, mount, "", map[string]any{"sub": sub}, time.Time{})
			n := adm.Mount.Load()
			assert.Equal(t, computeOver(adm, n, gs, now, nil, true).Groups, compute(adm, n, gs, now).Groups, "%s %s", mount, sub)
		}
	}
}

func TestMembership_SteadyState(t *testing.T) {
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a", "repository": "acme/x"}, time.Now())
	now := time.Now()
	// A valid_until ahead, so the fast path compares it too.
	gs := testNS(t, 3, group("g", []string{"deploy"}, now.Add(time.Hour), rule("mount", []string{"auth/jwt/"}, "sub", []string{"a"})))

	first := membership(adm, gs, now)
	assert.Equal(t, []string{"g"}, first.Groups)
	require.False(t, first.ValidUntil.IsZero())
	assert.Same(t, first, adm.LoadMembership(), "the result is cached on the admission")

	matches := countMatches(t)
	allocs := testing.AllocsPerRun(1000, func() {
		if membership(adm, gs, now) != first {
			t.Fatal("the steady state recomputed")
		}
	})
	assert.Zero(t, allocs, "the steady state does not allocate")
	assert.Zero(t, matches.Load(), "the steady state never matches a rule")
}

func TestMembership_Recompute(t *testing.T) {
	now := time.Now()
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a", "repository": "acme/x"}, time.Time{})
	match := rule("mount", []string{"auth/jwt/"}, "sub", []string{"a"})
	gs := testNS(t, 3, group("g", []string{"deploy"}, noEnd, match))
	m1 := membership(adm, gs, now)
	matches := countMatches(t)

	// A new generation recomputes.
	gs2 := testNS(t, 4, group("g", []string{"deploy", "read"}, noEnd, match))
	m2 := membership(adm, gs2, now)
	assert.NotSame(t, m1, m2)
	assert.Contains(t, m2.Roles, "read")
	assert.Equal(t, int64(1), matches.Load())

	// A new naming recomputes, metadata included.
	adm.Mount.Publish(testNaming(t, "", map[string]string{"repository": "project"}))
	m3 := membership(adm, gs2, now)
	assert.NotSame(t, m2, m3)
	assert.Equal(t, map[string]string{"project": "acme/x"}, m3.Metadata)
	assert.Same(t, m3, membership(adm, gs2, now))

	// A cached membership holds through the earliest valid_until of its
	// groups, inclusive; the first request past it recomputes, and the group
	// that ended drops while the others stay.
	end := now.Add(2 * time.Minute)
	gs3 := testNS(t, 5,
		group("g", []string{"deploy"}, end, match),
		group("h", []string{"read"}, now.Add(time.Hour), match))
	m4 := membership(adm, gs3, now)
	require.Equal(t, end, m4.ValidUntil, "the earliest of several")
	before := matches.Load()
	assert.Same(t, m4, membership(adm, gs3, end), "still valid at valid_until")
	assert.Equal(t, before, matches.Load(), "without matching")
	m5 := membership(adm, gs3, end.Add(time.Nanosecond))
	assert.NotSame(t, m4, m5, "the first request past it recomputes")
	assert.Equal(t, []string{"h"}, m5.Groups, "the ended group dropped")
	assert.NotContains(t, m5.Roles, "deploy")
	assert.Equal(t, now.Add(time.Hour), m5.ValidUntil, "the next end now bounds it")
	assert.Same(t, m5, membership(adm, gs3, end.Add(time.Minute)), "and it is cached again")
}

// TestMembership_ConcurrentRecompute: many requests finding no membership
// compute at once; the race is benign. Run with -race.
func TestMembership_ConcurrentRecompute(t *testing.T) {
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})
	gs := testNS(t, 9, group("g", []string{"deploy"}, noEnd, rule("mount", []string{"auth/jwt/"}, "sub", []string{"a"})))
	now := time.Now()

	const n = 32
	results := make([]*logical.Membership, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = membership(adm, gs, now)
		}()
	}
	close(start)
	wg.Wait()

	cached := adm.LoadMembership()
	require.NotNil(t, cached)
	for _, r := range results {
		assert.Equal(t, cached.Groups, r.Groups)
		assert.Equal(t, cached.Roles, r.Roles)
		assert.Equal(t, cached.Gen, r.Gen)
	}
	assert.Same(t, cached, membership(adm, gs, now), "one membership stays cached")
}

// TestMembership_ThroughStore: publishes in one namespace leave another's
// memberships valid; a namespace without groups uses the empty sentinel; a
// namespace cleared recomputes. Readers run during publishes under -race.
func TestMembership_ThroughStore(t *testing.T) {
	c := createTestCore(t)
	s := c.identityStore
	ctxX := rootCtx()
	nsY := &namespace.Namespace{ID: "ns-y", UUID: "ns-y-uuid", Path: "y/"}
	ctxY := namespace.ContextWithNamespace(context.Background(), nsY)
	now := time.Now()

	admX := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})
	admY := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})

	// No groups yet: the sentinel, generation 0.
	gsY := s.namespaceGroups(nsY.ID)
	assert.Same(t, emptyNSGroups, gsY)
	mY := membership(admY, gsY, now)
	assert.Zero(t, mY.Gen)
	assert.Empty(t, mY.Groups)

	_, err := s.CreateGroup(ctxY, virtualGroup("yg", "deploy"))
	require.NoError(t, err)
	_, err = s.CreateGroup(ctxX, &logical.Group{Name: "xg", Type: logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/jwt/"}, "sub": {"a"}}}})
	require.NoError(t, err)
	mY = membership(admY, s.namespaceGroups(nsY.ID), now)
	assert.NotZero(t, mY.Gen)

	// Readers keep computing while X publishes.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m := membership(admX, s.namespaceGroups(namespace.RootNamespaceID), time.Now())
				if len(m.Groups) > 1 {
					t.Errorf("unexpected groups %v", m.Groups)
					return
				}
			}
		}()
	}
	for i := range 50 {
		_, err := s.UpdateGroup(ctxX, &logical.Group{Name: "xg", Type: logical.GroupTypeVirtual,
			Description: fmt.Sprint(i),
			Rules:       []logical.GroupRule{{"mount": {"auth/jwt/"}, "sub": {"a"}}}}, "")
		require.NoError(t, err)
	}
	close(stop)
	wg.Wait()

	assert.Same(t, mY, membership(admY, s.namespaceGroups(nsY.ID), now),
		"publishes in another namespace leave this one's membership valid")
	mX := membership(admX, s.namespaceGroups(namespace.RootNamespaceID), now)
	assert.Equal(t, []string{"xg"}, mX.Groups)

	// A group change in Y recomputes Y.
	require.NoError(t, s.DeleteGroup(ctxY, "yg", ""))
	assert.Same(t, emptyNSGroups, s.namespaceGroups(nsY.ID), "a namespace whose last group is deleted is empty")
	mY2 := membership(admY, s.namespaceGroups(nsY.ID), now)
	assert.NotSame(t, mY, mY2)
	assert.Zero(t, mY2.Gen)

	// Clearing X recomputes X to nothing.
	require.NoError(t, s.ClearNamespace(ctxX))
	mX2 := membership(admX, s.namespaceGroups(namespace.RootNamespaceID), now)
	assert.NotSame(t, mX, mX2)
	assert.Empty(t, mX2.Groups)
}

// TestMembership_GenerationNeverRepeats: an Unload and Load publish new
// generations, so a membership from before never reads as current.
func TestMembership_GenerationNeverRepeats(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	_, err := c.identityStore.CreateGroup(ctx, virtualGroup("g", "deploy"))
	require.NoError(t, err)
	before := c.identityStore.namespaceGroups(namespace.RootNamespaceID).gen

	c.teardownIdentityStore()
	require.NoError(t, c.setupIdentityStore(ctx, false))
	after := c.identityStore.namespaceGroups(namespace.RootNamespaceID).gen
	assert.Greater(t, after, before)
}
