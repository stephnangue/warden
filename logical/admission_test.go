package logical

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMapping(t testing.TB, builtins []string, facts map[string]string) *selector.Mapping {
	t.Helper()
	m, err := selector.CompileMapping(builtins, facts)
	require.NoError(t, err)
	return m
}

func testNaming(t testing.TB, m *selector.Mapping, kind string) *MountNaming {
	t.Helper()
	n, err := NewMountNaming(m, kind)
	require.NoError(t, err)
	return n
}

func testClaims(t testing.TB, js string) *selector.Claims {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(js), &m))
	return selector.NewClaims(m)
}

// values drains a cursor into the strings FormatScalar renders.
func values(c selector.Cursor) []string {
	var out []string
	for v, ok := c.Next(); ok; v, ok = c.Next() {
		out = append(out, string(selector.FormatScalar(nil, v)))
	}
	return out
}

// jwtAdmission is an admission of a jwt-like mount that maps two claims, one
// through a JSON pointer, and identity-maps the built-in "sub".
func jwtAdmission(t testing.TB) (*Admission, *MountNaming) {
	t.Helper()
	naming := testNaming(t, testMapping(t, []string{"sub", "iss", "aud"}, map[string]string{
		"repository":      "repo",
		"/deployment/env": "env",
		"sub":             "sub",
		"absent":          "gone",
	}), "")
	mf := &MountFacts{}
	mf.Publish(naming)
	adm := &Admission{
		MountPath: "auth/jwt/",
		Facts: testClaims(t, `{
			"sub": "agent-1",
			"iss": "https://issuer.example",
			"aud": ["warden", "other"],
			"repository": "acme/api",
			"email": "a@example.com",
			"deployment": {"env": "prod"}
		}`),
		Mount: mf,
	}
	return adm, naming
}

func TestAdmissionLookup(t *testing.T) {
	adm, naming := jwtAdmission(t)
	require.Same(t, naming, adm.Mount.Load())

	cases := []struct {
		name string
		want []string
	}{
		{"mount", []string{"auth/jwt/"}},
		{"kind", []string{"agent"}},
		{"repo", []string{"acme/api"}},              // mapped
		{"env", []string{"prod"}},                   // mapped through a pointer
		{"sub", []string{"agent-1"}},                // built-in, identity-mapped
		{"iss", []string{"https://issuer.example"}}, // built-in
		{"aud", []string{"warden", "other"}},        // built-in, multi-valued
		{"repository", nil},                         // the raw name of a mapped fact is invisible
		{"email", nil},                              // carried but unmapped: invisible
		{"gone", nil},                               // mapped but absent
		{"nope", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, values(adm.Lookup(naming, tc.name)))
		})
	}
}

func TestAdmissionLookup_KindFromNaming(t *testing.T) {
	adm, _ := jwtAdmission(t)
	human := testNaming(t, testMapping(t, []string{"sub"}, nil), EntityKindHuman)
	assert.Equal(t, []string{"human"}, values(adm.Lookup(human, "kind")))
	// The naming passed in decides what is visible, not the one the mount holds.
	assert.Nil(t, values(adm.Lookup(human, "repo")))
	assert.Equal(t, []string{"agent-1"}, values(adm.Lookup(human, "sub")))
}

func TestAdmissionLookup_Table(t *testing.T) {
	adm := &Admission{
		MountPath: "auth/kubernetes/",
		Facts: selector.NewTable(
			selector.Field{Name: "service_account_name", Values: []string{"deployer"}},
			selector.Field{Name: "groups", Values: []string{"system:serviceaccounts", "ci"}},
		),
	}
	naming := testNaming(t, testMapping(t, []string{"service_account_name", "groups"},
		map[string]string{"service_account_name": "workload"}), EntityKindAgent)
	assert.Equal(t, []string{"deployer"}, values(adm.Lookup(naming, "workload")))
	assert.Equal(t, []string{"system:serviceaccounts", "ci"}, values(adm.Lookup(naming, "groups")))
	assert.Equal(t, []string{"auth/kubernetes/"}, values(adm.Lookup(naming, "mount")))
}

func TestAdmissionLookup_Empty(t *testing.T) {
	adm, naming := jwtAdmission(t)
	var nilAdm *Admission
	assert.Nil(t, values(nilAdm.Lookup(naming, "mount")), "nil admission")
	assert.Nil(t, values(adm.Lookup(nil, "mount")), "nil naming")
	assert.Nil(t, values(adm.Lookup(nil, "sub")), "nil naming")
	assert.Nil(t, values((&Admission{}).Lookup(naming, "mount")), "no mount path")
	assert.Nil(t, values((&Admission{}).Lookup(naming, "sub")), "no facts")
	assert.Nil(t, values(adm.Lookup(&MountNaming{}, "kind")), "no kind (only a hand-built naming)")
	assert.Nil(t, values(adm.Lookup(&MountNaming{Kind: EntityKindAgent}, "sub")), "no mapping")
}

func TestAdmissionLookup_DoesNotAllocate(t *testing.T) {
	adm, _ := jwtAdmission(t)
	names := []string{"mount", "kind", "repo", "env", "sub", "aud", "email", "gone"}
	allocs := testing.AllocsPerRun(1000, func() {
		n := adm.Mount.Load()
		for _, name := range names {
			cur := adm.Lookup(n, name)
			for _, ok := cur.Next(); ok; _, ok = cur.Next() {
			}
		}
	})
	assert.Zero(t, allocs)
}

func TestParseEntityKind(t *testing.T) {
	for in, want := range map[string]string{"": EntityKindAgent, "agent": EntityKindAgent, "human": EntityKindHuman} {
		got, err := ParseEntityKind(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"Agent", "HUMAN", "service", " agent", "agent "} {
		_, err := ParseEntityKind(in)
		assert.Error(t, err, in)
	}
}

func TestNewMountNaming(t *testing.T) {
	m := testMapping(t, []string{"sub"}, nil)
	n, err := NewMountNaming(m, "")
	require.NoError(t, err)
	assert.Same(t, m, n.Mapping)
	assert.Equal(t, EntityKindAgent, n.Kind, "an empty kind is agent")
	assert.Equal(t, EntityKindHuman, testNaming(t, m, EntityKindHuman).Kind)

	n, err = NewMountNaming(m, "robot")
	assert.Error(t, err, "an unknown kind is refused")
	assert.Nil(t, n)
}

func TestMountFactsPublishLoad(t *testing.T) {
	var nilMF *MountFacts
	assert.Nil(t, nilMF.Load())
	mf := &MountFacts{}
	assert.Nil(t, mf.Load(), "nothing published yet")
	n := testNaming(t, testMapping(t, []string{"sub"}, nil), "")
	mf.Publish(n)
	assert.Same(t, n, mf.Load())
}

func TestAdmissionSize(t *testing.T) {
	var nilAdm *Admission
	assert.Zero(t, nilAdm.Size())
	assert.Zero(t, (&Admission{}).Size())
	assert.Zero(t, (&Admission{Bytes: -5}).Size(), "a negative estimate counts as none")
	assert.Equal(t, int64(1234), (&Admission{Bytes: 1234}).Size())
}

// A published naming is seen whole: a reader never pairs one configuration's
// kind with another's mapping.
func TestMountFacts_PublishSeenWhole(t *testing.T) {
	agent := testNaming(t, testMapping(t, nil, map[string]string{"a": "x"}), EntityKindAgent)
	human := testNaming(t, testMapping(t, nil, map[string]string{"h": "x"}), EntityKindHuman)
	mf := &MountFacts{}
	mf.Publish(agent)
	adm := &Admission{
		MountPath: "auth/jwt/",
		Facts:     testClaims(t, `{"a": "agent", "h": "human"}`),
		Mount:     mf,
	}

	const readers, rounds = 8, 2000
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				mf.Publish(human)
			} else {
				mf.Publish(agent)
			}
		}
	})
	errs := make(chan error, readers)
	var rwg sync.WaitGroup
	for range readers {
		rwg.Go(func() {
			for range rounds {
				n := adm.Mount.Load()
				kind, x := values(adm.Lookup(n, "kind")), values(adm.Lookup(n, "x"))
				if len(kind) != 1 || len(x) != 1 || kind[0] != x[0] {
					errs <- fmt.Errorf("kind %v seen with fact x = %v", kind, x)
					return
				}
			}
		})
	}
	rwg.Wait()
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestAdmissionRenderMetadata(t *testing.T) {
	naming := testNaming(t, testMapping(t, []string{"sub", "iss"}, map[string]string{
		"team":          "team",
		"groups":        "groups",
		"level":         "level",
		"ratio":         "ratio",
		"admin":         "admin",
		"mixed":         "mixed",
		"/deploy/env":   "env",
		"blank":         "blank",
		"objects":       "objects",
		"absent":        "absent",
		"sub":           "sub",
		"https://x/big": "big",
	}), EntityKindAgent)
	adm := &Admission{
		MountPath: "auth/jwt/",
		Facts: testClaims(t, `{
			"sub": "agent-1",
			"iss": "https://issuer.example",
			"team": "platform",
			"groups": ["a", "b", "c"],
			"level": 42,
			"ratio": 1.5,
			"admin": false,
			"mixed": ["x", 7, true, {"o": 1}],
			"deploy": {"env": "prod"},
			"blank": "",
			"objects": [{"o": 1}],
			"https://x/big": 1e21
		}`),
	}
	assert.Equal(t, map[string]string{
		"team":   "platform",
		"groups": "a,b,c",
		"level":  "42",
		"ratio":  "1.5",
		"admin":  "false",
		"mixed":  "x,7,true",
		"env":    "prod",
		"blank":  "", // present, so rendered
		"sub":    "agent-1",
		"big":    "1e+21",
		// "objects" yields no scalar and "absent" is not carried: both skipped.
		// "iss" is a built-in that is not mapped: not metadata.
	}, adm.RenderMetadata(naming))
}

func TestAdmissionRenderMetadata_Nil(t *testing.T) {
	adm, naming := jwtAdmission(t)
	var nilAdm *Admission
	assert.Nil(t, adm.RenderMetadata(nil))
	assert.Nil(t, nilAdm.RenderMetadata(naming))
	builtinsOnly := testNaming(t, testMapping(t, []string{"sub"}, nil), EntityKindAgent)
	assert.Nil(t, adm.RenderMetadata(builtinsOnly), "no mapped names")
	absentOnly := testNaming(t, testMapping(t, nil, map[string]string{"absent": "gone"}), EntityKindAgent)
	assert.Nil(t, adm.RenderMetadata(absentOnly), "nothing rendered")
}

// An admission never leaves memory: the structs that are serialized (the
// login Auth, the auth data, a persisted token) leave it out.
func TestAdmission_NeverSerialized(t *testing.T) {
	adm, _ := jwtAdmission(t)
	for name, v := range map[string]any{
		"Auth":       &Auth{Admission: adm},
		"AuthData":   &AuthData{Admission: adm},
		"TokenEntry": &TokenEntry{Admission: adm},
	} {
		b, err := json.Marshal(v)
		require.NoError(t, err, name)
		assert.NotContains(t, string(b), "Admission", name)
		assert.NotContains(t, string(b), "agent-1", name)
	}

	// Held anywhere else, such as a response's data map, it refuses to encode.
	for name, v := range map[string]any{
		"pointer":  adm,
		"data map": map[string]any{"admission": adm},
	} {
		b, err := json.Marshal(v)
		assert.ErrorIs(t, err, ErrAdmissionNotSerializable, name)
		assert.Nil(t, b, name)
	}
}

// A request is marked internal only in process: the flag never encodes or
// decodes.
func TestRequest_InternalNotSerialized(t *testing.T) {
	b, err := json.Marshal(&Request{Internal: true})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "Internal")
	assert.NotContains(t, string(b), "internal")

	var req Request
	require.NoError(t, json.Unmarshal([]byte(`{"Internal":true,"internal":true}`), &req))
	assert.False(t, req.Internal)
}
