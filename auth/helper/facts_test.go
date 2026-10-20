package helper

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

var testBuiltins = []string{"sub", "iss", "aud"}

func TestFactsConfig_Compile(t *testing.T) {
	c := FactsConfig{Facts: map[string]string{"repository": "repo"}}
	c.Compile(testBuiltins)
	require.NoError(t, c.Err())
	require.NotNil(t, c.Naming())
	assert.Equal(t, logical.EntityKindAgent, c.EntityKind, "an empty kind is normalized")
	assert.Equal(t, logical.EntityKindAgent, c.Naming().Kind)
	assert.Equal(t, []string{"repo"}, c.Naming().Mapping.Mapped())
	assert.Equal(t, []string{"aud", "iss", "repo", "sub"}, c.Naming().Mapping.Names())

	human := FactsConfig{EntityKind: logical.EntityKindHuman}
	human.Compile(testBuiltins)
	require.NoError(t, human.Err())
	assert.Equal(t, logical.EntityKindHuman, human.Naming().Kind)

	badFacts := FactsConfig{Facts: map[string]string{"path": "mount"}}
	badFacts.Compile(testBuiltins)
	assert.Nil(t, badFacts.Naming())
	assert.ErrorContains(t, badFacts.Err(), "facts: ")

	badKind := FactsConfig{EntityKind: "robot"}
	badKind.Compile(testBuiltins)
	assert.Nil(t, badKind.Naming())
	assert.ErrorContains(t, badKind.Err(), "entity_kind: ")
	assert.Equal(t, "robot", badKind.EntityKind, "a failed compile leaves the kind as written")

	// Compiling again replaces the earlier result.
	badKind.EntityKind = ""
	badKind.Compile(testBuiltins)
	assert.NoError(t, badKind.Err())
	assert.NotNil(t, badKind.Naming())
}

// A method whose facts are a fixed set of fields maps only those fields.
func TestFactsConfig_CompileFields(t *testing.T) {
	fields := []string{"username", "groups", "aud"}

	ok := FactsConfig{Facts: map[string]string{"username": "workload", "groups": "groups"}}
	ok.CompileFields(fields)
	require.NoError(t, ok.Err())
	assert.Equal(t, []string{"groups", "workload"}, ok.Naming().Mapping.Mapped())
	assert.Equal(t, []string{"aud", "groups", "username", "workload"}, ok.Naming().Mapping.Names())

	for _, source := range []string{"email", "/a/b", "Username"} {
		c := FactsConfig{Facts: map[string]string{"username": "workload", source: "x"}}
		c.CompileFields(fields)
		assert.Nil(t, c.Naming(), "source %q", source)
		assert.EqualError(t, c.Err(), `facts: source "`+source+`" is not a field of this mount (one of aud, groups, username)`)
	}

	// Compile's own refusals still apply, and a later success replaces a failure.
	c := FactsConfig{Facts: map[string]string{"username": "aud"}}
	c.CompileFields(fields)
	assert.ErrorContains(t, c.Err(), "built-in")
	c.Facts = nil
	c.CompileFields(fields)
	require.NoError(t, c.Err())
	assert.NotNil(t, c.Naming())
}

// Embedded in a config struct, FactsConfig is flattened by encoding/json, and
// its compiled state is neither written nor read.
func TestFactsConfig_JSON(t *testing.T) {
	type config struct {
		URL string `json:"url"`
		FactsConfig
	}
	in := config{URL: "u", FactsConfig: FactsConfig{EntityKind: "human", Facts: map[string]string{"a": "b"}}}
	in.Compile(testBuiltins)
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	assert.JSONEq(t, `{"url":"u","entity_kind":"human","facts":{"a":"b"}}`, string(raw))

	var out config
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, "human", out.EntityKind)
	assert.Equal(t, map[string]string{"a": "b"}, out.Facts)
	assert.Nil(t, out.Naming(), "compiled state is not decoded")
}

func TestFactsWriteError(t *testing.T) {
	ok := FactsConfig{}
	ok.Compile(testBuiltins)
	assert.NoError(t, FactsWriteError(&ok, true))
	assert.NoError(t, FactsWriteError(&ok, false))

	bad := FactsConfig{Facts: map[string]string{"a": "Bad"}}
	bad.Compile(testBuiltins)
	assert.Equal(t, bad.Err(), FactsWriteError(&bad, true), "a write that sent facts gets their error")
	err := FactsWriteError(&bad, false)
	require.Error(t, err)
	assert.Equal(t, "the stored facts do not compile ("+bad.Err().Error()+
		"); send facts (and entity_kind) in this write to replace them", err.Error())
}

func TestParseFactsField(t *testing.T) {
	got, err := ParseFactsField(map[string]any{"repository": "repo", "/a/b": "env"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"repository": "repo", "/a/b": "env"}, got)

	for _, empty := range []any{nil, map[string]any{}, map[string]string{}} {
		got, err := ParseFactsField(empty)
		require.NoError(t, err)
		assert.Nil(t, got)
	}

	in := map[string]string{"a": "b"}
	got, err = ParseFactsField(in)
	require.NoError(t, err)
	got["a"] = "changed"
	assert.Equal(t, "b", in["a"], "the result is a copy")

	_, err = ParseFactsField(map[string]any{"team": 5})
	assert.EqualError(t, err, `facts: the fact name for source "team" must be a string, got int`)
	_, err = ParseFactsField("team=team")
	assert.ErrorContains(t, err, "must be a map")
}

func TestFactsFieldSchemas(t *testing.T) {
	s := FactsFieldSchemas("one of the fields: a, b")
	require.Len(t, s, 2)
	assert.Equal(t, framework.TypeString, s["entity_kind"].Type)
	assert.Equal(t, framework.TypeMap, s["facts"].Type)
	assert.NotEmpty(t, s["entity_kind"].Description)
	assert.Contains(t, s["facts"].Description, "Map of a source (one of the fields: a, b) to the fact name")
	assert.NotContains(t, s["facts"].Description, "Pointer", "the source phrase is the method's")

	s["facts"].Description = "changed"
	assert.NotEqual(t, "changed", FactsFieldSchemas("x")["facts"].Description, "each call is fresh")
}

func TestParseBoundAudiences(t *testing.T) {
	cases := []struct {
		raw  any
		want []string
		err  string
	}{
		{nil, nil, ""},
		{"", nil, ""},
		{[]string{}, nil, ""},
		{[]any{}, nil, ""},
		{"warden", []string{"warden"}, ""},
		{" warden , vault ", []string{"warden", "vault"}, ""},
		{[]string{"warden", " vault"}, []string{"warden", "vault"}, ""},
		{[]any{"warden"}, []string{"warden"}, ""},
		{"warden,,vault", nil, "bound_audiences: entry 1 is empty"},
		{[]string{"warden", ""}, nil, "bound_audiences: entry 1 is empty"},
		{[]string{"  "}, nil, "bound_audiences: entry 0 is empty"},
		{map[string]any{"a": 1}, nil, "bound_audiences: "},
	}
	for _, tc := range cases {
		got, err := ParseBoundAudiences(tc.raw)
		if tc.err != "" {
			assert.ErrorContains(t, err, tc.err, "raw %#v", tc.raw)
			continue
		}
		require.NoError(t, err, "raw %#v", tc.raw)
		assert.Equal(t, tc.want, got, "raw %#v", tc.raw)
	}
}

func TestTableValues(t *testing.T) {
	assert.Equal(t, selector.Field{Name: "uid"}, TableValue("uid", ""))
	assert.Equal(t, selector.Field{Name: "uid", Values: []string{"u"}}, TableValue("uid", "u"))

	assert.Equal(t, selector.Field{Name: "g"}, TableValues("g", nil))
	assert.Equal(t, selector.Field{Name: "g", Values: []string{}}, TableValues("g", []string{"", ""}))
	assert.Equal(t, []string{"a", "b"}, TableValues("g", []string{"", "a", "", "b", ""}).Values)

	vs := []string{"a", "b"}
	got := TableValues("g", vs)
	assert.Same(t, &vs[0], &got.Values[0], "a list without empty entries is used as is")

	in := []string{"a", "", "b"}
	TableValues("g", in)
	assert.Equal(t, []string{"a", "", "b"}, in, "the input is not modified")
}

func TestFactNames(t *testing.T) {
	assert.Nil(t, FactNames(nil))
	mf := &logical.MountFacts{}
	assert.Nil(t, FactNames(mf))

	c := FactsConfig{Facts: map[string]string{"repository": "repo"}}
	c.Compile(testBuiltins)
	mf.Publish(c.Naming())
	names := FactNames(mf)
	assert.Equal(t, []string{"aud", "iss", "repo", "sub"}, names)
	names[0] = "changed"
	assert.Equal(t, "aud", FactNames(mf)[0], "the result is a copy")
}

func TestIssuedAt(t *testing.T) {
	want := time.Unix(1700000000, 0)
	cases := []struct {
		name string
		iat  any
		want time.Time
	}{
		{"float64", 1700000000.0, want},
		{"float64 fraction truncated", 1700000000.9, want},
		{"json.Number", json.Number("1700000000"), want},
		{"json.Number with exponent", json.Number("1.7e9"), want},
		{"int", 1700000000, want},
		{"int32", int32(1700000000), want},
		{"int64", int64(1700000000), want},
		{"uint64", uint64(1700000000), want},
		{"upper bound", int64(1 << 40), time.Unix(1<<40, 0)},
		{"zero", 0.0, time.Time{}},
		{"negative float", -5.0, time.Time{}},
		{"negative int64", int64(-5), time.Time{}},
		{"negative json.Number", json.Number("-5"), time.Time{}},
		{"huge float", 1e300, time.Time{}},
		{"huge int64", int64(1<<40 + 1), time.Time{}},
		{"huge uint64", uint64(1 << 63), time.Time{}},
		{"huge json.Number", json.Number("99999999999999999999"), time.Time{}},
		{"string", "1700000000", time.Time{}},
		{"bool", true, time.Time{}},
		{"bad json.Number", json.Number("soon"), time.Time{}},
		{"null", nil, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IssuedAt(map[string]any{"iat": tc.iat}))
		})
	}
	assert.True(t, IssuedAt(map[string]any{}).IsZero(), "absent")
	assert.True(t, IssuedAt(nil).IsZero(), "nil claims")
}

func TestJWTPayloadBytes(t *testing.T) {
	payload := `{"sub":"agent-1","n":12345}`
	seg := base64.RawURLEncoding.EncodeToString([]byte(payload))
	assert.Equal(t, int64(len(payload)), JWTPayloadBytes("eyJhbGciOiJFUzI1NiJ9."+seg+".sig"))
	assert.Zero(t, JWTPayloadBytes(""))
	assert.Zero(t, JWTPayloadBytes("no-dots"))
	assert.Zero(t, JWTPayloadBytes("one.dot"))
}

func TestAnchorFingerprints(t *testing.T) {
	// A fingerprint hashes the DER alone, so certificates holding only Raw do.
	cert := func(der string) *x509.Certificate { return &x509.Certificate{Raw: []byte(der)} }
	fp := func(der string) string {
		sum := sha256.Sum256([]byte(der))
		return hex.EncodeToString(sum[:])
	}
	assert.Equal(t, fp("leaf"), CertFingerprint(cert("leaf")))
	assert.Regexp(t, "^[0-9a-f]{64}$", CertFingerprint(cert("leaf")))

	leaf, mid := cert("leaf"), cert("mid")
	rootA, rootB := cert("root a"), cert("root b")
	want := []string{fp("root a"), fp("root b")}
	slices.Sort(want)

	// Each distinct anchor once, sorted, whatever the order of the chains.
	chains := [][]*x509.Certificate{
		{leaf, rootB},
		{leaf, mid, rootA},
		{leaf, rootA},
		{leaf, mid, rootB},
	}
	assert.Equal(t, want, AnchorFingerprints(chains))
	slices.Reverse(chains)
	assert.Equal(t, want, AnchorFingerprints(chains))

	assert.Equal(t, []string{fp("root a")}, AnchorFingerprints([][]*x509.Certificate{{leaf, rootA}}))
	assert.Empty(t, AnchorFingerprints(nil))
}
