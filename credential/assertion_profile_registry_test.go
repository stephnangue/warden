package credential

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProfile is a minimal profile for registry and validation tests.
type fakeProfile struct {
	name        string
	typ         string
	sourceTypes []string
	specErr     error
}

func (f fakeProfile) Name() string { return f.name }

func (f fakeProfile) Typ() string {
	if f.typ == "" {
		return "JWT"
	}
	return f.typ
}

func (f fakeProfile) Claims(AssertionRequest) (map[string]any, error) { return map[string]any{}, nil }

func (f fakeProfile) ValidateSpec(Config) error { return f.specErr }

// pinnedFakeProfile adds the optional source-pin capability.
type pinnedFakeProfile struct {
	fakeProfile
}

func (p pinnedFakeProfile) SourceTypes() []string { return p.sourceTypes }

func TestAssertionProfileRegistry_RegisterAndGet(t *testing.T) {
	reg := NewAssertionProfileRegistry()

	require.NoError(t, reg.Register(fakeProfile{name: "shape_a"}))

	got, err := reg.GetByName("shape_a")
	require.NoError(t, err)
	assert.Equal(t, "shape_a", got.Name())

	assert.True(t, reg.HasProfile("shape_a"))
	assert.False(t, reg.HasProfile("shape_b"))

	_, err = reg.GetByName("shape_b")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAssertionProfileNotFound)
}

// Resolve is the one lookup both spec-create and mint use, so its message is the
// one operators see from either path.
func TestAssertionProfileRegistry_Resolve(t *testing.T) {
	reg := NewAssertionProfileRegistry()
	require.NoError(t, reg.Register(fakeProfile{name: "zeta"}))
	require.NoError(t, reg.Register(fakeProfile{name: "alpha"}))

	got, err := reg.Resolve("alpha")
	require.NoError(t, err)
	assert.Equal(t, "alpha", got.Name())

	_, err = reg.Resolve("nope")
	require.Error(t, err)
	// Exact text, including the sorted available list.
	assert.EqualError(t, err, "unknown assertion profile: nope (available profiles: [alpha zeta])")
}

func TestAssertionProfileRegistry_RejectsDuplicate(t *testing.T) {
	reg := NewAssertionProfileRegistry()

	require.NoError(t, reg.Register(fakeProfile{name: "shape_a"}))
	err := reg.Register(fakeProfile{name: "shape_a"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAssertionProfileAlreadyRegistered)
}

// TestAssertionProfileRegistry_RejectsReservedNames is where the id_jag reservation
// lives in code: it fires at startup when a builtin is added, not only when an
// operator writes one into a spec config.
func TestAssertionProfileRegistry_RejectsReservedNames(t *testing.T) {
	for _, name := range []string{
		"", "id_jag", "jwt_bearer", "rfc8693",
		"none", "warden_identity", "agent_identity", "user_identity",
		"access_token", "refresh_token", "id_token", "jwt", "saml2", "at_jwt",
	} {
		t.Run(name, func(t *testing.T) {
			reg := NewAssertionProfileRegistry()
			err := reg.Register(fakeProfile{name: name})
			require.Error(t, err, "name %q must be rejected", name)
			assert.ErrorIs(t, err, ErrAssertionProfileNameReserved)
			assert.False(t, reg.HasProfile(name))
		})
	}
}

// A vendor name is NOT reserved: a source-pinned profile shares its source's name
// on purpose, which is the whole naming rule.
func TestAssertionProfileRegistry_SourceTypeNamesAreNotReserved(t *testing.T) {
	reg := NewAssertionProfileRegistry()
	for _, name := range []string{SourceTypeAWS, SourceTypeGCP, SourceTypeAzure} {
		assert.NoError(t, reg.Register(fakeProfile{name: name}), "source name %q must be registrable", name)
	}
}

// A blank typ would sign `"typ":""` (or `"typ":" "`) into a header a verifier may
// reject, so it is refused at registration. Whitespace counts as blank: " " is
// functionally no typ.
func TestAssertionProfileRegistry_RejectsBlankTyp(t *testing.T) {
	for _, typ := range []string{"", " ", "\t", "\n  "} {
		t.Run(typ, func(t *testing.T) {
			err := NewAssertionProfileRegistry().Register(blankTypProfile{typ: typ})
			require.Error(t, err, "typ %q must be rejected", typ)
			assert.ErrorIs(t, err, ErrAssertionProfileInvalid)
		})
	}

	// A real typ registers.
	assert.NoError(t, NewAssertionProfileRegistry().Register(fakeProfile{name: "shape_a", typ: "JWT"}))
	assert.NoError(t, NewAssertionProfileRegistry().Register(fakeProfile{name: "shape_b", typ: "at+jwt"}))
}

func TestAssertionProfileRegistry_RejectsNilProfile(t *testing.T) {
	err := NewAssertionProfileRegistry().Register(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAssertionProfileInvalid)
}

// blankTypProfile returns its typ verbatim, so a test can supply a blank one
// (fakeProfile deliberately substitutes "JWT" for an empty typ).
type blankTypProfile struct{ typ string }

func (blankTypProfile) Name() string                                    { return "shape_no_typ" }
func (b blankTypProfile) Typ() string                                   { return b.typ }
func (blankTypProfile) Claims(AssertionRequest) (map[string]any, error) { return nil, nil }
func (blankTypProfile) ValidateSpec(Config) error                       { return nil }

// ListProfiles must be sorted: the list is interpolated into the "available
// profiles" error, and map order would make that message nondeterministic.
func TestAssertionProfileRegistry_ListProfilesIsSorted(t *testing.T) {
	reg := NewAssertionProfileRegistry()
	for _, name := range []string{"zeta", "alpha", "mu", "beta"} {
		require.NoError(t, reg.Register(fakeProfile{name: name}))
	}
	assert.Equal(t, []string{"alpha", "beta", "mu", "zeta"}, reg.ListProfiles())

	assert.Empty(t, NewAssertionProfileRegistry().ListProfiles())
}

// TestReservedAssertionProfileNames_CoversTokenSources is the drift guard for the
// *_token_source values.
//
// It iterates subjectTokenSources and actorTokenSources — the SAME slices the
// ValidateExchangeSpecConfig OneOf checks use — so a value added to either validator
// is automatically in this loop and fails it until it is also reserved. Iterating a
// hardcoded copy would let a new value through, which is the failure this test
// exists to prevent.
//
// The sibling guard for the exchange GRANT values lives in package drivers, which
// can see those unexported constants; credential cannot, and drivers imports
// credential rather than the reverse.
func TestReservedAssertionProfileNames_CoversTokenSources(t *testing.T) {
	all := append(append([]string(nil), subjectTokenSources...), actorTokenSources...)
	require.NotEmpty(t, all, "the token-source lists must not be empty, or this test asserts nothing")

	for _, v := range all {
		assert.True(t, IsReservedAssertionProfileName(v),
			"token-source value %q is not a reserved assertion profile name: reserve it, or an operator can confuse the two in one spec config", v)
	}
}

func TestIsReservedAssertionProfileName(t *testing.T) {
	assert.True(t, IsReservedAssertionProfileName("id_jag"))
	assert.True(t, IsReservedAssertionProfileName(""))
	assert.False(t, IsReservedAssertionProfileName(DefaultAssertionProfileName),
		"default is guarded by the duplicate check, not by reservation")
	assert.False(t, IsReservedAssertionProfileName(SourceTypeAWS),
		"a source-pinned profile shares its source's name on purpose")
}

func TestAssertionProfileName(t *testing.T) {
	assert.Equal(t, DefaultAssertionProfileName, AssertionProfileName(Config{}))
	assert.Equal(t, DefaultAssertionProfileName,
		AssertionProfileName(NewConfig(map[string]string{ConfigAssertionProfile: ""})))
	assert.Equal(t, "shape_a",
		AssertionProfileName(NewConfig(map[string]string{ConfigAssertionProfile: "shape_a"})))
}
