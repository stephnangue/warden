package core

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/profiles"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shapeProfile is a registrable non-default profile for cache-fragment tests. It
// emits a correct claim set so the issuer's guard passes and the test is only about
// the cache key.
type shapeProfile struct{ name string }

func (s shapeProfile) Name() string                         { return s.name }
func (s shapeProfile) Typ() string                          { return "JWT" }
func (s shapeProfile) ValidateSpec(credential.Config) error { return nil }
func (s shapeProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	return map[string]any{
		"iss": req.Issuer,
		"sub": req.Identity.WardenSubject(),
		"aud": req.Audience,
		"iat": req.IssuedAt.Unix(),
		"nbf": req.NotBefore.Unix(),
		"exp": req.ExpiresAt.Unix(),
		"jti": req.JTI,
	}, nil
}

// TestCacheIdentity_ProfileFragment pins that the profile fragment is appended
// AFTER every existing fragment, and that the default profile appends nothing.
//
// The "after" part is contract, not taste: the sibling test
// ...RoleCannotImpersonateAnotherFragment relies on fragment order, and the golden
// cacheIdentity literals in request_handler_test.go (:2681, :2730, :2766, :2811,
// :3138-3189) are the byte-for-byte proof that keys predating this fragment did not
// move.
func TestCacheIdentity_ProfileFragment(t *testing.T) {
	c, ctx := exchangeResolveEnv(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden-oidc.example")

	// Register a non-default profile so a spec may legitimately name it.
	require.NoError(t, c.assertionProfileRegistry.Register(shapeProfile{name: "x"}))

	require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{
		Name: "aws-prof", Type: credential.SourceTypeAWS,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))

	newSpecTE := func(name, profileName string) *logical.TokenEntry {
		cfg := map[string]string{
			credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
			credential.ConfigAssertionAudience:  "sts.amazonaws.com",
			credential.ConfigAssertionResource:  credential.AssertionResourceNone,
			"mint_method":                       "secrets_manager",
			"secret_id":                         "prod/db",
		}
		if profileName != "" {
			cfg[credential.ConfigAssertionProfile] = profileName
		}
		require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
			Name: name, Type: "vault_token", Source: "aws-prof",
			Config: credential.NewConfig(cfg),
		}))
		return &logical.TokenEntry{
			CredentialSpec: name, PrincipalID: "p", NamespaceID: "n",
			MountAccessor: "m", RoleName: "reader",
		}
	}

	// Unset → no fragment at all, so the key is byte-identical to a pre-profile key.
	teUnset := newSpecTE("prof-unset", "")
	inUnset, err := resolveExchangeInputsForTest(c, ctx, requestWith("s.opaque", nil), teUnset)
	require.NoError(t, err)
	wantBase := wardenSubject(teUnset) + "\x00sts.amazonaws.com\x00role=reader"
	assert.Equal(t, wantBase, inUnset.SubjectCacheIdentity,
		"an unset profile must leave the cache key byte-for-byte unchanged")

	// Explicitly "default" → also no fragment, so it cannot split the cache from unset.
	teDefault := newSpecTE("prof-default", credential.DefaultAssertionProfileName)
	inDefault, err := resolveExchangeInputsForTest(c, ctx, requestWith("s.opaque", nil), teDefault)
	require.NoError(t, err)
	assert.Equal(t, wardenSubject(teDefault)+"\x00sts.amazonaws.com\x00role=reader",
		inDefault.SubjectCacheIdentity,
		"assertion_profile=default must key identically to an unset profile")

	// A non-default profile → "prof=" appended after every existing fragment.
	teX := newSpecTE("prof-x", "x")
	inX, err := resolveExchangeInputsForTest(c, ctx, requestWith("s.opaque", nil), teX)
	require.NoError(t, err)
	assert.Equal(t, wardenSubject(teX)+"\x00sts.amazonaws.com\x00role=reader\x00prof=x",
		inX.SubjectCacheIdentity)

	// And it genuinely separates the two answers.
	assert.NotEqual(t, inUnset.SubjectCacheIdentity, inX.SubjectCacheIdentity,
		"two profiles must not share a cache identity")
}

// TestCacheIdentity_ProfileFragmentAfterAllFragments pins the ordering against a
// fully-populated key — role, resource and metadata all present.
func TestCacheIdentity_ProfileFragmentAfterAllFragments(t *testing.T) {
	c, ctx := exchangeResolveEnv(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden-oidc.example")
	require.NoError(t, c.assertionProfileRegistry.Register(shapeProfile{name: "x"}))

	require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{
		Name: "aws-prof-all", Type: credential.SourceTypeAWS,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name: "prof-all", Type: "vault_token", Source: "aws-prof-all",
		Config: credential.NewConfig(map[string]string{
			credential.ConfigSubjectTokenSource:      credential.SourceWardenIdentity,
			credential.ConfigAssertionAudience:       "sts.amazonaws.com",
			credential.ConfigAssertionResource:       "custom:thing",
			credential.ConfigAssertionMetadataClaims: "team",
			credential.ConfigAssertionProfile:        "x",
			"mint_method":                            "secrets_manager",
			"secret_id":                              "prod/db",
		}),
	}))

	te := &logical.TokenEntry{
		CredentialSpec: "prof-all", PrincipalID: "p", NamespaceID: "n",
		MountAccessor: "m", RoleName: "reader",
		Metadata: map[string]string{"team": "payments"},
	}
	in, err := resolveExchangeInputsForTest(c, ctx, requestWith("s.opaque", nil), te)
	require.NoError(t, err)

	// prof= is last, after role=, res= and the metadata fingerprint — and the
	// metadata fragment's '{' lead is pinned too, since the lead-byte discipline
	// documented in buildAssertionSetup relies on it.
	assert.Regexp(t,
		`^.*\x00sts\.amazonaws\.com\x00role=reader\x00res=custom:thing\x00\{.+\}\x00prof=x$`,
		in.SubjectCacheIdentity)
}

// TestResolveAssertionProfile_NilRegistry pins the nil-registry case explicitly,
// because the issuer's nil-Profile fallback would otherwise hide it.
//
// Spec-create validation passes on a nil registry, so a spec naming a non-default
// profile CAN be persisted by a test or bootstrap setup. Such a spec must NOT then
// quietly mint the default shape — a caller that asked for a different claim set
// silently getting the old one is exactly what the registry exists to prevent.
func TestResolveAssertionProfile_NilRegistry(t *testing.T) {
	c := &Core{}
	require.Nil(t, c.assertionProfileRegistry)

	// Unset (which resolves to "default") and an explicit "default" both work.
	got, err := c.resolveAssertionProfile(credential.DefaultAssertionProfileName)
	require.NoError(t, err)
	assert.Equal(t, profiles.Default().Name(), got.Name())

	// Any other name fails closed.
	_, err = c.resolveAssertionProfile("x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unavailable")
	assert.Contains(t, err.Error(), "x")
}

func TestResolveAssertionProfile_UnknownName(t *testing.T) {
	c, _ := exchangeResolveEnv(t)
	require.NotNil(t, c.assertionProfileRegistry)

	got, err := c.resolveAssertionProfile(credential.DefaultAssertionProfileName)
	require.NoError(t, err)
	assert.Equal(t, credential.DefaultAssertionProfileName, got.Name())

	_, err = c.resolveAssertionProfile("nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown assertion profile: nope")
	assert.Contains(t, err.Error(), "available profiles: [default]")
}

// A spec naming a profile this build lacks must fail BEFORE any cache interaction,
// in buildAssertionSetup rather than at signing time.
func TestResolveExchangeInputs_UnknownProfileFailsClosed(t *testing.T) {
	c, ctx := exchangeResolveEnv(t)
	c.oidcIssuer = newReadyIssuer(t, "https://warden-oidc.example")

	require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{
		Name: "aws-gone", Type: credential.SourceTypeAWS,
		Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}),
	}))
	// Register the profile, create the spec, then drop the registry entry — the
	// shape of "a profile removed from a later build".
	require.NoError(t, c.assertionProfileRegistry.Register(shapeProfile{name: "retired"}))
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name: "prof-gone", Type: "vault_token", Source: "aws-gone",
		Config: credential.NewConfig(map[string]string{
			credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
			credential.ConfigAssertionAudience:  "sts.amazonaws.com",
			credential.ConfigAssertionProfile:   "retired",
			"mint_method":                       "secrets_manager",
			"secret_id":                         "prod/db",
		}),
	}))
	c.assertionProfileRegistry = credential.NewAssertionProfileRegistry()
	require.NoError(t, profiles.RegisterBuiltinProfiles(c.assertionProfileRegistry))

	te := &logical.TokenEntry{
		CredentialSpec: "prof-gone", PrincipalID: "p", NamespaceID: "n", MountAccessor: "m",
	}
	_, err := resolveExchangeInputsForTest(c, ctx, requestWith("s.opaque", nil), te)
	require.Error(t, err, "a spec naming an absent profile must fail closed, not mint the default shape")
	assert.Contains(t, err.Error(), "unknown assertion profile: retired")
}
