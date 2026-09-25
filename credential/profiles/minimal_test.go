package profiles

import (
	"sync"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMinimalProfile_Metadata(t *testing.T) {
	p := MinimalProfile{}
	assert.Equal(t, "minimal", p.Name())
	assert.Equal(t, "JWT", p.Typ())
	// Named after its shape, not a vendor, so it carries no source pin.
	_, pinned := any(p).(credential.AssertionProfileSourcePinned)
	assert.False(t, pinned, "minimal must not be source-pinned")
}

// TestMinimalProfile_Claims_ExactSet pins the exact frozen shape: the seven registered
// claims, typed as the issuer's post-render guard compares them, and nothing else —
// although the request carries metadata, user claims, a resource and a role.
func TestMinimalProfile_Claims_ExactSet(t *testing.T) {
	req := fixedRequest()
	require.NotEmpty(t, req.Metadata, "precondition: the request carries metadata")
	require.NotEmpty(t, req.UserClaims, "precondition: the request carries user claims")
	require.NotEmpty(t, req.Resource, "precondition: the request carries a resource")

	claims, err := MinimalProfile{}.Claims(req)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss": "https://warden.example.com",
		"sub": "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
		"aud": "sts.amazonaws.com",
		"iat": int64(1755248400),
		"nbf": int64(1755248370),
		"exp": int64(1755248700),
		"jti": "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
	}, claims)
}

// The subject is byte-for-byte the default profile's, so a trust written against a
// default-profile subject keeps matching when a spec moves to minimal.
func TestMinimalProfile_Claims_SubjectMatchesDefault(t *testing.T) {
	req := fixedRequest()
	minimal, err := MinimalProfile{}.Claims(req)
	require.NoError(t, err)
	def, err := Default().Claims(req)
	require.NoError(t, err)
	assert.Equal(t, def["sub"], minimal["sub"])
}

// A role-less identity (a root token) mints the same shape: the role is not
// rendered, so there is nothing to omit or refuse.
func TestMinimalProfile_Claims_RoleLessIdentity(t *testing.T) {
	req := fixedRequest()
	req.Identity.RoleName = ""

	claims, err := MinimalProfile{}.Claims(req)
	require.NoError(t, err)
	assert.Len(t, claims, 7)
	assert.Equal(t, "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7", claims["sub"])
}

func TestMinimalProfile_Claims_Pure(t *testing.T) {
	req := fixedRequest()

	first, err := MinimalProfile{}.Claims(req)
	require.NoError(t, err)
	second, err := MinimalProfile{}.Claims(req)
	require.NoError(t, err)

	first["injected"] = "should not leak"
	assert.NotContains(t, second, "injected", "Claims returned a shared map")

	assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata)
	assert.Equal(t, map[string]string{"sub": "alice@example.com", "username": "alice"}, req.UserClaims)
}

func TestMinimalProfile_Claims_Concurrent(t *testing.T) {
	req := fixedRequest()
	p := MinimalProfile{}

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]map[string]any, goroutines)
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = p.Claims(req)
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i])
		assert.Equal(t, results[0], results[i])
	}
}

// assertion_resource's sole effect is the warden_resource claim, which this profile
// never emits, so an explicit value is rejected. Unset (derive) and "none" are fine.
func TestMinimalProfile_ValidateSpec_Resource(t *testing.T) {
	res := func(v string) credential.Config {
		return credential.NewConfig(map[string]string{credential.ConfigAssertionResource: v})
	}

	assert.NoError(t, MinimalProfile{}.ValidateSpec(credential.Config{}))
	assert.NoError(t, MinimalProfile{}.ValidateSpec(res(credential.AssertionResourceNone)))

	err := MinimalProfile{}.ValidateSpec(res("azure:https://management.azure.com/"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigAssertionResource)
	assert.Contains(t, err.Error(), "never emits warden_resource")
}

// The claim-projection keys also drive {{user.*}} / {{agent.*}} templating, and the
// remaining assertion_* keys shape aud, alg and lifetime rather than claims — none of
// them may be rejected.
func TestMinimalProfile_ValidateSpec_AcceptsNonClaimKeys(t *testing.T) {
	assert.NoError(t, MinimalProfile{}.ValidateSpec(credential.NewConfig(map[string]string{
		credential.ConfigAssertionUserClaims:     "sub,email",
		credential.ConfigAssertionMetadataClaims: "team,env",
		credential.ConfigAssertionAudience:       "api://AzureADTokenExchange",
		credential.ConfigAssertionAlgorithm:      "RS256",
		credential.ConfigAssertionTTL:            "5m",
	})))
}

// Usable with every source type: the profile is registered and resolves, and the
// source-pin check has nothing to refuse.
func TestMinimalProfile_WorksWithEverySourceType(t *testing.T) {
	reg := credential.NewAssertionProfileRegistry()
	require.NoError(t, RegisterBuiltinProfiles(reg))

	cfg := credential.NewConfig(map[string]string{credential.ConfigAssertionProfile: MinimalProfileName})
	for _, src := range []string{
		credential.SourceTypeAzure, credential.SourceTypeAWS, credential.SourceTypeGCP,
		credential.SourceTypeVault, credential.SourceTypeKubernetes,
	} {
		assert.NoError(t, credential.ValidateAssertionProfileConfig(reg, cfg, src), src)
	}
}
