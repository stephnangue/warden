package profiles

import (
	"strings"
	"sync"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSProfile_Metadata(t *testing.T) {
	p := AWSProfile{}
	assert.Equal(t, "aws", p.Name())
	assert.Equal(t, "JWT", p.Typ())
	// Pinned to AWS sources: the shape is meaningful only to an AWS STS verifier.
	assert.Equal(t, []string{credential.SourceTypeAWS}, p.SourceTypes())
}

// TestAWSProfile_Claims_FullyPopulated pins the exact frozen shape: the composite sub
// (as default) and the role plus every projected metadata key as AWS session tags,
// in the nested https://aws.amazon.com/tags format. Nothing else.
func TestAWSProfile_Claims_FullyPopulated(t *testing.T) {
	claims, err := AWSProfile{}.Claims(fixedRequest())
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss": "https://warden.example.com",
		"sub": "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
		"aud": "sts.amazonaws.com",
		"iat": int64(1755248400),
		"nbf": int64(1755248370),
		"exp": int64(1755248700),
		"jti": "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		"https://aws.amazon.com/tags": map[string]any{
			"principal_tags": map[string][]string{
				"warden_role": {"orders-reader"},
				"team":        {"payments"},
				"env":         {"prod"},
			},
		},
	}, claims)
}

// Emit only what AWS can bind: every warden_* claim is dropped — warden_sub included
// (the principal is the trailing segment of sub), and warden_resource although the
// request carries one.
func TestAWSProfile_Claims_EmitsNoWardenClaims(t *testing.T) {
	req := fixedRequest()
	require.NotEmpty(t, req.Resource, "precondition: the request carries a resource")

	claims, err := AWSProfile{}.Claims(req)
	require.NoError(t, err)
	for claim := range claims {
		assert.False(t, strings.HasPrefix(claim, "warden_"), "aws must not emit %s", claim)
	}
}

// A role-less identity (a root token) gets no warden_role tag, and a configured
// metadata key the login lacks gets no tag. Neither is an error: sub is unchanged,
// and a trust policy conditioning on the missing tag fails closed at AWS.
func TestAWSProfile_Claims_RoleLessAndSparseMetadata(t *testing.T) {
	req := fixedRequest()
	req.Identity.RoleName = ""
	req.Metadata = map[string]string{"team": "payments"} // "env" absent at login

	claims, err := AWSProfile{}.Claims(req)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"principal_tags": map[string][]string{"team": {"payments"}},
	}, claims["https://aws.amazon.com/tags"])
	assert.Equal(t, "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7", claims["sub"])
}

// No role and no metadata: no tags claim at all, rather than an empty principal_tags
// object that would say nothing.
func TestAWSProfile_Claims_NoTagsNoClaim(t *testing.T) {
	req := fixedRequest()
	req.Identity.RoleName = ""
	req.Metadata = nil

	claims, err := AWSProfile{}.Claims(req)
	require.NoError(t, err)
	assert.NotContains(t, claims, "https://aws.amazon.com/tags")
}

// Metadata VALUES arrive per login, so they can only be checked at mint. A value AWS
// would refuse fails here, with a reason, instead of as an opaque STS rejection.
func TestAWSProfile_Claims_RejectsInvalidTagValues(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
	}{
		{"disallowed character", "prod;drop", `character ';' is not allowed`},
		{"template braces", "{{user.sub}}", `character '{' is not allowed`},
		{"too long", strings.Repeat("a", 257), "257 characters exceeds AWS's limit of 256"},
		{"reserved prefix", "aws:prod", `"aws:" prefix is reserved`},
		{"reserved prefix, any case", "AWS:prod", `"aws:" prefix is reserved`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := fixedRequest()
			req.Metadata = map[string]string{"env": tc.value}
			claims, err := AWSProfile{}.Claims(req)
			require.Error(t, err)
			assert.Nil(t, claims, "no claims may be returned alongside the error")
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// The boundaries AWS allows: 256 characters, the full symbol set, spaces,
	// non-ASCII letters, and an empty value.
	for _, ok := range []string{
		strings.Repeat("a", 256), "a_b.c:d/e=f+g-h@i", "two words", "prod-é", "",
	} {
		req := fixedRequest()
		req.Metadata = map[string]string{"env": ok}
		_, err := AWSProfile{}.Claims(req)
		assert.NoError(t, err, "value %q is a valid AWS tag value", ok)
	}
}

// AWS documents the web identity subject as at most 255 characters. A composite sub
// longer than that fails at mint, locally and with a reason.
func TestAWSProfile_Claims_SubjectLengthLimit(t *testing.T) {
	req := fixedRequest()
	prefix := len("wid:ns-3f2a1b:auth_jwt_9c1e:")

	req.Identity.PrincipalID = strings.Repeat("p", 255-prefix)
	_, err := AWSProfile{}.Claims(req)
	require.NoError(t, err, "exactly 255 characters is allowed")

	req.Identity.PrincipalID = strings.Repeat("p", 256-prefix)
	claims, err := AWSProfile{}.Claims(req)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "subject is 256 characters")
}

func TestAWSProfile_ValidateSpec_MetadataKeys(t *testing.T) {
	cfg := func(keys string) credential.Config {
		return credential.NewConfig(map[string]string{credential.ConfigAssertionMetadataClaims: keys})
	}

	// Valid tag keys, including the symbols AWS allows.
	for _, ok := range []string{"", "team,env", "cost-center", "org:unit", "a.b/c=d+e@f"} {
		assert.NoError(t, AWSProfile{}.ValidateSpec(cfg(ok)), "keys %q are valid", ok)
	}

	for _, tc := range []struct {
		name, keys, want string
	}{
		{"disallowed character", "team,env;x", `character ';' is not allowed`},
		{"too long", strings.Repeat("k", 129), "129 characters exceeds AWS's limit of 128"},
		{"reserved prefix", "aws:team", `"aws:" prefix is reserved`},
		{"case-insensitive duplicate", "Team,team", `"team" collides with "Team"`},
		{"collides with the role tag", "WARDEN_ROLE", `collides with "warden_role"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := AWSProfile{}.ValidateSpec(cfg(tc.keys))
			require.Error(t, err)
			assert.Contains(t, err.Error(), credential.ConfigAssertionMetadataClaims)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// 49 keys + the role tag = AWS's 50-tag maximum; one more is refused.
	many := func(n int) string {
		keys := make([]string, n)
		for i := range keys {
			keys[i] = "k" + strings.Repeat("x", i)
		}
		return strings.Join(keys, ",")
	}
	assert.NoError(t, AWSProfile{}.ValidateSpec(cfg(many(49))))
	err := AWSProfile{}.ValidateSpec(cfg(many(50)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most 50 tags")
}

// assertion_resource's sole effect is the warden_resource claim, which this profile
// never emits, so an explicit value is rejected. Unset (derive) and "none" are fine:
// neither asks for output the profile won't render.
func TestAWSProfile_ValidateSpec_Resource(t *testing.T) {
	res := func(v string) credential.Config {
		return credential.NewConfig(map[string]string{credential.ConfigAssertionResource: v})
	}

	assert.NoError(t, AWSProfile{}.ValidateSpec(credential.Config{}), "unset means derive, and is ignored")
	assert.NoError(t, AWSProfile{}.ValidateSpec(res(credential.AssertionResourceNone)))

	err := AWSProfile{}.ValidateSpec(res("aws-iam:arn:aws:iam::1:role/R"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigAssertionResource)
	assert.Contains(t, err.Error(), "never emits warden_resource")
}

// assertion_user_claims is never rejected: this profile does not render warden_user,
// but the key also drives {{user.*}} request templating on AWS specs.
func TestAWSProfile_ValidateSpec_AcceptsUserClaims(t *testing.T) {
	assert.NoError(t, AWSProfile{}.ValidateSpec(credential.NewConfig(map[string]string{
		credential.ConfigAssertionUserClaims: "sub,email",
	})))
}

// The purity contract, under real concurrency: Claims can run for one spec from
// several goroutines at once (the chained path's uncoalesced branches), sharing the
// Metadata map.
func TestAWSProfile_Claims_Concurrent(t *testing.T) {
	req := fixedRequest()
	p := AWSProfile{}

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
	assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata,
		"Claims must not mutate the shared metadata map")
}

func TestRegisterBuiltinProfiles_IncludesAWS(t *testing.T) {
	reg := credential.NewAssertionProfileRegistry()
	require.NoError(t, RegisterBuiltinProfiles(reg))
	assert.Equal(t, []string{"aws", "default"}, reg.ListProfiles())
}
