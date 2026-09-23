package profiles

import (
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultProfile_Metadata(t *testing.T) {
	p := Default()
	assert.Equal(t, "default", p.Name())
	assert.Equal(t, credential.DefaultAssertionProfileName, p.Name())
	assert.Equal(t, "JWT", p.Typ())
	// It renders all five assertion_* keys, so it rejects no spec.
	assert.NoError(t, p.ValidateSpec(credential.NewConfig(map[string]string{
		credential.ConfigAssertionAudience:       "sts.amazonaws.com",
		credential.ConfigAssertionAlgorithm:      "RS256",
		credential.ConfigAssertionResource:       "aws-iam:arn:aws:iam::1:role/R",
		credential.ConfigAssertionMetadataClaims: "team,env",
		credential.ConfigAssertionUserClaims:     "sub",
	})))
}

// fixedRequest is a fully-populated request with fixed times, so the expected
// claim maps below can be written by hand.
func fixedRequest() credential.AssertionRequest {
	iat := time.Unix(1755248400, 0)
	return credential.AssertionRequest{
		Issuer: "https://warden.example.com",
		Identity: credential.AssertionIdentity{
			PrincipalID:   "agent-checkout-7",
			RoleName:      "orders-reader",
			NamespaceID:   "ns-3f2a1b",
			NamespacePath: "team-payments/",
			MountAccessor: "auth_jwt_9c1e",
		},
		Audience:   "sts.amazonaws.com",
		IssuedAt:   iat,
		NotBefore:  iat.Add(-30 * time.Second),
		ExpiresAt:  iat.Add(5 * time.Minute),
		JTI:        "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		Metadata:   map[string]string{"team": "payments", "env": "prod"},
		Resource:   "aws-iam:arn:aws:iam::123456789012:role/OrdersReader",
		UserClaims: map[string]string{"sub": "alice@example.com", "username": "alice"},
	}
}

func TestDefaultProfile_Claims_FullyPopulated(t *testing.T) {
	req := fixedRequest()

	claims, err := Default().Claims(req)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss":               "https://warden.example.com",
		"sub":               "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
		"aud":               "sts.amazonaws.com",
		"iat":               int64(1755248400),
		"nbf":               int64(1755248370),
		"exp":               int64(1755248700),
		"jti":               "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		"warden_sub":        "agent-checkout-7",
		"warden_role":       "orders-reader",
		"warden_namespace":  "team-payments/",
		"warden_auth_mount": "auth_jwt_9c1e",
		"warden_metadata":   map[string]string{"team": "payments", "env": "prod"},
		"warden_user":       map[string]string{"sub": "alice@example.com", "username": "alice"},
		"warden_resource":   "aws-iam:arn:aws:iam::123456789012:role/OrdersReader",
	}, claims)
}

func TestDefaultProfile_Claims_Minimal(t *testing.T) {
	req := fixedRequest()
	// The three conditional claims opt out. An absent warden_metadata is NOT the
	// same as an empty one: emitting the empty forms would change the assertion
	// bytes for every spec that does not opt in.
	req.Metadata = nil
	req.UserClaims = nil
	req.Resource = ""

	claims, err := Default().Claims(req)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss":               "https://warden.example.com",
		"sub":               "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
		"aud":               "sts.amazonaws.com",
		"iat":               int64(1755248400),
		"nbf":               int64(1755248370),
		"exp":               int64(1755248700),
		"jti":               "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		"warden_sub":        "agent-checkout-7",
		"warden_role":       "orders-reader",
		"warden_namespace":  "team-payments/",
		"warden_auth_mount": "auth_jwt_9c1e",
	}, claims)

	// An EMPTY (non-nil) metadata/user map must also be treated as opt-out, since
	// the guard is len()>0, not != nil.
	req.Metadata = map[string]string{}
	req.UserClaims = map[string]string{}
	claims, err = Default().Claims(req)
	require.NoError(t, err)
	assert.NotContains(t, claims, "warden_metadata")
	assert.NotContains(t, claims, "warden_user")
}

// TestDefaultProfile_Claims_RoleLess pins what default does for a role-less
// identity, which is LIVE behavior and not a hypothetical: a root token is not
// issued by an auth method and carries no role, and the access path mints for
// whatever token it is handed — which is why cacheIdentity guards `RoleName != ""`.
//
// default emits the empty warden_role rather than erroring or omitting the claim.
// Pinning it here keeps each profile's role-less behavior a deliberate, reviewed
// choice rather than an accident: aws, for one, omits its warden_role tag instead
// (see TestAWSProfile_Claims_RoleLessAndSparseMetadata).
func TestDefaultProfile_Claims_RoleLess(t *testing.T) {
	req := fixedRequest()
	req.Identity.RoleName = ""

	claims, err := Default().Claims(req)
	require.NoError(t, err)

	require.Contains(t, claims, "warden_role")
	assert.Equal(t, "", claims["warden_role"])
	// The composite subject does not carry the role, so it is unchanged.
	assert.Equal(t, "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7", claims["sub"])
}

// TestDefaultProfile_Claims_Pure pins the purity contract the issuer relies on:
// Claims can run concurrently for one spec (the chained path's fetchUncached branch
// mints per request with no coalescing), so a shared map or a mutated input would be
// a data race, not a style problem.
func TestDefaultProfile_Claims_Pure(t *testing.T) {
	req := fixedRequest()

	first, err := Default().Claims(req)
	require.NoError(t, err)
	second, err := Default().Claims(req)
	require.NoError(t, err)

	// A fresh map per call. Writing into one must not show up in the other —
	// comparing &first to &second would be vacuous, since those are the addresses of
	// two distinct locals whatever the maps behind them are.
	first["injected"] = "should not leak"
	assert.NotContains(t, second, "injected", "Claims returned a shared map")

	// The inputs are untouched.
	assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata)
	assert.Equal(t, map[string]string{"sub": "alice@example.com", "username": "alice"}, req.UserClaims)
}

// TestDefaultProfile_Claims_Concurrent actually exercises the concurrency the
// purity contract exists for, so `go test -race` has something to catch.
//
// Claims runs from both mint-closure invokers — the manager's singleflight leader on
// a primary miss, and fetchChainedSecret on the chained path — and the chained path
// has five fetchUncached branches that mint per request with NO coalescing. So two
// goroutines really can be inside Claims for one spec at once, sharing the Metadata
// and UserClaims maps.
func TestDefaultProfile_Claims_Concurrent(t *testing.T) {
	req := fixedRequest()
	p := Default()

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
		assert.Equal(t, results[0], results[i], "concurrent Claims calls disagreed")
	}

	// The shared inputs are unchanged after 32 concurrent renders.
	assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata)
	assert.Equal(t, map[string]string{"sub": "alice@example.com", "username": "alice"}, req.UserClaims)
}

func TestAssertionIdentity_WardenSubject(t *testing.T) {
	// The principal stays trailing precisely so a delimiter-bearing one (a SPIFFE
	// ID) cannot make the value ambiguous.
	id := credential.AssertionIdentity{
		PrincipalID:   "spiffe://acme.internal/agent/refund-bot",
		NamespaceID:   "ns-1234",
		MountAccessor: "auth_jwt_abc",
	}
	assert.Equal(t, "wid:ns-1234:auth_jwt_abc:spiffe://acme.internal/agent/refund-bot", id.WardenSubject())
}
