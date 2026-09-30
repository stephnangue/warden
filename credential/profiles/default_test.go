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
	_, pinned := p.(credential.AssertionProfileSourcePinned)
	assert.False(t, pinned, "default must not be source-pinned")
	_, checks := p.(credential.AssertionProfileIdentityChecker)
	assert.True(t, checks, "default must refuse a misstated delegation before the cache lookup")
	// It renders every assertion_* key, and the subject is decided per request, so
	// it rejects no spec — including one filling the actor slot of an exchange.
	assert.NoError(t, p.ValidateSpec(credential.NewConfig(map[string]string{
		credential.ConfigAssertionAudience:       "sts.amazonaws.com",
		credential.ConfigAssertionAlgorithm:      "RS256",
		credential.ConfigAssertionResource:       "aws-iam:arn:aws:iam::1:role/R",
		credential.ConfigAssertionMetadataClaims: "team,env",
		credential.ConfigAssertionUserClaims:     "sub",
	})))
	assert.NoError(t, p.ValidateSpec(credential.NewConfig(map[string]string{
		credential.ConfigSubjectTokenSource:  credential.SourceUserIdentity,
		credential.ConfigActorTokenSource:    credential.SourceWardenIdentity,
		credential.ConfigAssertionUserClaims: "sub",
	})))
}

// fixedRequest is a fully-populated request with fixed times and NO user disclosed,
// so the expected claim maps below can be written by hand. The user's claims are
// set, as the core sets them for templating even when it withholds the user.
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

// delegationRequest is fixedRequest with the user DISCLOSED: alice, whose token the
// agent presented and a different auth mount validated, in a CHILD of the agent's
// namespace — so a test catches the user's namespace or mount leaking, or the two
// levels' claims being swapped.
func delegationRequest() credential.AssertionRequest {
	req := fixedRequest()
	req.Audience = "https://orders.internal.example.com"
	req.User = &credential.AssertionIdentity{
		PrincipalID:   "alice@example.com",
		RoleName:      "users",
		NamespaceID:   "ns-77c0d4",
		NamespacePath: "team-payments/orders/",
		MountAccessor: "auth_oidc_77aa",
	}
	return req
}

// TestDefaultProfile_Claims_AgentOnly pins the no-user shape: the agent at the top
// level by its composite sub — byte-identical to the sub the earlier default shape
// emitted, so existing agent trusts keep matching — with its role and metadata, no
// warden_namespace (the composite carries it) and no act. The user's claims are set
// on the request but NOT rendered: without req.User the user is withheld.
func TestDefaultProfile_Claims_AgentOnly(t *testing.T) {
	claims, err := Default().Claims(fixedRequest())
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss":             "https://warden.example.com",
		"sub":             "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
		"aud":             "sts.amazonaws.com",
		"iat":             int64(1755248400),
		"nbf":             int64(1755248370),
		"exp":             int64(1755248700),
		"jti":             "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		"warden_role":     "orders-reader",
		"warden_metadata": map[string]string{"team": "payments", "env": "prod"},
		"warden_resource": "aws-iam:arn:aws:iam::123456789012:role/OrdersReader",
	}, claims)
}

// TestDefaultProfile_Claims_Delegation pins the user-disclosed shape: the user at
// the top level by raw id, qualified by ITS namespace, with its role and its claims
// minus sub as warden_metadata; the agent in act by composite sub, with its own role
// and metadata and Warden's iss. No auth mount appears, and the agent level has no
// warden_namespace.
func TestDefaultProfile_Claims_Delegation(t *testing.T) {
	claims, err := Default().Claims(delegationRequest())
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss":              "https://warden.example.com",
		"sub":              "alice@example.com",
		"warden_namespace": "team-payments/orders/",
		"warden_role":      "users",
		"warden_metadata":  map[string]string{"username": "alice"},
		"aud":              "https://orders.internal.example.com",
		"iat":              int64(1755248400),
		"nbf":              int64(1755248370),
		"exp":              int64(1755248700),
		"jti":              "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		"act": map[string]any{
			"sub":             "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7",
			"iss":             "https://warden.example.com",
			"warden_role":     "orders-reader",
			"warden_metadata": map[string]string{"team": "payments", "env": "prod"},
		},
		"warden_resource": "aws-iam:arn:aws:iam::123456789012:role/OrdersReader",
	}, claims)
}

// The user token's own act chain nests under the agent as prior actors, outermost
// first, each layer re-emitted as attested: iss only where the inbound layer had
// one, and no Warden claims.
func TestDefaultProfile_Claims_NestsUserChain(t *testing.T) {
	req := delegationRequest()
	req.User.Actors = []credential.AssertionActor{
		{Subject: "broker-beta", Issuer: "https://idp.example.com"},
		{Subject: "agents/alpha"},
	}

	claims, err := Default().Claims(req)
	require.NoError(t, err)

	act := claims["act"].(map[string]any)
	assert.Equal(t, map[string]any{
		"sub": "broker-beta",
		"iss": "https://idp.example.com",
		"act": map[string]any{"sub": "agents/alpha"},
	}, act["act"])
}

// The deepest chain kept when a token is authenticated (4 layers) renders 5 act
// objects, in order.
func TestDefaultProfile_Claims_MaxDepth(t *testing.T) {
	req := delegationRequest()
	req.User.Actors = []credential.AssertionActor{
		{Subject: "l1"}, {Subject: "l2"}, {Subject: "l3"}, {Subject: "l4"},
	}

	claims, err := Default().Claims(req)
	require.NoError(t, err)

	var subs []string
	layer, _ := claims["act"].(map[string]any)
	for layer != nil {
		subs = append(subs, layer["sub"].(string))
		layer, _ = layer["act"].(map[string]any)
	}
	assert.Equal(t, []string{"wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7", "l1", "l2", "l3", "l4"}, subs)
}

// The opt-in claims stay opt-in at both levels: absent, never emitted empty. Listing
// only sub leaves no user metadata. An EMPTY (non-nil) map is opt-out too, since the
// guard is len()>0, not != nil.
func TestDefaultProfile_Claims_OptInClaimsAbsent(t *testing.T) {
	agentOnly := fixedRequest()
	agentOnly.Metadata = map[string]string{}
	agentOnly.Resource = ""
	claims, err := Default().Claims(agentOnly)
	require.NoError(t, err)
	assert.NotContains(t, claims, "warden_metadata")
	assert.NotContains(t, claims, "warden_resource")

	delegated := delegationRequest()
	delegated.Metadata = nil
	delegated.UserClaims = map[string]string{"sub": "alice@example.com"}
	claims, err = Default().Claims(delegated)
	require.NoError(t, err)
	assert.NotContains(t, claims, "warden_metadata")
	assert.NotContains(t, claims["act"], "warden_metadata")

	// Nothing the earlier default shape emitted beside them survives.
	for _, gone := range []string{"warden_sub", "warden_auth_mount", "warden_user"} {
		assert.NotContains(t, claims, gone)
		assert.NotContains(t, claims["act"], gone)
	}
	assert.NotContains(t, claims["act"], "warden_namespace", "the agent's composite carries its namespace")
}

// The root namespace's path is the empty string; the user's warden_namespace renders
// it "root" — a value a verifier binds — never "" or an absent claim.
func TestDefaultProfile_Claims_RootNamespace(t *testing.T) {
	req := delegationRequest()
	req.User.NamespacePath = ""

	claims, err := Default().Claims(req)
	require.NoError(t, err)
	assert.Equal(t, credential.RootNamespaceClaim, claims["warden_namespace"])
	assert.Equal(t, "root", claims["warden_namespace"])
}

// TestDefaultProfile_Claims_RoleLess pins what default does for a role-less agent,
// which is LIVE behavior and not a hypothetical: a root token is not issued by an
// auth method and carries no role, and the access path mints for whatever token it
// is handed — which is why cacheIdentity guards `RoleName != ""`. default emits the
// empty warden_role at the agent's level rather than erroring or omitting it; aws,
// for one, omits its warden_role tag instead (see
// TestAWSProfile_Claims_RoleLessAndSparseMetadata).
func TestDefaultProfile_Claims_RoleLess(t *testing.T) {
	agentOnly := fixedRequest()
	agentOnly.Identity.RoleName = ""
	claims, err := Default().Claims(agentOnly)
	require.NoError(t, err)
	require.Contains(t, claims, "warden_role")
	assert.Equal(t, "", claims["warden_role"])
	assert.Equal(t, "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7", claims["sub"])

	// In a delegation the empty role is the agent's, in act; the top-level role
	// stays the user's.
	delegated := delegationRequest()
	delegated.Identity.RoleName = ""
	claims, err = Default().Claims(delegated)
	require.NoError(t, err)
	act := claims["act"].(map[string]any)
	require.Contains(t, act, "warden_role")
	assert.Equal(t, "", act["warden_role"])
	assert.Equal(t, "users", claims["warden_role"])
}

// An agent whose own token carries act is refused only when a user is disclosed —
// then act.sub = agent would misstate the current actor. With no user nothing is
// asserted about delegation, so it mints the agent shape and renders no act.
func TestDefaultProfile_AgentActChain(t *testing.T) {
	chain := []credential.AssertionActor{{Subject: "orchestrator"}}
	p := DefaultProfile{}

	delegated := delegationRequest()
	delegated.Identity.Actors = chain
	assert.ErrorIs(t, p.CheckIdentities(delegated.Identity, delegated.User), errAgentActChain)
	_, err := p.Claims(delegated)
	assert.ErrorIs(t, err, errAgentActChain, "Claims re-runs the check")

	agentOnly := fixedRequest()
	agentOnly.Identity.Actors = chain
	assert.NoError(t, p.CheckIdentities(agentOnly.Identity, nil))
	claims, err := p.Claims(agentOnly)
	require.NoError(t, err)
	assert.NotContains(t, claims, "act")

	// A user token's own chain is fine: it renders as prior actors.
	user := *delegationRequest().User
	user.Actors = chain
	assert.NoError(t, p.CheckIdentities(delegationRequest().Identity, &user))
}

// TestDefaultProfile_Claims_Pure pins the purity contract the issuer relies on:
// Claims can run concurrently for one spec (the chained path's fetchUncached branch
// mints per request with no coalescing), so a shared map or a mutated input would be
// a data race, not a style problem.
func TestDefaultProfile_Claims_Pure(t *testing.T) {
	req := delegationRequest()
	req.User.Actors = []credential.AssertionActor{{Subject: "broker-beta", Issuer: "https://idp.example.com"}}

	first, err := Default().Claims(req)
	require.NoError(t, err)
	second, err := Default().Claims(req)
	require.NoError(t, err)

	// A fresh map per call, nested act layers and the user's metadata included.
	first["injected"] = "should not leak"
	firstAct := first["act"].(map[string]any)
	firstAct["sub"] = "tampered"
	firstAct["act"].(map[string]any)["sub"] = "tampered"
	first["warden_metadata"].(map[string]string)["username"] = "tampered"

	assert.NotContains(t, second, "injected", "Claims returned a shared map")
	assert.Equal(t, "wid:ns-3f2a1b:auth_jwt_9c1e:agent-checkout-7", second["act"].(map[string]any)["sub"])
	assert.Equal(t, "broker-beta", second["act"].(map[string]any)["act"].(map[string]any)["sub"])
	assert.Equal(t, map[string]string{"username": "alice"}, second["warden_metadata"])

	// The inputs are untouched: sub is stripped from a COPY of the user claims.
	assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata)
	assert.Equal(t, map[string]string{"sub": "alice@example.com", "username": "alice"}, req.UserClaims)
	assert.Equal(t, []credential.AssertionActor{{Subject: "broker-beta", Issuer: "https://idp.example.com"}}, req.User.Actors)
}

// TestDefaultProfile_Claims_Concurrent actually exercises the concurrency the
// purity contract exists for, so `go test -race` has something to catch.
//
// Claims runs from both mint-closure invokers — the manager's singleflight leader on
// a primary miss, and fetchChainedSecret on the chained path — and the chained path
// has five fetchUncached branches that mint per request with NO coalescing. So two
// goroutines really can be inside Claims for one spec at once, sharing the Metadata
// and UserClaims maps and the user's act chain.
func TestDefaultProfile_Claims_Concurrent(t *testing.T) {
	for name, req := range map[string]credential.AssertionRequest{
		"agent only": fixedRequest(),
		"delegation": delegationRequest(),
	} {
		t.Run(name, func(t *testing.T) {
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
			assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata)
			assert.Equal(t, map[string]string{"sub": "alice@example.com", "username": "alice"}, req.UserClaims)
		})
	}
}

// The profiles other than default never render the user: their claims are
// byte-identical whether or not the core discloses one, or either principal carries
// an act chain. A frozen shape cannot start reading a new input.
func TestNonDefaultProfiles_IgnoreUserIdentity(t *testing.T) {
	for _, p := range []credential.AssertionProfile{&MinimalProfile{}, &AWSProfile{}} {
		base := fixedRequest()
		before, err := p.Claims(base)
		require.NoError(t, err, p.Name())

		withUser := delegationRequest()
		withUser.Audience = base.Audience
		withUser.Identity.Actors = []credential.AssertionActor{{Subject: "broker-x"}}
		withUser.User.Actors = []credential.AssertionActor{{Subject: "broker-beta"}}
		after, err := p.Claims(withUser)
		require.NoError(t, err, p.Name())

		assert.Equal(t, before, after, p.Name())
	}
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

func TestNamespaceClaim(t *testing.T) {
	assert.Equal(t, "root", credential.NamespaceClaim(""))
	assert.Equal(t, "team-payments/", credential.NamespaceClaim("team-payments/"))
	// A child named "root" has the path "root/", so it never equals the root value.
	assert.NotEqual(t, credential.NamespaceClaim(""), credential.NamespaceClaim("root/"))
}
