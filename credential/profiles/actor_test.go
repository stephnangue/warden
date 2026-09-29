package profiles

import (
	"errors"
	"sync"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// actorRequest is fixedRequest with the user principal disclosed: alice, whose token
// the agent presented and a DIFFERENT auth mount than the agent's validated — in a
// CHILD of the agent's namespace, the case where a parent-namespace agent acts in a
// child. The two namespaces differ so the exact-set test catches one qualifying the
// other's id; the user's mount is populated so it would catch that leaking too.
func actorRequest() credential.AssertionRequest {
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

func TestActorProfile_Metadata(t *testing.T) {
	p := ActorProfile{}
	assert.Equal(t, "actor", p.Name())
	assert.Equal(t, "JWT", p.Typ())
	_, pinned := any(p).(credential.AssertionProfileSourcePinned)
	assert.False(t, pinned, "actor must not be source-pinned")
	_, checks := any(p).(credential.AssertionProfileIdentityChecker)
	assert.True(t, checks, "actor must refuse identities before the cache lookup")
}

// TestActorProfile_Claims_ExactSet pins the exact frozen shape with no prior actors:
// both principals by their raw ids, each paired with its OWN namespace path (the
// user's at the top level, the agent's in act), each with its own role, the agent's
// metadata in act and the user's claims without sub as the top-level
// warden_metadata, no auth mount anywhere, and Warden's iss in act.
func TestActorProfile_Claims_ExactSet(t *testing.T) {
	claims, err := ActorProfile{}.Claims(actorRequest())
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"iss": "https://warden.example.com",
		"sub": "alice@example.com",
		"aud": "https://orders.internal.example.com",
		"iat": int64(1755248400),
		"nbf": int64(1755248370),
		"exp": int64(1755248700),
		"jti": "a3d9f0c2-8b41-4e77-9f2a-1c6b5e0d4a88",
		"act": map[string]any{
			"sub":              "agent-checkout-7",
			"iss":              "https://warden.example.com",
			"warden_namespace": "team-payments/",
			"warden_role":      "orders-reader",
			"warden_metadata":  map[string]string{"team": "payments", "env": "prod"},
		},
		"warden_namespace": "team-payments/orders/",
		"warden_role":      "users",
		"warden_metadata":  map[string]string{"username": "alice"},
		"warden_resource":  "aws-iam:arn:aws:iam::123456789012:role/OrdersReader",
	}, claims)
}

// The user token's own act chain nests under the agent as prior actors, outermost
// first, each layer re-emitted as attested: iss only where the inbound layer had one.
func TestActorProfile_Claims_NestsUserChain(t *testing.T) {
	req := actorRequest()
	req.User.Actors = []credential.AssertionActor{
		{Subject: "broker-beta", Issuer: "https://idp.example.com"},
		{Subject: "agents/alpha"},
	}

	claims, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"sub":              "agent-checkout-7",
		"iss":              "https://warden.example.com",
		"warden_namespace": "team-payments/",
		"warden_role":      "orders-reader",
		"warden_metadata":  map[string]string{"team": "payments", "env": "prod"},
		"act": map[string]any{
			"sub": "broker-beta",
			"iss": "https://idp.example.com",
			"act": map[string]any{
				"sub": "agents/alpha",
			},
		},
	}, claims["act"])
}

// The deepest chain kept when a token is authenticated (4 layers) renders 5 act
// objects, in order.
func TestActorProfile_Claims_MaxDepth(t *testing.T) {
	req := actorRequest()
	req.User.Actors = []credential.AssertionActor{
		{Subject: "l1"}, {Subject: "l2"}, {Subject: "l3"}, {Subject: "l4"},
	}

	claims, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)

	var subs []string
	layer, _ := claims["act"].(map[string]any)
	for layer != nil {
		subs = append(subs, layer["sub"].(string))
		layer, _ = layer["act"].(map[string]any)
	}
	assert.Equal(t, []string{"agent-checkout-7", "l1", "l2", "l3", "l4"}, subs)
}

// sub moves to the top level, so listing only sub leaves no user metadata;
// the claim is omitted rather than emitted empty. Metadata and resource stay opt-in.
func TestActorProfile_Claims_OptInClaimsAbsent(t *testing.T) {
	req := actorRequest()
	req.UserClaims = map[string]string{"sub": "alice@example.com"}
	req.Metadata = nil
	req.Resource = ""

	claims, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)
	assert.NotContains(t, claims, "warden_user")
	assert.NotContains(t, claims, "warden_metadata")
	assert.NotContains(t, claims["act"], "warden_metadata", "absent, not emitted empty")
	assert.NotContains(t, claims, "warden_resource")
	assert.NotContains(t, claims, "warden_sub")
	assert.NotContains(t, claims, "warden_auth_mount")
}

// The root namespace's path is the empty string. It is still rendered — a value a
// verifier binds — never dropped as if the claim were absent: a verifier that read
// a missing claim as "any namespace" would fail open.
func TestActorProfile_Claims_RootNamespaceIsRendered(t *testing.T) {
	req := actorRequest()
	req.Identity.NamespacePath = ""
	req.User.NamespacePath = ""

	claims, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)
	require.Contains(t, claims, "warden_namespace")
	assert.Equal(t, "", claims["warden_namespace"])
	act := claims["act"].(map[string]any)
	require.Contains(t, act, "warden_namespace")
	assert.Equal(t, "", act["warden_namespace"])
}

// A role-less agent (a root token) renders an empty act.warden_role, as default
// does — and the top-level warden_role stays the USER's, never the agent's.
func TestActorProfile_Claims_RoleLessAgent(t *testing.T) {
	req := actorRequest()
	req.Identity.RoleName = ""

	claims, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)
	act := claims["act"].(map[string]any)
	require.Contains(t, act, "warden_role")
	assert.Equal(t, "", act["warden_role"])
	assert.Equal(t, "users", claims["warden_role"])
}

// Claims re-runs the identity checks, so a caller that skipped the setup-time
// check still cannot mint a refused shape.
func TestActorProfile_Claims_RefusesLikeCheckIdentities(t *testing.T) {
	noUser := actorRequest()
	noUser.User = nil
	_, err := ActorProfile{}.Claims(noUser)
	assert.ErrorIs(t, err, credential.ErrUserRequired)

	actedAgent := actorRequest()
	actedAgent.Identity.Actors = []credential.AssertionActor{{Subject: "broker-x"}}
	_, err = ActorProfile{}.Claims(actedAgent)
	assert.ErrorIs(t, err, errAgentActChain)
}

func TestActorProfile_CheckIdentities(t *testing.T) {
	req := actorRequest()
	p := ActorProfile{}

	assert.NoError(t, p.CheckIdentities(req.Identity, req.User))

	// The user's own chain is fine: it renders as prior actors.
	user := *req.User
	user.Actors = []credential.AssertionActor{{Subject: "broker-beta"}}
	assert.NoError(t, p.CheckIdentities(req.Identity, &user))

	err := p.CheckIdentities(req.Identity, nil)
	assert.True(t, errors.Is(err, credential.ErrUserRequired), "got %v", err)

	agent := req.Identity
	agent.Actors = []credential.AssertionActor{{Subject: "broker-x"}}
	assert.ErrorIs(t, p.CheckIdentities(agent, req.User), errAgentActChain)
}

func TestActorProfile_Claims_Pure(t *testing.T) {
	req := actorRequest()
	req.User.Actors = []credential.AssertionActor{
		{Subject: "broker-beta", Issuer: "https://idp.example.com"},
	}

	first, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)
	second, err := ActorProfile{}.Claims(req)
	require.NoError(t, err)

	// Mutating every returned map, nested act layers included, must not reach a
	// later call.
	first["injected"] = "x"
	firstAct := first["act"].(map[string]any)
	firstAct["sub"] = "tampered"
	firstAct["act"].(map[string]any)["sub"] = "tampered"
	first["warden_metadata"].(map[string]string)["username"] = "tampered"

	assert.NotContains(t, second, "injected")
	assert.Equal(t, "agent-checkout-7", second["act"].(map[string]any)["sub"])
	assert.Equal(t, "broker-beta", second["act"].(map[string]any)["act"].(map[string]any)["sub"])

	// Inputs are untouched: sub is stripped from a COPY of the user claims.
	assert.Equal(t, map[string]string{"sub": "alice@example.com", "username": "alice"}, req.UserClaims)
	assert.Equal(t, map[string]string{"team": "payments", "env": "prod"}, req.Metadata)
	assert.Equal(t, []credential.AssertionActor{{Subject: "broker-beta", Issuer: "https://idp.example.com"}}, req.User.Actors)
}

func TestActorProfile_Claims_Concurrent(t *testing.T) {
	req := actorRequest()
	req.User.Actors = []credential.AssertionActor{{Subject: "broker-beta"}}
	p := ActorProfile{}

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

func TestActorProfile_ValidateSpec(t *testing.T) {
	cfg := func(kv map[string]string) credential.Config { return credential.NewConfig(kv) }
	valid := map[string]string{
		credential.ConfigSubjectTokenSource:  credential.SourceWardenIdentity,
		credential.ConfigAssertionUserClaims: "sub",
	}
	assert.NoError(t, ActorProfile{}.ValidateSpec(cfg(valid)))

	// Metadata, resource and the non-claim keys all stay accepted.
	assert.NoError(t, ActorProfile{}.ValidateSpec(cfg(map[string]string{
		credential.ConfigSubjectTokenSource:      credential.SourceWardenIdentity,
		credential.ConfigActorTokenSource:        credential.SourceNone,
		credential.ConfigAssertionUserClaims:     "sub,username",
		credential.ConfigAssertionMetadataClaims: "team",
		credential.ConfigAssertionResource:       "orders",
		credential.ConfigAssertionAudience:       "https://orders.internal.example.com",
	})))

	for name, kv := range map[string]map[string]string{
		"actor slot (two-token shape)": {
			credential.ConfigSubjectTokenSource:  credential.SourceUserIdentity,
			credential.ConfigActorTokenSource:    credential.SourceWardenIdentity,
			credential.ConfigAssertionUserClaims: "sub",
		},
		"subject not warden_identity": {
			credential.ConfigSubjectTokenSource:  credential.SourceAgentIdentity,
			credential.ConfigAssertionUserClaims: "sub",
		},
	} {
		err := ActorProfile{}.ValidateSpec(cfg(kv))
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "mints the subject token", name)
		assert.Contains(t, err.Error(), credential.ConfigActorTokenSource, name)
	}

	err := ActorProfile{}.ValidateSpec(cfg(map[string]string{
		credential.ConfigSubjectTokenSource: credential.SourceWardenIdentity,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigAssertionUserClaims)
}

// The profiles that predate User and Actors must render byte-identical claims
// whether or not they are set: a frozen shape cannot start reading a new input.
func TestExistingProfiles_IgnoreUserIdentity(t *testing.T) {
	for _, p := range []credential.AssertionProfile{Default(), &MinimalProfile{}, &AWSProfile{}} {
		base := fixedRequest()
		before, err := p.Claims(base)
		require.NoError(t, err, p.Name())

		withUser := actorRequest()
		withUser.Audience = base.Audience
		withUser.Identity.Actors = []credential.AssertionActor{{Subject: "broker-x"}}
		withUser.User.Actors = []credential.AssertionActor{{Subject: "broker-beta"}}
		after, err := p.Claims(withUser)
		require.NoError(t, err, p.Name())

		assert.Equal(t, before, after, p.Name())
	}
}
