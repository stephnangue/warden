package core

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/profiles"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func profileTestTokenEntry() *logical.TokenEntry {
	return &logical.TokenEntry{
		PrincipalID:   "agent-checkout-7",
		RoleName:      "orders-reader",
		NamespaceID:   "ns-3f2a1b",
		NamespacePath: "team-payments/",
		MountAccessor: "auth_jwt_9c1e",
	}
}

func profileTestClaims(p credential.AssertionProfile) AssertionClaims {
	return AssertionClaims{
		Audience:   "sts.amazonaws.com",
		TTL:        5 * time.Minute,
		Alg:        oidcAlgRS256,
		Metadata:   map[string]string{"team": "payments"},
		Resource:   "aws-iam:arn:aws:iam::1:role/OrdersReader",
		UserClaims: map[string]string{"sub": "alice@example.com"},
		Profile:    p,
	}
}

// decodeAssertionHeader and decodeAssertionClaims are shared with
// request_handler_test.go.

// TestMintIdentityAssertion_NilProfileMatchesDefault pins that the issuer's nil
// fallback and the registered default profile mint identically — i.e. that "no
// profile" and "profile=default" cannot drift apart at the issuer.
//
// It is NOT the proof that this refactor preserved the old bytes: both sides run the
// new code, and nil resolves to profiles.Default(), so the comparison is circular
// for that purpose. The proof against the pre-refactor literal lives elsewhere:
//   - TestDefaultProfile_Claims_FullyPopulated / _Minimal in credential/profiles,
//     whose hand-written expected maps encode that literal (keys, int64 times,
//     the three conditionals), plus Typ()=="JWT" for the header; and
//   - the 22 pre-existing mint call sites (18 in oidc_issuer_test.go, 4 in
//     oidc_signing_backend_test.go) that pass no profile and still pass unmodified.
func TestMintIdentityAssertion_NilProfileMatchesDefault(t *testing.T) {
	iss := newReadyIssuer(t, "https://warden-oidc.example")
	te := profileTestTokenEntry()

	implicit, err := iss.MintIdentityAssertion(context.Background(), te, profileTestClaims(nil))
	require.NoError(t, err)
	explicit, err := iss.MintIdentityAssertion(context.Background(), te, profileTestClaims(profiles.Default()))
	require.NoError(t, err)

	assert.Equal(t, decodeAssertionHeader(t, implicit), decodeAssertionHeader(t, explicit),
		"a nil Profile must sign with the same header as the default profile")

	implicitClaims := decodeAssertionClaims(t, implicit)
	explicitClaims := decodeAssertionClaims(t, explicit)

	// jti is random and the time claims move between the two mints, so compare the
	// claim NAMES exactly and the stable values exactly.
	assert.ElementsMatch(t, mapKeys(implicitClaims), mapKeys(explicitClaims))
	for _, k := range []string{
		"iss", "sub", "aud", "warden_sub", "warden_role",
		"warden_namespace", "warden_auth_mount", "warden_metadata",
		"warden_user", "warden_resource",
	} {
		assert.Equal(t, implicitClaims[k], explicitClaims[k], "claim %q differs", k)
	}
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// brokenProfile lets each test bend exactly one part of the contract.
type brokenProfile struct {
	name    string
	typ     string
	claims  func(credential.AssertionRequest) map[string]any
	claimsE error
}

func (b brokenProfile) Name() string { return b.name }
func (b brokenProfile) Typ() string {
	if b.typ == "" {
		return "JWT"
	}
	if b.typ == "<empty>" {
		return ""
	}
	return b.typ
}
func (b brokenProfile) ValidateSpec(credential.Config) error { return nil }
func (b brokenProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	if b.claimsE != nil {
		return nil, b.claimsE
	}
	return b.claims(req), nil
}

// goodClaims is what a correct profile returns, for a test to then break one field of.
func goodClaims(req credential.AssertionRequest) map[string]any {
	return map[string]any{
		"iss": req.Issuer,
		"sub": req.Identity.WardenSubject(),
		"aud": req.Audience,
		"iat": req.IssuedAt.Unix(),
		"nbf": req.NotBefore.Unix(),
		"exp": req.ExpiresAt.Unix(),
		"jti": req.JTI,
	}
}

// TestMintIdentityAssertion_ProfileGuard is the fail-closed guard: a buggy profile
// must never get an assertion signed. Each case returns no token and names the real
// defect, so a contributor debugging a profile is not sent hunting.
func TestMintIdentityAssertion_ProfileGuard(t *testing.T) {
	tests := []struct {
		name    string
		profile credential.AssertionProfile
		wantErr string
	}{
		{
			name: "drops exp",
			profile: brokenProfile{name: "no_exp", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				delete(c, "exp")
				return c
			}},
			wantErr: `claim "exp" is missing`,
		},
		{
			name: "stretches exp",
			profile: brokenProfile{name: "long_exp", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["exp"] = req.ExpiresAt.Add(24 * time.Hour).Unix()
				return c
			}},
			wantErr: `claim "exp" must be`,
		},
		{
			// A profile emitting the right number in the wrong type must be told
			// that, not handed the misleading "exp mismatch" a bare interface
			// comparison would report.
			name: "emits exp as int not int64",
			profile: brokenProfile{name: "int_exp", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["exp"] = int(req.ExpiresAt.Unix())
				return c
			}},
			wantErr: `claim "exp" must be int64 Unix seconds, got int`,
		},
		{
			name: "wrong iss",
			profile: brokenProfile{name: "bad_iss", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["iss"] = "https://attacker.example"
				return c
			}},
			wantErr: `claim "iss" must be`,
		},
		{
			name: "drops sub",
			profile: brokenProfile{name: "no_sub", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				delete(c, "sub")
				return c
			}},
			wantErr: `claim "sub" is missing`,
		},
		{
			name: "empty sub",
			profile: brokenProfile{name: "blank_sub", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["sub"] = ""
				return c
			}},
			wantErr: `claim "sub" must not be empty`,
		},
		{
			name: "wrong aud",
			profile: brokenProfile{name: "bad_aud", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["aud"] = "https://elsewhere.example"
				return c
			}},
			wantErr: `claim "aud" must be`,
		},
		{
			name: "wrong jti",
			profile: brokenProfile{name: "bad_jti", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["jti"] = "attacker-chosen"
				return c
			}},
			wantErr: `claim "jti" must be`,
		},
		{
			name: "shifts nbf",
			profile: brokenProfile{name: "bad_nbf", claims: func(req credential.AssertionRequest) map[string]any {
				c := goodClaims(req)
				c["nbf"] = req.NotBefore.Add(-time.Hour).Unix()
				return c
			}},
			wantErr: `claim "nbf" must be`,
		},
		{
			name:    "empty typ",
			profile: brokenProfile{name: "no_typ", typ: "<empty>", claims: goodClaims},
			wantErr: "blank typ header",
		},
		{
			// Whitespace is blank: a typ of " " would sign `"typ":" "` into a header
			// a verifier may reject. The registry refuses it too, but Profile is an
			// exported field an unregistered profile can arrive through.
			name:    "whitespace-only typ",
			profile: brokenProfile{name: "space_typ", typ: "  ", claims: goodClaims},
			wantErr: "blank typ header",
		},
		{
			name:    "returns no claims",
			profile: brokenProfile{name: "nil_claims", claims: func(credential.AssertionRequest) map[string]any { return nil }},
			wantErr: "returned no claims",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iss := newReadyIssuer(t, "https://warden-oidc.example")
			token, err := iss.MintIdentityAssertion(context.Background(), profileTestTokenEntry(),
				profileTestClaims(tc.profile))

			require.Error(t, err, "a broken profile must not get an assertion signed")
			assert.Empty(t, token, "no token may be returned alongside the error")
			assert.Contains(t, err.Error(), tc.wantErr)
			// The profile is named, so the operator knows which one to fix.
			assert.Contains(t, err.Error(), tc.profile.Name())
		})
	}
}

// iat and nbf are OPTIONAL per RFC 7519, so a profile that omits them still mints.
func TestMintIdentityAssertion_ProfileMayOmitIatNbf(t *testing.T) {
	iss := newReadyIssuer(t, "https://warden-oidc.example")

	p := brokenProfile{name: "no_iat_nbf", claims: func(req credential.AssertionRequest) map[string]any {
		c := goodClaims(req)
		delete(c, "iat")
		delete(c, "nbf")
		return c
	}}

	token, err := iss.MintIdentityAssertion(context.Background(), profileTestTokenEntry(), profileTestClaims(p))
	require.NoError(t, err)

	claims := decodeAssertionClaims(t, token)
	assert.NotContains(t, claims, "iat")
	assert.NotContains(t, claims, "nbf")
	assert.Contains(t, claims, "exp", "exp stays mandatory")
}

// A profile's own error is surfaced, wrapped with its name, and mints nothing.
func TestMintIdentityAssertion_ProfileClaimsError(t *testing.T) {
	iss := newReadyIssuer(t, "https://warden-oidc.example")

	p := brokenProfile{name: "angry_shape", claimsE: assert.AnError}
	token, err := iss.MintIdentityAssertion(context.Background(), profileTestTokenEntry(), profileTestClaims(p))

	require.Error(t, err)
	assert.Empty(t, token)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Contains(t, err.Error(), "angry_shape")
}

// The profile controls typ, and it reaches the signed header.
func TestMintIdentityAssertion_ProfileControlsTyp(t *testing.T) {
	iss := newReadyIssuer(t, "https://warden-oidc.example")

	p := brokenProfile{name: "rfc9068_shape", typ: "at+jwt", claims: goodClaims}
	token, err := iss.MintIdentityAssertion(context.Background(), profileTestTokenEntry(), profileTestClaims(p))
	require.NoError(t, err)

	header := decodeAssertionHeader(t, token)
	assert.Equal(t, "at+jwt", header["typ"])
	// alg and kid stay the issuer's: a profile controls claims and typ, nothing else.
	assert.Equal(t, oidcAlgRS256, header["alg"])
	assert.NotEmpty(t, header["kid"])
}

// TestIdentityFromTokenEntry pins the projection that lets package credential stay
// free of a logical import.
func TestIdentityFromTokenEntry(t *testing.T) {
	te := profileTestTokenEntry()
	id := identityFromTokenEntry(te)

	assert.Equal(t, credential.AssertionIdentity{
		PrincipalID:   "agent-checkout-7",
		RoleName:      "orders-reader",
		NamespaceID:   "ns-3f2a1b",
		NamespacePath: "team-payments/",
		MountAccessor: "auth_jwt_9c1e",
	}, id)

	// wardenSubject is now a thin wrapper over the moved method; the two must agree,
	// because cacheIdentity uses the wrapper while the default profile uses the method.
	assert.Equal(t, id.WardenSubject(), wardenSubject(te))
}
