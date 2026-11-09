package playground

import (
	"context"
	"crypto"
	"encoding/pem"
	"testing"
	"time"

	capjwt "github.com/hashicorp/cap/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyWith checks token was signed by idp and returns its claims.
func verifyWith(t *testing.T, idp *IdP, token string, audience string) map[string]any {
	t.Helper()
	keys, err := capjwt.NewStaticKeySet([]crypto.PublicKey{idp.PublicKey()})
	require.NoError(t, err)
	v, err := capjwt.NewValidator(keys)
	require.NoError(t, err)
	claims, err := v.Validate(context.Background(), token, capjwt.Expected{
		Issuer: idp.Issuer(), Audiences: []string{audience}, SigningAlgorithms: []capjwt.Alg{capjwt.ES256},
	})
	require.NoError(t, err)
	return claims
}

func TestIdP_MintAgent(t *testing.T) {
	idp, err := NewIdP("https://localhost:8410/")
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:8410", idp.Issuer(), "a trailing slash is dropped")

	token, err := idp.Mint(Identity{Kind: KindAgent, Subject: "agent-1", Claims: map[string]any{"team": "ops"}})
	require.NoError(t, err)

	claims := verifyWith(t, idp, token, AudienceAgent)
	assert.Equal(t, "agent-1", claims["sub"])
	assert.Equal(t, "ops", claims["team"])
	assert.NotContains(t, claims, "may_act")
	for _, c := range []string{"iat", "nbf", "exp", "jti"} {
		assert.Contains(t, claims, c, "Warden's JWT auth refuses a token without %s", c)
	}
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	assert.WithinDuration(t, time.Now().Add(DefaultIdentityTTL), exp, 5*time.Second)
}

func TestIdP_MintUserWithMayAct(t *testing.T) {
	idp, err := NewIdP("https://localhost:8410")
	require.NoError(t, err)

	token, err := idp.Mint(Identity{Kind: KindUser, Subject: "alice", MayAct: "agent-1", TTL: 2 * time.Hour})
	require.NoError(t, err)

	claims := verifyWith(t, idp, token, AudienceUser)
	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, map[string]any{"sub": "agent-1"}, claims["may_act"])
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), exp, 5*time.Second)
}

func TestIdP_MintRefuses(t *testing.T) {
	idp, err := NewIdP("https://localhost:8410")
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      Identity
		wantErr string
	}{
		{"unknown kind", Identity{Kind: "robot", Subject: "x"}, "kind must be"},
		{"missing sub", Identity{Kind: KindAgent}, "sub is required"},
		{"may_act on an agent", Identity{Kind: KindAgent, Subject: "agent-1", MayAct: "agent-2"}, "applies to a user"},
		{"ttl too long", Identity{Kind: KindAgent, Subject: "a", TTL: 48 * time.Hour}, "ttl must be"},
		{"negative ttl", Identity{Kind: KindAgent, Subject: "a", TTL: -time.Minute}, "ttl must be"},
		{"overriding sub", Identity{Kind: KindAgent, Subject: "a", Claims: map[string]any{"sub": "root"}}, `claim "sub"`},
		{"overriding aud", Identity{Kind: KindAgent, Subject: "a", Claims: map[string]any{"aud": AudienceUser}}, `claim "aud"`},
		{"smuggling may_act", Identity{Kind: KindAgent, Subject: "a", Claims: map[string]any{"may_act": map[string]any{"sub": "x"}}}, `claim "may_act"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := idp.Mint(tt.id)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestIdP_JWKS(t *testing.T) {
	idp, err := NewIdP("https://localhost:8410")
	require.NoError(t, err)
	set := idp.JWKS()
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "ES256", set.Keys[0].Algorithm)
	assert.NotEmpty(t, set.Keys[0].KeyID)
	assert.True(t, set.Keys[0].IsPublic())
}

// certPEM encodes a DER certificate as PEM.
func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
