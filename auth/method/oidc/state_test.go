package oidc

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState_Refusals(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(nil)
	e.tp.SetCustomClaims(personClaims())

	seal := func(b *oidcAuthBackend, edit func(*pendingLogin)) (string, string) {
		state, proof := e.start(e.b)
		p, err := e.b.openState(e.ctx, state, time.Now())
		require.NoError(t, err)
		edit(p)
		s, err := b.sealState(e.ctx, p)
		require.NoError(t, err)
		return s, proof
	}
	refused := func(name, state, proof string, want error) {
		resp := e.finish(e.b, state, proof)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
		assert.ErrorIs(t, resp.Err, want, name)
	}

	s, proof := seal(e.b, func(p *pendingLogin) { p.ExpiresAt = time.Now().Add(-time.Second).Unix() })
	refused("expired", s, proof, errStateInvalid)
	s, proof = seal(e.b, func(p *pendingLogin) { p.NamespaceID = "ns_other" })
	refused("another namespace", s, proof, errStateInvalid)
	s, proof = seal(e.b, func(p *pendingLogin) { p.V = 2 })
	refused("another version", s, proof, errStateInvalid)
	s, proof = seal(e.b, func(p *pendingLogin) { p.Verifier = "" })
	refused("no verifier", s, proof, errStateInvalid)
	other := e.newBackend("auth_oidc_00000002")
	s, proof = seal(other, func(*pendingLogin) {})
	refused("sealed by another mount", s, proof, errStateInvalid)
	refused("garbage", "not-a-state", proof, errStateInvalid)
	refused("too long", strings.Repeat("A", maxStateLen+1), proof, errStateInvalid)

	state, proof := e.start(e.b)
	refused("no proof", state, "", errProofMismatch)
	_, wrong := secret()
	refused("wrong proof", state, wrong, errProofMismatch)
	refused("short proof", state, base64.RawURLEncoding.EncodeToString([]byte("short")), errProofMismatch)
	resp := e.finish(e.b, state, proof)
	require.NoError(t, resp.Err, "the right proof still completes the login")

	// A redirect URI dropped from the config after auth_url.
	state, proof = e.start(e.b)
	e.mustConfigure(map[string]any{"allowed_redirect_uris": []string{"https://warden.example/cb"}})
	refused("redirect no longer allowed", state, proof, errRedirectNotListed)
}

func TestState_RoundTrip(t *testing.T) {
	e := newEnv(t)
	binding, _ := secret()
	in := &pendingLogin{V: 1, Verifier: "v", Nonce: "n", RedirectURI: testRedirect, Binding: binding,
		NamespaceID: "root", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	s, err := e.b.sealState(e.ctx, in)
	require.NoError(t, err)
	out, err := e.b.openState(e.ctx, s, time.Now())
	require.NoError(t, err)
	assert.Equal(t, in, out)
	assert.NotContains(t, s, testRedirect, "the state is sealed, not encoded")
	_, err = e.b.openState(e.ctx, s, time.Now().Add(2*time.Minute))
	assert.ErrorIs(t, err, errStateInvalid, "expired at a later now")
}

func TestProofMatches(t *testing.T) {
	binding, proof := secret()
	assert.True(t, proofMatches(binding, proof))
	_, other := secret()
	assert.False(t, proofMatches(binding, other))
	assert.False(t, proofMatches(binding, ""))
	assert.False(t, proofMatches("", proof))
	assert.NoError(t, checkBinding(binding))
	assert.Error(t, checkBinding(proof[:10]))
	assert.Error(t, checkBinding(""))
}
