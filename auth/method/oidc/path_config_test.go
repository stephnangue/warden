package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

func TestConfigWrite_Refusals(t *testing.T) {
	e := newEnv(t)
	_, keyPEM, certPEM := rsaKey(t)
	_, _, otherCert := rsaKey(t)
	cases := map[string]struct {
		over map[string]any
		want string
	}{
		"agent kind":           {map[string]any{"entity_kind": "agent"}, "admits people only"},
		"unknown alg":          {map[string]any{"supported_algs": []string{"HS256"}}, "not a supported signing algorithm"},
		"session too long":     {map[string]any{"session_ttl": "9h"}, "at most 8h"},
		"no redirect":          {map[string]any{"allowed_redirect_uris": nil}, "allowed_redirect_uris is required"},
		"bad redirect":         {map[string]any{"allowed_redirect_uris": []string{"/cb"}}, "absolute http(s) URL"},
		"no client id":         {map[string]any{"client_id": nil}, "client_id is required"},
		"no discovery url":     {map[string]any{"oidc_discovery_url": nil}, "oidc_discovery_url is required"},
		"no secret":            {map[string]any{"client_secret": nil}, "client_secret is required"},
		"key without key auth": {map[string]any{"private_key": keyPEM}, "set only when client_auth is private_key_jwt"},
		"key auth without key": {map[string]any{"client_auth": "private_key_jwt", "client_secret": nil}, "private_key is required"},
		"bad key":              {map[string]any{"client_auth": "private_key_jwt", "client_secret": nil, "private_key": "x"}, "private_key"},
		"certificate of another key": {map[string]any{"client_auth": "private_key_jwt", "client_secret": nil, "private_key": keyPEM,
			"client_certificate": otherCert}, "does not certify private_key"},
		"none with secret":      {map[string]any{"client_auth": "none"}, "neither"},
		"unknown client auth":   {map[string]any{"client_auth": "basic"}, "client_auth must be"},
		"no openid scope":       {map[string]any{"scopes": []string{"profile"}}, `must include "openid"`},
		"alias not published":   {map[string]any{"alias_name_source": "email"}, "alias_name_source"},
		"33 mapped facts":       {map[string]any{"facts": manyFacts(33)}, "at most 32"},
		"discovery unreachable": {map[string]any{"oidc_discovery_url": "https://127.0.0.1:1"}, "discovery"},
	}
	for name, tc := range cases {
		resp := e.configure(tc.over)
		require.Error(t, resp.Err, name)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
		assert.ErrorContains(t, resp.Err, tc.want, name)
	}

	e.mustConfigure(map[string]any{"facts": manyFacts(32), "alias_name_source": nil})
	e.mustConfigure(map[string]any{"facts": map[string]any{"sub": "sub", "oid": "oid"}})
	e.mustConfigure(map[string]any{"client_auth": "private_key_jwt", "client_secret": nil, "private_key": keyPEM,
		"client_certificate": certPEM})
}

// A discovery document whose issuer is not the URL it is served at is
// refused, as a multi-tenant authority's templated issuer is: no
// provider-specific check is needed.
func TestConfigWrite_IssuerMismatch(t *testing.T) {
	e := newEnv(t)
	client := e.tp.HTTPClient()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(e.tp.Addr() + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(proxy.Close)

	resp := e.configure(map[string]any{"oidc_discovery_url": proxy.URL, "oidc_discovery_ca_pem": nil})
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.ErrorContains(t, resp.Err, "issuer did not match")
}

func TestConfigRead_NoSecrets(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(nil)
	read, err := e.b.HandleRequest(e.ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config"})
	require.NoError(t, err)
	assert.Equal(t, []string{e.alg()}, read.Data["supported_algs"])
	assert.Equal(t, "1h0m0s", read.Data["session_ttl"])
	assert.Equal(t, "human", read.Data["entity_kind"])
	assert.Equal(t, "client_secret", read.Data["client_auth"])
	assert.Equal(t, []string{"openid", "profile"}, read.Data["scopes"])
	for _, k := range []string{"client_secret", "private_key"} {
		_, has := read.Data[k]
		assert.False(t, has, "%s is never read back", k)
	}
	b, _ := json.Marshal(read.Data)
	assert.NotContains(t, string(b), testSecret)
}

// A write merges onto the stored config: a secret not sent is kept, a change
// of client_auth drops the other method's credentials, 0 restores the
// session_ttl default, and an empty facts map clears the mapping.
func TestConfigWrite_Merge(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(map[string]any{"session_ttl": "2h"})

	resp := e.call(e.b, "config", map[string]any{"scopes": []string{"openid", "email"}})
	require.NoError(t, resp.Err)
	cfg, _ := e.liveConfig(e.b)
	assert.Equal(t, testSecret, cfg.ClientSecret, "a secret not sent is kept")
	assert.Equal(t, 2*time.Hour, cfg.SessionTTL)
	assert.Equal(t, []string{"openid", "email"}, cfg.Scopes)

	_, keyPEM, certPEM := rsaKey(t)
	resp = e.call(e.b, "config", map[string]any{"client_auth": "private_key_jwt", "private_key": keyPEM,
		"client_certificate": certPEM, "client_assertion_kid": "kid-1"})
	require.NoError(t, resp.Err)
	cfg, _ = e.liveConfig(e.b)
	assert.Empty(t, cfg.ClientSecret, "changing client_auth drops the client secret")
	assert.NotEmpty(t, cfg.x5tS256)

	resp = e.call(e.b, "config", map[string]any{"client_auth": "none"})
	require.NoError(t, resp.Err)
	cfg, _ = e.liveConfig(e.b)
	assert.Empty(t, cfg.PrivateKey)
	assert.Empty(t, cfg.ClientCertificate)
	assert.Equal(t, "kid-1", cfg.ClientAssertionKID, "an unrelated key is kept")

	resp = e.call(e.b, "config", map[string]any{"session_ttl": 0})
	require.NoError(t, resp.Err)
	cfg, _ = e.liveConfig(e.b)
	assert.Equal(t, time.Hour, cfg.SessionTTL, "0 restores the default")

	// Clearing the mapping leaves alias_name_source naming a fact that is
	// gone: refused, the stored config unchanged.
	resp = e.call(e.b, "config", map[string]any{"facts": map[string]any{}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.ErrorContains(t, resp.Err, "alias_name_source")
	resp = e.call(e.b, "config", map[string]any{"facts": map[string]any{}, "alias_name_source": ""})
	require.NoError(t, resp.Err)
	assert.Equal(t, "sub", e.b.mountFacts.Load().AliasSource)
}

func manyFacts(n int) map[string]any {
	f := make(map[string]any, n)
	for i := range n {
		f[fmt.Sprintf("c%d", i)] = fmt.Sprintf("f%d", i)
	}
	return f
}
