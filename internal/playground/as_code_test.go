package playground

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedirect = "http://127.0.0.1:8251/oidc/callback"

// codeFixture is an authorization server whose issuer is the URL it is served
// at, as an OpenID Connect client requires.
type codeFixture struct {
	srv *httptest.Server
	as  *AuthServer
}

func newCodeFixture(t *testing.T, people map[string]map[string]any) *codeFixture {
	t.Helper()
	var h atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	idp, err := NewIdP(srv.URL)
	require.NoError(t, err)
	as, err := NewAuthServer(AuthServerConfig{
		IdP:           idp,
		WardenIssuer:  "https://warden.test",
		WardenJWKSURL: "https://warden.test/jwks",
		Audiences:     []string{"bank"},
		People:        people,
	})
	require.NoError(t, err)
	h.Store(as.Handler())
	return &codeFixture{srv: srv, as: as}
}

// provider is an OpenID Connect client of the fixture, as the oidc auth
// method's.
func (f *codeFixture) provider(t *testing.T) *capoidc.Provider {
	t.Helper()
	cfg, err := capoidc.NewConfig(f.srv.URL, HumanClientID, "", []capoidc.Alg{capoidc.ES256},
		[]string{"http://127.0.0.1/oidc/callback"}, capoidc.WithScopes("profile"))
	require.NoError(t, err)
	p, err := capoidc.NewProvider(cfg)
	require.NoError(t, err)
	t.Cleanup(p.Done)
	return p
}

// authorize opens authURL as a browser would, without following the redirect,
// and returns its query.
func authorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8251", loc.Host)
	return loc.Query()
}

func TestCodeFlow_SignsInWithCap(t *testing.T) {
	f := newCodeFixture(t, nil)
	p := f.provider(t)
	ctx := context.Background()
	v, err := capoidc.NewCodeVerifier()
	require.NoError(t, err)
	req, err := capoidc.NewRequest(time.Minute, testRedirect, capoidc.WithPKCE(v))
	require.NoError(t, err)
	authURL, err := p.AuthURL(ctx, req)
	require.NoError(t, err)

	q := authorize(t, authURL)
	require.Empty(t, q.Get("error"), q.Get("error_description"))
	assert.Equal(t, req.State(), q.Get("state"))

	// cap verifies the signature, iss, aud, exp, the nonce and at_hash.
	tk, err := p.Exchange(ctx, req, q.Get("state"), q.Get("code"))
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, tk.IDToken().Claims(&claims))
	assert.Equal(t, DefaultPerson, claims["sub"])
	assert.Equal(t, []any{"Warden.Operator"}, claims["roles"])
	assert.Equal(t, req.Nonce(), claims["nonce"])
	assert.NotZero(t, claims["auth_time"])
	assert.Equal(t, f.srv.URL, claims["iss"])
}

func TestCodeFlow_LoginHintPicksThePerson(t *testing.T) {
	f := newCodeFixture(t, map[string]map[string]any{
		"bob": {"roles": []any{"Warden.Auditor"}},
	})
	p := f.provider(t)
	v, _ := capoidc.NewCodeVerifier()
	req, err := capoidc.NewRequest(time.Minute, testRedirect, capoidc.WithPKCE(v))
	require.NoError(t, err)
	authURL, err := p.AuthURL(context.Background(), req)
	require.NoError(t, err)

	q := authorize(t, authURL+"&login_hint=bob")
	tk, err := p.Exchange(context.Background(), req, q.Get("state"), q.Get("code"))
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, tk.IDToken().Claims(&claims))
	assert.Equal(t, "bob", claims["sub"])
	assert.Equal(t, []any{"Warden.Auditor"}, claims["roles"])

	q = authorize(t, authURL+"&login_hint=mallory")
	assert.Equal(t, "access_denied", q.Get("error"))
	assert.Equal(t, req.State(), q.Get("state"))
}

func TestCodeFlow_Refusals(t *testing.T) {
	f := newCodeFixture(t, nil)
	base := url.Values{
		"response_type":         {"code"},
		"client_id":             {HumanClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid"},
		"state":                 {"s"},
		"code_challenge":        {"c"},
		"code_challenge_method": {"S256"},
	}
	with := func(k, v string) string {
		q := url.Values{}
		for kk, vv := range base {
			q[kk] = vv
		}
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
		return f.srv.URL + "/authorize?" + q.Encode()
	}

	for name, u := range map[string]string{
		"another client":          with("client_id", "other"),
		"a non-loopback redirect": with("redirect_uri", "https://evil.example/cb"),
	} {
		resp, err := http.Get(u)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
	}
	for name, tc := range map[string]struct{ url, err string }{
		"no PKCE":           {with("code_challenge", ""), "invalid_request"},
		"plain PKCE":        {with("code_challenge_method", "plain"), "invalid_request"},
		"no openid scope":   {with("scope", "profile"), "invalid_scope"},
		"a token response":  {with("response_type", "token"), "unsupported_response_type"},
		"an unknown person": {with("login_hint", "mallory"), "access_denied"},
	} {
		q := authorize(t, tc.url)
		assert.Equal(t, tc.err, q.Get("error"), name)
		assert.Equal(t, "s", q.Get("state"), name)
	}

	// state comes back only when the request sent one.
	q := authorize(t, with("state", ""))
	assert.NotEmpty(t, q.Get("code"))
	assert.False(t, q.Has("state"))
}

// A code is redeemed once, by its client, with its redirect URI and the
// verifier of its challenge, within its minute.
func TestCodeFlow_RedeemRefusals(t *testing.T) {
	f := newCodeFixture(t, nil)
	verifier := strings.Repeat("v", 43)
	codeFor := func(challenge string) string {
		q := authorize(t, f.srv.URL+"/authorize?"+url.Values{
			"response_type": {"code"}, "client_id": {HumanClientID}, "redirect_uri": {testRedirect},
			"scope": {"openid"}, "state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		}.Encode())
		return q.Get("code")
	}
	code := func() string { return codeFor(pkceChallenge(verifier)) }
	redeem := func(form url.Values) (int, string) {
		resp, err := http.PostForm(f.srv.URL+"/token", form)
		require.NoError(t, err)
		defer resp.Body.Close()
		var body map[string]any
		_ = jsonDecode(resp, &body)
		e, _ := body["error"].(string)
		return resp.StatusCode, e
	}
	good := func(c string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {c}, "client_id": {HumanClientID},
			"redirect_uri": {testRedirect}, "code_verifier": {verifier}}
	}

	c := code()
	status, _ := redeem(good(c))
	assert.Equal(t, http.StatusOK, status)
	status, e := redeem(good(c))
	assert.Equal(t, "invalid_grant", e, "a code is redeemed once")
	assert.Equal(t, http.StatusBadRequest, status)

	for name, edit := range map[string]func(url.Values){
		"wrong verifier": func(f url.Values) { f.Set("code_verifier", strings.Repeat("x", 43)) },
		"no verifier":    func(f url.Values) { f.Del("code_verifier") },
		"other redirect": func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:9/oidc/callback") },
		"other client":   func(f url.Values) { f.Set("client_id", "other") },
	} {
		form := good(code())
		edit(form)
		status, e := redeem(form)
		assert.Equal(t, http.StatusBadRequest, status, name)
		assert.NotEmpty(t, e, name)
	}

	// A verifier shorter than RFC 7636 allows is refused, even one that
	// matches its challenge.
	short := strings.Repeat("s", 42)
	form := good(codeFor(pkceChallenge(short)))
	form.Set("code_verifier", short)
	_, e = redeem(form)
	assert.Equal(t, "invalid_grant", e, "short verifier")

	// A code past its minute is refused.
	now := time.Now()
	f.as.codes.put("stale", pendingCode{
		clientID:    HumanClientID,
		redirectURI: testRedirect,
		challenge:   pkceChallenge(verifier),
		subject:     DefaultPerson,
		authTime:    now.Add(-2 * time.Minute),
		expires:     now.Add(-time.Minute),
	}, now)
	_, e = redeem(good("stale"))
	assert.Equal(t, "invalid_grant", e, "expired code")
}

func TestCodeFlow_Metadata(t *testing.T) {
	f := newCodeFixture(t, nil)
	resp, err := http.Get(f.srv.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	var m map[string]any
	require.NoError(t, jsonDecode(resp, &m))
	assert.Equal(t, f.srv.URL+"/authorize", m["authorization_endpoint"])
	assert.Contains(t, m["grant_types_supported"], "authorization_code")
	assert.Contains(t, m["code_challenge_methods_supported"], "S256")
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func jsonDecode(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}
