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

func newCodeFixture(t *testing.T, people map[string]map[string]any, edits ...func(*AuthServerConfig)) *codeFixture {
	t.Helper()
	var h atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	idp, err := NewIdP(srv.URL)
	require.NoError(t, err)
	cfg := AuthServerConfig{
		IdP:           idp,
		WardenIssuer:  "https://warden.test",
		WardenJWKSURL: "https://warden.test/jwks",
		Audiences:     []string{"bank"},
		People:        people,
	}
	for _, edit := range edits {
		edit(&cfg)
	}
	as, err := NewAuthServer(cfg)
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

// signIn runs one sign-in of the person hint names (none for DefaultPerson)
// with opts on the request, and returns the verified ID token's claims.
func (f *codeFixture) signIn(t *testing.T, hint string, opts ...capoidc.Option) map[string]any {
	t.Helper()
	p := f.provider(t)
	v, err := capoidc.NewCodeVerifier()
	require.NoError(t, err)
	req, err := capoidc.NewRequest(time.Minute, testRedirect, append(opts, capoidc.WithPKCE(v))...)
	require.NoError(t, err)
	authURL, err := p.AuthURL(context.Background(), req)
	require.NoError(t, err)
	if hint != "" {
		authURL += "&login_hint=" + url.QueryEscape(hint)
	}
	q := authorize(t, authURL)
	require.Empty(t, q.Get("error"), q.Get("error_description"))
	tk, err := p.Exchange(context.Background(), req, q.Get("state"), q.Get("code"))
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, tk.IDToken().Claims(&claims))
	return claims
}

func authTimeOf(claims map[string]any) time.Time {
	at, _ := claims["auth_time"].(float64)
	return time.Unix(int64(at), 0)
}

// A sign-in reuses the person's session, and its auth_time, until a login asks
// for a new authentication with prompt=login or a max_age the session has
// outlived; IgnoreReauthentication keeps it whatever is asked.
func TestCodeFlow_Sessions(t *testing.T) {
	f := newCodeFixture(t, nil)
	first := authTimeOf(f.signIn(t, ""))
	assert.WithinDuration(t, time.Now(), first, 2*time.Second, "a first sign-in authenticates")

	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	f.as.StartSession(DefaultPerson, old)
	assert.Equal(t, old, authTimeOf(f.signIn(t, "")), "single sign-on keeps the session")
	assert.Equal(t, old, authTimeOf(f.signIn(t, "", capoidc.WithMaxAge(3*3600))), "max_age the session meets")
	assert.WithinDuration(t, time.Now(), authTimeOf(f.signIn(t, "", capoidc.WithMaxAge(3600))), 2*time.Second,
		"max_age the session outlived")

	f.as.StartSession(DefaultPerson, old)
	fresh := authTimeOf(f.signIn(t, "", capoidc.WithPrompts(capoidc.Login)))
	assert.WithinDuration(t, time.Now(), fresh, 2*time.Second, "prompt=login")
	assert.Equal(t, fresh, authTimeOf(f.signIn(t, "")), "the new session is reused")

	ignoring := newCodeFixture(t, nil, func(c *AuthServerConfig) { c.IgnoreReauthentication = true })
	ignoring.as.StartSession(DefaultPerson, old)
	assert.Equal(t, old, authTimeOf(ignoring.signIn(t, "", capoidc.WithPrompts(capoidc.Login))),
		"a server ignoring the request keeps the session")

	q := authorize(t, f.srv.URL+"/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {HumanClientID}, "redirect_uri": {testRedirect},
		"scope": {"openid"}, "code_challenge": {"c"}, "code_challenge_method": {"S256"}, "max_age": {"soon"},
	}.Encode())
	assert.Equal(t, "invalid_request", q.Get("error"), "a malformed max_age")
}

// acr_values pick the acr the ID token carries among those the person can
// reach; a person who can reach none carries none.
func TestCodeFlow_ACR(t *testing.T) {
	f := newCodeFixture(t, map[string]map[string]any{
		DefaultPerson: {"roles": []any{"Warden.Operator"}},
		"bob":         {},
	}, func(c *AuthServerConfig) {
		c.ACRs = map[string][]string{DefaultPerson: {"urn:okta:loa:2fa:any", "phr"}}
	})
	acr := func(hint string, opts ...capoidc.Option) any {
		return f.signIn(t, hint, opts...)["acr"]
	}
	assert.Equal(t, "phr", acr("", capoidc.WithACRValues("phrh", "phr", "urn:okta:loa:2fa:any")), "the first reachable, in the order asked")
	assert.Equal(t, "urn:okta:loa:2fa:any", acr("", capoidc.WithACRValues("phrh")), "none reachable: the person's first")
	assert.Equal(t, "urn:okta:loa:2fa:any", acr(""), "none asked: the person's first")
	assert.Nil(t, acr("bob", capoidc.WithACRValues("phr")), "a person who can reach none")
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
