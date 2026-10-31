package playground

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// The authorization code flow (OpenID Connect Core §3.1) that people sign in
// to Warden with: the oidc auth method sends their browser here, and the
// server signs them in without asking anything. The person is the one the
// request's login_hint names, or DefaultPerson. It is for a playground and
// for end-to-end tests: anyone who can reach it is whoever they name.

const grantTypeAuthorizationCode = "authorization_code"

// HumanClientID is the one client of the authorization code flow: an oidc
// auth mount configured with client_auth none (a public client, PKCE only).
const HumanClientID = "warden-login"

// DefaultPerson is who signs in when a request names nobody.
const DefaultPerson = "ada@playground.example"

// DefaultPeople are the persons the authorization endpoint signs in by
// default, with their extra ID token claims: Ada holds the operator app role.
func DefaultPeople() map[string]map[string]any {
	return map[string]map[string]any{
		DefaultPerson: {"roles": []any{"Warden.Operator"}, "preferred_username": DefaultPerson},
	}
}

// Code flow lifetimes: a code must be redeemed within a minute, and an ID
// token lives as long as a bank token.
const (
	codeTTL    = time.Minute
	idTokenTTL = DefaultAccessTokenTTL
)

// pendingCode is what a code stands for until it is redeemed.
type pendingCode struct {
	clientID    string
	redirectURI string
	nonce       string
	challenge   string
	subject     string
	authTime    time.Time
	expires     time.Time
}

// codeStore holds the codes issued and not yet redeemed. Each is redeemed at
// most once; expired ones are dropped when a new one is issued.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]pendingCode
}

func newCodeStore() *codeStore { return &codeStore{codes: map[string]pendingCode{}} }

func (s *codeStore) put(code string, p pendingCode, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, old := range s.codes {
		if now.After(old.expires) {
			delete(s.codes, c)
		}
	}
	s.codes[code] = p
}

// take removes and returns the code's pending login, if it exists and has not
// expired.
func (s *codeStore) take(code string, now time.Time) (pendingCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || now.After(p.expires) {
		return pendingCode{}, false
	}
	return p, true
}

// handleAuthorize signs in the person login_hint names and sends the browser
// back to the redirect URI with a code. It takes only what a public client
// using PKCE sends, and redirects only to a loopback address, where a CLI
// listens. A refusal it can send back is a redirect carrying error; one it
// cannot (no usable redirect URI) is a 400.
func (a *AuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	if q.Get("client_id") != HumanClientID || !loopbackRedirect(redirectURI) {
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_request",
			"client_id must be " + HumanClientID + " and redirect_uri a loopback http URL"})
		return
	}
	back := func(params url.Values) {
		u, _ := url.Parse(redirectURI)
		vals := u.Query()
		for k, v := range params {
			vals[k] = v
		}
		// state goes back only when the request sent one (RFC 6749 §4.1.2).
		if state := q.Get("state"); state != "" {
			vals.Set("state", state)
		}
		u.RawQuery = vals.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	refuse := func(code, description string) {
		back(url.Values{"error": {code}, "error_description": {description}})
	}
	switch {
	case q.Get("response_type") != "code":
		refuse("unsupported_response_type", "only response_type=code is supported")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		refuse("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		refuse("invalid_scope", "the openid scope is required")
		return
	}
	subject := q.Get("login_hint")
	if subject == "" {
		subject = DefaultPerson
	}
	if _, ok := a.people[subject]; !ok {
		refuse("access_denied", "no such person: "+subject)
		return
	}
	code, err := randomHex(16)
	if err != nil {
		refuse("server_error", err.Error())
		return
	}
	now := a.idp.now()
	a.codes.put(code, pendingCode{
		clientID:    HumanClientID,
		redirectURI: redirectURI,
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		subject:     subject,
		authTime:    now,
		expires:     now.Add(codeTTL),
	}, now)
	back(url.Values{"code": {code}})
}

// loopbackRedirect reports whether raw is an http URL on a loopback host.
func loopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, u.Hostname())
}

// codeResponse is an OpenID Connect token response.
type codeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// handleCodeGrant redeems a code: once, by the client and with the redirect
// URI it was issued to, and with the PKCE verifier of its challenge. The ID
// token carries the nonce of the authorization request, the time the person
// signed in, at_hash of the access token, and the person's claims.
func (a *AuthServer) handleCodeGrant(w http.ResponseWriter, r *http.Request) {
	form := r.PostForm
	// A public client names itself in the form, or as the user of an HTTP
	// Basic header with an empty password.
	clientID := form.Get("client_id")
	if user, _, ok := r.BasicAuth(); ok && clientID == "" {
		clientID = user
	}
	now := a.idp.now()
	p, ok := a.codes.take(form.Get("code"), now)
	switch {
	case !ok:
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_grant", "the code is unknown, used or expired"})
		return
	case clientID != p.clientID:
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_client", "the code was issued to another client"})
		return
	case form.Get("redirect_uri") != p.redirectURI:
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_grant", "redirect_uri differs from the authorization request's"})
		return
	case !pkceMatches(form.Get("code_verifier"), p.challenge):
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_grant", "code_verifier does not match the code_challenge"})
		return
	}

	access, err := a.idp.sign(map[string]any{"sub": p.subject, "aud": a.idp.Issuer(), "scope": "openid"}, idTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError{"server_error", err.Error()})
		return
	}
	claims := map[string]any{}
	for k, v := range a.people[p.subject] {
		claims[k] = v
	}
	claims["sub"] = p.subject
	claims["aud"] = p.clientID
	claims["auth_time"] = p.authTime.Unix()
	claims["at_hash"] = halfHash(access)
	if p.nonce != "" {
		claims["nonce"] = p.nonce
	}
	idToken, err := a.idp.sign(claims, idTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError{"server_error", err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, codeResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(idTokenTTL / time.Second),
		IDToken:     idToken,
		Scope:       "openid",
	})
}

// pkceMatches reports whether verifier is a well-formed code verifier (43 to
// 128 characters, RFC 7636 §4.1) that hashes to challenge (S256).
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// halfHash is the at_hash of token for an ES256 signature: the base64url of
// the left half of its SHA-256 (OpenID Connect Core §3.1.3.6).
func halfHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
