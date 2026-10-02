package playground

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	capjwt "github.com/hashicorp/cap/jwt"
)

// Grant and token types of RFC 8693.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// DefaultAccessTokenTTL is how long a bank token lives: short, so a token is
// worth little outside the call Warden minted it for.
const DefaultAccessTokenTTL = 5 * time.Minute

// defaultScope is granted when a token request names none.
const defaultScope = "bank"

// AuthServerConfig configures the bank's authorization server.
type AuthServerConfig struct {
	// IdP signs the access tokens; its issuer is the authorization server's.
	IdP *IdP
	// WardenIssuer and WardenJWKSURL say whose assertions the server accepts as
	// a subject token: Warden's OIDC issuer, and where its keys are published.
	WardenIssuer  string
	WardenJWKSURL string
	// WardenCAPEM, when set, is the CA Warden's JWKS is served under (a dev
	// server started with -dev-tls). Empty means system roots, or plain HTTP.
	WardenCAPEM string
	// Audiences are the resources a token may be requested for: the bank's faces.
	Audiences []string
	// AccessTokenTTL defaults to DefaultAccessTokenTTL.
	AccessTokenTTL time.Duration
}

// AuthServer is the bank's authorization server. Its one grant is the RFC 8693
// token exchange: it takes an assertion Warden signed, checks it against Warden's
// published keys, and issues a short-lived bank token for the same subject and,
// when the assertion names one, the same actor.
//
// It needs no client authentication. Warden calls it as a public client
// (client_auth=none) and the assertion is the proof of who is asking, so no
// secret is stored on either side.
type AuthServer struct {
	idp          *IdP
	wardenIssuer string
	wardenKeys   *capjwt.Validator
	audiences    []string
	ttl          time.Duration
}

// NewAuthServer builds the authorization server. Warden's keys are fetched lazily,
// on the first exchange, and refetched when an unknown key id appears, so the
// server can start before Warden's issuer is serving.
func NewAuthServer(cfg AuthServerConfig) (*AuthServer, error) {
	if cfg.IdP == nil {
		return nil, fmt.Errorf("an IdP is required")
	}
	if cfg.WardenIssuer == "" || cfg.WardenJWKSURL == "" {
		return nil, fmt.Errorf("Warden's issuer and JWKS URL are required")
	}
	if len(cfg.Audiences) == 0 {
		return nil, fmt.Errorf("at least one audience is required")
	}
	// The key set's HTTP client lives as long as the context it is built with.
	keySet, err := capjwt.NewJSONWebKeySet(context.Background(), cfg.WardenJWKSURL, cfg.WardenCAPEM)
	if err != nil {
		return nil, fmt.Errorf("Warden JWKS: %w", err)
	}
	validator, err := capjwt.NewValidator(keySet)
	if err != nil {
		return nil, fmt.Errorf("Warden assertion validator: %w", err)
	}
	ttl := cfg.AccessTokenTTL
	if ttl == 0 {
		ttl = DefaultAccessTokenTTL
	}
	return &AuthServer{
		idp:          cfg.IdP,
		wardenIssuer: strings.TrimRight(cfg.WardenIssuer, "/"),
		wardenKeys:   validator,
		audiences:    slices.Clone(cfg.Audiences),
		ttl:          ttl,
	}, nil
}

// Handler serves the IdP's discovery documents and keys and the token endpoint.
func (a *AuthServer) Handler() http.Handler {
	mux := http.NewServeMux()
	issuer := a.idp.Issuer()
	metadata := map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/jwks",
		"token_endpoint":                        issuer + "/token",
		"grant_types_supported":                 []string{grantTypeTokenExchange},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"id_token"},
	}
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, metadata)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, metadata)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, a.idp.JWKS())
	})
	mux.HandleFunc("POST /token", a.handleToken)
	return mux
}

// tokenResponse is an RFC 8693 §2.2.1 success response.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

// oauthError is an RFC 6749 §5.2 error response.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (a *AuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError{"invalid_request", "the token request body is not form-encoded"})
		return
	}
	resp, oerr := a.exchange(r.Context(), r.PostForm)
	if oerr != nil {
		writeJSON(w, http.StatusBadRequest, oerr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// exchange runs one token exchange. Every refusal names what was wrong, since the
// person reading it is learning how the pieces fit.
func (a *AuthServer) exchange(ctx context.Context, form map[string][]string) (*tokenResponse, *oauthError) {
	get := func(k string) string {
		if v := form[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if grant := get("grant_type"); grant != grantTypeTokenExchange {
		return nil, &oauthError{"unsupported_grant_type", fmt.Sprintf("only %s is supported, got %q", grantTypeTokenExchange, grant)}
	}
	subjectToken := get("subject_token")
	if subjectToken == "" {
		return nil, &oauthError{"invalid_request", "subject_token is required"}
	}
	audience := get("audience")
	if !slices.Contains(a.audiences, audience) {
		return nil, &oauthError{"invalid_target", fmt.Sprintf("audience must be one of %s, got %q", strings.Join(a.audiences, ", "), audience)}
	}

	// The subject must be an assertion Warden signed for this server.
	subject, err := a.wardenKeys.Validate(ctx, subjectToken, capjwt.Expected{
		Issuer:            a.wardenIssuer,
		Audiences:         []string{a.idp.Issuer()},
		SigningAlgorithms: []capjwt.Alg{capjwt.RS256, capjwt.ES256},
	})
	if err != nil {
		return nil, &oauthError{"invalid_grant", fmt.Sprintf("subject_token is not a valid Warden assertion for %s: %v", a.idp.Issuer(), err)}
	}
	sub, _ := subject["sub"].(string)
	if sub == "" {
		return nil, &oauthError{"invalid_grant", "subject_token carries no sub"}
	}

	scope := get("scope")
	if scope == "" {
		scope = defaultScope
	}
	claims := map[string]any{"sub": sub, "aud": audience, "scope": scope}
	// A delegation assertion names the person as sub and the agent in act. The
	// bank token carries both, so the bank acts for the person and can see who
	// asked.
	if act, ok := subject["act"].(map[string]any); ok {
		claims["act"] = act
	}
	if clientID := get("client_id"); clientID != "" {
		claims["client_id"] = clientID
	}
	token, err := a.idp.sign(claims, a.ttl)
	if err != nil {
		return nil, &oauthError{"server_error", err.Error()}
	}
	return &tokenResponse{
		AccessToken:     token,
		IssuedTokenType: tokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(a.ttl / time.Second),
		Scope:           scope,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
