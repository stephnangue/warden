package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/clientassertion"
	"golang.org/x/oauth2"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var (
	errLoginRefused      = errors.New("the identity provider did not complete the login, or its ID token did not verify")
	errRedirectNotListed = errors.New("redirect_uri is not one of the mount's allowed_redirect_uris")
)

// clientAssertionType is the client_assertion_type of a JWT client assertion
// (RFC 7523 §2.2).
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func (b *oidcAuthBackend) pathAuthURL() *framework.Path {
	return &framework.Path{
		Pattern: "auth_url",
		Fields: map[string]*framework.FieldSchema{
			"redirect_uri": {
				Type:        framework.TypeString,
				Description: "Where the identity provider sends the browser back: one of allowed_redirect_uris (a loopback one on any port).",
				Required:    true,
			},
			"login_binding": {
				Type:        framework.TypeString,
				Description: "base64url SHA-256 of a 32-byte secret the client keeps, presented as login_proof at callback.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleAuthURL,
				Summary:  "Start a login: the identity provider's authorization URL and the login state",
			},
		},
		HelpSynopsis: "Start a login",
		HelpDescription: "Returns the authorization URL to open in a browser and the state the identity provider " +
			"sends back. The pending login is sealed into the state: the mount keeps nothing.",
	}
}

func (b *oidcAuthBackend) pathCallback() *framework.Path {
	return &framework.Path{
		Pattern: "callback",
		Fields: map[string]*framework.FieldSchema{
			"state": {
				Type:        framework.TypeString,
				Description: "The state auth_url returned, as the identity provider sent it back.",
			},
			"code": {
				Type:        framework.TypeString,
				Description: "The authorization code the identity provider sent back.",
			},
			"login_proof": {
				Type:        framework.TypeString,
				Description: "base64url of the secret whose hash was sent as login_binding.",
			},
			"error": {
				Type:        framework.TypeString,
				Description: "The error the identity provider sent back instead of a code, if any.",
			},
			"error_description": {
				Type:        framework.TypeString,
				Description: "The identity provider's description of that error.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleCallback,
				Summary:  "Finish a login: exchange the code and issue a session",
			},
		},
		HelpSynopsis: "Finish a login",
		HelpDescription: "Exchanges the authorization code at the identity provider, verifies the ID token and " +
			"issues a ticket token: a self-contained session carrying no role. The identity provider's tokens " +
			"are discarded.",
	}
}

// handleAuthURL starts a login. It checks the redirect URI and the binding,
// draws a PKCE verifier and a nonce, and seals them with the redirect URI,
// the binding, the namespace and an expiry into the state; the authorization
// URL carries that state. Nothing is stored.
func (b *oidcAuthBackend) handleAuthURL(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, p, release, err := b.live(ctx)
	if err != nil {
		return b.unavailable(err), nil
	}
	defer release()
	redirectURI := d.Get("redirect_uri").(string)
	binding := d.Get("login_binding").(string)
	if !redirectAllowed(cfg.AllowedRedirectURIs, redirectURI) {
		return badRequest(errRedirectNotListed), nil
	}
	if err := checkBinding(binding); err != nil {
		return badRequest(err), nil
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return internalError(errors.New("namespace missing")), nil
	}

	verifier, err := capoidc.NewCodeVerifier()
	if err != nil {
		return internalError(err), nil
	}
	nonce, err := capoidc.NewID()
	if err != nil {
		return internalError(err), nil
	}
	state, err := b.sealState(ctx, &pendingLogin{
		V:           1,
		Verifier:    verifier.Verifier(),
		Nonce:       nonce,
		RedirectURI: redirectURI,
		Binding:     binding,
		NamespaceID: ns.ID,
		ExpiresAt:   time.Now().Add(stateTTL).Unix(),
	})
	if err != nil {
		return internalError(err), nil
	}
	oreq, err := capoidc.NewRequest(stateTTL, redirectURI,
		capoidc.WithState(state), capoidc.WithNonce(nonce), capoidc.WithPKCE(verifier))
	if err != nil {
		return internalError(err), nil
	}
	authURL, err := p.AuthURL(ctx, oreq)
	if err != nil {
		return internalError(err), nil
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{
		"auth_url": authURL,
		"state":    state,
	}}, nil
}

// handleCallback finishes a login. It opens the state, checks that it was
// started in this namespace and that its redirect URI is still allowed, and
// only then relays an error the identity provider sent back. It checks that
// the caller holds the secret the login was bound to, exchanges the code, and
// verifies the ID token: signature, iss, aud, azp, expiry, nonce, and the
// access token and code hashes. The ID token's claims become the admission's
// facts, kept to what the mount publishes; the alias must be derivable and the
// session must fit in a ticket. The identity provider's tokens are discarded.
func (b *oidcAuthBackend) handleCallback(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, p, release, err := b.live(ctx)
	if err != nil {
		return b.unavailable(err), nil
	}
	defer release()
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return internalError(errors.New("namespace missing")), nil
	}

	now := time.Now()
	state := d.Get("state").(string)
	pending, err := b.openState(ctx, state, now)
	if err != nil || pending.NamespaceID != ns.ID {
		return badRequest(errStateInvalid), nil
	}
	if !redirectAllowed(cfg.AllowedRedirectURIs, pending.RedirectURI) {
		return badRequest(errRedirectNotListed), nil
	}
	if idpErr := d.Get("error").(string); idpErr != "" {
		return badRequest(fmt.Errorf("the identity provider refused the login: %s", idpError(idpErr, d.Get("error_description").(string)))), nil
	}
	if !proofMatches(pending.Binding, d.Get("login_proof").(string)) {
		return badRequest(errProofMismatch), nil
	}
	code := d.Get("code").(string)
	if code == "" {
		return badRequest(errors.New("code is required")), nil
	}

	claims, err := b.exchange(ctx, cfg, p, pending, state, code)
	if err != nil {
		b.logger.Warn("oidc login refused", logger.Err(err))
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: errLoginRefused}, nil
	}

	naming := b.mountFacts.Load()
	if naming == nil {
		return b.unavailable(errConfigInvalid), nil
	}
	if err := checkDistributedClaims(claims, naming); err != nil {
		return badRequest(err), nil
	}
	kept := keptClaims(claims, naming)
	facts := selector.NewClaims(kept)
	factsJSON, err := facts.EncodeJSON()
	if err != nil {
		return internalError(err), nil
	}
	adm := &logical.Admission{
		Facts:    facts,
		Mount:    b.mountFacts,
		AuthTime: authTime(claims),
		Bytes:    int64(len(factsJSON)),
	}
	alias := adm.DeriveAlias(naming)
	if alias == "" {
		return badRequest(fmt.Errorf("alias_name_source %q yields no usable value on this ID token", naming.AliasSource)), nil
	}
	adm.PrincipalID = alias

	if n := ticketLen(alias, naming.Kind, adm.AuthTime, ns.ID, req.MountAccessor, factsJSON, now, cfg.SessionTTL); n > logical.MaxTicketLen {
		return badRequest(fmt.Errorf("the session would be %d bytes (limit %d): the mapped claims are too large; "+
			"map fewer claims, or claims with fewer values", n, logical.MaxTicketLen)), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			PrincipalID: alias,
			TokenType:   logical.TokenTypeTicket,
			TokenTTL:    cfg.SessionTTL,
			ClientIP:    req.ClientIP,
			Admission:   adm,
		},
		Data: map[string]any{"principal_id": alias},
	}, nil
}

// exchange redeems the code at the token endpoint and returns the verified ID
// token's claims. The request carries exactly one client authentication, the
// mount's (exchangeCode); the ID token is then verified as cap verifies it
// after its own exchange, against the request rebuilt from the pending login.
func (b *oidcAuthBackend) exchange(ctx context.Context, cfg *oidcConfig, p *liveProvider,
	pending *pendingLogin, state, code string) (map[string]any, error) {
	var assertion string
	if cfg.ClientAuth == clientAuthKeyJWT {
		var err error
		if assertion, err = b.newAssertion(cfg, p.tokenURL); err != nil {
			return nil, fmt.Errorf("client assertion: %w", err)
		}
	}
	httpCtx, err := p.HTTPClientContext(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := exchangeCode(httpCtx, cfg, p.tokenURL, pending.RedirectURI, code, pending.Verifier, assertion)
	if err != nil {
		return nil, err
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, errors.New("the token response carries no id_token")
	}
	oreq, err := capoidc.NewRequest(time.Until(time.Unix(pending.ExpiresAt, 0)), pending.RedirectURI,
		capoidc.WithState(state), capoidc.WithNonce(pending.Nonce))
	if err != nil {
		return nil, err
	}
	idToken := capoidc.IDToken(rawID)
	claims, err := p.VerifyIDToken(ctx, idToken, oreq)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	if tok.AccessToken != "" {
		if _, err := idToken.VerifyAccessToken(capoidc.AccessToken(tok.AccessToken)); err != nil {
			return nil, fmt.Errorf("access_token: %w", err)
		}
	}
	if cHash, _ := claims["c_hash"].(string); cHash != "" {
		if _, err := idToken.VerifyAuthorizationCode(code); err != nil {
			return nil, fmt.Errorf("code hash: %w", err)
		}
	}
	return claims, nil
}

// exchangeCode redeems code at tokenURL, authenticating as cfg.ClientAuth
// says and in no other way: client_secret as HTTP Basic (RFC 6749 §2.3.1),
// none and private_key_jwt as form parameters (the client ID, and for
// private_key_jwt the assertion, RFC 7523 §2.2). The style is set, never
// probed, so no request carries two client authentications. ctx carries the
// HTTP client (oauth2.HTTPClient).
func exchangeCode(ctx context.Context, cfg *oidcConfig, tokenURL, redirectURI, code, verifier, assertion string) (*oauth2.Token, error) {
	oc := oauth2.Config{
		ClientID:    cfg.ClientID,
		RedirectURL: redirectURI,
		Endpoint:    oauth2.Endpoint{TokenURL: tokenURL, AuthStyle: oauth2.AuthStyleInParams},
	}
	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	switch cfg.ClientAuth {
	case clientAuthSecret:
		oc.ClientSecret = cfg.ClientSecret
		oc.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case clientAuthKeyJWT:
		opts = append(opts,
			oauth2.SetAuthURLParam("client_assertion_type", clientAssertionType),
			oauth2.SetAuthURLParam("client_assertion", assertion))
	}
	tok, err := oc.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	return tok, nil
}

// newClientAssertion signs the private_key_jwt assertion: issuer and subject
// the client ID, audience the token endpoint (RFC 7523 §3), with the key's
// kid and, when a certificate is configured, its x5t#S256 thumbprint.
func newClientAssertion(cfg *oidcConfig, tokenURL string) (string, error) {
	var opts []clientassertion.Option
	if cfg.ClientAssertionKID != "" {
		opts = append(opts, clientassertion.WithKeyID(cfg.ClientAssertionKID))
	}
	if cfg.x5tS256 != "" {
		opts = append(opts, clientassertion.WithHeaders(map[string]string{"x5t#S256": cfg.x5tS256}))
	}
	j, err := clientassertion.NewJWTWithRSAKey(cfg.ClientID, []string{tokenURL}, clientassertion.RS256, cfg.privateKey, opts...)
	if err != nil {
		return "", err
	}
	return j.Serialize()
}

// checkDistributedClaims refuses an ID token in which a claim the mount reads
// is delivered elsewhere (OpenID Connect Core §5.6.2: listed in _claim_names
// and absent): matching would see none of its values, and a person would
// silently lose every group it grants.
func checkDistributedClaims(claims map[string]any, n *logical.MountNaming) error {
	names, _ := claims["_claim_names"].(map[string]any)
	if len(names) == 0 {
		return nil
	}
	for _, k := range n.Mapping.Sources() {
		top := k.Name
		if k.IsPointer() {
			top = k.Path[0]
		}
		if _, elsewhere := names[top]; !elsewhere {
			continue
		}
		if _, present := claims[top]; !present {
			return fmt.Errorf("the ID token delivers claim %q elsewhere (distributed claims), so it cannot be matched; "+
				"have the identity provider put it in the ID token, or map another claim", top)
		}
	}
	return nil
}

// authTime returns when the person authenticated: the ID token's auth_time,
// else its iat.
func authTime(claims map[string]any) time.Time {
	if t := helper.IssuedAt(map[string]any{"iat": claims["auth_time"]}); !t.IsZero() {
		return t
	}
	return helper.IssuedAt(claims)
}

// ticketLen is the length of the ticket core would issue for this login, so a
// login whose ticket would be refused on every request is refused here, with
// its reason, rather than by core as an internal error.
func ticketLen(alias, kind string, auth time.Time, nsID, accessor string, facts []byte, now time.Time, ttl time.Duration) int {
	p := logical.TicketPayload{
		V:             logical.TicketPayloadVersion,
		Alias:         alias,
		PrincipalID:   alias,
		Kind:          kind,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(ttl).Unix(),
		NamespaceID:   nsID,
		MountAccessor: accessor,
		Facts:         facts,
	}
	if !auth.IsZero() {
		p.AuthTime = auth.Unix()
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return logical.MaxTicketLen + 1
	}
	return logical.TicketLen(len(plain))
}

// maxIdPErrorRunes bounds the identity provider's error text relayed.
const maxIdPErrorRunes = 256

// idpError renders the identity provider's error for the caller: valid UTF-8,
// without control characters, at most maxIdPErrorRunes runes. It is the
// identity provider's text, relayed, and reaches the audit log.
func idpError(code, description string) string {
	s := code
	if description != "" {
		s += ": " + description
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > maxIdPErrorRunes {
		s = string(r[:maxIdPErrorRunes])
	}
	return s
}

// unavailable answers a login on a mount that cannot proceed: not configured
// (400), its configuration invalid (503), or its identity provider
// unreachable (503).
func (b *oidcAuthBackend) unavailable(err error) *logical.Response {
	switch {
	case errors.Is(err, errNotConfigured):
		return badRequest(err)
	case errors.Is(err, errConfigInvalid):
		return &logical.Response{StatusCode: http.StatusServiceUnavailable, Err: err}
	}
	b.logger.Warn("oidc login: identity provider unavailable", logger.Err(err))
	return &logical.Response{StatusCode: http.StatusServiceUnavailable, Err: errors.New("the identity provider cannot be reached")}
}

func internalError(err error) *logical.Response {
	return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}
}
