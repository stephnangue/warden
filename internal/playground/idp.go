package playground

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// Identity kinds the IdP mints, and the audience each is minted for. Agents and
// users get distinct audiences so that each auth mount's roles only ever match
// its own kind: discovery checks a token against every JWT mount, and without
// the split an agent would be offered the user role.
const (
	KindAgent = "agent"
	KindUser  = "user"

	AudienceAgent = "warden-agent"
	AudienceUser  = "warden-user"
)

// Identity token lifetimes. An hour covers a session, since an MCP client such as
// Claude Code stores the header it was attached with; a day is the ceiling.
const (
	DefaultIdentityTTL = time.Hour
	MaxIdentityTTL     = 24 * time.Hour
)

// Identity is what the IdP is asked to vouch for.
type Identity struct {
	Kind    string
	Subject string
	// MayAct names the agent a user lets act for them. It becomes the may_act
	// claim (RFC 8693 §4.4), which the playground's policy checks; core does not
	// interpret it.
	MayAct string
	// Claims are extra claims, such as a team. They cannot override a claim
	// the IdP sets itself.
	Claims map[string]any
	TTL    time.Duration
}

// reservedClaims are set by the IdP and cannot be supplied in Identity.Claims.
var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "iat": true, "nbf": true, "exp": true, "jti": true, "may_act": true,
}

// IdP is the playground's identity provider. It also signs the bank's access
// tokens, as the authorization server they come from: one issuer, one key.
type IdP struct {
	issuer string
	key    *ecdsa.PrivateKey
	kid    string
	now    func() time.Time
}

// NewIdP makes an IdP with a fresh in-memory ES256 key. The key is generated once
// and only read afterwards, so an IdP is safe for concurrent use.
func NewIdP(issuer string) (*IdP, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate playground IdP key: %w", err)
	}
	kid, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	return &IdP{issuer: strings.TrimRight(issuer, "/"), key: key, kid: kid, now: time.Now}, nil
}

// Issuer is the IdP's issuer URL.
func (p *IdP) Issuer() string { return p.issuer }

// PublicKey is the key tokens are verified with.
func (p *IdP) PublicKey() crypto.PublicKey { return &p.key.PublicKey }

// JWKS is the IdP's public key set.
func (p *IdP) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
}

// Mint signs an agent or user identity token. Its iat, nbf and exp are always set:
// a token missing them is refused by Warden's JWT auth.
func (p *IdP) Mint(id Identity) (string, error) {
	var aud string
	switch id.Kind {
	case KindAgent:
		if id.MayAct != "" {
			return "", fmt.Errorf("may_act applies to a user, not an agent")
		}
		aud = AudienceAgent
	case KindUser:
		aud = AudienceUser
	default:
		return "", fmt.Errorf("kind must be %q or %q, got %q", KindAgent, KindUser, id.Kind)
	}
	if strings.TrimSpace(id.Subject) == "" {
		return "", fmt.Errorf("sub is required")
	}
	ttl := id.TTL
	if ttl == 0 {
		ttl = DefaultIdentityTTL
	}
	if ttl < 0 || ttl > MaxIdentityTTL {
		return "", fmt.Errorf("ttl must be between 0 and %s, got %s", MaxIdentityTTL, ttl)
	}

	claims := make(map[string]any, len(id.Claims)+8)
	for k, v := range id.Claims {
		if reservedClaims[k] {
			return "", fmt.Errorf("claim %q is set by the IdP and cannot be supplied", k)
		}
		claims[k] = v
	}
	claims["sub"] = id.Subject
	claims["aud"] = aud
	if id.MayAct != "" {
		claims["may_act"] = map[string]any{"sub": id.MayAct}
	}
	return p.sign(claims, ttl)
}

// sign stamps the registered claims every token carries and signs the result.
func (p *IdP) sign(claims map[string]any, ttl time.Duration) (string, error) {
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}
	now := p.now()
	claims["iss"] = p.issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()
	claims["jti"] = jti

	// A signer per token: building one is cheap, and it keeps signing free of
	// shared mutable state.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.kid),
	)
	if err != nil {
		return "", fmt.Errorf("create playground signer: %w", err)
	}
	return josejwt.Signed(signer).Claims(claims).Serialize()
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
