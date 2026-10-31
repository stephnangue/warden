package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	capoidc "github.com/hashicorp/cap/oidc"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/logical"
)

// Client authentication methods at the identity provider's token endpoint.
const (
	clientAuthSecret = "client_secret"
	clientAuthKeyJWT = "private_key_jwt"
	clientAuthNone   = "none"
)

// Session lifetime: the default, and the most a mount may set. A ticket cannot
// be revoked, so its lifetime is the bound on a leaked or offboarded one.
const (
	defaultSessionTTL = time.Hour
	maxSessionTTL     = 8 * time.Hour
)

var (
	defaultSupportedAlgs = []string{string(capoidc.RS256)}
	defaultScopes        = []string{"openid", "profile"}

	// supportedAlgs are the ID token signing algorithms cap verifies.
	supportedAlgs = []capoidc.Alg{
		capoidc.RS256, capoidc.RS384, capoidc.RS512,
		capoidc.ES256, capoidc.ES384, capoidc.ES512,
		capoidc.PS256, capoidc.PS384, capoidc.PS512,
		capoidc.EdDSA,
	}

	// loopbackHosts are the hosts a redirect URI may use on any port. They
	// are the literals cap's provider compares against, so the two agree.
	loopbackHosts = []string{"localhost", "127.0.0.1", "::1"}
)

// oidcConfig is the mount's configuration, as storage holds it: secrets
// included, compiled state excluded. validate fills the defaults and compiles
// it; the result is never modified afterwards.
type oidcConfig struct {
	OIDCDiscoveryURL    string        `json:"oidc_discovery_url"`
	OIDCDiscoveryCA     string        `json:"oidc_discovery_ca_pem,omitempty"`
	ClientID            string        `json:"client_id"`
	ClientAuth          string        `json:"client_auth"`
	ClientSecret        string        `json:"client_secret,omitempty"`
	PrivateKey          string        `json:"private_key,omitempty"`
	ClientCertificate   string        `json:"client_certificate,omitempty"`
	ClientAssertionKID  string        `json:"client_assertion_kid,omitempty"`
	SupportedAlgs       []string      `json:"supported_algs"`
	AllowedRedirectURIs []string      `json:"allowed_redirect_uris"`
	Scopes              []string      `json:"scopes"`
	SessionTTL          time.Duration `json:"session_ttl"`

	// Facts: entity_kind (always human), the claims the mount publishes
	// beyond its built-ins, and alias_name_source (default sub).
	helper.FactsConfig

	privateKey *rsa.PrivateKey
	// x5tS256 is the client certificate's SHA-256 thumbprint, base64url,
	// sent as the assertion's x5t#S256 header; "" without a certificate.
	x5tS256 string

	// invalid is why a stored config fails validate: it is kept, readable
	// and rewritable, and refuses every login until it is rewritten.
	invalid error
}

// validate fills the defaults, checks every key and compiles the facts. Facts
// that do not compile are kept on the config (FactsConfig.Err), not returned,
// as for every auth method: a write refuses them, a login fails closed.
//
// Whether the issuer is one the provider vouches for is not decided here:
// discovery (newProvider) requires the issuer the provider publishes to equal
// oidc_discovery_url, and every ID token's iss to equal it in turn.
func (c *oidcConfig) validate() error {
	if c.ClientAuth == "" {
		c.ClientAuth = clientAuthSecret
	}
	if len(c.SupportedAlgs) == 0 {
		c.SupportedAlgs = slices.Clone(defaultSupportedAlgs)
	}
	if len(c.Scopes) == 0 {
		c.Scopes = slices.Clone(defaultScopes)
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = defaultSessionTTL
	}
	if c.EntityKind == "" {
		c.EntityKind = logical.EntityKindHuman
	}
	c.Compile(builtinFacts(), aliasPolicy)

	switch {
	case c.OIDCDiscoveryURL == "":
		return errors.New("oidc_discovery_url is required")
	case c.ClientID == "":
		return errors.New("client_id is required")
	case c.EntityKind != logical.EntityKindHuman:
		return fmt.Errorf("entity_kind: this mount admits people only; it cannot be %q", c.EntityKind)
	case c.SessionTTL < 0 || c.SessionTTL > maxSessionTTL:
		return fmt.Errorf("session_ttl must be positive and at most %s", maxSessionTTL)
	case len(c.AllowedRedirectURIs) == 0:
		return errors.New("allowed_redirect_uris is required")
	}
	if u, err := url.Parse(c.OIDCDiscoveryURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("oidc_discovery_url must be an absolute https URL")
	}
	for _, u := range c.AllowedRedirectURIs {
		if err := checkRedirectURI(u); err != nil {
			return err
		}
	}
	for _, alg := range c.SupportedAlgs {
		if !slices.Contains(supportedAlgs, capoidc.Alg(alg)) {
			return fmt.Errorf("supported_algs: %q is not a supported signing algorithm", alg)
		}
	}
	if !slices.Contains(c.Scopes, "openid") {
		return errors.New(`scopes must include "openid"`)
	}
	return c.checkClientAuth()
}

// checkClientAuth checks that client_auth has what it needs, and nothing that
// would go unused, and parses the private key and certificate.
func (c *oidcConfig) checkClientAuth() error {
	switch c.ClientAuth {
	case clientAuthSecret:
		if c.ClientSecret == "" {
			return errors.New("client_secret is required when client_auth is client_secret")
		}
		if c.PrivateKey != "" || c.ClientCertificate != "" {
			return errors.New("private_key and client_certificate are set only when client_auth is private_key_jwt")
		}
	case clientAuthKeyJWT:
		if c.PrivateKey == "" {
			return errors.New("private_key is required when client_auth is private_key_jwt")
		}
		if c.ClientSecret != "" {
			return errors.New("client_secret is set only when client_auth is client_secret")
		}
		key, err := parseRSAPrivateKey(c.PrivateKey)
		if err != nil {
			return fmt.Errorf("private_key: %w", err)
		}
		c.privateKey = key
		if c.ClientCertificate != "" {
			thumb, err := certificateThumbprint(c.ClientCertificate, key)
			if err != nil {
				return fmt.Errorf("client_certificate: %w", err)
			}
			c.x5tS256 = thumb
		}
	case clientAuthNone:
		if c.ClientSecret != "" || c.PrivateKey != "" || c.ClientCertificate != "" {
			return errors.New("client_auth none uses neither client_secret, private_key nor client_certificate")
		}
	default:
		return fmt.Errorf("client_auth must be %s, %s or %s", clientAuthSecret, clientAuthKeyJWT, clientAuthNone)
	}
	return nil
}

// checkRedirectURI refuses a redirect URI that is not an absolute http(s) URL
// without a fragment.
func checkRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("allowed_redirect_uris: %q is not an absolute http(s) URL without a fragment", raw)
	}
	return nil
}

// redirectAllowed reports whether uri is one of allowed: exactly, or, for a
// loopback host (loopbackHosts), on any port (RFC 8252 §7.3), as a native
// client listens on a port it picks. It is the rule cap's provider applies,
// host literals included, so the two agree.
func redirectAllowed(allowed []string, uri string) bool {
	in, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if !slices.Contains(loopbackHosts, in.Hostname()) {
		return slices.Contains(allowed, uri)
	}
	in.Host = in.Hostname()
	for _, a := range allowed {
		au, err := url.Parse(a)
		if err != nil {
			continue
		}
		au.Host = au.Hostname()
		if au.String() == in.String() {
			return true
		}
	}
	return false
}

func parseRSAPrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("not an RSA private key (PKCS#1 or PKCS#8)")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return key, nil
}

// certificateThumbprint returns the base64url SHA-256 thumbprint of the PEM
// certificate raw (the x5t#S256 JOSE header, RFC 7515 §4.1.8), which must
// certify key.
func certificateThumbprint(raw string, key *rsa.PrivateKey) (string, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return "", errors.New("not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("not a certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return "", errors.New("does not certify private_key")
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// newProvider runs discovery against the identity provider and returns a
// provider for c. Discovery fails unless the issuer the provider publishes
// equals oidc_discovery_url. The scopes passed on are c's without openid,
// which cap always adds.
func (c *oidcConfig) newProvider(ctx context.Context) (*liveProvider, error) {
	algs := make([]capoidc.Alg, len(c.SupportedAlgs))
	for i, a := range c.SupportedAlgs {
		algs[i] = capoidc.Alg(a)
	}
	opts := []capoidc.Option{capoidc.WithScopes(c.extraScopes()...)}
	if c.OIDCDiscoveryCA != "" {
		opts = append(opts, capoidc.WithProviderCA(c.OIDCDiscoveryCA))
	}
	pc, err := capoidc.NewConfig(c.OIDCDiscoveryURL, c.ClientID, capoidc.ClientSecret(c.ClientSecret),
		algs, c.AllowedRedirectURIs, opts...)
	if err != nil {
		return nil, fmt.Errorf("provider config: %w", err)
	}
	p, err := capoidc.NewProvider(pc)
	if err != nil {
		return nil, fmt.Errorf("discovery at %s: %w", c.OIDCDiscoveryURL, err)
	}
	info, err := p.DiscoveryInfo(ctx)
	if err != nil {
		p.Done()
		return nil, fmt.Errorf("discovery at %s: %w", c.OIDCDiscoveryURL, err)
	}
	return &liveProvider{Provider: p, tokenURL: info.TokenURL}, nil
}

// extraScopes returns c's scopes without openid.
func (c *oidcConfig) extraScopes() []string {
	out := make([]string, 0, len(c.Scopes))
	for _, s := range c.Scopes {
		if s != "openid" {
			out = append(out, s)
		}
	}
	return out
}
