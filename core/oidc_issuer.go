package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/stephnangue/warden/logical"
)

// OIDCIssuer makes Warden its own OpenID Connect issuer: it mints short-lived
// JWT assertions of a calling agent's resolved identity and publishes the public
// keys (JWKS) + discovery document that an upstream (AWS STS, an OAuth token
// endpoint, …) uses to verify them. This is the "one place" every agent's
// identity flows through for Workload Identity Federation, regardless of how the
// agent authenticated to Warden.
//
// The private signing key never leaves Warden. Key generation and rotation
// happen only on the active node; a promoted standby loads the key from storage.
// The issuer is inert until an active signing key is installed, so the
// warden_identity mint path fails closed when it is not ready.
type OIDCIssuer struct {
	mu sync.RWMutex

	// issuerURL is the public URL an upstream fetches discovery/JWKS from and the
	// `iss` claim of every minted assertion. Normally the published bucket/CDN URL.
	issuerURL string

	// active is the current signing key. nil until installed (issuer not ready).
	active *signingKey
	// retired holds keys rotated out but still published in the JWKS until every
	// assertion they signed has expired, so in-flight assertions still verify.
	retired []*signingKey

	// clockSkewLeeway is subtracted from a minted assertion's nbf to tolerate
	// modest clock skew at the verifier.
	clockSkewLeeway time.Duration

	// assertionTTL is the configured lifetime of a minted assertion.
	assertionTTL time.Duration
}

// signingKey is an RSA keypair plus its stable JWKS key id.
type signingKey struct {
	key       *rsa.PrivateKey
	kid       string
	createdAt time.Time
}

// oidcSigningAlg is fixed to RS256 for v1 — the universal OIDC verifier default,
// and the algorithm AWS IAM OIDC providers accept. EC/ES256 can be added later
// as an additional JWKS key rather than a switch.
const oidcSigningAlg = "RS256"

// defaultClockSkewLeeway backdates nbf so a verifier with a slightly fast clock
// does not reject a freshly minted assertion.
const defaultClockSkewLeeway = 60 * time.Second

// NewOIDCIssuer returns an issuer with no signing key installed (not ready).
// Call SetActiveKey (from storage or a freshly generated key) to activate it.
func NewOIDCIssuer(issuerURL string) *OIDCIssuer {
	return &OIDCIssuer{
		issuerURL:       issuerURL,
		clockSkewLeeway: defaultClockSkewLeeway,
		assertionTTL:    defaultAssertionTTL,
	}
}

// SetAssertionTTL configures the minted-assertion lifetime. A non-positive value
// keeps the default.
func (i *OIDCIssuer) SetAssertionTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.assertionTTL = ttl
}

// AssertionTTL returns the configured assertion lifetime.
func (i *OIDCIssuer) AssertionTTL() time.Duration {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.assertionTTL
}

// Ready reports whether an active signing key is installed. The mint path must
// fail closed when this is false.
func (i *OIDCIssuer) Ready() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.active != nil
}

// IssuerURL returns the configured issuer URL (the `iss` claim value).
func (i *OIDCIssuer) IssuerURL() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.issuerURL
}

// SetActiveKey installs key as the active signing key, moving any previous
// active key into the retired set (so its still-valid assertions keep verifying
// until it is pruned).
func (i *OIDCIssuer) SetActiveKey(key *signingKey) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.active != nil && i.active.kid != key.kid {
		i.retired = append(i.retired, i.active)
	}
	i.active = key
}

// generateSigningKey creates a fresh RSA-2048 keypair and its RFC 7638 key id.
func generateSigningKey() (*signingKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: generate signing key: %w", err)
	}
	return &signingKey{
		key:       key,
		kid:       rsaThumbprint(&key.PublicKey),
		createdAt: time.Now(),
	}, nil
}

// MintIdentityAssertion signs a short-lived RS256 JWT asserting te's identity for
// presentation to the upstream named by audience. It fails closed when the issuer
// has no active key or when audience is empty (an assertion without an audience
// is replayable at any upstream whose trust policy does not pin `aud`).
func (i *OIDCIssuer) MintIdentityAssertion(te *logical.TokenEntry, audience string, ttl time.Duration) (string, error) {
	if te == nil {
		return "", fmt.Errorf("oidc issuer: nil token entry")
	}
	if te.PrincipalID == "" {
		return "", fmt.Errorf("oidc issuer: token entry has no principal")
	}
	if audience == "" {
		return "", fmt.Errorf("oidc issuer: assertion audience is required")
	}
	if ttl <= 0 {
		return "", fmt.Errorf("oidc issuer: assertion ttl must be positive")
	}

	i.mu.RLock()
	active := i.active
	issuerURL := i.issuerURL
	leeway := i.clockSkewLeeway
	i.mu.RUnlock()

	if active == nil {
		return "", fmt.Errorf("oidc issuer: no active signing key (issuer not ready)")
	}

	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("oidc issuer: %w", err)
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss":               issuerURL,
		"sub":               wardenSubject(te),
		"aud":               audience,
		"iat":               now.Unix(),
		"nbf":               now.Add(-leeway).Unix(),
		"exp":               now.Add(ttl).Unix(),
		"jti":               jti,
		"warden_role":       te.RoleName,
		"warden_namespace":  te.NamespacePath,
		"warden_auth_mount": te.MountAccessor,
	}
	header := map[string]string{"alg": oidcSigningAlg, "typ": "JWT", "kid": active.kid}

	return signRS256(active.key, header, claims)
}

// wardenSubject builds the globally-unique subject of a minted assertion:
// "wid:{namespaceID}:{mountAccessor}:{principalID}". namespaceID and the mount
// accessor are Warden-generated and delimiter-free; the possibly-delimiter-bearing
// principal (e.g. a SPIFFE ID) is the trailing segment, so the value is
// unambiguous and an operator can bind a role to a mount with a `sub` StringLike
// prefix "wid:{nsID}:{accessor}:*".
func wardenSubject(te *logical.TokenEntry) string {
	return fmt.Sprintf("wid:%s:%s:%s", te.NamespaceID, te.MountAccessor, te.PrincipalID)
}

// JWKS returns the JSON Web Key Set (active plus retired-but-unpruned public
// keys) that a verifier fetches to validate a minted assertion.
func (i *OIDCIssuer) JWKS() ([]byte, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	keys := make([]jwkRSA, 0, 1+len(i.retired))
	if i.active != nil {
		keys = append(keys, rsaPublicJWK(i.active))
	}
	for _, r := range i.retired {
		keys = append(keys, rsaPublicJWK(r))
	}
	return json.Marshal(struct {
		Keys []jwkRSA `json:"keys"`
	}{Keys: keys})
}

// DiscoveryDocument returns the minimal OIDC discovery metadata an upstream reads
// at /.well-known/openid-configuration to locate the JWKS and confirm the signing
// algorithm.
func (i *OIDCIssuer) DiscoveryDocument(jwksURI string) ([]byte, error) {
	i.mu.RLock()
	issuerURL := i.issuerURL
	i.mu.RUnlock()

	doc := map[string]interface{}{
		"issuer":                                issuerURL,
		"jwks_uri":                              jwksURI,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{oidcSigningAlg},
	}
	return json.Marshal(doc)
}

// jwkRSA is a public RSA key in JWK form.
type jwkRSA struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// rsaPublicJWK renders a signing key's public half as a JWK.
func rsaPublicJWK(sk *signingKey) jwkRSA {
	pub := &sk.key.PublicKey
	return jwkRSA{
		Kty: "RSA",
		Use: "sig",
		Alg: oidcSigningAlg,
		Kid: sk.kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigEndianExponent(pub.E)),
	}
}

// rsaThumbprint computes the RFC 7638 JWK thumbprint (SHA-256 over the canonical
// {"e","kty","n"} JSON) as the key id, so the kid is a stable function of the key.
func rsaThumbprint(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigEndianExponent(pub.E))
	// RFC 7638: members in lexicographic order, no whitespace.
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// bigEndianExponent renders an RSA public exponent as a minimal big-endian byte
// slice (e.g. 65537 -> {0x01,0x00,0x01}).
func bigEndianExponent(e int) []byte {
	b := []byte{byte(e >> 24), byte(e >> 16), byte(e >> 8), byte(e)}
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// signRS256 signs header+claims as a compact RS256 JWS. Kept self-contained (the
// driver package has an equivalent private signer; core does not reach into it).
func signRS256(key *rsa.PrivateKey, header map[string]string, claims map[string]interface{}) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("oidc issuer: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oidc issuer: marshal claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("oidc issuer: sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// randomJTI returns a random assertion identifier.
func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
