package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
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

	// keysets holds one keyset per supported signing algorithm (RS256, ES256),
	// keyed by the JWS alg. A spec selects which algorithm signs its assertion; the
	// JWKS publishes every keyset's keys so a verifier picks by kid+alg. Empty until
	// keys are installed (issuer not ready).
	keysets map[string]*algKeyset

	// clockSkewLeeway is subtracted from a minted assertion's nbf to tolerate
	// modest clock skew at the verifier.
	clockSkewLeeway time.Duration

	// assertionTTL is the configured lifetime of a minted assertion.
	assertionTTL time.Duration

	// cacheControl is the Cache-Control header served on the JWKS/discovery, and
	// pushed to the publisher. Derived from the JWKS cache TTL so a cached JWKS is
	// always refreshed before a newly published key starts signing.
	cacheControl string
}

// oidcCacheControl derives the Cache-Control header from the JWKS cache TTL.
func oidcCacheControl(cacheTTL time.Duration) string {
	secs := int(cacheTTL.Seconds())
	if secs < 0 {
		secs = 0
	}
	return fmt.Sprintf("public, max-age=%d", secs)
}

// signingKey is a signing keypair (RSA or ECDSA) plus its algorithm and stable
// JWKS key id.
type signingKey struct {
	key       crypto.Signer // *rsa.PrivateKey (RS256) or *ecdsa.PrivateKey (ES256)
	alg       string        // oidcAlgRS256 | oidcAlgES256
	kid       string
	createdAt time.Time
	// retiredAt is set when the key stops being active. It stays in the JWKS until
	// every assertion it signed has expired, then is pruned. Zero for the active key.
	retiredAt time.Time
}

// Supported JWS signing algorithms. RS256 (RSA-2048, PKCS#1 v1.5) is the universal
// OIDC verifier default and the algorithm AWS IAM OIDC providers accept; ES256
// (ECDSA P-256) is the smaller/faster alternative some upstreams prefer. They
// coexist in one JWKS — a verifier selects the key by kid+alg from the token.
const (
	oidcAlgRS256 = "RS256"
	oidcAlgES256 = "ES256"
)

// oidcSupportedAlgs is the fixed set of algorithms the issuer maintains a keyset
// for. The issuer generates, rotates, and publishes a keyset per entry; a spec
// selects which one signs its assertion (RS256 by default).
var oidcSupportedAlgs = []string{oidcAlgRS256, oidcAlgES256}

// algKeyset is the active/next/retired triple for one signing algorithm. active
// signs; next is the pre-published successor promoted on rotation; retired keys
// stay in the JWKS until their assertions expire, then are pruned.
type algKeyset struct {
	active  *signingKey
	next    *signingKey
	retired []*signingKey
}

// copyKeysets deep-copies the map (and each retired slice) so callers cannot
// mutate the issuer's live state through a returned/stored reference.
func copyKeysets(src map[string]*algKeyset) map[string]*algKeyset {
	dst := make(map[string]*algKeyset, len(src))
	for alg, ks := range src {
		if ks == nil {
			continue
		}
		dst[alg] = &algKeyset{
			active:  ks.active,
			next:    ks.next,
			retired: append([]*signingKey(nil), ks.retired...),
		}
	}
	return dst
}

// defaultClockSkewLeeway backdates nbf so a verifier with a slightly fast clock
// does not reject a freshly minted assertion.
const defaultClockSkewLeeway = 60 * time.Second

// NewOIDCIssuer returns an issuer with no signing key installed (not ready).
// Call RestoreKeys (from storage, or with freshly generated keys) to activate it.
func NewOIDCIssuer(issuerURL string) *OIDCIssuer {
	return &OIDCIssuer{
		issuerURL:       issuerURL,
		keysets:         make(map[string]*algKeyset),
		clockSkewLeeway: defaultClockSkewLeeway,
		assertionTTL:    defaultAssertionTTL,
		cacheControl:    oidcCacheControl(defaultJWKSCacheTTL),
	}
}

// SetCacheControl sets the served/published Cache-Control from the JWKS cache TTL.
func (i *OIDCIssuer) SetCacheControl(cacheTTL time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cacheControl = oidcCacheControl(cacheTTL)
}

// CacheControl returns the Cache-Control header value for the JWKS/discovery.
func (i *OIDCIssuer) CacheControl() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cacheControl
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

// Ready reports whether every supported algorithm has an active signing key. The
// mint path must fail closed when this is false.
func (i *OIDCIssuer) Ready() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	for _, alg := range oidcSupportedAlgs {
		if ks := i.keysets[alg]; ks == nil || ks.active == nil {
			return false
		}
	}
	return true
}

// IssuerURL returns the configured issuer URL (the `iss` claim value).
func (i *OIDCIssuer) IssuerURL() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.issuerURL
}

// RestoreKeys installs the full per-algorithm keyset map loaded from storage (or
// freshly generated), used on unseal / standby promotion so in-flight assertions
// signed by a retired key still verify and each pre-published next key survives a
// restart.
func (i *OIDCIssuer) RestoreKeys(keysets map[string]*algKeyset) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keysets = copyKeysets(keysets)
}

// Keys returns a deep copy of the per-algorithm keyset map, for persistence.
func (i *OIDCIssuer) Keys() map[string]*algKeyset {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return copyKeysets(i.keysets)
}

// PruneRetired drops, across every algorithm, retired keys retired before cutoff
// (their assertions have all expired) and returns how many were removed.
func (i *OIDCIssuer) PruneRetired(cutoff time.Time) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	removed := 0
	for _, ks := range i.keysets {
		before := len(ks.retired)
		ks.retired = prunedRetired(ks.retired, cutoff)
		removed += before - len(ks.retired)
	}
	return removed
}

// prunedRetired returns retired keys not yet past cutoff (a fresh copy).
func prunedRetired(retired []*signingKey, cutoff time.Time) []*signingKey {
	out := make([]*signingKey, 0, len(retired))
	for _, k := range retired {
		if k.retiredAt.Before(cutoff) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// PendingRotation returns the (active, retired) state that Rotate(alg, cutoff)
// would produce for one algorithm, WITHOUT mutating the issuer, so the rotation
// loop can persist it before flipping in memory (nothing signs with a key not yet
// in storage). The returned active is that algorithm's current next key. It errors
// when the algorithm has no next key to promote.
func (i *OIDCIssuer) PendingRotation(alg string, cutoff time.Time) (active *signingKey, retired []*signingKey, err error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	ks := i.keysets[alg]
	if ks == nil || ks.next == nil {
		return nil, nil, fmt.Errorf("oidc issuer: no next %s key to promote", alg)
	}
	next := append([]*signingKey(nil), ks.retired...)
	if ks.active != nil && ks.active.kid != ks.next.kid {
		// Copy so the persisted retiredAt does not mutate the live active key.
		old := *ks.active
		old.retiredAt = time.Now()
		next = append(next, &old)
	}
	return ks.next, prunedRetired(next, cutoff), nil
}

// Rotate retires one algorithm's active key, promotes its next key to active,
// installs newNext as the new next, and prunes that algorithm's retired keys past
// cutoff. It errors (leaving the issuer untouched) when the algorithm has no next
// key to promote.
func (i *OIDCIssuer) Rotate(alg string, newNext *signingKey, cutoff time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	ks := i.keysets[alg]
	if ks == nil || ks.next == nil {
		return fmt.Errorf("oidc issuer: no next %s key to promote", alg)
	}
	if ks.active != nil && ks.active.kid != ks.next.kid {
		// Copy before stamping retiredAt so a signingKey is never mutated in place
		// (any Keys() snapshot or JWKS reader that shares the pointer stays stable),
		// matching PendingRotation.
		old := *ks.active
		old.retiredAt = time.Now()
		ks.retired = append(ks.retired, &old)
	}
	ks.active = ks.next
	ks.next = newNext
	ks.retired = prunedRetired(ks.retired, cutoff)
	return nil
}

// generateSigningKey creates a fresh keypair for alg (RS256 → RSA-2048, ES256 →
// ECDSA P-256) and its stable RFC 7638 key id.
func generateSigningKey(alg string) (*signingKey, error) {
	switch alg {
	case oidcAlgRS256:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("oidc issuer: generate RS256 signing key: %w", err)
		}
		return &signingKey{key: key, alg: alg, kid: rsaThumbprint(&key.PublicKey), createdAt: time.Now()}, nil
	case oidcAlgES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("oidc issuer: generate ES256 signing key: %w", err)
		}
		return &signingKey{key: key, alg: alg, kid: ecThumbprint(&key.PublicKey), createdAt: time.Now()}, nil
	default:
		return nil, fmt.Errorf("oidc issuer: unsupported signing algorithm %q", alg)
	}
}

// MintIdentityAssertion signs a short-lived JWT with the alg-selected signing key,
// asserting te's identity for presentation to the upstream named by audience. It
// fails closed when the issuer has no active key for alg or when audience is empty
// (an assertion without an audience is replayable at any upstream whose trust
// policy does not pin `aud`).
//
// metadata, when non-empty, is embedded under a single nested "warden_metadata"
// claim (never splatted at the top level, so it cannot clobber a registered or
// warden_* claim). The caller is responsible for choosing and bounding what it
// contains: the assertion crosses a trust boundary, so only operator-allowlisted,
// size-capped attributes should reach this point.
func (i *OIDCIssuer) MintIdentityAssertion(te *logical.TokenEntry, audience string, ttl time.Duration, metadata map[string]string, alg string) (string, error) {
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
	var active *signingKey
	if ks := i.keysets[alg]; ks != nil {
		active = ks.active
	}
	issuerURL := i.issuerURL
	leeway := i.clockSkewLeeway
	i.mu.RUnlock()

	if active == nil {
		return "", fmt.Errorf("oidc issuer: no active %s signing key (issuer not ready)", alg)
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
	if len(metadata) > 0 {
		claims["warden_metadata"] = metadata
	}
	header := map[string]string{"alg": active.alg, "typ": "JWT", "kid": active.kid}

	return signJWT(active, header, claims)
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

// JWKS returns the JSON Web Key Set (the active key, the pre-published next key,
// and retired-but-unpruned keys) that a verifier fetches to validate a minted
// assertion.
func (i *OIDCIssuer) JWKS() ([]byte, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	keys := make([]jwk, 0, 2*len(i.keysets))
	// Publish every keyset the issuer holds (sorted by alg for a deterministic
	// order), so a verifier can validate a token signed by any of them.
	for _, alg := range sortedKeys(i.keysets) {
		ks := i.keysets[alg]
		if ks.active != nil {
			keys = append(keys, publicJWK(ks.active))
		}
		if ks.next != nil {
			keys = append(keys, publicJWK(ks.next))
		}
		for _, r := range ks.retired {
			keys = append(keys, publicJWK(r))
		}
	}
	return json.Marshal(struct {
		Keys []jwk `json:"keys"`
	}{Keys: keys})
}

// sortedKeys returns the keyset map's algorithm keys in sorted order.
func sortedKeys(keysets map[string]*algKeyset) []string {
	algs := make([]string, 0, len(keysets))
	for alg := range keysets {
		algs = append(algs, alg)
	}
	sort.Strings(algs)
	return algs
}

// DiscoveryDocument returns the minimal OIDC discovery metadata an upstream reads
// at /.well-known/openid-configuration to locate the JWKS and confirm the signing
// algorithm.
func (i *OIDCIssuer) DiscoveryDocument(jwksURI string) ([]byte, error) {
	// Advertise every algorithm that currently has an active key.
	i.mu.RLock()
	issuerURL := i.issuerURL
	var algs []string
	for _, alg := range sortedKeys(i.keysets) {
		if ks := i.keysets[alg]; ks.active != nil {
			algs = append(algs, alg)
		}
	}
	i.mu.RUnlock()
	if len(algs) == 0 {
		algs = []string{oidcAlgRS256}
	}

	doc := map[string]interface{}{
		"issuer":                                issuerURL,
		"jwks_uri":                              jwksURI,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algs,
	}
	return json.Marshal(doc)
}

// jwk is a public signing key in JWK form — RSA (n,e) or EC (crv,x,y).
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// publicJWK renders a signing key's public half as a JWK, dispatching on key type.
func publicJWK(sk *signingKey) jwk {
	j := jwk{Use: "sig", Alg: sk.alg, Kid: sk.kid}
	switch pub := sk.key.Public().(type) {
	case *rsa.PublicKey:
		j.Kty = "RSA"
		j.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		j.E = base64.RawURLEncoding.EncodeToString(bigEndianExponent(pub.E))
	case *ecdsa.PublicKey:
		j.Kty = "EC"
		j.Crv = "P-256"
		j.X = base64.RawURLEncoding.EncodeToString(ecCoord(pub.X))
		j.Y = base64.RawURLEncoding.EncodeToString(ecCoord(pub.Y))
	}
	return j
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

// ecThumbprint computes the RFC 7638 JWK thumbprint (SHA-256 over the canonical
// {"crv","kty","x","y"} JSON) as the key id for a P-256 EC key.
func ecThumbprint(pub *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(ecCoord(pub.X))
	y := base64.RawURLEncoding.EncodeToString(ecCoord(pub.Y))
	// RFC 7638: members in lexicographic order, no whitespace.
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ecCoord renders a P-256 coordinate (or ECDSA signature scalar) as a fixed 32-byte
// big-endian slice — the width JWK/JWS require, left-padded with zeros.
func ecCoord(n *big.Int) []byte {
	b := make([]byte, 32)
	n.FillBytes(b)
	return b
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

// signJWT signs header+claims as a compact JWS using the key's algorithm. Kept
// self-contained (the driver package has an equivalent private signer; core does
// not reach into it).
func signJWT(sk *signingKey, header map[string]string, claims map[string]interface{}) (string, error) {
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

	var sig []byte
	switch key := sk.key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("oidc issuer: sign: %w", err)
		}
	case *ecdsa.PrivateKey:
		r, s, serr := ecdsa.Sign(rand.Reader, key, digest[:])
		if serr != nil {
			return "", fmt.Errorf("oidc issuer: sign: %w", serr)
		}
		// JWS ES256 signature is the fixed-width concatenation R‖S (32 bytes each),
		// NOT the ASN.1/DER form ecdsa.PrivateKey.Sign would produce.
		sig = append(ecCoord(r), ecCoord(s)...)
	default:
		return "", fmt.Errorf("oidc issuer: unsupported signing key type %T", sk.key)
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
