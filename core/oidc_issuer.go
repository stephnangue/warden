package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-384/512 for crypto.Hash.New()
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

// JWS signing algorithm names. RS* are RSA + PKCS#1 v1.5; ES* are ECDSA. A
// verifier selects a key by kid+alg from the token, so any mix coexists in one JWKS.
const (
	oidcAlgRS256 = "RS256"
	oidcAlgRS384 = "RS384"
	oidcAlgES256 = "ES256"
	oidcAlgES384 = "ES384"
)

// algSpec describes how to generate and sign for one JWS algorithm. All of the
// generate / sign / JWK / thumbprint code is driven by this table, so ADDING an
// algorithm is a single entry here. Enabling it for the issuer additionally means
// adding the name to oidcSupportedAlgs (below) and to the credential package's
// assertion_algorithm OneOf validation.
type algSpec struct {
	hash    crypto.Hash    // signing digest (SHA-256/384/512)
	curve   elliptic.Curve // the EC curve for ES*, or nil for RSA
	rsaBits int            // RSA modulus size for RS*, 0 for EC
}

var oidcAlgSpecs = map[string]algSpec{
	oidcAlgRS256: {hash: crypto.SHA256, rsaBits: 2048},
	oidcAlgRS384: {hash: crypto.SHA384, rsaBits: 3072},
	oidcAlgES256: {hash: crypto.SHA256, curve: elliptic.P256()},
	oidcAlgES384: {hash: crypto.SHA384, curve: elliptic.P384()},
}

// oidcSupportedAlgs is the subset of oidcAlgSpecs the issuer actually maintains a
// keyset for: it generates, rotates, and publishes a keyset per entry, and a spec
// may select any of them (RS256 by default). The others are supported by the
// signing code but dormant until enabled here.
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

// NextKeyCreatedAt returns the earliest creation time of the pre-published next key
// across supported algorithms (falling back to the active key for a keyset without a
// next). This is the anchor the rotation loop schedules its next tick from, and the
// moment of the last rotation (or of enable, before the first rotation). ok is false when
// the issuer holds no keys.
func (i *OIDCIssuer) NextKeyCreatedAt() (time.Time, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var anchor time.Time
	for _, ks := range i.keysets {
		k := ks.next
		if k == nil {
			k = ks.active
		}
		if k == nil {
			continue
		}
		if anchor.IsZero() || k.createdAt.Before(anchor) {
			anchor = k.createdAt
		}
	}
	if anchor.IsZero() {
		return time.Time{}, false
	}
	return anchor, true
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

// generateSigningKey creates a fresh keypair for alg (per its algSpec: RS* → RSA of
// the spec's size, ES* → ECDSA on the spec's curve) and its stable RFC 7638 key id.
func generateSigningKey(alg string) (*signingKey, error) {
	spec, ok := oidcAlgSpecs[alg]
	if !ok {
		return nil, fmt.Errorf("oidc issuer: unsupported signing algorithm %q", alg)
	}
	if spec.curve != nil {
		key, err := ecdsa.GenerateKey(spec.curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("oidc issuer: generate %s signing key: %w", alg, err)
		}
		kid, err := ecThumbprint(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("oidc issuer: %s key id: %w", alg, err)
		}
		return &signingKey{key: key, alg: alg, kid: kid, createdAt: time.Now()}, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, spec.rsaBits)
	if err != nil {
		return nil, fmt.Errorf("oidc issuer: generate %s signing key: %w", alg, err)
	}
	return &signingKey{key: key, alg: alg, kid: rsaThumbprint(&key.PublicKey), createdAt: time.Now()}, nil
}

// AssertionClaims carries the per-mint inputs for MintIdentityAssertion beyond
// the token identity: the target audience, TTL, signing algorithm, optional
// projected metadata, and an optional named resource.
type AssertionClaims struct {
	// Audience is the `aud` — the upstream the assertion is minted for. Required.
	Audience string
	// TTL is the assertion lifetime (`exp` = iat + TTL). Must be positive.
	TTL time.Duration
	// Alg selects the signing key/algorithm (e.g. RS256, ES256).
	Alg string
	// Metadata, when non-empty, is embedded under a single nested
	// "warden_metadata" claim (never splatted at the top level, so it cannot
	// clobber a registered or warden_* claim). The caller chooses and bounds what
	// it contains: the assertion crosses a trust boundary, so only
	// operator-allowlisted, size-capped attributes should reach this point.
	Metadata map[string]string
	// Resource, when non-empty, is emitted as the top-level "warden_resource"
	// claim naming the single downstream resource the assertion targets, so a
	// verifier evaluating bound claims can pin it to one resource. Opaque string.
	Resource string
}

// MintIdentityAssertion signs a short-lived JWT with the alg-selected signing key,
// asserting te's identity for presentation to the upstream named by c.Audience. It
// fails closed when the issuer has no active key for c.Alg or when c.Audience is
// empty (an assertion without an audience is replayable at any upstream whose trust
// policy does not pin `aud`).
func (i *OIDCIssuer) MintIdentityAssertion(te *logical.TokenEntry, c AssertionClaims) (string, error) {
	if te == nil {
		return "", fmt.Errorf("oidc issuer: nil token entry")
	}
	if te.PrincipalID == "" {
		return "", fmt.Errorf("oidc issuer: token entry has no principal")
	}
	if c.Audience == "" {
		return "", fmt.Errorf("oidc issuer: assertion audience is required")
	}
	if c.TTL <= 0 {
		return "", fmt.Errorf("oidc issuer: assertion ttl must be positive")
	}

	i.mu.RLock()
	var active *signingKey
	if ks := i.keysets[c.Alg]; ks != nil {
		active = ks.active
	}
	issuerURL := i.issuerURL
	leeway := i.clockSkewLeeway
	i.mu.RUnlock()

	if active == nil {
		return "", fmt.Errorf("oidc issuer: no active %s signing key (issuer not ready)", c.Alg)
	}

	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("oidc issuer: %w", err)
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss":               issuerURL,
		"sub":               wardenSubject(te),
		"aud":               c.Audience,
		"iat":               now.Unix(),
		"nbf":               now.Add(-leeway).Unix(),
		"exp":               now.Add(c.TTL).Unix(),
		"jti":               jti,
		"warden_role":       te.RoleName,
		"warden_namespace":  te.NamespacePath,
		"warden_auth_mount": te.MountAccessor,
	}
	if len(c.Metadata) > 0 {
		claims["warden_metadata"] = c.Metadata
	}
	if c.Resource != "" {
		claims["warden_resource"] = c.Resource
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
	appendJWK := func(sk *signingKey) error {
		if sk == nil {
			return nil
		}
		j, err := publicJWK(sk)
		if err != nil {
			return err
		}
		keys = append(keys, j)
		return nil
	}
	// Publish every keyset the issuer holds (sorted by alg for a deterministic
	// order), so a verifier can validate a token signed by any of them.
	for _, alg := range sortedKeys(i.keysets) {
		ks := i.keysets[alg]
		if err := appendJWK(ks.active); err != nil {
			return nil, err
		}
		if err := appendJWK(ks.next); err != nil {
			return nil, err
		}
		for _, r := range ks.retired {
			if err := appendJWK(r); err != nil {
				return nil, err
			}
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
func publicJWK(sk *signingKey) (jwk, error) {
	j := jwk{Use: "sig", Alg: sk.alg, Kid: sk.kid}
	switch pub := sk.key.Public().(type) {
	case *rsa.PublicKey:
		j.Kty = "RSA"
		j.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		j.E = base64.RawURLEncoding.EncodeToString(bigEndianExponent(pub.E))
	case *ecdsa.PublicKey:
		x, y, err := ecPublicXY(pub)
		if err != nil {
			return jwk{}, err
		}
		j.Kty = "EC"
		j.Crv = pub.Curve.Params().Name
		j.X, j.Y = x, y
	default:
		return jwk{}, fmt.Errorf("oidc issuer: unsupported public key type %T", pub)
	}
	return j, nil
}

// ecPublicXY returns the base64url-encoded, fixed-width X and Y coordinates of an
// EC public key, taken from its SEC 1 uncompressed encoding (0x04 || X || Y). It
// uses PublicKey.Bytes rather than the deprecated big.Int PublicKey.X/Y fields.
func ecPublicXY(pub *ecdsa.PublicKey) (x, y string, err error) {
	b, err := pub.Bytes()
	if err != nil {
		return "", "", fmt.Errorf("oidc issuer: encode EC public key: %w", err)
	}
	n := ecByteLen(pub.Curve)
	if len(b) != 1+2*n || b[0] != 4 {
		return "", "", fmt.Errorf("oidc issuer: unexpected EC point encoding (%d bytes)", len(b))
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(b[1 : 1+n]), enc.EncodeToString(b[1+n:]), nil
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

// ecThumbprint computes the RFC 7638 JWK thumbprint (always SHA-256, independent of
// the key's signing hash, over the canonical {"crv","kty","x","y"} JSON) as the key
// id for an EC key of any supported curve.
func ecThumbprint(pub *ecdsa.PublicKey) (string, error) {
	x, y, err := ecPublicXY(pub)
	if err != nil {
		return "", err
	}
	// RFC 7638: members in lexicographic order, no whitespace.
	canonical := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, pub.Curve.Params().Name, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ecByteLen is the byte width of a coordinate or signature scalar on curve c
// (e.g. 32 for P-256, 48 for P-384).
func ecByteLen(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

// ecCoord renders an EC coordinate (or ECDSA signature scalar) as a fixed
// byteLen-wide big-endian slice — the width JWK/JWS require, left-padded with zeros.
func ecCoord(n *big.Int, byteLen int) []byte {
	b := make([]byte, byteLen)
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
	spec, ok := oidcAlgSpecs[sk.alg]
	if !ok {
		return "", fmt.Errorf("oidc issuer: unsupported signing algorithm %q", sk.alg)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := spec.hash.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	var sig []byte
	switch key := sk.key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, spec.hash, digest)
		if err != nil {
			return "", fmt.Errorf("oidc issuer: sign: %w", err)
		}
	case *ecdsa.PrivateKey:
		r, s, serr := ecdsa.Sign(rand.Reader, key, digest)
		if serr != nil {
			return "", fmt.Errorf("oidc issuer: sign: %w", serr)
		}
		// JWS ES* signature is the fixed-width concatenation R‖S (each the curve's
		// coordinate width), NOT the ASN.1/DER form ecdsa.PrivateKey.Sign produces.
		n := ecByteLen(key.Curve)
		sig = append(ecCoord(r, n), ecCoord(s, n)...)
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
