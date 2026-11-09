// Package dpop verifies and signs the proofs that bind a ticket to a key its
// client holds: Warden's profile of RFC 9449 (OAuth 2.0 Demonstrating Proof of
// Possession).
//
// The profile accepts ES256 only and keeps no state: a proof is checked
// against the request it rides and the key the ticket is bound to, never
// against the proofs seen before it. A captured proof can therefore be
// replayed within Window of its iat, for the same request; the signed request
// context (Context) is what makes "the same request" more than a method and a
// path.
//
// It departs from RFC 9449 where only the warden CLI signs, so nothing is
// gained by interoperating:
//
//   - htu is compared by path, exactly, never by host;
//   - a request proof must carry the warden_ctx claim (Context);
//   - no nonce is ever issued.
//
// Verify keeps no state, and a Key is safe for concurrent use.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// HeaderName is the request header a proof rides.
	HeaderName = "DPoP"

	// Alg is the only signing algorithm a proof may use.
	Alg = "ES256"

	// MaxProofLen bounds a proof, checked before anything is decoded.
	MaxProofLen = 2048

	// MaxJTILen bounds a proof's jti.
	MaxJTILen = 128

	// Window is how far a proof's iat may be from when its request arrived,
	// either way.
	Window = 30 * time.Second

	typ = "dpop+jwt"

	// coordLen is the base64url length of a P-256 coordinate (32 bytes), and
	// sigLen that of an ES256 signature (64 bytes).
	coordLen = 43
	sigLen   = 86
)

// ErrInvalidProof is wrapped by every refusal of a proof. Its text is the
// RFC 9449 error code a refusal's challenge names; the wrapping error names
// the check that failed, for the server's log only.
var ErrInvalidProof = errors.New("invalid_dpop_proof")

var b64 = base64.RawURLEncoding.Strict()

// Context is the warden_ctx claim: what a request proof signs beyond its
// method, path and ticket. The selectors are the raw values of the request
// headers that choose what the request does, "" when absent; Query and Body
// are Hash of the raw query and of the body.
type Context struct {
	Role        string `json:"role"`
	Namespace   string `json:"ns"`
	Provider    string `json:"provider"`
	Request     string `json:"request"`
	ContentType string `json:"content_type"`
	Query       string `json:"query"`
	Body        string `json:"body"`
}

// Hash returns the unpadded base64url SHA-256 of b: the form of ath and of
// Context's Query and Body.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return b64.EncodeToString(sum[:])
}

// Want is what a proof must match.
type Want struct {
	// JKT is the thumbprint of the key the ticket is bound to.
	JKT string

	// Method is the request's method, and Path its path as the client sent
	// it, escaped.
	Method string
	Path   string

	// Now is when the request arrived.
	Now time.Time

	// ATH is Hash of the ticket the request presents, and Context what the
	// request carries. A request proof sets both; a login proof sets neither,
	// and a proof carrying either is then refused: a request proof is never
	// taken for a login's.
	ATH     string
	Context *Context

	// Body is whether Context.Body is compared: false where the request's
	// body streams through unread.
	Body bool
}

// Proof is what a verified proof tells its verifier.
type Proof struct {
	// JTI is the proof's identifier, as its client chose it.
	JTI      string
	IssuedAt time.Time
}

type header struct {
	Typ  string          `json:"typ"`
	Alg  string          `json:"alg"`
	JWK  *jwk            `json:"jwk"`
	Crit json.RawMessage `json:"crit,omitempty"`
}

type jwk struct {
	Kty string          `json:"kty"`
	Crv string          `json:"crv"`
	X   string          `json:"x"`
	Y   string          `json:"y"`
	D   json.RawMessage `json:"d,omitempty"`
}

type claims struct {
	HTM string   `json:"htm"`
	HTU string   `json:"htu"`
	IAT int64    `json:"iat"`
	JTI string   `json:"jti"`
	ATH string   `json:"ath,omitempty"`
	Ctx *Context `json:"warden_ctx,omitempty"`
}

// Verify checks the proof that values, the request's DPoP header values,
// carry against want. Checks run cheapest first, and the signature, the only
// expensive one, last; the key's thumbprint is compared before the key is
// parsed. Every refusal wraps ErrInvalidProof.
func Verify(values []string, want *Want) (Proof, error) {
	if len(values) != 1 {
		return Proof{}, refuse("%d proofs, want one", len(values))
	}
	p := values[0]
	if len(p) > MaxProofLen {
		return Proof{}, refuse("longer than %d bytes", MaxProofLen)
	}
	h64, rest, ok1 := strings.Cut(p, ".")
	c64, s64, ok2 := strings.Cut(rest, ".")
	if !ok1 || !ok2 || strings.Contains(s64, ".") || strings.ContainsAny(p, "\r\n") {
		return Proof{}, refuse("not a compact JWS")
	}
	hb, err := b64.DecodeString(h64)
	if err != nil {
		return Proof{}, refuse("header is not base64url")
	}
	cb, err := b64.DecodeString(c64)
	if err != nil {
		return Proof{}, refuse("payload is not base64url")
	}
	if len(s64) != sigLen {
		return Proof{}, refuse("signature is not %d bytes", 64)
	}
	var sig [64]byte
	if n, err := b64.Decode(sig[:], []byte(s64)); err != nil || n != len(sig) {
		return Proof{}, refuse("signature is not base64url")
	}

	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Proof{}, refuse("header is not a JSON object")
	}
	switch {
	case h.Typ != typ:
		return Proof{}, refuse("typ is %q", h.Typ)
	case h.Alg != Alg:
		return Proof{}, refuse("alg is %q", h.Alg)
	case len(h.Crit) > 0:
		return Proof{}, refuse("crit is set")
	case h.JWK == nil:
		return Proof{}, refuse("no jwk")
	case h.JWK.Kty != "EC" || h.JWK.Crv != "P-256":
		return Proof{}, refuse("jwk is not a P-256 key")
	case len(h.JWK.D) > 0:
		return Proof{}, refuse("jwk carries a private key")
	case !isCoord(h.JWK.X) || !isCoord(h.JWK.Y):
		return Proof{}, refuse("jwk coordinates are malformed")
	}
	if subtle.ConstantTimeCompare([]byte(thumbprint(h.JWK.X, h.JWK.Y)), []byte(want.JKT)) != 1 {
		return Proof{}, refuse("jwk is not the bound key")
	}

	var c claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return Proof{}, refuse("payload is not a JSON object of the expected claims")
	}
	if c.HTM != want.Method {
		return Proof{}, refuse("htm is %q, want %q", c.HTM, want.Method)
	}
	if err := checkHTU(c.HTU, want.Path); err != nil {
		return Proof{}, err
	}
	login := want.ATH == "" && want.Context == nil
	switch {
	case login && (c.ATH != "" || c.Ctx != nil):
		return Proof{}, refuse("a login proof carries ath or warden_ctx")
	case want.ATH != "" && c.ATH != want.ATH:
		return Proof{}, refuse("ath is not the presented ticket's")
	}
	now := want.Now.Unix()
	if w := int64(Window / time.Second); c.IAT < now-w || c.IAT > now+w {
		return Proof{}, refuse("iat is %ds from the request's arrival", c.IAT-now)
	}
	if c.JTI == "" || len(c.JTI) > MaxJTILen {
		return Proof{}, refuse("jti is missing or longer than %d bytes", MaxJTILen)
	}
	if want.Context != nil {
		if c.Ctx == nil {
			return Proof{}, refuse("no warden_ctx")
		}
		if err := checkContext(c.Ctx, want.Context, want.Body); err != nil {
			return Proof{}, err
		}
	}

	// Both coordinates passed isCoord, so each decodes to exactly 32 bytes.
	var point [65]byte
	point[0] = 4
	if _, err := b64.Decode(point[1:33], []byte(h.JWK.X)); err != nil {
		return Proof{}, refuse("jwk x is not base64url")
	}
	if _, err := b64.Decode(point[33:], []byte(h.JWK.Y)); err != nil {
		return Proof{}, refuse("jwk y is not base64url")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point[:])
	if err != nil {
		return Proof{}, refuse("jwk is not a point on P-256")
	}
	digest := sha256.Sum256([]byte(p[:len(h64)+1+len(c64)]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Proof{}, refuse("signature does not verify")
	}
	return Proof{JTI: c.JTI, IssuedAt: time.Unix(c.IAT, 0)}, nil
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidProof}, args...)...)
}

// checkHTU checks that htu is an absolute http(s) URL with no query or
// fragment whose path is path. The host is not compared: Warden does not know
// the address its clients use, and the client chooses the Host header anyway.
func checkHTU(htu, path string) error {
	u, err := url.Parse(htu)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return refuse("htu is not an absolute http(s) URL without query or fragment")
	}
	if !EqualPath(u.EscapedPath(), path) {
		return refuse("htu path %q is not the request's %q", u.EscapedPath(), path)
	}
	return nil
}

// RequestPath is the path r's request line carried, escaped, and whether it
// parses: the path a proof's htu is compared with. r.URL's may have been
// rewritten on the way in (the X-Warden-Provider prefix, a role header), and a
// proof signs the client's, so a request line that does not parse is never
// replaced by it. A request no client sent (built in process) has no request
// line, and its URL is its own.
func RequestPath(r *http.Request) (string, bool) {
	if r.RequestURI == "" {
		return r.URL.EscapedPath(), true
	}
	u, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		return "", false
	}
	return u.EscapedPath(), true
}

// EqualPath reports whether the escaped paths a and b name the same path. Only
// the normalisations of RFC 3986 §6.2.2 that never change a route apply: the
// case of a percent-encoding's hex digits, and decoding a percent-encoded
// unreserved character. Nothing else is decoded, since an encoded slash is
// not a slash to Warden's router, and an empty path is "/".
func EqualPath(a, b string) bool {
	return normalizePath(a) == normalizePath(b)
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.Contains(p, "%") {
		return p
	}
	var sb strings.Builder
	sb.Grow(len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c != '%' || i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
			sb.WriteByte(c)
			continue
		}
		v := unhex(p[i+1])<<4 | unhex(p[i+2])
		if isUnreserved(v) {
			sb.WriteByte(v)
		} else {
			const upper = "0123456789ABCDEF"
			sb.WriteByte('%')
			sb.WriteByte(upper[v>>4])
			sb.WriteByte(upper[v&0xf])
		}
		i += 2
	}
	return sb.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// checkContext compares the warden_ctx a proof carries with the request's.
func checkContext(got, want *Context, body bool) error {
	switch {
	case got.Role != want.Role:
		return refuse("warden_ctx role is not the request's")
	case got.Namespace != want.Namespace:
		return refuse("warden_ctx ns is not the request's")
	case got.Provider != want.Provider:
		return refuse("warden_ctx provider is not the request's")
	case got.Request != want.Request:
		return refuse("warden_ctx request is not the request's")
	case got.ContentType != want.ContentType:
		return refuse("warden_ctx content_type is not the request's")
	case got.Query != want.Query:
		return refuse("warden_ctx query is not the request's")
	case body && got.Body != want.Body:
		return refuse("warden_ctx body is not the request's")
	}
	return nil
}

// isCoord reports whether s has the shape of a base64url P-256 coordinate, 32
// bytes, the size of a SHA-256 too.
func isCoord(s string) bool {
	if len(s) != coordLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ValidThumbprint reports whether s has the shape of a key thumbprint: the
// unpadded base64url of a SHA-256.
func ValidThumbprint(s string) bool {
	return isCoord(s)
}

// thumbprint returns the RFC 7638 thumbprint of the P-256 key with base64url
// coordinates x and y: the SHA-256 of its required members in lexicographic
// order, without whitespace. Callers pass coordinates that passed isCoord, so
// nothing in them needs escaping.
func thumbprint(x, y string) string {
	var buf [128]byte
	b := append(buf[:0], `{"crv":"P-256","kty":"EC","x":"`...)
	b = append(b, x...)
	b = append(b, `","y":"`...)
	b = append(b, y...)
	b = append(b, `"}`...)
	return Hash(b)
}

// Key is a client's proof key, a P-256 key pair. It is created per login and
// never leaves the client.
type Key struct {
	priv *ecdsa.PrivateKey
	// header is the encoded JOSE header of every proof under the key.
	header string
	jkt    string
}

// GenerateKey returns a new key.
func GenerateKey() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return newKey(priv)
}

// ParseKey returns the key that Key.Bytes encoded.
func ParseKey(b []byte) (*Key, error) {
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), b)
	if err != nil {
		return nil, fmt.Errorf("not a P-256 private key: %w", err)
	}
	return newKey(priv)
}

func newKey(priv *ecdsa.PrivateKey) (*Key, error) {
	pt, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	x, y := b64.EncodeToString(pt[1:33]), b64.EncodeToString(pt[33:])
	h, err := json.Marshal(header{Typ: typ, Alg: Alg, JWK: &jwk{Kty: "EC", Crv: "P-256", X: x, Y: y}})
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, header: b64.EncodeToString(h), jkt: thumbprint(x, y)}, nil
}

// Bytes encodes k's private key for storage, as ParseKey reads it. The result
// is secret.
func (k *Key) Bytes() ([]byte, error) {
	return k.priv.Bytes()
}

// Thumbprint returns the RFC 7638 thumbprint of k's public key: the jkt of a
// ticket bound to k.
func (k *Key) Thumbprint() string {
	return k.jkt
}

// Claims are what a proof signs.
type Claims struct {
	Method string

	// URL is the request's URL, absolute, without query or fragment.
	URL string

	IssuedAt time.Time

	// ATH is Hash of the ticket the request presents, and Context what the
	// request carries; a login proof sets neither.
	ATH     string
	Context *Context
}

// Sign returns a proof of c under k, with a fresh jti.
func (k *Key) Sign(c Claims) (string, error) {
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims{
		HTM: c.Method,
		HTU: c.URL,
		IAT: c.IssuedAt.Unix(),
		JTI: b64.EncodeToString(jti[:]),
		ATH: c.ATH,
		Ctx: c.Context,
	})
	if err != nil {
		return "", err
	}
	input := k.header + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		return "", err
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64.EncodeToString(sig[:]), nil
}
