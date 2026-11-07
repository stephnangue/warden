package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

var testNow = time.Unix(1_800_000_000, 0)

func testKey(t testing.TB) *Key {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testContext() *Context {
	return &Context{
		Role:      "warden-viewer",
		Namespace: "team-a",
		Query:     Hash([]byte("a=1")),
		Body:      Hash([]byte(`{"x":1}`)),
	}
}

func testClaims() Claims {
	return Claims{
		Method:   "POST",
		URL:      "https://warden.example/v1/sys/policies/acl/team",
		IssuedAt: testNow,
		ATH:      Hash([]byte("wdt.ticket")),
		Context:  testContext(),
	}
}

func testWant(k *Key) *Want {
	return &Want{
		JKT:     k.Thumbprint(),
		Method:  "POST",
		Path:    "/v1/sys/policies/acl/team",
		Now:     testNow,
		ATH:     Hash([]byte("wdt.ticket")),
		Context: testContext(),
		Body:    true,
	}
}

func sign(t testing.TB, k *Key, c Claims) string {
	t.Helper()
	p, err := k.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// signRaw signs header and payload, given as JSON, under k's private key,
// whatever they say.
func signRaw(t testing.TB, k *Key, header, payload string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig[:])
}

func jwkJSON(t testing.TB, k *Key) map[string]any {
	t.Helper()
	hb, err := base64.RawURLEncoding.DecodeString(k.header)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}
	return h["jwk"].(map[string]any)
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func claimsJSON(t testing.TB, edit func(map[string]any)) string {
	t.Helper()
	m := map[string]any{
		"htm":        "POST",
		"htu":        "https://warden.example/v1/sys/policies/acl/team",
		"iat":        testNow.Unix(),
		"jti":        "j1",
		"ath":        Hash([]byte("wdt.ticket")),
		"warden_ctx": testContext(),
	}
	if edit != nil {
		edit(m)
	}
	return mustJSON(t, m)
}

func TestVerifyAccepts(t *testing.T) {
	k := testKey(t)
	p, err := Verify([]string{sign(t, k, testClaims())}, testWant(k))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.JTI == "" || !p.IssuedAt.Equal(testNow) {
		t.Fatalf("proof = %+v", p)
	}
}

func TestVerifyFreshJTI(t *testing.T) {
	k := testKey(t)
	a, _ := Verify([]string{sign(t, k, testClaims())}, testWant(k))
	b, _ := Verify([]string{sign(t, k, testClaims())}, testWant(k))
	if a.JTI == b.JTI {
		t.Fatalf("two proofs share jti %q", a.JTI)
	}
}

func TestVerifyLoginProof(t *testing.T) {
	k := testKey(t)
	c := testClaims()
	c.ATH, c.Context = "", nil
	want := testWant(k)
	want.ATH, want.Context = "", nil
	if _, err := Verify([]string{sign(t, k, c)}, want); err != nil {
		t.Fatalf("login proof: %v", err)
	}
}

func TestVerifyWindow(t *testing.T) {
	k := testKey(t)
	for _, d := range []time.Duration{-Window, Window} {
		c := testClaims()
		c.IssuedAt = testNow.Add(d)
		if _, err := Verify([]string{sign(t, k, c)}, testWant(k)); err != nil {
			t.Errorf("iat %v from arrival: %v", d, err)
		}
	}
	for _, d := range []time.Duration{-Window - time.Second, Window + time.Second} {
		c := testClaims()
		c.IssuedAt = testNow.Add(d)
		if _, err := Verify([]string{sign(t, k, c)}, testWant(k)); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("iat %v from arrival: err = %v, want refused", d, err)
		}
	}
}

func TestVerifyStreamingBodyNotCompared(t *testing.T) {
	k := testKey(t)
	c := testClaims()
	c.Context.Body = Hash([]byte("other"))
	want := testWant(k)
	want.Body = false
	if _, err := Verify([]string{sign(t, k, c)}, want); err != nil {
		t.Fatalf("streaming body: %v", err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	k := testKey(t)
	other := testKey(t)
	good := sign(t, k, testClaims())
	h64, rest, _ := strings.Cut(good, ".")
	c64, s64, _ := strings.Cut(rest, ".")
	jwkOf := jwkJSON(t, k)
	hdr := func(edit func(map[string]any)) string {
		m := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkOf}
		if edit != nil {
			edit(m)
		}
		return mustJSON(t, m)
	}
	ctxWith := func(edit func(*Context)) func(map[string]any) {
		return func(m map[string]any) {
			c := testContext()
			edit(c)
			m["warden_ctx"] = c
		}
	}

	// An off-curve point under a binding to it, so only the curve check can
	// refuse it.
	pt, _ := k.priv.PublicKey.Bytes()
	pt[64] ^= 1
	offX, offY := b64.EncodeToString(pt[1:33]), b64.EncodeToString(pt[33:])
	offCurve := signRaw(t, k, hdr(func(m map[string]any) {
		m["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": offX, "y": offY}
	}), claimsJSON(t, nil))

	tamperedSig := []byte(s64)
	if tamperedSig[0] == 'A' {
		tamperedSig[0] = 'B'
	} else {
		tamperedSig[0] = 'A'
	}

	cases := []struct {
		name   string
		values []string
		want   func(*Want)
	}{
		{name: "no proof", values: nil},
		{name: "two proofs", values: []string{good, good}},
		{name: "too long", values: []string{good + strings.Repeat("A", MaxProofLen)}},
		{name: "two segments", values: []string{h64 + "." + c64}},
		{name: "four segments", values: []string{good + ".x"}},
		{name: "line break", values: []string{h64 + "\n." + c64 + "." + s64}},
		{name: "padded header", values: []string{h64 + "=." + c64 + "." + s64}},
		{name: "standard base64 payload", values: []string{h64 + "." + strings.ReplaceAll(c64, "-", "+") + "+." + s64}},
		{name: "short signature", values: []string{h64 + "." + c64 + "." + s64[:85]}},
		{name: "tampered signature", values: []string{h64 + "." + c64 + "." + string(tamperedSig)}},
		{name: "typ jwt", values: []string{signRaw(t, k, hdr(func(m map[string]any) { m["typ"] = "JWT" }), claimsJSON(t, nil))}},
		{name: "alg none", values: []string{signRaw(t, k, hdr(func(m map[string]any) { m["alg"] = "none" }), claimsJSON(t, nil))}},
		{name: "alg HS256", values: []string{signRaw(t, k, hdr(func(m map[string]any) { m["alg"] = "HS256" }), claimsJSON(t, nil))}},
		{name: "crit", values: []string{signRaw(t, k, hdr(func(m map[string]any) { m["crit"] = []string{"exp"} }), claimsJSON(t, nil))}},
		{name: "no jwk", values: []string{signRaw(t, k, hdr(func(m map[string]any) { delete(m, "jwk") }), claimsJSON(t, nil))}},
		{name: "private jwk", values: []string{signRaw(t, k, hdr(func(m map[string]any) {
			j := map[string]any{"d": "AAAA"}
			for k, v := range jwkOf {
				j[k] = v
			}
			m["jwk"] = j
		}), claimsJSON(t, nil))}},
		{name: "P-384 jwk", values: []string{signRaw(t, k, hdr(func(m map[string]any) {
			j := map[string]any{}
			for k, v := range jwkOf {
				j[k] = v
			}
			j["crv"] = "P-384"
			m["jwk"] = j
		}), claimsJSON(t, nil))}},
		{name: "off-curve point", values: []string{offCurve}, want: func(w *Want) { w.JKT = thumbprint(offX, offY) }},
		{name: "another key", values: []string{sign(t, other, testClaims())}},
		{name: "wrong htm", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htm"] = "PUT" }))}},
		{name: "wrong htu path", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htu"] = "https://warden.example/v1/sys/policies/acl/other" }))}},
		{name: "htu path suffix", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htu"] = "https://warden.example/acl/team" }))}},
		{name: "htu query", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htu"] = "https://warden.example/v1/sys/policies/acl/team?x=1" }))}},
		{name: "htu fragment", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htu"] = "https://warden.example/v1/sys/policies/acl/team#f" }))}},
		{name: "htu relative", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htu"] = "/v1/sys/policies/acl/team" }))}},
		{name: "htu ftp", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["htu"] = "ftp://warden.example/v1/sys/policies/acl/team" }))}},
		{name: "wrong ath", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["ath"] = Hash([]byte("wdt.other")) }))}},
		{name: "no ath", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { delete(m, "ath") }))}},
		{name: "float iat", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["iat"] = 1.8e9 + 0.5 }))}},
		{name: "no jti", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { delete(m, "jti") }))}},
		{name: "long jti", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { m["jti"] = strings.Repeat("j", MaxJTILen+1) }))}},
		{name: "no warden_ctx", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, func(m map[string]any) { delete(m, "warden_ctx") }))}},
		{name: "ctx role", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Role = "warden-admin" })))}},
		{name: "ctx ns", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Namespace = "team-b" })))}},
		{name: "ctx provider", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Provider = "vault" })))}},
		{name: "ctx request", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Request = "list" })))}},
		{name: "ctx content_type", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.ContentType = "text/plain" })))}},
		{name: "ctx query", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Query = Hash([]byte("a=2")) })))}},
		{name: "ctx body", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Body = Hash([]byte(`{"x":2}`)) })))}},
		{name: "ctx body missing", values: []string{signRaw(t, k, hdr(nil), claimsJSON(t, ctxWith(func(c *Context) { c.Body = "" })))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := testWant(k)
			if tc.want != nil {
				tc.want(want)
			}
			if _, err := Verify(tc.values, want); !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("err = %v, want ErrInvalidProof", err)
			}
		})
	}
}

func TestEqualPath(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"/v1/sys/mounts", "/v1/sys/mounts", true},
		{"", "/", true},
		{"/a%2Fb", "/a/b", false},
		{"/a%2fb", "/a%2Fb", true},
		{"/%7Euser", "/~user", true},
		{"/%41", "/A", true},
		{"/a%20b", "/a%20b", true},
		{"/a%2", "/a%2", true},
		{"/v1/secret", "/v1/vault/role/r/gateway/v1/secret", false},
		{"/v1/x/", "/v1/x", false},
	} {
		if got := EqualPath(tc.a, tc.b); got != tc.want {
			t.Errorf("EqualPath(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVerifyHTUHostIgnored(t *testing.T) {
	k := testKey(t)
	c := testClaims()
	c.URL = "http://10.0.0.7:8400/v1/sys/policies/acl/team"
	if _, err := Verify([]string{sign(t, k, c)}, testWant(k)); err != nil {
		t.Fatalf("another host: %v", err)
	}
}

func TestParseKeyRoundTrip(t *testing.T) {
	k := testKey(t)
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Thumbprint() != k.Thumbprint() {
		t.Fatal("thumbprint changed across Bytes and ParseKey")
	}
	if _, err := Verify([]string{sign(t, k2, testClaims())}, testWant(k)); err != nil {
		t.Fatalf("proof under the parsed key: %v", err)
	}
	if _, err := ParseKey([]byte("short")); err == nil {
		t.Fatal("ParseKey accepted a malformed key")
	}
}

// go-jose is an independent implementation of JWS and RFC 7638: proofs it
// signs must verify, and proofs Sign makes must verify under it.
func TestCrossCheckGoJose(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := newKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	tp, err := (&jose.JSONWebKey{Key: &priv.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(tp); got != k.Thumbprint() {
		t.Fatalf("thumbprint %q, go-jose %q", k.Thumbprint(), got)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte(claimsJSON(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify([]string{proof}, testWant(k)); err != nil {
		t.Fatalf("go-jose proof: %v", err)
	}

	jws, err := jose.ParseSigned(sign(t, k, testClaims()), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	h := jws.Signatures[0].Header
	if h.ExtraHeaders["typ"] != "dpop+jwt" || h.JSONWebKey == nil {
		t.Fatalf("header = %+v", h)
	}
	if _, err := jws.Verify(h.JSONWebKey); err != nil {
		t.Fatalf("go-jose rejects Sign's proof: %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	k := testKey(f)
	f.Add(sign(f, k, testClaims()))
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, p string) {
		_, _ = Verify([]string{p}, testWant(k))
	})
}

func BenchmarkVerify(b *testing.B) {
	k := testKey(b)
	values := []string{sign(b, k, testClaims())}
	want := testWant(k)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Verify(values, want); err != nil {
			b.Fatal(err)
		}
	}
}
