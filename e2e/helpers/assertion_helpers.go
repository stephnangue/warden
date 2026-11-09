//go:build e2e

package helpers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// Verifying a Warden-minted identity assertion the way an upstream would: fetch
// the issuer's published JWKS, rebuild the key the token names, and check the
// signature before reading a single claim.
//
// These live here rather than beside one suite's tests because more than one
// federation source is worth driving end to end, and each would otherwise carry
// its own copy of the same JOSE handling. There is no JOSE dependency in the
// tree; this is stdlib throughout, which is why it is worth writing once.

// VerifyAssertion checks a Warden-minted assertion against the issuer's published
// JWKS and returns its claims.
//
// The signature check is not decoration. An upstream that could not verify the
// token would reject it, so a test that decoded the claims without verifying
// could pass on an assertion no real cluster would accept.
//
// leaderPort names the node to fetch the JWKS from. The document is public, so
// any node serves it.
func VerifyAssertion(t *testing.T, leaderPort int, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion is not a three-part JWT (%d parts)", len(parts))
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(DecodeJWTSegment(t, parts[0]), &header); err != nil {
		t.Fatalf("parse assertion header: %v", err)
	}

	key := jwksKey(t, leaderPort, header.Kid, header.Alg)
	signed := parts[0] + "." + parts[1]
	verifyAssertionSignature(t, header.Alg, key, signed, DecodeJWTSegment(t, parts[2]))

	var claims map[string]any
	if err := json.Unmarshal(DecodeJWTSegment(t, parts[1]), &claims); err != nil {
		t.Fatalf("parse assertion claims: %v", err)
	}
	return claims
}

// DecodeJWTSegment decodes one base64url JWT segment.
func DecodeJWTSegment(t *testing.T, segment string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode JWT segment: %v", err)
	}
	return decoded
}

// jwksKey fetches the issuer's published JWKS and rebuilds the key the assertion
// names. Going through the published document rather than any internal handle is
// the point: it is what a cluster would fetch.
func jwksKey(t *testing.T, leaderPort int, kid, alg string) any {
	t.Helper()

	status, body := DoRequest(t, "GET", NodeURL(leaderPort)+"/oidc/jwks", nil, "")
	if status != 200 {
		t.Fatalf("GET /oidc/jwks = %d: %s", status, body)
	}

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse jwks: %v (%s)", err, body)
	}

	for _, k := range doc.Keys {
		if k.Kid != kid {
			continue
		}
		switch k.Kty {
		case "RSA":
			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(DecodeJWTSegment(t, k.N)),
				E: int(new(big.Int).SetBytes(DecodeJWTSegment(t, k.E)).Int64()),
			}
		case "EC":
			return &ecdsa.PublicKey{
				Curve: ecCurve(t, k.Crv),
				X:     new(big.Int).SetBytes(DecodeJWTSegment(t, k.X)),
				Y:     new(big.Int).SetBytes(DecodeJWTSegment(t, k.Y)),
			}
		default:
			t.Fatalf("jwk %s has unsupported kty %q", kid, k.Kty)
		}
	}

	t.Fatalf("assertion names kid %q (alg %s), which the published JWKS does not carry", kid, alg)
	return nil
}

func ecCurve(t *testing.T, crv string) elliptic.Curve {
	t.Helper()
	if crv != "P-256" {
		t.Fatalf("unsupported EC curve %q", crv)
	}
	return elliptic.P256()
}

// verifyAssertionSignature checks the assertion's signature with the published key.
func verifyAssertionSignature(t *testing.T, alg string, key any, signed string, sig []byte) {
	t.Helper()

	digest := sha256.Sum256([]byte(signed))

	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("alg RS256 but the JWKS key is %T", key)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("assertion signature does not verify against the published JWKS: %v", err)
		}
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("alg ES256 but the JWKS key is %T", key)
		}
		// JWS packs ES256 as r||s fixed-width, not as the ASN.1 form ecdsa.Verify
		// would take.
		if len(sig) != 64 {
			t.Fatalf("ES256 signature is %d bytes, want 64", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			t.Fatal("assertion signature does not verify against the published JWKS")
		}
	default:
		t.Fatalf("unsupported assertion alg %q", alg)
	}
}
