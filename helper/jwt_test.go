package helper

import (
	"encoding/base64"
	"strings"
	"testing"
)

// mintJWT returns a JWT with the given JSON payload and a fixed bogus
// signature. Header is the standard {"alg":"RS256","typ":"JWT"} encoded.
// Signature is not validated by ParseJWTClaimsUnverified.
func mintJWT(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signature := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payload + "." + signature
}

func TestParseJWTClaimsUnverified(t *testing.T) {
	t.Run("kubernetes SA token shape", func(t *testing.T) {
		tok := mintJWT(`{"iss":"https://kubernetes.default.svc","sub":"system:serviceaccount:default:myapp","aud":["api"]}`)
		claims, err := ParseJWTClaimsUnverified(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, _ := claims["iss"].(string); got != "https://kubernetes.default.svc" {
			t.Fatalf("iss: got %q", got)
		}
		if got, _ := claims["sub"].(string); got != "system:serviceaccount:default:myapp" {
			t.Fatalf("sub: got %q", got)
		}
	})

	t.Run("generic OIDC JWT shape", func(t *testing.T) {
		tok := mintJWT(`{"iss":"https://accounts.google.com","sub":"1234567890","email":"u@example.com"}`)
		claims, err := ParseJWTClaimsUnverified(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, _ := claims["sub"].(string); got != "1234567890" {
			t.Fatalf("sub: got %q", got)
		}
		if strings.HasPrefix(claims["sub"].(string), "system:serviceaccount:") {
			t.Fatal("generic JWT must not look like a K8s SA token")
		}
	})

	t.Run("not three segments", func(t *testing.T) {
		_, err := ParseJWTClaimsUnverified("not.a.jwt.four.segments")
		if err == nil {
			t.Fatal("expected error for wrong segment count")
		}
	})

	t.Run("payload not base64url", func(t *testing.T) {
		_, err := ParseJWTClaimsUnverified("header.!!!.signature")
		if err == nil {
			t.Fatal("expected error for invalid base64 payload")
		}
	})

	t.Run("payload not JSON", func(t *testing.T) {
		tok := "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature"
		_, err := ParseJWTClaimsUnverified(tok)
		if err == nil {
			t.Fatal("expected error for non-JSON payload")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseJWTClaimsUnverified("")
		if err == nil {
			t.Fatal("expected error for empty token")
		}
	})
}
