package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/logical"
)

func newReadyIssuer(t *testing.T, issuerURL string) *OIDCIssuer {
	t.Helper()
	iss := NewOIDCIssuer(issuerURL)
	key, err := generateSigningKey()
	if err != nil {
		t.Fatalf("generateSigningKey: %v", err)
	}
	iss.SetActiveKey(key)
	return iss
}

// serveJWKS stands up an httptest server returning the issuer's JWKS, so a real
// cap/jwt validator can fetch and verify against it exactly like an upstream STS.
func serveJWKS(t *testing.T, iss *OIDCIssuer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := iss.JWKS()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestOIDCIssuer_Mint_VerifiesAgainstJWKS is the interoperability proof: a minted
// assertion validates against the published JWKS using the same verifier library
// (hashicorp/cap/jwt) an upstream would use, and carries the expected claims.
func TestOIDCIssuer_Mint_VerifiesAgainstJWKS(t *testing.T) {
	const issuerURL = "https://warden-oidc.example.com"
	iss := newReadyIssuer(t, issuerURL)
	jwks := serveJWKS(t, iss)

	te := &logical.TokenEntry{
		PrincipalID:   "spiffe://acme.internal/agent/refund-bot",
		RoleName:      "payments-agent",
		NamespaceID:   "ns-1234",
		NamespacePath: "/acme/prod/",
		MountAccessor: "auth_jwt_abc",
	}
	const audience = "https://sso.acme.internal/realms/acme"

	token, err := iss.MintIdentityAssertion(te, audience, 5*time.Minute)
	if err != nil {
		t.Fatalf("MintIdentityAssertion: %v", err)
	}

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	if err != nil {
		t.Fatalf("NewJSONWebKeySet: %v", err)
	}
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	claims, err := validator.Validate(ctx, token, jwt.Expected{
		Issuer:            issuerURL,
		Audiences:         []string{audience},
		SigningAlgorithms: []jwt.Alg{jwt.RS256},
	})
	if err != nil {
		t.Fatalf("validate minted assertion against JWKS: %v", err)
	}

	if got := claims["sub"]; got != "wid:ns-1234:auth_jwt_abc:spiffe://acme.internal/agent/refund-bot" {
		t.Errorf("sub = %v", got)
	}
	if got := claims["warden_role"]; got != "payments-agent" {
		t.Errorf("warden_role = %v", got)
	}
	if got := claims["warden_namespace"]; got != "/acme/prod/" {
		t.Errorf("warden_namespace = %v", got)
	}
	if got := claims["warden_auth_mount"]; got != "auth_jwt_abc" {
		t.Errorf("warden_auth_mount = %v", got)
	}
}

// TestOIDCIssuer_FailClosed covers the cases where minting must refuse.
func TestOIDCIssuer_FailClosed(t *testing.T) {
	te := &logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}

	// Not ready: no active key.
	notReady := NewOIDCIssuer("https://iss.example")
	if notReady.Ready() {
		t.Fatal("issuer with no key must not be ready")
	}
	if _, err := notReady.MintIdentityAssertion(te, "aud", time.Minute); err == nil {
		t.Error("mint must fail closed when no active key is installed")
	}

	ready := newReadyIssuer(t, "https://iss.example")
	if _, err := ready.MintIdentityAssertion(te, "", time.Minute); err == nil {
		t.Error("mint must fail closed on empty audience")
	}
	if _, err := ready.MintIdentityAssertion(nil, "aud", time.Minute); err == nil {
		t.Error("mint must fail closed on nil token entry")
	}
	if _, err := ready.MintIdentityAssertion(&logical.TokenEntry{}, "aud", time.Minute); err == nil {
		t.Error("mint must fail closed when the principal is empty")
	}
}

// TestOIDCIssuer_KeyStorage_RoundTrip verifies the signing key survives a
// persist/load cycle through a barrier view (so a promoted standby can reload the
// key an active node generated) and still signs a verifiable assertion.
func TestOIDCIssuer_KeyStorage_RoundTrip(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	ctx := context.Background()

	// No key yet -> (nil, nil).
	got, err := loadSigningKey(ctx, storage)
	if err != nil {
		t.Fatalf("loadSigningKey (empty): %v", err)
	}
	if got != nil {
		t.Fatal("expected no signing key before one is persisted")
	}

	original, err := generateSigningKey()
	if err != nil {
		t.Fatalf("generateSigningKey: %v", err)
	}
	if err := persistSigningKey(ctx, storage, original); err != nil {
		t.Fatalf("persistSigningKey: %v", err)
	}

	loaded, err := loadSigningKey(ctx, storage)
	if err != nil {
		t.Fatalf("loadSigningKey: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected a signing key after persist")
	}
	if loaded.kid != original.kid {
		t.Errorf("kid mismatch: got %q want %q", loaded.kid, original.kid)
	}
	if !loaded.key.Equal(original.key) {
		t.Error("loaded private key does not equal the persisted one")
	}

	// The reloaded key mints an assertion that verifies against the same key's JWKS.
	iss := NewOIDCIssuer("https://iss.example")
	iss.SetActiveKey(loaded)
	jwks := serveJWKS(t, iss)
	tok, err := iss.MintIdentityAssertion(&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}, "aud", time.Minute)
	if err != nil {
		t.Fatalf("mint with reloaded key: %v", err)
	}
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	if _, err := validator.Validate(ctx, tok, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from reloaded key must verify: %v", err)
	}
}

// TestOIDCIssuer_Rotation checks that installing a new active key retires the old
// one and both remain in the JWKS so in-flight assertions still verify.
func TestOIDCIssuer_Rotation(t *testing.T) {
	iss := newReadyIssuer(t, "https://iss.example")
	te := &logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}

	// Sign with key 1, then rotate.
	tok1, err := iss.MintIdentityAssertion(te, "aud", 5*time.Minute)
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}

	key2, err := generateSigningKey()
	if err != nil {
		t.Fatalf("generate key 2: %v", err)
	}
	iss.SetActiveKey(key2)

	jwks := serveJWKS(t, iss)
	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	// The assertion signed by the retired key still verifies (overlap window).
	if _, err := validator.Validate(ctx, tok1, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from retired key must still verify during overlap: %v", err)
	}

	// A new assertion signed by the active key verifies too.
	tok2, err := iss.MintIdentityAssertion(te, "aud", 5*time.Minute)
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	if _, err := validator.Validate(ctx, tok2, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from active key must verify: %v", err)
	}
}
