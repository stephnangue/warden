package core

import (
	"strings"
	"testing"
)

func TestSpiffeRoleTokenType_Metadata(t *testing.T) {
	st := &SpiffeRoleTokenType{}
	meta := st.Metadata()
	if meta.Name != "spiffe_role" {
		t.Fatalf("expected name 'spiffe_role', got %q", meta.Name)
	}
	if meta.IDPrefix != "spif_" {
		t.Fatalf("expected IDPrefix 'spif_', got %q", meta.IDPrefix)
	}
	// MUST be empty: a JWT-SVID is also "eyJ...", and jwt_role owns that prefix in
	// the registry. A spiffe credential is routed by mount type, never by prefix.
	if meta.ValuePrefix != "" {
		t.Fatalf("spiffe_role MUST have an empty ValuePrefix, got %q", meta.ValuePrefix)
	}
	if meta.AuthMethodType != "spiffe" {
		t.Fatalf("expected AuthMethodType 'spiffe', got %q", meta.AuthMethodType)
	}
}

func TestSpiffeRoleTokenType_TransparentContract(t *testing.T) {
	st := &SpiffeRoleTokenType{}
	if !st.IsTransparent() {
		t.Fatal("spiffe_role must be transparent")
	}
	if st.CredentialFormat() != "spiffe" {
		t.Fatalf("expected virtual format 'spiffe', got %q", st.CredentialFormat())
	}
	if st.LookupKey() != "spiffe_cred" {
		t.Fatalf("expected lookup key 'spiffe_cred', got %q", st.LookupKey())
	}
}

// A cert fingerprint and a raw JWT must hash to distinct cache keys under the
// single lookup key — this is what lets one spiffe_role serve both SVID types
// without a dual-key generalization.
func TestSpiffeRoleTokenType_FingerprintAndJWTDoNotCollide(t *testing.T) {
	st := &SpiffeRoleTokenType{}
	fingerprint := strings.Repeat("ab", 32) // 64-hex like a SHA-256 fingerprint
	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzcGlmZmU6Ly9leC5vcmcvYSJ9.sig"

	fpHash := st.LookupValue(fingerprint, "acc1", "api")
	jwtHash := st.LookupValue(jwt, "acc1", "api")
	if fpHash == jwtHash {
		t.Fatal("a cert fingerprint and a JWT must produce distinct cache keys")
	}
	if st.ComputeID(fpHash) == st.ComputeID(jwtHash) {
		t.Fatal("a cert login and a JWT login must produce distinct token IDs")
	}
}

func TestSpiffeRoleTokenType_LookupValueDeterministicAndNamespaced(t *testing.T) {
	st := &SpiffeRoleTokenType{}
	h := func(cred, acc, role string) string { return st.LookupValue(cred, acc, role) }

	if h("c", "acc1", "api") != h("c", "acc1", "api") {
		t.Fatal("LookupValue must be deterministic")
	}
	if h("c", "acc1", "api") == h("c", "acc1", "reader") {
		t.Fatal("different roles must produce different hashes")
	}
	if h("c", "accA", "api") == h("c", "accB", "api") {
		t.Fatal("mount accessor must namespace the cache key")
	}
}

func TestSpiffeRoleTokenType_ComputeIDPrefix(t *testing.T) {
	st := &SpiffeRoleTokenType{}
	id := st.ComputeID(st.LookupValue("c", "acc1", "api"))
	if !strings.HasPrefix(id, "spif_") {
		t.Fatalf("token ID must carry the spif_ prefix, got %q", id)
	}
}

func TestSpiffeRoleTokenType_ImplementsTransparentTokenType(t *testing.T) {
	var _ TransparentTokenType = (*SpiffeRoleTokenType)(nil)
}

// The registry must resolve the "spiffe" mount type to spiffe_role so the
// implicit-auth dispatcher and the introspect aggregator find it.
func TestSpiffeRoleTokenType_RegistryWiring(t *testing.T) {
	reg := NewTokenTypeRegistry()
	if err := reg.Register(&SpiffeRoleTokenType{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	tt := reg.GetTransparentTokenTypeForAuthMethod("spiffe")
	if tt == nil {
		t.Fatal("registry did not map mount type 'spiffe' to a transparent token type")
	}
	if tt.CredentialFormat() != "spiffe" {
		t.Fatalf("expected 'spiffe' format, got %q", tt.CredentialFormat())
	}
	// Empty ValuePrefix means it must not be discoverable by value-prefix detection.
	if _, err := reg.DetectType("eyJhbGciOiJFUzI1NiJ9.x.y"); err == nil {
		t.Fatal("a JWT value must not resolve to spiffe_role via DetectType")
	}
}
