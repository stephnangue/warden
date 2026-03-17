package core

import (
	"context"
	"testing"
)

func TestCertRoleTokenType_Metadata(t *testing.T) {
	ct := &CertRoleTokenType{}
	meta := ct.Metadata()

	if meta.Name != "cert_role" {
		t.Fatalf("expected name 'cert_role', got %q", meta.Name)
	}
	if meta.IDPrefix != "cert_" {
		t.Fatalf("expected IDPrefix 'cert_', got %q", meta.IDPrefix)
	}
	if meta.ValuePrefix != "" {
		t.Fatalf("expected empty ValuePrefix, got %q", meta.ValuePrefix)
	}
}

func TestCertRoleTokenType_ComputeData(t *testing.T) {
	ct := &CertRoleTokenType{}

	// With role
	hash1 := ct.ComputeData("fingerprint123", "admin")
	hash2 := ct.ComputeData("fingerprint123", "admin")
	if hash1 != hash2 {
		t.Fatal("ComputeData should be deterministic")
	}

	// Different roles should produce different hashes
	hash3 := ct.ComputeData("fingerprint123", "reader")
	if hash1 == hash3 {
		t.Fatal("different roles should produce different hashes")
	}

	// Different fingerprints should produce different hashes
	hash4 := ct.ComputeData("fingerprint456", "admin")
	if hash1 == hash4 {
		t.Fatal("different fingerprints should produce different hashes")
	}

	// Without role
	hash5 := ct.ComputeData("fingerprint123", "")
	if hash5 == hash1 {
		t.Fatal("empty role should produce different hash from non-empty role")
	}
}

func TestCertRoleTokenType_ComputeID(t *testing.T) {
	ct := &CertRoleTokenType{}

	id := ct.ComputeID("somehash")
	if len(id) == 0 {
		t.Fatal("ComputeID should return non-empty ID")
	}
	if id[:5] != "cert_" {
		t.Fatalf("expected 'cert_' prefix, got %q", id[:5])
	}

	// Deterministic
	id2 := ct.ComputeID("somehash")
	if id != id2 {
		t.Fatal("ComputeID should be deterministic")
	}

	// Different input → different ID
	id3 := ct.ComputeID("differenthash")
	if id == id3 {
		t.Fatal("different inputs should produce different IDs")
	}
}

func TestCertRoleTokenType_LookupKey(t *testing.T) {
	ct := &CertRoleTokenType{}
	if ct.LookupKey() != "cert_fingerprint" {
		t.Fatalf("expected 'cert_fingerprint', got %q", ct.LookupKey())
	}
}

func TestCertRoleTokenType_ValidateValue(t *testing.T) {
	ct := &CertRoleTokenType{}
	// Cert tokens always pass validation (no bearer token to check)
	if !ct.ValidateValue("anything") {
		t.Fatal("ValidateValue should always return true for cert tokens")
	}
	if !ct.ValidateValue("") {
		t.Fatal("ValidateValue should return true even for empty string")
	}
}

func TestCertRoleTokenType_Generate(t *testing.T) {
	ct := &CertRoleTokenType{}

	// With authData
	entry := &TokenEntry{Data: make(map[string]string)}
	authData := &AuthData{
		TokenValue: "abc123fingerprint",
		RoleName:   "agent",
	}

	result, err := ct.Generate(context.Background(), authData, entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fingerprint, ok := result["cert_fingerprint"]
	if !ok {
		t.Fatal("expected cert_fingerprint in result")
	}
	if fingerprint == "" {
		t.Fatal("expected non-empty cert_fingerprint")
	}

	// Verify it matches ComputeData
	expected := ct.ComputeData("abc123fingerprint", "agent")
	if fingerprint != expected {
		t.Fatalf("expected %q, got %q", expected, fingerprint)
	}

	// Without authData
	entry2 := &TokenEntry{Data: map[string]string{"existing": "data"}}
	result2, err := ct.Generate(context.Background(), nil, entry2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result2["cert_fingerprint"]; ok {
		t.Fatal("should not set cert_fingerprint when authData is nil")
	}

	// With empty TokenValue
	entry3 := &TokenEntry{Data: make(map[string]string)}
	authData3 := &AuthData{TokenValue: "", RoleName: "agent"}
	result3, err := ct.Generate(context.Background(), authData3, entry3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result3["cert_fingerprint"]; ok {
		t.Fatal("should not set cert_fingerprint when TokenValue is empty")
	}
}

func TestCertRoleTokenType_RegisteredInRegistry(t *testing.T) {
	registry := NewTokenTypeRegistry()
	err := registry.Register(&CertRoleTokenType{})
	if err != nil {
		t.Fatalf("failed to register cert_role type: %v", err)
	}

	tokenType, err := registry.GetByName("cert_role")
	if err != nil {
		t.Fatalf("failed to look up cert_role type: %v", err)
	}

	if tokenType.Metadata().Name != "cert_role" {
		t.Fatalf("expected name 'cert_role', got %q", tokenType.Metadata().Name)
	}

	// cert_role has no ValuePrefix, so DetectType won't find it
	_, err = registry.DetectType("some-value")
	if err == nil {
		t.Fatal("expected error from DetectType with no matching prefix")
	}
}

func TestCertRoleTokenType_EndToEndIDComputation(t *testing.T) {
	ct := &CertRoleTokenType{}

	fingerprint := "a1b2c3d4e5f6"
	role := "agent"

	// This simulates the full flow: Generate stores hash, ComputeID creates the ID
	hash := ct.ComputeData(fingerprint, role)
	tokenID := ct.ComputeID(hash)

	// Verify the same computation in LookupCertTokenWithRole would produce the same ID
	hash2 := ct.ComputeData(fingerprint, role)
	tokenID2 := ct.ComputeID(hash2)

	if tokenID != tokenID2 {
		t.Fatalf("ID computation should be deterministic: %q != %q", tokenID, tokenID2)
	}
}
