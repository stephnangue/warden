package audit

import (
	"context"
	"testing"
)

func TestHMACSalting(t *testing.T) {
	hmacer := NewHMACer("test-secret-key")

	input := "my-secret-token"
	salted, err := hmacer.Salt(context.Background(), input)
	if err != nil {
		t.Fatalf("Failed to salt data: %v", err)
	}

	// Check that salted value is different from input
	if salted == input {
		t.Error("Salted value should be different from input")
	}

	// Check that it has the correct prefix
	if len(salted) < 12 || salted[:12] != "hmac-sha256:" {
		t.Error("Salted value should have 'hmac-sha256:' prefix")
	}

	// Check that same input produces same output
	salted2, _ := hmacer.Salt(context.Background(), input)
	if salted != salted2 {
		t.Error("Same input should produce same salted output")
	}
}

func TestHMACerSaltFunc(t *testing.T) {
	h := NewHMACer("test-key")
	fn := h.SaltFunc()

	result, err := fn(context.Background(), "hello")
	if err != nil {
		t.Fatalf("SaltFunc failed: %v", err)
	}
	if result == "" || result == "hello" {
		t.Error("expected salted output")
	}
	if !containsSubstring(result, "hmac-sha256:") {
		t.Error("expected hmac-sha256: prefix")
	}

	// Empty string
	result, err = fn(context.Background(), "")
	if err != nil {
		t.Fatalf("SaltFunc empty failed: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty for empty input, got %s", result)
	}
}
