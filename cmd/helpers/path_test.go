package helpers

import (
	"errors"
	"testing"
)

func TestValidatePath_Valid(t *testing.T) {
	valid := []string{
		"aws/config",
		"auth/jwt/config",
		"auth/jwt/role/developer",
		"sys/mounts",
		"sys/policies/admin",
		"sys/cred/sources/my-aws",
		"sys/cred/specs/vault-token-reader",
		"some-mount/with-hyphens/and_underscores",
		"a",
		"a/b/c/d/e/f/g",
		"with.dots/in.segments",
		"sys/policies/cbp/policy.with.dots",
	}
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) returned error: %v; want nil", p, err)
		}
	}
}

func TestValidatePath_Invalid(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"only spaces", "   "},
		{"leading whitespace", " aws/config"},
		{"trailing whitespace", "aws/config "},
		{"trailing newline", "aws/config\n"},
		{"leading slash", "/aws/config"},
		{"absolute root", "/"},
		{"traversal at root", "../etc/passwd"},
		{"traversal in middle", "aws/../sys/health"},
		{"traversal at end", "aws/config/.."},
		{"null byte", "aws/config\x00malicious"},
		{"control char SOH", "aws/\x01bad"},
		{"DEL byte", "aws/config\x7f"},
		{"newline embedded", "aws/config\nfoo"},
		{"tab embedded", "aws/\tconfig"},
		{"question mark", "aws/config?warden-help=1"},
		{"hash fragment", "aws/config#section"},
		{"percent literal", "aws/config%foo"},
		{"percent-encoded slash", "aws%2Fconfig"},
		{"percent-encoded null", "foo%00"},
		{"percent-encoded space", "foo%20bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if err == nil {
				t.Fatalf("ValidatePath(%q) returned nil; want error", tt.path)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("ValidatePath(%q) error = %v; want errors.Is(err, ErrInvalidInput)", tt.path, err)
			}
		})
	}
}

func TestValidatePath_ErrorMentionsInputForAgentDebugging(t *testing.T) {
	// Agents need the offending input echoed back so they can correct it.
	// Confirm that the error message contains the offending path verbatim.
	err := ValidatePath("../etc/passwd")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !contains(msg, "../etc/passwd") {
		t.Errorf("error message %q does not contain offending path; agent recovery becomes harder", msg)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- ValidateHeaderValue: HTTP header injection prevention ---

func TestValidateHeaderValue_Empty(t *testing.T) {
	// Empty is allowed — caller treats it as absent header.
	if err := ValidateHeaderValue("--namespace", ""); err != nil {
		t.Errorf("ValidateHeaderValue(empty) returned %v; want nil", err)
	}
}

func TestValidateHeaderValue_Valid(t *testing.T) {
	for _, v := range []string{"my-team", "engineering/sre", "tenant_42", "ns.with.dots"} {
		if err := ValidateHeaderValue("--namespace", v); err != nil {
			t.Errorf("ValidateHeaderValue(%q) returned %v; want nil", v, err)
		}
	}
}

func TestValidateHeaderValue_RejectsCRLFAndControlChars(t *testing.T) {
	tests := []struct {
		name string
		v    string
	}{
		{"CR injection", "ns\rX-Evil: true"},
		{"LF injection", "ns\nX-Evil: true"},
		{"CRLF injection", "ns\r\nX-Evil: true"},
		{"null byte", "ns\x00x"},
		{"tab", "ns\tx"},
		{"DEL", "ns\x7f"},
		{"leading whitespace", " ns"},
		{"trailing whitespace", "ns "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaderValue("--namespace", tt.v)
			if err == nil {
				t.Fatalf("ValidateHeaderValue(%q) returned nil; want error", tt.v)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("ValidateHeaderValue(%q) error = %v; want errors.Is(err, ErrInvalidInput)", tt.v, err)
			}
		})
	}
}

// --- ValidateIdentifier: single-segment flag values like --type ---

func TestValidateIdentifier_Valid(t *testing.T) {
	for _, v := range []string{"aws", "vault", "azure", "ovh-storage", "type_42", "type.subtype"} {
		if err := ValidateIdentifier("--type", v); err != nil {
			t.Errorf("ValidateIdentifier(%q) returned %v; want nil", v, err)
		}
	}
}

func TestValidateIdentifier_Invalid(t *testing.T) {
	tests := []struct {
		name string
		v    string
	}{
		{"empty", ""},
		{"slash", "aws/config"},
		{"leading slash", "/aws"},
		{"control char", "aws\x01"},
		{"null", "aws\x00"},
		{"DEL", "aws\x7f"},
		{"question mark", "aws?"},
		{"hash", "aws#frag"},
		{"percent", "aws%20"},
		{"leading space", " aws"},
		{"trailing space", "aws "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIdentifier("--type", tt.v)
			if err == nil {
				t.Fatalf("ValidateIdentifier(%q) returned nil; want error", tt.v)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("ValidateIdentifier(%q) error = %v; want errors.Is(err, ErrInvalidInput)", tt.v, err)
			}
		})
	}
}
