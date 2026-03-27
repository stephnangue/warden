package aws

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
)

func TestExtractToken_JWTTransparent(t *testing.T) {
	// JWT in X-Amz-Security-Token → return JWT
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=my-role/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig")

	token := extractToken(r)
	if token != "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig" {
		t.Errorf("expected JWT, got %q", token)
	}
}

func TestExtractToken_CertTransparent(t *testing.T) {
	// No JWT in X-Amz-Security-Token → return access_key_id (role name)
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=my-service-role/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")

	token := extractToken(r)
	if token != "my-service-role" {
		t.Errorf("expected role name, got %q", token)
	}
}

func TestExtractToken_RegularMode(t *testing.T) {
	// AKIA access_key_id → return Warden token
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")

	token := extractToken(r)
	if token != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected AKIA token, got %q", token)
	}
}

func TestExtractToken_RealAWSSecurityToken(t *testing.T) {
	// Real AWS security token (not JWT) → return access_key_id, not the security token
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
	r.Header.Set("X-Amz-Security-Token", "IQoJb3JpZ2luX2VjEBkaCXVzLWVhc3QtMQ==")

	token := extractToken(r)
	if token != "ASIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected access_key_id, got %q", token)
	}
}

func TestExtractToken_NoAuthHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)

	token := extractToken(r)
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}
}

func TestGetAuthRoleFromRequest_RoleName(t *testing.T) {
	b := &awsBackend{}

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=my-role/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")

	role, ok := b.GetAuthRoleFromRequest(r)
	if !ok {
		t.Fatal("expected ok=true for role name")
	}
	if role != "my-role" {
		t.Errorf("expected role 'my-role', got %q", role)
	}
}

func TestGetAuthRoleFromRequest_AKIAPrefix(t *testing.T) {
	b := &awsBackend{}

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")

	_, ok := b.GetAuthRoleFromRequest(r)
	if ok {
		t.Fatal("expected ok=false for AKIA prefix (explicit auth)")
	}
}

func TestGetAuthRoleFromRequest_ASIAPrefix(t *testing.T) {
	// ASIA = STS temporary credentials, also Warden-compatible
	b := &awsBackend{}

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ASIAIOSFODNN7EXAMPLE/20260326/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")

	role, ok := b.GetAuthRoleFromRequest(r)
	if !ok {
		t.Fatal("expected ok=true for ASIA prefix (not AKIA)")
	}
	if role != "ASIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected role 'ASIAIOSFODNN7EXAMPLE', got %q", role)
	}
}

func TestGetAuthRoleFromRequest_NoAuthHeader(t *testing.T) {
	b := &awsBackend{}

	r, _ := http.NewRequest("GET", "/", nil)

	_, ok := b.GetAuthRoleFromRequest(r)
	if ok {
		t.Fatal("expected ok=false for missing auth header")
	}
}

func TestValidateConfig_TransparentFields(t *testing.T) {
	// Transparent mode fields should be allowed
	err := ValidateConfig(map[string]any{
		"transparent_mode": true,
		"auto_auth_path":   "auth/jwt/",
		"default_role":     "my-role",
	})
	if err != nil {
		t.Errorf("expected no error for transparent config, got: %v", err)
	}
}

func TestTransparentConfig_SetAndRead(t *testing.T) {
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{},
		},
	}

	b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
		Enabled:         true,
		AutoAuthPath:    "auth/jwt/",
		DefaultAuthRole: "default-role",
	})

	if !b.StreamingBackend.IsTransparentMode() {
		t.Error("expected transparent mode to be enabled")
	}
	if b.StreamingBackend.GetAutoAuthPath() != "auth/jwt/" {
		t.Errorf("expected auto_auth_path 'auth/jwt/', got %q", b.StreamingBackend.GetAutoAuthPath())
	}
}
