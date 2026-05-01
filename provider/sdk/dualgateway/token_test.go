package dualgateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "X-Warden-Token",
			headers:  map[string]string{"X-Warden-Token": "my-token"},
			expected: "my-token",
		},
		{
			name:     "Bearer token",
			headers:  map[string]string{"Authorization": "Bearer my-jwt"},
			expected: "my-jwt",
		},
		{
			name:     "SigV4 with JWT access key",
			headers:  map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123"},
			expected: "eyJhbGciOiJSUzI1NiJ9",
		},
		{
			name:     "SigV4 with role name",
			headers:  map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=my-role/20260410/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123"},
			expected: "my-role",
		},
		{
			name:     "no auth headers",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "X-Warden-Token takes precedence over Bearer",
			headers:  map[string]string{"X-Warden-Token": "warden-token", "Authorization": "Bearer other"},
			expected: "warden-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			assert.Equal(t, tt.expected, extractToken(r))
		})
	}
}
