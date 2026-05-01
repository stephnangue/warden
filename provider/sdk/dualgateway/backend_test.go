package dualgateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Spec validation tests ---

func TestValidateSpec(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		assert.Error(t, validateSpec(nil))
	})

	t.Run("missing Name", func(t *testing.T) {
		s := *headerAuthSpec
		s.Name = ""
		assert.Contains(t, validateSpec(&s).Error(), "Name")
	})

	t.Run("missing DefaultURL", func(t *testing.T) {
		s := *headerAuthSpec
		s.DefaultURL = ""
		assert.Contains(t, validateSpec(&s).Error(), "DefaultURL")
	})

	t.Run("missing URLConfigKey", func(t *testing.T) {
		s := *headerAuthSpec
		s.URLConfigKey = ""
		assert.Contains(t, validateSpec(&s).Error(), "URLConfigKey")
	})

	t.Run("missing S3Endpoint", func(t *testing.T) {
		s := *headerAuthSpec
		s.S3Endpoint = nil
		assert.Contains(t, validateSpec(&s).Error(), "S3Endpoint")
	})

	t.Run("missing APIAuth.HeaderName", func(t *testing.T) {
		s := *headerAuthSpec
		s.APIAuth.HeaderName = ""
		assert.Contains(t, validateSpec(&s).Error(), "HeaderName")
	})

	t.Run("missing APIAuth.CredentialField", func(t *testing.T) {
		s := *headerAuthSpec
		s.APIAuth.CredentialField = ""
		assert.Contains(t, validateSpec(&s).Error(), "CredentialField")
	})

	t.Run("valid spec", func(t *testing.T) {
		assert.NoError(t, validateSpec(headerAuthSpec))
	})
}

func TestNewFactory_InvalidSpec(t *testing.T) {
	factory := NewFactory(&ProviderSpec{}) // empty spec
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      createTestLogger(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name")
}

// --- Factory tests ---

func TestNewFactory_Defaults(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	assert.Equal(t, "https://api.test.com", b.providerURL)
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize)
	assert.Equal(t, 30*time.Second, b.Timeout)
	assert.NotNil(t, b.s3Signer)
	assert.Equal(t, headerAuthSpec, b.spec)
}

func TestNewFactory_WithConfig(t *testing.T) {
	factory := NewFactory(headerAuthSpec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      createTestLogger(),
		Config: map[string]any{
			"test_url":      "https://custom.test.com",
			"max_body_size": int64(5242880),
			"timeout":       "60s",
		},
	})
	require.NoError(t, err)
	backend := b.(*dualgatewayBackend)
	assert.Equal(t, "https://custom.test.com", backend.providerURL)
	assert.Equal(t, int64(5242880), backend.MaxBodySize)
}

func TestNewFactory_InvalidConfig(t *testing.T) {
	factory := NewFactory(headerAuthSpec)
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      createTestLogger(),
		Config: map[string]any{
			"unknown_key": "value",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown configuration key")
}

// --- TransparentAuthRoleExtractor ---

func TestGetAuthRoleFromRequest(t *testing.T) {
	b := createBackend(t, headerAuthSpec)

	tests := []struct {
		name       string
		authHeader string
		wantRole   string
		wantOK     bool
	}{
		{
			name:       "cert transparent - role name",
			authHeader: "AWS4-HMAC-SHA256 Credential=admin-role/20260410/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
			wantRole:   "admin-role",
			wantOK:     true,
		},
		{
			name:       "JWT transparent - no role",
			authHeader: "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
			wantRole:   "",
			wantOK:     false,
		},
		{
			name:       "non-SigV4",
			authHeader: "Bearer some-token",
			wantRole:   "",
			wantOK:     false,
		},
		{
			name:       "empty header",
			authHeader: "",
			wantRole:   "",
			wantOK:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			role, ok := b.GetAuthRoleFromRequest(r)
			assert.Equal(t, tt.wantRole, role)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

// --- IsSigV4Request detection ---

func TestIsSigV4RequestDetection(t *testing.T) {
	t.Run("SigV4 request", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260410/us-east-1/s3/aws4_request")
		assert.True(t, sigv4.IsSigV4Request(r))
	})

	t.Run("Bearer request", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer some-token")
		assert.False(t, sigv4.IsSigV4Request(r))
	})

	t.Run("no auth header", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		assert.False(t, sigv4.IsSigV4Request(r))
	})
}

// --- OnConfigParsed / extraState ---

func TestNewFactory_OnConfigParsed(t *testing.T) {
	spec := &ProviderSpec{
		Name: "stateful", HelpText: "h", CredentialType: "c",
		DefaultURL: "https://x.com", URLConfigKey: "stateful_url",
		DefaultTimeout:  30e9, UserAgent: "u",
		APIAuth:         APIAuthStrategy{HeaderName: "X", HeaderValueFormat: "%s", CredentialField: "k"},
		S3Endpoint:      func(state map[string]any, r string) string { return state["account_id"].(string) + "." + r },
		ExtraConfigKeys: []string{"account_id"},
		OnConfigParsed: func(config map[string]any) map[string]any {
			state := map[string]any{}
			if v, ok := config["account_id"].(string); ok {
				state["account_id"] = v
			}
			return state
		},
	}

	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      createTestLogger(),
		Config: map[string]any{
			"account_id": "abc123",
		},
	})
	require.NoError(t, err)
	backend := b.(*dualgatewayBackend)
	assert.Equal(t, "abc123", backend.extraState["account_id"])
}

func TestNewFactory_NoOnConfigParsed(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	assert.Nil(t, b.extraState)
}

// --- SensitiveConfigFields ---

func TestSensitiveConfigFields(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	assert.Contains(t, b.SensitiveConfigFields(), "ca_data")
}

// --- Paths ---

func TestPaths(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)
}
