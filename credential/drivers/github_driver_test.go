package drivers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestRSAKey generates a PEM-encoded RSA private key for testing
func generateTestRSAKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

func TestGitHubDriverFactory_Type(t *testing.T) {
	factory := &GitHubDriverFactory{}
	assert.Equal(t, credential.SourceTypeGitHub, factory.Type())
}

func TestGitHubDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &GitHubDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Nil(t, fields, "source has no secrets — they live in the spec")
}

func TestGitHubDriverFactory_ValidateConfig(t *testing.T) {
	factory := &GitHubDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default github_url",
			config:  map[string]string{},
			wantErr: false,
		},
		{
			name:    "valid explicit github_url",
			config:  map[string]string{"github_url": "https://api.github.com"},
			wantErr: false,
		},
		{
			name:    "valid GHE URL",
			config:  map[string]string{"github_url": "https://github.example.com/api/v3"},
			wantErr: false,
		},
		{
			name:    "invalid github_url scheme",
			config:  map[string]string{"github_url": "http://api.github.com"},
			wantErr: true,
			errMsg:  "must use https://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGitHubDriverFactory_Create(t *testing.T) {
	factory := &GitHubDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := factory.Create(map[string]string{
		"github_url": "https://api.github.com",
	}, log)
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeGitHub, driver.Type())
}

func TestGitHubDriver_Type(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeGitHub, driver.Type())
}

func TestGitHubDriver_Cleanup(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestGitHubDriver_Revoke_NoOp(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{},
		},
	}
	// GitHub tokens expire naturally - revoke is a no-op
	err := driver.Revoke(context.Background(), "any-lease-id")
	assert.NoError(t, err)

	err = driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestGitHubDriver_NotRotatable(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{},
		},
	}
	// GitHubDriver should not implement Rotatable
	var sd credential.SourceDriver = driver
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "GitHubDriver should not implement credential.Rotatable")
}

func TestGitHubDriver_MintPATCredential(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": "https://api.github.com"},
		},
		appTokens: make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-pat",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method": "pat",
			"token":       "ghp_test123",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghp_test123", rawData["token"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID)
}

func TestGitHubDriver_MintPATCredential_EmptyToken(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": "https://api.github.com"},
		},
		appTokens: make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-pat",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method": "pat",
			"token":       "",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GitHub PAT configured")
}

func TestGitHubDriver_MintCredential_UnsupportedAuthMethod(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": "https://api.github.com"},
		},
		appTokens: make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method": "unknown",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth_method")
}

func TestGitHubDriver_MintAppCredential(t *testing.T) {
	testKey := generateTestRSAKey(t)

	// Mock server to return installation token
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/app/installations/67890/access_tokens")
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))

		expiresAt := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_installation_token_123",
			"expires_at": expiresAt,
		})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": server.URL},
		},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-app",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	rawData, ttl, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghs_installation_token_123", rawData["token"])
	assert.NotEmpty(t, rawData["expires_at"])
	assert.True(t, ttl > 0, "TTL should be positive for installation tokens")
}

func TestGitHubDriver_MintAppCredential_Cached(t *testing.T) {
	testKey := generateTestRSAKey(t)

	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		expiresAt := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_cached_token",
			"expires_at": expiresAt,
		})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": server.URL},
		},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-app",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	// First call mints
	rawData1, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghs_cached_token", rawData1["token"])
	assert.Equal(t, 1, callCount)

	// Second call should use cache (no additional HTTP call)
	rawData2, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghs_cached_token", rawData2["token"])
	assert.Equal(t, 1, callCount, "should use cached token, not call API again")
}

func TestGitHubDriver_MintAppCredential_PerSpecCache(t *testing.T) {
	testKey := generateTestRSAKey(t)

	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		expiresAt := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_token_" + r.URL.Path,
			"expires_at": expiresAt,
		})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": server.URL},
		},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	specA := &credential.CredSpec{
		Name: "spec-a",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "111",
		},
	}
	specB := &credential.CredSpec{
		Name: "spec-b",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "222",
		},
	}

	// Mint for spec A
	_, _, _, err := driver.MintCredential(context.Background(), specA)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Mint for spec B — should call API again (different spec)
	_, _, _, err = driver.MintCredential(context.Background(), specB)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "different specs should not share cache")

	// Mint for spec A again — should use cache
	_, _, _, err = driver.MintCredential(context.Background(), specA)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "same spec should use cached token")
}

func TestGitHubDriver_MintInstallationToken_APIError(t *testing.T) {
	testKey := generateTestRSAKey(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": server.URL},
		},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-app",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mint installation token")
}

func TestGitHubDriver_MintInstallationToken_EmptyToken(t *testing.T) {
	testKey := generateTestRSAKey(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": server.URL},
		},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "test-app",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"auth_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty token")
}

func TestGitHubDriver_GetGitHubURL(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{"github_url": "https://api.github.com/"},
		},
	}
	// getGitHubURL trims trailing slash
	assert.Equal(t, "https://api.github.com", driver.getGitHubURL())
}

func TestGitHubDriver_GetGitHubURL_Default(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitHub,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, "https://api.github.com", driver.getGitHubURL())
}

func TestParseRSAPrivateKey_PKCS1(t *testing.T) {
	pemKey := generateTestRSAKey(t) // PKCS1 format
	key, err := parseRSAPrivateKey(pemKey)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParseRSAPrivateKey_PKCS8(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemKey := string(pem.EncodeToMemory(pemBlock))

	key, err := parseRSAPrivateKey(pemKey)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParseRSAPrivateKey_Invalid(t *testing.T) {
	_, err := parseRSAPrivateKey("not-a-pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block found")
}

func TestValidateGitHubURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://api.github.com", false, ""},
		{"https://github.example.com/api/v3", false, ""},
		{"http://api.github.com", true, "must use https://"},
		{"ftp://api.github.com", true, "must use https://"},
		{"https://", true, "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateGitHubURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGenerateAppJWT(t *testing.T) {
	testKey := generateTestRSAKey(t)
	key, err := parseRSAPrivateKey(testKey)
	require.NoError(t, err)

	jwt, err := generateAppJWT(key, "12345")
	require.NoError(t, err)
	assert.NotEmpty(t, jwt)

	// JWT should have 3 parts separated by dots
	parts := splitJWT(jwt)
	assert.Len(t, parts, 3)
}

func TestGenerateAppJWT_NilKey(t *testing.T) {
	_, err := generateAppJWT(nil, "12345")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private key not configured")
}

func TestValidatePEMBlock(t *testing.T) {
	testKey := generateTestRSAKey(t)
	assert.NoError(t, ValidatePEMBlock(testKey))
	assert.Error(t, ValidatePEMBlock("not-a-pem"))
}

// splitJWT splits a JWT string into its parts
func splitJWT(token string) []string {
	parts := []string{}
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}
