package drivers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
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
	assert.Contains(t, fields, "ca_data")
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
			"mint_method": "pat",
			"token":       "ghp_test123",
		},
	}

	rawData, _, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
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
			"mint_method": "pat",
			"token":       "",
		},
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GitHub PAT configured")
}

func TestGitHubDriver_MintCredential_FailsClosedWhenChained(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": "https://api.github.com"}},
		appTokens:  make(map[string]*appTokenCache),
	}
	spec := &credential.CredSpec{
		Name: "chained",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"mint_method":               "pat",
			credential.ConfigSecretSpec: "gh-secret",
		},
	}
	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_spec")
}

func TestGitHubDriver_MintFromSecret_PAT(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": "https://api.github.com"}},
		appTokens:  make(map[string]*appTokenCache),
	}
	spec := &credential.CredSpec{
		Name:   "chained-pat",
		Type:   credential.TypeGitHubToken,
		Config: map[string]string{"mint_method": "pat", credential.ConfigSecretSpec: "gh-secret"},
	}
	material := credential.SecretMaterial{Data: map[string]string{"token": "ghp_fetched"}, Field: "token"}

	rawData, _, ttl, leaseID, err := driver.MintFromSecret(context.Background(), spec, material)
	require.NoError(t, err)
	assert.Equal(t, "ghp_fetched", rawData["token"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID)
}

// A resolved secret_field that is empty/absent must fail loudly rather than silently
// falling back to the conventional key name (which would mask the misconfiguration).
func TestGitHubDriver_MintFromSecret_MisconfiguredFieldFailsClosed(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": "https://api.github.com"}},
		appTokens:  make(map[string]*appTokenCache),
	}
	spec := &credential.CredSpec{
		Name:   "chained-pat",
		Type:   credential.TypeGitHubToken,
		Config: map[string]string{"mint_method": "pat", credential.ConfigSecretSpec: "gh-secret"},
	}
	// secret_field points at "wrong", but the payload carries the token under the
	// conventional "token" key. The old fallback would have used it silently.
	material := credential.SecretMaterial{Data: map[string]string{"token": "ghp_fetched"}, Field: "wrong"}

	_, _, _, _, err := driver.MintFromSecret(context.Background(), spec, material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong")
}

func TestGitHubDriver_MintFromSecret_App(t *testing.T) {
	testKey := generateTestRSAKey(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/app/installations/67890/access_tokens")
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_from_fetched_key",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": server.URL}},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}
	// App identifiers inline (non-secret); private key comes from fetched material.
	spec := &credential.CredSpec{
		Name: "chained-app",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"mint_method":               "app",
			"app_id":                    "12345",
			"installation_id":           "67890",
			credential.ConfigSecretSpec: "gh-secret",
		},
	}
	material := credential.SecretMaterial{Data: map[string]string{"private_key": testKey}, Field: "private_key"}

	rawData, _, ttl, _, err := driver.MintFromSecret(context.Background(), spec, material)
	require.NoError(t, err)
	assert.Equal(t, "ghs_from_fetched_key", rawData["token"])
	assert.True(t, ttl > 0)
}

func TestGitHubDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
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
			"mint_method": "unknown",
		},
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

// A spec persisted before the auth_method -> mint_method rename skips create-time
// validation on load, so the mint paths themselves must reject the legacy key with
// a migration message rather than defaulting to "app" and failing obscurely.
func TestGitHubDriver_MintPaths_RejectLegacyAuthMethod(t *testing.T) {
	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": "https://api.github.com"}},
		appTokens:  make(map[string]*appTokenCache),
	}
	spec := &credential.CredSpec{
		Name:   "legacy",
		Type:   credential.TypeGitHubToken,
		Config: map[string]string{"auth_method": "pat", "token": "ghp_legacy"},
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method' is no longer supported")

	_, _, _, _, err = driver.MintFromSecret(context.Background(), spec,
		credential.SecretMaterial{Data: map[string]string{"token": "ghp_x"}, Field: "token"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method' is no longer supported")

	require.ErrorContains(t, driver.VerifySpec(context.Background(), spec), "auth_method' is no longer supported")
}

// VerifySpec dispatches on mint_method: pat verifies with GET /user; app is a no-op
// (verified by the trial mint in ValidateSpec).
func TestGitHubDriver_VerifySpec_Dispatch(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/user", r.URL.Path)
		assert.Equal(t, "token ghp_verify", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"login": "octocat"})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": server.URL}},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	// pat mode → hits GET /user
	patSpec := &credential.CredSpec{Name: "v-pat", Type: credential.TypeGitHubToken,
		Config: map[string]string{"mint_method": "pat", "token": "ghp_verify"}}
	require.NoError(t, driver.VerifySpec(context.Background(), patSpec))
	assert.Equal(t, 1, calls, "pat mode verifies via GET /user")

	// app mode → no-op, no API call
	appSpec := &credential.CredSpec{Name: "v-app", Type: credential.TypeGitHubToken,
		Config: map[string]string{"mint_method": "app", "app_id": "1", "installation_id": "2"}}
	require.NoError(t, driver.VerifySpec(context.Background(), appSpec))
	assert.Equal(t, 1, calls, "app mode makes no verification call")
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
			"mint_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	rawData, _, ttl, _, err := driver.MintCredential(context.Background(), spec)
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
			"mint_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	// First call mints
	rawData1, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghs_cached_token", rawData1["token"])
	assert.Equal(t, 1, callCount)

	// Second call should use cache (no additional HTTP call)
	rawData2, _, _, _, err := driver.MintCredential(context.Background(), spec)
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
			"mint_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "111",
		},
	}
	specB := &credential.CredSpec{
		Name: "spec-b",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"mint_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "222",
		},
	}

	// Mint for spec A
	_, _, _, _, err := driver.MintCredential(context.Background(), specA)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Mint for spec B — should call API again (different spec)
	_, _, _, _, err = driver.MintCredential(context.Background(), specB)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "different specs should not share cache")

	// Mint for spec A again — should use cache
	_, _, _, _, err = driver.MintCredential(context.Background(), specA)
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
			"mint_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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
			"mint_method":     "app",
			"app_id":          "12345",
			"private_key":     testKey,
			"installation_id": "67890",
		},
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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
			err := validateGitHubURL(tt.url, false)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGitHubURL_TLSSkipVerify(t *testing.T) {
	// HTTP allowed when tlsSkipVerify is true
	require.NoError(t, validateGitHubURL("http://github.local", true))
	// HTTPS still works
	require.NoError(t, validateGitHubURL("https://github.local", true))
	// FTP still rejected
	require.Error(t, validateGitHubURL("ftp://github.local", true))
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

// --- app installation token cache keying ---

// assertionSignedBy reports whether the App JWT was signed with keyPEM. The
// stand-in API never sees the private key itself, only what it signed, so this is
// how a test tells which caller's key actually reached GitHub.
func assertionSignedBy(t *testing.T, assertion, keyPEM string) bool {
	t.Helper()

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	key, err := parseRSAPrivateKey(keyPEM)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) == nil
}

// newCachingGitHubDriver builds a driver against a stand-in API that maps each
// signing key to its own installation token, so a test can tell which key a
// returned token was minted from. keyForToken is consulted per request.
func newCachingGitHubDriver(t *testing.T, tokenFor func(jwtAssertion string) (string, int)) (*GitHubDriver, *int) {
	t.Helper()

	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		token, status := tokenFor(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if status != http.StatusCreated {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      token,
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	t.Cleanup(server.Close)

	return &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": server.URL}},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}, &calls
}

func githubAppSpec(name string) *credential.CredSpec {
	return &credential.CredSpec{
		Name: name,
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"mint_method":               "app",
			"app_id":                    "12345",
			"installation_id":           "67890",
			credential.ConfigSecretSpec: "gh-key",
		},
	}
}

// TestGitHubDriver_AppTokenCacheIsKeyedByKey is the crux: two callers of the same
// spec whose chained private key resolves differently must each mint with their own
// key. Keyed by spec name, the second is served the first's token and its key is
// never exercised at all.
func TestGitHubDriver_AppTokenCacheIsKeyedByKey(t *testing.T) {
	keyA := generateTestRSAKey(t)
	keyB := generateTestRSAKey(t)

	// The stand-in cannot see the key, only the assertion signed with it, so it
	// distinguishes callers by which key verifies the JWT signature.
	driver, calls := newCachingGitHubDriver(t, func(assertion string) (string, int) {
		switch {
		case assertionSignedBy(t, assertion, keyA):
			return "ghs_from_key_a", http.StatusCreated
		case assertionSignedBy(t, assertion, keyB):
			return "ghs_from_key_b", http.StatusCreated
		default:
			return "", http.StatusUnauthorized
		}
	})

	spec := githubAppSpec("shared-spec")
	mintWith := func(keyPEM string) map[string]interface{} {
		rawData, _, _, _, err := driver.MintFromSecret(context.Background(), spec,
			credential.SecretMaterial{Data: map[string]string{"private_key": keyPEM}, Field: "private_key"})
		require.NoError(t, err)
		return rawData
	}

	assert.Equal(t, "ghs_from_key_a", mintWith(keyA)["token"])

	// Same key again must be served from cache.
	assert.Equal(t, "ghs_from_key_a", mintWith(keyA)["token"])
	assert.Equal(t, 1, *calls, "a repeated key must reuse the cached token")

	// A different key must mint its own token, not inherit the first caller's.
	assert.Equal(t, "ghs_from_key_b", mintWith(keyB)["token"])
	assert.Equal(t, 2, *calls, "a different key must mint its own token")
}

// TestGitHubDriver_AppTokenCacheFollowsSpecConfig covers the direct path: a spec
// edited to point at another installation must not keep serving the old one's
// token. A spec update does not rebuild the driver, so nothing else would notice.
func TestGitHubDriver_AppTokenCacheFollowsSpecConfig(t *testing.T) {
	key := generateTestRSAKey(t)

	var lastInstallation string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastInstallation = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/app/installations/"), "/access_tokens")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_for_installation_" + lastInstallation,
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer server.Close()

	driver := &GitHubDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGitHub, Config: map[string]string{"github_url": server.URL}},
		httpClient: server.Client(),
		appTokens:  make(map[string]*appTokenCache),
	}

	spec := &credential.CredSpec{
		Name: "edited-spec",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"mint_method": "app", "app_id": "12345",
			"installation_id": "111", "private_key": key,
		},
	}
	rawData, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghs_for_installation_111", rawData["token"])

	spec.Config["installation_id"] = "222"
	rawData, _, _, _, err = driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "ghs_for_installation_222", rawData["token"],
		"a spec repointed at another installation must not be served the old one's token")
}

// TestGitHubDriver_ChainedKeyRejectionIsRetryable pins the marking that lets the
// minting layer evict a stale chained key and retry. Without it a key rotated where
// it is held fails every request under the spec until the entry ages out.
func TestGitHubDriver_ChainedKeyRejectionIsRetryable(t *testing.T) {
	driver, _ := newCachingGitHubDriver(t, func(string) (string, int) {
		return "", http.StatusUnauthorized
	})

	_, _, _, _, err := driver.MintFromSecret(context.Background(), githubAppSpec("chained-spec"),
		credential.SecretMaterial{Data: map[string]string{"private_key": generateTestRSAKey(t)}, Field: "private_key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
}

// An inline key has no fresher copy to fetch, so marking its refusal would buy a
// retry of the identical credentials.
func TestGitHubDriver_InlineKeyRejectionIsNotRetryable(t *testing.T) {
	driver, _ := newCachingGitHubDriver(t, func(string) (string, int) {
		return "", http.StatusUnauthorized
	})

	spec := &credential.CredSpec{
		Name: "inline-spec",
		Type: credential.TypeGitHubToken,
		Config: map[string]string{
			"mint_method": "app", "app_id": "12345",
			"installation_id": "67890", "private_key": generateTestRSAKey(t),
		},
	}
	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
}

func TestGitHubAppTokenCacheKey(t *testing.T) {
	assert.Equal(t, appTokenCacheKey("a", "i", "k"), appTokenCacheKey("a", "i", "k"))
	assert.NotEqual(t, appTokenCacheKey("a", "i", "k"), appTokenCacheKey("a", "i", "k2"))
	assert.NotEqual(t, appTokenCacheKey("a", "i", "k"), appTokenCacheKey("a", "i2", "k"))
	assert.NotEqual(t, appTokenCacheKey("a", "i", "k"), appTokenCacheKey("a2", "i", "k"))
	// Fields that would collide under plain concatenation must not.
	assert.NotEqual(t, appTokenCacheKey("ab", "c", "d"), appTokenCacheKey("a", "bc", "d"))

	assert.NotContains(t, appTokenCacheKey("app", "inst", "SECRETKEY"), "SECRETKEY",
		"the private key must not sit in a map key")
}
