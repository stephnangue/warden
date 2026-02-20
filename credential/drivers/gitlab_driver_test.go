package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestGitLabDriver creates a GitLabDriver suitable for unit testing (PAT mode)
func newTestGitLabDriver(patToken string) *GitLabDriver {
	return &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        "https://gitlab.example.com",
				"auth_method":           "pat",
				"personal_access_token": patToken,
			},
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func TestGitLabDriverFactory_Type(t *testing.T) {
	factory := &GitLabDriverFactory{}
	assert.Equal(t, credential.SourceTypeGitLab, factory.Type())
}

func TestGitLabDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &GitLabDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "personal_access_token")
	assert.Contains(t, fields, "application_secret")
	assert.Len(t, fields, 2)
}

func TestGitLabDriverFactory_ValidateConfig(t *testing.T) {
	factory := &GitLabDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid PAT config",
			config: map[string]string{
				"gitlab_address":        "https://gitlab.example.com",
				"auth_method":           "pat",
				"personal_access_token": "glpat-xxxxx",
			},
			wantErr: false,
		},
		{
			name: "valid PAT config with default auth_method",
			config: map[string]string{
				"gitlab_address":        "https://gitlab.example.com",
				"personal_access_token": "glpat-xxxxx",
			},
			wantErr: false,
		},
		{
			name: "valid OAuth2 config",
			config: map[string]string{
				"gitlab_address":     "https://gitlab.example.com",
				"auth_method":        "oauth2",
				"application_id":     "app-123",
				"application_secret": "secret-456",
			},
			wantErr: false,
		},
		{
			name: "valid HTTP address",
			config: map[string]string{
				"gitlab_address":        "http://gitlab.local",
				"personal_access_token": "glpat-xxxxx",
			},
			wantErr: false,
		},
		{
			name:    "missing gitlab_address",
			config:  map[string]string{},
			wantErr: true,
			errMsg:  "gitlab_address",
		},
		{
			name: "invalid gitlab_address scheme",
			config: map[string]string{
				"gitlab_address": "ftp://gitlab.example.com",
			},
			wantErr: true,
			errMsg:  "must use http:// or https://",
		},
		{
			name: "gitlab_address missing host",
			config: map[string]string{
				"gitlab_address": "https://",
			},
			wantErr: true,
			errMsg:  "must include a host",
		},
		{
			name: "PAT mode missing token",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "pat",
			},
			wantErr: true,
			errMsg:  "personal_access_token",
		},
		{
			name: "OAuth2 mode missing application_id",
			config: map[string]string{
				"gitlab_address":     "https://gitlab.example.com",
				"auth_method":        "oauth2",
				"application_secret": "secret-456",
			},
			wantErr: true,
			errMsg:  "application_id",
		},
		{
			name: "OAuth2 mode missing application_secret",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "oauth2",
				"application_id": "app-123",
			},
			wantErr: true,
			errMsg:  "application_secret",
		},
		{
			name: "unsupported auth_method",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "ldap",
			},
			wantErr: true,
			errMsg:  "must be one of",
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

func TestGitLabDriver_Type(t *testing.T) {
	driver := newTestGitLabDriver("test-token")
	assert.Equal(t, credential.SourceTypeGitLab, driver.Type())
}

func TestGitLabDriver_Cleanup(t *testing.T) {
	driver := newTestGitLabDriver("test-token")
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestGitLabDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := newTestGitLabDriver("test-token")
	err := driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestGitLabDriver_Revoke_InvalidLeaseFormat(t *testing.T) {
	driver := newTestGitLabDriver("test-token")
	err := driver.Revoke(context.Background(), "invalid-format")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid lease ID format")
}

func TestGitLabDriver_Revoke_UnknownTokenType(t *testing.T) {
	driver := newTestGitLabDriver("test-token")
	err := driver.Revoke(context.Background(), "unknown_type:123:456")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown token type")
}

func TestGitLabDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
	driver := newTestGitLabDriver("test-token")

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method": "invalid_method",
		},
	}
	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method 'invalid_method'")
}

func TestGitLabDriver_MintCredential_MissingMintMethod(t *testing.T) {
	driver := newTestGitLabDriver("test-token")

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeGitLabAccessToken,
		Config: map[string]string{},
	}
	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

func TestGitLabDriver_SupportsRotation(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		want       bool
	}{
		{"PAT mode supports rotation", "pat", true},
		{"OAuth2 mode supports rotation", "oauth2", true},
		{"default (PAT) supports rotation", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := map[string]string{
				"gitlab_address":        "https://gitlab.example.com",
				"personal_access_token": "test-token",
			}
			if tt.authMethod != "" {
				config["auth_method"] = tt.authMethod
			}
			driver := &GitLabDriver{
				credSource: &credential.CredSource{
					Type:   credential.SourceTypeGitLab,
					Config: config,
				},
				httpClient: &http.Client{Timeout: 30 * time.Second},
			}
			assert.Equal(t, tt.want, driver.SupportsRotation())
		})
	}
}

func TestGitLabDriver_CleanupRotation_NoOp(t *testing.T) {
	driver := newTestGitLabDriver("test-token")
	err := driver.CleanupRotation(context.Background(), map[string]string{
		"old_token_id": "123",
	})
	assert.NoError(t, err)
}

func TestGitLabDriver_MintProjectAccessToken(t *testing.T) {
	// Set up mock server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/api/v4/projects/42/access_tokens")
		assert.Equal(t, "test-pat", r.Header.Get("PRIVATE-TOKEN"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    99,
			"token": "glpat-minted-token",
		})
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method":  "project_access_token",
			"project_id":   "42",
			"token_name":   "warden-test",
			"scopes":       "api,read_api",
			"access_level": "30",
			"ttl":          "24h",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "glpat-minted-token", rawData["access_token"])
	assert.Equal(t, "99", rawData["token_id"])
	assert.Equal(t, 24*time.Hour, ttl)
	assert.Equal(t, "project_access_token:42:99", leaseID)
}

func TestGitLabDriver_MintGroupAccessToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/api/v4/groups/mygroup/access_tokens")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    77,
			"token": "glpat-group-token",
		})
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method":  "group_access_token",
			"group_id":     "mygroup",
			"token_name":   "warden-test",
			"scopes":       "api",
			"access_level": "40",
		},
	}

	rawData, _, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "glpat-group-token", rawData["access_token"])
	assert.Equal(t, "77", rawData["token_id"])
	assert.Equal(t, "group_access_token:mygroup:77", leaseID)
}

func TestGitLabDriver_Revoke_ProjectAccessToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v4/projects/42/access_tokens/99", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.Revoke(context.Background(), "project_access_token:42:99")
	assert.NoError(t, err)
}

func TestGitLabDriver_Revoke_GroupAccessToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v4/groups/mygroup/access_tokens/77", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.Revoke(context.Background(), "group_access_token:mygroup:77")
	assert.NoError(t, err)
}

func TestGitLabDriver_MintProjectAccessToken_EmptyToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    1,
			"token": "",
		})
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method":  "project_access_token",
			"project_id":   "42",
			"token_name":   "warden-test",
			"scopes":       "api",
			"access_level": "30",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty token")
}

func TestGitLabDriver_MintProjectAccessToken_APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"insufficient_scope"}`))
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method":  "project_access_token",
			"project_id":   "42",
			"token_name":   "warden-test",
			"scopes":       "api",
			"access_level": "30",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create project access token")
}

func TestGitLabDriver_ConfigAccessors(t *testing.T) {
	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        "https://gitlab.example.com/",
				"auth_method":           "pat",
				"personal_access_token": "glpat-test",
			},
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// getGitLabAddress trims trailing slash
	assert.Equal(t, "https://gitlab.example.com", driver.getGitLabAddress())
	assert.Equal(t, "pat", driver.getAuthMethod())
	assert.Equal(t, "glpat-test", driver.getPAT())
}

func TestGitLabDriver_ConfigAccessors_Defaults(t *testing.T) {
	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGitLab,
			Config: map[string]string{},
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	assert.Equal(t, "", driver.getGitLabAddress())
	assert.Equal(t, "pat", driver.getAuthMethod()) // default
	assert.Equal(t, "", driver.getPAT())
}

func TestGitLabDriver_PrepareRotation_PAT_FastPath(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 10})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v4/personal_access_tokens/10/rotate":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    11,
				"token": "glpat-new-rotated-token",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":        server.URL,
				"auth_method":           "pat",
				"personal_access_token": "glpat-old-token",
			},
		},
		httpClient: server.Client(),
	}

	newConfig, cleanupConfig, activateAfter, err := driver.PrepareRotation(context.Background())
	require.NoError(t, err)

	// GitLab rotate is atomic — must use fast path (no activation delay)
	assert.Equal(t, time.Duration(0), activateAfter, "GitLab PAT rotation must use activateAfter=0 (fast path)")
	assert.Equal(t, "glpat-new-rotated-token", newConfig["personal_access_token"])
	assert.Equal(t, "10", cleanupConfig["old_token_id"])
	assert.Equal(t, 2, callCount)

	// Eager update: driver config should already reflect the new token
	assert.Equal(t, "glpat-new-rotated-token", driver.credSource.Config["personal_access_token"],
		"driver config must be eagerly updated since old token is already revoked")
}

func TestGitLabDriver_PrepareRotation_OAuth2_FastPath(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v4/applications/app-123/rotate_secret":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": "new-rotated-secret",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":     server.URL,
				"auth_method":        "oauth2",
				"application_id":     "app-123",
				"application_secret": "old-secret",
			},
		},
		tokenCache: NewTokenCache(),
		httpClient: server.Client(),
	}

	// Pre-set a cached OAuth2 token so the driver can authenticate API calls
	driver.tokenCache.Set("oauth2_token", "cached-bearer-token", time.Now().Add(1*time.Hour))

	newConfig, cleanupConfig, activateAfter, err := driver.PrepareRotation(context.Background())
	require.NoError(t, err)

	// GitLab rotate_secret is atomic — must use fast path (no activation delay)
	assert.Equal(t, time.Duration(0), activateAfter, "GitLab OAuth2 rotation must use activateAfter=0 (fast path)")
	assert.Equal(t, "new-rotated-secret", newConfig["application_secret"])
	assert.Equal(t, "app-123", cleanupConfig["application_id"])
	assert.Equal(t, 1, callCount)

	// Eager update: driver config and OAuth2 cache should already be updated
	assert.Equal(t, "new-rotated-secret", driver.credSource.Config["application_secret"],
		"driver config must be eagerly updated since old secret is already invalidated")
	// Token cache generation should be invalidated (internal state, can't easily test directly)
}
