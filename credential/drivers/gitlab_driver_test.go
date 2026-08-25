package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
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
	assert.Contains(t, fields, "ca_data")
	assert.Len(t, fields, 3)
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
	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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
	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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

	rawData, _, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "glpat-minted-token", rawData["access_token"])
	assert.Equal(t, "99", rawData["token_id"])
	// Expiry is a date, so the lease runs to the first UTC midnight at or after the
	// requested 24h — at least the request, under a day more.
	assert.GreaterOrEqual(t, ttl, 24*time.Hour)
	assert.Less(t, ttl, 48*time.Hour)
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

	rawData, _, _, leaseID, err := driver.MintCredential(context.Background(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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
		case r.Method == http.MethodPost && r.URL.Path == "/api/v4/applications/app-123/renew-secret":
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

	// Pre-set a cached OAuth2 token so the driver can authenticate API calls without
	// the test server having to serve the grant. The key is the fingerprint of the
	// credentials the bearer was granted from, so it must be built the same way the
	// driver builds it.
	driver.tokenCache.Set(oauth2CacheKey("app-123", "old-secret"), "cached-bearer-token", time.Now().Add(1*time.Hour))

	newConfig, cleanupConfig, activateAfter, err := driver.PrepareRotation(context.Background())
	require.NoError(t, err)

	// GitLab renew-secret is atomic — must use fast path (no activation delay)
	assert.Equal(t, time.Duration(0), activateAfter, "GitLab OAuth2 rotation must use activateAfter=0 (fast path)")
	assert.Equal(t, "new-rotated-secret", newConfig["application_secret"])
	assert.Equal(t, "app-123", cleanupConfig["application_id"])
	assert.Equal(t, 1, callCount)

	// Eager update: driver config and OAuth2 cache should already be updated
	assert.Equal(t, "new-rotated-secret", driver.credSource.Config["application_secret"],
		"driver config must be eagerly updated since old secret is already invalidated")
	// Token cache generation should be invalidated (internal state, can't easily test directly)
}

func TestGitLabTokenExpiry(t *testing.T) {
	// The API expresses expiry as a date and kills the token at midnight UTC on it,
	// so the granted lifetime always lands on a day boundary at or after now+ttl.
	tests := []struct {
		name        string
		now         time.Time
		ttl         time.Duration
		wantDate    string
		wantGranted time.Duration
	}{
		{
			name:        "deadline already on a boundary grants exactly the ttl",
			now:         time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC),
			ttl:         24 * time.Hour,
			wantDate:    "2026-08-25",
			wantGranted: 24 * time.Hour,
		},
		{
			name:        "mid-day deadline rounds up to the next boundary",
			now:         time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC),
			ttl:         24 * time.Hour,
			wantDate:    "2026-08-26",
			wantGranted: 39 * time.Hour,
		},
		{
			name:        "late-day mint still clears the requested ttl",
			now:         time.Date(2026, 8, 24, 23, 0, 0, 0, time.UTC),
			ttl:         24 * time.Hour,
			wantDate:    "2026-08-26",
			wantGranted: 25 * time.Hour,
		},
		{
			// Truncating instead of rounding up would name today's midnight, which
			// has already passed — a token dead on arrival.
			name:        "sub-day ttl lands on tomorrow, never a past boundary",
			now:         time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC),
			ttl:         time.Hour,
			wantDate:    "2026-08-25",
			wantGranted: 15 * time.Hour,
		},
		{
			name:        "multi-day ttl",
			now:         time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC),
			ttl:         72 * time.Hour,
			wantDate:    "2026-08-28",
			wantGranted: 87 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			date, granted := tokenExpiry(tt.now, tt.ttl)
			assert.Equal(t, tt.wantDate, date)
			assert.Equal(t, tt.wantGranted, granted)
		})
	}
}

func TestGitLabTokenExpiry_IgnoresServerTimezone(t *testing.T) {
	// Formatting in the server's local zone rather than UTC lands on the wrong day
	// for a server running ahead of UTC. Same instant, two zones, one answer.
	instant := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	ahead := instant.In(time.FixedZone("UTC+10", 10*60*60))
	behind := instant.In(time.FixedZone("UTC-7", -7*60*60))

	wantDate, wantGranted := tokenExpiry(instant, 24*time.Hour)

	for name, now := range map[string]time.Time{"ahead": ahead, "behind": behind} {
		t.Run(name, func(t *testing.T) {
			date, granted := tokenExpiry(now, 24*time.Hour)
			assert.Equal(t, wantDate, date)
			assert.Equal(t, wantGranted, granted)
		})
	}
}

func TestGitLabTokenExpiry_Invariants(t *testing.T) {
	// Across every mint hour and a spread of ttls: the token always outlives the
	// requested ttl, by under a day, and the date is always in the future.
	for hour := 0; hour < 24; hour++ {
		now := time.Date(2026, 8, 24, hour, 30, 0, 0, time.UTC)
		for _, ttl := range []time.Duration{time.Minute, time.Hour, 12 * time.Hour, 24 * time.Hour, 72 * time.Hour} {
			date, granted := tokenExpiry(now, ttl)

			assert.GreaterOrEqual(t, granted, ttl,
				"hour=%d ttl=%s: token must live at least the requested ttl", hour, ttl)
			assert.Less(t, granted, ttl+24*time.Hour,
				"hour=%d ttl=%s: overshoot must stay under a day", hour, ttl)

			parsed, err := time.ParseInLocation("2006-01-02", date, time.UTC)
			require.NoError(t, err)
			assert.True(t, parsed.After(now),
				"hour=%d ttl=%s: expiry %s must be in the future", hour, ttl, date)
		}
	}
}

func TestGitLabTokenExpiry_StaysInsideTheLifetimeLimit(t *testing.T) {
	// Rounding up must not push the request past the maximum lifetime the server
	// enforces: a ttl at the limit used to mint fine, and asking for a day more
	// would fail it outright.
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)

	for _, ttl := range []time.Duration{maxTokenLifetime - time.Hour, maxTokenLifetime, maxTokenLifetime + 30*24*time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			date, granted := tokenExpiry(now, ttl)

			parsed, err := time.ParseInLocation("2006-01-02", date, time.UTC)
			require.NoError(t, err)
			assert.False(t, parsed.After(now.Add(maxTokenLifetime)),
				"expiry %s exceeds the limit %s", date, now.Add(maxTokenLifetime).Format("2006-01-02"))
			assert.True(t, parsed.After(now), "expiry %s must be in the future", date)
			assert.Equal(t, parsed.Sub(now), granted)
		})
	}
}

func TestGitLabGrantedExpiry(t *testing.T) {
	// The response's expires_at is authoritative: an instance with a shorter
	// maximum lifetime answers with a nearer date, and a lease derived from the
	// request would then outlive the token it names.
	now := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	const requested = "2026-08-26"
	requestedTTL := 39 * time.Hour

	tests := []struct {
		name        string
		granted     string
		wantDate    string
		wantGranted time.Duration
	}{
		{"server agrees", "2026-08-26", requested, requestedTTL},
		{"server says nothing", "", requested, requestedTTL},
		{"server clamps to a nearer date", "2026-08-25", "2026-08-25", 15 * time.Hour},
		{"server grants a later date", "2026-08-28", "2026-08-28", 87 * time.Hour},
		{"unparseable falls back to the request", "not-a-date", requested, requestedTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			date, granted := grantedExpiry(now, requested, requestedTTL, tt.granted)
			assert.Equal(t, tt.wantDate, date)
			assert.Equal(t, tt.wantGranted, granted)
		})
	}
}

func TestGitLabDriver_MintHonoursServerExpiry(t *testing.T) {
	// End to end through a mint: a server that clamps the date must shorten the
	// lease and the reported expires_at with it, not leave the credential cached
	// past the point it stops working.
	clamped := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": 99, "token": "glpat-minted-token", "expires_at": clamped,
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
		Name: "test-spec", Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method": "project_access_token", "project_id": "42",
			"token_name": "warden-test", "scopes": "api", "access_level": "30",
			// Long enough that the driver would have asked for a much later date.
			"ttl": "720h",
		},
	}

	rawData, _, ttl, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)

	assert.Equal(t, clamped, rawData["expires_at"], "the server's date must be the one reported")
	assert.Less(t, ttl, 48*time.Hour, "the lease must follow the server's date, not the request")
	assert.Greater(t, ttl, time.Duration(0))
}

func TestGitLabDriverFactory_ValidateConfig_Chaining(t *testing.T) {
	factory := &GitLabDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "chained PAT source needs no inline token",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "pat",
				"secret_spec":    "gitlab-pat-from-vault",
				"secret_field":   "pat",
			},
		},
		{
			name: "chained source accepts a cache ttl",
			config: map[string]string{
				"gitlab_address":   "https://gitlab.example.com",
				"secret_spec":      "gitlab-pat-from-vault",
				"secret_cache_ttl": "30m",
			},
		},
		{
			name: "non-chained source still requires the inline token",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "pat",
			},
			wantErr: true,
			errMsg:  "personal_access_token",
		},
		{
			name: "chaining plus an inline token leaves a secret at rest",
			config: map[string]string{
				"gitlab_address":        "https://gitlab.example.com",
				"auth_method":           "pat",
				"secret_spec":           "gitlab-pat-from-vault",
				"personal_access_token": "glpat-still-here",
			},
			wantErr: true,
			errMsg:  "must be omitted when secret_spec is set",
		},
		{
			name: "oauth2 chained without an inline secret",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "oauth2",
				"application_id": "app-123",
				"secret_spec":    "gitlab-app-secret",
			},
			wantErr: false,
		},
		{
			name: "oauth2 chained but secret still inline",
			config: map[string]string{
				"gitlab_address":     "https://gitlab.example.com",
				"auth_method":        "oauth2",
				"application_id":     "app-123",
				"application_secret": "secret-456",
				"secret_spec":        "gitlab-app-secret",
			},
			wantErr: true,
			errMsg:  "application_secret must be omitted when secret_spec is set",
		},
		{
			// The id is not a secret and the grant needs it, so chaining does not
			// excuse leaving it out.
			name: "oauth2 chained without an application id",
			config: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "oauth2",
				"secret_spec":    "gitlab-app-secret",
			},
			wantErr: true,
			errMsg:  "application_id",
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

func TestGitLabDriverFactory_Create_ChainedSkipsVerifyAuth(t *testing.T) {
	// A chained source has no token at construction time, so Create must not try to
	// authenticate — there is nothing to authenticate with until a request arrives.
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	factory := &GitLabDriverFactory{}
	driver, err := factory.Create(map[string]string{
		"gitlab_address":  server.URL,
		"auth_method":     "pat",
		"secret_spec":     "gitlab-pat-from-vault",
		"tls_skip_verify": "true",
	}, log)

	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Zero(t, calls, "chained Create must not call the API")
}

func TestGitLabDriver_MintCredential_FailsClosedWhenChained(t *testing.T) {
	// The manager routes chained specs to MintFromSecret. Reaching MintCredential
	// means that routing was bypassed, so it must not fall through to an inline
	// token the source does not have.
	tests := []struct {
		name         string
		sourceConfig map[string]string
		specConfig   map[string]string
	}{
		{
			name: "secret_spec on the source",
			sourceConfig: map[string]string{
				"gitlab_address": "https://gitlab.example.com",
				"auth_method":    "pat",
				"secret_spec":    "gitlab-pat-from-vault",
			},
			specConfig: map[string]string{"mint_method": "project_access_token", "project_id": "42"},
		},
		{
			name: "secret_spec on the spec",
			sourceConfig: map[string]string{
				"gitlab_address":        "https://gitlab.example.com",
				"auth_method":           "pat",
				"personal_access_token": "test-pat",
			},
			specConfig: map[string]string{
				"mint_method": "project_access_token",
				"project_id":  "42",
				"secret_spec": "gitlab-pat-from-vault",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &GitLabDriver{
				credSource: &credential.CredSource{Type: credential.SourceTypeGitLab, Config: tt.sourceConfig},
				httpClient: &http.Client{Timeout: 30 * time.Second},
			}
			spec := &credential.CredSpec{Name: "test-spec", Type: credential.TypeGitLabAccessToken, Config: tt.specConfig}

			_, _, _, _, err := driver.MintCredential(context.Background(), spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must mint from fetched secret material")
		})
	}
}

// newChainedGitLabDriver builds a chained (secret_spec, no inline token) driver
// pointed at the given test server.
func newChainedGitLabDriver(server *httptest.Server) *GitLabDriver {
	return &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address": server.URL,
				"auth_method":    "pat",
				"secret_spec":    "gitlab-pat-from-vault",
			},
		},
		httpClient: server.Client(),
	}
}

func projectTokenSpec() *credential.CredSpec {
	return &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeGitLabAccessToken,
		Config: map[string]string{
			"mint_method":  "project_access_token",
			"project_id":   "42",
			"token_name":   "warden-test",
			"scopes":       "api",
			"access_level": "30",
			"ttl":          "24h",
		},
	}
}

func TestGitLabDriver_MintFromSecret(t *testing.T) {
	var gotToken string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 99, "token": "glpat-minted-token"})
	}))
	defer server.Close()

	tests := []struct {
		name      string
		material  credential.SecretMaterial
		wantToken string
	}{
		{
			name:      "resolved field",
			material:  credential.SecretMaterial{Data: map[string]string{"pat": "glpat-from-vault"}, Field: "pat"},
			wantToken: "glpat-from-vault",
		},
		{
			name:      "conventional key when no field resolved",
			material:  credential.SecretMaterial{Data: map[string]string{"personal_access_token": "glpat-conventional"}},
			wantToken: "glpat-conventional",
		},
		{
			name:      "short conventional key when no field resolved",
			material:  credential.SecretMaterial{Data: map[string]string{"pat": "glpat-short"}},
			wantToken: "glpat-short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken = ""
			driver := newChainedGitLabDriver(server)

			rawData, _, ttl, leaseID, err := driver.MintFromSecret(context.Background(), projectTokenSpec(), tt.material)
			require.NoError(t, err)

			assert.Equal(t, tt.wantToken, gotToken, "fetched token must authenticate the mint")
			assert.Equal(t, "glpat-minted-token", rawData["access_token"])
			assert.GreaterOrEqual(t, ttl, 24*time.Hour)
			// Chained mints are leaseless: revocation runs with no caller and could
			// not re-fetch the token needed to authenticate the delete.
			assert.Empty(t, leaseID)
		})
	}
}

func TestGitLabDriver_MintFromSecret_Errors(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("must not reach the API without a token")
	}))
	defer server.Close()

	tests := []struct {
		name       string
		authMethod string
		material   credential.SecretMaterial
		errMsg     string
	}{
		{
			// A resolved-but-empty field is a misconfigured secret_field, not an
			// invitation to authenticate with some other value in the payload.
			name:     "resolved field is empty",
			material: credential.SecretMaterial{Data: map[string]string{"pat": "", "other": "glpat-wrong"}, Field: "pat"},
			errMsg:   `secret_field "pat" is empty or absent`,
		},
		{
			name:     "no field and no conventional key",
			material: credential.SecretMaterial{Data: map[string]string{"unexpected": "glpat-wrong"}},
			errMsg:   "no personal access token in fetched secret material",
		},
		{
			name:       "oauth2 resolved field is empty",
			authMethod: "oauth2",
			material:   credential.SecretMaterial{Data: map[string]string{"application_secret": "", "other": "wrong"}, Field: "application_secret"},
			errMsg:     `secret_field "application_secret" is empty or absent`,
		},
		{
			name:       "oauth2 with no field and no conventional key",
			authMethod: "oauth2",
			material:   credential.SecretMaterial{Data: map[string]string{"unexpected": "wrong"}},
			errMsg:     "no application secret in fetched secret material",
		},
		{
			name:       "auth_method drifted to something neither method understands",
			authMethod: "mtls",
			material:   credential.SecretMaterial{Data: map[string]string{"pat": "glpat-from-vault"}, Field: "pat"},
			errMsg:     "supports auth_method=pat or oauth2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := newChainedGitLabDriver(server)
			if tt.authMethod != "" {
				driver.credSource.Config["auth_method"] = tt.authMethod
			}

			_, _, _, _, err := driver.MintFromSecret(context.Background(), projectTokenSpec(), tt.material)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestGitLabDriver_MintFromSecret_RejectedTokenIsRetryable(t *testing.T) {
	// A token rotated at its source goes stale in the chained-secret cache. Marking
	// the rejection lets the minting layer evict it and retry once, instead of
	// failing every request until the entry ages out.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			driver := newChainedGitLabDriver(server)
			material := credential.SecretMaterial{Data: map[string]string{"pat": "glpat-stale"}, Field: "pat"}

			_, _, _, _, err := driver.MintFromSecret(context.Background(), projectTokenSpec(), material)
			require.Error(t, err)
			assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
		})
	}
}

func TestGitLabDriver_MintFromSecret_OtherFailuresAreNotRetryable(t *testing.T) {
	// Only an authentication rejection implicates the fetched token. A 404 means the
	// project is wrong; evicting and refetching would not help.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	driver := newChainedGitLabDriver(server)
	material := credential.SecretMaterial{Data: map[string]string{"pat": "glpat-fine"}, Field: "pat"}

	_, _, _, _, err := driver.MintFromSecret(context.Background(), projectTokenSpec(), material)
	require.Error(t, err)
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
}

func TestGitLabDriver_SupportsRotation_ChainedSourceOwnsNothing(t *testing.T) {
	for _, authMethod := range []string{"pat", "oauth2"} {
		t.Run(authMethod, func(t *testing.T) {
			driver := &GitLabDriver{
				credSource: &credential.CredSource{
					Type: credential.SourceTypeGitLab,
					Config: map[string]string{
						"gitlab_address": "https://gitlab.example.com",
						"auth_method":    authMethod,
						"secret_spec":    "gitlab-pat-from-vault",
					},
				},
				httpClient: &http.Client{Timeout: 30 * time.Second},
			}
			assert.False(t, driver.SupportsRotation())
		})
	}
}

// --- oauth2 credential chaining ---

// gitlabOAuth2Fake stands in for the GitLab instance across the oauth2 chaining
// tests: it grants a bearer per application secret and accepts that bearer on the
// mint. Both halves are swappable so a test can rotate the secret mid-run, and both
// call counts are recorded because the point of most of these tests is how many
// grants happened.
type gitlabOAuth2Fake struct {
	mu sync.Mutex

	acceptedSecret  string
	bearerForSecret map[string]string

	grantSecrets []string // client_secret seen on each /oauth/token call
	mintBearers  []string // Authorization seen on each mint call
	mintStatus   int      // when non-zero, the status the mint answers instead of 200
}

func newGitLabOAuth2Fake(acceptedSecret, bearer string) *gitlabOAuth2Fake {
	return &gitlabOAuth2Fake{
		acceptedSecret:  acceptedSecret,
		bearerForSecret: map[string]string{acceptedSecret: bearer},
	}
}

func (f *gitlabOAuth2Fake) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		switch {
		case r.URL.Path == "/oauth/token":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
			secret := r.Form.Get("client_secret")
			f.grantSecrets = append(f.grantSecrets, secret)

			if secret != f.acceptedSecret {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_client"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": f.bearerForSecret[secret],
				"token_type":   "bearer",
				"expires_in":   7200,
			})

		default:
			f.mintBearers = append(f.mintBearers, r.Header.Get("Authorization"))
			if f.mintStatus != 0 {
				w.WriteHeader(f.mintStatus)
				json.NewEncoder(w).Encode(map[string]interface{}{"message": "401 Unauthorized"})
				return
			}
			if got, want := r.Header.Get("Authorization"), "Bearer "+f.bearerForSecret[f.acceptedSecret]; got != want {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"message": "401 Unauthorized"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 99, "token": "glpat-minted-token"})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// rotate swaps the secret the fake accepts and the bearer it grants for it,
// standing in for the secret being rotated wherever it is held.
func (f *gitlabOAuth2Fake) rotate(secret, bearer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acceptedSecret = secret
	f.bearerForSecret[secret] = bearer
}

func (f *gitlabOAuth2Fake) snapshot() (grants []string, mints []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.grantSecrets...), append([]string(nil), f.mintBearers...)
}

func newChainedOAuth2GitLabDriver(server *httptest.Server) *GitLabDriver {
	return &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address": server.URL,
				"auth_method":    "oauth2",
				"application_id": "app-123",
				"secret_spec":    "gitlab-app-secret",
			},
		},
		tokenCache: NewTokenCache(),
		httpClient: server.Client(),
	}
}

func TestGitLabDriver_MintFromSecret_OAuth2_ChainedSecretReachesGrant(t *testing.T) {
	fake := newGitLabOAuth2Fake("app-secret-from-store", "bearer-for-store-secret")
	driver := newChainedOAuth2GitLabDriver(fake.server(t))

	rawData, _, ttl, leaseID, err := driver.MintFromSecret(context.Background(), projectTokenSpec(),
		credential.SecretMaterial{Data: map[string]string{"application_secret": "app-secret-from-store"}})
	require.NoError(t, err)

	grants, mints := fake.snapshot()
	require.Len(t, grants, 1, "the mint must be preceded by exactly one grant")
	assert.Equal(t, "app-secret-from-store", grants[0],
		"the grant must carry the chained secret, which appears in no config")
	require.Len(t, mints, 1)
	assert.Equal(t, "Bearer bearer-for-store-secret", mints[0])

	assert.Equal(t, "glpat-minted-token", rawData["access_token"])
	assert.GreaterOrEqual(t, ttl, 24*time.Hour)
	assert.Empty(t, leaseID, "a chained mint is leaseless: it has no secret of its own to revoke with")
}

func TestGitLabDriver_OAuth2CacheKeyIsolation(t *testing.T) {
	// The bearer cache is keyed by the credentials it was granted from. Two callers
	// whose chained secret resolves differently must each get their own grant —
	// under a single fixed key the second would be served the first's bearer.
	fake := newGitLabOAuth2Fake("secret-a", "bearer-a")
	fake.bearerForSecret["secret-b"] = "bearer-b"
	driver := newChainedOAuth2GitLabDriver(fake.server(t))

	mintWith := func(secret string) error {
		_, _, _, _, err := driver.MintFromSecret(context.Background(), projectTokenSpec(),
			credential.SecretMaterial{Data: map[string]string{"application_secret": secret}})
		return err
	}

	require.NoError(t, mintWith("secret-a"))

	// Same secret again: this one must be served from cache.
	require.NoError(t, mintWith("secret-a"))
	grants, _ := fake.snapshot()
	assert.Len(t, grants, 1, "a repeated secret must reuse the cached bearer")

	// A different secret must not reuse it. Accept it upstream so the mint succeeds
	// and the bearer it carried can be inspected.
	fake.rotate("secret-b", "bearer-b")
	require.NoError(t, mintWith("secret-b"))

	grants, mints := fake.snapshot()
	require.Len(t, grants, 2, "a different secret must trigger its own grant")
	assert.Equal(t, []string{"secret-a", "secret-b"}, grants)
	require.Len(t, mints, 3)
	assert.Equal(t, "Bearer bearer-b", mints[2], "the second caller must not be served the first's bearer")
}

func TestGitLabDriver_OAuth2ChainedSecretRejectionIsRetryable(t *testing.T) {
	// A secret rotated where it is held goes stale in the chained-secret cache. The
	// token endpoint is where that surfaces in oauth2 mode — one call earlier than
	// in pat mode — so the marking has to happen there for the minting layer to
	// evict and retry.
	fake := newGitLabOAuth2Fake("current-secret", "bearer-current")
	driver := newChainedOAuth2GitLabDriver(fake.server(t))

	_, _, _, _, err := driver.MintFromSecret(context.Background(), projectTokenSpec(),
		credential.SecretMaterial{Data: map[string]string{"application_secret": "stale-secret"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
}

func TestGitLabDriver_OAuth2InlineSecretRejectionIsNotRetryable(t *testing.T) {
	// An inline source owns its secret: nothing upstream can refetch a fresher one,
	// so marking the error would buy a pointless retry of the same credentials.
	fake := newGitLabOAuth2Fake("current-secret", "bearer-current")
	server := fake.server(t)

	driver := &GitLabDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGitLab,
			Config: map[string]string{
				"gitlab_address":     server.URL,
				"auth_method":        "oauth2",
				"application_id":     "app-123",
				"application_secret": "stale-secret",
			},
		},
		tokenCache: NewTokenCache(),
		httpClient: server.Client(),
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), projectTokenSpec())
	require.Error(t, err)
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
}

func TestGitLabDriver_OAuth2BearerEvictedOnUnauthorized(t *testing.T) {
	// A bearer the upstream refuses must not stay cached: the minting layer's one
	// retry would replay it and fail identically, and an inline source would keep
	// failing until the bearer expired on its own.
	fake := newGitLabOAuth2Fake("app-secret", "bearer-one")
	driver := newChainedOAuth2GitLabDriver(fake.server(t))

	material := credential.SecretMaterial{Data: map[string]string{"application_secret": "app-secret"}}

	// First mint: grant succeeds and caches a bearer with a long expiry, but the
	// upstream refuses it — as it would for a bearer revoked out of band.
	fake.mu.Lock()
	fake.mintStatus = http.StatusUnauthorized
	fake.mu.Unlock()

	_, _, _, _, err := driver.MintFromSecret(context.Background(), projectTokenSpec(), material)
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)

	// Second mint with the same secret: the cached bearer is gone, so this must
	// re-grant rather than reuse it.
	fake.mu.Lock()
	fake.mintStatus = 0
	fake.mu.Unlock()

	_, _, _, _, err = driver.MintFromSecret(context.Background(), projectTokenSpec(), material)
	require.NoError(t, err)

	grants, _ := fake.snapshot()
	assert.Len(t, grants, 2, "the refused bearer must have been evicted, forcing a fresh grant")
}

func TestGitLabOAuth2CacheKey(t *testing.T) {
	// The key must separate every distinct pair, including pairs that would collide
	// if the two fields were simply concatenated.
	assert.Equal(t, oauth2CacheKey("app", "secret"), oauth2CacheKey("app", "secret"))
	assert.NotEqual(t, oauth2CacheKey("app", "secret"), oauth2CacheKey("app", "other"))
	assert.NotEqual(t, oauth2CacheKey("app", "secret"), oauth2CacheKey("other", "secret"))
	assert.NotEqual(t, oauth2CacheKey("ab", "c"), oauth2CacheKey("a", "bc"))

	assert.NotContains(t, oauth2CacheKey("app", "secret"), "secret", "the raw secret must not sit in the key")
}
