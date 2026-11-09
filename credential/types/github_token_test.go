package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestPEM generates a PEM-encoded RSA private key for testing
func generateTestPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	return string(pem.EncodeToMemory(block))
}

func TestGitHubTokenCredType_Metadata(t *testing.T) {
	ct := NewGitHubTokenCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeGitHubToken, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Contains(t, metadata.Description, "GitHub token")
	assert.Equal(t, time.Duration(0), metadata.DefaultTTL)
}

func TestGitHubTokenCredType_ValidateConfig(t *testing.T) {
	ct := NewGitHubTokenCredType()

	testPEM := generateTestPEM(t)

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		// --- GitHub source: app mode ---
		{
			name: "github app - valid config",
			config: map[string]string{
				"mint_method":     "app",
				"app_id":          "12345",
				"private_key":     testPEM,
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github app - missing app_id",
			config: map[string]string{
				"mint_method":     "app",
				"private_key":     testPEM,
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "app_id",
		},
		{
			name: "github app - missing private_key",
			config: map[string]string{
				"mint_method":     "app",
				"app_id":          "12345",
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "private_key",
		},
		{
			name: "github app - missing installation_id",
			config: map[string]string{
				"mint_method": "app",
				"app_id":      "12345",
				"private_key": testPEM,
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "installation_id",
		},
		{
			name: "github app - invalid PEM",
			config: map[string]string{
				"mint_method":     "app",
				"app_id":          "12345",
				"private_key":     "not-a-pem",
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "must be valid PEM format",
		},
		// --- GitHub source: credential chaining (secret_spec) ---
		{
			name: "github app chained - valid (no inline private_key)",
			config: map[string]string{
				"mint_method":               "app",
				"app_id":                    "12345",
				"installation_id":           "67890",
				credential.ConfigSecretSpec: "gh-key-secret",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github app chained - inline private_key and secret_spec are mutually exclusive",
			config: map[string]string{
				"mint_method":               "app",
				"app_id":                    "12345",
				"installation_id":           "67890",
				"private_key":               testPEM,
				credential.ConfigSecretSpec: "gh-key-secret",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "mutually exclusive",
		},
		{
			name: "github pat chained - valid (no inline token)",
			config: map[string]string{
				"mint_method":               "pat",
				credential.ConfigSecretSpec: "gh-pat-secret",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github pat chained - inline token and secret_spec are mutually exclusive",
			config: map[string]string{
				"mint_method":               "pat",
				"token":                     "ghp_xxxxxxx",
				credential.ConfigSecretSpec: "gh-pat-secret",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "mutually exclusive",
		},
		{
			name: "local source rejects secret_spec",
			config: map[string]string{
				"token":                     "ghp_xxxxxxx",
				credential.ConfigSecretSpec: "gh-pat-secret",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "not supported with a local source",
		},
		// --- GitHub source: pat mode ---
		{
			name: "github pat - valid config",
			config: map[string]string{
				"mint_method": "pat",
				"token":       "ghp_xxxxxxx",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github pat - missing token",
			config: map[string]string{
				"mint_method": "pat",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "token",
		},
		// --- GitHub source: mint_method validation ---
		{
			name:       "github - missing mint_method",
			config:     map[string]string{},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "mint_method",
		},
		{
			name: "github - unsupported mint_method",
			config: map[string]string{
				"mint_method": "oauth",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "must be one of: app, pat",
		},
		{
			// The dispatch key was renamed auth_method -> mint_method; the old key
			// must be rejected with a migration message, not silently ignored.
			name: "github - legacy auth_method rejected",
			config: map[string]string{
				"auth_method": "pat",
				"token":       "ghp_xxxxxxx",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "auth_method' is no longer supported",
		},
		// --- Local source ---
		{
			name: "local source - valid config",
			config: map[string]string{
				"token": "ghp_xxxxxxx",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name:       "local source - missing token",
			config:     map[string]string{},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "token",
		},
		// --- Unsupported source types ---
		{
			name: "unsupported source type",
			config: map[string]string{
				"token": "test",
			},
			sourceType: "aws",
			wantErr:    true,
			errMsg:     "require a github or local source",
		},
		{
			name: "unsupported source type - vault",
			config: map[string]string{
				"token": "test",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "require a github or local source",
		},

		// --- token scope ---
		{
			name: "github app - scoped",
			config: map[string]string{
				"mint_method":     "app",
				"app_id":          "12345",
				"private_key":     testPEM,
				"installation_id": "67890",
				"repositories":    "backend,frontend",
				"permissions":     "contents:read,pull_requests:write",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github app - legacy repository key",
			config: map[string]string{
				"mint_method":     "app",
				"app_id":          "12345",
				"private_key":     testPEM,
				"installation_id": "67890",
				"repository":      "acme-corp/backend",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "'repository' is no longer supported; use 'repositories'",
		},
		{
			name: "github app - invalid scope",
			config: map[string]string{
				"mint_method":     "app",
				"app_id":          "12345",
				"private_key":     testPEM,
				"installation_id": "67890",
				"permissions":     "contents:owner",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "level must be read, write or admin",
		},
		{
			name: "github pat - scope rejected",
			config: map[string]string{
				"mint_method":  "pat",
				"token":        "ghp_test",
				"repositories": "backend",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "apply only to mint_method=app",
		},
		{
			// Parses to no scope, but the driver refuses the raw key at mint, so
			// accepting it here would store a spec that can never mint.
			name: "github pat - scope key that parses to nothing still rejected",
			config: map[string]string{
				"mint_method":  "pat",
				"token":        "ghp_test",
				"repositories": " , ",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "apply only to mint_method=app",
		},
		{
			name: "local - scope rejected",
			config: map[string]string{
				"token":       "ghp_test",
				"permissions": "contents:read",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "not supported with a local source",
		},
		{
			name: "local - legacy repository key",
			config: map[string]string{
				"token":      "ghp_test",
				"repository": "acme-corp/backend",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "'repository' is no longer supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(credential.NewConfig(tt.config), tt.sourceType)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseGitHubTokenScope(t *testing.T) {
	tooMany := make([]string, githubMaxScopedRepositories+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("repo-%d", i)
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantRepos []string
		wantPerms map[string]string
		errMsg    string
	}{
		{name: "empty", config: map[string]string{}},
		{
			name:      "trimmed, deduplicated and sorted",
			config:    map[string]string{"repositories": " frontend,backend , frontend,,", "permissions": " issues:write , contents:read"},
			wantRepos: []string{"backend", "frontend"},
			wantPerms: map[string]string{"contents": "read", "issues": "write"},
		},
		{
			name:      "deduplicated without regard to case, first spelling kept",
			config:    map[string]string{"repositories": "Backend,frontend,backend,BACKEND"},
			wantRepos: []string{"Backend", "frontend"},
		},
		{
			name:      "repository name characters",
			config:    map[string]string{"repositories": "Hello-World,my.repo,under_score"},
			wantRepos: []string{"Hello-World", "my.repo", "under_score"},
		},
		{
			name:      "same permission twice at one level collapses",
			config:    map[string]string{"permissions": "contents:read,contents:read"},
			wantPerms: map[string]string{"contents": "read"},
		},
		{
			name:      "admin level",
			config:    map[string]string{"permissions": "repository_projects:admin"},
			wantPerms: map[string]string{"repository_projects": "admin"},
		},
		{name: "owner in name", config: map[string]string{"repositories": "acme/backend"}, errMsg: "must be a bare repository name"},
		{name: "dot", config: map[string]string{"repositories": "."}, errMsg: "not a valid repository name"},
		{name: "dot dot", config: map[string]string{"repositories": ".."}, errMsg: "not a valid repository name"},
		{name: "invalid character", config: map[string]string{"repositories": "back end"}, errMsg: "not a valid repository name"},
		{name: "name too long", config: map[string]string{"repositories": strings.Repeat("a", 101)}, errMsg: "not a valid repository name"},
		{name: "too many", config: map[string]string{"repositories": strings.Join(tooMany, ",")}, errMsg: "at most 500"},
		{name: "missing level", config: map[string]string{"permissions": "contents"}, errMsg: "must be name:level"},
		{name: "missing name", config: map[string]string{"permissions": ":read"}, errMsg: "must be name:level"},
		{name: "bad level", config: map[string]string{"permissions": "contents:owner"}, errMsg: "level must be read, write or admin"},
		{name: "bad name", config: map[string]string{"permissions": "Contents:read"}, errMsg: "not a valid permission name"},
		{name: "conflicting levels", config: map[string]string{"permissions": "contents:read,contents:write"}, errMsg: "given twice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, err := ParseGitHubTokenScope(credential.NewConfig(tt.config))
			if tt.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRepos, scope.Repositories)
			assert.Equal(t, tt.wantPerms, scope.Permissions)
			assert.Equal(t, tt.wantRepos == nil && tt.wantPerms == nil, scope.IsZero())
		})
	}

	// Exactly the limit is allowed.
	scope, err := ParseGitHubTokenScope(credential.NewConfig(map[string]string{"repositories": strings.Join(tooMany[:githubMaxScopedRepositories], ",")}))
	require.NoError(t, err)
	assert.Len(t, scope.Repositories, githubMaxScopedRepositories)
}

func TestGitHubTokenCredType_Parse(t *testing.T) {
	ct := NewGitHubTokenCredType()

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid token with all fields",
			rawData: map[string]interface{}{
				"token":       "ghs_installation_token_123",
				"expires_at":  "2026-02-15T12:00:00Z",
				"permissions": `{"contents":"read","metadata":"read"}`,
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "valid PAT token (minimal)",
			rawData: map[string]interface{}{
				"token": "ghp_pat_token",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name:     "missing token",
			rawData:  map[string]interface{}{},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid token",
		},
		{
			name: "empty token",
			rawData: map[string]interface{}{
				"token": "",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid token",
		},
		{
			name: "token with lease",
			rawData: map[string]interface{}{
				"token": "ghs_leased",
			},
			leaseTTL: 30 * time.Minute,
			leaseID:  "lease-abc",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := ct.Parse(tt.rawData, nil, tt.leaseTTL, tt.leaseID)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cred)
				assert.Equal(t, credential.TypeGitHubToken, cred.Type)
				assert.Equal(t, credential.CategoryAPI, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.NotEmpty(t, cred.Data["token"])
				if tt.leaseID != "" {
					assert.True(t, cred.Revocable)
				} else {
					assert.False(t, cred.Revocable)
				}
			}
		})
	}
}

func TestGitHubTokenCredType_Parse_OptionalFields(t *testing.T) {
	ct := NewGitHubTokenCredType()

	rawData := map[string]interface{}{
		"token":       "ghs_test",
		"expires_at":  "2026-02-15T12:00:00Z",
		"permissions": `{"contents":"read"}`,
	}

	cred, err := ct.Parse(rawData, nil, 1*time.Hour, "")
	require.NoError(t, err)

	assert.Equal(t, "ghs_test", cred.Data["token"])
	assert.Equal(t, "2026-02-15T12:00:00Z", cred.Data["expires_at"])
	assert.Equal(t, `{"contents":"read"}`, cred.Data["permissions"])
}

func TestGitHubTokenCredType_Validate(t *testing.T) {
	ct := NewGitHubTokenCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{
					"token": "ghp_xxxxxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "ghp_xxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "expected type github_token",
		},
		{
			name: "missing token",
			cred: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing token",
		},
		{
			name: "empty token",
			cred: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{
					"token": "",
				},
			},
			wantErr: true,
			errMsg:  "missing token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.Validate(tt.cred)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGitHubTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewGitHubTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestGitHubTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewGitHubTokenCredType()
	fields := ct.SensitiveConfigFields()
	assert.Len(t, fields, 2)
	assert.Contains(t, fields, "token")
	assert.Contains(t, fields, "private_key")
}

func TestGitHubTokenCredType_FieldSchemas(t *testing.T) {
	ct := NewGitHubTokenCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "token")
	assert.True(t, schemas["token"].Sensitive)
	assert.NotEmpty(t, schemas["token"].Description)

	assert.Contains(t, schemas, "expires_at")
	assert.False(t, schemas["expires_at"].Sensitive)

	assert.Contains(t, schemas, "permissions")
	assert.False(t, schemas["permissions"].Sensitive)
}
