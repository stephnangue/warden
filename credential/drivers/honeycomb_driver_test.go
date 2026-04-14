package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHoneycombDriverFactory_Type(t *testing.T) {
	factory := &HoneycombDriverFactory{}
	assert.Equal(t, credential.SourceTypeHoneycomb, factory.Type())
}

func TestHoneycombDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &HoneycombDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "management_key_id")
	assert.Contains(t, fields, "management_key_secret")
	assert.Contains(t, fields, "ca_data")
}

func TestHoneycombDriverFactory_InferCredentialType(t *testing.T) {
	factory := &HoneycombDriverFactory{}
	credType, err := factory.InferCredentialType(nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, credType)
}

func TestHoneycombDriverFactory_ValidateConfig(t *testing.T) {
	factory := &HoneycombDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc123",
				"management_key_secret": "secret-value",
				"team_slug":             "my-team",
			},
			wantErr: false,
		},
		{
			name: "valid config without url (uses default)",
			config: map[string]string{
				"management_key_id":     "hcxmk_01abc123",
				"management_key_secret": "secret-value",
				"team_slug":             "my-team",
			},
			wantErr: false,
		},
		{
			name: "missing management_key_id",
			config: map[string]string{
				"management_key_secret": "secret-value",
				"team_slug":             "my-team",
			},
			wantErr: true,
			errMsg:  "management_key_id",
		},
		{
			name: "missing management_key_secret",
			config: map[string]string{
				"management_key_id": "hcxmk_01abc123",
				"team_slug":         "my-team",
			},
			wantErr: true,
			errMsg:  "management_key_secret",
		},
		{
			name: "missing team_slug",
			config: map[string]string{
				"management_key_id":     "hcxmk_01abc123",
				"management_key_secret": "secret-value",
			},
			wantErr: true,
			errMsg:  "team_slug",
		},
		{
			name: "invalid honeycomb_url scheme",
			config: map[string]string{
				"honeycomb_url":         "http://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc123",
				"management_key_secret": "secret-value",
				"team_slug":             "my-team",
			},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name: "http allowed with tls_skip_verify",
			config: map[string]string{
				"honeycomb_url":         "http://honeycomb.local",
				"management_key_id":     "hcxmk_01abc123",
				"management_key_secret": "secret-value",
				"team_slug":             "my-team",
				"tls_skip_verify":       "true",
			},
			wantErr: false,
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

func TestHoneycombDriverFactory_Create(t *testing.T) {
	factory := &HoneycombDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := factory.Create(map[string]string{
		"honeycomb_url":         "https://api.honeycomb.io",
		"management_key_id":     "hcxmk_01abc123",
		"management_key_secret": "secret-value",
		"team_slug":             "my-team",
	}, log)
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeHoneycomb, driver.Type())
}

func TestHoneycombDriver_Type(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeHoneycomb,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeHoneycomb, driver.Type())
}

func TestHoneycombDriver_Cleanup(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeHoneycomb,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestHoneycombDriver_NotRotatable(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeHoneycomb,
			Config: map[string]string{},
		},
	}
	var sd credential.SourceDriver = driver
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "HoneycombDriver should not implement credential.Rotatable")
}

func TestHoneycombDriver_GetHoneycombURL(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Config: map[string]string{"honeycomb_url": "https://api.honeycomb.io/"},
		},
	}
	assert.Equal(t, "https://api.honeycomb.io", driver.getHoneycombURL())
}

func TestHoneycombDriver_GetHoneycombURL_Default(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Config: map[string]string{},
		},
	}
	assert.Equal(t, "https://api.honeycomb.io", driver.getHoneycombURL())
}

func TestHoneycombDriver_MintCredential(t *testing.T) {
	var createCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/2/teams/my-team/api-keys" {
			createCalled.Add(1)

			assert.Equal(t, honeycombContentType, r.Header.Get("Content-Type"))
			assert.Equal(t, honeycombContentType, r.Header.Get("Accept"))
			assert.Equal(t, "Bearer hcxmk_01abc:secret123", r.Header.Get("Authorization"))

			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)

			data, _ := body["data"].(map[string]interface{})
			assert.Equal(t, "api-keys", data["type"])

			attrs, _ := data["attributes"].(map[string]interface{})
			assert.Equal(t, "ingest", attrs["key_type"])

			rels, _ := data["relationships"].(map[string]interface{})
			env, _ := rels["environment"].(map[string]interface{})
			envData, _ := env["data"].(map[string]interface{})
			assert.Equal(t, "env-123", envData["id"])

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":   "hcxik_01xyz",
					"type": "api-keys",
					"attributes": map[string]interface{}{
						"secret": "secret-ingest-key-value",
						"name":   attrs["name"],
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-ingest",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"environment_id": "env-123",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "secret-ingest-key-value", rawData["api_key"])
	assert.Equal(t, "ingest", rawData["key_type"])
	assert.Equal(t, honeycombDefaultKeyTTL, ttl)
	assert.Equal(t, "hcxik_01xyz", leaseID)
	assert.Equal(t, int32(1), createCalled.Load())
}

func TestHoneycombDriver_MintCredential_ConfigurationKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/2/teams/my-team/api-keys" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)

			data, _ := body["data"].(map[string]interface{})
			attrs, _ := data["attributes"].(map[string]interface{})
			assert.Equal(t, "configuration", attrs["key_type"])

			perms, _ := attrs["permissions"].(map[string]interface{})
			assert.Equal(t, true, perms["run_queries"])

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id": "hcxlk_01xyz",
					"attributes": map[string]interface{}{
						"secret": "secret-config-key",
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-config",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"environment_id": "env-456",
			"key_type":       "configuration",
			"permissions":    `{"run_queries":true}`,
		},
	}

	rawData, _, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "secret-config-key", rawData["api_key"])
	assert.Equal(t, "configuration", rawData["key_type"])
	assert.Equal(t, "hcxlk_01xyz", leaseID)
}

func TestHoneycombDriver_MintCredential_CustomConfig(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/2/teams/my-team/api-keys" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)

			data, _ := body["data"].(map[string]interface{})
			attrs, _ := data["attributes"].(map[string]interface{})
			name, _ := attrs["name"].(string)
			assert.True(t, len(name) > 0 && name[:7] == "myapp--", "key name should start with custom prefix: got %q", name)

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id": "hcxik_custom",
					"attributes": map[string]interface{}{
						"secret": "secret-custom",
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"environment_id":  "env-123",
			"key_type":        "ingest",
			"key_name_prefix": "myapp-",
			"key_ttl":         "1h",
		},
	}

	rawData, ttl, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "secret-custom", rawData["api_key"])
	assert.Equal(t, "ingest", rawData["key_type"])
	assert.Equal(t, 1*time.Hour, ttl)
}

func TestHoneycombDriver_MintCredential_InvalidPermissionsJSON(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name: "test-bad-perms",
		Config: map[string]string{
			"environment_id": "env-123",
			"key_type":       "configuration",
			"permissions":    `{not valid json`,
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permissions JSON")
}

func TestHoneycombDriver_MintCredential_EmptyID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id": "",
				"attributes": map[string]interface{}{
					"secret": "some-secret",
				},
			},
		})
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-empty-id",
		Config: map[string]string{
			"environment_id": "env-123",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty ID")
}

func TestHoneycombDriver_MintCredential_InvalidKeyType(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name: "test-bad-type",
		Config: map[string]string{
			"environment_id": "env-123",
			"key_type":       "management",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key_type")
}

func TestHoneycombDriver_MintCredential_MissingEnvironmentID(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name:   "test-no-env",
		Config: map[string]string{},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment_id is required")
}

func TestHoneycombDriver_MintCredential_PermissionsOnIngestKey(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name: "test-perms-ingest",
		Config: map[string]string{
			"environment_id": "env-123",
			"key_type":       "ingest",
			"permissions":    `{"create_datasets":true}`,
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permissions can only be set for configuration keys")
}

func TestHoneycombDriver_MintCredential_APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":[{"title":"Forbidden"}]}`))
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_bad",
				"management_key_secret": "bad-secret",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-error",
		Config: map[string]string{
			"environment_id": "env-123",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create API key")
}

func TestHoneycombDriver_MintCredential_EmptySecret(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id": "hcxik_01xyz",
				"attributes": map[string]interface{}{
					"secret": "",
				},
			},
		})
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-empty-secret",
		Config: map[string]string{
			"environment_id": "env-123",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty secret")
}

func TestHoneycombDriver_Revoke(t *testing.T) {
	var deleteCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/2/teams/my-team/api-keys/hcxik_01xyz" {
			deleteCalled.Add(1)
			assert.Equal(t, "Bearer hcxmk_01abc:secret123", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.Revoke(context.Background(), "hcxik_01xyz")
	require.NoError(t, err)
	assert.Equal(t, int32(1), deleteCalled.Load())
}

func TestHoneycombDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeHoneycomb,
			Config: map[string]string{},
		},
	}
	err := driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestHoneycombDriver_Revoke_AlreadyDeleted(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errors":[{"title":"Not Found"}]}`))
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	// 404 should be treated as success (key already deleted)
	err := driver.Revoke(context.Background(), "hcxik_gone")
	require.NoError(t, err)
}

func TestHoneycombDriver_VerifySpec(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/2/teams/my-team/api-keys", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("page[size]"))
		assert.Equal(t, "ingest", r.URL.Query().Get("filter[type]"))
		assert.Equal(t, "Bearer hcxmk_01abc:secret123", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []interface{}{},
		})
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.VerifySpec(context.Background(), &credential.CredSpec{
		Name: "test",
		Config: map[string]string{
			"environment_id": "env-123",
		},
	})
	require.NoError(t, err)
}

func TestHoneycombDriver_VerifySpec_MissingEnvironmentID(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: &http.Client{},
	}

	err := driver.VerifySpec(context.Background(), &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment_id")
}

func TestHoneycombDriver_VerifySpec_InvalidKeyType(t *testing.T) {
	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         "https://api.honeycomb.io",
				"management_key_id":     "hcxmk_01abc",
				"management_key_secret": "secret123",
				"team_slug":             "my-team",
			},
		},
		httpClient: &http.Client{},
	}

	err := driver.VerifySpec(context.Background(), &credential.CredSpec{
		Name: "test",
		Config: map[string]string{
			"environment_id": "env-123",
			"key_type":       "management",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key_type")
}

func TestHoneycombDriver_VerifySpec_Unauthorized(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"title":"Unauthorized"}]}`))
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_bad",
				"management_key_secret": "bad-secret",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.VerifySpec(context.Background(), &credential.CredSpec{
		Name: "test",
		Config: map[string]string{
			"environment_id": "env-123",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "management key verification failed")
}

func TestValidateHoneycombURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://api.honeycomb.io", false, ""},
		{"https://api.eu1.honeycomb.io", false, ""},
		{"", false, ""}, // empty uses default
		{"http://honeycomb.local", true, "must use https://"},
		{"ftp://honeycomb.local", true, "must use https://"},
		{"https://", true, "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateHoneycombURL(tt.url, false)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateHoneycombURL_TLSSkipVerify(t *testing.T) {
	require.NoError(t, validateHoneycombURL("http://honeycomb.local", true))
	require.NoError(t, validateHoneycombURL("https://honeycomb.local", true))
	require.Error(t, validateHoneycombURL("ftp://honeycomb.local", true))
}

func TestHoneycombDriver_AuthorizationHeader(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer hcxmk_mykey:mysecret", r.Header.Get("Authorization"))
		assert.Equal(t, honeycombContentType, r.Header.Get("Accept"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_mykey",
				"management_key_secret": "mysecret",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	_, _, err := driver.doHoneycombRequest(context.Background(), http.MethodGet, "/2/teams/my-team/api-keys", nil)
	require.NoError(t, err)
}

func TestHoneycombDriver_ContentTypeOnPost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, honeycombContentType, r.Header.Get("Content-Type"))
		assert.Equal(t, honeycombContentType, r.Header.Get("Accept"))

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":         "hcxik_test",
				"attributes": map[string]interface{}{"secret": "s"},
			},
		})
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_k",
				"management_key_secret": "s",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	_, _, err := driver.doHoneycombRequest(context.Background(), http.MethodPost, "/2/teams/my-team/api-keys", []byte(`{}`))
	require.NoError(t, err)
}

func TestHoneycombDriver_NoContentTypeOnGet(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Content-Type"), "GET requests should not set Content-Type")
		assert.Equal(t, honeycombContentType, r.Header.Get("Accept"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	driver := &HoneycombDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeHoneycomb,
			Config: map[string]string{
				"honeycomb_url":         server.URL,
				"management_key_id":     "hcxmk_k",
				"management_key_secret": "s",
				"team_slug":             "my-team",
			},
		},
		httpClient: server.Client(),
	}

	_, _, err := driver.doHoneycombRequest(context.Background(), http.MethodGet, "/2/teams/my-team/api-keys", nil)
	require.NoError(t, err)
}
