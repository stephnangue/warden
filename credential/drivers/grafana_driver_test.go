package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrafanaDriverFactory_Type(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	assert.Equal(t, credential.SourceTypeGrafana, factory.Type())
}

func TestGrafanaDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "admin_token")
	assert.Contains(t, fields, "ca_data")
}

func TestGrafanaDriverFactory_InferCredentialType(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	credType, err := factory.InferCredentialType(nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, credType)
}

func TestGrafanaDriverFactory_ValidateConfig(t *testing.T) {
	factory := &GrafanaDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: map[string]string{
				"grafana_url": "https://mystack.grafana.net",
				"admin_token": "glsa_test_token",
			},
			wantErr: false,
		},
		{
			name: "missing grafana_url",
			config: map[string]string{
				"admin_token": "glsa_test_token",
			},
			wantErr: true,
			errMsg:  "grafana_url",
		},
		{
			name: "missing admin_token",
			config: map[string]string{
				"grafana_url": "https://mystack.grafana.net",
			},
			wantErr: true,
			errMsg:  "admin_token",
		},
		{
			name: "invalid grafana_url scheme",
			config: map[string]string{
				"grafana_url": "http://mystack.grafana.net",
				"admin_token": "glsa_test_token",
			},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name: "http allowed with tls_skip_verify",
			config: map[string]string{
				"grafana_url":     "http://grafana.local",
				"admin_token":     "glsa_test_token",
				"tls_skip_verify": "true",
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

func TestGrafanaDriverFactory_Create(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := factory.Create(map[string]string{
		"grafana_url": "https://mystack.grafana.net",
		"admin_token": "glsa_test_token",
	}, log)
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeGrafana, driver.Type())
}

func TestGrafanaDriver_Type(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeGrafana, driver.Type())
}

func TestGrafanaDriver_Cleanup(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestGrafanaDriver_NotRotatable(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: map[string]string{},
		},
	}
	var sd credential.SourceDriver = driver
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "GrafanaDriver should not implement credential.Rotatable")
}

func TestGrafanaDriver_GetGrafanaURL(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Config: map[string]string{"grafana_url": "https://mystack.grafana.net/"},
		},
	}
	assert.Equal(t, "https://mystack.grafana.net", driver.getGrafanaURL())
}

func TestGrafanaDriver_MintCredential(t *testing.T) {
	var saCreateCalled, tokenCreateCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts":
			saCreateCalled.Add(1)

			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "Viewer", body["role"])
			assert.Equal(t, false, body["isDisabled"])
			name, _ := body["name"].(string)
			assert.True(t, strings.HasPrefix(name, "warden-"), "SA name should start with warden-")

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 42,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts/42/tokens":
			tokenCreateCalled.Add(1)

			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "warden-token", body["name"])
			secondsToLive, _ := body["secondsToLive"].(float64)
			assert.Equal(t, float64(3600), secondsToLive)

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"key": "glsa_minted_token_123",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin_token",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test-viewer",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "glsa_minted_token_123", rawData["api_key"])
	assert.Equal(t, grafanaDefaultTokenExpiry, ttl)
	assert.Equal(t, "42", leaseID)
	assert.Equal(t, int32(1), saCreateCalled.Load())
	assert.Equal(t, int32(1), tokenCreateCalled.Load())
}

func TestGrafanaDriver_MintCredential_CustomConfig(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "Admin", body["role"])
			name, _ := body["name"].(string)
			assert.True(t, strings.HasPrefix(name, "myprefix-"), "SA name should start with custom prefix")

			// Verify org_id header
			assert.Equal(t, "99", r.Header.Get("X-Grafana-Org-Id"))

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 100})

		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts/100/tokens":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			secondsToLive, _ := body["secondsToLive"].(float64)
			assert.Equal(t, float64(1800), secondsToLive) // 30m

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"key": "glsa_custom"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-admin",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"role":         "Admin",
			"token_expiry": "30m",
			"name_prefix":  "myprefix-",
			"org_id":       "99",
		},
	}

	rawData, _, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "glsa_custom", rawData["api_key"])
	assert.Equal(t, "100", leaseID)
}

func TestGrafanaDriver_MintCredential_InvalidRole(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": "https://grafana.test",
				"admin_token": "test",
			},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name: "test-bad-role",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"role": "SuperAdmin",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
}

func TestGrafanaDriver_MintCredential_SACreateFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Insufficient permissions"}`))
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_bad_token",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test-fail",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create service account")
}

func TestGrafanaDriver_MintCredential_TokenCreateFails_CleansUpSA(t *testing.T) {
	var deleteCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 77})

		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts/77/tokens":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"Internal error"}`))

		case r.Method == http.MethodDelete && r.URL.Path == "/api/serviceaccounts/77":
			deleteCalled.Add(1)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test-cleanup",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create service account token")
	assert.Equal(t, int32(1), deleteCalled.Load(), "should cleanup service account on token create failure")
}

func TestGrafanaDriver_MintCredential_EmptyTokenKey(t *testing.T) {
	var deleteCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 88})

		case r.Method == http.MethodPost && r.URL.Path == "/api/serviceaccounts/88/tokens":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"key": ""})

		case r.Method == http.MethodDelete && r.URL.Path == "/api/serviceaccounts/88":
			deleteCalled.Add(1)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test-empty-key",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty token key")
	assert.Equal(t, int32(1), deleteCalled.Load(), "should cleanup on empty token key")
}

func TestGrafanaDriver_Revoke(t *testing.T) {
	var deleteCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/serviceaccounts/42" {
			deleteCalled.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.Revoke(context.Background(), "42")
	require.NoError(t, err)
	assert.Equal(t, int32(1), deleteCalled.Load())
}

func TestGrafanaDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: map[string]string{},
		},
	}
	err := driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestGrafanaDriver_Revoke_APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Service account not found"}`))
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.Revoke(context.Background(), "999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete service account")
}

func TestGrafanaDriver_VerifySpec(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/serviceaccounts/search", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("perpage"))
		assert.Equal(t, "Bearer glsa_admin", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalCount":      1,
			"serviceAccounts": []interface{}{},
		})
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.VerifySpec(context.Background(), &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{},
	})
	require.NoError(t, err)
}

func TestGrafanaDriver_VerifySpec_Unauthorized(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_bad_token",
			},
		},
		httpClient: server.Client(),
	}

	err := driver.VerifySpec(context.Background(), &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin token verification failed")
}

func TestValidateGrafanaURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://mystack.grafana.net", false, ""},
		{"https://grafana.example.com", false, ""},
		{"https://logs-prod-us-central1.grafana.net", false, ""},
		{"http://grafana.local", true, "must use https://"},
		{"ftp://grafana.local", true, "must use https://"},
		{"https://", true, "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateGrafanaURL(tt.url, false)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGrafanaURL_TLSSkipVerify(t *testing.T) {
	require.NoError(t, validateGrafanaURL("http://grafana.local", true))
	require.NoError(t, validateGrafanaURL("https://grafana.local", true))
	require.Error(t, validateGrafanaURL("ftp://grafana.local", true))
}

func TestGrafanaDriver_MintCredential_SAZeroID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 0})
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_admin",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test-zero-id",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ID 0")
}

func TestGrafanaDriver_AuthorizationHeader(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer glsa_my_admin_token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"totalCount":0,"serviceAccounts":[]}`)
	}))
	defer server.Close()

	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGrafana,
			Config: map[string]string{
				"grafana_url": server.URL,
				"admin_token": "glsa_my_admin_token",
			},
		},
		httpClient: server.Client(),
	}

	_, _, err := driver.doGrafanaRequest(context.Background(), http.MethodGet, "/api/serviceaccounts/search", nil, "")
	require.NoError(t, err)
}
