package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEncodedAPIKey returns a base64-encoded "id:api_key" string for testing.
func testEncodedAPIKey(id, key string) string {
	return base64.StdEncoding.EncodeToString([]byte(id + ":" + key))
}

// ============================================================================
// Factory Tests
// ============================================================================

func TestElasticDriverFactory_Type(t *testing.T) {
	f := &ElasticDriverFactory{}
	assert.Equal(t, credential.SourceTypeElastic, f.Type())
}

func TestElasticDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &ElasticDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "api_key")
}

func TestElasticDriverFactory_InferCredentialType(t *testing.T) {
	f := &ElasticDriverFactory{}

	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, ct)
}

func TestElasticDriverFactory_ValidateConfig(t *testing.T) {
	f := &ElasticDriverFactory{}

	t.Run("missing elastic_url", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"api_key": testEncodedAPIKey("id1", "secret"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "elastic_url")
	})

	t.Run("missing api_key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url": "https://elastic.example.com",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key")
	})

	t.Run("elastic_url rejects http scheme", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url": "http://elastic.example.com",
			"api_key":     testEncodedAPIKey("id1", "secret"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})

	t.Run("valid minimal config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url": "https://elastic.example.com",
			"api_key":     testEncodedAPIKey("id1", "secret"),
		})
		require.NoError(t, err)
	})

	t.Run("valid full config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url":      "https://elastic.example.com",
			"api_key":          testEncodedAPIKey("id1", "secret"),
			"api_key_id":       "id1",
			"activation_delay": "30s",
			"key_name_prefix":  "myapp",
		})
		require.NoError(t, err)
	})

	t.Run("invalid activation_delay", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url":      "https://elastic.example.com",
			"api_key":          testEncodedAPIKey("id1", "secret"),
			"activation_delay": "not-a-duration",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "activation_delay")
	})
}

// ============================================================================
// decodeElasticAPIKeyID Tests
// ============================================================================

func TestDecodeElasticAPIKeyID(t *testing.T) {
	t.Run("valid encoded key", func(t *testing.T) {
		encoded := testEncodedAPIKey("VuaCfGcBCdbkQm", "ui2lp2axTNmsyakw9tvNnw")
		id, err := decodeElasticAPIKeyID(encoded)
		require.NoError(t, err)
		assert.Equal(t, "VuaCfGcBCdbkQm", id)
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := decodeElasticAPIKeyID("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := decodeElasticAPIKeyID("!!!not-base64!!!")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base64")
	})

	t.Run("missing colon separator", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("nocolonhere"))
		_, err := decodeElasticAPIKeyID(encoded)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "id:api_key")
	})

	t.Run("empty id before colon", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(":some-key"))
		_, err := decodeElasticAPIKeyID(encoded)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "id:api_key")
	})
}

// ============================================================================
// Mock Server
// ============================================================================

// newElasticMockServer creates a test server that mocks Elasticsearch Security API endpoints.
func newElasticMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Authenticate endpoint
	mux.HandleFunc("/_security/_authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" || auth == "ApiKey invalid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "security_exception",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"username":            "warden-service",
			"roles":               []string{"superuser"},
			"enabled":             true,
			"authentication_type": "api_key",
			"api_key": map[string]interface{}{
				"id":   "source-key-id",
				"name": "warden-source",
			},
		})
	})

	// Create API key endpoint
	mux.HandleFunc("/_security/api_key", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || auth == "ApiKey invalid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "security_exception"})
			return
		}

		switch r.Method {
		case http.MethodPost:
			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			name, _ := reqBody["name"].(string)
			newID := "new-key-id-123"
			newKey := "new-api-key-secret"
			encoded := base64.StdEncoding.EncodeToString([]byte(newID + ":" + newKey))

			resp := map[string]interface{}{
				"id":      newID,
				"name":    name,
				"api_key": newKey,
				"encoded": encoded,
			}

			// Include expiration if requested
			if exp, ok := reqBody["expiration"]; ok && exp != "" {
				// Return expiration as Unix millis 1 hour from now
				resp["expiration"] = time.Now().Add(1 * time.Hour).UnixMilli()
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)

		case http.MethodDelete:
			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			ids, _ := reqBody["ids"].([]interface{})
			invalidated := make([]string, 0, len(ids))
			for _, id := range ids {
				if s, ok := id.(string); ok {
					invalidated = append(invalidated, s)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"invalidated_api_keys":            invalidated,
				"previously_invalidated_api_keys": []string{},
				"error_count":                     0,
			})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Query API keys, which the rotation orphan sweep uses. The default cluster
	// holds no orphans; tests that want some use newElasticSweepServer.
	mux.HandleFunc("/_security/_query/api_key", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"api_keys": []interface{}{},
			"total":    0,
			"count":    0,
		})
	})

	return httptest.NewServer(mux)
}

// elasticSweepServer is a cluster that holds rotation keys and records what the
// sweep asked of it, so a test can assert both the scoping of the query and the
// set of keys the sweep chose to invalidate.
type elasticSweepServer struct {
	*httptest.Server

	// keys are the api keys the query endpoint reports, by id.
	keys []string

	lastQuery       map[string]interface{}
	lastInvalidated []string
}

func newElasticSweepServer(t *testing.T, keys ...string) *elasticSweepServer {
	t.Helper()

	s := &elasticSweepServer{keys: keys}
	mux := http.NewServeMux()

	mux.HandleFunc("/_security/_authenticate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "warden-service",
			"enabled":  true,
			"api_key":  map[string]interface{}{"id": "source-key-id"},
		})
	})

	mux.HandleFunc("/_security/_query/api_key", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&s.lastQuery)

		found := make([]interface{}, 0, len(s.keys))
		for _, id := range s.keys {
			found = append(found, map[string]interface{}{"id": id, "name": "warden-source-rotated-1"})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"api_keys": found})
	})

	mux.HandleFunc("/_security/api_key", func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		switch r.Method {
		case http.MethodDelete:
			ids, _ := reqBody["ids"].([]interface{})
			s.lastInvalidated = nil
			for _, id := range ids {
				if v, ok := id.(string); ok {
					s.lastInvalidated = append(s.lastInvalidated, v)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"invalidated_api_keys":            s.lastInvalidated,
				"previously_invalidated_api_keys": []string{},
				"error_count":                     0,
			})
		default:
			name, _ := reqBody["name"].(string)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "new-key-id-123",
				"name":    name,
				"encoded": testEncodedAPIKey("new-key-id-123", "new-secret"),
			})
		}
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// newElasticInvalidateServer answers every invalidate with a fixed body, so the
// per-key outcomes the cluster reports under a 200 can be driven directly.
func newElasticInvalidateServer(t *testing.T, body map[string]interface{}) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/_security/api_key", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestElasticDriver(t *testing.T, serverURL string) *ElasticDriver {
	t.Helper()
	return &ElasticDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeElastic,
			Config: map[string]string{
				"elastic_url": serverURL,
				"api_key":     testEncodedAPIKey("source-key-id", "source-secret"),
			},
		},
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		sourceAPIKeyID: "source-key-id",
		sourceUsername: "warden-service",
	}
}

// ============================================================================
// Driver Unit Tests
// ============================================================================

func TestElasticDriver_Type(t *testing.T) {
	d := &ElasticDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeElastic,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeElastic, d.Type())
}

func TestElasticDriver_Cleanup(t *testing.T) {
	d := &ElasticDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeElastic,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	require.NoError(t, d.Cleanup(context.TODO()))
}

func TestElasticDriver_SupportsRotation(t *testing.T) {
	newDriver := func(config map[string]string, keyID string) *ElasticDriver {
		return &ElasticDriver{
			credSource:     &credential.CredSource{Type: credential.SourceTypeElastic, Config: config},
			sourceAPIKeyID: keyID,
		}
	}

	t.Run("true when sourceAPIKeyID is set", func(t *testing.T) {
		d := newDriver(map[string]string{"api_key": "k"}, "key-123")
		assert.True(t, d.SupportsRotation())
	})

	t.Run("false when sourceAPIKeyID is empty", func(t *testing.T) {
		d := newDriver(map[string]string{}, "")
		assert.False(t, d.SupportsRotation())
	})

	// A chained source holds no key of its own to rotate: it lives at its source
	// of truth, and whoever owns the referenced spec rotates it there.
	t.Run("false when the cluster key is chained", func(t *testing.T) {
		d := newDriver(map[string]string{credential.ConfigSecretSpec: "es-key"}, "key-123")
		assert.False(t, d.SupportsRotation())
	})
}

// ============================================================================
// MintCredential Tests
// ============================================================================

func TestElasticDriver_MintCredential(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Config: map[string]string{},
	}

	rawData, _, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.NotEmpty(t, rawData["api_key"], "should return encoded API key")
	assert.True(t, ttl > 0, "default expiration of 1h should produce a positive TTL")
	assert.Equal(t, "elastic:new-key-id-123", leaseID)
}

func TestElasticDriver_MintCredential_WithExpiration(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"expiration": "1h",
		},
	}

	rawData, _, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.NotEmpty(t, rawData["api_key"])
	assert.True(t, ttl > 0, "should have a positive TTL when expiration is set")
	assert.Contains(t, leaseID, "elastic:")
}

func TestElasticDriver_MintCredential_WithRoleDescriptors(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"role_descriptors": `{"reader":{"indices":[{"names":["logs-*"],"privileges":["read"]}]}}`,
		},
	}

	rawData, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)
	assert.NotEmpty(t, rawData["api_key"])
}

func TestElasticDriver_MintCredential_InvalidRoleDescriptors(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"role_descriptors": "not-valid-json",
		},
	}

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role_descriptors JSON")
}

func TestElasticDriver_MintCredential_WithCustomKeyName(t *testing.T) {
	var receivedName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_security/_authenticate":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "test-user",
				"enabled":  true,
			})
		case "/_security/api_key":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			receivedName, _ = body["name"].(string)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "key-id",
				"api_key": "secret",
				"encoded": testEncodedAPIKey("key-id", "secret"),
			})
		}
	}))
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"key_name": "my-custom-key",
		},
	}

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)
	assert.Equal(t, "my-custom-key", receivedName)
}

// ============================================================================
// Revoke Tests
// ============================================================================

func TestElasticDriver_Revoke(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	err := d.Revoke(context.TODO(), "elastic:some-key-id")
	require.NoError(t, err)
}

func TestElasticDriver_Revoke_EmptyLeaseID(t *testing.T) {
	d := &ElasticDriver{}
	err := d.Revoke(context.TODO(), "")
	require.NoError(t, err, "empty lease ID should be a no-op")
}

func TestElasticDriver_Revoke_InvalidLeaseIDFormat(t *testing.T) {
	d := &ElasticDriver{
		credSource: &credential.CredSource{
			Config: map[string]string{
				"elastic_url": "https://example.com",
				"api_key":     "some-key",
			},
		},
		httpClient: &http.Client{},
	}
	err := d.Revoke(context.TODO(), "bad-format-no-prefix")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid lease ID format")
}

func TestElasticDriver_Revoke_VerifiesKeyIDSent(t *testing.T) {
	var receivedIDs []interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_security/_authenticate":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "test-user",
			})
		case "/_security/api_key":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			receivedIDs = body["ids"].([]interface{})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"invalidated_api_keys":            receivedIDs,
				"previously_invalidated_api_keys": []string{},
				"error_count":                     0,
			})
		}
	}))
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	err := d.Revoke(context.TODO(), "elastic:my-key-to-revoke")
	require.NoError(t, err)
	require.Len(t, receivedIDs, 1)
	assert.Equal(t, "my-key-to-revoke", receivedIDs[0])
}

// ============================================================================
// VerifySpec Tests
// ============================================================================

func TestElasticDriver_VerifySpec(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	t.Run("valid credentials", func(t *testing.T) {
		spec := &credential.CredSpec{Name: "test-spec", Config: map[string]string{}}
		err := d.VerifySpec(context.TODO(), spec)
		require.NoError(t, err)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		d2 := newTestElasticDriver(t, srv.URL)
		d2.credSource.Config["api_key"] = "invalid-key"

		spec := &credential.CredSpec{Name: "test-spec", Config: map[string]string{}}
		err := d2.VerifySpec(context.TODO(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "spec verification failed")
	})
}

// ============================================================================
// Rotation Tests
// ============================================================================

func TestElasticDriver_PrepareRotation(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	newConfig, cleanupConfig, activateAfter, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)

	// New config should contain updated api_key and api_key_id
	assert.NotEmpty(t, newConfig["api_key"])
	assert.NotEqual(t, d.credSource.Config["api_key"], newConfig["api_key"], "new key should differ from old")
	assert.Equal(t, "new-key-id-123", newConfig["api_key_id"])

	// Cleanup config should contain old key ID
	assert.Equal(t, "source-key-id", cleanupConfig["api_key_id"])

	// Activation delay should be default
	assert.Equal(t, DefaultElasticActivationDelay, activateAfter)

	// Original config should be preserved (elastic_url copied over)
	assert.Equal(t, srv.URL, newConfig["elastic_url"])
}

func TestElasticDriver_PrepareRotation_CustomActivationDelay(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)
	d.credSource.Config["activation_delay"] = "5m"

	_, _, activateAfter, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, activateAfter)
}

func TestElasticDriver_PrepareRotation_NoKeyID(t *testing.T) {
	d := &ElasticDriver{sourceAPIKeyID: ""}
	_, _, _, err := d.PrepareRotation(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source API key ID not discovered")
}

func TestElasticDriver_CommitRotation(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)
	oldAPIKeyID := d.sourceAPIKeyID

	newConfig := map[string]string{
		"elastic_url": srv.URL,
		"api_key":     testEncodedAPIKey("new-key-id", "new-secret"),
		"api_key_id":  "new-key-id",
	}

	err := d.CommitRotation(context.TODO(), newConfig)
	require.NoError(t, err)

	// Driver should now use new config
	assert.Equal(t, newConfig["api_key"], d.credSource.Config["api_key"])
	assert.Equal(t, "new-key-id", d.sourceAPIKeyID)
	assert.NotEqual(t, oldAPIKeyID, d.sourceAPIKeyID)
}

// A failed commit must NOT put the old config back. The rotation manager
// persists the new config before calling CommitRotation, so restoring the old
// one here would leave this instance authenticating as a key storage no longer
// records — and the next cycle would then mint a replacement for that key,
// stranding a new one every time it failed.
func TestElasticDriver_CommitRotation_KeepsNewConfigOnFailure(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	// Provide an invalid key so authentication fails
	newConfig := map[string]string{
		"elastic_url": srv.URL,
		"api_key":     "invalid-key",
		"api_key_id":  "bad-key-id",
	}

	err := d.CommitRotation(context.TODO(), newConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate")

	assert.Equal(t, "invalid-key", d.credSource.Config["api_key"],
		"driver must keep the config the manager already persisted")
	assert.Equal(t, "bad-key-id", d.sourceAPIKeyID)
}

func TestElasticDriver_CleanupRotation(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	err := d.CleanupRotation(context.TODO(), map[string]string{
		"api_key_id": "old-key-to-invalidate",
	})
	require.NoError(t, err)
}

func TestElasticDriver_CleanupRotation_EmptyID(t *testing.T) {
	d := &ElasticDriver{}
	err := d.CleanupRotation(context.TODO(), map[string]string{})
	require.NoError(t, err, "empty api_key_id should be a no-op")
}

// ============================================================================
// Full Rotation Lifecycle
// ============================================================================

func TestElasticDriver_FullRotationLifecycle(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)
	originalAPIKey := d.credSource.Config["api_key"]

	// Step 1: Prepare
	newConfig, cleanupConfig, activateAfter, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)
	assert.True(t, activateAfter > 0)

	// Step 2: Commit
	err = d.CommitRotation(context.TODO(), newConfig)
	require.NoError(t, err)
	assert.NotEqual(t, originalAPIKey, d.credSource.Config["api_key"])

	// Step 3: Cleanup
	err = d.CleanupRotation(context.TODO(), cleanupConfig)
	require.NoError(t, err)

	// Verify the driver still works after rotation
	spec := &credential.CredSpec{Name: "post-rotation", Config: map[string]string{}}
	rawData, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)
	assert.NotEmpty(t, rawData["api_key"])
}

// ============================================================================
// Factory Create Tests
// ============================================================================

func TestElasticDriverFactory_Create(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	f := &ElasticDriverFactory{}
	driver, err := f.Create(map[string]string{
		"elastic_url": srv.URL,
		"api_key":     testEncodedAPIKey("source-key-id", "source-secret"),
	}, log)
	require.NoError(t, err)

	elasticDriver, ok := driver.(*ElasticDriver)
	require.True(t, ok)
	assert.Equal(t, "source-key-id", elasticDriver.sourceAPIKeyID)
}

func TestElasticDriverFactory_Create_WithExplicitKeyID(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	f := &ElasticDriverFactory{}

	t.Run("agreeing with the encoded key", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"elastic_url": srv.URL,
			"api_key":     testEncodedAPIKey("source-key-id", "source-secret"),
			"api_key_id":  "source-key-id",
		}, log)
		require.NoError(t, err)

		elasticDriver := driver.(*ElasticDriver)
		assert.Equal(t, "source-key-id", elasticDriver.sourceAPIKeyID)
		assert.Equal(t, "warden-service", elasticDriver.sourceUsername,
			"the sweep is scoped by this, so it must be discovered at create")
	})

	// Nothing downstream re-derives the id, and rotation cleanup spends it on a
	// DELETE — so an id that names a different key than the one being
	// authenticated with would invalidate whatever key it does name.
	t.Run("disagreeing with the encoded key is refused", func(t *testing.T) {
		_, err := f.Create(map[string]string{
			"elastic_url": srv.URL,
			"api_key":     testEncodedAPIKey("source-key-id", "source-secret"),
			"api_key_id":  "explicit-id",
		}, log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the id encoded in api_key")
	})
}

func TestElasticDriverFactory_Create_InvalidKey(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	f := &ElasticDriverFactory{}
	_, err := f.Create(map[string]string{
		"elastic_url": srv.URL,
		"api_key":     "invalid-key",
	}, log)
	require.Error(t, err)
	// Either base64 decode fails or authentication fails
	assert.True(t,
		assert.ObjectsAreEqual("", "") || err != nil,
		"should fail with invalid key",
	)
}

func TestElasticDriverFactory_Create_AuthenticationFails(t *testing.T) {
	// Server that always returns 401
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "security_exception"})
	}))
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	f := &ElasticDriverFactory{}
	_, err := f.Create(map[string]string{
		"elastic_url": srv.URL,
		"api_key":     testEncodedAPIKey("id", "bad-key"),
	}, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Elasticsearch authentication failed")
}

// ============================================================================
// Authentication Header Tests
// ============================================================================

func TestElasticDriver_RequestIncludesApiKeyHeader(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_security/_authenticate":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "test",
				"enabled":  true,
			})
		case "/_security/api_key":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "k1",
				"api_key": "s1",
				"encoded": testEncodedAPIKey("k1", "s1"),
			})
		}
	}))
	defer srv.Close()

	apiKey := testEncodedAPIKey("myid", "mysecret")
	d := &ElasticDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeElastic,
			Config: map[string]string{
				"elastic_url": srv.URL,
				"api_key":     apiKey,
			},
		},
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		sourceAPIKeyID: "myid",
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.Equal(t, "ApiKey "+apiKey, receivedAuth)
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestElasticDriver_ConcurrentSupportsRotation(t *testing.T) {
	d := &ElasticDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeElastic,
			Config: map[string]string{"api_key": "k"},
		},
		sourceAPIKeyID: "key-123",
	}

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = d.SupportsRotation()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestElasticDriver_ConcurrentMintCredential(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_security/_authenticate":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "test",
				"enabled":  true,
			})
		case "/_security/api_key":
			n := callCount.Add(1)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      fmt.Sprintf("key-%d", n),
				"api_key": "secret",
				"encoded": testEncodedAPIKey(fmt.Sprintf("key-%d", n), "secret"),
			})
		}
	}))
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			spec := &credential.CredSpec{Name: "concurrent-spec", Config: map[string]string{}}
			_, _, _, _, err := d.MintCredential(context.TODO(), spec)
			errs <- err
		}()
	}

	for i := 0; i < 5; i++ {
		err := <-errs
		assert.NoError(t, err)
	}
}

// ============================================================================
// Compile-time Interface Assertions
// ============================================================================

func TestElasticDriver_ImplementsInterfaces(t *testing.T) {
	var _ credential.SourceDriver = (*ElasticDriver)(nil)
	var _ credential.Rotatable = (*ElasticDriver)(nil)
	var _ credential.SpecVerifier = (*ElasticDriver)(nil)
}

// ============================================================================
// Invalidation outcome tests
//
// Elasticsearch answers an invalidate request with 200 and reports the per-key
// outcome in the body, so the status alone says nothing about whether anything
// was actually invalidated.
// ============================================================================

func TestElasticDriver_Revoke_ReportsClusterRefusal(t *testing.T) {
	srv := newElasticInvalidateServer(t, map[string]interface{}{
		"invalidated_api_keys":            []string{},
		"previously_invalidated_api_keys": []string{},
		"error_count":                     1,
		"error_details": []map[string]interface{}{
			{"type": "security_exception", "reason": "unauthorized for user [warden-service]"},
		},
	})

	d := newTestElasticDriver(t, srv.URL)

	err := d.Revoke(context.TODO(), "elastic:some-key-id")
	require.Error(t, err, "a refused invalidation must not read as success")
	assert.Contains(t, err.Error(), "security_exception")
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestElasticDriver_CleanupRotation_ReportsClusterRefusal(t *testing.T) {
	srv := newElasticInvalidateServer(t, map[string]interface{}{
		"invalidated_api_keys":            []string{},
		"previously_invalidated_api_keys": []string{},
		"error_count":                     1,
		"error_details": []map[string]interface{}{
			{"type": "security_exception", "reason": "unauthorized"},
		},
	})

	d := newTestElasticDriver(t, srv.URL)

	// This is the case that matters most: a cleanup reported as done while the
	// old source key is still live is a rotation that did not rotate.
	err := d.CleanupRotation(context.TODO(), map[string]string{"api_key_id": "old-key-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to invalidate old API key")
}

func TestElasticDriver_Revoke_AcceptsAlreadyInvalidatedKey(t *testing.T) {
	srv := newElasticInvalidateServer(t, map[string]interface{}{
		"invalidated_api_keys":            []string{},
		"previously_invalidated_api_keys": []string{"some-key-id"},
		"error_count":                     0,
	})

	d := newTestElasticDriver(t, srv.URL)

	require.NoError(t, d.Revoke(context.TODO(), "elastic:some-key-id"),
		"a key that is already invalidated leaves nothing live, so this is success")
}

// A key that is gone entirely must not fail either. Cleanup failures are
// retried daily for a week before being abandoned, so calling this a failure
// buys a week of retries for a request that can never succeed.
func TestElasticDriver_CleanupRotation_AcceptsMissingKey(t *testing.T) {
	srv := newElasticInvalidateServer(t, map[string]interface{}{
		"invalidated_api_keys":            []string{},
		"previously_invalidated_api_keys": []string{},
		"error_count":                     1,
		"error_details": []map[string]interface{}{
			{"type": "resource_not_found_exception", "reason": "no API key owned by requesting user found for id [old-key-id]"},
		},
	})

	d := newTestElasticDriver(t, srv.URL)

	require.NoError(t, d.CleanupRotation(context.TODO(), map[string]string{"api_key_id": "old-key-id"}))
}

func TestElasticDriver_Revoke_RejectsEmptyKeyID(t *testing.T) {
	d := newTestElasticDriver(t, "https://unused.example.com")

	// "elastic:" clears a naive TrimPrefix guard and would post {"ids":[""]}.
	err := d.Revoke(context.TODO(), "elastic:")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid lease ID format")
}

// ============================================================================
// Rotation orphan sweep
// ============================================================================

func TestElasticDriver_PrepareRotation_SweepsOrphansButNotTheLiveKey(t *testing.T) {
	srv := newElasticSweepServer(t, "source-key-id", "abandoned-1", "abandoned-2")

	d := newTestElasticDriver(t, srv.URL)

	_, _, _, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"abandoned-1", "abandoned-2"}, srv.lastInvalidated,
		"every rotation key but the one in use should be reclaimed")
	assert.NotContains(t, srv.lastInvalidated, "source-key-id",
		"the key this source authenticates with must be excluded by id")
}

// The sweep issues an authenticated bulk DELETE, so what it is allowed to match
// is the whole of its safety. A filter that is not bound to this source's own
// cluster principal would reach the mid-rotation keys of every other elastic
// source sharing the cluster.
func TestElasticDriver_PrepareRotation_SweepIsScopedToThisPrincipal(t *testing.T) {
	srv := newElasticSweepServer(t, "source-key-id")

	d := newTestElasticDriver(t, srv.URL)

	_, _, _, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)

	require.NotNil(t, srv.lastQuery, "the sweep must query before it deletes")
	encoded, err := json.Marshal(srv.lastQuery)
	require.NoError(t, err)
	query := string(encoded)

	assert.Contains(t, query, `"username":"warden-service"`)
	assert.Contains(t, query, `"invalidated":false`)
	assert.Contains(t, query, `"metadata.managed_by":"warden"`)
	assert.Contains(t, query, `"metadata.purpose":"source_rotation"`)
}

// A cluster that cannot answer the listing must not block the rotation: the
// sweep is a reclamation, not a precondition.
func TestElasticDriver_PrepareRotation_SucceedsWhenSweepCannotList(t *testing.T) {
	srv := newElasticMockServer(t) // has no orphans, and answers the query with none
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)
	d.sourceUsername = "" // as if the username were never discovered

	newConfig, cleanupConfig, _, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)
	assert.Equal(t, "new-key-id-123", newConfig["api_key_id"])
	assert.Equal(t, "source-key-id", cleanupConfig["api_key_id"])
}

// ============================================================================
// Concurrency
// ============================================================================

// Mint reads the config while a commit replaces it. Run under -race, this is
// what pins the snapshot: the config is a whole map that rotation swaps, and
// reading it unsynchronised from the request path is a data race however benign
// the values look.
func TestElasticDriver_MintRacesCommitRotation(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	spec := &credential.CredSpec{Name: "race-spec", Config: map[string]string{}}

	// Each goroutine loops: the unsynchronised read was a narrow window at the
	// top of the mint, so a single pass each could pass on timing alone.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				// The error is not the point; reaching the config safely is.
				_, _, _, _, _ = d.MintCredential(context.TODO(), spec)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = d.CommitRotation(context.TODO(), map[string]string{
					"elastic_url": srv.URL,
					"api_key":     testEncodedAPIKey(fmt.Sprintf("rotated-%d-%d", n, j), "secret"),
					"api_key_id":  fmt.Sprintf("rotated-%d-%d", n, j),
				})
			}
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// Authentication and URL handling
// ============================================================================

func TestElasticDriver_VerifyRejectsDisabledPrincipal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_security/_authenticate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "warden-service",
			"enabled":  false,
			"api_key":  map[string]interface{}{"id": "source-key-id"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	err := d.VerifySpec(context.TODO(), &credential.CredSpec{Name: "s"})
	require.Error(t, err, "a disabled principal answers _authenticate but cannot mint")
	assert.Contains(t, err.Error(), "disabled")
}

func TestElasticDriver_TrailingSlashInURLIsTrimmed(t *testing.T) {
	var paths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "warden-service",
			"enabled":  true,
			"api_key":  map[string]interface{}{"id": "source-key-id"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL+"/")

	require.NoError(t, d.VerifySpec(context.TODO(), &credential.CredSpec{Name: "s"}))
	require.Len(t, paths, 1)
	assert.Equal(t, "/_security/_authenticate", paths[0],
		"a configured trailing slash must not reach the cluster as a doubled separator")
}

// ============================================================================
// Expiration
// ============================================================================

// A key created without an expiration never expires. The driver's 1h default
// only applies when the field is absent, so a set-but-empty value would reach
// the cluster as "no expiration" — a permanent key from a spec that looks like
// it asked for a lifetime.
func TestElasticDriver_MintCredential_RejectsEmptyExpiration(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	_, _, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name:   "test-spec",
		Config: map[string]string{"expiration": ""},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty expiration")
}

func TestElasticDriver_MintCredential_ReturnsKeyMetadata(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)

	_, metadata, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name:   "test-spec",
		Config: map[string]string{},
	})
	require.NoError(t, err)
	require.NotNil(t, metadata, "the audit record should name the key that was created")
	assert.Equal(t, "new-key-id-123", metadata["key_id"])
}

// ============================================================================
// Credential chaining
// ============================================================================

func newChainedElasticDriver(t *testing.T, serverURL string) *ElasticDriver {
	t.Helper()
	return &ElasticDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeElastic,
			Config: map[string]string{
				"elastic_url":                serverURL,
				credential.ConfigSecretSpec:  "es-cluster-key",
				credential.ConfigSecretField: "api_key",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func TestElasticDriverFactory_ValidateConfig_Chained(t *testing.T) {
	f := &ElasticDriverFactory{}

	t.Run("a chained source needs no api_key", func(t *testing.T) {
		require.NoError(t, f.ValidateConfig(map[string]string{
			"elastic_url":               "https://elastic.example.com",
			credential.ConfigSecretSpec: "es-cluster-key",
		}))
	})

	// Keeping the key would leave a source that reads as keyless while storing
	// the very secret chaining removes.
	t.Run("api_key beside secret_spec is refused", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url":               "https://elastic.example.com",
			"api_key":                   testEncodedAPIKey("id1", "secret"),
			credential.ConfigSecretSpec: "es-cluster-key",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be omitted")
	})

	// The id is derived from the key; one kept here beside a fetched key would
	// name one key while presenting another's.
	t.Run("api_key_id beside secret_spec is refused", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"elastic_url":               "https://elastic.example.com",
			"api_key_id":                "id1",
			credential.ConfigSecretSpec: "es-cluster-key",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key_id must be omitted")
	})

	t.Run("api_key is still required without secret_spec", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{"elastic_url": "https://elastic.example.com"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key is required")
	})
}

// A chained source has no key to probe with and no caller to fetch one as, so
// construction must not reach the cluster at all.
func TestElasticDriverFactory_Create_ChainedMakesNoRequest(t *testing.T) {
	var reached int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	f := &ElasticDriverFactory{}

	driver, err := f.Create(map[string]string{
		"elastic_url":               srv.URL,
		credential.ConfigSecretSpec: "es-cluster-key",
	}, log)
	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Zero(t, reached, "creating a chained source must not authenticate")
}

func TestResolveChainedElasticAuth(t *testing.T) {
	const id = "source-key-id"
	const raw = "raw-api-key-half"
	encoded := testEncodedAPIKey(id, raw)

	t.Run("pre-encoded value with no id beside it", func(t *testing.T) {
		auth, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"api_key": encoded},
			Field: "api_key",
		})
		require.NoError(t, err)
		assert.Equal(t, encoded, auth.encoded)
	})

	t.Run("raw half composed with the id beside it", func(t *testing.T) {
		auth, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"api_key": raw, "id": id},
			Field: "api_key",
		})
		require.NoError(t, err)
		assert.Equal(t, encoded, auth.encoded, "the pair should be encoded here")
	})

	t.Run("pre-encoded value that already carries the id beside it", func(t *testing.T) {
		auth, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"api_key": encoded, "id": id},
			Field: "api_key",
		})
		require.NoError(t, err)
		assert.Equal(t, encoded, auth.encoded, "already encoded, so used as it stands")
	})

	t.Run("api_key_id is accepted as the id's name", func(t *testing.T) {
		auth, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"api_key": raw, "api_key_id": id},
			Field: "api_key",
		})
		require.NoError(t, err)
		assert.Equal(t, encoded, auth.encoded)
	})

	// The classification must not rest on whether a value happens to decode. A
	// raw half that decodes to something with a colon would otherwise be sent
	// verbatim with a garbage id, draw a 401, and be misread as a stale secret.
	t.Run("a raw half that decodes to id:key shape is still composed", func(t *testing.T) {
		decoyRaw := testEncodedAPIKey("someone-else", "value")
		auth, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"api_key": decoyRaw, "id": id},
			Field: "api_key",
		})
		require.NoError(t, err)
		assert.Equal(t, testEncodedAPIKey(id, decoyRaw), auth.encoded,
			"the id beside it says this is the raw half, whatever it decodes to")
	})

	t.Run("conventional names when no field was resolved", func(t *testing.T) {
		auth, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data: map[string]string{"encoded": encoded},
		})
		require.NoError(t, err)
		assert.Equal(t, encoded, auth.encoded)
	})

	// A field that resolved to nothing is a misconfigured secret_field. Falling
	// back would silently authenticate with some other value from the payload.
	t.Run("a resolved-but-empty field is reported, not worked around", func(t *testing.T) {
		_, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"wrong_name": encoded},
			Field: "api_key",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		assert.Contains(t, err.Error(), "secret_field")
	})

	t.Run("secret_field naming the id is refused", func(t *testing.T) {
		_, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"id": id, "api_key": raw},
			Field: "id",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must name the api key")
	})

	t.Run("a raw half with no id is incomplete", func(t *testing.T) {
		_, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data:  map[string]string{"api_key": raw},
			Field: "api_key",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
	})

	t.Run("empty material is incomplete", func(t *testing.T) {
		_, err := resolveChainedElasticAuth("https://es", credential.SecretMaterial{
			Data: map[string]string{},
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
	})
}

func TestElasticDriver_MintFromSecret(t *testing.T) {
	var sawAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/_security/api_key", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "minted-key",
			"name":       "warden-chained",
			"encoded":    testEncodedAPIKey("minted-key", "minted-secret"),
			"expiration": time.Now().Add(time.Hour).UnixMilli(),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := newChainedElasticDriver(t, srv.URL)

	rawData, _, ttl, leaseID, err := d.MintFromSecret(context.TODO(),
		&credential.CredSpec{Name: "chained-spec", Config: map[string]string{}},
		credential.SecretMaterial{
			Data:  map[string]string{"api_key": testEncodedAPIKey("cluster-id", "cluster-secret")},
			Field: "api_key",
		})
	require.NoError(t, err)

	assert.Equal(t, "ApiKey "+testEncodedAPIKey("cluster-id", "cluster-secret"), sawAuth,
		"the fetched key is what authenticates the create")
	assert.Equal(t, testEncodedAPIKey("minted-key", "minted-secret"), rawData["api_key"])
	assert.Equal(t, "elastic:minted-key", leaseID)
	assert.Positive(t, ttl)
}

// A refusal on the chained path marks the fetched key as stale so the minting
// layer evicts what it cached and retries once. An inline source has nothing to
// evict, so it must not carry the marker.
func TestElasticDriver_MintFromSecret_MarksRejectedKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_security/api_key", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	spec := &credential.CredSpec{Name: "chained-spec", Config: map[string]string{}}

	d := newChainedElasticDriver(t, srv.URL)
	_, _, _, _, err := d.MintFromSecret(context.TODO(), spec, credential.SecretMaterial{
		Data:  map[string]string{"api_key": testEncodedAPIKey("cluster-id", "stale")},
		Field: "api_key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)

	inline := newTestElasticDriver(t, srv.URL)
	_, _, _, _, err = inline.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected,
		"an inline source has no fetched secret to evict")
}

// A chained spec routes through MintFromSecret. Reaching MintCredential means
// that routing was bypassed, and there is no inline key here to fall back to.
func TestElasticDriver_MintCredential_RefusesChained(t *testing.T) {
	d := newChainedElasticDriver(t, "https://unused.example.com")

	_, _, _, _, err := d.MintCredential(context.TODO(),
		&credential.CredSpec{Name: "chained-spec", Config: map[string]string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential chaining")
}

// Revocation runs at lease expiry, where a chained source has neither a stored
// key to authorise the delete nor a caller to walk the chain with. Returning an
// error would only buy a week of retries for a request that cannot succeed.
func TestElasticDriver_Revoke_ChainedIsANoOp(t *testing.T) {
	var reached int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := newChainedElasticDriver(t, srv.URL)

	require.NoError(t, d.Revoke(context.TODO(), "elastic:minted-key"))
	assert.Zero(t, reached, "there is nothing to revoke with")
}

func TestElasticDriver_VerifySpec_ChainedIsANoOp(t *testing.T) {
	var reached int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	d := newChainedElasticDriver(t, srv.URL)

	require.NoError(t, d.VerifySpec(context.TODO(), &credential.CredSpec{Name: "s"}))
	assert.Zero(t, reached, "a chained source holds no key to verify")
}
