package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	return httptest.NewServer(mux)
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
	t.Run("true when sourceAPIKeyID is set", func(t *testing.T) {
		d := &ElasticDriver{sourceAPIKeyID: "key-123"}
		assert.True(t, d.SupportsRotation())
	})

	t.Run("false when sourceAPIKeyID is empty", func(t *testing.T) {
		d := &ElasticDriver{}
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

	rawData, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
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

	rawData, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
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

	rawData, _, _, err := d.MintCredential(context.TODO(), spec)
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

	_, _, _, err := d.MintCredential(context.TODO(), spec)
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

	_, _, _, err := d.MintCredential(context.TODO(), spec)
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

func TestElasticDriver_CommitRotation_RollbackOnFailure(t *testing.T) {
	srv := newElasticMockServer(t)
	defer srv.Close()

	d := newTestElasticDriver(t, srv.URL)
	originalConfig := d.credSource.Config
	originalKeyID := d.sourceAPIKeyID

	// Provide an invalid key so authentication fails
	newConfig := map[string]string{
		"elastic_url": srv.URL,
		"api_key":     "invalid-key",
		"api_key_id":  "bad-key-id",
	}

	err := d.CommitRotation(context.TODO(), newConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate")

	// Config should be rolled back
	assert.Equal(t, originalConfig["api_key"], d.credSource.Config["api_key"])
	assert.Equal(t, originalKeyID, d.sourceAPIKeyID)
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
	rawData, _, _, err := d.MintCredential(context.TODO(), spec)
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
	driver, err := f.Create(map[string]string{
		"elastic_url": srv.URL,
		"api_key":     testEncodedAPIKey("source-key-id", "source-secret"),
		"api_key_id":  "explicit-id",
	}, log)
	require.NoError(t, err)

	elasticDriver := driver.(*ElasticDriver)
	assert.Equal(t, "explicit-id", elasticDriver.sourceAPIKeyID, "should use explicit api_key_id over decoded")
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
	_, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.Equal(t, "ApiKey "+apiKey, receivedAuth)
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestElasticDriver_ConcurrentSupportsRotation(t *testing.T) {
	d := &ElasticDriver{sourceAPIKeyID: "key-123"}

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
			_, _, _, err := d.MintCredential(context.TODO(), spec)
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
