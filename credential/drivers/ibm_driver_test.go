package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Factory Tests
// ============================================================================

func TestIBMDriverFactory_Type(t *testing.T) {
	f := &IBMDriverFactory{}
	assert.Equal(t, credential.SourceTypeIBM, f.Type())
}

func TestIBMDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &IBMDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "api_key")
}

func TestIBMDriverFactory_ValidateConfig(t *testing.T) {
	f := &IBMDriverFactory{}

	t.Run("missing api_key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key")
	})

	t.Run("valid minimal config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"api_key": "test-api-key",
		})
		require.NoError(t, err)
	})

	t.Run("valid full config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"api_key":      "test-api-key",
			"account_id":   "abc123",
			"iam_endpoint": "https://iam.test.cloud.ibm.com",
		})
		require.NoError(t, err)
	})

	t.Run("iam_endpoint rejects http scheme", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"api_key":      "test-api-key",
			"iam_endpoint": "http://iam.cloud.ibm.com",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})
}

func TestIBMDriverFactory_InferCredentialType(t *testing.T) {
	f := &IBMDriverFactory{}

	t.Run("iam_token", func(t *testing.T) {
		ct, err := f.InferCredentialType(map[string]string{"mint_method": "iam_token"})
		require.NoError(t, err)
		assert.Equal(t, credential.TypeOAuthBearerToken, ct)
	})

	t.Run("empty defaults to oauth bearer token", func(t *testing.T) {
		ct, err := f.InferCredentialType(map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, credential.TypeOAuthBearerToken, ct)
	})

	t.Run("iam_with_cos", func(t *testing.T) {
		ct, err := f.InferCredentialType(map[string]string{"mint_method": "iam_with_cos"})
		require.NoError(t, err)
		assert.Equal(t, credential.TypeIBMCloudKeys, ct)
	})

	t.Run("unsupported mint method", func(t *testing.T) {
		_, err := f.InferCredentialType(map[string]string{"mint_method": "invalid"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot infer credential type")
	})
}

// ============================================================================
// Driver Unit Tests
// ============================================================================

func TestIBMDriver_Type(t *testing.T) {
	d := &IBMDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeIBM,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeIBM, d.Type())
}

func TestIBMDriver_Cleanup(t *testing.T) {
	d := &IBMDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeIBM,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Cleanup(context.TODO()))
}

func TestIBMDriver_Revoke_NoOp(t *testing.T) {
	d := &IBMDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeIBM,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Revoke(context.TODO(), "some-lease-id"))
}

func TestIBMDriver_SupportsRotation(t *testing.T) {
	t.Run("true when iamID is set", func(t *testing.T) {
		d := &IBMDriver{iamID: "iam-1234"}
		assert.True(t, d.SupportsRotation())
	})

	t.Run("false when iamID is empty", func(t *testing.T) {
		d := &IBMDriver{}
		assert.False(t, d.SupportsRotation())
	})
}

func TestIBMDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
	d := &IBMDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeIBM,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "invalid_method",
		},
	}

	_, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

// ============================================================================
// Mock Server Tests
// ============================================================================

// newIBMMockServer creates a test server that mocks IBM Cloud IAM endpoints
func newIBMMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// IAM token endpoint
	mux.HandleFunc("/identity/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		apiKey := r.FormValue("apikey")

		if grantType != "urn:ibm:params:oauth:grant-type:apikey" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		if apiKey == "" || apiKey == "invalid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"errorCode":    "BXNIM0415E",
				"errorMessage": "Provided API key could not be found.",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-iam-token-" + apiKey,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"expiration":   time.Now().Add(1 * time.Hour).Unix(),
		})
	})

	// API key details endpoint (POST with API key in body)
	mux.HandleFunc("/v1/apikeys/details", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed; use POST", http.StatusMethodNotAllowed)
			return
		}

		var reqBody map[string]string
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if reqBody["apikey"] == "" {
			http.Error(w, "missing apikey in body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "ApiKey-12345",
			"iam_id":     "iam-ServiceId-abcdef",
			"account_id": "acc-123456",
			"name":       "warden-test-key",
		})
	})

	// Create API key endpoint
	mux.HandleFunc("/v1/apikeys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		// Verify description field is present
		if _, ok := reqBody["description"]; !ok {
			http.Error(w, "missing description", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     "ApiKey-new-67890",
			"apikey": "new-rotated-api-key",
			"name":   reqBody["name"],
			"iam_id": reqBody["iam_id"],
		})
	})

	// Delete API key endpoint
	mux.HandleFunc("/v1/apikeys/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	return httptest.NewServer(mux)
}

func newTestIBMDriver(t *testing.T, serverURL string) *IBMDriver {
	t.Helper()
	return &IBMDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeIBM,
			Config: map[string]string{
				"api_key":      "test-key",
				"iam_endpoint": serverURL,
			},
		},
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
		iamID:      "iam-ServiceId-abcdef",
		apiKeyID:   "ApiKey-12345",
	}
}

func TestIBMDriver_MintIAMToken(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "iam_token",
		},
	}

	rawData, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.NotEmpty(t, rawData["api_key"])
	assert.NotEmpty(t, rawData["access_token"])
	assert.Equal(t, "Bearer", rawData["token_type"])
	assert.Equal(t, rawData["api_key"], rawData["access_token"])
	assert.True(t, ttl > 0)
	assert.Empty(t, leaseID, "IAM tokens should have no lease ID")
}

func TestIBMDriver_MintIAMToken_DefaultMintMethod(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Config: map[string]string{}, // no mint_method = defaults to iam_token
	}

	rawData, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)
	assert.NotEmpty(t, rawData["access_token"])
}

func TestIBMDriver_MintIAMToken_InvalidKey(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	d.credSource.Config["api_key"] = "invalid-key"
	d.tokenCache.Clear()

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "iam_token",
		},
	}

	_, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IBM IAM token")
}

func TestIBMDriver_TokenCaching(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/token" {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": fmt.Sprintf("token-call-%d", callCount),
				"token_type":   "Bearer",
				"expires_in":   3600,
				"expiration":   time.Now().Add(1 * time.Hour).Unix(),
			})
		}
	}))
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	d.tokenCache.Clear()

	// First call should hit the server
	token1, _, err := d.getIAMToken(context.TODO())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call should use cache
	token2, _, err := d.getIAMToken(context.TODO())
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "should not have made another server call")
	assert.Equal(t, token1, token2)
}

func TestIBMDriver_DiscoverAPIKeyDetails(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := &IBMDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeIBM,
			Config: map[string]string{
				"api_key":      "test-key",
				"iam_endpoint": srv.URL,
			},
		},
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	err := d.discoverAPIKeyDetails(context.TODO())
	require.NoError(t, err)

	assert.Equal(t, "iam-ServiceId-abcdef", d.iamID)
	assert.Equal(t, "ApiKey-12345", d.apiKeyID)
	assert.Equal(t, "acc-123456", d.credSource.Config["account_id"])
}

func TestIBMDriver_PrepareRotation(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	d.credSource.Config["account_id"] = "acc-123456"

	newConfig, cleanupConfig, activateAfter, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)

	assert.Equal(t, "new-rotated-api-key", newConfig["api_key"])
	assert.Equal(t, "ApiKey-12345", cleanupConfig["api_key_id"])
	assert.Equal(t, DefaultIBMActivationDelay, activateAfter)
}

func TestIBMDriver_PrepareRotation_NoIAMID(t *testing.T) {
	d := &IBMDriver{iamID: ""}
	_, _, _, err := d.PrepareRotation(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IAM identity not discovered")
}

func TestIBMDriver_CleanupRotation(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	err := d.CleanupRotation(context.TODO(), map[string]string{
		"api_key_id": "ApiKey-old-12345",
	})
	require.NoError(t, err)
}

func TestIBMDriver_CleanupRotation_EmptyID(t *testing.T) {
	d := &IBMDriver{}
	err := d.CleanupRotation(context.TODO(), map[string]string{})
	require.NoError(t, err, "empty api_key_id should be a no-op")
}

func TestIBMDriverFactory_Create(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	f := &IBMDriverFactory{}
	driver, err := f.Create(map[string]string{
		"api_key":      "test-key",
		"iam_endpoint": srv.URL,
	}, log)
	require.NoError(t, err)

	ibmDriver, ok := driver.(*IBMDriver)
	require.True(t, ok)
	assert.Equal(t, "iam-ServiceId-abcdef", ibmDriver.iamID)
	assert.Equal(t, "ApiKey-12345", ibmDriver.apiKeyID)
}

func TestIBMDriverFactory_Create_InvalidKey(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	f := &IBMDriverFactory{}
	_, err := f.Create(map[string]string{
		"api_key":      "invalid-key",
		"iam_endpoint": srv.URL,
	}, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IBM Cloud authentication failed")
}

// ============================================================================
// SpecVerifier Tests
// ============================================================================

func TestIBMDriver_VerifySpec(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	t.Run("valid spec", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "iam_token",
			},
		}
		err := d.VerifySpec(context.TODO(), spec)
		require.NoError(t, err)
	})

	t.Run("default mint method", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name:   "test-spec",
			Config: map[string]string{},
		}
		err := d.VerifySpec(context.TODO(), spec)
		require.NoError(t, err)
	})

	t.Run("invalid api key fails verification", func(t *testing.T) {
		d2 := newTestIBMDriver(t, srv.URL)
		d2.credSource.Config["api_key"] = "invalid-key"
		d2.tokenCache.Clear()

		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "iam_token",
			},
		}
		err := d2.VerifySpec(context.TODO(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "spec verification failed")
	})
}

// ============================================================================
// iam_with_cos Mint Method Tests
// ============================================================================

func TestIBMDriver_MintIAMWithCOS_DualMode(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method":       "iam_with_cos",
			"access_key_id":     "cos-access-key",
			"secret_access_key": "cos-secret-key",
		},
	}

	rawData, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.NotEmpty(t, rawData["access_token"])
	assert.Equal(t, "cos-access-key", rawData["access_key_id"])
	assert.Equal(t, "cos-secret-key", rawData["secret_access_key"])
	assert.True(t, ttl > 0)
	assert.Empty(t, leaseID, "IAM tokens should have no lease ID")
}

func TestIBMDriver_MintIAMWithCOS_APIOnly(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "iam_with_cos",
		},
	}

	rawData, _, _, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.NotEmpty(t, rawData["access_token"])
	_, hasAK := rawData["access_key_id"]
	_, hasSK := rawData["secret_access_key"]
	assert.False(t, hasAK, "COS keys should be absent when not configured")
	assert.False(t, hasSK, "COS keys should be absent when not configured")
}

func TestIBMDriver_MintIAMWithCOS_InvalidKey(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	d.credSource.Config["api_key"] = "invalid-key"
	d.tokenCache.Clear()

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "iam_with_cos",
		},
	}

	_, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire IBM IAM token")
}

// ============================================================================
// Compile-time Interface Assertions
// ============================================================================

func TestIBMDriver_ImplementsSpecVerifier(t *testing.T) {
	var _ credential.SpecVerifier = (*IBMDriver)(nil)
}
