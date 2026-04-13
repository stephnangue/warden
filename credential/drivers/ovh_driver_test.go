package drivers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createOVHTestLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.TraceLevel,
		Format:  logger.DefaultFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})
	return gl
}

// createOVHTestDriver creates an OVHDriver pointing at a test server.
// The driver's apiURL and tokenURL are overridden to point at the test server.
func createOVHTestDriver(t *testing.T, serverURL string, extraConfig map[string]string) *OVHDriver {
	t.Helper()

	config := map[string]string{
		"client_id":       "test-client-id",
		"client_secret":   "test-client-secret",
		"ovh_endpoint":    "ovh-eu",
		"tls_skip_verify": "true",
	}
	for k, v := range extraConfig {
		config[k] = v
	}

	log := createOVHTestLogger()

	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	require.NoError(t, err)

	driver := &OVHDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOVH,
			Config: config,
		},
		logger:     log.WithSubsystem(credential.SourceTypeOVH),
		httpClient: httpClient,
		apiURL:     serverURL,
		tokenURL:   serverURL + "/auth/oauth2/token",
	}

	return driver
}

// --- Factory tests ---

func TestOVHDriverFactory_Type(t *testing.T) {
	f := &OVHDriverFactory{}
	assert.Equal(t, credential.SourceTypeOVH, f.Type())
}

func TestOVHDriverFactory_InferCredentialType(t *testing.T) {
	f := &OVHDriverFactory{}
	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOVHKeys, ct)
}

func TestOVHDriverFactory_ValidateConfig(t *testing.T) {
	f := &OVHDriverFactory{}

	t.Run("valid config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"ovh_endpoint":  "ovh-eu",
		})
		assert.NoError(t, err)
	})

	t.Run("valid config with S3 fields", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"project_id":    "proj-123",
			"user_id":       "user-456",
		})
		assert.NoError(t, err)
	})

	t.Run("missing client_id", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"client_secret": "test-secret",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id")
	})

	t.Run("missing client_secret", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"client_id": "test-id",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_secret")
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"ovh_endpoint":  "ovh-invalid",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ovh_endpoint")
	})
}

func TestOVHDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &OVHDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "client_secret")
	assert.Contains(t, fields, "ca_data")
}

func TestOVHDriverFactory_Create(t *testing.T) {
	f := &OVHDriverFactory{}
	log := createOVHTestLogger()

	t.Run("valid creation", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
		}, log)
		require.NoError(t, err)
		require.NotNil(t, driver)
		assert.Equal(t, credential.SourceTypeOVH, driver.Type())
	})

	t.Run("defaults to ovh-eu", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
		}, log)
		require.NoError(t, err)
		ovhDriver := driver.(*OVHDriver)
		assert.Equal(t, "https://eu.api.ovh.com/1.0", ovhDriver.apiURL)
		assert.Equal(t, "https://www.ovh.com/auth/oauth2/token", ovhDriver.tokenURL)
	})

	t.Run("ovh-us endpoint", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"ovh_endpoint":  "ovh-us",
		}, log)
		require.NoError(t, err)
		ovhDriver := driver.(*OVHDriver)
		assert.Equal(t, "https://api.us.ovhcloud.com/1.0", ovhDriver.apiURL)
		assert.Equal(t, "https://us.ovhcloud.com/auth/oauth2/token", ovhDriver.tokenURL)
	})

	t.Run("unknown endpoint", func(t *testing.T) {
		_, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"ovh_endpoint":  "ovh-invalid",
		}, log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown ovh_endpoint")
	})
}

// --- OAuth2 token mint tests ---

func TestOVHDriver_MintOAuth2Token(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/auth/oauth2/token" {
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

			r.ParseForm()
			assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
			assert.Equal(t, "test-client-id", r.PostForm.Get("client_id"))
			assert.Equal(t, "test-client-secret", r.PostForm.Get("client_secret"))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "eyJhbGciOiJSUzI1NiIs.test-token",
				"token_type":   "Bearer",
				"expires_in":   3599,
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)

	spec := &credential.CredSpec{
		Name: "api-spec",
		Config: map[string]string{
			"mint_method": "oauth2_token",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiIs.test-token", rawData["api_token"])
	assert.Equal(t, 3599*time.Second, ttl)
	assert.Empty(t, leaseID) // OAuth2 tokens expire naturally
}

func TestOVHDriver_MintOAuth2Token_EmptyResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "",
			"token_type":   "Bearer",
			"expires_in":   3599,
		})
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)

	spec := &credential.CredSpec{
		Name:   "api-spec",
		Config: map[string]string{"mint_method": "oauth2_token"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty access_token")
}

// --- Dynamic S3 credential tests ---

func TestOVHDriver_MintDynamicS3(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "temp-token",
				"token_type":   "Bearer",
				"expires_in":   3599,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/cloud/project/proj-123/user/user-456/s3Credentials":
			assert.Equal(t, "Bearer temp-token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access": "s3-access-key-123",
				"secret": "s3-secret-key-456",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
		"user_id":    "user-456",
	})

	spec := &credential.CredSpec{
		Name: "s3-spec",
		Config: map[string]string{
			"mint_method": "dynamic_s3",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "s3-access-key-123", rawData["access_key"])
	assert.Equal(t, "s3-secret-key-456", rawData["secret_key"])
	assert.Equal(t, 3599*time.Second, ttl) // TTL from OAuth2 token
	assert.Equal(t, "proj-123/user-456/s3-access-key-123", leaseID)
}

func TestOVHDriver_MintDynamicS3_SpecOverridesSource(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "temp-token",
				"token_type":   "Bearer",
				"expires_in":   3599,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/cloud/project/spec-proj/user/spec-user/s3Credentials":
			// Spec-level project_id and user_id should be used
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access": "s3-key",
				"secret": "s3-secret",
			})

		default:
			http.Error(w, "unexpected: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "source-proj",
		"user_id":    "source-user",
	})

	spec := &credential.CredSpec{
		Name: "s3-spec",
		Config: map[string]string{
			"mint_method": "dynamic_s3",
			"project_id":  "spec-proj",
			"user_id":     "spec-user",
		},
	}

	rawData, _, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "s3-key", rawData["access_key"])
	assert.Equal(t, "spec-proj/spec-user/s3-key", leaseID)
}

func TestOVHDriver_MintDynamicS3_MissingProjectID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "temp-token",
			"expires_in":   3599,
		})
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil) // No project_id on source

	spec := &credential.CredSpec{
		Name: "s3-spec",
		Config: map[string]string{
			"mint_method": "dynamic_s3",
			// No project_id on spec either
			"user_id": "user-123",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id")
}

func TestOVHDriver_MintDynamicS3_MissingUserID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "temp-token",
			"expires_in":   3599,
		})
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
	})

	spec := &credential.CredSpec{
		Name: "s3-spec",
		Config: map[string]string{
			"mint_method": "dynamic_s3",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_id")
}

// --- Dual mode (oauth2_token_and_s3) tests ---

func TestOVHDriver_MintOAuth2TokenAndS3(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "dual-token",
				"token_type":   "Bearer",
				"expires_in":   3599,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/cloud/project/proj-123/user/user-456/s3Credentials":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access": "dual-s3-key",
				"secret": "dual-s3-secret",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
		"user_id":    "user-456",
	})

	spec := &credential.CredSpec{
		Name: "dual-spec",
		Config: map[string]string{
			"mint_method": "oauth2_token_and_s3",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "dual-token", rawData["api_token"])
	assert.Equal(t, "dual-s3-key", rawData["access_key"])
	assert.Equal(t, "dual-s3-secret", rawData["secret_key"])
	assert.Equal(t, 3599*time.Second, ttl) // Token TTL governs refresh
	assert.Equal(t, "proj-123/user-456/dual-s3-key", leaseID)
}

// --- Unsupported mint method ---

func TestOVHDriver_MintCredential_UnsupportedMethod(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)

	spec := &credential.CredSpec{
		Name: "bad-spec",
		Config: map[string]string{
			"mint_method": "unknown",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

// --- Revoke tests ---

func TestOVHDriver_Revoke(t *testing.T) {
	var deletedPath string
	tokenCalled := false

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/oauth2/token":
			tokenCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "revoke-token",
				"expires_in":   3599,
			})

		case r.Method == http.MethodDelete:
			assert.Equal(t, "Bearer revoke-token", r.Header.Get("Authorization"))
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)

	err := driver.Revoke(context.Background(), "proj-123/user-456/s3-key-789")
	require.NoError(t, err)
	assert.True(t, tokenCalled)
	assert.Equal(t, "/cloud/project/proj-123/user/user-456/s3Credentials/s3-key-789", deletedPath)
}

func TestOVHDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)
	err := driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestOVHDriver_Revoke_InvalidLeaseID(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)
	err := driver.Revoke(context.Background(), "invalid-format")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid OVH lease ID format")
}

// --- VerifySpec tests ---

func TestOVHDriver_VerifySpec(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", map[string]string{
		"project_id": "proj-123",
		"user_id":    "user-456",
	})

	t.Run("oauth2_token - no extra config needed", func(t *testing.T) {
		err := driver.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "api-spec",
			Config: map[string]string{"mint_method": "oauth2_token"},
		})
		assert.NoError(t, err)
	})

	t.Run("dynamic_s3 - source has project_id and user_id", func(t *testing.T) {
		err := driver.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "s3-spec",
			Config: map[string]string{"mint_method": "dynamic_s3"},
		})
		assert.NoError(t, err)
	})

	t.Run("dynamic_s3 - missing project_id", func(t *testing.T) {
		driverNoProject := createOVHTestDriver(t, "https://unused", nil)
		err := driverNoProject.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "s3-spec",
			Config: map[string]string{"mint_method": "dynamic_s3"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project_id")
	})

	t.Run("unsupported mint_method", func(t *testing.T) {
		err := driver.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "bad-spec",
			Config: map[string]string{"mint_method": "unknown"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported mint_method")
	})
}

// --- Error handling tests ---

func TestOVHDriver_MintOAuth2Token_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client","error_description":"unknown client"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)
	spec := &credential.CredSpec{
		Name:   "api-spec",
		Config: map[string]string{"mint_method": "oauth2_token"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OAuth2 token request failed")
}

func TestOVHDriver_MintOAuth2Token_MalformedJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":`)) // truncated JSON
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)
	spec := &credential.CredSpec{
		Name:   "api-spec",
		Config: map[string]string{"mint_method": "oauth2_token"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse OAuth2 token response")
}

func TestOVHDriver_MintOAuth2Token_MissingExpiresIn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "valid-token",
			"token_type":   "Bearer",
			// no expires_in — should fall back to 1h
		})
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)
	spec := &credential.CredSpec{
		Name:   "api-spec",
		Config: map[string]string{"mint_method": "oauth2_token"},
	}

	rawData, ttl, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "valid-token", rawData["api_token"])
	assert.Equal(t, 1*time.Hour, ttl) // fallback TTL
}

func TestOVHDriver_MintDynamicS3_EmptySecret(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "temp-token",
				"expires_in":   3599,
			})
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access": "s3-key",
				"secret": "", // empty secret
			})
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
		"user_id":    "user-456",
	})

	spec := &credential.CredSpec{
		Name:   "s3-spec",
		Config: map[string]string{"mint_method": "dynamic_s3"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty S3 access or secret key")
}

func TestOVHDriver_MintDynamicS3_APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "temp-token",
				"expires_in":   3599,
			})
		default:
			http.Error(w, `{"message":"User not found"}`, http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
		"user_id":    "bad-user",
	})

	spec := &credential.CredSpec{
		Name:   "s3-spec",
		Config: map[string]string{"mint_method": "dynamic_s3"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create OVH S3 credentials")
}

func TestOVHDriver_MintOAuth2TokenAndS3_CallCount(t *testing.T) {
	var tokenCalls, s3Calls int

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/oauth2/token":
			tokenCalls++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "counted-token",
				"expires_in":   3599,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/cloud/project/proj-123/user/user-456/s3Credentials":
			s3Calls++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access": "counted-key",
				"secret": "counted-secret",
			})

		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
		"user_id":    "user-456",
	})

	spec := &credential.CredSpec{
		Name:   "dual-spec",
		Config: map[string]string{"mint_method": "oauth2_token_and_s3"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, 1, tokenCalls, "should make exactly 1 token call")
	assert.Equal(t, 1, s3Calls, "should make exactly 1 S3 credential call")
}

func TestOVHDriver_MintOAuth2TokenAndS3_S3APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/oauth2/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "good-token",
				"expires_in":   3599,
			})
		default:
			http.Error(w, `{"message":"Forbidden"}`, http.StatusForbidden)
		}
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, map[string]string{
		"project_id": "proj-123",
		"user_id":    "user-456",
	})

	spec := &credential.CredSpec{
		Name:   "dual-spec",
		Config: map[string]string{"mint_method": "oauth2_token_and_s3"},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create OVH S3 credentials")
}

// --- Cleanup test ---

func TestOVHDriver_Cleanup(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}
