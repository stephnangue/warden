package drivers

import (
	"context"
	"encoding/json"
	"fmt"
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

// ============================================================================
// Factory Tests
// ============================================================================

func TestKubernetesDriverFactory_Type(t *testing.T) {
	f := &KubernetesDriverFactory{}
	assert.Equal(t, credential.SourceTypeKubernetes, f.Type())
}

func TestKubernetesDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &KubernetesDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "token")
	assert.Contains(t, fields, "ca_data")
}

func TestKubernetesDriverFactory_InferCredentialType(t *testing.T) {
	f := &KubernetesDriverFactory{}

	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeKubernetesToken, ct)
}

func TestKubernetesDriverFactory_ValidateConfig(t *testing.T) {
	f := &KubernetesDriverFactory{}

	t.Run("missing kubernetes_url", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"token": "test-token",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kubernetes_url")
	})

	t.Run("missing token", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token")
	})

	t.Run("kubernetes_url rejects http scheme", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "http://k8s.example.com",
			"token":          "test-token",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})

	t.Run("http allowed with tls_skip_verify", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url":  "http://k8s.example.com",
			"token":           "test-token",
			"tls_skip_verify": "true",
		})
		require.NoError(t, err)
	})

	t.Run("valid minimal config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"token":          "test-token",
		})
		require.NoError(t, err)
	})

	t.Run("valid full config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url":  "https://k8s.example.com:6443",
			"token":           "test-token",
			"tls_skip_verify": "false",
		})
		require.NoError(t, err)
	})
}

// ============================================================================
// Mock Server
// ============================================================================

// newK8sMockServer creates a test server that mocks Kubernetes API endpoints.
func newK8sMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Connection verification endpoint (/version requires no RBAC)
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"kind":    "Status",
				"status":  "Failure",
				"message": "Unauthorized",
				"code":    401,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"major":        "1",
			"minor":        "29",
			"gitVersion":   "v1.29.0",
			"goVersion":    "go1.21.5",
			"platform":     "linux/amd64",
		})
	})

	// ServiceAccount GET endpoint
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		path := r.URL.Path

		// Handle token creation: POST .../serviceaccounts/{name}/token
		if r.Method == http.MethodPost && strings.HasSuffix(path, "/token") {
			parts := strings.Split(strings.TrimPrefix(path, "/api/v1/namespaces/"), "/")
			// parts: [namespace, "serviceaccounts", sa-name, "token"]
			if len(parts) != 4 {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			namespace := parts[0]
			saName := parts[2]

			if saName == "not-found-sa" {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"kind":    "Status",
					"status":  "Failure",
					"message": "serviceaccounts \"not-found-sa\" not found",
					"code":    404,
				})
				return
			}

			if saName == "forbidden-sa" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"kind":    "Status",
					"status":  "Failure",
					"message": "forbidden: User cannot create token",
					"code":    403,
				})
				return
			}

			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			spec, _ := reqBody["spec"].(map[string]interface{})
			expSeconds := int64(3600) // default
			if es, ok := spec["expirationSeconds"].(float64); ok {
				expSeconds = int64(es)
			}

			expirationTime := time.Now().Add(time.Duration(expSeconds) * time.Second)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"kind":       "TokenRequest",
				"apiVersion": "authentication.k8s.io/v1",
				"metadata": map[string]interface{}{
					"name":      saName,
					"namespace": namespace,
				},
				"spec": spec,
				"status": map[string]interface{}{
					"token":               "minted-token-for-" + saName,
					"expirationTimestamp": expirationTime.UTC().Format(time.RFC3339),
				},
			})
			return
		}

		// Handle ServiceAccount GET: GET .../serviceaccounts/{name}
		if r.Method == http.MethodGet && strings.Contains(path, "/serviceaccounts/") {
			parts := strings.Split(strings.TrimPrefix(path, "/api/v1/namespaces/"), "/")
			if len(parts) != 3 {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			saName := parts[2]

			if saName == "not-found-sa" {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"kind":    "Status",
					"status":  "Failure",
					"message": "serviceaccounts \"not-found-sa\" not found",
					"code":    404,
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"kind":       "ServiceAccount",
				"apiVersion": "v1",
				"metadata": map[string]interface{}{
					"name":      saName,
					"namespace": parts[0],
				},
			})
			return
		}

		http.Error(w, "not found", http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

func newTestK8sDriver(t *testing.T, serverURL string) *KubernetesDriver {
	t.Helper()
	return &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: map[string]string{
				"kubernetes_url":  serverURL,
				"token":           "valid-token",
				"tls_skip_verify": "true",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// ============================================================================
// Driver Unit Tests
// ============================================================================

func TestKubernetesDriver_Type(t *testing.T) {
	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeKubernetes,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeKubernetes, d.Type())
}

func TestKubernetesDriver_Cleanup(t *testing.T) {
	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeKubernetes,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	require.NoError(t, d.Cleanup(context.TODO()))
}

func TestKubernetesDriver_Revoke_NoOp(t *testing.T) {
	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeKubernetes,
			Config: map[string]string{},
		},
	}
	err := d.Revoke(context.TODO(), "any-lease-id")
	require.NoError(t, err)
}

// ============================================================================
// MintCredential Tests
// ============================================================================

func TestKubernetesDriver_MintCredential_Success(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	rawData, ttl, leaseID, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			"ttl":             "1h",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "minted-token-for-my-sa", rawData["token"])
	assert.Equal(t, "default", rawData["namespace"])
	assert.Equal(t, "my-sa", rawData["service_account"])
	assert.Empty(t, leaseID)
	assert.True(t, ttl > 0)
}

func TestKubernetesDriver_MintCredential_DefaultTTL(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	rawData, ttl, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			// no ttl specified — should default to 1h
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "minted-token-for-my-sa", rawData["token"])
	// TTL should be approximately 1 hour (3600s minus small elapsed time)
	assert.True(t, ttl > 59*time.Minute && ttl <= 1*time.Hour, "expected ~1h TTL, got %v", ttl)
}

func TestKubernetesDriver_MintCredential_CustomAudiences(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	rawData, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
			"audiences":       "https://app1.example.com, https://app2.example.com",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://app1.example.com, https://app2.example.com", rawData["audiences"])
}

func TestKubernetesDriver_MintCredential_MissingServiceAccount(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	_, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"namespace": "default",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service_account")
}

func TestKubernetesDriver_MintCredential_MissingNamespace(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	_, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "my-sa",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace")
}

func TestKubernetesDriver_MintCredential_SANotFound(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	_, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "not-found-sa",
			"namespace":       "default",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKubernetesDriver_MintCredential_Forbidden(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	_, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "forbidden-sa",
			"namespace":       "default",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}

// ============================================================================
// VerifySpec Tests
// ============================================================================

func TestKubernetesDriver_VerifySpec_Exists(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	err := d.VerifySpec(context.TODO(), &credential.CredSpec{
		Config: map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
		},
	})
	require.NoError(t, err)
}

func TestKubernetesDriver_VerifySpec_NotFound(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	err := d.VerifySpec(context.TODO(), &credential.CredSpec{
		Config: map[string]string{
			"service_account": "not-found-sa",
			"namespace":       "default",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKubernetesDriver_VerifySpec_MissingFields(t *testing.T) {
	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeKubernetes,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}

	err := d.VerifySpec(context.TODO(), &credential.CredSpec{
		Config: map[string]string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// ============================================================================
// Rotation Tests
// ============================================================================

func TestKubernetesDriver_SupportsRotation(t *testing.T) {
	t.Run("true when source SA is configured", func(t *testing.T) {
		d := &KubernetesDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{
					"source_service_account": "warden-sa",
					"source_namespace":       "warden",
				},
			},
		}
		assert.True(t, d.SupportsRotation())
	})

	t.Run("false when source SA is missing", func(t *testing.T) {
		d := &KubernetesDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{},
			},
		}
		assert.False(t, d.SupportsRotation())
	})

	t.Run("false when only SA name is set", func(t *testing.T) {
		d := &KubernetesDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{
					"source_service_account": "warden-sa",
				},
			},
		}
		assert.False(t, d.SupportsRotation())
	})
}

func TestKubernetesDriver_PrepareRotation_Success(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: map[string]string{
				"kubernetes_url":         server.URL,
				"token":                  "valid-token",
				"source_service_account": "warden-sa",
				"source_namespace":       "warden",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	newConfig, cleanupConfig, activateAfter, err := d.PrepareRotation(context.TODO())
	require.NoError(t, err)

	// New config should have a fresh token
	assert.Equal(t, "minted-token-for-warden-sa", newConfig["token"])
	// Other config preserved
	assert.Equal(t, server.URL, newConfig["kubernetes_url"])
	assert.Equal(t, "warden-sa", newConfig["source_service_account"])
	assert.Equal(t, "warden", newConfig["source_namespace"])
	// Kubernetes has immediate consistency
	assert.Equal(t, time.Duration(0), activateAfter)
	// No cleanup needed (old tokens expire naturally)
	assert.Empty(t, cleanupConfig)
}

func TestKubernetesDriver_PrepareRotation_MissingSAConfig(t *testing.T) {
	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Config: map[string]string{
				"kubernetes_url": "https://k8s.example.com",
				"token":          "valid-token",
			},
		},
	}

	_, _, _, err := d.PrepareRotation(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source_service_account")
}

func TestKubernetesDriver_CommitRotation_Success(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: map[string]string{
				"kubernetes_url": server.URL,
				"token":          "old-token",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	newConfig := map[string]string{
		"kubernetes_url": server.URL,
		"token":          "valid-token", // mock server accepts this
	}

	err := d.CommitRotation(context.TODO(), newConfig)
	require.NoError(t, err)

	// Config should be updated
	assert.Equal(t, "valid-token", d.credSource.Config["token"])
}

func TestKubernetesDriver_CommitRotation_RollbackOnFailure(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: map[string]string{
				"kubernetes_url": server.URL,
				"token":          "valid-token",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	newConfig := map[string]string{
		"kubernetes_url": server.URL,
		"token":          "invalid-token", // mock server rejects this
	}

	err := d.CommitRotation(context.TODO(), newConfig)
	require.Error(t, err)

	// Config should be rolled back
	assert.Equal(t, "valid-token", d.credSource.Config["token"])
}

func TestKubernetesDriver_CleanupRotation_NoOp(t *testing.T) {
	d := &KubernetesDriver{}
	err := d.CleanupRotation(context.TODO(), map[string]string{})
	require.NoError(t, err)
}

// ============================================================================
// Factory Create Tests
// ============================================================================

func newTestLogger(t *testing.T) *logger.GatedLogger {
	t.Helper()
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	return log
}

func TestKubernetesDriverFactory_Create_Success(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	f := &KubernetesDriverFactory{}
	driver, err := f.Create(map[string]string{
		"kubernetes_url":  server.URL,
		"token":           "valid-token",
		"tls_skip_verify": "true",
	}, newTestLogger(t))
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeKubernetes, driver.Type())
}

func TestKubernetesDriverFactory_Create_InvalidToken(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	f := &KubernetesDriverFactory{}
	_, err := f.Create(map[string]string{
		"kubernetes_url":  server.URL,
		"token":           "bad-token",
		"tls_skip_verify": "true",
	}, newTestLogger(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection failed")
}

func TestKubernetesDriverFactory_Create_InvalidCAData(t *testing.T) {
	f := &KubernetesDriverFactory{}
	_, err := f.Create(map[string]string{
		"kubernetes_url": "https://k8s.example.com",
		"token":          "valid-token",
		"ca_data":        "not-valid-base64!!!",
	}, newTestLogger(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_data")
}

// ============================================================================
// Validation Tests
// ============================================================================

func TestKubernetesDriverFactory_ValidateConfig_SourceTokenTTL(t *testing.T) {
	f := &KubernetesDriverFactory{}

	t.Run("valid source_token_ttl", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url":   "https://k8s.example.com",
			"token":            "test-token",
			"source_token_ttl": "24h",
		})
		require.NoError(t, err)
	})

	t.Run("source_token_ttl too short", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url":   "https://k8s.example.com",
			"token":            "test-token",
			"source_token_ttl": "5m",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 10m")
	})

	t.Run("source_token_ttl too long", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url":   "https://k8s.example.com",
			"token":            "test-token",
			"source_token_ttl": "72h",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceed 48h")
	})
}

// ============================================================================
// Context and Concurrency Tests
// ============================================================================

func TestKubernetesDriver_MintCredential_ContextCancelled(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newTestK8sDriver(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, _, err := d.MintCredential(ctx, &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"service_account": "my-sa",
			"namespace":       "default",
		},
	})
	require.Error(t, err)
}

func TestKubernetesDriver_ConcurrentMintAndRotation(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: map[string]string{
				"kubernetes_url":         server.URL,
				"token":                  "valid-token",
				"source_service_account": "warden-sa",
				"source_namespace":       "warden",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	// Run MintCredential and PrepareRotation concurrently to check for races
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 10; i++ {
			_, _, _, _ = d.MintCredential(context.Background(), &credential.CredSpec{
				Name: "test-spec",
				Config: map[string]string{
					"service_account": "my-sa",
					"namespace":       "default",
				},
			})
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 10; i++ {
			newConfig, _, _, err := d.PrepareRotation(context.Background())
			if err == nil {
				_ = d.CommitRotation(context.Background(), newConfig)
			}
		}
	}()

	<-done
	<-done
}

// ============================================================================
// mapError Tests
// ============================================================================

func TestKubernetesDriver_MapError_RateLimit(t *testing.T) {
	d := &KubernetesDriver{}
	err := d.mapError(fmt.Errorf("status 429"), http.StatusTooManyRequests, "my-sa", "default")
	assert.Contains(t, err.Error(), "rate limited")
}
