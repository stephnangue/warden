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

func TestKubernetesDriverFactory_ValidateConfig_AuthMethod(t *testing.T) {
	f := &KubernetesDriverFactory{}

	t.Run("absent auth_method behaves as static", func(t *testing.T) {
		// The back-compat case: every source written before federation existed.
		require.NoError(t, f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"token":          "test-token",
		}))
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")
	})

	t.Run("present but empty auth_method is validated as static", func(t *testing.T) {
		// GetString hands back a stored "" rather than the default, and the schema
		// pass skips empty values — so an auth_method key set to "" must still be
		// held to the static rules. Otherwise a source is accepted carrying neither
		// a token nor a federation config, and every mint 401s with an empty bearer.
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"auth_method":    "",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")

		require.NoError(t, f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"auth_method":    "",
			"token":          "test-token",
		}))
	})

	t.Run("unknown auth_method rejected", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"auth_method":    "kubeconfig",
			"token":          "test-token",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth_method")
	})

	t.Run("static rejects audience", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"auth_method":    kubernetesAuthMethodStatic,
			"token":          "test-token",
			"audience":       "https://k8s.example.com",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audience is only valid")
	})

	t.Run("federation minimal config", func(t *testing.T) {
		require.NoError(t, f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"auth_method":    kubernetesAuthMethodOIDCFederation,
		}))
	})

	t.Run("federation accepts audience", func(t *testing.T) {
		require.NoError(t, f.ValidateConfig(map[string]string{
			"kubernetes_url": "https://k8s.example.com",
			"auth_method":    kubernetesAuthMethodOIDCFederation,
			"audience":       "https://k8s.example.com",
		}))
	})

	// A keyless source holds nothing to authenticate or rotate with, so every
	// static field is rejected rather than silently ignored.
	for _, field := range []string{"token", "source_service_account", "source_namespace", "source_token_ttl"} {
		t.Run("federation rejects "+field, func(t *testing.T) {
			config := map[string]string{
				"kubernetes_url": "https://k8s.example.com",
				"auth_method":    kubernetesAuthMethodOIDCFederation,
			}
			switch field {
			case "source_token_ttl":
				config[field] = "24h"
			default:
				config[field] = "some-value"
			}
			err := f.ValidateConfig(config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
			assert.Contains(t, err.Error(), "must not be set")
		})
	}
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
			"major":      "1",
			"minor":      "29",
			"gitVersion": "v1.29.0",
			"goVersion":  "go1.21.5",
			"platform":   "linux/amd64",
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

	rawData, _, ttl, leaseID, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	rawData, _, ttl, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	rawData, _, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	_, _, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	_, _, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	_, _, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	_, _, _, _, err := d.MintCredential(context.TODO(), &credential.CredSpec{
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

	_, _, _, _, err := d.MintCredential(ctx, &credential.CredSpec{
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
			_, _, _, _, _ = d.MintCredential(context.Background(), &credential.CredSpec{
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

func TestKubernetesTokenMetadata(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		meta := kubernetesTokenMetadata("app-backend", "default",
			"https://app.example.com", "2026-06-09T16:04:05Z")

		assert.Equal(t, "system:serviceaccount:default:app-backend", meta["subject"])
		assert.Equal(t, "app-backend", meta["service_account"])
		assert.Equal(t, "default", meta["namespace"])
		assert.Equal(t, "https://app.example.com", meta["audiences"])
		assert.Equal(t, "2026-06-09T16:04:05Z", meta["expiration"])

		// Secret material never lands in the clear-logged metadata, and every
		// value is a string (Metadata parsing rejects non-strings).
		assert.NotContains(t, meta, "token")
		for k, v := range meta {
			_, ok := v.(string)
			assert.Truef(t, ok, "metadata[%q] is %T, expected string", k, v)
		}
	})

	t.Run("omits empty audiences and expiration", func(t *testing.T) {
		meta := kubernetesTokenMetadata("app-backend", "default", "", "")

		assert.Equal(t, "system:serviceaccount:default:app-backend", meta["subject"])
		assert.NotContains(t, meta, "audiences")
		assert.NotContains(t, meta, "expiration")
	})
}

// ============================================================================
// Keyless (workload identity federation) Tests
// ============================================================================

// newFederatedK8sDriver builds a driver backed by the shared mock server with no
// stored token, the way a keyless source is configured.
func newFederatedK8sDriver(t *testing.T, serverURL string) *KubernetesDriver {
	t.Helper()
	return &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: map[string]string{
				"kubernetes_url":  serverURL,
				"auth_method":     kubernetesAuthMethodOIDCFederation,
				"audience":        "https://k8s.example.com",
				"tls_skip_verify": "true",
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func TestKubernetesDriver_MintCredentialWithExchange_UsesAssertionAsBearer(t *testing.T) {
	// The assertion the caller presents must be the bearer on the TokenRequest
	// call — that is the whole of federation here, since there is no exchange hop.
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kind":       "TokenRequest",
			"apiVersion": "authentication.k8s.io/v1",
			"status": map[string]interface{}{
				"token":               "minted-token-for-payments",
				"expirationTimestamp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
		})
	}))
	defer server.Close()

	d := newFederatedK8sDriver(t, server.URL)
	spec := &credential.CredSpec{
		Name: "payments",
		Config: map[string]string{
			"service_account":      "payments",
			"namespace":            "prod",
			"subject_token_source": credential.SourceWardenIdentity,
		},
	}

	rawData, metadata, ttl, leaseID, err := d.MintCredentialWithExchange(
		context.Background(), spec, &credential.ExchangeInputs{SubjectToken: "assertion-jwt"})
	require.NoError(t, err)

	assert.Equal(t, "Bearer assertion-jwt", gotAuth)
	assert.Equal(t, "minted-token-for-payments", rawData["token"])
	assert.Equal(t, "prod", rawData["namespace"])
	assert.Equal(t, "payments", rawData["service_account"])
	assert.Equal(t, "system:serviceaccount:prod:payments", metadata["subject"])
	assert.InDelta(t, time.Hour.Seconds(), ttl.Seconds(), 5)
	// A ServiceAccount token cannot be revoked, so there is no lease to hold.
	assert.Empty(t, leaseID)
}

func TestKubernetesDriver_ExchangeFailsClosed(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	spec := &credential.CredSpec{
		Name:   "app",
		Config: map[string]string{"service_account": "app-backend", "namespace": "default"},
	}

	t.Run("MintCredential refuses a federated source", func(t *testing.T) {
		d := newFederatedK8sDriver(t, server.URL)
		_, _, _, _, err := d.MintCredential(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject_token_source")
	})

	t.Run("MintCredentialWithExchange refuses a static source", func(t *testing.T) {
		d := newTestK8sDriver(t, server.URL)
		_, _, _, _, err := d.MintCredentialWithExchange(
			context.Background(), spec, &credential.ExchangeInputs{SubjectToken: "assertion-jwt"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), kubernetesAuthMethodOIDCFederation)
	})

	t.Run("empty subject token is refused", func(t *testing.T) {
		d := newFederatedK8sDriver(t, server.URL)
		_, _, _, _, err := d.MintCredentialWithExchange(
			context.Background(), spec, &credential.ExchangeInputs{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no subject token")
	})

	t.Run("nil exchange inputs are refused", func(t *testing.T) {
		d := newFederatedK8sDriver(t, server.URL)
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no subject token")
	})
}

func TestKubernetesDriver_Federation_RotationAndVerifyDisabled(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	d := newFederatedK8sDriver(t, server.URL)

	assert.False(t, d.SupportsRotation(), "a source holding no token has nothing to rotate")

	// A stored empty auth_method resolves to static, matching what ValidateConfig
	// holds such a source to.
	empty := newTestK8sDriver(t, server.URL)
	empty.credSource.Config["auth_method"] = ""
	assert.Equal(t, kubernetesAuthMethodStatic, empty.getAuthMethod())

	_, _, _, err := d.PrepareRotation(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no token to rotate")

	// VerifySpec has no ambient credential to look the account up with, so it is
	// skipped rather than attempted unauthenticated.
	require.NoError(t, d.VerifySpec(context.Background(), &credential.CredSpec{
		Config: map[string]string{"service_account": "not-found-sa", "namespace": "default"},
	}))
}

func TestKubernetesDriverFactory_Create_Federation(t *testing.T) {
	f := &KubernetesDriverFactory{}

	t.Run("no request is sent to the API server", func(t *testing.T) {
		// Driver creation runs on every mint, not just at source create, so a
		// federated Create must not depend on a credential it does not have.
		var calls int
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		d, err := f.Create(map[string]string{
			"kubernetes_url":  server.URL,
			"auth_method":     kubernetesAuthMethodOIDCFederation,
			"audience":        "https://k8s.example.com",
			"tls_skip_verify": "true",
		}, newTestLogger(t))
		require.NoError(t, err)
		require.NotNil(t, d)
		assert.Zero(t, calls, "the TLS probe must send no HTTP request")
	})

	t.Run("rejects a certificate the CA does not verify", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer server.Close()

		// httptest signs with its own throwaway CA, which the system roots do not
		// carry — so verification must fail without tls_skip_verify.
		_, err := f.Create(map[string]string{
			"kubernetes_url": server.URL,
			"auth_method":    kubernetesAuthMethodOIDCFederation,
		}, newTestLogger(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLS connection")
	})

	t.Run("rejects an unreachable host", func(t *testing.T) {
		_, err := f.Create(map[string]string{
			"kubernetes_url":  "https://127.0.0.1:1",
			"auth_method":     kubernetesAuthMethodOIDCFederation,
			"tls_skip_verify": "true",
		}, newTestLogger(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLS connection")
	})

	t.Run("plain http is not probed", func(t *testing.T) {
		// tls_skip_verify permits an http URL for dev clusters; a handshake against
		// a plain listener would fail regardless of InsecureSkipVerify, so the probe
		// must skip it. The e2e harness depends on this.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("no request should reach the server")
		}))
		defer server.Close()

		_, err := f.Create(map[string]string{
			"kubernetes_url":  server.URL,
			"auth_method":     kubernetesAuthMethodOIDCFederation,
			"tls_skip_verify": "true",
		}, newTestLogger(t))
		require.NoError(t, err)
	})

	t.Run("survives a nil transport", func(t *testing.T) {
		// With neither ca_data nor tls_skip_verify, BuildHTTPClient returns a bare
		// client whose Transport is nil — the probe must not panic reaching for it.
		_, err := f.Create(map[string]string{
			"kubernetes_url": "https://127.0.0.1:1",
			"auth_method":    kubernetesAuthMethodOIDCFederation,
		}, newTestLogger(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLS connection")
	})
}

func TestKubernetesDriver_MapError_Federated(t *testing.T) {
	server := newK8sMockServer(t)
	defer server.Close()

	// A federated refusal is as likely to be a trust or audience mismatch as a
	// missing grant, so the message must name all three.
	d := newFederatedK8sDriver(t, server.URL)
	err := d.mapError(fmt.Errorf("forbidden"), http.StatusForbidden, "payments", "prod")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
	assert.Contains(t, err.Error(), "audience")
	assert.Contains(t, err.Error(), "serviceaccounts/token")

	// The static message is unchanged.
	static := newTestK8sDriver(t, server.URL)
	err = static.mapError(fmt.Errorf("forbidden"), http.StatusForbidden, "payments", "prod")
	assert.Contains(t, err.Error(), "insufficient permissions")
}
