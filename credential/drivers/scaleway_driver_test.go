package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createScalewayTestLogger() *logger.GatedLogger {
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

// --- Factory tests ---

func TestScalewayDriverFactory_Type(t *testing.T) {
	f := &ScalewayDriverFactory{}
	assert.Equal(t, credential.SourceTypeScaleway, f.Type())
}

func TestScalewayDriverFactory_InferCredentialType(t *testing.T) {
	f := &ScalewayDriverFactory{}
	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeScalewayKeys, ct)
}

func TestScalewayDriverFactory_ValidateConfig(t *testing.T) {
	f := &ScalewayDriverFactory{}

	t.Run("empty config is valid", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{})
		assert.NoError(t, err)
	})

	t.Run("valid config with all fields", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"scaleway_url":          "https://api.scaleway.com",
			"management_secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		})
		assert.NoError(t, err)
	})

	t.Run("invalid URL", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"scaleway_url": "http://api.scaleway.com",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})
}

func TestScalewayDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &ScalewayDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "management_secret_key")
	assert.Contains(t, fields, "ca_data")
}

func TestScalewayDriverFactory_Create(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":          "https://api.scaleway.com",
		"management_secret_key": "test-key",
	}, log)
	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeScaleway, driver.Type())
}

// --- Static credential tests ---

func TestScalewayDriver_MintStaticCredential(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)

	t.Run("valid static keys", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "static_keys",
				"access_key":  "SCWXXXXXXXXXXXXXXXXX",
				"secret_key":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
		}

		rawData, _, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "SCWXXXXXXXXXXXXXXXXX", rawData["access_key"])
		assert.Equal(t, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", rawData["secret_key"])
		assert.Equal(t, time.Duration(0), ttl)
		assert.Empty(t, leaseID)
	})

	t.Run("mint_method is not defaulted", func(t *testing.T) {
		// The credential type refuses a spec without an explicit mint_method, so an
		// empty one here means validation was bypassed. Minting static keys anyway
		// would guess at what the operator meant.
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
		}

		_, _, _, _, err := driver.MintCredential(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected static_keys or dynamic_keys")
	})

	t.Run("missing access_key", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "static_keys",
				"secret_key":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
		}

		_, _, _, _, err := driver.MintCredential(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key")
	})

	t.Run("missing secret_key", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "static_keys",
				"access_key":  "SCWXXXXXXXXXXXXXXXXX",
			},
		}

		_, _, _, _, err := driver.MintCredential(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_key")
	})

	t.Run("unsupported mint_method", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "unknown",
			},
		}

		_, _, _, _, err := driver.MintCredential(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported mint_method")
	})
}

// --- Dynamic credential tests ---

func TestScalewayDriver_MintDynamicCredential(t *testing.T) {
	// Mock Scaleway IAM API
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		assert.Equal(t, "mgmt-secret-key", r.Header.Get("X-Auth-Token"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/iam/v1alpha1/api-keys":
			// Parse request body
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			assert.Equal(t, "app-123", reqBody["application_id"])
			assert.NotEmpty(t, reqBody["expires_at"])
			assert.NotEmpty(t, reqBody["description"])

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_key":     "SCWNEWKEYXXXXXXXXXX",
				"secret_key":     "new-uuid-secret-key",
				"application_id": "app-123",
				"description":    reqBody["description"],
				"expires_at":     reqBody["expires_at"],
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"tls_skip_verify":       "true",
	}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "dynamic-spec",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
			"ttl":            "2h",
			"description":    "test-key",
		},
	}

	rawData, _, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "SCWNEWKEYXXXXXXXXXX", rawData["access_key"])
	assert.Equal(t, "new-uuid-secret-key", rawData["secret_key"])
	// The lease follows the server's expires_at, which the stub echoes back — so it
	// lands just under the requested 2h by the round-trip time, never above it.
	assert.LessOrEqual(t, ttl, 2*time.Hour)
	assert.Greater(t, ttl, 2*time.Hour-time.Minute)
	assert.Equal(t, "SCWNEWKEYXXXXXXXXXX", leaseID) // leaseID = access_key
}

func TestScalewayDriver_MintDynamicCredential_LeaseFollowsServerExpiry(t *testing.T) {
	// An organization credential-duration policy can cap a key well below what was
	// asked for. The lease has to follow the key, not the request: it bounds how
	// long the credential is served from cache, and a lease outliving its key means
	// later requests are handed something already dead.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_key": "SCWCLAMPEDKEYXXXXXX",
			"secret_key": "clamped-secret",
			"expires_at": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
		})
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"tls_skip_verify":       "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "clamped-spec",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
			"ttl":            "24h",
		},
	}

	_, _, ttl, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Less(t, ttl, 16*time.Minute, "lease must follow the clamped expires_at, not the requested 24h")
	assert.Greater(t, ttl, 14*time.Minute)
}

func TestScalewayDriver_MintDynamicCredential_UnparseableExpiryFallsBack(t *testing.T) {
	// A usable key is not thrown away over a timestamp format.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_key": "SCWWEIRDEXPIRYXXXXX",
			"secret_key": "weird-secret",
			"expires_at": "next tuesday",
		})
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"tls_skip_verify":       "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)

	_, _, ttl, _, err := driver.MintCredential(context.Background(), &credential.CredSpec{
		Name: "weird-spec",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
			"ttl":            "30m",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 30*time.Minute, ttl)
}

func TestScalewayDriver_MintDynamicCredential_AlreadyExpiredIsAnError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_key": "SCWDEADKEYXXXXXXXXX",
			"secret_key": "dead-secret",
			"expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		})
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"tls_skip_verify":       "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)

	_, _, _, _, err = driver.MintCredential(context.Background(), &credential.CredSpec{
		Name: "dead-spec",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
			"ttl":            "1h",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already expired")
}

func TestScalewayDriver_MintDynamicCredential_MissingManagementKey(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "dynamic-spec",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
		},
	}

	_, _, _, _, err = driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "management_secret_key")
}

func TestScalewayDriver_MintDynamicCredential_MissingApplicationID(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"management_secret_key": "mgmt-key",
	}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "dynamic-spec",
		Config: map[string]string{
			"mint_method": "dynamic_keys",
		},
	}

	_, _, _, _, err = driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "application_id")
}

// --- Revoke tests ---

func TestScalewayDriver_Revoke(t *testing.T) {
	var deletedKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			assert.Equal(t, "mgmt-secret-key", r.Header.Get("X-Auth-Token"))
			deletedKey = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"tls_skip_verify":       "true",
	}, log)
	require.NoError(t, err)

	err = driver.Revoke(context.Background(), "SCWNEWKEYXXXXXXXXXX")
	require.NoError(t, err)
	assert.Equal(t, "/iam/v1alpha1/api-keys/SCWNEWKEYXXXXXXXXXX", deletedKey)
}

func TestScalewayDriver_Revoke_EmptyLeaseID(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)

	// Empty leaseID should be a no-op
	err = driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestScalewayDriver_Revoke_MissingManagementKey(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)

	err = driver.Revoke(context.Background(), "SCWKEY123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "management_secret_key")
}

// --- VerifySpec tests ---

func TestScalewayDriver_VerifySpec_StaticKeys(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/iam/v1alpha1/api-keys/SCWXXXXXXXXXXXXXXXXX" {
			assert.Equal(t, "test-secret", r.Header.Get("X-Auth-Token"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_key":"SCWXXXXXXXXXXXXXXXXX"}`))
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":    server.URL,
		"tls_skip_verify": "true",
	}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "static_keys",
			"access_key":  "SCWXXXXXXXXXXXXXXXXX",
			"secret_key":  "test-secret",
		},
	}

	scwDriver := driver.(*ScalewayDriver)
	err = scwDriver.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestScalewayDriver_VerifySpec_DynamicKeys(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"management_secret_key": "mgmt-key",
	}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "dynamic-spec",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
		},
	}

	scwDriver := driver.(*ScalewayDriver)
	err = scwDriver.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestScalewayDriver_VerifySpec_DynamicKeys_MissingFields(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)

	t.Run("missing management_secret_key", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "dynamic-spec",
			Config: map[string]string{
				"mint_method":    "dynamic_keys",
				"application_id": "app-123",
			},
		}
		scwDriver := driver.(*ScalewayDriver)
		err := scwDriver.VerifySpec(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "management_secret_key")
	})

	t.Run("missing application_id", func(t *testing.T) {
		f2 := &ScalewayDriverFactory{}
		driver2, _ := f2.Create(map[string]string{
			"management_secret_key": "mgmt-key",
		}, log)
		spec := &credential.CredSpec{
			Name: "dynamic-spec",
			Config: map[string]string{
				"mint_method": "dynamic_keys",
			},
		}
		scwDriver := driver2.(*ScalewayDriver)
		err := scwDriver.VerifySpec(context.Background(), spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "application_id")
	})
}

// --- Cleanup test ---

func TestScalewayDriver_Cleanup(t *testing.T) {
	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)

	// Should not panic
	err = driver.(*ScalewayDriver).Cleanup(context.Background())
	assert.NoError(t, err)
}

// --- Rotation tests ---

func TestScalewayDriver_SupportsRotation(t *testing.T) {
	t.Run("supports when both keys present", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"management_secret_key": "secret",
				"management_access_key": "SCWMGMTKEY",
			}},
		}
		assert.True(t, d.SupportsRotation())
	})

	t.Run("does not support without access key", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"management_secret_key": "secret",
			}},
		}
		assert.False(t, d.SupportsRotation())
	})

	t.Run("does not support without secret key", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"management_access_key": "SCWMGMTKEY",
			}},
		}
		assert.False(t, d.SupportsRotation())
	})

	t.Run("does not support with empty config", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{}},
		}
		assert.False(t, d.SupportsRotation())
	})
}

func TestScalewayDriver_PrepareRotation(t *testing.T) {
	// Mock Scaleway IAM API for rotation
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "old-mgmt-secret", r.Header.Get("X-Auth-Token"))

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/iam/v1alpha1/api-keys/SCWOLDMGMTKEY":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_key":     "SCWOLDMGMTKEY",
				"application_id": "app-mgmt-123",
			})

		// The orphan sweep lists the bearer's keys before creating anything.
		case r.Method == http.MethodGet && r.URL.Path == "/iam/v1alpha1/api-keys":
			assert.Equal(t, "app-mgmt-123", r.URL.Query().Get("application_id"))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"api_keys":    []interface{}{},
				"total_count": 0,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/iam/v1alpha1/api-keys":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "app-mgmt-123", body["application_id"])
			// The stamp names the key being replaced, so two sources rotating for the
			// same bearer produce distinguishable lineages.
			assert.Equal(t, "warden-management-key-rotated-from-SCWOLDMGMTKEY", body["description"])

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_key": "SCWNEWMGMTKEY",
				"secret_key": "new-mgmt-secret",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "old-mgmt-secret",
		"management_access_key": "SCWOLDMGMTKEY",
		"tls_skip_verify":       "true",
	}, log)
	require.NoError(t, err)

	scwDriver := driver.(*ScalewayDriver)
	newConfig, cleanupConfig, activateAfter, err := scwDriver.PrepareRotation(context.Background())
	require.NoError(t, err)

	// Verify new config
	assert.Equal(t, "new-mgmt-secret", newConfig["management_secret_key"])
	assert.Equal(t, "SCWNEWMGMTKEY", newConfig["management_access_key"])
	// Original config fields should be preserved
	assert.Equal(t, server.URL, newConfig["scaleway_url"])
	assert.Equal(t, "true", newConfig["tls_skip_verify"])

	// Verify cleanup config
	assert.Equal(t, "SCWOLDMGMTKEY", cleanupConfig["access_key"])

	// Verify activation delay
	assert.Equal(t, DefaultScalewayActivationDelay, activateAfter)
}

func TestScalewayDriver_PrepareRotation_MissingFields(t *testing.T) {
	log := createScalewayTestLogger()

	t.Run("missing management_secret_key", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"management_access_key": "SCWKEY",
			}},
			logger: log,
		}
		_, _, _, err := d.PrepareRotation(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "management_secret_key")
	})

	t.Run("missing management_access_key", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"management_secret_key": "secret",
			}},
			logger: log,
		}
		_, _, _, err := d.PrepareRotation(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "management_access_key")
	})
}

func TestScalewayDriver_CommitRotation(t *testing.T) {
	log := createScalewayTestLogger()

	d := &ScalewayDriver{
		credSource: &credential.CredSource{Config: map[string]string{
			"management_secret_key": "old-secret",
			"management_access_key": "SCWOLDKEY",
			"scaleway_url":          "https://api.scaleway.com",
		}},
		logger: log,
	}

	newConfig := map[string]string{
		"management_secret_key": "new-secret",
		"management_access_key": "SCWNEWKEY",
		"scaleway_url":          "https://api.scaleway.com",
	}

	err := d.CommitRotation(context.Background(), newConfig)
	require.NoError(t, err)

	// Config should be updated
	d.configMu.RLock()
	assert.Equal(t, "new-secret", d.getManagementSecretKeyLocked())
	assert.Equal(t, "SCWNEWKEY", credential.GetString(d.credSource.Config, "management_access_key", ""))
	d.configMu.RUnlock()
}

func TestScalewayDriver_CleanupRotation(t *testing.T) {
	var deletedPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			assert.Equal(t, "new-mgmt-secret", r.Header.Get("X-Auth-Token"))
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "new-mgmt-secret",
		"management_access_key": "SCWNEWMGMTKEY",
		"tls_skip_verify":       "true",
	}, log)
	require.NoError(t, err)

	scwDriver := driver.(*ScalewayDriver)
	err = scwDriver.CleanupRotation(context.Background(), map[string]string{
		"access_key": "SCWOLDMGMTKEY",
	})
	require.NoError(t, err)
	assert.Equal(t, "/iam/v1alpha1/api-keys/SCWOLDMGMTKEY", deletedPath)
}

func TestScalewayDriver_CleanupRotation_EmptyAccessKey(t *testing.T) {
	log := createScalewayTestLogger()

	d := &ScalewayDriver{
		credSource: &credential.CredSource{Config: map[string]string{}},
		logger:     log,
	}

	err := d.CleanupRotation(context.Background(), map[string]string{})
	assert.NoError(t, err)
}

func TestScalewayDriver_PrepareRotation_CustomActivationDelay(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_key":     "SCWKEY",
				"application_id": "app-123",
			})
		case r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_key": "SCWNEWKEY",
				"secret_key": "new-secret",
			})
		}
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	log := createScalewayTestLogger()

	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "secret",
		"management_access_key": "SCWKEY",
		"activation_delay":      "2m",
		"tls_skip_verify":       "true",
	}, log)
	require.NoError(t, err)

	scwDriver := driver.(*ScalewayDriver)
	_, _, activateAfter, err := scwDriver.PrepareRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, activateAfter)
}

// --- URL helper tests ---

func TestScalewayDriver_GetScalewayURL(t *testing.T) {
	t.Run("default URL", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{}},
		}
		assert.Equal(t, "https://api.scaleway.com", d.getScalewayURLLocked())
	})

	t.Run("custom URL", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"scaleway_url": "https://api.fr-par.scaleway.com/",
			}},
		}
		assert.Equal(t, "https://api.fr-par.scaleway.com", d.getScalewayURLLocked())
	})
}

// --- Credential chaining ---

func newChainedScalewayDriver(t *testing.T, serverURL string) *ScalewayDriver {
	t.Helper()
	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":    serverURL,
		"secret_spec":     "scw-mgmt-key",
		"secret_field":    "management_secret_key",
		"tls_skip_verify": "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)
	return driver.(*ScalewayDriver)
}

func chainedDynamicKeysSpec() *credential.CredSpec {
	return &credential.CredSpec{
		Name: "chained-dynamic",
		Config: map[string]string{
			"mint_method":    "dynamic_keys",
			"application_id": "app-123",
			"ttl":            "1h",
		},
	}
}

func chainedStaticKeysSpec() *credential.CredSpec {
	return &credential.CredSpec{
		Name:   "chained-static",
		Config: map[string]string{"mint_method": "static_keys", "secret_spec": "scw-pair"},
	}
}

func TestScalewayDriverFactory_ValidateConfig_Chaining(t *testing.T) {
	f := &ScalewayDriverFactory{}

	t.Run("minimal chained config", func(t *testing.T) {
		require.NoError(t, f.ValidateConfig(map[string]string{
			"secret_spec":      "scw-mgmt-key",
			"secret_field":     "management_secret_key",
			"secret_cache_ttl": "30m",
		}))
	})

	// A source that keeps its key while claiming to fetch one reads as keyless but
	// still stores the very secret chaining exists to remove. The rotation keys go
	// with it: their only consumer is rotation, which a chained source hands away.
	for _, key := range []string{"management_secret_key", "management_access_key", "activation_delay"} {
		t.Run("chained rejects "+key, func(t *testing.T) {
			cfg := map[string]string{"secret_spec": "scw-mgmt-key"}
			switch key {
			case "management_access_key":
				cfg[key] = "SCWXXXXXXXXXXXXXXXXX"
			case "activation_delay":
				cfg[key] = "2m"
			default:
				cfg[key] = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
			}
			err := f.ValidateConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}

	t.Run("non-chained config still accepts management keys", func(t *testing.T) {
		require.NoError(t, f.ValidateConfig(map[string]string{
			"management_access_key": "SCWXXXXXXXXXXXXXXXXX",
			"management_secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			"activation_delay":      "2m",
		}))
	})
}

func TestScalewayDriver_MintCredential_FailsClosedWhenChained(t *testing.T) {
	t.Run("source-level", func(t *testing.T) {
		d := newChainedScalewayDriver(t, "https://api.scaleway.com")
		_, _, _, _, err := d.MintCredential(context.Background(), chainedDynamicKeysSpec())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_spec")
	})

	t.Run("spec-level", func(t *testing.T) {
		f := &ScalewayDriverFactory{}
		driver, err := f.Create(map[string]string{}, createScalewayTestLogger())
		require.NoError(t, err)
		_, _, _, _, err = driver.MintCredential(context.Background(), chainedStaticKeysSpec())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_spec")
	})
}

func TestScalewayDriver_MintFromSecret_DynamicKeys(t *testing.T) {
	cases := []struct {
		name     string
		material credential.SecretMaterial
	}{
		{"resolved field", credential.SecretMaterial{
			Data:  map[string]string{"management_secret_key": "FETCHED-MGMT"},
			Field: "management_secret_key",
		}},
		{"conventional management_secret_key", credential.SecretMaterial{
			Data: map[string]string{"management_secret_key": "FETCHED-MGMT", "note": "x"},
		}},
		{"conventional secret_key", credential.SecretMaterial{
			Data: map[string]string{"secret_key": "FETCHED-MGMT", "note": "x"},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotToken string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotToken = r.Header.Get("X-Auth-Token")
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_key": "SCWCHAINEDKEYXXXXXX",
					"secret_key": "chained-minted-secret",
					"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				})
			}))
			defer server.Close()

			d := newChainedScalewayDriver(t, server.URL)
			rawData, _, ttl, leaseID, err := d.MintFromSecret(context.Background(), chainedDynamicKeysSpec(), tc.material)
			require.NoError(t, err)

			assert.Equal(t, "FETCHED-MGMT", gotToken, "the fetched key authenticates the mint")
			assert.Equal(t, "SCWCHAINEDKEYXXXXXX", rawData["access_key"])
			assert.Greater(t, ttl, time.Duration(0))
			assert.Empty(t, leaseID, "a chained source cannot honour a lease it has no key to revoke with")
		})
	}
}

func TestScalewayDriver_MintFromSecret_StaticKeys(t *testing.T) {
	// The static path spends the material directly; it must not call Scaleway at all.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("static_keys must not call the Scaleway API")
	}))
	defer server.Close()

	d := newChainedScalewayDriver(t, server.URL)
	material := credential.SecretMaterial{
		Data: map[string]string{"access_key": "SCWFETCHEDPAIRXXXXX", "secret_key": "fetched-pair-secret"},
		// A resolved field has no meaning for a pair; it must not derail the read.
		Field: "management_secret_key",
	}

	rawData, _, ttl, leaseID, err := d.MintFromSecret(context.Background(), chainedStaticKeysSpec(), material)
	require.NoError(t, err)
	assert.Equal(t, "SCWFETCHEDPAIRXXXXX", rawData["access_key"])
	assert.Equal(t, "fetched-pair-secret", rawData["secret_key"])
	assert.Empty(t, leaseID)
	assert.Equal(t, defaultScalewayStaticChainTTL, ttl,
		"a positive TTL bounds staleness: this path can never learn the pair was rotated")
}

func TestScalewayDriver_MintFromSecret_StaticKeys_RefusesSourceLevelRouting(t *testing.T) {
	// Converting a source to chaining does not re-validate the specs already bound
	// to it, so an inline static_keys spec can end up routed by the SOURCE's
	// reference. Its material is then the management key — whose payload is also a
	// Scaleway pair — and minting from it would hand the caller a credential that
	// can create and delete API keys, in place of the scoped one the spec describes.
	d := newChainedScalewayDriver(t, "https://api.scaleway.com")

	inlineSpec := &credential.CredSpec{
		Name: "pre-conversion",
		Config: map[string]string{
			"mint_method": "static_keys",
			"access_key":  "SCWSPECOWNKEYXXXXXX",
			"secret_key":  "spec-own-secret",
		},
	}
	managementPayload := credential.SecretMaterial{
		Data: map[string]string{"access_key": "SCWMANAGEMENTKEYXXX", "secret_key": "management-secret"},
	}

	_, _, _, _, err := d.MintFromSecret(context.Background(), inlineSpec, managementPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must set its own secret_spec")
}

func TestScalewayDriver_MintFromSecret_StaticKeys_TTLFollowsCacheTTL(t *testing.T) {
	d := newChainedScalewayDriver(t, "https://api.scaleway.com")
	spec := chainedStaticKeysSpec()
	spec.Config["secret_cache_ttl"] = "5m"

	_, _, ttl, _, err := d.MintFromSecret(context.Background(), spec, credential.SecretMaterial{
		Data: map[string]string{"access_key": "SCWPAIRXXXXXXXXXXXX", "secret_key": "s"},
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, ttl)

	// "0" opts out of caching, not out of a staleness bound: taking it literally
	// would restore the session-long pin this TTL exists to prevent.
	spec.Config["secret_cache_ttl"] = "0"
	_, _, ttl, _, err = d.MintFromSecret(context.Background(), spec, credential.SecretMaterial{
		Data: map[string]string{"access_key": "SCWPAIRXXXXXXXXXXXX", "secret_key": "s"},
	})
	require.NoError(t, err)
	assert.Equal(t, defaultScalewayStaticChainTTL, ttl)
}

func TestScalewayDriver_MintFromSecret_IncompleteMaterial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("must not reach the Scaleway API with unusable material")
	}))
	defer server.Close()
	d := newChainedScalewayDriver(t, server.URL)

	t.Run("dynamic: resolved field is empty", func(t *testing.T) {
		_, _, _, _, err := d.MintFromSecret(context.Background(), chainedDynamicKeysSpec(),
			credential.SecretMaterial{Data: map[string]string{"other": "x"}, Field: "management_secret_key"})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		assert.Contains(t, err.Error(), "management_secret_key")
	})

	t.Run("dynamic: no field and no conventional key", func(t *testing.T) {
		_, _, _, _, err := d.MintFromSecret(context.Background(), chainedDynamicKeysSpec(),
			credential.SecretMaterial{Data: map[string]string{"other": "x", "more": "y"}})
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
	})

	for _, tc := range []struct {
		name string
		data map[string]string
	}{
		{"missing access_key", map[string]string{"secret_key": "s"}},
		{"missing secret_key", map[string]string{"access_key": "SCWXXXXXXXXXXXXXXXXX"}},
		{"missing both", map[string]string{"unrelated": "x"}},
	} {
		t.Run("static: "+tc.name, func(t *testing.T) {
			_, _, _, _, err := d.MintFromSecret(context.Background(), chainedStaticKeysSpec(),
				credential.SecretMaterial{Data: tc.data})
			require.Error(t, err)
			assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		})
	}

	t.Run("unknown mint_method", func(t *testing.T) {
		_, _, _, _, err := d.MintFromSecret(context.Background(),
			&credential.CredSpec{Name: "drifted", Config: map[string]string{"mint_method": "wat"}},
			credential.SecretMaterial{Data: map[string]string{"secret_key": "s"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dynamic_keys or static_keys")
	})
}

func TestScalewayDriver_MintFromSecret_RejectionIsRetryable(t *testing.T) {
	// A key rotated at its source must be recoverable: the minting layer evicts the
	// cached secret and retries once, but only if the driver says it was rejected.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"type":"denied_authentication"}`, status)
			}))
			defer server.Close()

			d := newChainedScalewayDriver(t, server.URL)
			_, _, _, _, err := d.MintFromSecret(context.Background(), chainedDynamicKeysSpec(),
				credential.SecretMaterial{Data: map[string]string{"management_secret_key": "STALE"}})
			require.Error(t, err)
			assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
		})
	}

	t.Run("other failures are not retryable", func(t *testing.T) {
		// Re-fetching an identical secret cannot help, so it must not be tried.
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"type":"not_found"}`, http.StatusNotFound)
		}))
		defer server.Close()

		d := newChainedScalewayDriver(t, server.URL)
		_, _, _, _, err := d.MintFromSecret(context.Background(), chainedDynamicKeysSpec(),
			credential.SecretMaterial{Data: map[string]string{"management_secret_key": "FINE"}})
		require.Error(t, err)
		assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
	})
}

func TestScalewayDriver_ChainedSourceOwnsNoRotation(t *testing.T) {
	d := newChainedScalewayDriver(t, "https://api.scaleway.com")
	assert.False(t, d.SupportsRotation(), "the referenced spec's owner rotates the key at its source of truth")

	// A lease predating the conversion can never be revoked, and saying so with an
	// error would only make the expiration manager retry it daily, forever.
	require.NoError(t, d.Revoke(context.Background(), "SCWPRECONVERSIONKEY"))
}

func TestScalewayDriver_NonChainedSourceStillRotates(t *testing.T) {
	// A plain source that merely hosts a spec-chained static spec keeps its own
	// management key, and keeps rotating it.
	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"management_secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		"management_access_key": "SCWXXXXXXXXXXXXXXXXX",
	}, createScalewayTestLogger())
	require.NoError(t, err)
	assert.True(t, driver.(*ScalewayDriver).SupportsRotation())
}

// --- Defect regression tests ---

func TestScalewayDriverFactory_ValidateConfig_DoesNotEchoSwappedSecret(t *testing.T) {
	// The swap this check catches puts the SECRET key in management_access_key.
	// Echoing the offending value would leak it into API responses and logs, where
	// SensitiveConfigFields cannot mask it.
	f := &ScalewayDriverFactory{}
	secret := "11111111-2222-3333-4444-555555555555"

	err := f.ValidateConfig(map[string]string{"management_access_key": secret})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "did you swap")
}

func TestScalewayDriverFactory_ValidateConfig_ActivationDelay(t *testing.T) {
	f := &ScalewayDriverFactory{}

	require.NoError(t, f.ValidateConfig(map[string]string{"activation_delay": "2m"}))

	// Previously undeclared, so a typo passed validation and was then silently
	// swallowed by GetDuration, leaving the operator with the 30s default.
	err := f.ValidateConfig(map[string]string{"activation_delay": "30sec"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "activation_delay")
}

func TestScalewayDriver_Revoke_NotFoundBodyIsSuccessBareIsNot(t *testing.T) {
	t.Run("not_found body means already gone", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"type":"not_found","message":"api key not found"}`))
		}))
		defer server.Close()

		f := &ScalewayDriverFactory{}
		driver, err := f.Create(map[string]string{
			"scaleway_url":          server.URL,
			"management_secret_key": "mgmt-secret-key",
			"tls_skip_verify":       "true",
		}, createScalewayTestLogger())
		require.NoError(t, err)

		require.NoError(t, driver.Revoke(context.Background(), "SCWGONEKEYXXXXXXXXX"))
	})

	t.Run("bare 404 does not claim revocation", func(t *testing.T) {
		// What a mistyped iam_api_path produces. Revoke still returns nil — an error
		// would send the expiration manager into backoff and then a daily retry for a
		// request that can never succeed — but it must not log success.
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "404 page not found", http.StatusNotFound)
		}))
		defer server.Close()

		f := &ScalewayDriverFactory{}
		driver, err := f.Create(map[string]string{
			"scaleway_url":          server.URL,
			"management_secret_key": "mgmt-secret-key",
			"tls_skip_verify":       "true",
		}, createScalewayTestLogger())
		require.NoError(t, err)

		require.NoError(t, driver.Revoke(context.Background(), "SCWLIVEKEYXXXXXXXXX"))
	})
}

func TestScalewayDriver_CleanupRotation_BareNotFoundIsAnError(t *testing.T) {
	// The old management key carries no expiry, so reporting a failed delete as
	// success would leave a fully privileged credential alive indefinitely.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "404 page not found", http.StatusNotFound)
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"tls_skip_verify":       "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)

	err = driver.(*ScalewayDriver).CleanupRotation(context.Background(),
		map[string]string{"access_key": "SCWOLDMGMTKEY"})
	require.Error(t, err)
}

func TestScalewayDriver_PrepareRotation_SweepsOnlyItsOwnLineage(t *testing.T) {
	// The sweep must reclaim orphans from a previous attempt at THIS rotation while
	// leaving alone an operator's own key and a sibling Warden source's key, which
	// is stamped from a different predecessor. Deleting the latter would be the
	// delete-a-key-you-do-not-own bug re-aimed at another Warden.
	var deleted []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/iam/v1alpha1/api-keys/SCWOLDMGMTKEY":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_key":     "SCWOLDMGMTKEY",
				"application_id": "app-mgmt-123",
			})

		case r.Method == http.MethodGet && r.URL.Path == "/iam/v1alpha1/api-keys":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"api_keys": []map[string]string{
					{"access_key": "SCWORPHANKEY", "description": "warden-management-key-rotated-from-SCWOLDMGMTKEY"},
					{"access_key": "SCWSIBLINGKEY", "description": "warden-management-key-rotated-from-SCWOTHERKEY"},
					{"access_key": "SCWOPERATORKEY", "description": "ops-terraform"},
					{"access_key": "SCWOLDMGMTKEY", "description": "warden-management-key-rotated-from-SCWANCESTOR"},
				},
				"total_count": 4,
			})

		case r.Method == http.MethodDelete:
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/iam/v1alpha1/api-keys/"))
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/iam/v1alpha1/api-keys":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_key": "SCWNEWMGMTKEY",
				"secret_key": "new-mgmt-secret",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "old-mgmt-secret",
		"management_access_key": "SCWOLDMGMTKEY",
		"tls_skip_verify":       "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)

	_, _, _, err = driver.(*ScalewayDriver).PrepareRotation(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"SCWORPHANKEY"}, deleted,
		"only this lineage's orphan may be deleted — not a sibling source's key, an operator key, or the key in use")
}

func TestScalewayDriver_MintConcurrentWithCommitRotation(t *testing.T) {
	// Rotation replaces the whole config map, so every read of it — including the
	// ones behind iamURL, for keys rotation never rewrites — has to hold the lock.
	// Meaningful under -race.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_key": "SCWRACEKEYXXXXXXXXX",
			"secret_key": "race-secret",
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer server.Close()

	f := &ScalewayDriverFactory{}
	driver, err := f.Create(map[string]string{
		"scaleway_url":          server.URL,
		"management_secret_key": "mgmt-secret-key",
		"management_access_key": "SCWMGMTKEY",
		"tls_skip_verify":       "true",
	}, createScalewayTestLogger())
	require.NoError(t, err)
	scw := driver.(*ScalewayDriver)

	spec := &credential.CredSpec{
		Name:   "race-spec",
		Config: map[string]string{"mint_method": "dynamic_keys", "application_id": "app-123", "ttl": "1h"},
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, _ = scw.MintCredential(context.Background(), spec)
			_ = scw.SupportsRotation()
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = scw.CommitRotation(context.Background(), map[string]string{
				"scaleway_url":          server.URL,
				"management_secret_key": fmt.Sprintf("rotated-secret-%d", n),
				"management_access_key": fmt.Sprintf("SCWROTATED%d", n),
				"tls_skip_verify":       "true",
			})
		}(i)
	}
	wg.Wait()
}
