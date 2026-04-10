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

		rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "SCWXXXXXXXXXXXXXXXXX", rawData["access_key"])
		assert.Equal(t, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", rawData["secret_key"])
		assert.Equal(t, time.Duration(0), ttl)
		assert.Empty(t, leaseID)
	})

	t.Run("default mint_method is static_keys", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
		}

		rawData, _, _, err := driver.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "SCWXXXXXXXXXXXXXXXXX", rawData["access_key"])
	})

	t.Run("missing access_key", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test-spec",
			Config: map[string]string{
				"mint_method": "static_keys",
				"secret_key":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
		}

		_, _, _, err := driver.MintCredential(context.Background(), spec)
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

		_, _, _, err := driver.MintCredential(context.Background(), spec)
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

		_, _, _, err := driver.MintCredential(context.Background(), spec)
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

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "SCWNEWKEYXXXXXXXXXX", rawData["access_key"])
	assert.Equal(t, "new-uuid-secret-key", rawData["secret_key"])
	assert.Equal(t, 2*time.Hour, ttl)
	assert.Equal(t, "SCWNEWKEYXXXXXXXXXX", leaseID) // leaseID = access_key
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

	_, _, _, err = driver.MintCredential(context.Background(), spec)
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

	_, _, _, err = driver.MintCredential(context.Background(), spec)
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

		case r.Method == http.MethodPost && r.URL.Path == "/iam/v1alpha1/api-keys":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "app-mgmt-123", body["application_id"])
			assert.Equal(t, "warden-management-key-rotated", body["description"])

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
		assert.Equal(t, "https://api.scaleway.com", d.getScalewayURL())
	})

	t.Run("custom URL", func(t *testing.T) {
		d := &ScalewayDriver{
			credSource: &credential.CredSource{Config: map[string]string{
				"scaleway_url": "https://api.fr-par.scaleway.com/",
			}},
		}
		assert.Equal(t, "https://api.fr-par.scaleway.com", d.getScalewayURL())
	})
}
