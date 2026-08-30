package drivers

import (
	"context"
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

	t.Run("access_keys", func(t *testing.T) {
		ct, err := f.InferCredentialType(map[string]string{"mint_method": "access_keys"})
		require.NoError(t, err)
		assert.Equal(t, credential.TypeIBMCloudKeys, ct)
	})

	t.Run("iam_with_cos is gone", func(t *testing.T) {
		_, err := f.InferCredentialType(map[string]string{"mint_method": "iam_with_cos"})
		require.Error(t, err)
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

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
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

	rawData, _, ttl, leaseID, err := d.MintCredential(context.TODO(), spec)
	require.NoError(t, err)

	assert.NotEmpty(t, rawData["access_token"])
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

	rawData, _, _, _, err := d.MintCredential(context.TODO(), spec)
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

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
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
	assert.Equal(t, "acc-123456", d.discoveredAccountID)

	// The discovered account is held on the driver, never written back into the
	// config map. That map belongs to the config store, which hands the same
	// instance to readers taking no driver lock, so a write here raced them.
	assert.NotContains(t, d.credSource.Config, "account_id",
		"discovery must not mutate the source config map")
}

// An operator-configured account wins over whatever discovery reports, which is
// what the removed write-back used to express by only filling an unset key.
func TestIBMDriver_AccountID_ConfiguredWinsOverDiscovered(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := &IBMDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeIBM,
			Config: map[string]string{
				"api_key":      "test-key",
				"iam_endpoint": srv.URL,
				"account_id":   "acc-operator",
			},
		},
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	require.NoError(t, d.discoverAPIKeyDetails(context.TODO()))

	assert.Equal(t, "acc-123456", d.discoveredAccountID, "discovery still records what it saw")

	d.authMu.Lock()
	defer d.authMu.Unlock()
	assert.Equal(t, "acc-operator", d.accountIDLocked())
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
// access_keys Mint Method Tests
// ============================================================================

func accessKeysSpec(secretSpec string) *credential.CredSpec {
	cfg := map[string]string{"mint_method": "access_keys"}
	if secretSpec != "" {
		cfg[credential.ConfigSecretSpec] = secretSpec
	}
	return &credential.CredSpec{Name: "test-spec", Config: cfg}
}

func TestIBMDriver_MintFromSecret_ServesThePair(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	material := credential.SecretMaterial{Data: map[string]string{
		"access_key_id":     "cos-access-key",
		"secret_access_key": "cos-secret-key",
	}}

	rawData, _, ttl, leaseID, err := d.MintFromSecret(context.TODO(), accessKeysSpec("cos-pair"), material)
	require.NoError(t, err)

	assert.Equal(t, "cos-access-key", rawData["access_key_id"])
	assert.Equal(t, "cos-secret-key", rawData["secret_access_key"])
	// The bearer half is gone: a spec serves one mode, and this one is COS.
	assert.NotContains(t, rawData, "access_token")
	assert.Equal(t, defaultIBMAccessKeysChainTTL, ttl)
	assert.Empty(t, leaseID, "nothing was created, so nothing is revocable")
}

func TestIBMDriver_MintFromSecret_HonoursSecretCacheTTL(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := accessKeysSpec("cos-pair")
	spec.Config[credential.ConfigSecretCacheTTL] = "5m"

	material := credential.SecretMaterial{Data: map[string]string{
		"access_key_id":     "ak",
		"secret_access_key": "sk",
	}}

	_, _, ttl, _, err := d.MintFromSecret(context.TODO(), spec, material)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, ttl)
}

// Half a pair is refused rather than served: the gateway's COS leg needs both, and
// silently dropping one would surface as an opaque SigV4 failure at the provider.
func TestIBMDriver_MintFromSecret_RequiresBothHalves(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	for _, tc := range []struct {
		name string
		data map[string]string
	}{
		{"missing secret_access_key", map[string]string{"access_key_id": "ak"}},
		{"missing access_key_id", map[string]string{"secret_access_key": "sk"}},
		{"empty payload", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := d.MintFromSecret(context.TODO(), accessKeysSpec("cos-pair"), credential.SecretMaterial{Data: tc.data})
			require.Error(t, err)
			assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		})
	}
}

// The guard that holds once a source is converted to chaining with specs already
// bound to it: the store cannot re-validate those, so the driver refuses again.
func TestIBMDriver_MintFromSecret_RequiresSpecOwnReference(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	material := credential.SecretMaterial{Data: map[string]string{
		"access_key_id":     "ak",
		"secret_access_key": "sk",
	}}

	_, _, _, _, err := d.MintFromSecret(context.TODO(), accessKeysSpec(""), material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigSecretSpec)
}

func TestIBMDriver_MintFromSecret_RefusesOtherMintMethods(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := &credential.CredSpec{Name: "test-spec", Config: map[string]string{"mint_method": "iam_token"}}
	_, _, _, _, err := d.MintFromSecret(context.TODO(), spec, credential.SecretMaterial{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_keys")
}

// An access_keys spec reaching the direct mint path named no reference; nothing
// here creates a pair, so it fails closed naming what is missing.
func TestIBMDriver_MintCredential_AccessKeysRefusedWithoutChain(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	_, _, _, _, err := d.MintCredential(context.TODO(), accessKeysSpec(""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigSecretSpec)
}

func TestIBMDriver_MintCredential_IAMWithCOSNowUnsupported(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)

	spec := &credential.CredSpec{Name: "test-spec", Config: map[string]string{"mint_method": "iam_with_cos"}}
	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

// ============================================================================
// Compile-time Interface Assertions
// ============================================================================

func TestIBMDriver_ImplementsSpecVerifier(t *testing.T) {
	var _ credential.SpecVerifier = (*IBMDriver)(nil)
}

// TestIBMDriver_RotationDuringMintDiscardsStaleToken pins the generation guard in
// getIAMToken. The IAM entry is keyed by a fixed string, so the generation is the only
// thing separating a token minted by the current API key from one minted by a key that
// has since been retired. A plain Set stamps the entry with whatever generation is
// current when it lands, which files the retired key's token under the new generation —
// and IBM does not revoke outstanding IAM tokens when CleanupRotation deletes the key
// that minted them, so it would be served for its full hour.
func TestIBMDriver_RotationDuringMintDiscardsStaleToken(t *testing.T) {
	var d *IBMDriver
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/token" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		n := atomic.AddInt32(&callCount, 1)
		// Retire the key that is minting this very token, mid-exchange. This is what
		// CommitRotation does to a mint that is already in flight.
		if n == 1 {
			d.tokenCache.InvalidateGeneration()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-call-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"expiration":   time.Now().Add(1 * time.Hour).Unix(),
		})
	}))
	defer srv.Close()

	d = newTestIBMDriver(t, srv.URL)
	d.tokenCache.Clear()

	token, _, err := d.getIAMToken(context.TODO())
	require.NoError(t, err)

	assert.Equal(t, int32(2), atomic.LoadInt32(&callCount), "the in-flight token belonged to the retired key, so it must be minted again")
	assert.Equal(t, "token-call-2", token, "the retired key's token must not be returned")

	cached, _, ok := d.tokenCache.Get("iam", 30*time.Second)
	require.True(t, ok, "the re-minted token is cached")
	assert.Equal(t, "token-call-2", cached, "the retired key's token must never reach the cache")
}

// TestIBMDriver_ConcurrentRotationAndMintIsRaceFree covers the locking half:
// CommitRotation replaces credSource.Config while mints read api_key and iam_endpoint
// out of it. The assertions are modest — this test earns its keep under -race, which is
// what catches the mint path reading the config without the lock that guards the swap.
func TestIBMDriver_ConcurrentRotationAndMintIsRaceFree(t *testing.T) {
	srv := newIBMMockServer(t)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	d.tokenCache.Clear()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := d.getIAMToken(context.TODO())
			assert.NoError(t, err)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, d.CommitRotation(context.TODO(), map[string]string{
			"api_key":      "rotated-key",
			"iam_endpoint": srv.URL,
		}))
	}()

	wg.Wait()

	assert.Equal(t, "rotated-key", d.getAPIKey(), "the driver ends on the rotated key whatever the interleaving")

	// Whether an entry survives depends on the interleaving, but if one did it cannot
	// be the retired key's: the config write and the generation bump share a critical
	// section, so a mint that read the old key also captured the old generation.
	// CommitRotation's own discovery repopulates the entry under the final generation,
	// so an entry must exist — requiring it keeps this assertion from silently
	// vanishing if that ever stops being true.
	token, _, ok := d.tokenCache.Get("iam", 30*time.Second)
	require.True(t, ok, "rotation leaves a usable entry behind")
	assert.Equal(t, "test-iam-token-rotated-key", token,
		"a token the retired key minted must never remain readable after rotation")
}

// TestIBMDriver_TokenFromRetiredKeyIsNeverServed drives the real interleaving rather
// than simulating it: a mint's exchange is held open until an actual CommitRotation has
// swapped the API key underneath it, so the response genuinely carries a token the
// retired key minted. That token must never be returned or cached — the caller must
// discard it and mint again against the key now in force.
func TestIBMDriver_TokenFromRetiredKeyIsNeverServed(t *testing.T) {
	mintStarted := make(chan struct{})
	rotationDone := make(chan struct{})
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/identity/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		apiKey := r.FormValue("apikey")

		// Hold the outgoing key's exchange open until the rotation has landed. The
		// rotated key's own exchanges pass straight through, so CommitRotation's
		// verify is not deadlocked behind this.
		if apiKey == "test-key" {
			once.Do(func() { close(mintStarted) })
			<-rotationDone
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-iam-token-" + apiKey,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"expiration":   time.Now().Add(1 * time.Hour).Unix(),
		})
	})
	mux.HandleFunc("/v1/apikeys/details", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "ApiKey-12345", "iam_id": "iam-ServiceId-abcdef", "account_id": "acc-123456",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	d.tokenCache.Clear()

	var token string
	var mintErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		token, _, mintErr = d.getIAMToken(context.TODO())
	}()

	<-mintStarted
	require.NoError(t, d.CommitRotation(context.TODO(), map[string]string{
		"api_key":      "rotated-key",
		"iam_endpoint": srv.URL,
	}))
	close(rotationDone)
	wg.Wait()

	require.NoError(t, mintErr)
	assert.Equal(t, "test-iam-token-rotated-key", token,
		"the exchange completed against the retired key; its token must be discarded, not served")

	cached, _, ok := d.tokenCache.Get("iam", 30*time.Second)
	require.True(t, ok)
	assert.NotEqual(t, "test-iam-token-test-key", cached, "the retired key's token must never reach the cache")
}
