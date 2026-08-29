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
// The driver's tokenURL is overridden to point at the test server.
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

	// A source serving only access_keys specs never performs the grant, so the
	// service account is not demanded here. VerifySpec is what refuses an
	// oauth2_token spec on a source that has none.
	t.Run("a source with no service account is accepted", func(t *testing.T) {
		assert.NoError(t, f.ValidateConfig(map[string]string{"ovh_endpoint": "ovh-eu"}))
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
		assert.Equal(t, "https://www.ovh.com/auth/oauth2/token", driver.(*OVHDriver).tokenURL)
	})

	t.Run("ovh-us endpoint", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"ovh_endpoint":  "ovh-us",
		}, log)
		require.NoError(t, err)
		assert.Equal(t, "https://us.ovhcloud.com/auth/oauth2/token", driver.(*OVHDriver).tokenURL)
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

	// The grant is the only request this driver makes, so a deployment whose
	// service-account tokens come from somewhere other than ovh.com points
	// token_url there and the region stops mattering.
	t.Run("token_url override replaces the regional default", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"token_url":     "https://issuer.internal/oauth2/token",
		}, log)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.internal/oauth2/token", driver.(*OVHDriver).tokenURL)
	})

	t.Run("an override wins over a non-default endpoint", func(t *testing.T) {
		driver, err := f.Create(map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
			"ovh_endpoint":  "ovh-us",
			"token_url":     "https://issuer.internal/oauth2/token",
		}, log)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.internal/oauth2/token", driver.(*OVHDriver).tokenURL)
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

	rawData, _, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty access_token")
}

// --- Dynamic S3 credential tests ---

// --- Dual mode (oauth2_token_and_s3) tests ---

// --- Unsupported mint method ---

func TestOVHDriver_MintCredential_UnsupportedMethod(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)

	spec := &credential.CredSpec{
		Name: "bad-spec",
		Config: map[string]string{
			"mint_method": "unknown",
		},
	}

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

// --- Revoke tests ---

// No mint method issues a lease any more, so revocation has nothing to release.
// A lease id from before that change is ignored rather than erroring: erroring
// would only send the expiration manager into a retry ladder for a request that
// can never succeed.
func TestOVHDriver_Revoke_IsNoOp(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)

	for _, leaseID := range []string{"", "proj-123/user-456/s3-key-789", "not-a-lease-shape"} {
		assert.NoError(t, driver.Revoke(context.Background(), leaseID), "leaseID %q", leaseID)
	}
	assert.Zero(t, calls, "revocation must not reach the network")
}

// --- VerifySpec tests ---

func TestOVHDriver_VerifySpec(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)

	t.Run("oauth2_token - the source's service account suffices", func(t *testing.T) {
		err := driver.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "api-spec",
			Config: map[string]string{"mint_method": "oauth2_token"},
		})
		assert.NoError(t, err)
	})

	// The source schema no longer demands a service account, so this is where an
	// oauth2_token spec on a source without one is caught.
	t.Run("oauth2_token - refused on a source with no service account", func(t *testing.T) {
		bare := createOVHTestDriver(t, "https://unused", map[string]string{
			"client_id":     "",
			"client_secret": "",
		})
		err := bare.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "api-spec",
			Config: map[string]string{"mint_method": "oauth2_token"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id and client_secret")
	})

	t.Run("access_keys - refused without a reference to serve", func(t *testing.T) {
		err := driver.VerifySpec(context.Background(), &credential.CredSpec{
			Name:   "s3-spec",
			Config: map[string]string{"mint_method": "access_keys"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), credential.ConfigSecretSpec)
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

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
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

	_, _, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse OAuth2 token response")
}

func TestOVHDriver_MintOAuth2Token_MissingExpiresIn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "valid-token",
			"token_type":   "Bearer",
			// no expires_in — the lease is bounded by the fallback instead
		})
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)
	spec := &credential.CredSpec{
		Name:   "api-spec",
		Config: map[string]string{"mint_method": "oauth2_token"},
	}

	rawData, _, ttl, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "valid-token", rawData["api_token"])
	// A token of unstated lifetime is served for a short span, not an assumed
	// hour: the credential is cached for the whole lease, so guessing long hands
	// out a bearer that is already dead.
	assert.Equal(t, ovhFallbackTokenTTL, ttl)
	assert.Less(t, ttl, 1*time.Hour)
}

// --- Cleanup test ---

func TestOVHDriver_Cleanup(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

// --- access_keys (chained) tests ---

func ovhAccessKeysSpec(secretSpec string) *credential.CredSpec {
	cfg := map[string]string{"mint_method": "access_keys"}
	if secretSpec != "" {
		cfg[credential.ConfigSecretSpec] = secretSpec
	}
	return &credential.CredSpec{Name: "s3-spec", Config: cfg}
}

// The pair is served straight from the fetched material. The point of the method
// is that OVH is never asked for anything, so the test fails if any request is
// made — the driver is pointed at a server that would record one.
func TestOVHDriver_MintFromSecret_AccessKeys(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)
	material := credential.SecretMaterial{Data: map[string]string{
		"access_key": "held-access",
		"secret_key": "held-secret",
	}}

	rawData, _, ttl, leaseID, err := driver.MintFromSecret(context.Background(), ovhAccessKeysSpec("ovh-pair"), material)
	require.NoError(t, err)
	assert.Equal(t, "held-access", rawData["access_key"])
	assert.Equal(t, "held-secret", rawData["secret_key"])
	assert.Zero(t, calls, "serving a pair that already exists must make no request")

	// No lease: nothing was created here, so there is no handle to release and
	// nothing for the expiration manager to try to revoke.
	assert.Empty(t, leaseID)
	assert.Equal(t, defaultOVHAccessKeysChainTTL, ttl)

	t.Run("the spec's secret_cache_ttl bounds how long the pair is reused", func(t *testing.T) {
		spec := ovhAccessKeysSpec("ovh-pair")
		spec.Config[credential.ConfigSecretCacheTTL] = "2m"
		_, _, ttl, _, err := driver.MintFromSecret(context.Background(), spec, material)
		require.NoError(t, err)
		assert.Equal(t, 2*time.Minute, ttl)
	})
}

// A source-level reference describes whatever that source authenticates with, not
// this credential. Spec create refuses the combination, but converting a source
// afterwards does not re-validate the specs already bound to it — so this guard
// is the one that actually holds.
func TestOVHDriver_MintFromSecret_RequiresOwnSecretSpec(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)

	_, _, _, _, err := driver.MintFromSecret(context.Background(), ovhAccessKeysSpec(""), credential.SecretMaterial{
		Data: map[string]string{"access_key": "a", "secret_key": "b"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigSecretSpec)
}

func TestOVHDriver_MintFromSecret_IncompletePair(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)

	for name, data := range map[string]map[string]string{
		"no secret_key": {"access_key": "a"},
		"no access_key": {"secret_key": "b"},
		"neither":       {},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, err := driver.MintFromSecret(context.Background(), ovhAccessKeysSpec("ovh-pair"),
				credential.SecretMaterial{Data: data})
			require.Error(t, err)
			// The sentinel is what lets the minting layer evict a cached copy and
			// fetch again, rather than serving half a credential.
			assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		})
	}
}

func TestOVHDriver_MintFromSecret_RefusesOtherMintMethods(t *testing.T) {
	driver := createOVHTestDriver(t, "https://unused", nil)

	spec := &credential.CredSpec{Name: "api-spec", Config: map[string]string{
		"mint_method":               "oauth2_token",
		credential.ConfigSecretSpec: "ovh-pair",
	}}
	_, _, _, _, err := driver.MintFromSecret(context.Background(), spec, credential.SecretMaterial{
		Data: map[string]string{"access_key": "a", "secret_key": "b"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_keys")
}

// Routing is the minting layer's job; if a chained spec ever reaches the direct
// path the driver must refuse rather than mint something else.
func TestOVHDriver_MintCredential_FailsClosedForAccessKeys(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := createOVHTestDriver(t, server.URL, nil)

	for _, spec := range []*credential.CredSpec{
		ovhAccessKeysSpec("ovh-pair"),
		ovhAccessKeysSpec(""),
	} {
		_, _, _, _, err := driver.MintCredential(context.Background(), spec)
		require.Error(t, err)
	}
	assert.Zero(t, calls)
}
