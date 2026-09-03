package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// grafanaTestDriver builds a driver against a stub, with the given source config
// keys layered onto the connection ones.
func grafanaTestDriver(server *httptest.Server, config map[string]string) *GrafanaDriver {
	full := map[string]string{
		"grafana_url": server.URL,
		"admin_token": "glsa_admin",
	}
	for k, v := range config {
		full[k] = v
	}
	return &GrafanaDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGrafana,
			Config: full,
		},
		httpClient: server.Client(),
	}
}

func grafanaSpec(name string, config map[string]string) *credential.CredSpec {
	if config == nil {
		config = map[string]string{}
	}
	return &credential.CredSpec{Name: name, Type: credential.TypeAPIKey, Config: config}
}

func TestGrafanaDriverFactory_Type(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	assert.Equal(t, credential.SourceTypeGrafana, factory.Type())
}

func TestGrafanaDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "admin_token")
	assert.Contains(t, fields, "ca_data")
}

func TestGrafanaDriverFactory_InferCredentialType(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	credType, err := factory.InferCredentialType(nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, credType)
}

func TestGrafanaDriverFactory_ValidateConfig(t *testing.T) {
	factory := &GrafanaDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: map[string]string{
				"grafana_url": "https://mystack.grafana.net",
				"admin_token": "glsa_test_token",
			},
		},
		{
			name: "with a default service account",
			config: map[string]string{
				"grafana_url":        "https://mystack.grafana.net",
				"admin_token":        "glsa_test_token",
				"service_account_id": "42",
			},
		},
		{
			name: "non-numeric default service account",
			config: map[string]string{
				"grafana_url":        "https://mystack.grafana.net",
				"admin_token":        "glsa_test_token",
				"service_account_id": "my-account",
			},
			wantErr: true,
			errMsg:  "positive integer",
		},
		{
			name:    "missing grafana_url",
			config:  map[string]string{"admin_token": "glsa_test_token"},
			wantErr: true,
			errMsg:  "grafana_url",
		},
		{
			name:    "missing admin_token",
			config:  map[string]string{"grafana_url": "https://mystack.grafana.net"},
			wantErr: true,
			errMsg:  "admin_token",
		},
		{
			name: "invalid grafana_url scheme",
			config: map[string]string{
				"grafana_url": "http://mystack.grafana.net",
				"admin_token": "glsa_test_token",
			},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name: "http allowed with tls_skip_verify",
			config: map[string]string{
				"grafana_url":     "http://grafana.local",
				"admin_token":     "glsa_test_token",
				"tls_skip_verify": "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// A rotation_period on a grafana source is accepted and then fails every cycle
// forever, visible only in server logs — so the factory refuses it outright.
func TestGrafanaDriverFactory_ValidateRotationConfig(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	err := factory.ValidateRotationConfig(map[string]string{
		"grafana_url": "https://mystack.grafana.net",
		"admin_token": "glsa_admin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation does not apply")
}

func TestGrafanaDriverFactory_Create(t *testing.T) {
	factory := &GrafanaDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := factory.Create(map[string]string{
		"grafana_url": "https://mystack.grafana.net",
		"admin_token": "glsa_test_token",
	}, log)
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeGrafana, driver.Type())
}

func TestGrafanaDriver_Type(t *testing.T) {
	driver := &GrafanaDriver{credSource: &credential.CredSource{Type: credential.SourceTypeGrafana}}
	assert.Equal(t, credential.SourceTypeGrafana, driver.Type())
}

func TestGrafanaDriver_Cleanup(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeGrafana},
		httpClient: &http.Client{},
	}
	assert.NoError(t, driver.Cleanup(context.Background()))
}

func TestGrafanaDriver_Cleanup_NilHTTPClient(t *testing.T) {
	driver := &GrafanaDriver{credSource: &credential.CredSource{Type: credential.SourceTypeGrafana}}
	assert.NoError(t, driver.Cleanup(context.Background()))
}

func TestGrafanaDriver_NotRotatable(t *testing.T) {
	var sd credential.SourceDriver = &GrafanaDriver{credSource: &credential.CredSource{}}
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "GrafanaDriver should not implement credential.Rotatable")
}

func TestGrafanaDriver_GetGrafanaURL(t *testing.T) {
	driver := &GrafanaDriver{
		credSource: &credential.CredSource{
			Config: map[string]string{"grafana_url": "https://mystack.grafana.net/"},
		},
	}
	assert.Equal(t, "https://mystack.grafana.net", driver.getGrafanaURL())
}

// --- Resolving the provisioned account ---

func TestGrafanaDriver_ResolveServiceAccountID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	t.Run("the spec's id wins over the source default", func(t *testing.T) {
		d := grafanaTestDriver(server, map[string]string{"service_account_id": "1"})
		saID, err := d.resolveGrafanaServiceAccountID(grafanaSpec("s", map[string]string{"service_account_id": "42"}))
		require.NoError(t, err)
		assert.Equal(t, "42", saID)
	})

	t.Run("the source default applies when the spec is silent", func(t *testing.T) {
		d := grafanaTestDriver(server, map[string]string{"service_account_id": "7"})
		saID, err := d.resolveGrafanaServiceAccountID(grafanaSpec("s", nil))
		require.NoError(t, err)
		assert.Equal(t, "7", saID)
	})

	t.Run("neither is an error naming the fix", func(t *testing.T) {
		d := grafanaTestDriver(server, nil)
		_, err := d.resolveGrafanaServiceAccountID(grafanaSpec("s", nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account_id is required")
		assert.Contains(t, err.Error(), "it does not create one")
	})

	t.Run("a non-numeric id is refused", func(t *testing.T) {
		d := grafanaTestDriver(server, nil)
		_, err := d.resolveGrafanaServiceAccountID(grafanaSpec("s", map[string]string{"service_account_id": "abc"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "positive integer")
	})
}

// --- Mint ---

func TestGrafanaDriver_MintCredential(t *testing.T) {
	var tokenPath, tokenName string
	var secondsToLive float64
	var createCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tokens") {
			createCalled.Add(1)
			tokenPath = r.URL.Path
			assert.Equal(t, "Bearer glsa_admin", r.Header.Get("Authorization"))

			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			tokenName, _ = body["name"].(string)
			secondsToLive, _ = body["secondsToLive"].(float64)

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 7, "name": tokenName, "key": "glsa_minted_token_123",
			})
			return
		}
		// The sweep's token listing.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	rawData, metadata, ttl, leaseID, err := driver.MintCredential(context.Background(),
		grafanaSpec("dashboards", map[string]string{"service_account_id": "42"}))
	require.NoError(t, err)

	assert.Equal(t, "glsa_minted_token_123", rawData["api_key"])
	assert.Equal(t, grafanaDefaultTokenExpiry, ttl)
	assert.Equal(t, float64(3600), secondsToLive)
	assert.Equal(t, "42:7", leaseID, "the lease names the token, not just the account")
	assert.Equal(t, "/api/serviceaccounts/42/tokens", tokenPath,
		"the token is created on the provisioned account; no account is created")
	assert.Equal(t, int32(1), createCalled.Load())

	// The token name is the only thing distinguishing one lease from another in
	// Grafana's view, so it is recorded.
	assert.Equal(t, "7", metadata["token_id"])
	assert.Equal(t, tokenName, metadata["token_name"])
	assert.Equal(t, "42", metadata["service_account_id"])
	assert.True(t, strings.HasPrefix(tokenName, "warden-dashboards-"), "got %q", tokenName)
}

func TestGrafanaDriver_MintCredential_CustomConfig(t *testing.T) {
	var tokenPath, tokenName string
	var secondsToLive float64

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			tokenPath = r.URL.Path
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			tokenName, _ = body["name"].(string)
			secondsToLive, _ = body["secondsToLive"].(float64)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 9, "key": "glsa_custom"})
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	// A source default the spec overrides.
	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "1"})
	rawData, _, ttl, leaseID, err := driver.MintCredential(context.Background(),
		grafanaSpec("editor", map[string]string{
			"service_account_id": "57",
			"token_expiry":       "30m",
			"name_prefix":        "warden-myprefix-",
		}))
	require.NoError(t, err)

	assert.Equal(t, "glsa_custom", rawData["api_key"])
	assert.Equal(t, 30*time.Minute, ttl)
	assert.Equal(t, float64(1800), secondsToLive)
	assert.Equal(t, "57:9", leaseID)
	assert.Equal(t, "/api/serviceaccounts/57/tokens", tokenPath)
	assert.True(t, strings.HasPrefix(tokenName, "warden-myprefix-editor-"), "got %q", tokenName)
}

func TestGrafanaDriver_MintCredential_NoServiceAccount(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	_, _, _, _, err := driver.MintCredential(context.Background(), grafanaSpec("x", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service_account_id is required")
	assert.Equal(t, int32(0), called.Load(), "nothing should reach Grafana")
}

// Token names are unique per service account, and specs now share one — so two
// mints in the same millisecond must not collide.
func TestGrafanaDriver_MintCredential_TokenNamesAreUnique(t *testing.T) {
	var mu sync.Mutex
	names := map[string]bool{}
	var nextID atomic.Int64

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[]`)
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		name, _ := body["name"].(string)

		mu.Lock()
		duplicate := names[name]
		names[name] = true
		mu.Unlock()

		if duplicate {
			// What Grafana does with a name already on the account: ErrDuplicateToken,
			// an errutil.BadRequest, so 400 and never retryable.
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"messageId":"serviceaccounts.ErrTokenAlreadyExists","message":"service account token with name busy already exists in the organization"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": nextID.Add(1), "key": "glsa_" + name})
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	spec := grafanaSpec("busy", nil)

	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, _, errs[i] = driver.MintCredential(context.Background(), spec)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "mint %d collided on the token name", i)
	}
}

// Creating a token is not idempotent: a retry after a lost response draws Grafana's
// duplicate-name refusal, so the mint reports failure while the first attempt's
// token stands, unknown to Warden and unrevokable until it expires.
func TestGrafanaDriver_MintCredential_CreateNotRetried(t *testing.T) {
	var createCalled atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		createCalled.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"boom"}`))
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, _, _, err := driver.MintCredential(context.Background(), grafanaSpec("x", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create token")
	assert.Equal(t, int32(1), createCalled.Load(), "a 500 on create must not be retried")
}

// Grafana reads secondsToLive=0 as "never expires", and a zero lease TTL reads to
// Warden as a static credential — so a sub-second lifetime must be refused before
// either sees it.
func TestGrafanaDriver_MintCredential_SubSecondExpiryRefused(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	for _, expiry := range []string{"0s", "500ms", "999ms"} {
		t.Run(expiry, func(t *testing.T) {
			_, _, _, _, err := driver.MintCredential(context.Background(),
				grafanaSpec("tiny", map[string]string{"token_expiry": expiry}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "never expires")
		})
	}
	assert.Equal(t, int32(0), called.Load(), "nothing should reach Grafana")
}

// The lease must not outlive the token: Grafana is asked for whole seconds, so the
// TTL Warden records is the truncated value, not the configured one.
func TestGrafanaDriver_MintCredential_LeaseTTLMatchesSecondsToLive(t *testing.T) {
	var secondsToLive float64

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[]`)
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		secondsToLive, _ = body["secondsToLive"].(float64)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 3, "key": "glsa_x"})
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, ttl, _, err := driver.MintCredential(context.Background(),
		grafanaSpec("trunc", map[string]string{"token_expiry": "90s500ms"}))
	require.NoError(t, err)
	assert.Equal(t, float64(90), secondsToLive)
	assert.Equal(t, 90*time.Second, ttl, "the lease must not outlive the token")
}

// A token with no id could never be revoked, so it is refused rather than issued.
func TestGrafanaDriver_MintCredential_NoTokenID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"key": "glsa_orphan"})
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, _, _, err := driver.MintCredential(context.Background(), grafanaSpec("x", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could never be revoked")
}

func TestGrafanaDriver_MintCredential_EmptyTokenKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 5, "key": ""})
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, _, _, err := driver.MintCredential(context.Background(), grafanaSpec("x", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty token key")
}

func TestGrafanaDriver_MintCredential_APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Insufficient permissions"}`))
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, _, _, err := driver.MintCredential(context.Background(), grafanaSpec("x", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create token on service account 42")
}

// The sweep reclaims only names carrying the default prefix, so a spec that
// wandered outside it would mint tokens nothing ever removes — and on a chained
// source, where revocation cannot run either, that is permanent.
func TestGrafanaDriver_MintCredential_NamePrefixMustStayInTheSweptNamespace(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, _, _, err := driver.MintCredential(context.Background(),
		grafanaSpec("x", map[string]string{"name_prefix": "acme-"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must start with")
	assert.Equal(t, int32(0), called.Load(), "nothing should reach Grafana")
}

// GetDuration swallows a parse error and returns the default, so a spec that
// predates the write-time check — or one written with verification skipped —
// would mint an hour while saying sixty of something.
func TestGrafanaDriver_MintCredential_UnparseableExpiryIsRefusedAtMint(t *testing.T) {
	var called atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"service_account_id": "42"})
	_, _, _, _, err := driver.MintCredential(context.Background(),
		grafanaSpec("x", map[string]string{"token_expiry": "60"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a duration")
	assert.Equal(t, int32(0), called.Load(), "nothing should reach Grafana")
}

// A sweep that could not even list has not done its job. Parking the account for
// the full interval would mute it exactly when the thing it compensates for —
// a token the server will not accept — is what just broke.
func TestGrafanaDriver_SweepRetriesSoonerAfterAFailedListing(t *testing.T) {
	var listCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listCalls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	require.False(t, driver.sweepExpiredTokens(context.Background(), "glsa_admin", "42"),
		"a listing that failed must not report success")

	// Now through startSweep, which is what owns the backoff. It stamps the full
	// interval up front to stop a stampede, then brings it back in when the sweep
	// reports failure — so the value read here is the driver's, not this test's.
	driver.startSweep("glsa_admin", "42")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		driver.sweepMu.Lock()
		next, ok := driver.sweepNext["42"]
		driver.sweepMu.Unlock()
		if ok && time.Until(next) <= grafanaSweepRetryInterval {
			return // the failed sweep pulled its own next attempt forward
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a failed sweep left the account parked for the full interval")
}

// --- Revoke ---

// Revocation deletes the one token, leaving the provisioned account and every other
// token on it untouched.
func TestGrafanaDriver_Revoke(t *testing.T) {
	var method, path string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	require.NoError(t, driver.Revoke(context.Background(), "42:7"))
	assert.Equal(t, http.MethodDelete, method)
	assert.Equal(t, "/api/serviceaccounts/42/tokens/7", path,
		"the token is deleted, not the account")
}

func TestGrafanaDriver_Revoke_EmptyLeaseID(t *testing.T) {
	driver := &GrafanaDriver{credSource: &credential.CredSource{Config: map[string]string{}}}
	assert.NoError(t, driver.Revoke(context.Background(), ""))
}

// A token deleted out of band must not fail revocation: an error here sends the
// expiration manager into backoff and then a daily retry, forever, for a request
// that can never succeed.
func TestGrafanaDriver_Revoke_AlreadyGone(t *testing.T) {
	var called atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"token not found"}`))
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	require.NoError(t, driver.Revoke(context.Background(), "42:7"))
	assert.Equal(t, int32(1), called.Load(), "404 is success, and must not be retried")
}

func TestGrafanaDriver_Revoke_APIError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"Internal error"}`))
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	err := driver.Revoke(context.Background(), "42:7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete token")
}

// Both halves reach Revoke from persisted state and are interpolated into a request
// path, so a lease that is not of this shape is refused rather than sent.
func TestGrafanaDriver_Revoke_MalformedLease(t *testing.T) {
	var called atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	for _, lease := range []string{"42", "42:../../admin/users", "abc:7", "42:0"} {
		err := driver.Revoke(context.Background(), lease)
		require.Error(t, err, "lease %q", lease)
		assert.Contains(t, err.Error(), "invalid lease ID")
	}
	assert.Equal(t, int32(0), called.Load(), "nothing should reach Grafana")
}

func TestParseGrafanaLeaseID(t *testing.T) {
	saID, tokenID, err := parseGrafanaLeaseID("42:7")
	require.NoError(t, err)
	assert.Equal(t, "42", saID)
	assert.Equal(t, "7", tokenID)

	for _, lease := range []string{"", "42", "42:", ":7", "abc:7", "42:abc", "42:0", "0:7", "42:7:9"} {
		_, _, err := parseGrafanaLeaseID(lease)
		assert.Error(t, err, "lease %q must not parse", lease)
	}
}

// --- VerifySpec ---

func TestGrafanaDriver_VerifySpec(t *testing.T) {
	var path string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		assert.Equal(t, "Bearer glsa_admin", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": 42, "name": "warden-reader", "role": "Viewer", "isDisabled": false,
		})
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	require.NoError(t, driver.VerifySpec(context.Background(),
		grafanaSpec("x", map[string]string{"service_account_id": "42"})))
	assert.Equal(t, "/api/serviceaccounts/42", path)
}

func TestGrafanaDriver_VerifySpec_MissingAccount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"service account not found"}`))
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	err := driver.VerifySpec(context.Background(),
		grafanaSpec("x", map[string]string{"service_account_id": "999"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service account 999 is not reachable")
}

// A disabled account's tokens do not authenticate, so the spec would mint
// credentials that never work.
func TestGrafanaDriver_VerifySpec_DisabledAccount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": 42, "name": "warden-reader", "role": "Viewer", "isDisabled": true,
		})
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	err := driver.VerifySpec(context.Background(),
		grafanaSpec("x", map[string]string{"service_account_id": "42"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is disabled in Grafana")
}

// Reading an account takes a scope minting a token on it does not, so a
// write-scoped privileged token is legitimate — and the mint that ran just before
// this already proved it works.
func TestGrafanaDriver_VerifySpec_ForbiddenIsAccepted(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"access denied"}`))
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	require.NoError(t, driver.VerifySpec(context.Background(),
		grafanaSpec("x", map[string]string{"service_account_id": "42"})))
}

func TestGrafanaDriver_VerifySpec_NoServiceAccount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	err := driver.VerifySpec(context.Background(), grafanaSpec("x", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service_account_id is required")
}

// --- Sweep ---

// Grafana leaves an expired token listed on the account. The sweep reclaims the
// ones Warden minted, and only those: the account is operator-provisioned and may
// be shared.
func TestGrafanaDriver_SweepExpiredTokens(t *testing.T) {
	var mu sync.Mutex
	var deleted []string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "warden-dashboards-1-aaa", "hasExpired": true},
				{"id": 2, "name": "warden-dashboards-2-bbb", "hasExpired": false},
				{"id": 3, "name": "ci-pipeline-token", "hasExpired": true}, // not ours
				{"id": 4, "name": "warden-editor-3-ccc", "hasExpired": true},
			})
			return
		}
		mu.Lock()
		deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/api/serviceaccounts/42/tokens/"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	driver.sweepExpiredTokens(context.Background(), "glsa_admin", "42")

	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t, []string{"1", "4"}, deleted,
		"only expired tokens Warden minted: not the live one, not the hand-issued one")
}

func TestGrafanaDriver_SweepExpiredTokens_ListFailureIsHarmless(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	assert.NotPanics(t, func() {
		driver.sweepExpiredTokens(context.Background(), "glsa_admin", "42")
	}, "a driver without a logger must not panic on the warn path")
}

// A single timestamp per driver would be spent by whichever spec minted first,
// starving every other account on the same source.
func TestGrafanaDriver_SweepRateLimitIsPerAccount(t *testing.T) {
	var mu sync.Mutex
	var listed []string
	done := make(chan struct{}, 8)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		listed = append(listed, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[]`)
		done <- struct{}{}
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, nil)
	driver.startSweep("glsa_admin", "42")
	driver.startSweep("glsa_admin", "57")
	driver.startSweep("glsa_admin", "42") // inside the interval; must not sweep again

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the sweeps")
		}
	}

	// Settle before concluding. Waiting for exactly two and asserting immediately
	// would pass a rate limiter that merely made the third sweep slower rather
	// than suppressing it.
	select {
	case <-done:
		t.Fatal("a third sweep ran; the repeat for account 42 should have been rate-limited away")
	case <-time.After(time.Second):
	}

	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t,
		[]string{"/api/serviceaccounts/42/tokens", "/api/serviceaccounts/57/tokens"}, listed,
		"each account sweeps once; the repeat for 42 is rate-limited away")
}

func TestIsGrafanaWardenTokenName(t *testing.T) {
	assert.True(t, isGrafanaWardenTokenName("warden-dashboards-123-abc"))
	assert.False(t, isGrafanaWardenTokenName("ci-pipeline-token"))
	assert.False(t, isGrafanaWardenTokenName("my-warden-token"))
}

// --- Credential chaining (keyless source) ---

func TestGrafanaDriverFactory_ValidateConfig_Chained(t *testing.T) {
	factory := &GrafanaDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "secret_spec without admin_token",
			config: map[string]string{
				"grafana_url":               "https://mystack.grafana.net",
				credential.ConfigSecretSpec: "grafana-admin-token",
			},
		},
		{
			name: "secret_spec with the modifiers",
			config: map[string]string{
				"grafana_url":                   "https://mystack.grafana.net",
				"service_account_id":            "42",
				credential.ConfigSecretSpec:     "grafana-admin-token",
				credential.ConfigSecretField:    "admin_token",
				credential.ConfigSecretCacheTTL: "30m",
			},
		},
		{
			// Keeping the token would leave a source that reads as keyless while
			// storing the very secret chaining removes.
			name: "admin_token alongside secret_spec is refused",
			config: map[string]string{
				"grafana_url":               "https://mystack.grafana.net",
				"admin_token":               "glsa_still_here",
				credential.ConfigSecretSpec: "grafana-admin-token",
			},
			wantErr: true,
			errMsg:  "admin_token must be omitted",
		},
		{
			name:    "neither admin_token nor secret_spec is refused",
			config:  map[string]string{"grafana_url": "https://mystack.grafana.net"},
			wantErr: true,
			errMsg:  "admin_token is required unless",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveChainedGrafanaToken(t *testing.T) {
	tests := []struct {
		name     string
		material credential.SecretMaterial
		want     string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "secret_field names the token",
			material: credential.SecretMaterial{Data: map[string]string{"admin_token": "glsa_a", "other": "x"}, Field: "admin_token"},
			want:     "glsa_a",
		},
		{
			name:     "conventional name admin_token",
			material: credential.SecretMaterial{Data: map[string]string{"admin_token": "glsa_b"}},
			want:     "glsa_b",
		},
		{
			name:     "conventional name api_key",
			material: credential.SecretMaterial{Data: map[string]string{"api_key": "glsa_c"}},
			want:     "glsa_c",
		},
		{
			name:     "conventional name token",
			material: credential.SecretMaterial{Data: map[string]string{"token": "glsa_d"}},
			want:     "glsa_d",
		},
		{
			// A field that resolved to nothing is a misconfigured secret_field. Say
			// so, rather than silently authenticating with some other value from the
			// payload — admin_token is present here and must NOT be used.
			name:     "a resolved-to-nothing secret_field does not fall back",
			material: credential.SecretMaterial{Data: map[string]string{"admin_token": "glsa_e"}, Field: "wrong_name"},
			wantErr:  true,
			errMsg:   "is empty or absent",
		},
		{
			name:     "no token at all",
			material: credential.SecretMaterial{Data: map[string]string{"unrelated": "x"}},
			wantErr:  true,
			errMsg:   "no privileged token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveChainedGrafanaToken(tt.material)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGrafanaDriver_MintFromSecret(t *testing.T) {
	var gotAuth, gotPath string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": 31, "key": "glsa_minted"})
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{
		"admin_token":               "", // a chained source holds none
		credential.ConfigSecretSpec: "grafana-admin-token",
	})

	rawData, metadata, ttl, leaseID, err := driver.MintFromSecret(context.Background(),
		grafanaSpec("kv", map[string]string{"service_account_id": "42"}),
		credential.SecretMaterial{Data: map[string]string{"admin_token": "glsa_chained_admin"}})
	require.NoError(t, err)

	assert.Equal(t, "glsa_minted", rawData["api_key"])
	assert.Equal(t, time.Hour, ttl)
	assert.Equal(t, "42:31", leaseID)
	assert.Equal(t, "42", metadata["service_account_id"])
	assert.Equal(t, "/api/serviceaccounts/42/tokens", gotPath)
	assert.Equal(t, "Bearer glsa_chained_admin", gotAuth,
		"the chained token must authenticate, not a stored one")
}

// Routing a chained spec is the minting layer's job. Arriving at MintCredential
// means it was bypassed, and falling through would authenticate with an empty
// token.
func TestGrafanaDriver_MintCredential_RefusesChainedSource(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("nothing should reach Grafana")
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{
		"admin_token":               "",
		credential.ConfigSecretSpec: "grafana-admin-token",
	})

	_, _, _, _, err := driver.MintCredential(context.Background(),
		grafanaSpec("x", map[string]string{"service_account_id": "42"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential chaining")
}

// A fetched token can be stale and worth re-fetching; an inline one cannot, and
// saying so would send it round a loop that cannot change the outcome.
func TestGrafanaDriver_ChainedRejectionMarksSecretStale(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer server.Close()

	spec := grafanaSpec("x", map[string]string{"service_account_id": "42"})

	chained := grafanaTestDriver(server, map[string]string{
		"admin_token":               "",
		credential.ConfigSecretSpec: "grafana-admin-token",
	})
	_, _, _, _, err := chained.MintFromSecret(context.Background(), spec,
		credential.SecretMaterial{Data: map[string]string{"admin_token": "glsa_stale"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)

	inline := grafanaTestDriver(server, nil)
	_, _, _, _, err = inline.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected,
		"an inline source has nothing to evict")
}

// Revocation runs at lease expiry, where a chained source has no caller to fetch
// its privileged token as. An error there would only feed the daily irrevocable
// loop.
func TestGrafanaDriver_Revoke_ChainedIsNoOp(t *testing.T) {
	var called atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{
		"admin_token":               "",
		credential.ConfigSecretSpec: "grafana-admin-token",
	})

	require.NoError(t, driver.Revoke(context.Background(), "42:7"))
	assert.Equal(t, int32(0), called.Load(), "nothing should reach Grafana")

	// A malformed lease is still refused: that check does not depend on a token.
	require.Error(t, driver.Revoke(context.Background(), "42"))
}

func TestGrafanaDriver_VerifySpec_ChainedIsNoOp(t *testing.T) {
	var called atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{
		"admin_token":               "",
		credential.ConfigSecretSpec: "grafana-admin-token",
	})

	require.NoError(t, driver.VerifySpec(context.Background(),
		grafanaSpec("x", map[string]string{"service_account_id": "42"})))
	assert.Equal(t, int32(0), called.Load())
}

// --- Helpers ---

func TestValidateGrafanaServiceAccountID(t *testing.T) {
	for _, v := range []string{"1", "42", "999999"} {
		assert.NoError(t, validateGrafanaServiceAccountID(v), "id %q", v)
	}
	for _, v := range []string{"", "0", "-1", "abc", "4.2", "42 ", "../42"} {
		assert.Error(t, validateGrafanaServiceAccountID(v), "id %q must be refused", v)
	}
}

func TestGrafanaDriver_AuthorizationHeader(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer glsa_my_admin_token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	driver := grafanaTestDriver(server, map[string]string{"admin_token": "glsa_my_admin_token"})
	_, _, err := driver.doGrafanaRequest(context.Background(), driver.getAdminToken(), http.MethodGet, "/api/serviceaccounts/42", nil)
	require.NoError(t, err)
}

func TestValidateGrafanaURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://mystack.grafana.net", false, ""},
		{"https://grafana.example.com", false, ""},
		{"https://logs-prod-us-central1.grafana.net", false, ""},
		{"http://grafana.local", true, "must use https://"},
		{"ftp://grafana.local", true, "must use https://"},
		{"https://", true, "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateGrafanaURL(tt.url, false)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGrafanaURL_TLSSkipVerify(t *testing.T) {
	require.NoError(t, validateGrafanaURL("http://grafana.local", true))
	require.NoError(t, validateGrafanaURL("https://grafana.local", true))
	require.Error(t, validateGrafanaURL("ftp://grafana.local", true))
}

// A chained source cannot revoke, so a token it mints stays live until its own
// expiry however the lease ended. That window is bounded; the inline path, which
// revokes precisely, is not.
func TestGrafanaDriver_ChainedTokenExpiryIsCapped(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 4, "key": "glsa_x"})
	}))
	defer server.Close()

	spec := grafanaSpec("long", map[string]string{
		"service_account_id": "42",
		"token_expiry":       "720h",
	})

	chained := grafanaTestDriver(server, map[string]string{
		"admin_token":               "",
		credential.ConfigSecretSpec: "grafana-admin-token",
	})
	_, _, _, _, err := chained.MintFromSecret(context.Background(), spec,
		credential.SecretMaterial{Data: map[string]string{"admin_token": "glsa_chained"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ceiling for a chained source")

	// The same lifetime is fine inline, where revocation removes the token
	// precisely when the lease ends.
	inline := grafanaTestDriver(server, nil)
	_, _, ttl, _, err := inline.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, 720*time.Hour, ttl)
}
