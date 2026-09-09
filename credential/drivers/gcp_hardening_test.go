package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The GCP driver carried a set of defects that survived because the paths holding
// them had no coverage at all: the two static mint methods were never driven end to
// end, and the two service-account key calls rotation makes had none whatsoever. The
// rows here pin each fix at the level the bug lived at.

func TestSplitScopes(t *testing.T) {
	// A blank scope reaches the token grant as a scope and is rejected there, while
	// reading as "no scopes" in every log on the way. A space-separated list is the
	// form Google's own documentation uses, and silently became one bogus scope.
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"empty yields nothing", "", []string{}},
		{"only separators yields nothing", " , , ", []string{}},
		{"trailing comma dropped", "a,b,", []string{"a", "b"}},
		{"surrounding space trimmed", " a , b ", []string{"a", "b"}},
		{"space separated", "a b", []string{"a", "b"}},
		{"mixed separators", "a, b c", []string{"a", "b", "c"}},
		{"single", gcpCloudPlatformScope, []string{gcpCloudPlatformScope}},
		{"comma separated pair", "https://www.googleapis.com/auth/compute, https://www.googleapis.com/auth/devstorage.read_only",
			[]string{"https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitScopes(tc.in))
		})
	}
}

func TestBase64Decode_AcceptsEveryProto3Encoding(t *testing.T) {
	payload := []byte(`{"type":"service_account"}?~`)

	for name, encoded := range map[string]string{
		"standard":     base64.StdEncoding.EncodeToString(payload),
		"url safe":     base64.URLEncoding.EncodeToString(payload),
		"raw standard": base64.RawStdEncoding.EncodeToString(payload),
		"raw url safe": base64.RawURLEncoding.EncodeToString(payload),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := base64Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, payload, got)
		})
	}

	t.Run("still reports a real failure", func(t *testing.T) {
		_, err := base64Decode("!!!not base64!!!")
		require.Error(t, err)
	})
}

// The lifetime string is forwarded verbatim to a protobuf Duration field, which
// accepts only seconds. Go's duration parser accepts a great deal more, so a value
// like "1h" used to validate locally and then be rejected by the API on every mint.
func TestValidateGCPLifetime(t *testing.T) {
	spec := &credential.CredSpec{Name: "s"}

	t.Run("accepts the seconds form", func(t *testing.T) {
		got, err := validateGCPLifetime(spec, "1800s")
		require.NoError(t, err)
		assert.Equal(t, 30*time.Minute, got)
	})

	for _, bad := range []string{"1h", "30m", "0s", "-10s", "", "3600", "1.5h"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			_, err := validateGCPLifetime(spec, bad)
			require.Errorf(t, err, "lifetime %q must be refused", bad)
		})
	}

	t.Run("rejects beyond the API ceiling", func(t *testing.T) {
		_, err := validateGCPLifetime(spec, "50000s")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum")
	})

	t.Run("honours the spec bounds", func(t *testing.T) {
		bounded := &credential.CredSpec{Name: "s", MinTTL: 10 * time.Minute, MaxTTL: 20 * time.Minute}
		_, err := validateGCPLifetime(bounded, "60s")
		require.Error(t, err)
		_, err = validateGCPLifetime(bounded, "3600s")
		require.Error(t, err)
		_, err = validateGCPLifetime(bounded, "900s")
		require.NoError(t, err)
	})
}

// A fixed fallback here handed out a lease outliving the token: a spec asking for
// 600s was served a dead token from cache for the remaining 50 minutes of an hour.
func TestImpersonationTTL(t *testing.T) {
	spec := &credential.CredSpec{Name: "s"}

	t.Run("expireTime wins when present", func(t *testing.T) {
		exp := time.Now().Add(25 * time.Minute).UTC().Format(time.RFC3339)
		got := impersonationTTL(exp, 10*time.Minute, spec)
		assert.InDelta(t, (25 * time.Minute).Seconds(), got.Seconds(), 5)
	})

	t.Run("falls back to what was requested, not a constant", func(t *testing.T) {
		assert.Equal(t, 10*time.Minute, impersonationTTL("", 10*time.Minute, spec))
		assert.Equal(t, 10*time.Minute, impersonationTTL("not-a-timestamp", 10*time.Minute, spec))
	})

	t.Run("capped by MaxTTL", func(t *testing.T) {
		bounded := &credential.CredSpec{Name: "s", MaxTTL: 5 * time.Minute}
		assert.Equal(t, 5*time.Minute, impersonationTTL("", 10*time.Minute, bounded))
	})
}

func TestGCPDriverFactory_EndpointOverrides(t *testing.T) {
	f := &GCPDriverFactory{}

	t.Run("rejected on a static source", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":         "static",
			"service_account_key": `{"type":"service_account","project_id":"p","private_key_id":"kid","client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
			"sts_endpoint":        "https://sts.example",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid for auth_method=oidc_federation")
	})

	t.Run("accepted on a federation source", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
			"sts_endpoint":               "http://127.0.0.1:1234",
			"iamcredentials_endpoint":    "http://127.0.0.1:1234",
		}))
		require.NoError(t, err)
	})

	t.Run("malformed endpoint refused", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
			"sts_endpoint":               "not-a-url",
		}))
		require.Error(t, err)
	})

	// Rotation acts on the real project through IAM, which has no override, so a
	// source whose impersonation is redirected cannot also be rotated.
	t.Run("rotation refused alongside an impersonation override", func(t *testing.T) {
		err := f.ValidateRotationConfig(credential.NewConfig(map[string]string{
			"iamcredentials_endpoint": "http://127.0.0.1:1234",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotation_period")

		require.NoError(t, f.ValidateRotationConfig(credential.NewConfig(map[string]string{})))
	})
}

// newStaticGCPDriver builds a static-auth driver whose token grant and IAM calls both
// reach the given server.
func newStaticGCPDriver(t *testing.T, srvURL, keyJSON string) *GCPDriver {
	t.Helper()
	return &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: credential.NewConfig(map[string]string{"service_account_key": keyJSON}),
		},
		tokenCache:         NewTokenCache(),
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		stsHost:            srvURL,
		iamCredentialsHost: srvURL,
		iamHost:            srvURL,
	}
}

// tokenGrantServer answers the OAuth2 JWT-bearer grant the static path makes, with a
// caller-chosen expires_in so the lease arithmetic can be driven.
func tokenGrantServer(t *testing.T, expiresIn int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{"access_token": "static-token", "token_type": "Bearer"}
		if expiresIn > 0 {
			body["expires_in"] = expiresIn
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGCPDriver_MintAccessToken_Static(t *testing.T) {
	// The credential vended here is the source service account's own token, shared by
	// everyone asking for the same scopes. Defaulting it to cloud-platform handed out
	// the source's full authority — including, on a rotation-enabled source, the
	// ability to mint a replacement key for Warden's own identity.
	t.Run("scopes are required", func(t *testing.T) {
		srv := tokenGrantServer(t, 3600)
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, _, _, err := d.mintAccessToken(context.TODO(),
			&credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{})})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scopes")
	})

	t.Run("lease capped by MaxTTL", func(t *testing.T) {
		srv := tokenGrantServer(t, 3600)
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, ttl, _, err := d.mintAccessToken(context.TODO(), &credential.CredSpec{
			Name:   "s",
			MaxTTL: 5 * time.Minute,
			Config: credential.NewConfig(map[string]string{"scopes": "https://www.googleapis.com/auth/devstorage.read_only"}),
		})
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, ttl, "an hour-long token must not outlive the spec's ceiling")
	})

	t.Run("unbounded spec keeps the token's own life", func(t *testing.T) {
		srv := tokenGrantServer(t, 3600)
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, ttl, leaseID, err := d.mintAccessToken(context.TODO(), &credential.CredSpec{
			Name:   "s",
			Config: credential.NewConfig(map[string]string{"scopes": "https://www.googleapis.com/auth/devstorage.read_only"}),
		})
		require.NoError(t, err)
		assert.InDelta(t, time.Hour.Seconds(), ttl.Seconds(), 30)
		assert.Empty(t, leaseID, "an access token expires naturally and carries no lease")
	})

	// Without expires_in the library leaves Expiry at the zero time, so the lease was
	// hugely negative. The manager then cached a credential already expired on
	// arrival, and every single request re-minted.
	t.Run("a grant with no expiry is refused, not cached", func(t *testing.T) {
		srv := tokenGrantServer(t, 0)
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, _, _, err := d.mintAccessToken(context.TODO(), &credential.CredSpec{
			Name:   "s",
			Config: credential.NewConfig(map[string]string{"scopes": "https://www.googleapis.com/auth/devstorage.read_only"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expiry")
	})
}

// gcpAssertionScope reads the scope claim out of the signed JWT the oauth2 library
// sends for a service-account grant, so a test server can tell what a token was
// actually asked to authorize.
func gcpAssertionScope(t *testing.T, r *http.Request) string {
	t.Helper()
	require.NoError(t, r.ParseForm())

	parts := strings.Split(r.FormValue("assertion"), ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims struct {
		Scope string `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Scope
}

// impersonationServer answers both the token grant and generateAccessToken, recording
// the scopes the impersonation call was authorized with.
type impersonationServer struct {
	*httptest.Server
	authScopes atomic.Value // string: the scope of the source token grant
	expireTime string
}

func newImpersonationServer(t *testing.T, expireTime string) *impersonationServer {
	t.Helper()
	s := &impersonationServer{expireTime: expireTime}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, ":generateAccessToken") {
			body := map[string]string{"accessToken": "impersonated-token"}
			if s.expireTime != "" {
				body["expireTime"] = s.expireTime
			}
			_ = json.NewEncoder(w).Encode(body)
			return
		}

		// The JWT-bearer grant carries the requested scope inside the signed
		// assertion, not as a form field.
		s.authScopes.Store(gcpAssertionScope(t, r))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "source-token", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	t.Cleanup(s.Close)
	return s
}

func TestGCPDriver_MintImpersonatedAccessToken_Static(t *testing.T) {
	specCfg := func(extra map[string]string) credential.Config {
		cfg := map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "bq@test-project.iam.gserviceaccount.com",
		}
		for k, v := range extra {
			cfg[k] = v
		}
		return credential.NewConfig(cfg)
	}

	t.Run("rejects a lifetime the API would reject", func(t *testing.T) {
		srv := newImpersonationServer(t, "")
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, _, _, err := d.mintImpersonatedAccessToken(context.TODO(),
			&credential.CredSpec{Name: "s", Config: specCfg(map[string]string{"lifetime": "1h"})})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "lifetime")
	})

	t.Run("rejects a lifetime outside the spec bounds", func(t *testing.T) {
		srv := newImpersonationServer(t, "")
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, _, _, err := d.mintImpersonatedAccessToken(context.TODO(), &credential.CredSpec{
			Name: "s", MaxTTL: 5 * time.Minute, Config: specCfg(map[string]string{"lifetime": "3600s"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum")
	})

	// The federated path authorizes the identical generateAccessToken call with
	// cloud-platform; the static one asked for a different scope entirely.
	t.Run("authorizes with cloud-platform", func(t *testing.T) {
		srv := newImpersonationServer(t, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, _, _, err := d.mintImpersonatedAccessToken(context.TODO(),
			&credential.CredSpec{Name: "s", Config: specCfg(nil)})
		require.NoError(t, err)
		assert.Equal(t, gcpCloudPlatformScope, srv.authScopes.Load())
	})

	// No expireTime in the response used to mean a flat one-hour lease regardless of
	// what was asked for, so a 600s token was served from cache long after it died.
	t.Run("lease follows the requested lifetime when expireTime is absent", func(t *testing.T) {
		srv := newImpersonationServer(t, "")
		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, ttl, _, err := d.mintImpersonatedAccessToken(context.TODO(),
			&credential.CredSpec{Name: "s", Config: specCfg(map[string]string{"lifetime": "600s"})})
		require.NoError(t, err)
		assert.Equal(t, 10*time.Minute, ttl)
	})
}

func TestGCPDriver_Cleanup_ClosesIdleConnections(t *testing.T) {
	d := &GCPDriver{httpClient: &http.Client{}}
	require.NoError(t, d.Cleanup(context.TODO()))

	// A driver built without a client (as several tests do) must not panic.
	bare := &GCPDriver{}
	require.NoError(t, bare.Cleanup(context.TODO()))
}

func TestGCPDriver_GetSourceToken_HonoursCancellation(t *testing.T) {
	srv := tokenGrantServer(t, 3600)
	d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := d.getSourceToken(ctx, []string{gcpCloudPlatformScope})
	require.Error(t, err, "a cancelled request must not spin on the generation race")
}

// doGCPRequest retried nothing at all: its retryable-status list was empty and every
// caller asked for a single attempt. GCP answers 429 on the service-account key quota
// and 5xx under load, so one transient answer failed a mint outright.
func TestGCPDriver_RetriesTransientStatuses(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"FED","expires_in":1800,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	d := newFederationDriver(testWIFProvider, srv.URL, "")
	tok, _, err := d.exchangeWIFToken(context.TODO(), "jwt", "", gcpCloudPlatformScope)
	require.NoError(t, err)
	assert.Equal(t, "FED", tok)
	assert.EqualValues(t, 2, atomic.LoadInt32(&calls), "the 429 must have been retried")

	t.Run("a client error is not retried", func(t *testing.T) {
		var bad int32
		badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&bad, 1)
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer badSrv.Close()

		bd := newFederationDriver(testWIFProvider, badSrv.URL, "")
		_, _, err := bd.exchangeWIFToken(context.TODO(), "jwt", "", gcpCloudPlatformScope)
		require.Error(t, err)
		assert.EqualValues(t, 1, atomic.LoadInt32(&bad))
	})
}

// rotationServer stands in for the IAM key-management API and the token grant. These
// two calls had no coverage whatsoever, which is why they hardcoded their host.
type rotationServer struct {
	*httptest.Server

	newKeyUsable atomic.Bool
	created      atomic.Int32
	deleted      atomic.Value // string: the last key id deleted
	deleteIssuer atomic.Value // string: client_email of the key that authorized the delete
	newKeyJSON   string
}

func newRotationServer(t *testing.T, newKeyEmail string) *rotationServer {
	t.Helper()
	s := &rotationServer{}
	s.newKeyUsable.Store(true)

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		issuer := gcpAssertionIssuer(t, r)
		// The new key is refused until the test says it has propagated, which is what
		// PrepareRotation's verification waits out.
		if issuer == newKeyEmail && !s.newKeyUsable.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
			return
		}
		s.deleteIssuer.Store(issuer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "iam-token-" + issuer, "token_type": "Bearer", "expires_in": 3600,
		})
	})

	mux.HandleFunc("/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			s.created.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"privateKeyData": base64.StdEncoding.EncodeToString([]byte(s.newKeyJSON)),
			})
		case http.MethodDelete:
			parts := strings.Split(r.URL.Path, "/keys/")
			s.deleted.Store(parts[len(parts)-1])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestGCPDriver_PrepareRotation(t *testing.T) {
	const (
		oldEmail = "old@test-project.iam.gserviceaccount.com"
		newEmail = "new@test-project.iam.gserviceaccount.com"
	)

	t.Run("carries the retired key on the cleanup handle", func(t *testing.T) {
		srv := newRotationServer(t, newEmail)
		oldKey := newTestGCPSAKeyWithID(t, srv.URL+"/token", oldEmail, "old-key-id")
		srv.newKeyJSON = newTestGCPSAKeyWithID(t, srv.URL+"/token", newEmail, "new-key-id")

		d := newStaticGCPDriver(t, srv.URL, oldKey)
		newConfig, cleanupConfig, _, err := d.PrepareRotation(context.TODO())
		require.NoError(t, err)

		assert.Equal(t, srv.newKeyJSON, newConfig["service_account_key"])
		assert.Equal(t, "old-key-id", cleanupConfig["old_key_id"])
		assert.Equal(t, oldKey, cleanupConfig["old_service_account_key"],
			"cleanup must be able to authenticate as the key it deletes")
	})

	// The rotation manager persists the returned config before CommitRotation ever
	// runs, so a key that never works is already the source's stored credential by
	// the time anything notices — and the created key counts against a quota of ten.
	t.Run("deletes a key that never becomes usable", func(t *testing.T) {
		srv := newRotationServer(t, newEmail)
		srv.newKeyUsable.Store(false)
		srv.newKeyJSON = newTestGCPSAKeyWithID(t, srv.URL+"/token", newEmail, "new-key-id")

		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKeyWithID(t, srv.URL+"/token", oldEmail, "old-key-id"))

		// Shorten the window so the test does not sit through the real one.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_, _, _, err := d.PrepareRotation(ctx)
		require.Error(t, err)
		assert.EqualValues(t, 1, srv.created.Load())
		assert.Equal(t, "new-key-id", srv.deleted.Load(),
			"the unusable key must be reclaimed, or repeated failures exhaust the ten-key quota")
	})

	t.Run("a key that becomes usable after a delay is kept", func(t *testing.T) {
		srv := newRotationServer(t, newEmail)
		srv.newKeyUsable.Store(false)
		srv.newKeyJSON = newTestGCPSAKeyWithID(t, srv.URL+"/token", newEmail, "new-key-id")

		d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKeyWithID(t, srv.URL+"/token", oldEmail, "old-key-id"))

		go func() {
			time.Sleep(1500 * time.Millisecond)
			srv.newKeyUsable.Store(true)
		}()

		newConfig, _, _, err := d.PrepareRotation(context.TODO())
		require.NoError(t, err, "propagation delay must not be mistaken for a bad key")
		assert.Equal(t, srv.newKeyJSON, newConfig["service_account_key"])
		assert.Empty(t, srv.deleted.Load(), "a key that came good must not be deleted")
	})
}

func TestGCPDriver_CommitRotation_ProbesBeforePublishing(t *testing.T) {
	srv := tokenGrantServer(t, 3600)
	goodKey := newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com")
	d := newStaticGCPDriver(t, srv.URL, goodKey)

	// A key whose grant endpoint answers nothing usable.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer dead.Close()
	badKey := newTestGCPSAKey(t, dead.URL+"/token", "broken@test-project.iam.gserviceaccount.com")

	err := d.CommitRotation(context.TODO(), map[string]string{"service_account_key": badKey})
	require.Error(t, err)
	assert.Equal(t, goodKey, d.getServiceAccountKey(),
		"a failed commit must leave the working key in place, not publish the broken one")
}

func TestGCPDriver_CleanupRotation_AuthenticatesAsTheRetiredKey(t *testing.T) {
	const (
		oldEmail = "old@test-project.iam.gserviceaccount.com"
		newEmail = "new@test-project.iam.gserviceaccount.com"
	)

	srv := newRotationServer(t, newEmail)
	oldKey := newTestGCPSAKeyWithID(t, srv.URL+"/token", oldEmail, "old-key-id")

	// The driver already holds the new key, as it would after a commit.
	d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKeyWithID(t, srv.URL+"/token", newEmail, "new-key-id"))

	require.NoError(t, d.CleanupRotation(context.TODO(), map[string]string{
		"old_key_id":              "old-key-id",
		"service_account_email":   oldEmail,
		"project_id":              "test-project",
		"old_service_account_key": oldKey,
	}))

	assert.Equal(t, "old-key-id", srv.deleted.Load())
	// The newly published key is the one whose public half may not have propagated;
	// the retired key has been known to every replica for as long as it existed.
	assert.Equal(t, oldEmail, srv.deleteIssuer.Load(),
		"the deletion must authenticate as the key being deleted")
}

func TestGCPDriver_CleanupRotation_FallsBackForOlderHandles(t *testing.T) {
	const newEmail = "new@test-project.iam.gserviceaccount.com"

	srv := newRotationServer(t, newEmail)
	d := newStaticGCPDriver(t, srv.URL, newTestGCPSAKeyWithID(t, srv.URL+"/token", newEmail, "new-key-id"))

	// A handle written before the retired key travelled with it.
	require.NoError(t, d.CleanupRotation(context.TODO(), map[string]string{
		"old_key_id":            "old-key-id",
		"service_account_email": "old@test-project.iam.gserviceaccount.com",
		"project_id":            "test-project",
	}))

	assert.Equal(t, "old-key-id", srv.deleted.Load())
	assert.Equal(t, newEmail, srv.deleteIssuer.Load(), "falls back to the live credential")
}

func TestGCPDriver_CreateServiceAccountKey_RejectsUnusableMaterial(t *testing.T) {
	for name, payload := range map[string]string{
		"null":      `null`,
		"empty":     `{}`,
		"truncated": `{"type":"service_account","project_id":"p"}`,
		"wrong type": `{"type":"external_account","project_id":"p","private_key_id":"k",` +
			`"client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"privateKeyData": base64.StdEncoding.EncodeToString([]byte(payload)),
				})
			}))
			defer srv.Close()

			d := &GCPDriver{httpClient: &http.Client{Timeout: 5 * time.Second}, iamHost: srv.URL}
			_, err := d.createServiceAccountKey(context.TODO(), "tok", "sa@p.iam.gserviceaccount.com", "p")
			require.Error(t, err, "%s would otherwise be stored as the source credential", name)
		})
	}

	t.Run("a key missing its project cannot be addressed", func(t *testing.T) {
		d := &GCPDriver{httpClient: &http.Client{}, iamHost: "http://127.0.0.1:1"}
		_, err := d.createServiceAccountKey(context.TODO(), "tok", "sa@p.iam.gserviceaccount.com", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project_id")
	})
}

// The driver's HTTP client carries ca_data, tls_skip_verify and the request timeout.
// The OAuth2 token grant used to run on http.DefaultClient instead, so all three were
// silently ignored on every static-auth mint.
func TestGCPDriver_TokenGrantUsesTheConfiguredClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	keyJSON := newTestGCPSAKey(t, srv.URL+"/token", "sa@test-project.iam.gserviceaccount.com")

	t.Run("a client trusting the server succeeds", func(t *testing.T) {
		d := newStaticGCPDriver(t, srv.URL, keyJSON)
		d.httpClient = srv.Client() // carries the test CA, as ca_data would
		_, _, err := d.acquireToken(context.TODO(), []string{gcpCloudPlatformScope})
		require.NoError(t, err)
	})

	t.Run("a client that does not trust it fails", func(t *testing.T) {
		d := newStaticGCPDriver(t, srv.URL, keyJSON)
		d.httpClient = &http.Client{Timeout: 5 * time.Second}
		_, _, err := d.acquireToken(context.TODO(), []string{gcpCloudPlatformScope})
		require.Error(t, err, "the driver's client must be the one making the grant")
		assert.Contains(t, strings.ToLower(err.Error()), "certificate")
	})
}

// The library dispatches on the document's own "type", so an external_account names a
// file or URL for it to fetch. Refused at the grant as well as at config validation:
// a key can reach here from storage written before the validator tightened.
func TestGCPDriver_TokenGrantRefusesForeignCredentialTypes(t *testing.T) {
	d := &GCPDriver{httpClient: &http.Client{Timeout: 5 * time.Second}}

	external := fmt.Sprintf(`{"type":"external_account","audience":"//x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"%s","credential_source":{"file":"/etc/passwd"}}`, "http://127.0.0.1:1/token")

	_, _, err := d.tokenFromKeyJSON(context.TODO(), external, []string{gcpCloudPlatformScope})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "/etc/passwd", "the document must be refused before anything it names is read")
}
