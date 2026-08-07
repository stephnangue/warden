package drivers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWIFProvider = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden-oidc"

// newFederationDriver builds a keyless GCP driver whose STS and IAM Credentials
// hosts point at the given test servers.
func newFederationDriver(provider, stsHost, iamHost string) *GCPDriver {
	return &GCPDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGCP,
			Config: map[string]string{
				"auth_method":                gcpAuthMethodOIDCFederation,
				"workload_identity_provider": provider,
			},
		},
		httpClient:         &http.Client{},
		tokenCache:         NewTokenCache(),
		stsHost:            stsHost,
		iamCredentialsHost: iamHost,
	}
}

func TestGCPDriverFactory_ValidateConfig_Federation(t *testing.T) {
	f := &GCPDriverFactory{}

	t.Run("missing workload_identity_provider", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{"auth_method": "oidc_federation"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "workload_identity_provider is required")
	})

	t.Run("service_account_key rejected in federation", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
			"service_account_key":        `{"client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be set")
	})

	t.Run("bad provider prefix", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": "https://iam.googleapis.com/projects/123/x",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must start with //iam.googleapis.com/")
	})

	t.Run("valid federation config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
		})
		require.NoError(t, err)
	})

	t.Run("static still requires key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{"auth_method": "static"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account_key is required")
	})

	t.Run("workload_identity_provider rejected on static", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"auth_method":                "static",
			"service_account_key":        `{"client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
			"workload_identity_provider": testWIFProvider,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid for auth_method=oidc_federation")
	})
}

func TestGCPDriverFactory_InferCredentialType_Federation(t *testing.T) {
	f := &GCPDriverFactory{}

	for _, mm := range []string{"", "access_token", "impersonated_access_token"} {
		got, err := f.InferCredentialType(map[string]string{"mint_method": mm})
		require.NoError(t, err, "mint_method=%q", mm)
		assert.Equal(t, credential.TypeGCPAccessToken, got, "mint_method=%q", mm)
	}

	got, err := f.InferCredentialType(map[string]string{"mint_method": "cloud_sql_iam_token"})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeDBAuthToken, got)

	_, err = f.InferCredentialType(map[string]string{"mint_method": "bogus"})
	require.Error(t, err)
}

func TestGCPDriver_SupportsRotation_ByAuthMethod(t *testing.T) {
	fed := newFederationDriver(testWIFProvider, "", "")
	assert.False(t, fed.SupportsRotation(), "federation source has no key to rotate")

	static := &GCPDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeGCP,
		Config: map[string]string{"auth_method": "static"},
	}}
	assert.True(t, static.SupportsRotation())
}

func TestGCPDriver_MintCredential_FederationFailsClosed(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "access_token"}}
	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_source")
}

func TestGCPDriver_MintCredentialWithExchange_RejectsStaticSource(t *testing.T) {
	d := &GCPDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeGCP,
		Config: map[string]string{"auth_method": "static"},
	}}
	inputs := &credential.ExchangeInputs{SubjectToken: "tok", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "access_token"}}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=oidc_federation")
}

func TestGCPDriver_MintCredentialWithExchange_RejectsUnverified(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	inputs := &credential.ExchangeInputs{SubjectToken: "tok", SubjectTokenOrigin: credential.ExchangeOriginUnverified}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "access_token"}}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verified subject")
}

func TestGCPDriver_ExchangeWIFToken(t *testing.T) {
	t.Run("form params and ttl", func(t *testing.T) {
		var gotForm map[string]string
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			gotForm = map[string]string{
				"grant_type":           r.PostForm.Get("grant_type"),
				"audience":             r.PostForm.Get("audience"),
				"scope":                r.PostForm.Get("scope"),
				"requested_token_type": r.PostForm.Get("requested_token_type"),
				"subject_token_type":   r.PostForm.Get("subject_token_type"),
				"subject_token":        r.PostForm.Get("subject_token"),
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":1800,"token_type":"Bearer"}`))
		}))
		defer sts.Close()

		d := newFederationDriver(testWIFProvider, sts.URL, "")
		tok, ttl, err := d.exchangeWIFToken(context.TODO(), "SUBJECT-JWT", "", "https://www.googleapis.com/auth/cloud-platform")
		require.NoError(t, err)
		assert.Equal(t, "FED-TOKEN", tok)
		assert.Equal(t, 1800*time.Second, ttl)

		assert.Equal(t, gcpTokenExchangeGrantType, gotForm["grant_type"])
		assert.Equal(t, testWIFProvider, gotForm["audience"])
		assert.Equal(t, credential.TokenTypeAccessToken, gotForm["requested_token_type"])
		assert.Equal(t, credential.TokenTypeJWT, gotForm["subject_token_type"], "empty type defaults to jwt")
		assert.Equal(t, "SUBJECT-JWT", gotForm["subject_token"])
	})

	t.Run("subject_token_type forwarded", func(t *testing.T) {
		var gotType string
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			gotType = r.PostForm.Get("subject_token_type")
			_, _ = w.Write([]byte(`{"access_token":"t","expires_in":10}`))
		}))
		defer sts.Close()
		d := newFederationDriver(testWIFProvider, sts.URL, "")
		_, _, err := d.exchangeWIFToken(context.TODO(), "jwt", credential.TokenTypeIDToken, "scope")
		require.NoError(t, err)
		assert.Equal(t, credential.TokenTypeIDToken, gotType)
	})

	t.Run("missing expires_in falls back", func(t *testing.T) {
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"t"}`))
		}))
		defer sts.Close()
		d := newFederationDriver(testWIFProvider, sts.URL, "")
		_, ttl, err := d.exchangeWIFToken(context.TODO(), "jwt", "", "scope")
		require.NoError(t, err)
		assert.Equal(t, gcpFederatedTokenFallbackTTL, ttl)
	})

	t.Run("comma-separated scope normalized to space list", func(t *testing.T) {
		var gotScope string
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			gotScope = r.PostForm.Get("scope")
			_, _ = w.Write([]byte(`{"access_token":"t","expires_in":10}`))
		}))
		defer sts.Close()
		d := newFederationDriver(testWIFProvider, sts.URL, "")
		_, _, err := d.exchangeWIFToken(context.TODO(), "jwt", "",
			"https://www.googleapis.com/auth/bigquery, https://www.googleapis.com/auth/devstorage.read_only")
		require.NoError(t, err)
		assert.Equal(t, "https://www.googleapis.com/auth/bigquery https://www.googleapis.com/auth/devstorage.read_only", gotScope)
	})

	t.Run("STS error status propagates", func(t *testing.T) {
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"audience mismatch"}`))
		}))
		defer sts.Close()
		d := newFederationDriver(testWIFProvider, sts.URL, "")
		_, _, err := d.exchangeWIFToken(context.TODO(), "jwt", "", "scope")
		require.Error(t, err)
	})
}

func TestGCPDriver_MintCredentialWithExchange_Impersonation(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":3600}`))
	}))
	defer sts.Close()

	var gotAuth, gotPath string
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"IMPERSONATED-TOKEN","expireTime":"2099-01-01T00:00:00Z"}`))
	}))
	defer iam.Close()

	d := newFederationDriver(testWIFProvider, sts.URL, iam.URL)
	inputs := &credential.ExchangeInputs{SubjectToken: "SUBJECT-JWT", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	spec := &credential.CredSpec{
		Name:   "s",
		MaxTTL: 24 * time.Hour,
		Config: map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "bq@proj.iam.gserviceaccount.com",
			"lifetime":               "1800s",
		},
	}

	raw, meta, ttl, lease, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "IMPERSONATED-TOKEN", raw["access_token"])
	assert.Empty(t, lease, "GCP tokens are irrevocable, no lease")
	assert.Greater(t, ttl, time.Duration(0))
	assert.Equal(t, "bq@proj.iam.gserviceaccount.com", meta["subject"])

	// The bearer on the impersonation call must be the WIF-federated token, not any
	// source-SA token.
	assert.Equal(t, "Bearer FED-TOKEN", gotAuth)
	assert.True(t, strings.HasSuffix(gotPath, ":generateAccessToken"), "path was %q", gotPath)
}

func TestGCPDriver_MintCredentialWithExchange_ImpersonationIAMError(t *testing.T) {
	// STS leg succeeds, but the generateAccessToken leg denies the impersonation.
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":3600}`))
	}))
	defer sts.Close()
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"permission denied on workloadIdentityUser"}}`))
	}))
	defer iam.Close()

	d := newFederationDriver(testWIFProvider, sts.URL, iam.URL)
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	spec := &credential.CredSpec{Name: "s", MaxTTL: time.Hour, Config: map[string]string{
		"mint_method":            "impersonated_access_token",
		"target_service_account": "bq@proj.iam.gserviceaccount.com",
	}}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
}

func TestGCPDriver_MintCredentialWithExchange_ImpersonationLifetimeBounds(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	spec := &credential.CredSpec{
		Name:   "s",
		MaxTTL: 15 * time.Minute,
		Config: map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "bq@proj.iam.gserviceaccount.com",
			"lifetime":               "3600s", // exceeds MaxTTL
		},
	}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the spec maximum")
}

func TestGCPDriver_MintCredentialWithExchange_Federated_TTLCap(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":3600}`)) // 1h
	}))
	defer sts.Close()

	d := newFederationDriver(testWIFProvider, sts.URL, "")
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	spec := &credential.CredSpec{
		Name:   "s",
		MaxTTL: 15 * time.Minute,
		Config: map[string]string{"mint_method": "access_token"},
	}

	raw, _, ttl, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "FED-TOKEN", raw["access_token"])
	assert.Equal(t, 15*time.Minute, ttl, "lease TTL capped at MaxTTL")
}

func TestGCPDriver_MintCredentialWithExchange_DefaultsToAccessToken(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":3600}`))
	}))
	defer sts.Close()

	d := newFederationDriver(testWIFProvider, sts.URL, "")
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	// No mint_method set: federation defaults to access_token (the federated token itself).
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{}}

	raw, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "FED-TOKEN", raw["access_token"])
}

func TestGCPDriver_MintCredentialWithExchange_UnsupportedMethod(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt", SubjectTokenOrigin: credential.ExchangeOriginVerified}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "impersonated_service_account"}}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")
}

func TestGCPAssertionResource(t *testing.T) {
	t.Run("impersonation from spec", func(t *testing.T) {
		res, ok := gcpAssertionResource(
			map[string]string{"workload_identity_provider": testWIFProvider},
			map[string]string{"mint_method": "impersonated_access_token", "target_service_account": "bq@proj.iam.gserviceaccount.com"},
		)
		assert.True(t, ok)
		assert.Equal(t, "gcp-iam:bq@proj.iam.gserviceaccount.com", res)
	})

	t.Run("federated from source", func(t *testing.T) {
		res, ok := gcpAssertionResource(
			map[string]string{"workload_identity_provider": testWIFProvider},
			map[string]string{"mint_method": "access_token"},
		)
		assert.True(t, ok)
		assert.Equal(t, "gcp-wif:"+testWIFProvider, res)
	})

	t.Run("routed via DeriveAssertionResource", func(t *testing.T) {
		res, ok := DeriveAssertionResource(credential.SourceTypeGCP,
			map[string]string{"workload_identity_provider": testWIFProvider},
			map[string]string{"mint_method": "access_token"},
		)
		assert.True(t, ok)
		assert.Equal(t, "gcp-wif:"+testWIFProvider, res)
	})

	t.Run("no resource when unset", func(t *testing.T) {
		_, ok := gcpAssertionResource(map[string]string{}, map[string]string{"mint_method": "access_token"})
		assert.False(t, ok)
	})
}

func TestGCPAssertionAudience(t *testing.T) {
	t.Run("derives https form from provider", func(t *testing.T) {
		aud, ok := gcpAssertionAudience(map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": testWIFProvider})
		require.True(t, ok)
		assert.Equal(t, "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden-oidc", aud)
	})

	t.Run("routed via DeriveAssertionAudience", func(t *testing.T) {
		aud, ok := DeriveAssertionAudience(credential.SourceTypeGCP,
			map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": testWIFProvider}, map[string]string{})
		require.True(t, ok)
		assert.Equal(t, "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden-oidc", aud)
	})

	t.Run("only the leading slashes are swapped", func(t *testing.T) {
		// A path segment that itself contains "//" must survive intact.
		aud, ok := gcpAssertionAudience(map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": "//iam.googleapis.com/a//b"})
		require.True(t, ok)
		assert.Equal(t, "https://iam.googleapis.com/a//b", aud)
	})

	t.Run("empty provider yields no audience", func(t *testing.T) {
		_, ok := gcpAssertionAudience(map[string]string{"auth_method": "oidc_federation"})
		assert.False(t, ok)
	})

	t.Run("static source yields no audience even with a provider set", func(t *testing.T) {
		_, ok := gcpAssertionAudience(map[string]string{"auth_method": "static", "workload_identity_provider": testWIFProvider})
		assert.False(t, ok)
	})

	t.Run("non-gcp source returns false", func(t *testing.T) {
		_, ok := DeriveAssertionAudience(credential.SourceTypeAWS, map[string]string{}, map[string]string{})
		assert.False(t, ok)
	})
}
