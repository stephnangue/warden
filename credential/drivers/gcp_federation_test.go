package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

const testWIFProvider = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden-oidc"

// newFederationDriver builds a keyless GCP driver whose STS and IAM Credentials
// hosts point at the given test servers.
func newFederationDriver(provider, stsHost, iamHost string) *GCPDriver {
	return &GCPDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeGCP,
			Config: credential.NewConfig(map[string]string{
				"auth_method":                gcpAuthMethodOIDCFederation,
				"workload_identity_provider": provider,
			}),
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
		err := f.ValidateConfig(credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "workload_identity_provider is required")
	})

	t.Run("service_account_key rejected in federation", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
			"service_account_key":        `{"type":"service_account","project_id":"p","private_key_id":"kid","client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be set")
	})

	t.Run("bad provider prefix", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": "https://iam.googleapis.com/projects/123/x",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must start with //iam.googleapis.com/")
	})

	t.Run("valid federation config", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
		}))
		require.NoError(t, err)
	})

	t.Run("oauth_token_endpoint is a federation override", func(t *testing.T) {
		federated := map[string]string{
			"auth_method":                "oidc_federation",
			"workload_identity_provider": testWIFProvider,
			"oauth_token_endpoint":       "https://token.example.test/token",
		}
		require.NoError(t, f.ValidateConfig(credential.NewConfig(federated)))

		log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
		d, err := f.Create(credential.NewConfig(federated), log)
		require.NoError(t, err)
		assert.Equal(t, "https://token.example.test/token", d.(*GCPDriver).oauthTokenURL)

		// Only domain-wide delegation trades there, and a static source cannot serve it.
		err = f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":          "static",
			"service_account_key":  `{"type":"service_account","project_id":"p","private_key_id":"kid","client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
			"oauth_token_endpoint": "https://token.example.test/token",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "oauth_token_endpoint is only valid for auth_method=oidc_federation")
	})

	t.Run("static still requires key", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{"auth_method": "static"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account_key is required")
	})

	t.Run("workload_identity_provider rejected on static", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":                "static",
			"service_account_key":        `{"type":"service_account","project_id":"p","private_key_id":"kid","client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`,
			"workload_identity_provider": testWIFProvider,
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid for auth_method=oidc_federation")
	})
}

func TestGCPDriverFactory_InferCredentialType_Federation(t *testing.T) {
	f := &GCPDriverFactory{}

	for _, mm := range []string{"", "access_token", "impersonated_access_token"} {
		got, err := f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": mm}))
		require.NoError(t, err, "mint_method=%q", mm)
		assert.Equal(t, credential.TypeGCPAccessToken, got, "mint_method=%q", mm)
	}

	// A token acting as a Workspace user is a type of its own, which the gcp and
	// mcp providers do not accept.
	got, err := f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "delegated_access_token"}))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeGCPDelegatedToken, got)

	// cloud_sql_iam_token infers a type but has no mint path, so a spec naming it
	// used to write cleanly and fail on every request. Refused here instead — the
	// db_auth_token validator refuses it too, for the operator who states `type`
	// rather than leaving it inferred.
	_, err = f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "cloud_sql_iam_token"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")

	_, err = f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "bogus"}))
	require.Error(t, err)
}

func TestGCPDriver_SupportsRotation_ByAuthMethod(t *testing.T) {
	fed := newFederationDriver(testWIFProvider, "", "")
	assert.False(t, fed.SupportsRotation(), "federation source has no key to rotate")

	static := &GCPDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeGCP,
		Config: credential.NewConfig(map[string]string{"auth_method": "static"}),
	}}
	assert.True(t, static.SupportsRotation())
}

func TestGCPDriver_MintCredential_FederationFailsClosed(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "access_token"})}
	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_source")
}

func TestGCPDriver_MintCredentialWithExchange_RejectsStaticSource(t *testing.T) {
	d := &GCPDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeGCP,
		Config: credential.NewConfig(map[string]string{"auth_method": "static"}),
	}}
	inputs := &credential.ExchangeInputs{SubjectToken: "tok"}
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "access_token"})}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=oidc_federation")
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
		assert.Equal(t, gcpSTSTokenFallbackTTL, ttl)
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
	inputs := &credential.ExchangeInputs{SubjectToken: "SUBJECT-JWT"}
	spec := &credential.CredSpec{
		Name:   "s",
		MaxTTL: 24 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "bq@proj.iam.gserviceaccount.com",
			"lifetime":               "1800s",
		}),
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
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt"}
	spec := &credential.CredSpec{Name: "s", MaxTTL: time.Hour, Config: credential.NewConfig(map[string]string{
		"mint_method":            "impersonated_access_token",
		"target_service_account": "bq@proj.iam.gserviceaccount.com",
	})}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
}

func TestGCPDriver_MintCredentialWithExchange_ImpersonationLifetimeBounds(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt"}
	spec := &credential.CredSpec{
		Name:   "s",
		MaxTTL: 15 * time.Minute,
		Config: credential.NewConfig(map[string]string{
			"mint_method":            "impersonated_access_token",
			"target_service_account": "bq@proj.iam.gserviceaccount.com",
			"lifetime":               "3600s", // exceeds MaxTTL
		}),
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
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt"}
	spec := &credential.CredSpec{
		Name:   "s",
		MaxTTL: 15 * time.Minute,
		Config: credential.NewConfig(map[string]string{"mint_method": "access_token"}),
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
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt"}
	// No mint_method set: federation defaults to access_token (the federated token itself).
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{})}

	raw, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "FED-TOKEN", raw["access_token"])
}

// The federated token's subject is read off the token Google verified, so a
// delegation assertion names the user as subject and the agent as actor — not the
// agent as subject, which would attribute the token to the wrong party. A subject
// token that does not parse yields no subject and still mints.
func TestGCPDriver_MintCredentialWithExchange_SubjectMetadata(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":3600}`))
	}))
	defer sts.Close()
	d := newFederationDriver(testWIFProvider, sts.URL, "")
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "access_token"})}

	tests := []struct {
		name        string
		token       string
		wantSubject string
		wantActor   string
	}{
		{
			name:        "agent-only assertion",
			token:       makeUnsignedJWT(map[string]interface{}{"sub": "wid:root:auth/jwt/:agent-1"}),
			wantSubject: "wid:root:auth/jwt/:agent-1",
		},
		{
			name: "delegation assertion",
			token: makeUnsignedJWT(map[string]interface{}{
				"sub": "user-42",
				"act": map[string]interface{}{"sub": "wid:root:auth/jwt/:agent-1"},
			}),
			wantSubject: "user-42",
			wantActor:   "wid:root:auth/jwt/:agent-1",
		},
		{name: "unparseable subject token", token: "jwt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := &credential.ExchangeInputs{
				SubjectToken: tt.token,
				AgentClaims:  map[string]string{"sub": "agent-1"},
			}
			_, meta, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
			require.NoError(t, err)
			if tt.wantSubject == "" {
				assert.NotContains(t, meta, "subject")
			} else {
				assert.Equal(t, tt.wantSubject, meta["subject"])
			}
			if tt.wantActor == "" {
				assert.NotContains(t, meta, "actor")
			} else {
				assert.Equal(t, tt.wantActor, meta["actor"])
			}
		})
	}
}

func TestGCPDriver_MintCredentialWithExchange_UnsupportedMethod(t *testing.T) {
	d := newFederationDriver(testWIFProvider, "", "")
	inputs := &credential.ExchangeInputs{SubjectToken: "jwt"}
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "impersonated_service_account"})}
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")
}

func TestGCPAssertionResource(t *testing.T) {
	federatedSource := map[string]string{
		"auth_method":                gcpAuthMethodOIDCFederation,
		"workload_identity_provider": testWIFProvider,
	}

	t.Run("impersonation from spec", func(t *testing.T) {
		res, ok := gcpAssertionResource(
			credential.NewConfig(federatedSource),
			credential.NewConfig(map[string]string{"mint_method": "impersonated_access_token", "target_service_account": "bq@proj.iam.gserviceaccount.com"}),
		)
		assert.True(t, ok)
		assert.Equal(t, "gcp-iam:bq@proj.iam.gserviceaccount.com", res)
	})

	t.Run("federated from source", func(t *testing.T) {
		res, ok := gcpAssertionResource(
			credential.NewConfig(federatedSource),
			credential.NewConfig(map[string]string{"mint_method": "access_token"}),
		)
		assert.True(t, ok)
		assert.Equal(t, "gcp-wif:"+testWIFProvider, res)
	})

	// The pool binds the right to sign as the delegating account to this value, so
	// it names the account under the prefix no spec may write.
	t.Run("delegation names the account under the reserved prefix", func(t *testing.T) {
		res, ok := gcpAssertionResource(
			credential.NewConfig(federatedSource),
			credential.NewConfig(map[string]string{"mint_method": "delegated_access_token", "target_service_account": "dwd@proj.iam.gserviceaccount.com"}),
		)
		assert.True(t, ok)
		assert.Equal(t, credential.GCPDelegationResourcePrefix+"dwd@proj.iam.gserviceaccount.com", res)
	})

	t.Run("routed via DeriveAssertionResource", func(t *testing.T) {
		res, ok := DeriveAssertionResource(credential.SourceTypeGCP,
			credential.NewConfig(federatedSource),
			credential.NewConfig(map[string]string{"mint_method": "access_token"}),
		)
		assert.True(t, ok)
		assert.Equal(t, "gcp-wif:"+testWIFProvider, res)
	})

	t.Run("no resource when unset", func(t *testing.T) {
		_, ok := gcpAssertionResource(credential.NewConfig(map[string]string{}), credential.NewConfig(map[string]string{"mint_method": "access_token"}))
		assert.False(t, ok)
	})

	// A static source presents no assertion, so naming a resource for one describes a
	// mint the exchange path refuses outright. The audience derivation gates on the
	// same condition; this one did not, and would answer for a source that never
	// federates anything.
	t.Run("no resource on a static source", func(t *testing.T) {
		_, ok := gcpAssertionResource(
			credential.NewConfig(map[string]string{"service_account_key": "{}"}),
			credential.NewConfig(map[string]string{"mint_method": "impersonated_access_token", "target_service_account": "bq@proj.iam.gserviceaccount.com"}),
		)
		assert.False(t, ok)
	})
}

func TestGCPAssertionAudience(t *testing.T) {
	t.Run("derives https form from provider", func(t *testing.T) {
		aud, ok := gcpAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": testWIFProvider}))
		require.True(t, ok)
		assert.Equal(t, "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden-oidc", aud)
	})

	t.Run("routed via DeriveAssertionAudience", func(t *testing.T) {
		aud, ok := DeriveAssertionAudience(credential.SourceTypeGCP,
			credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": testWIFProvider}), credential.NewConfig(map[string]string{}))
		require.True(t, ok)
		assert.Equal(t, "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/warden/providers/warden-oidc", aud)
	})

	t.Run("only the leading slashes are swapped", func(t *testing.T) {
		// A path segment that itself contains "//" must survive intact.
		aud, ok := gcpAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "workload_identity_provider": "//iam.googleapis.com/a//b"}))
		require.True(t, ok)
		assert.Equal(t, "https://iam.googleapis.com/a//b", aud)
	})

	t.Run("empty provider yields no audience", func(t *testing.T) {
		_, ok := gcpAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}))
		assert.False(t, ok)
	})

	t.Run("static source yields no audience even with a provider set", func(t *testing.T) {
		_, ok := gcpAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "static", "workload_identity_provider": testWIFProvider}))
		assert.False(t, ok)
	})

	t.Run("non-gcp source returns false", func(t *testing.T) {
		_, ok := DeriveAssertionAudience(credential.SourceTypeAWS, credential.NewConfig(map[string]string{}), credential.NewConfig(map[string]string{}))
		assert.False(t, ok)
	})
}

// delegationFakes stands in for the three Google endpoints a domain-wide
// delegation mint calls: STS, the IAM Credentials signJwt API, and the OAuth2
// token endpoint, which answers with tokenStatus and tokenBody.
type delegationFakes struct {
	sts, iam, token *httptest.Server
	hits            atomic.Int32 // calls to any of the three

	mu           sync.Mutex
	signAuth     string
	signPath     string
	signedClaims map[string]interface{}
	tokenForm    url.Values
}

func newDelegationFakes(t *testing.T, signStatus, tokenStatus int, tokenBody string) *delegationFakes {
	t.Helper()
	f := &delegationFakes{}
	f.sts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"FED-TOKEN","expires_in":3600}`))
	}))
	f.iam = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		var req struct {
			Payload string `json:"payload"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		var claims map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(req.Payload), &claims))
		f.mu.Lock()
		f.signAuth, f.signPath, f.signedClaims = r.Header.Get("Authorization"), r.URL.Path, claims
		f.mu.Unlock()
		w.WriteHeader(signStatus)
		if signStatus != http.StatusOK {
			// Google's answer can quote the account, as this one does.
			_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Permission 'iam.serviceAccounts.signJwt' denied on resource 'projects/-/serviceAccounts/` + testDWDAccount + `' (or it may not exist).","status":"PERMISSION_DENIED"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"keyId":"k1","signedJwt":"SIGNED-JWT"}`))
	}))
	f.token = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		require.NoError(t, r.ParseForm())
		f.mu.Lock()
		f.tokenForm = r.PostForm
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tokenStatus)
		_, _ = w.Write([]byte(tokenBody))
	}))
	t.Cleanup(func() {
		f.sts.Close()
		f.iam.Close()
		f.token.Close()
	})
	return f
}

func (f *delegationFakes) driver() *GCPDriver {
	d := newFederationDriver(testWIFProvider, f.sts.URL, f.iam.URL)
	d.oauthTokenURL = f.token.URL
	return d
}

const testDWDAccount = "dwd@proj.iam.gserviceaccount.com"

func delegationSpec(maxTTL time.Duration) *credential.CredSpec {
	return &credential.CredSpec{
		Name:   "workspace-user",
		Type:   credential.TypeGCPDelegatedToken,
		MaxTTL: maxTTL,
		Config: credential.NewConfig(map[string]string{
			"mint_method":            "delegated_access_token",
			"target_service_account": testDWDAccount,
			"scopes":                 "https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/drive.file",
			"delegated_user_claim":   "email",
			"delegated_user_domains": "example.com",
		}),
	}
}

// delegationInputs is what core hands the driver for a delegation spec: Warden's
// assertion naming the user (and the agent as actor), and the user's projected
// claims.
func delegationInputs(email string) *credential.ExchangeInputs {
	return &credential.ExchangeInputs{
		SubjectToken: makeUnsignedJWT(map[string]interface{}{
			"sub": "user-42",
			"act": map[string]interface{}{"sub": "wid:root:auth/jwt/:agent-1"},
		}),
		UserClaims: map[string]string{"sub": "user-42", "email": email},
	}
}

func TestGCPDriver_DelegatedAccessToken_MintsAsTheUser(t *testing.T) {
	f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"access_token":"USER-TOKEN","expires_in":3600,"token_type":"Bearer"}`)
	d := f.driver()

	raw, meta, ttl, lease, err := d.MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("Alice@Example.com"))
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"access_token": "USER-TOKEN"}, raw)
	assert.Empty(t, lease, "a delegated token cannot be revoked")
	assert.Equal(t, 59*time.Minute, ttl, "the hour Google gives, less the refresh buffer")

	assert.Equal(t, "alice@example.com", meta["delegated_user"])
	assert.Equal(t, testDWDAccount, meta["service_account"])
	assert.Equal(t, "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.file", meta["scopes"])
	assert.Equal(t, "user-42", meta["subject"], "the assertion's subject, as Google saw it")
	assert.Equal(t, "wid:root:auth/jwt/:agent-1", meta["actor"])

	f.mu.Lock()
	defer f.mu.Unlock()
	// Google signs as the account, authorized by the token federated for the caller.
	assert.Equal(t, "Bearer FED-TOKEN", f.signAuth)
	assert.True(t, strings.HasSuffix(f.signPath, "/v1/projects/-/serviceAccounts/"+testDWDAccount+":signJwt"), "path was %q", f.signPath)
	assert.Equal(t, testDWDAccount, f.signedClaims["iss"])
	assert.Equal(t, "alice@example.com", f.signedClaims["sub"])
	assert.Equal(t, "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.file", f.signedClaims["scope"],
		"Google wants the scopes space-separated")
	assert.Equal(t, "https://oauth2.googleapis.com/token", f.signedClaims["aud"],
		"the audience is Google's endpoint wherever the trade is sent")
	assert.Equal(t, float64(310), f.signedClaims["exp"].(float64)-f.signedClaims["iat"].(float64),
		"a five-minute assertion, iat backdated ten seconds")

	assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", f.tokenForm.Get("grant_type"))
	assert.Equal(t, "SIGNED-JWT", f.tokenForm.Get("assertion"))

	d.tokenCache.mu.Lock()
	defer d.tokenCache.mu.Unlock()
	assert.Empty(t, d.tokenCache.cache, "a user's token is never kept on the driver, where only scopes key it")
}

func TestGCPDriver_DelegatedAccessToken_MaxTTLCapsTheLease(t *testing.T) {
	f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"access_token":"USER-TOKEN","expires_in":3600}`)

	_, _, ttl, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(10*time.Minute), delegationInputs("alice@example.com"))
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, ttl)
}

func TestResolveDelegatedSubject(t *testing.T) {
	// kexample.com is listed so the Kelvin-sign row proves the raw match: folded
	// first, alice@Kexample.com would land on it.
	domains := []string{"example.com", "eng.example.org", "kexample.com"}
	tests := []struct {
		name    string
		claims  map[string]string
		want    string
		refused bool // ErrUserNotAllowed
		wantErr string
	}{
		{name: "listed domain", claims: map[string]string{"email": "alice@example.com"}, want: "alice@example.com"},
		{name: "folded to lowercase", claims: map[string]string{"email": "Alice.Smith@EXAMPLE.com"}, want: "alice.smith@example.com"},
		{name: "apostrophe and dash", claims: map[string]string{"email": "o'neil-jr@example.com"}, want: "o'neil-jr@example.com"},
		{name: "listed subdomain", claims: map[string]string{"email": "bob@eng.example.org"}, want: "bob@eng.example.org"},
		{name: "subdomain not implied", claims: map[string]string{"email": "bob@eng.example.com"}, refused: true},
		{name: "parent not implied", claims: map[string]string{"email": "bob@example.org"}, refused: true},
		{name: "unlisted domain", claims: map[string]string{"email": "eve@evil.com"}, refused: true},
		{name: "suffix is not the domain", claims: map[string]string{"email": "eve@notexample.com"}, refused: true},
		{name: "two @", claims: map[string]string{"email": "eve@evil.com@example.com"}, refused: true},
		{name: "multi-valued fact", claims: map[string]string{"email": "alice@example.com,eve@example.com"}, refused: true},
		{name: "trailing dot", claims: map[string]string{"email": "alice@example.com."}, refused: true},
		{name: "plus addressing", claims: map[string]string{"email": "alice+x@example.com"}, refused: true},
		// U+212A KELVIN SIGN lowercases to an ASCII k; matched raw, it never gets there.
		{name: "kelvin sign", claims: map[string]string{"email": "alice@Kexample.com"}, refused: true},
		{name: "empty", claims: map[string]string{"email": ""}, refused: true},
		{name: "too long", claims: map[string]string{"email": strings.Repeat("a", 250) + "@example.com"}, refused: true},
		{name: "claim not projected", claims: map[string]string{"sub": "user-42"}, wantErr: "not among the user's projected claims"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDelegatedSubject(tt.claims, "email", domains)
			switch {
			case tt.refused:
				require.ErrorIs(t, err, credential.ErrUserNotAllowed)
				if v := tt.claims["email"]; v != "" {
					assert.NotContains(t, err.Error(), v, "a refusal never repeats the address")
				}
			case tt.wantErr != "":
				require.Error(t, err)
				assert.NotErrorIs(t, err, credential.ErrUserNotAllowed, "a spec fault, not a user to refuse")
				assert.Contains(t, err.Error(), tt.wantErr)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}

	// The user's principal id is projected as sub; named as the claim, it is not an
	// address and is refused rather than sent to Google.
	_, err := resolveDelegatedSubject(map[string]string{"sub": "user-42"}, "sub", domains)
	require.ErrorIs(t, err, credential.ErrUserNotAllowed)
}

func TestGCPDelegatedAccess(t *testing.T) {
	assert.True(t, GCPDelegatedAccess(credential.TypeGCPDelegatedToken, credential.NewConfig(nil)))
	assert.True(t, GCPDelegatedAccess(credential.TypeGCPAccessToken,
		credential.NewConfig(map[string]string{"mint_method": "delegated_access_token"})),
		"a spec naming the method meets the delegation rules whatever its type")
	assert.False(t, GCPDelegatedAccess(credential.TypeGCPAccessToken,
		credential.NewConfig(map[string]string{"mint_method": "impersonated_access_token"})))
}

// A token acting as a user is issued only as the type the gcp and mcp providers
// refuse.
func TestGCPDriver_DelegatedAccessToken_RefusesAnotherType(t *testing.T) {
	f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"access_token":"USER-TOKEN"}`)
	spec := delegationSpec(0)
	spec.Type = credential.TypeGCPAccessToken

	_, _, _, _, err := f.driver().MintCredentialWithExchange(context.Background(), spec, delegationInputs("alice@example.com"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issues a gcp_delegated_token")
	assert.Zero(t, f.hits.Load())
}

func TestGCPDriver_DelegatedAccessToken_Answers(t *testing.T) {
	t.Run("no expires_in takes the short fallback", func(t *testing.T) {
		f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"access_token":"USER-TOKEN"}`)
		_, _, ttl, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("alice@example.com"))
		require.NoError(t, err)
		assert.Equal(t, 4*time.Minute, ttl, "five minutes less the refresh buffer")
	})

	t.Run("an answer without a token", func(t *testing.T) {
		f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"token_type":"Bearer","expires_in":3600}`)
		_, _, _, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("alice@example.com"))
		require.ErrorIs(t, err, errNoAccessToken)
		assert.Contains(t, err.Error(), "no usable answer")
	})

	t.Run("an outage is not a refusal", func(t *testing.T) {
		f := newDelegationFakes(t, http.StatusOK, http.StatusServiceUnavailable, `<html>unavailable</html>`)
		_, _, _, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("alice@example.com"))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "refused")
		assert.NotErrorIs(t, err, credential.ErrUserNotAllowed)
		status, ok := credential.UpstreamStatus(err)
		require.True(t, ok)
		assert.Equal(t, http.StatusServiceUnavailable, status, "answered as an outage, which clients retry")
	})
}

// A user the spec may not act for is refused before Google is asked anything.
func TestGCPDriver_DelegatedAccessToken_RefusedUserCostsNoCall(t *testing.T) {
	f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"access_token":"USER-TOKEN"}`)

	_, _, _, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("eve@evil.com"))
	require.ErrorIs(t, err, credential.ErrUserNotAllowed)
	assert.Zero(t, f.hits.Load())
}

func TestGCPDriver_DelegatedAccessToken_Refusals(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		userFault bool
	}{
		{name: "delegation not authorized", status: http.StatusUnauthorized, body: `{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."}`},
		{name: "scope not authorized, on a 403", status: http.StatusForbidden, body: `{"error":"access_denied","error_description":"Requested client not authorized."}`},
		{name: "unknown scope", status: http.StatusBadRequest, body: `{"error":"invalid_scope","error_description":"Invalid OAuth scope or ID token audience provided."}`},
		{name: "clock skew", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe."}`},
		{name: "no such user", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"Invalid email or User ID"}`, userFault: true},
		{name: "not an email", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"Not a valid email."}`, userFault: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newDelegationFakes(t, http.StatusOK, tt.status, tt.body)

			_, _, _, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("alice@example.com"))
			require.Error(t, err)
			assert.Equal(t, tt.userFault, errors.Is(err, credential.ErrUserNotAllowed))
			var tee *tokenEndpointError
			require.ErrorAs(t, err, &tee, "the token endpoint's answer stays in the chain")
			assert.NotEmpty(t, tee.code, "the code is parsed whatever the status")

			// Answered as a refusal, never a server error.
			status, ok := credential.UpstreamStatus(err)
			require.True(t, ok)
			assert.Equal(t, tt.status, status)
			assert.NotContains(t, err.Error(), testDWDAccount, "what to fix goes to the log, not to the caller")
		})
	}
}

func TestGCPDriver_DelegatedAccessToken_SigningRefused(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		f := newDelegationFakes(t, http.StatusForbidden, http.StatusOK, `{"access_token":"USER-TOKEN"}`)

		_, _, _, _, err := f.driver().MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("alice@example.com"))
		require.Error(t, err)
		assert.Equal(t, "gcp: Google would not sign the domain-wide delegation assertion", err.Error(),
			"Google's answer quotes the account; the caller is told only that it refused")
		assert.NotErrorIs(t, err, credential.ErrUserNotAllowed)
		status, ok := credential.UpstreamStatus(err)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, status, "the refusal's status survives the fixed message")
		f.mu.Lock()
		defer f.mu.Unlock()
		assert.Nil(t, f.tokenForm, "nothing is traded without a signature")
	})

	t.Run("unreachable", func(t *testing.T) {
		f := newDelegationFakes(t, http.StatusOK, http.StatusOK, `{"access_token":"USER-TOKEN"}`)
		d := f.driver()
		f.iam.Close() // the dial error quotes the signJwt URL, account and all

		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), delegationSpec(0), delegationInputs("alice@example.com"))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), testDWDAccount)
		var netErr net.Error
		assert.True(t, errors.As(err, &netErr), "still a network failure underneath, answered as an outage")
	})
}

// A static source holds the key Google's guidance says not to have, and cannot
// receive the user's claims.
func TestGCPDriver_DelegatedAccessToken_RefusedOnStaticSource(t *testing.T) {
	d := &GCPDriver{credSource: &credential.CredSource{
		Type:   credential.SourceTypeGCP,
		Config: credential.NewConfig(map[string]string{"auth_method": "static"}),
	}}
	_, _, _, _, err := d.MintCredential(context.Background(), delegationSpec(0))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=oidc_federation")
}

func TestGCPDelegatedAccessSpecError(t *testing.T) {
	federated := credential.NewConfig(map[string]string{
		"auth_method":                gcpAuthMethodOIDCFederation,
		"workload_identity_provider": testWIFProvider,
	})
	base := map[string]string{
		"mint_method":            "delegated_access_token",
		"target_service_account": testDWDAccount,
		"scopes":                 "https://www.googleapis.com/auth/gmail.readonly",
		"delegated_user_claim":   "email",
		"delegated_user_domains": "example.com",
		"subject_token_source":   "warden_identity",
		"assertion_user_claims":  "email",
	}
	with := func(changes map[string]string) credential.Config {
		cfg := map[string]string{}
		for k, v := range base {
			cfg[k] = v
		}
		for k, v := range changes {
			if v == "" {
				delete(cfg, k)
			} else {
				cfg[k] = v
			}
		}
		return credential.NewConfig(cfg)
	}

	require.NoError(t, GCPDelegatedAccessSpecError(with(nil), federated))
	require.NoError(t, GCPDelegatedAccessSpecError(with(map[string]string{"assertion_profile": "default"}), federated))

	tests := []struct {
		name    string
		spec    credential.Config
		source  credential.Config
		wantErr string
	}{
		{"static source", with(nil), credential.NewConfig(map[string]string{"auth_method": "static"}), "auth_method=oidc_federation"},
		{"user's raw token as subject", with(map[string]string{"subject_token_source": "user_identity"}), federated, "subject_token_source=warden_identity"},
		{"no subject", with(map[string]string{"subject_token_source": ""}), federated, "subject_token_source=warden_identity"},
		{"actor", with(map[string]string{"actor_token_source": "warden_identity"}), federated, "actor_token_source"},
		{"claim not projected", with(map[string]string{"assertion_user_claims": "sub"}), federated, "must also be listed in assertion_user_claims"},
		{"own resource", with(map[string]string{"assertion_resource": "anything"}), federated, "the resource is derived"},
		{"resource suppressed", with(map[string]string{"assertion_resource": "none"}), federated, "the resource is derived"},
		{"profile without the resource", with(map[string]string{"assertion_profile": "minimal"}), federated, "must be \"default\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GCPDelegatedAccessSpecError(tt.spec, tt.source)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
