package drivers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPAccessTokenMetadata(t *testing.T) {
	expiry := time.Date(2026, 6, 9, 15, 4, 5, 0, time.UTC)
	saKey := &serviceAccountKey{
		ClientEmail: "warden-src@my-project.iam.gserviceaccount.com",
		ProjectID:   "my-project",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----",
	}

	meta := gcpAccessTokenMetadata(saKey, "https://www.googleapis.com/auth/cloud-platform", expiry)

	assert.Equal(t, "warden-src@my-project.iam.gserviceaccount.com", meta["subject"])
	assert.Equal(t, "my-project", meta["project_id"])
	assert.Equal(t, "https://www.googleapis.com/auth/cloud-platform", meta["scopes"])
	assert.Equal(t, "2026-06-09T15:04:05Z", meta["expiration"])

	// Secret material never lands in the clear-logged metadata, and every value
	// is a string (Metadata parsing rejects non-strings).
	assert.NotContains(t, meta, "private_key")
	assert.NotContains(t, meta, "access_token")
	for k, v := range meta {
		_, ok := v.(string)
		assert.Truef(t, ok, "metadata[%q] is %T, expected string", k, v)
	}
}

func TestGCPAccessTokenMetadata_NilKey(t *testing.T) {
	expiry := time.Date(2026, 6, 9, 15, 4, 5, 0, time.UTC)

	meta := gcpAccessTokenMetadata(nil, "scope", expiry)

	// Non-key source auth: no SA identity fields, but token context still present.
	assert.NotContains(t, meta, "subject")
	assert.NotContains(t, meta, "project_id")
	assert.Equal(t, "scope", meta["scopes"])
	assert.Equal(t, "2026-06-09T15:04:05Z", meta["expiration"])
}

func TestGCPImpersonatedMetadata(t *testing.T) {
	saKey := &serviceAccountKey{
		ClientEmail: "warden-src@my-project.iam.gserviceaccount.com",
		ProjectID:   "my-project",
	}

	meta := gcpImpersonatedMetadata(saKey,
		"app-backend@my-project.iam.gserviceaccount.com",
		"https://www.googleapis.com/auth/cloud-platform", "3600s", "2026-06-09T16:04:05Z")

	// subject is the impersonated target; the source SA is the authority.
	assert.Equal(t, "app-backend@my-project.iam.gserviceaccount.com", meta["subject"])
	assert.Equal(t, "warden-src@my-project.iam.gserviceaccount.com", meta["source_service_account"])
	assert.Equal(t, "my-project", meta["project_id"])
	assert.Equal(t, "3600s", meta["lifetime"])
	assert.Equal(t, "2026-06-09T16:04:05Z", meta["expiration"])
}

func TestGCPImpersonatedMetadata_NilKeyAndNoExpiry(t *testing.T) {
	meta := gcpImpersonatedMetadata(nil, "app-backend@x.iam.gserviceaccount.com", "scope", "3600s", "")

	assert.Equal(t, "app-backend@x.iam.gserviceaccount.com", meta["subject"])
	assert.NotContains(t, meta, "source_service_account")
	assert.NotContains(t, meta, "project_id")
	assert.NotContains(t, meta, "expiration")
}

func TestGCPDriverFactory_Type(t *testing.T) {
	f := &GCPDriverFactory{}
	assert.Equal(t, credential.SourceTypeGCP, f.Type())
}

func TestGCPDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &GCPDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "service_account_key")
}

func TestGCPDriverFactory_ValidateConfig(t *testing.T) {
	f := &GCPDriverFactory{}

	t.Run("missing service_account_key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account_key")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": "not-json",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid JSON")
	})

	t.Run("missing client_email", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": `{"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n"}`,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_email")
	})

	t.Run("missing private_key", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": `{"client_email": "test@project.iam.gserviceaccount.com"}`,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private_key")
	})

	t.Run("valid config", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"service_account_key": `{
				"type": "service_account",
				"project_id": "my-project",
				"private_key_id": "key-id",
				"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
				"client_email": "test@my-project.iam.gserviceaccount.com",
				"client_id": "123456789"
			}`,
		})
		require.NoError(t, err)
	})
}

func TestGCPDriver_Type(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeGCP, d.Type())
}

func TestGCPDriver_Cleanup(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Cleanup(context.TODO()))
}

func TestGCPDriver_Revoke_NoOp(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	require.NoError(t, d.Revoke(context.TODO(), "some-lease-id"))
}

func TestGCPDriver_SupportsRotation(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
	}
	assert.True(t, d.SupportsRotation())
}

func TestGCPDriver_MintCredential_UnsupportedMintMethod(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
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

func TestGCPDriver_MintCredential_ImpersonationMissingTarget(t *testing.T) {
	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{},
		},
		tokenCache: NewTokenCache(),
	}

	spec := &credential.CredSpec{
		Name: "test-spec",
		Config: map[string]string{
			"mint_method": "impersonated_access_token",
		},
	}

	_, _, _, _, err := d.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target_service_account")
}

func TestGCPDriver_ParseServiceAccountKey(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		d := &GCPDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{
					"service_account_key": `{
						"type": "service_account",
						"project_id": "my-project",
						"private_key_id": "key-123",
						"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
						"client_email": "test@my-project.iam.gserviceaccount.com",
						"client_id": "123456789"
					}`,
				},
			},
		}

		saKey, err := d.parseServiceAccountKey()
		require.NoError(t, err)
		assert.Equal(t, "my-project", saKey.ProjectID)
		assert.Equal(t, "key-123", saKey.PrivateKeyID)
		assert.Equal(t, "test@my-project.iam.gserviceaccount.com", saKey.ClientEmail)
	})

	t.Run("empty key", func(t *testing.T) {
		d := &GCPDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{},
			},
		}

		_, err := d.parseServiceAccountKey()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		d := &GCPDriver{
			credSource: &credential.CredSource{
				Config: map[string]string{
					"service_account_key": "not-json",
				},
			},
		}

		_, err := d.parseServiceAccountKey()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})
}

func TestSplitScopes(t *testing.T) {
	t.Run("single scope", func(t *testing.T) {
		scopes := splitScopes("https://www.googleapis.com/auth/cloud-platform")
		assert.Equal(t, []string{"https://www.googleapis.com/auth/cloud-platform"}, scopes)
	})

	t.Run("multiple scopes", func(t *testing.T) {
		scopes := splitScopes("https://www.googleapis.com/auth/compute, https://www.googleapis.com/auth/devstorage.read_only")
		assert.Equal(t, []string{
			"https://www.googleapis.com/auth/compute",
			"https://www.googleapis.com/auth/devstorage.read_only",
		}, scopes)
	})
}

// newTestGCPSAKey builds a usable service-account key whose token_uri points at a local
// server, so the oauth2 library performs a real signed JWT exchange against it.
func newTestGCPSAKey(t *testing.T, tokenURI, clientEmail string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	saKey := map[string]string{
		"type":         "service_account",
		"project_id":   "test-project",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": clientEmail,
		"token_uri":    tokenURI,
	}
	encoded, err := json.Marshal(saKey)
	require.NoError(t, err)
	return string(encoded)
}

// TestGCPDriver_RotationDuringMintDiscardsStaleToken pins the generation guard in
// getSourceToken. The scope key carries nothing about which SA key minted the token, so
// the generation is the sole barrier: without the guard, a token whose exchange was in
// flight when CommitRotation landed is stamped with the new generation and served for
// its full lifetime, defeating the rotation it outlived.
func TestGCPDriver_RotationDuringMintDiscardsStaleToken(t *testing.T) {
	var d *GCPDriver
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		// Retire the SA key that is minting this very token, mid-exchange.
		if n == 1 {
			d.tokenCache.InvalidateGeneration()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-call-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	d = &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{"service_account_key": newTestGCPSAKey(t, srv.URL, "sa@test-project.iam.gserviceaccount.com")},
		},
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	token, _, err := d.getSourceToken(context.TODO(), []string{"https://www.googleapis.com/auth/cloud-platform"})
	require.NoError(t, err)

	assert.Equal(t, int32(2), atomic.LoadInt32(&callCount), "the in-flight token belonged to the retired SA key, so it must be minted again")
	assert.Equal(t, "token-call-2", token, "the retired SA key's token must not be returned")
}

// TestGCPDriver_ConcurrentRotationAndMintIsRaceFree covers the other half: CommitRotation
// replaces credSource.Config wholesale while mints are reading it. The assertions are
// incidental — this test earns its keep under -race, which is what catches the driver
// losing the lock that makes the swap safe.
func TestGCPDriver_ConcurrentRotationAndMintIsRaceFree(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-call-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{"service_account_key": newTestGCPSAKey(t, srv.URL, "sa@test-project.iam.gserviceaccount.com")},
		},
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	rotatedKey := newTestGCPSAKey(t, srv.URL, "sa@test-project.iam.gserviceaccount.com")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := d.getSourceToken(context.TODO(), []string{"https://www.googleapis.com/auth/cloud-platform"})
			assert.NoError(t, err)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, d.CommitRotation(context.TODO(), map[string]string{"service_account_key": rotatedKey}))
	}()

	wg.Wait()

	// Whatever the interleaving, the driver ends on the rotated key and reports verified.
	assert.Equal(t, rotatedKey, d.getServiceAccountKey())
	assert.True(t, d.sourceVerified)
}

// gcpAssertionIssuer reads the client_email out of the signed JWT the oauth2 library
// sends, so a test server can tell which service-account key minted a given request.
// The signature is irrelevant here — only which key was used.
func gcpAssertionIssuer(t *testing.T, r *http.Request) string {
	t.Helper()
	require.NoError(t, r.ParseForm())

	parts := strings.Split(r.FormValue("assertion"), ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims struct {
		Iss string `json:"iss"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Iss
}

// TestGCPDriver_TokenFromRetiredKeyIsNeverServed is the GCP twin of the IBM test: a real
// CommitRotation lands while a mint's exchange is held open, so the response genuinely
// carries a token the retired SA key minted. That token must be discarded, not served.
func TestGCPDriver_TokenFromRetiredKeyIsNeverServed(t *testing.T) {
	const oldSA = "old-sa@test-project.iam.gserviceaccount.com"
	const newSA = "new-sa@test-project.iam.gserviceaccount.com"

	mintStarted := make(chan struct{})
	rotationDone := make(chan struct{})
	var once sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := gcpAssertionIssuer(t, r)

		// Hold the outgoing key's exchange open until the rotation has landed; the
		// rotated key's exchanges (including CommitRotation's own verify) pass through.
		if issuer == oldSA {
			once.Do(func() { close(mintStarted) })
			<-rotationDone
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token-from-" + issuer,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	d := &GCPDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeGCP,
			Config: map[string]string{"service_account_key": newTestGCPSAKey(t, srv.URL, oldSA)},
		},
		tokenCache: NewTokenCache(),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	rotatedKey := newTestGCPSAKey(t, srv.URL, newSA)
	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}

	var token string
	var mintErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		token, _, mintErr = d.getSourceToken(context.TODO(), scopes)
	}()

	<-mintStarted
	require.NoError(t, d.CommitRotation(context.TODO(), map[string]string{"service_account_key": rotatedKey}))
	close(rotationDone)
	wg.Wait()

	require.NoError(t, mintErr)
	assert.Equal(t, "token-from-"+newSA, token,
		"the exchange completed against the retired SA key; its token must be discarded, not served")
}
