package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fake Azure server (Entra ID token + Graph app-secret mgmt + blob PUT) --

// fakeAzure stubs the three surfaces azure_blob rotation touches: the OAuth2 token
// endpoint (client-credentials), Microsoft Graph (resolve app, add/remove password), and
// the blob data plane (UploadBuffer PUT). One httptest server handles all three
// (azureAuthorityHost/azureGraphEndpoint and the blob endpoint all point here).
type fakeAzure struct {
	mu                 sync.Mutex
	appObjectID        string // returned by the /applications filter query
	newSecret          string // returned by addPassword
	newSecretID        string
	failTokenForSecret string                    // token requests for this client_secret fail...
	failTokenRemaining int                       // ...this many times (verify propagation)
	passwords          []azurePasswordCredential // returned by the single-app GET (for prune)
	added              []string
	removed            []string
	uploads            []string
	uploadCT           map[string]string // path -> x-ms-blob-content-type
	uploadCC           map[string]string // path -> x-ms-blob-cache-control
}

func (s *fakeAzure) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/oauth2/v2.0/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			s.mu.Lock()
			fail := form.Get("client_secret") == s.failTokenForSecret && s.failTokenRemaining > 0
			if fail {
				s.failTokenRemaining--
			}
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if fail {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"secret not yet valid"}`)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"faketoken","token_type":"Bearer","expires_in":3600}`)
		case strings.HasSuffix(path, "/addPassword"):
			s.mu.Lock()
			s.added = append(s.added, s.newSecretID)
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"secretText":"`+s.newSecret+`","keyId":"`+s.newSecretID+`"}`)
		case strings.HasSuffix(path, "/removePassword"):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				KeyID string `json:"keyId"`
			}
			_ = json.Unmarshal(body, &req)
			s.mu.Lock()
			s.removed = append(s.removed, req.KeyID)
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case path == "/v1.0/applications": // filter query (resolveAppObjectID)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"value":[{"id":"`+s.appObjectID+`"}]}`)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1.0/applications/"): // single app: passwordCredentials
			s.mu.Lock()
			body, _ := json.Marshal(struct {
				PasswordCredentials []azurePasswordCredential `json:"passwordCredentials"`
			}{s.passwords})
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		case r.Method == http.MethodPut: // blob upload
			_, _ = io.Copy(io.Discard, r.Body)
			s.mu.Lock()
			s.uploads = append(s.uploads, path)
			if s.uploadCT != nil {
				s.uploadCT[path] = r.Header.Get("x-ms-blob-content-type")
			}
			if s.uploadCC != nil {
				s.uploadCC[path] = r.Header.Get("x-ms-blob-cache-control")
			}
			s.mu.Unlock()
			w.Header().Set("ETag", `"0x8DTEST"`)
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}
}

func withAzureFake(t *testing.T, u string) {
	t.Helper()
	pa, pg, pi := azureAuthorityHost, azureGraphEndpoint, azureInsecureAllowHTTP
	azureAuthorityHost, azureGraphEndpoint, azureInsecureAllowHTTP = u, u, true
	t.Cleanup(func() {
		azureAuthorityHost, azureGraphEndpoint, azureInsecureAllowHTTP = pa, pg, pi
	})
}

func withAzureVerifyTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := azureRotationVerifyTimeout
	azureRotationVerifyTimeout = d
	t.Cleanup(func() { azureRotationVerifyTimeout = prev })
}

func newTestAzureBlobPublisher(t *testing.T, endpoint, tenant, clientID, clientSecret, secretID string) *azureBlobPublisher {
	t.Helper()
	p := &azureBlobPublisher{
		clientSecret: clientSecret,
		secretID:     secretID,
		tenantID:     tenant,
		clientID:     clientID,
		accountName:  "acct",
		serviceURL:   endpoint,
		container:    "jwks",
	}
	client, err := p.buildClient(clientSecret)
	require.NoError(t, err)
	p.client = client
	return p
}

// --- publish + mechanism tests ----------------------------------------------

func TestAzureBlobPublisher(t *testing.T) {
	az := &fakeAzure{uploadCT: map[string]string{}, uploadCC: map[string]string{}}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	// Built through the real constructor with SP OAuth config + endpoint override; the
	// blob client authenticates with the fake token, and the server records the PUTs.
	p, err := newJWKSPublisher(publisherConfig{
		Type: "azure_blob", AccountName: "wardenoidc", Container: "jwks", Prefix: "prod",
		TenantID: "tenant", ClientID: "client", ClientSecret: "secret", Endpoint: srv.URL,
	}, "public, max-age=60")
	require.NoError(t, err)
	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	az.mu.Lock()
	defer az.mu.Unlock()
	assert.Contains(t, az.uploads, "/jwks/prod/.well-known/openid-configuration", "discovery blob must be PUT")
	assert.Contains(t, az.uploads, "/jwks/prod/oidc/jwks", "jwks blob must be PUT")
	// Content type / cache control ride on x-ms-blob-* headers.
	assert.Equal(t, "application/json", az.uploadCT["/jwks/prod/.well-known/openid-configuration"])
	assert.Equal(t, "public, max-age=60", az.uploadCC["/jwks/prod/.well-known/openid-configuration"])
}

func TestAzureBlobPublisher_RotateFullCycle(t *testing.T) {
	az := &fakeAzure{appObjectID: "appobj", newSecret: "newsecret", newSecretID: "newkid"}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "oldsecret", "oldkid")

	newFields, prevFields, cleanup, err := p.PrepareRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "newsecret", newFields["client_secret"])
	assert.Equal(t, "newkid", newFields["secret_id"])
	assert.Equal(t, "oldsecret", prevFields["client_secret"])
	assert.Equal(t, "oldkid", cleanup["old_secret_id"])
	assert.Contains(t, az.added, "newkid")

	require.NoError(t, p.CommitRotation(newFields))
	p.mu.RLock()
	assert.Equal(t, "newsecret", p.clientSecret)
	assert.Equal(t, "newkid", p.secretID)
	p.mu.RUnlock()

	require.NoError(t, p.CleanupRotation(context.Background(), cleanup))
	assert.Contains(t, az.removed, "oldkid")
}

func TestAzureBlobPublisher_RotateVerifyRetry(t *testing.T) {
	az := &fakeAzure{appObjectID: "appobj", newSecret: "newsecret", newSecretID: "newkid",
		failTokenForSecret: "newsecret", failTokenRemaining: 1}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "oldsecret", "oldkid")
	newFields, _, _, err := p.PrepareRotation(context.Background())
	require.NoError(t, err, "verify must retry past the initial invalid_client")
	assert.Equal(t, "newsecret", newFields["client_secret"])
	assert.Empty(t, az.removed, "a secret that verifies after retry must not be removed")
}

func TestAzureBlobPublisher_RotateVerifyFailureRemovesNewSecret(t *testing.T) {
	az := &fakeAzure{appObjectID: "appobj", newSecret: "newsecret", newSecretID: "newkid",
		failTokenForSecret: "newsecret", failTokenRemaining: 1 << 30}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)
	withAzureVerifyTimeout(t, 300*time.Millisecond)

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "oldsecret", "oldkid")
	_, _, _, err := p.PrepareRotation(context.Background())
	require.Error(t, err, "an unusable new secret must fail rotation")
	assert.Contains(t, az.removed, "newkid", "the unusable new secret must be removed from the app registration")
}

func TestAzureBlobPublisher_RotatePrunesOrphanSecrets(t *testing.T) {
	az := &fakeAzure{appObjectID: "appobj", newSecret: "newsecret", newSecretID: "newkid"}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "oldsecret", "oldkid")
	// The app already carries a leaked warden secret (from a prior failed cleanup) and an
	// operator-managed one. Prune runs in CleanupRotation, keeping the just-committed live
	// secret (newkid).
	name := p.secretDisplayName()
	az.mu.Lock()
	az.passwords = []azurePasswordCredential{
		{KeyID: "oldkid", DisplayName: name},                           // superseded this cycle
		{KeyID: "orphankid", DisplayName: name},                        // leaked by a prior failed cleanup
		{KeyID: "operatorkid", DisplayName: "operator-managed-secret"}, // NOT warden-created
	}
	az.mu.Unlock()

	newFields, _, cleanup, err := p.PrepareRotation(context.Background())
	require.NoError(t, err)
	require.NoError(t, p.CommitRotation(newFields))
	require.NoError(t, p.CleanupRotation(context.Background(), cleanup))

	assert.Contains(t, az.removed, "oldkid", "the superseded secret must be removed")
	assert.Contains(t, az.removed, "orphankid", "a leaked warden secret must be pruned")
	assert.NotContains(t, az.removed, "newkid", "the just-committed live secret must be kept")
	assert.NotContains(t, az.removed, "operatorkid", "operator-managed secrets must never be pruned")
}

func TestAzureBlobPublisher_RollbackRotation(t *testing.T) {
	az := &fakeAzure{appObjectID: "appobj", newSecret: "newsecret", newSecretID: "newkid"}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "oldsecret", "oldkid")
	require.NoError(t, p.RollbackRotation(context.Background(), map[string]string{"secret_id": "newkid"}))
	assert.Contains(t, az.removed, "newkid")
}

// TestAzureBlobPublisher_ConcurrentPublishAndCommit exercises the mutex under -race.
func TestAzureBlobPublisher_ConcurrentPublishAndCommit(t *testing.T) {
	az := &fakeAzure{appObjectID: "app", newSecret: "n", newSecretID: "nid"}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "s1", "k1")
	var wg sync.WaitGroup
	var commitErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			_ = p.Publish(context.Background(), []byte(`{}`), []byte(`{}`))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if err := p.CommitRotation(map[string]string{"client_secret": "s2", "secret_id": "k2"}); err != nil {
				commitErr = err
				return
			}
		}
	}()
	wg.Wait()
	require.NoError(t, commitErr)
}

// --- loop-level test: generic persist with azure (two-field) credentials ----

func TestRotatePublisherCredential_Azure(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	az := &fakeAzure{appObjectID: "appobj", newSecret: "newsecret", newSecretID: "newkid"}
	srv := httptest.NewServer(az.handler())
	defer srv.Close()
	withAzureFake(t, srv.URL)

	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled:   true,
		IssuerURL: "https://iss.example",
		Publisher: publisherConfig{
			Type: "azure_blob", AccountName: "acct", Container: "jwks", Endpoint: srv.URL,
			TenantID: "tenant", ClientID: "client", ClientSecret: "oldsecret", SecretID: "oldkid",
			RotationPeriod: "24h",
		},
	}))

	p := newTestAzureBlobPublisher(t, srv.URL, "tenant", "client", "oldsecret", "oldkid")
	require.NoError(t, core.rotatePublisherCredential(ctx, p))

	// The generalized persist wrote BOTH the new secret and its id.
	cfg, err := loadIssuerConfig(ctx, storage)
	require.NoError(t, err)
	assert.Equal(t, "newsecret", cfg.Publisher.ClientSecret)
	assert.Equal(t, "newkid", cfg.Publisher.SecretID)

	// Live publisher swapped, old secret removed.
	p.mu.RLock()
	assert.Equal(t, "newsecret", p.clientSecret)
	p.mu.RUnlock()
	assert.Contains(t, az.removed, "oldkid")
}
