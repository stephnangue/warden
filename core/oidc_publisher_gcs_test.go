package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// --- test helpers -----------------------------------------------------------

// genTestSAKeyJSON builds a service-account key JSON with a real RSA private key so the
// OAuth2 JWT-bearer flow can sign an assertion, and points token_uri at a fake server so
// no real Google token exchange happens.
func genTestSAKeyJSON(t *testing.T, tokenURI, projectID, email, keyID string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     projectID,
		"private_key_id": keyID,
		"private_key":    string(pemBytes),
		"client_email":   email,
		"token_uri":      tokenURI,
	})
	require.NoError(t, err)
	return string(b)
}

// fakeTokenServer returns access tokens, failing the first failFirst calls with
// invalid_grant (to exercise verify-with-retry / propagation absorption).
func fakeTokenServer(t *testing.T, failFirst int) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n <= failFirst {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
}

// fakeIAMServer serves the SA-key create/delete endpoints. POST returns newKeyJSON as the
// created key; DELETE records the request path so tests can assert the deleted key id.
func fakeIAMServer(t *testing.T, newKeyJSON string, deletes *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			enc := base64.StdEncoding.EncodeToString([]byte(newKeyJSON))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"privateKeyData":"` + enc + `"}`))
		case http.MethodDelete:
			mu.Lock()
			*deletes = append(*deletes, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func withIAMEndpoint(t *testing.T, url string) {
	t.Helper()
	prev := gcsIAMEndpoint
	gcsIAMEndpoint = url
	t.Cleanup(func() { gcsIAMEndpoint = prev })
}

func withVerifyTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := gcsRotationVerifyTimeout
	gcsRotationVerifyTimeout = d
	t.Cleanup(func() { gcsRotationVerifyTimeout = prev })
}

func newTestGCSPublisher(t *testing.T, credJSON, endpoint string, client *http.Client) *gcsPublisher {
	t.Helper()
	creds, err := google.CredentialsFromJSONWithType(context.Background(), []byte(credJSON), google.ServiceAccount, gcsScope)
	require.NoError(t, err)
	return &gcsPublisher{
		tokenSource:     creds.TokenSource,
		credentialsJSON: credJSON,
		endpoint:        endpoint,
		bucket:          "b",
		client:          client,
	}
}

// --- mechanism tests --------------------------------------------------------

func TestGCSPublisher_RotateFullCycle(t *testing.T) {
	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	oldKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj.iam.gserviceaccount.com", "OLDKEY")
	newKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj.iam.gserviceaccount.com", "NEWKEY")

	var deletes []string
	iamSrv := fakeIAMServer(t, newKey, &deletes)
	defer iamSrv.Close()
	withIAMEndpoint(t, iamSrv.URL)

	p := newTestGCSPublisher(t, oldKey, "https://storage.invalid", &http.Client{})

	newFields, prevFields, cleanup, err := p.PrepareRotation(context.Background())
	require.NoError(t, err)
	nk, err := parseGCSServiceAccountKey(newFields["credentials_json"])
	require.NoError(t, err)
	assert.Equal(t, "NEWKEY", nk.PrivateKeyID)
	assert.Equal(t, oldKey, prevFields["credentials_json"], "prevFields carries the pre-rotation value for the CAS")
	assert.Equal(t, "OLDKEY", cleanup["old_key_id"])
	assert.Equal(t, "sa@proj.iam.gserviceaccount.com", cleanup["service_account_email"])

	require.NoError(t, p.CommitRotation(newFields))
	p.mu.RLock()
	assert.Equal(t, newFields["credentials_json"], p.credentialsJSON)
	p.mu.RUnlock()

	require.NoError(t, p.CleanupRotation(context.Background(), cleanup))
	require.Len(t, deletes, 1)
	assert.Contains(t, deletes[0], "OLDKEY")
}

func TestGCSPublisher_RotateVerifyRetry(t *testing.T) {
	oldTokenSrv := fakeTokenServer(t, 0) // old key mints IAM token fine
	defer oldTokenSrv.Close()
	newTokenSrv := fakeTokenServer(t, 1) // new key: first verify attempt fails, then succeeds
	defer newTokenSrv.Close()

	oldKey := genTestSAKeyJSON(t, oldTokenSrv.URL, "proj", "sa@proj", "OLDKEY")
	newKey := genTestSAKeyJSON(t, newTokenSrv.URL, "proj", "sa@proj", "NEWKEY")

	var deletes []string
	iamSrv := fakeIAMServer(t, newKey, &deletes)
	defer iamSrv.Close()
	withIAMEndpoint(t, iamSrv.URL)

	p := newTestGCSPublisher(t, oldKey, "https://storage.invalid", &http.Client{})

	newFields, _, _, err := p.PrepareRotation(context.Background())
	require.NoError(t, err, "prepare must retry verification until the new key is usable")
	nk, err := parseGCSServiceAccountKey(newFields["credentials_json"])
	require.NoError(t, err)
	assert.Equal(t, "NEWKEY", nk.PrivateKeyID)
	assert.Empty(t, deletes, "a key that verifies after retry must not be deleted")
}

func TestGCSPublisher_RotateVerifyFailureDeletesNewKey(t *testing.T) {
	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	oldKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "OLDKEY")
	// A structurally invalid new key: creation succeeds (id fields present) but building a
	// credential from it fails, so verification fails without any network round-trip.
	badNewKey := `{"type":"service_account","project_id":"proj","private_key_id":"NEWKEY","client_email":"sa@proj","private_key":"-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n","token_uri":"` + tokenSrv.URL + `"}`

	var deletes []string
	iamSrv := fakeIAMServer(t, badNewKey, &deletes)
	defer iamSrv.Close()
	withIAMEndpoint(t, iamSrv.URL)

	p := newTestGCSPublisher(t, oldKey, "https://storage.invalid", &http.Client{})

	// Shorten the internal verify timeout so the retry loop gives up quickly. The parent
	// context stays alive (Background), so this is a genuine verify failure — not a
	// cancellation — and the unusable new key is deleted to protect the quota.
	withVerifyTimeout(t, 300*time.Millisecond)
	_, _, _, err := p.PrepareRotation(context.Background())
	require.Error(t, err, "an unusable new key must fail rotation")
	require.Len(t, deletes, 1, "a new key that fails verification must be deleted to protect the quota")
	assert.Contains(t, deletes[0], "NEWKEY")
}

func TestGCSPublisher_RollbackRotation(t *testing.T) {
	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	oldKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "OLDKEY")
	newKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "NEWKEY")
	var deletes []string
	iamSrv := fakeIAMServer(t, newKey, &deletes)
	defer iamSrv.Close()
	withIAMEndpoint(t, iamSrv.URL)

	p := newTestGCSPublisher(t, oldKey, "https://storage.invalid", &http.Client{})

	// Rollback deletes the uncommitted new key, authenticating with the still-live old key.
	require.NoError(t, p.RollbackRotation(context.Background(), map[string]string{"credentials_json": newKey}))
	require.Len(t, deletes, 1)
	assert.Contains(t, deletes[0], "NEWKEY")

	// Empty newFields is a no-op.
	deletes = nil
	require.NoError(t, p.RollbackRotation(context.Background(), map[string]string{}))
	assert.Empty(t, deletes)
}

// TestGCSPublisher_ConcurrentPublishAndCommit exercises the gcsPublisher mutex: a Publish
// reading the live token source must not race a CommitRotation swapping it. Run with -race.
func TestGCSPublisher_ConcurrentPublishAndCommit(t *testing.T) {
	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	stg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer stg.Close()

	k1 := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "K1")
	k2 := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "K2")
	p := newTestGCSPublisher(t, k1, stg.URL, stg.Client())

	var wg sync.WaitGroup
	var commitErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = p.Publish(context.Background(), []byte(`{}`), []byte(`{}`))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			// Don't call require.* off the test goroutine (its FailNow is undefined
			// there); record and assert after the join.
			if err := p.CommitRotation(map[string]string{"credentials_json": k2}); err != nil {
				commitErr = err
				return
			}
		}
	}()
	wg.Wait()
	require.NoError(t, commitErr)
}

func TestGCSPublisher(t *testing.T) {
	type got struct{ method, auth, contentType, cacheControl string }
	seen := map[string]got{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodPut {
			seen[r.URL.Path] = got{r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("Cache-Control")}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Inject a static token source and point the endpoint at the fake server, so the
	// upload path is exercised without a real Google token exchange.
	p := &gcsPublisher{
		tokenSource:  oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		endpoint:     srv.URL,
		bucket:       "warden-oidc",
		prefix:       "prod",
		cacheControl: "public, max-age=60",
		client:       srv.Client(),
	}

	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	disc, ok := seen["/warden-oidc/prod/.well-known/openid-configuration"]
	require.True(t, ok, "discovery object must be PUT")
	assert.Equal(t, http.MethodPut, disc.method)
	assert.Equal(t, "Bearer test-token", disc.auth)
	assert.Equal(t, "application/json", disc.contentType)
	assert.Equal(t, "public, max-age=60", disc.cacheControl)

	jwks, ok := seen["/warden-oidc/prod/oidc/jwks"]
	require.True(t, ok, "jwks object must be PUT")
	assert.Equal(t, "application/json", jwks.contentType)
}
