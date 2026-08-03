package core

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
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	newFields, cleanup, err := p.PrepareRotation(context.Background())
	require.NoError(t, err)
	nk, err := parseGCSServiceAccountKey(newFields["credentials_json"])
	require.NoError(t, err)
	assert.Equal(t, "NEWKEY", nk.PrivateKeyID)
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

	newFields, _, err := p.PrepareRotation(context.Background())
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
	_, _, err := p.PrepareRotation(context.Background())
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

// --- loop / state tests -----------------------------------------------------

func TestPublisherRotationFirstTick(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	// No state: seed LastRotatedAt=now and schedule a full period out.
	ft, err := core.publisherRotationFirstTick(ctx, storage, time.Hour)
	require.NoError(t, err)
	assert.InDelta(t, time.Hour.Seconds(), ft.Seconds(), 5)

	// State now persisted: anchored on it, still ~a period out (restart within a period
	// must not re-rotate).
	ft2, err := core.publisherRotationFirstTick(ctx, storage, time.Hour)
	require.NoError(t, err)
	assert.InDelta(t, time.Hour.Seconds(), ft2.Seconds(), 5)

	// A due-in-the-past anchor yields a non-positive delay (rotate promptly).
	require.NoError(t, savePublisherRotationState(ctx, storage, &publisherRotationState{LastRotatedAt: time.Now().Add(-2 * time.Hour)}))
	ft3, err := core.publisherRotationFirstTick(ctx, storage, time.Hour)
	require.NoError(t, err)
	assert.LessOrEqual(t, ft3, time.Duration(0))
}

func TestRotatePublisherCredential_PersistsSwapsAndCleans(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	oldKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "OLDKEY")
	newKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "NEWKEY")
	var deletes []string
	iamSrv := fakeIAMServer(t, newKey, &deletes)
	defer iamSrv.Close()
	withIAMEndpoint(t, iamSrv.URL)

	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled:   true,
		IssuerURL: "https://iss.example",
		Publisher: publisherConfig{Type: "gcs", Bucket: "b", CredentialsJSON: oldKey, RotationPeriod: "24h"},
	}))

	p := newTestGCSPublisher(t, oldKey, "https://storage.invalid", &http.Client{})
	rotErr := core.rotatePublisherCredential(ctx, p)
	require.NoError(t, rotErr)
	core.recordPublisherRotationOutcome(ctx, rotErr) // the loop records the outcome after each cycle

	// Config persisted with the new key.
	cfg, err := loadIssuerConfig(ctx, storage)
	require.NoError(t, err)
	pk, err := parseGCSServiceAccountKey(cfg.Publisher.CredentialsJSON)
	require.NoError(t, err)
	assert.Equal(t, "NEWKEY", pk.PrivateKeyID)

	// Live publisher swapped in place.
	p.mu.RLock()
	livePK, err := parseGCSServiceAccountKey(p.credentialsJSON)
	p.mu.RUnlock()
	require.NoError(t, err)
	assert.Equal(t, "NEWKEY", livePK.PrivateKeyID)

	// Old key deleted, and the schedule anchor advanced.
	require.Len(t, deletes, 1)
	assert.Contains(t, deletes[0], "OLDKEY")
	st, err := loadPublisherRotationState(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.WithinDuration(t, time.Now(), st.LastRotatedAt, 5*time.Second)
	assert.Empty(t, st.LastError)
}

// TestRecordPublisherRotationOutcome verifies the state doc tracks rotation health: a
// success advances the anchor and clears the error; a subsequent failure records the error
// while preserving the last-success anchor (so a failing cycle neither resets the schedule
// nor hides the reason).
func TestRecordPublisherRotationOutcome(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	// Success.
	core.recordPublisherRotationOutcome(ctx, nil)
	st, err := loadPublisherRotationState(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.WithinDuration(t, time.Now(), st.LastRotatedAt, 5*time.Second)
	assert.Empty(t, st.LastError)
	lastSuccess := st.LastRotatedAt

	// Failure: error recorded, anchor preserved (schedule stays on last success).
	core.recordPublisherRotationOutcome(ctx, assertAnError())
	st, err = loadPublisherRotationState(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, lastSuccess, st.LastRotatedAt, "a failure must not advance the schedule anchor")
	assert.NotEmpty(t, st.LastError)
	assert.False(t, st.LastErrorAt.IsZero())

	// Recovery clears the error.
	core.recordPublisherRotationOutcome(ctx, nil)
	st, err = loadPublisherRotationState(ctx, storage)
	require.NoError(t, err)
	assert.Empty(t, st.LastError)
	assert.True(t, st.LastErrorAt.IsZero())
}

func assertAnError() error { return fmt.Errorf("prepare: boom") }

// TestRotatePublisherCredential_SupersededByConfigChange verifies the compare-and-swap
// guard: if the stored credential changed while a rotation was in flight (e.g. an operator
// swapped credentials_json), the persist aborts, the operator's key stands, and the newly
// minted key is rolled back rather than silently discarding the operator's change.
func TestRotatePublisherCredential_SupersededByConfigChange(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	oldKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "OLDKEY")     // what the cycle chained from
	otherKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "OTHERKEY") // operator's concurrent replacement
	newKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "NEWKEY")     // minted by this cycle
	var deletes []string
	iamSrv := fakeIAMServer(t, newKey, &deletes)
	defer iamSrv.Close()
	withIAMEndpoint(t, iamSrv.URL)

	// Stored config already holds the operator's replacement key, not the one the cycle
	// started from — simulating a config write that landed during PrepareRotation.
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled:   true,
		IssuerURL: "https://iss.example",
		Publisher: publisherConfig{Type: "gcs", Bucket: "b", CredentialsJSON: otherKey, RotationPeriod: "24h"},
	}))

	p := newTestGCSPublisher(t, oldKey, "https://storage.invalid", &http.Client{})
	err := core.rotatePublisherCredential(ctx, p)
	require.Error(t, err, "rotation must abort when the stored credential changed underneath it")

	// The operator's key stands.
	cfg, err := loadIssuerConfig(ctx, storage)
	require.NoError(t, err)
	pk, err := parseGCSServiceAccountKey(cfg.Publisher.CredentialsJSON)
	require.NoError(t, err)
	assert.Equal(t, "OTHERKEY", pk.PrivateKeyID, "operator's replacement key must not be overwritten")

	// The just-minted key was rolled back (deleted), not left as a live orphan.
	require.Len(t, deletes, 1)
	assert.Contains(t, deletes[0], "NEWKEY")
}

func TestSetupOIDCIssuer_PublisherRotationLifecycle(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	tokenSrv := fakeTokenServer(t, 0)
	defer tokenSrv.Close()
	stg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer stg.Close()
	saKey := genTestSAKeyJSON(t, tokenSrv.URL, "proj", "sa@proj", "K1")

	// Enabled gcs publisher with rotation on; a long period keeps the loop from firing
	// during the test (we only assert it starts/stops). Endpoint points at a fake so the
	// initial publish does not reach the real Google.
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled:   true,
		IssuerURL: "https://iss.example",
		Publisher: publisherConfig{Type: "gcs", Bucket: "b", CredentialsJSON: saKey, Endpoint: stg.URL, RotationPeriod: "720h"},
	}))
	require.NoError(t, core.setupOIDCIssuer(ctx, false))

	core.oidcMu.RLock()
	running := core.oidcPubRotationCancel != nil
	core.oidcMu.RUnlock()
	assert.True(t, running, "rotation loop must be running when rotation_period is set")

	// Enabling seeds the schedule anchor.
	st, err := loadPublisherRotationState(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, st, "enabling rotation must seed the schedule anchor")

	// Disable rotation and re-setup: the loop must stop and the anchor must be cleared so
	// a later re-enable starts a fresh period instead of firing off a stale timestamp.
	cfg, err := loadIssuerConfig(ctx, storage)
	require.NoError(t, err)
	cfg.Publisher.RotationPeriod = ""
	require.NoError(t, saveIssuerConfig(ctx, storage, cfg))
	require.NoError(t, core.setupOIDCIssuer(ctx, false))

	core.oidcMu.RLock()
	running2 := core.oidcPubRotationCancel != nil
	core.oidcMu.RUnlock()
	assert.False(t, running2, "rotation loop must stop when rotation_period is cleared")

	st2, err := loadPublisherRotationState(ctx, storage)
	require.NoError(t, err)
	assert.Nil(t, st2, "disabling rotation must clear the schedule anchor")

	require.NoError(t, core.stopOIDCIssuer())
}
