package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// --- loop-level test: generic persist with s3 (two-field) credentials -------

func TestRotatePublisherCredential_S3(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	st := &fakeAWSState{existingKeys: []string{"AKIAOLD"}, newKeyID: "AKIANEW", newSecret: "newsecret"}
	srv := st.server(t)
	defer srv.Close()
	withAWSIAMEndpoint(t, srv.URL)

	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled:   true,
		IssuerURL: "https://iss.example",
		Publisher: publisherConfig{
			Type: "s3", Bucket: "b", Region: "us-east-1", Endpoint: srv.URL,
			AccessKeyID: "AKIAOLD", SecretAccessKey: "oldsecret", RotationPeriod: "24h",
		},
	}))

	p := newTestS3Publisher(srv.URL, "AKIAOLD", "oldsecret")
	require.NoError(t, core.rotatePublisherCredential(ctx, p))

	// The generalized persist wrote BOTH new credential fields.
	cfg, err := loadIssuerConfig(ctx, storage)
	require.NoError(t, err)
	assert.Equal(t, "AKIANEW", cfg.Publisher.AccessKeyID)
	assert.Equal(t, "newsecret", cfg.Publisher.SecretAccessKey)

	// Live publisher swapped, old key deleted.
	p.mu.RLock()
	assert.Equal(t, "AKIANEW", p.accessKeyID)
	p.mu.RUnlock()
	assert.Contains(t, st.deleted, "AKIAOLD")
}
