package core

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raceDriver is a Rotatable, StagedRotationDiscarder test driver that behaves
// like the real ones where it matters here: PrepareRotation snapshots the
// source's current config and adds a new secret, and every cleanup it is asked
// to do is recorded, so a test can tell a retirement of the old credential
// ({"old": ...}) from a discard of a staged one ({"discard": ...}).
type raceDriver struct {
	current func() map[string]string // the source's stored config

	activateAfter  time.Duration
	prepareGate    chan struct{} // when set, PrepareRotation waits for it to close
	commitGate     chan struct{} // when set, CommitRotation waits for it to close
	commitFailures int32         // CommitRotation fails this many times first
	commitStarted  chan struct{} // closed when CommitRotation is first entered

	prepares, commits int32
	secretSeq         int32

	mu       sync.Mutex
	cleanups []map[string]string
	startOne sync.Once
}

func (d *raceDriver) MintCredential(context.Context, *credential.CredSpec) (map[string]any, map[string]any, time.Duration, string, error) {
	return map[string]any{"key": "value"}, nil, 0, "", nil
}
func (d *raceDriver) Revoke(context.Context, string) error { return nil }
func (d *raceDriver) Type() string                         { return "mock" }
func (d *raceDriver) Cleanup(context.Context) error        { return nil }
func (d *raceDriver) SupportsRotation() bool               { return true }

func (d *raceDriver) PrepareRotation(context.Context) (map[string]string, map[string]string, time.Duration, error) {
	atomic.AddInt32(&d.prepares, 1)
	if d.prepareGate != nil {
		<-d.prepareGate
	}
	newConfig := maps.Clone(d.current())
	oldSecret := newConfig["secret_id"]
	newConfig["secret_id"] = fmt.Sprintf("new-%d", atomic.AddInt32(&d.secretSeq, 1))
	return newConfig, map[string]string{"old": oldSecret}, d.activateAfter, nil
}

func (d *raceDriver) CommitRotation(context.Context, map[string]string) error {
	atomic.AddInt32(&d.commits, 1)
	if d.commitStarted != nil {
		d.startOne.Do(func() { close(d.commitStarted) })
	}
	if d.commitGate != nil {
		<-d.commitGate
	}
	if atomic.AddInt32(&d.commitFailures, -1) >= 0 {
		return fmt.Errorf("simulated commit failure")
	}
	return nil
}

func (d *raceDriver) CleanupRotation(_ context.Context, cleanupConfig map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanups = append(d.cleanups, maps.Clone(cleanupConfig))
	return nil
}

func (d *raceDriver) StagedCleanupConfig(_ context.Context, newConfig map[string]string) (map[string]string, error) {
	return map[string]string{"discard": newConfig["secret_id"]}, nil
}

func (d *raceDriver) recordedCleanups() []map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]map[string]string(nil), d.cleanups...)
}

func (d *raceDriver) discarded(secret string) bool {
	for _, c := range d.recordedCleanups() {
		if c["discard"] == secret {
			return true
		}
	}
	return false
}

var (
	_ credential.Rotatable               = (*raceDriver)(nil)
	_ credential.StagedRotationDiscarder = (*raceDriver)(nil)
)

// raceHarness wires a rotation manager, the config store and the system
// backend around one raceDriver behind the "test-source" source.
type raceHarness struct {
	rm      *RotationManager
	core    *Core
	ctx     context.Context
	driver  *raceDriver
	cleanup func()
}

func newRaceHarness(t *testing.T, driver *raceDriver) *raceHarness {
	t.Helper()
	rm, ctx, core, cleanup := createTestRotationManagerWithFactory(t, &mockDriverFactory{driver: driver})
	core.rotationManager = rm
	core.credConfigStore.SetRotationManager(rm)
	driver.current = func() map[string]string {
		src, err := core.credConfigStore.GetSource(ctx, "test-source")
		if err != nil {
			return map[string]string{}
		}
		return src.Config.Map()
	}
	return &raceHarness{rm: rm, core: core, ctx: ctx, driver: driver, cleanup: cleanup}
}

func (h *raceHarness) storedConfig(t *testing.T) credential.Config {
	t.Helper()
	src, err := h.core.credConfigStore.ReloadSource(h.ctx, "test-source")
	require.NoError(t, err)
	return src.Config
}

func (h *raceHarness) entry(t *testing.T) *RotationEntry {
	t.Helper()
	e := h.rm.GetEntry(namespace.RootNamespace.UUID, "test-source")
	require.NotNil(t, e, "entry should be registered")
	return e
}

// operatorUpdate runs the source update handler, as an operator's write would.
func (h *raceHarness) operatorUpdate(t *testing.T, config map[string]any) *logical.Response {
	t.Helper()
	raw := map[string]any{"name": "test-source", "config": config}
	resp, err := h.core.systemBackend.handleCredentialSourceUpdate(h.ctx,
		createTestRequest(logical.UpdateOperation, "cred/sources/test-source", raw),
		createFieldData(h.core.systemBackend.pathCredentials()[0].Fields, raw))
	require.NoError(t, err)
	return resp
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An operator edit made while a rotation is staged used to be reverted when the
// activation wrote back its snapshot, and the staged credential was left live.
// Now the edit discards the staged credential first and survives activation.
func TestRotationRace_EditWhileStagedSurvivesActivation(t *testing.T) {
	d := &raceDriver{activateAfter: 300 * time.Millisecond}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", 50*time.Millisecond))
	waitFor(t, "a staged rotation", func() bool { return h.entry(t).GetState() == StateStaged })
	staged := h.entry(t).GetNewConfig()["secret_id"]

	resp := h.operatorUpdate(t, map[string]any{"key": "edited"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%+v", resp.Data)

	assert.True(t, d.discarded(staged), "the staged credential must be discarded, not left live")

	// Let further rotations run: each now prepares against the edited config.
	time.Sleep(700 * time.Millisecond)
	assert.Equal(t, "edited", h.storedConfig(t).Get("key"), "no activation may write a pre-edit snapshot back")
	assert.NotEqual(t, staged, h.storedConfig(t).Get("secret_id"), "the discarded credential must never be activated")
}

// An operator update arriving while an activation is in flight waits for it,
// then applies on top of the rotated config instead of overwriting it with a
// stale read — which used to leave the source pointing at a deleted key.
func TestRotationRace_UpdateWaitsForInflightActivation(t *testing.T) {
	d := &raceDriver{
		activateAfter: 50 * time.Millisecond,
		commitGate:    make(chan struct{}),
		commitStarted: make(chan struct{}),
	}
	h := newRaceHarness(t, d)
	defer h.cleanup()
	// Deferred after the cleanup so it runs first: a failure below must still
	// release the blocked commit, or stopping the manager waits on it forever.
	release := sync.OnceFunc(func() { close(d.commitGate) })
	defer release()

	// A long period, triggered by hand, so no second rotation can land between
	// the update and the assertions.
	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", time.Hour))
	e := h.entry(t)
	e.mu.Lock()
	e.NextAction = time.Now()
	e.mu.Unlock()
	select {
	case <-d.commitStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("activation never reached commit")
	}
	rotated := h.storedConfig(t).Get("secret_id")
	require.NotEmpty(t, rotated, "the activation persisted before committing")

	done := make(chan *logical.Response, 1)
	go func() { done <- h.operatorUpdate(t, map[string]any{"key": "edited"}) }()

	select {
	case <-done:
		t.Fatal("the update must wait for the in-flight activation")
	case <-time.After(150 * time.Millisecond):
	}

	release()
	resp := <-done
	require.Equal(t, http.StatusOK, resp.StatusCode, "%+v", resp.Data)

	stored := h.storedConfig(t)
	assert.Equal(t, "edited", stored.Get("key"))
	assert.Equal(t, rotated, stored.Get("secret_id"), "the update must land on top of the rotated credential")
}

// A commit that fails after the persist leaves the staged credential live. The
// retry must resume at commit; treating the changed config as someone else's
// edit would discard — delete — the key the source now uses.
func TestRotationRace_CommitFailureAfterPersistResumes(t *testing.T) {
	d := &raceDriver{activateAfter: 50 * time.Millisecond, commitFailures: 1}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", time.Hour))
	e := h.entry(t)
	e.mu.Lock()
	e.NextAction = time.Now()
	e.mu.Unlock()

	waitFor(t, "the activation to complete", func() bool {
		return atomic.LoadInt32(&d.commits) >= 2 && e.GetState() == StateIdle
	})

	live := h.storedConfig(t).Get("secret_id")
	assert.Equal(t, "new-1", live)
	assert.False(t, d.discarded(live), "the live credential must never be discarded")
	assert.Contains(t, d.recordedCleanups(), map[string]string{"old": ""}, "the replaced credential is retired")
}

// Unregistering while a prepare is in flight used to let the job finish, stage
// a credential nothing would activate, and write the removed entry back.
func TestRotationRace_UnregisterDuringInflightPrepare(t *testing.T) {
	d := &raceDriver{activateAfter: time.Hour, prepareGate: make(chan struct{})}
	h := newRaceHarness(t, d)
	defer h.cleanup()
	release := sync.OnceFunc(func() { close(d.prepareGate) })
	defer release() // see TestRotationRace_UpdateWaitsForInflightActivation

	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", 50*time.Millisecond))
	waitFor(t, "the prepare to start", func() bool { return atomic.LoadInt32(&d.prepares) == 1 })
	e := h.entry(t)

	// Simulates an unregister that does not take the source lock, as
	// namespace deletion does; the operator paths all hold it.
	require.NoError(t, h.rm.UnregisterSource(h.ctx, "test-source"))
	release()

	waitFor(t, "the prepared credential to be discarded", func() bool { return d.discarded("new-1") })
	waitFor(t, "the job to finish", func() bool { return atomic.LoadInt32(&e.inflight) == 0 })

	raw, err := h.rm.storage.Get(context.Background(), h.rm.entryStoragePath(e))
	require.NoError(t, err)
	assert.Nil(t, raw, "an unregistered entry must not be written back")
	assert.Empty(t, h.storedConfig(t).Get("secret_id"), "the source config must not be touched")
}

// A failed entry still holding staged data retries the activation rather than
// preparing over it, which used to lose track of the staged credential.
func TestRotationRace_FailedWithStagedRetriesActivation(t *testing.T) {
	d := &raceDriver{activateAfter: time.Hour}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", time.Hour))
	e := h.entry(t)
	base := h.storedConfig(t)
	e.mu.Lock()
	e.State = StateFailed
	e.NewConfig = base.With("secret_id", "staged").Map()
	e.CleanupConfig = map[string]string{"old": ""}
	e.BaseConfigHash = base.Hash()
	e.NextAction = time.Now()
	e.mu.Unlock()
	atomic.AddInt64(&h.rm.failedCount, 1)

	waitFor(t, "the activation", func() bool { return h.storedConfig(t).Get("secret_id") == "staged" })
	assert.Zero(t, atomic.LoadInt32(&d.prepares), "no prepare may run over the staged data")
	assert.Equal(t, int64(0), h.rm.GetFailedCount())
}

// A staged activation keeps its schedule when the period changes. Moving it
// out by a whole period left both credentials live for that long.
func TestRotationRace_PeriodChangeKeepsStagedActivation(t *testing.T) {
	d := &raceDriver{activateAfter: time.Hour}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", 50*time.Millisecond))
	waitFor(t, "a staged rotation", func() bool { return h.entry(t).GetState() == StateStaged })
	activateAt := h.entry(t).GetNextAction()

	require.NoError(t, h.rm.UpdateRotationPeriod(h.ctx, "test-source", 48*time.Hour))
	assert.Equal(t, activateAt, h.entry(t).GetNextAction())
}

// Two failed cleanups for one source used to share a single storage slot, so
// the second hid the first and its credential was never deleted.
func TestRotationRace_FailedCleanupsDoNotOverwrite(t *testing.T) {
	d := &raceDriver{}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	e := &RotationEntry{EntryType: EntryTypeSource, SourceName: "test-source", Namespace: namespace.RootNamespace.UUID}
	h.rm.persistFailedCleanup(e, cleanupKindCleanup, map[string]string{"old": "a"}, "")
	h.rm.persistFailedCleanup(e, cleanupKindCleanup, map[string]string{"old": "b"}, "")

	keys, err := h.rm.storage.List(context.Background(), rotationCleanupPath+namespace.RootNamespace.UUID+"/")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

// A pending discard only retries while the source still holds the config that
// can authenticate it. Once the config moved on it is handed to the operator,
// not retried for a week through a driver that cannot do it.
func TestRotationRace_PendingDiscardAbandonedAfterConfigChange(t *testing.T) {
	d := &raceDriver{}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	e := &RotationEntry{EntryType: EntryTypeSource, SourceName: "test-source", Namespace: namespace.RootNamespace.UUID}
	h.rm.persistFailedCleanup(e, cleanupKindDiscard, map[string]string{"discard": "x"}, "stale-hash")
	h.rm.retryFailedCleanups()

	assert.False(t, d.discarded("x"), "no driver may be asked to discard with the wrong credentials")
	keys, err := h.rm.storage.List(context.Background(), rotationCleanupPath+namespace.RootNamespace.UUID+"/")
	require.NoError(t, err)
	assert.Empty(t, keys, "the record is dropped once reported")
}

// specCleanupDriver records which cleanup method a retry used.
type specCleanupDriver struct {
	raceDriver
	specCleanups []map[string]string
}

func (d *specCleanupDriver) SupportsSpecRotation() bool { return true }
func (d *specCleanupDriver) PrepareSpecRotation(context.Context, *credential.CredSpec) (map[string]string, map[string]string, time.Duration, error) {
	return nil, nil, 0, fmt.Errorf("not used")
}
func (d *specCleanupDriver) CommitSpecRotation(context.Context, *credential.CredSpec, map[string]string) error {
	return nil
}
func (d *specCleanupDriver) CleanupSpecRotation(_ context.Context, cleanupConfig map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.specCleanups = append(d.specCleanups, maps.Clone(cleanupConfig))
	return nil
}

// A spec's pending cleanup used to be retried through the source method, which
// reads a different config and acts on the source's own credential. Both the
// current record format and the one written before SpecName existed are
// routed to CleanupSpecRotation.
func TestRotationRace_SpecCleanupRetryUsesSpecMethod(t *testing.T) {
	d := &specCleanupDriver{}
	rm, _, _, cleanup := createTestRotationManagerWithFactory(t, &mockDriverFactory{driver: d})
	defer cleanup()

	nsID := namespace.RootNamespace.UUID
	e := &RotationEntry{EntryType: EntryTypeSpec, SpecName: "s", SourceName: "test-source", Namespace: nsID}
	rm.persistFailedCleanup(e, cleanupKindCleanup, map[string]string{"client_id": "app", "old_secret_id": "current"}, "")

	// The legacy record: old path, the spec's name inside the config, no spec_name.
	legacy, err := json.Marshal(map[string]any{
		"source_name":    "test-source",
		"source_type":    EntryTypeSpec,
		"namespace":      nsID,
		"cleanup_config": map[string]string{"client_id": "app", "old_secret_id": "legacy", "_spec_name": "s"},
		"attempts":       3,
		"created_at":     time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, rm.storage.Put(context.Background(), &sdklogical.StorageEntry{
		Key: rotationCleanupPath + nsID + "/spec:s", Value: legacy,
	}))

	rm.retryFailedCleanups()

	d.mu.Lock()
	defer d.mu.Unlock()
	assert.Empty(t, d.cleanups, "the source method must not be used for a spec cleanup")
	assert.ElementsMatch(t, []map[string]string{
		{"client_id": "app", "old_secret_id": "current"},
		{"client_id": "app", "old_secret_id": "legacy"},
	}, d.specCleanups, "the legacy _spec_name marker must not reach the driver")
}

// raceSpecDriver adds staged spec rotation to raceDriver: PrepareSpecRotation
// snapshots the spec's stored config with a new secret, as the Azure driver
// does for its workload credentials.
type raceSpecDriver struct {
	raceDriver
	specCurrent func() map[string]string
}

func (d *raceSpecDriver) SupportsSpecRotation() bool { return true }
func (d *raceSpecDriver) PrepareSpecRotation(context.Context, *credential.CredSpec) (map[string]string, map[string]string, time.Duration, error) {
	atomic.AddInt32(&d.prepares, 1)
	newConfig := maps.Clone(d.specCurrent())
	oldSecret := newConfig["secret_id"]
	newConfig["secret_id"] = fmt.Sprintf("spec-new-%d", atomic.AddInt32(&d.secretSeq, 1))
	return newConfig, map[string]string{"old": oldSecret}, d.activateAfter, nil
}
func (d *raceSpecDriver) CommitSpecRotation(context.Context, *credential.CredSpec, map[string]string) error {
	atomic.AddInt32(&d.commits, 1)
	return nil
}
func (d *raceSpecDriver) CleanupSpecRotation(ctx context.Context, cleanupConfig map[string]string) error {
	return d.CleanupRotation(ctx, cleanupConfig)
}
func (d *raceSpecDriver) StagedSpecCleanupConfig(_ context.Context, newConfig map[string]string) (map[string]string, error) {
	return map[string]string{"discard": newConfig["secret_id"]}, nil
}

var _ credential.StagedSpecRotationDiscarder = (*raceSpecDriver)(nil)

// newRaceSpecHarness adds a rotating spec, "rot-spec", on test-source.
func newRaceSpecHarness(t *testing.T, d *raceSpecDriver) *raceHarness {
	t.Helper()
	h := newRaceHarness(t, &d.raceDriver)
	// The factory must hand out the spec-rotating driver, not the embedded one.
	factory, err := h.core.credentialDriverRegistry.GetFactory("mock")
	require.NoError(t, err)
	factory.(*mockDriverFactory).driver = d
	require.NoError(t, h.core.credentialTypeRegistry.Register(&testCredentialType{typeName: "rotating_type", requiresRotation: true}))

	require.NoError(t, h.core.credConfigStore.CreateSpec(h.ctx, &credential.CredSpec{
		Name:           "rot-spec",
		Type:           "rotating_type",
		Source:         "test-source",
		Config:         credential.NewConfig(map[string]string{"key": "value"}),
		RotationPeriod: 24 * time.Hour,
	}))
	d.specCurrent = func() map[string]string {
		spec, err := h.core.credConfigStore.GetSpec(h.ctx, "rot-spec")
		if err != nil {
			return map[string]string{}
		}
		return spec.Config.Map()
	}
	return h
}

func (h *raceHarness) specEntry(t *testing.T) *RotationEntry {
	t.Helper()
	v, ok := h.rm.entries.Load(buildSpecKey(namespace.RootNamespace.UUID, "rot-spec"))
	require.True(t, ok, "spec entry should be registered")
	return v.(*RotationEntry)
}

func (h *raceHarness) stageSpecNow(t *testing.T) string {
	t.Helper()
	e := h.specEntry(t)
	e.mu.Lock()
	e.NextAction = time.Now()
	e.mu.Unlock()
	waitFor(t, "a staged spec rotation", func() bool { return e.GetState() == StateStaged })
	return e.GetNewConfig()["secret_id"]
}

// The spec path has the same race as the source path: an operator's spec edit
// discards the staged spec rotation first, through the source's driver, and
// survives the activation that follows.
func TestRotationRace_SpecEditWhileStagedSurvives(t *testing.T) {
	d := &raceSpecDriver{raceDriver: raceDriver{activateAfter: 300 * time.Millisecond}}
	h := newRaceSpecHarness(t, d)
	defer h.cleanup()

	staged := h.stageSpecNow(t)

	raw := map[string]any{"name": "rot-spec", "config": map[string]any{"key": "edited"}}
	resp, err := h.core.systemBackend.handleCredentialSpecUpdate(h.ctx,
		createTestRequest(logical.UpdateOperation, "cred/specs/rot-spec", raw),
		createFieldData(h.core.systemBackend.pathCredentials()[2].Fields, raw))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%+v", resp.Data)

	assert.True(t, d.discarded(staged), "the staged spec credential must be discarded")

	// The entry re-prepares against the edited spec, and that activation keeps the edit.
	waitFor(t, "the re-prepared activation", func() bool {
		spec, err := h.core.credConfigStore.ReloadSpec(h.ctx, "rot-spec")
		return err == nil && spec.Config.Get("secret_id") != ""
	})
	spec, err := h.core.credConfigStore.ReloadSpec(h.ctx, "rot-spec")
	require.NoError(t, err)
	assert.Equal(t, "edited", spec.Config.Get("key"))
	assert.NotEqual(t, staged, spec.Config.Get("secret_id"))
}

// Changing a spec's period re-registers its entry. Replacing an entry used to
// drop its staged data, and with it the only record of the staged credential.
func TestRotationRace_SpecPeriodChangeDiscardsStaged(t *testing.T) {
	d := &raceSpecDriver{raceDriver: raceDriver{activateAfter: time.Hour}}
	h := newRaceSpecHarness(t, d)
	defer h.cleanup()

	staged := h.stageSpecNow(t)
	old := h.specEntry(t)

	spec, err := h.core.credConfigStore.GetSpec(h.ctx, "rot-spec")
	require.NoError(t, err)
	updated := *spec
	updated.RotationPeriod = 48 * time.Hour
	require.NoError(t, h.core.credConfigStore.UpdateSpec(h.ctx, &updated))

	assert.True(t, d.discarded(staged), "the replaced entry's staged credential must be discarded")
	assert.True(t, old.isRemoved())
	assert.NotSame(t, old, h.specEntry(t))
}

// Namespace deletion unregisters every entry before clearing the sources, so
// a staged credential can still be discarded by the driver that created it.
func TestRotationRace_NamespaceDeleteDiscardsStaged(t *testing.T) {
	d := &raceDriver{activateAfter: time.Hour}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	require.NoError(t, h.rm.RegisterSource(h.ctx, "test-source", "mock", 50*time.Millisecond))
	waitFor(t, "a staged rotation", func() bool { return h.entry(t).GetState() == StateStaged })
	staged := h.entry(t).GetNewConfig()["secret_id"]

	require.NoError(t, h.rm.UnregisterByNamespace(namespace.RootNamespace.UUID))

	assert.True(t, d.discarded(staged))
	assert.Nil(t, h.rm.GetEntry(namespace.RootNamespace.UUID, "test-source"))
}

// Restore checks entries against the config: one for a source that is gone is
// dropped; one for a source that no longer rotates discards its staged
// credential from the tick loop, then is dropped.
func TestRotationRace_RestoreDropsOrphans(t *testing.T) {
	d := &raceDriver{}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	nsID := namespace.RootNamespace.UUID
	gone := &RotationEntry{EntryType: EntryTypeSource, SourceName: "gone", SourceType: "mock", Namespace: nsID,
		RotationPeriod: time.Hour, NextAction: time.Now().Add(time.Hour), State: StateStaged,
		NewConfig: map[string]string{"secret_id": "orphan"}}
	// test-source has no rotation_period, so it is not eligible.
	ineligible := &RotationEntry{EntryType: EntryTypeSource, SourceName: "test-source", SourceType: "mock", Namespace: nsID,
		RotationPeriod: time.Hour, NextAction: time.Now().Add(time.Hour), State: StateStaged,
		NewConfig: map[string]string{"key": "value", "secret_id": "stale"}}
	require.NoError(t, h.rm.persistEntry(gone))
	require.NoError(t, h.rm.persistEntry(ineligible))

	require.NoError(t, h.rm.Restore(h.ctx))

	assert.Nil(t, h.rm.GetEntry(nsID, "gone"), "an entry for a deleted source is dropped at restore")
	waitFor(t, "the staged credential to be discarded", func() bool { return d.discarded("stale") })
	waitFor(t, "the entry to be dropped", func() bool { return h.rm.GetEntry(nsID, "test-source") == nil })

	for _, e := range []*RotationEntry{gone, ineligible} {
		raw, err := h.rm.storage.Get(context.Background(), h.rm.entryStoragePath(e))
		require.NoError(t, err)
		assert.Nil(t, raw)
	}
}

// A conditional update refuses to overwrite a config that changed since the
// caller read it, and leaves the cache showing what storage holds.
func TestCredentialConfigStore_UpdateSourceExpectedConfigHash(t *testing.T) {
	d := &raceDriver{}
	h := newRaceHarness(t, d)
	defer h.cleanup()

	stale := h.storedConfig(t).Hash()
	current, err := h.core.credConfigStore.GetSource(h.ctx, "test-source")
	require.NoError(t, err)

	moved := *current
	moved.Config = current.Config.With("key", "moved")
	require.NoError(t, h.core.credConfigStore.UpdateSource(h.ctx, &moved))

	late := *current
	late.Config = current.Config.With("key", "late")
	err = h.core.credConfigStore.UpdateSource(h.ctx, &late, UpdateSourceOptions{ExpectedConfigHash: stale})
	require.ErrorIs(t, err, ErrConfigChanged)

	cached, err := h.core.credConfigStore.GetSource(h.ctx, "test-source")
	require.NoError(t, err)
	assert.Equal(t, "moved", cached.Config.Get("key"))
}
