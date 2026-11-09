package credential

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingFactory builds a driver the way a factory that logs in does: it holds
// until the test releases it. entered receives once per Create, on entry.
type blockingFactory struct {
	recordingFactory
	entered chan struct{}
	release chan struct{}
	creates atomic.Int32
	fail    error
	panics  bool

	mu    sync.Mutex
	built []*cleanupCountingDriver
}

func newBlockingFactory() *blockingFactory {
	return &blockingFactory{entered: make(chan struct{}, 16), release: make(chan struct{})}
}

func (f *blockingFactory) Type() string { return "blocking" }
func (f *blockingFactory) Create(config Config, _ *logger.GatedLogger) (SourceDriver, error) {
	f.creates.Add(1)
	f.entered <- struct{}{}
	<-f.release
	if f.panics {
		panic("factory blew up")
	}
	if f.fail != nil {
		return nil, f.fail
	}
	d := &cleanupCountingDriver{recordingDriver: recordingDriver{config: config}}
	f.mu.Lock()
	f.built = append(f.built, d)
	f.mu.Unlock()
	return d, nil
}

type cleanupCountingDriver struct {
	recordingDriver
	cleanups atomic.Int32
}

func (d *cleanupCountingDriver) Cleanup(context.Context) error {
	d.cleanups.Add(1)
	return nil
}

type buildEnv struct {
	registry    *DriverRegistry
	coordinator *DriverCoordinator
	factory     *blockingFactory
	ctx         context.Context
}

func newBuildEnv(t *testing.T) *buildEnv {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	factory := newBlockingFactory()
	require.NoError(t, registry.RegisterFactory(factory))
	require.NoError(t, registry.RegisterFactory(&recordingFactory{}))

	store := newMockConfigStore()
	store.sources["slow"] = &CredSource{Name: "slow", Type: "blocking", Config: NewConfig(map[string]string{"version": "v1"})}
	store.sources["fast"] = &CredSource{Name: "fast", Type: "recording", Config: NewConfig(map[string]string{"version": "v1"})}

	return &buildEnv{
		registry:    registry,
		coordinator: NewDriverCoordinator(registry, store, log),
		factory:     factory,
		ctx:         namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace),
	}
}

func (e *buildEnv) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-e.factory.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the factory was never entered")
	}
}

type gotDriver struct {
	driver SourceDriver
	err    error
}

// getAsync runs GetOrCreateDriver on its own goroutine. Assertions stay on the test
// goroutine: a FailNow from here would only end this goroutine and hang the test.
func (e *buildEnv) getAsync(source string) <-chan gotDriver {
	out := make(chan gotDriver, 1)
	go func() {
		d, err := e.coordinator.GetOrCreateDriver(e.ctx, source)
		out <- gotDriver{d, err}
	}()
	return out
}

func (e *buildEnv) receive(t *testing.T, ch <-chan gotDriver) gotDriver {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("GetOrCreateDriver did not return")
		return gotDriver{}
	}
}

func (e *buildEnv) buildingCount() int {
	e.registry.mu.RLock()
	defer e.registry.mu.RUnlock()
	return len(e.registry.building)
}

// A factory that logs in runs without the registry lock: one slow upstream must
// not stall drivers, or lookups, for any other source.
func TestCreateDriver_SlowBuildDoesNotBlockOtherSources(t *testing.T) {
	e := newBuildEnv(t)
	go func() { _, _ = e.coordinator.GetOrCreateDriver(e.ctx, "slow") }()
	e.waitEntered(t)
	defer close(e.factory.release)

	done := make(chan error, 1)
	go func() {
		_, err := e.coordinator.GetOrCreateDriver(e.ctx, "fast")
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("another source's driver waited on the slow build")
	}

	_, ok := e.registry.GetDriver(e.ctx, "fast")
	assert.True(t, ok)
}

// Concurrent misses on one source share a single build and a single instance.
func TestCreateDriver_ConcurrentCallersShareOneBuild(t *testing.T) {
	e := newBuildEnv(t)
	const callers = 16
	drivers := make([]SourceDriver, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d, err := e.coordinator.GetOrCreateDriver(e.ctx, "slow")
			if err != nil {
				t.Errorf("caller %d: %v", idx, err)
				return
			}
			drivers[idx] = d
		}(i)
	}
	e.waitEntered(t)
	// Give the other callers time to find the build in flight before it settles.
	time.Sleep(50 * time.Millisecond)
	close(e.factory.release)
	wg.Wait()

	assert.EqualValues(t, 1, e.factory.creates.Load(), "the driver must be built exactly once")
	for i := 1; i < callers; i++ {
		assert.Same(t, drivers[0], drivers[i], "all callers must share one instance")
	}
	assert.Zero(t, e.buildingCount())
}

// A source invalidated while its driver is being built must not get that driver
// installed: it was built from the superseded config. It is cleaned up, and the
// caller builds again from the current one.
func TestCreateDriver_InvalidatedBuildIsCleanedUpAndRebuilt(t *testing.T) {
	e := newBuildEnv(t)
	result := e.getAsync("slow")
	e.waitEntered(t)

	require.NoError(t, e.registry.CloseDriver(e.ctx, "slow"))
	close(e.factory.release) // the first build settles stale; the retry is not held

	got := e.receive(t, result)
	require.NoError(t, got.err)
	installed := got.driver
	assert.EqualValues(t, 2, e.factory.creates.Load(), "the stale build is refused and the driver rebuilt")
	cached, ok := e.registry.GetDriver(e.ctx, "slow")
	require.True(t, ok)
	assert.Same(t, installed, cached)
	assert.Zero(t, installed.(*cleanupCountingDriver).cleanups.Load(), "the installed driver is live")
	e.factory.mu.Lock()
	stale := e.factory.built[0]
	e.factory.mu.Unlock()
	assert.NotSame(t, stale, installed)
	assert.EqualValues(t, 1, stale.cleanups.Load(), "the driver built from stale config must be cleaned up")
	assert.Zero(t, e.buildingCount())
}

// A caller that gives up stops waiting at once; the build it was waiting on still
// completes and installs its driver.
func TestCreateDriver_WaiterCancellationDoesNotAbortTheBuild(t *testing.T) {
	e := newBuildEnv(t)
	go func() { _, _ = e.coordinator.GetOrCreateDriver(e.ctx, "slow") }()
	e.waitEntered(t)

	gen, err := e.registry.Generation(e.ctx, "slow")
	require.NoError(t, err)
	waiterCtx, cancel := context.WithCancel(e.ctx)
	cancel()
	_, _, err = e.registry.CreateDriver(waiterCtx, "slow",
		&CredSource{Name: "slow", Type: "blocking", Config: NewConfig(nil)}, gen)
	assert.ErrorIs(t, err, context.Canceled)

	close(e.factory.release)
	assert.Eventually(t, func() bool {
		_, ok := e.registry.GetDriver(e.ctx, "slow")
		return ok
	}, 5*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, 1, e.factory.creates.Load())
}

// A failed build hands its error to every caller waiting on it and leaves nothing
// in flight, so the next miss builds afresh.
func TestCreateDriver_FailedBuildReleasesItsWaiters(t *testing.T) {
	e := newBuildEnv(t)
	e.factory.fail = errors.New("login refused")

	callers := []<-chan gotDriver{e.getAsync("slow"), e.getAsync("slow")}
	e.waitEntered(t)
	time.Sleep(50 * time.Millisecond)
	close(e.factory.release)

	for _, c := range callers {
		assert.ErrorIs(t, e.receive(t, c).err, ErrDriverCreationFailed)
	}
	assert.Zero(t, e.buildingCount())
	_, ok := e.registry.GetDriver(e.ctx, "slow")
	assert.False(t, ok)
}

// A factory that panics still releases its waiters and leaves nothing in flight.
func TestCreateDriver_PanickingFactoryReleasesItsWaiters(t *testing.T) {
	e := newBuildEnv(t)
	e.factory.panics = true

	go func() {
		defer func() { _ = recover() }()
		_, _ = e.coordinator.GetOrCreateDriver(e.ctx, "slow")
	}()
	e.waitEntered(t)

	waiter := make(chan error, 1)
	go func() {
		// Should it run late and start a build of its own, that build panics too:
		// recovered, so the test reports it rather than the process dying.
		defer func() { _ = recover() }()
		gen, _ := e.registry.Generation(e.ctx, "slow")
		_, _, err := e.registry.CreateDriver(e.ctx, "slow",
			&CredSource{Name: "slow", Type: "blocking", Config: NewConfig(nil)}, gen)
		waiter <- err
	}()
	time.Sleep(50 * time.Millisecond)
	close(e.factory.release)

	select {
	case err := <-waiter:
		assert.ErrorIs(t, err, ErrDriverCreationFailed)
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter was left hanging by a panicking factory")
	}
	assert.EqualValues(t, 1, e.factory.creates.Load(), "the waiter must have shared the panicking build")
	assert.Eventually(t, func() bool { return e.buildingCount() == 0 }, 5*time.Second, 10*time.Millisecond)
}

// A caller that joins a build which is then refused gets the refusal, not the
// stale driver, and re-reads through the coordinator.
func TestCreateDriver_WaiterOnARefusedBuildIsRefused(t *testing.T) {
	e := newBuildEnv(t)
	leader := e.getAsync("slow")
	e.waitEntered(t)

	gen, err := e.registry.Generation(e.ctx, "slow")
	require.NoError(t, err)
	waiter := make(chan error, 1)
	go func() {
		_, _, err := e.registry.CreateDriver(e.ctx, "slow",
			&CredSource{Name: "slow", Type: "blocking", Config: NewConfig(nil)}, gen)
		waiter <- err
	}()
	time.Sleep(50 * time.Millisecond) // let it join the build in flight

	// Invalidates the build; the waiter's own observed generation goes stale too.
	require.NoError(t, e.registry.CloseDriver(e.ctx, "slow"))
	close(e.factory.release)

	select {
	case err := <-waiter:
		assert.ErrorIs(t, err, ErrDriverConfigChanged)
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter did not return")
	}
	require.NoError(t, e.receive(t, leader).err, "the coordinator rebuilds from the current config")
}

// When the node stops being active the manager stops first, then the registry is
// closed. A build running across both is refused at install and must not be
// retried: the retry would install a driver the next promotion serves.
func TestCreateDriver_BuildAcrossStepDownIsNotRetried(t *testing.T) {
	e := newBuildEnv(t)
	result := e.getAsync("slow")
	e.waitEntered(t)

	e.coordinator.Stop()
	e.registry.CloseAll(e.ctx)
	close(e.factory.release)

	got := e.receive(t, result)
	assert.ErrorIs(t, got.err, ErrCredentialManagerStopped)
	assert.EqualValues(t, 1, e.factory.creates.Load(), "the refused build was retried")
	_, ok := e.registry.GetDriver(e.ctx, "slow")
	assert.False(t, ok, "a driver was installed after the registry was closed")
}

// Deleting a namespace while one of its drivers is being built must not leave that
// driver installed.
func TestCreateDriver_BuildAcrossNamespaceDeletionIsNotInstalled(t *testing.T) {
	e := newBuildEnv(t)
	gen, err := e.registry.Generation(e.ctx, "slow")
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		_, _, err := e.registry.CreateDriver(e.ctx, "slow",
			&CredSource{Name: "slow", Type: "blocking", Config: NewConfig(nil)}, gen)
		result <- err
	}()
	e.waitEntered(t)

	_, err = e.registry.CloseAllForNamespace(e.ctx)
	require.NoError(t, err)
	close(e.factory.release)

	select {
	case err := <-result:
		assert.ErrorIs(t, err, ErrDriverConfigChanged)
	case <-time.After(5 * time.Second):
		t.Fatal("the build did not settle")
	}
	_, ok := e.registry.GetDriver(e.ctx, "slow")
	assert.False(t, ok, "a driver was installed into the deleted namespace")
	e.factory.mu.Lock()
	defer e.factory.mu.Unlock()
	require.Len(t, e.factory.built, 1)
	assert.EqualValues(t, 1, e.factory.built[0].cleanups.Load(), "the refused driver was cleaned up")
}
