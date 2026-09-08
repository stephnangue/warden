package credential

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingDriver reports the config it was built from, so a test can tell which
// generation of a source an installed driver came from.
type recordingDriver struct {
	config Config
}

func (d *recordingDriver) MintCredential(context.Context, *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", nil
}
func (d *recordingDriver) Revoke(context.Context, string) error { return nil }
func (d *recordingDriver) Type() string                         { return "recording" }
func (d *recordingDriver) Cleanup(context.Context) error        { return nil }

type recordingFactory struct {
	mu    sync.Mutex
	built []string // the "version" config value each Create saw, in order
}

func (f *recordingFactory) Type() string                    { return "recording" }
func (f *recordingFactory) ValidateConfig(Config) error     { return nil }
func (f *recordingFactory) SensitiveConfigFields() []string { return nil }
func (f *recordingFactory) InferCredentialType(Config) (string, error) {
	return "", nil
}
func (f *recordingFactory) Create(config Config, _ *logger.GatedLogger) (SourceDriver, error) {
	f.mu.Lock()
	f.built = append(f.built, config.Get("version"))
	f.mu.Unlock()
	return &recordingDriver{config: config}, nil
}

// TestGetOrCreateDriver_RefusesToInstallDriverBuiltFromStaleConfig covers the window
// between reading a source and installing the driver built from it.
//
// The read goes through the config store and the install through the registry, so no
// single lock spans them. A source update landing in between used to leave the
// registry holding a driver built from the config read before the update — and
// permanently, because a registry hit is a plain map lookup that re-checks nothing.
// Every later mint on that source used the superseded credentials until the next
// config change or a restart.
//
// The hook here lands exactly that update, once, in exactly that window.
func TestGetOrCreateDriver_RefusesToInstallDriverBuiltFromStaleConfig(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	factory := &recordingFactory{}
	require.NoError(t, registry.RegisterFactory(factory))

	store := newMockConfigStore()
	store.sources["src"] = &CredSource{
		Name:   "src",
		Type:   "recording",
		Config: NewConfig(map[string]string{"version": "v1"}),
	}

	coordinator := NewDriverCoordinator(registry, store, log)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Fire once: the caller has just read v1 and has not installed yet. Publish v2
	// and invalidate, which is what a source update does.
	var once sync.Once
	store.getSourceHook = func() {
		once.Do(func() {
			store.mu.Lock()
			store.sources["src"] = &CredSource{
				Name:   "src",
				Type:   "recording",
				Config: NewConfig(map[string]string{"version": "v2"}),
			}
			store.mu.Unlock()

			require.NoError(t, registry.CloseDriver(ctx, "src"))
		})
	}

	driver, err := coordinator.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)

	installed, ok := driver.(*recordingDriver)
	require.True(t, ok)
	assert.Equal(t, "v2", installed.config.Get("version"),
		"the installed driver must come from the config that is current, not the one read before the update")

	// And the instance the registry serves from here on is that same one.
	cached, ok := registry.GetDriver(ctx, "src")
	require.True(t, ok)
	assert.Same(t, driver, cached)

	factory.mu.Lock()
	built := append([]string(nil), factory.built...)
	factory.mu.Unlock()
	assert.Equal(t, []string{"v2"}, built,
		"the stale generation is caught before the driver is built, so no wasted construction — "+
			"which matters because several factories authenticate inside Create")
}

// TestGetOrCreateDriver_ReturnsCachedInstanceWithoutRebuilding asserts the hot path
// is unchanged: a cached instance is returned without consulting the config store.
func TestGetOrCreateDriver_ReturnsCachedInstanceWithoutRebuilding(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	factory := &recordingFactory{}
	require.NoError(t, registry.RegisterFactory(factory))

	store := newMockConfigStore()
	store.sources["src"] = &CredSource{
		Name:   "src",
		Type:   "recording",
		Config: NewConfig(map[string]string{"version": "v1"}),
	}

	coordinator := NewDriverCoordinator(registry, store, log)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	first, err := coordinator.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)

	// Any further read of the source would trip this.
	store.getSourceHook = func() {
		t.Error("a cached driver must not re-read the source")
	}

	second, err := coordinator.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)
	assert.Same(t, first, second)

	factory.mu.Lock()
	defer factory.mu.Unlock()
	assert.Len(t, factory.built, 1, "the driver must be built exactly once")
}

// TestGetOrCreateDriver_ConcurrentCallersShareOneInstance guards the ordinary
// contended case: many mints missing the cache at once must not leave the registry
// churning or handing back different instances.
func TestGetOrCreateDriver_ConcurrentCallersShareOneInstance(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	require.NoError(t, registry.RegisterFactory(&recordingFactory{}))

	store := newMockConfigStore()
	store.sources["src"] = &CredSource{
		Name:   "src",
		Type:   "recording",
		Config: NewConfig(map[string]string{"version": "v1"}),
	}

	coordinator := NewDriverCoordinator(registry, store, log)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	const callers = 16
	drivers := make([]SourceDriver, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d, err := coordinator.GetOrCreateDriver(ctx, "src")
			if err != nil {
				t.Errorf("caller %d: %v", idx, err)
				return
			}
			drivers[idx] = d
		}(i)
	}
	wg.Wait()

	for i := 1; i < callers; i++ {
		assert.Same(t, drivers[0], drivers[i], "all callers must share one instance")
	}
}
