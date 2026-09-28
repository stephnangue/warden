package credential

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A node that steps down keeps its registry. While it is standby another node
// can change a source, and that change reaches only storage. Before CloseAll a
// node promoted again kept minting with the driver it had built from the old
// config; after it, the next use builds from what storage holds.
func TestDriverRegistry_CloseAllRebuildsFromCurrentConfig(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	factory := &recordingFactory{}
	require.NoError(t, registry.RegisterFactory(factory))
	store := newMockConfigStore()
	store.sources["src"] = &CredSource{Name: "src", Type: "recording", Config: NewConfig(map[string]string{"version": "1"})}
	coordinator := NewDriverCoordinator(registry, store, log)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	driver, err := coordinator.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)
	require.Equal(t, "1", driver.(*recordingDriver).config.Get("version"))

	// Another node rewrites the source; nothing tells this node's registry.
	store.sources["src"] = &CredSource{Name: "src", Type: "recording", Config: NewConfig(map[string]string{"version": "2"})}
	driver, err = coordinator.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)
	require.Equal(t, "1", driver.(*recordingDriver).config.Get("version"), "precondition: the stale instance is served")

	assert.Equal(t, 1, registry.CloseAll(context.Background()))

	driver, err = coordinator.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)
	assert.Equal(t, "2", driver.(*recordingDriver).config.Get("version"))
}

// CloseAll covers every namespace, and invalidates each generation so a build
// that read its source before the close cannot install afterwards.
func TestDriverRegistry_CloseAllEveryNamespaceAndBumpsGenerations(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	require.NoError(t, registry.RegisterFactory(&recordingFactory{}))

	root := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	child := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", UUID: "child-uuid"})
	source := &CredSource{Name: "src", Type: "recording", Config: NewConfig(nil)}

	for _, ctx := range []context.Context{root, child} {
		gen, err := registry.Generation(ctx, "src")
		require.NoError(t, err)
		_, created, err := registry.CreateDriver(ctx, "src", source, gen)
		require.NoError(t, err)
		require.True(t, created)
	}
	staleGen, err := registry.Generation(root, "src")
	require.NoError(t, err)

	assert.Equal(t, 2, registry.CloseAll(context.Background()))

	for _, ctx := range []context.Context{root, child} {
		_, ok := registry.GetDriver(ctx, "src")
		assert.False(t, ok)
	}
	_, _, err = registry.CreateDriver(root, "src", source, staleGen)
	assert.ErrorIs(t, err, ErrDriverConfigChanged, "a build that read its source before the close must be refused")
}

// A build that read its source before CloseAll is refused even for a source
// that never had an instance, and so no generation entry of its own to bump.
func TestDriverRegistry_CloseAllInvalidatesKeysWithNoInstance(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	require.NoError(t, registry.RegisterFactory(&recordingFactory{}))
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	source := &CredSource{Name: "never-built", Type: "recording", Config: NewConfig(nil)}

	staleGen, err := registry.Generation(ctx, "never-built")
	require.NoError(t, err)

	assert.Equal(t, 0, registry.CloseAll(context.Background()))

	_, _, err = registry.CreateDriver(ctx, "never-built", source, staleGen)
	assert.ErrorIs(t, err, ErrDriverConfigChanged)

	freshGen, err := registry.Generation(ctx, "never-built")
	require.NoError(t, err)
	_, created, err := registry.CreateDriver(ctx, "never-built", source, freshGen)
	require.NoError(t, err)
	assert.True(t, created, "a build that read its source after the close installs normally")
}

// reentrantDriver calls back into the registry from Cleanup, as a driver whose
// teardown looks something up would. Under the registry lock that deadlocks.
type reentrantDriver struct {
	recordingDriver
	registry *DriverRegistry
	ctx      context.Context
}

func (d *reentrantDriver) Cleanup(context.Context) error {
	d.registry.GetDriver(d.ctx, "other")
	return nil
}

// CloseAll runs each driver's Cleanup after releasing the registry lock, so a
// slow cleanup at step-down cannot hold the registry. (CloseDriver and
// CloseAllForNamespace still clean up under the lock; no driver's Cleanup
// calls back into the registry today.)
func TestDriverRegistry_CloseAllCleansUpOutsideTheLock(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	registry := NewDriverRegistry(log)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	registry.instances[namespace.RootNamespaceID+":src"] = &reentrantDriver{registry: registry, ctx: ctx}

	done := make(chan int, 1)
	go func() { done <- registry.CloseAll(context.Background()) }()
	select {
	case n := <-done:
		assert.Equal(t, 1, n)
	case <-time.After(2 * time.Second):
		t.Fatal("CloseAll deadlocked: Cleanup ran under the registry lock")
	}
}
