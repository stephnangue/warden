package core

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/openbao/openbao/helper/locking"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCore creates a minimal Core instance for testing
func createMockCore() *Core {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	router := NewRouter(log)

	return &Core{
		logger:        log,
		router:        router,
		mounts:        NewMountTable(),
		mountsLock:    locking.DeadlockRWMutex{},
		authMethods:   make(map[string]auth.Factory),
		providers:     make(map[string]provider.Factory),
		tokenStore:    &mockTokenStore{},
		roles:         authorize.NewRoleRegistry(),
		accessControl: &authorize.AccessControl{},
		credSources:   cred.NewCredSourceRegistry(),
		auditManager:  &mockAuditManager{},
	}
}

// mockTokenStore implements token.TokenStore for testing
type mockTokenStore struct {
	token.TokenStore
}

// mockAuditManager implements audit.AuditManager for testing
type mockAuditManager struct {
	audit.AuditManager
}

// mockAuthFactory implements auth.Factory for testing
type mockAuthFactory struct {
	createFunc func(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenStore token.TokenStore, roles *authorize.RoleRegistry, ac *authorize.AccessControl, am audit.AuditAccess) (logical.Backend, error)
}

func (f *mockAuthFactory) Type() string {
	return "mock"
}

func (f *mockAuthFactory) Class() string {
	return "auth"
}

func (f *mockAuthFactory) Create(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenStore token.TokenStore, roles *authorize.RoleRegistry, ac *authorize.AccessControl, am audit.AuditAccess) (logical.Backend, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, path, description, accessor, config, logger, tokenStore, roles, ac, am)
	}
	backend := newMockBackend(accessor)
	// Initialize with the provided config
	if config != nil {
		backend.Setup(config)
	}
	return backend, nil
}

func (f *mockAuthFactory) Initialize(logger logger.Logger) error {
	return nil
}

func (f *mockAuthFactory) ValidateConfig(config map[string]any) error {
	return nil
}

// mockProviderFactory implements provider.Factory for testing
type mockProviderFactory struct {
	createFunc func(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenAccess token.TokenAccess, roles *authorize.RoleRegistry, credSources *cred.CredSourceRegistry, am audit.AuditAccess) (logical.Backend, error)
}

func (f *mockProviderFactory) Type() string {
	return "mockprovider"
}

func (f *mockProviderFactory) Class() string {
	return "provider"
}

func (f *mockProviderFactory) Create(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenAccess token.TokenAccess, roles *authorize.RoleRegistry, credSources *cred.CredSourceRegistry, am audit.AuditAccess) (logical.Backend, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, path, description, accessor, config, logger, tokenAccess, roles, credSources, am)
	}
	backend := newMockBackend(accessor)
	// Initialize with the provided config
	if config != nil {
		backend.Setup(config)
	}
	return backend, nil
}

func (f *mockProviderFactory) Initialize(logger logger.Logger) error {
	return nil
}

func (f *mockProviderFactory) ValidateConfig(config map[string]any) error {
	return nil
}

func TestNewMountTable(t *testing.T) {
	table := NewMountTable()

	assert.NotNil(t, table)
	assert.NotNil(t, table.Entries)
	assert.Len(t, table.Entries, 0)
}

func TestMountTable_shallowClone(t *testing.T) {
	table := NewMountTable()
	entry1 := &MountEntry{Path: "test1/", Type: "mock"}
	entry2 := &MountEntry{Path: "test2/", Type: "mock"}
	table.Entries = append(table.Entries, entry1, entry2)

	clone := table.shallowClone()

	assert.NotNil(t, clone)
	assert.Len(t, clone.Entries, 2)
	assert.Equal(t, table.Entries[0], clone.Entries[0]) // Same pointer
	assert.Equal(t, table.Entries[1], clone.Entries[1]) // Same pointer

	// Modifying the clone's slice shouldn't affect the original
	clone.Entries = append(clone.Entries, &MountEntry{Path: "test3/", Type: "mock"})
	assert.Len(t, table.Entries, 2)
	assert.Len(t, clone.Entries, 3)
}

func TestMountTable_setTaint(t *testing.T) {
	table := NewMountTable()
	entry1 := &MountEntry{Path: "test1/", Type: "mock", Tainted: false}
	entry2 := &MountEntry{Path: "test2/", Type: "mock", Tainted: false}
	table.Entries = append(table.Entries, entry1, entry2)

	t.Run("taint existing entry", func(t *testing.T) {
		result, err := table.setTaint("test1/", true)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Tainted)
		assert.True(t, entry1.Tainted) // Original entry should be modified
	})

	t.Run("untaint entry", func(t *testing.T) {
		result, err := table.setTaint("test1/", false)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Tainted)
		assert.False(t, entry1.Tainted)
	})

	t.Run("taint non-existent entry", func(t *testing.T) {
		result, err := table.setTaint("nonexistent/", true)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestMountTable_remove(t *testing.T) {
	ctx := context.Background()

	t.Run("remove existing entry", func(t *testing.T) {
		table := NewMountTable()
		entry1 := &MountEntry{Path: "test1/", Type: "mock"}
		entry2 := &MountEntry{Path: "test2/", Type: "mock"}
		entry3 := &MountEntry{Path: "test3/", Type: "mock"}
		table.Entries = append(table.Entries, entry1, entry2, entry3)

		removed, err := table.remove(ctx, "test2/")
		require.NoError(t, err)
		assert.NotNil(t, removed)
		assert.Equal(t, "test2/", removed.Path)
		assert.Len(t, table.Entries, 2)
		assert.Equal(t, "test1/", table.Entries[0].Path)
		assert.Equal(t, "test3/", table.Entries[1].Path)
	})

	t.Run("remove non-existent entry", func(t *testing.T) {
		table := NewMountTable()
		entry1 := &MountEntry{Path: "test1/", Type: "mock"}
		table.Entries = append(table.Entries, entry1)

		removed, err := table.remove(ctx, "nonexistent/")
		require.NoError(t, err)
		assert.Nil(t, removed)
		assert.Len(t, table.Entries, 1)
	})

	t.Run("remove from empty table", func(t *testing.T) {
		table := NewMountTable()
		removed, err := table.remove(ctx, "test/")
		require.NoError(t, err)
		assert.Nil(t, removed)
	})
}

func TestMountTable_findByPath(t *testing.T) {
	ctx := context.Background()
	table := NewMountTable()
	entry1 := &MountEntry{Path: "test1/", Type: "mock"}
	entry2 := &MountEntry{Path: "test2/", Type: "mock"}
	table.Entries = append(table.Entries, entry1, entry2)

	t.Run("find existing entry", func(t *testing.T) {
		result, err := table.findByPath(ctx, "test1/")
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test1/", result.Path)
	})

	t.Run("find non-existent entry", func(t *testing.T) {
		result, err := table.findByPath(ctx, "nonexistent/")
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestMountTable_find(t *testing.T) {
	ctx := context.Background()
	table := NewMountTable()
	entry1 := &MountEntry{Path: "test1/", Type: "auth", Accessor: "accessor1"}
	entry2 := &MountEntry{Path: "test2/", Type: "provider", Accessor: "accessor2"}
	table.Entries = append(table.Entries, entry1, entry2)

	t.Run("find by type", func(t *testing.T) {
		result, err := table.find(ctx, func(me *MountEntry) bool {
			return me.Type == "provider"
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test2/", result.Path)
	})

	t.Run("find by accessor", func(t *testing.T) {
		result, err := table.find(ctx, func(me *MountEntry) bool {
			return me.Accessor == "accessor1"
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test1/", result.Path)
	})

	t.Run("no match", func(t *testing.T) {
		result, err := table.find(ctx, func(me *MountEntry) bool {
			return me.Type == "nonexistent"
		})
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestCore_generateMountAccessor(t *testing.T) {
	core := createMockCore()

	t.Run("generate unique accessor", func(t *testing.T) {
		accessor, err := core.generateMountAccessor("test")
		require.NoError(t, err)
		assert.NotEmpty(t, accessor)
		assert.Contains(t, accessor, "test_")
	})

	t.Run("generate multiple unique accessors", func(t *testing.T) {
		accessors := make(map[string]bool)
		for i := 0; i < 10; i++ {
			accessor, err := core.generateMountAccessor("test")
			require.NoError(t, err)
			assert.NotContains(t, accessors, accessor)
			accessors[accessor] = true
		}
	})
}

func TestCore_Mount(t *testing.T) {
	ctx := context.Background()

	t.Run("mount with trailing slash added", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry := &MountEntry{
			Class:       mountClassAuth,
			Type:        "mock",
			Path:        "test",
			Description: "test mount",
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)
		assert.Equal(t, "test/", entry.Path) // Should have trailing slash
	})

	t.Run("mount protected path sys", func(t *testing.T) {
		core := createMockCore()

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "sys/test/",
		}

		err := core.mount(ctx, entry)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot mount")
	})

	t.Run("mount protected path auth", func(t *testing.T) {
		core := createMockCore()

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "auth/test/",
		}

		err := core.mount(ctx, entry)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot mount")
	})

	t.Run("mount protected path audit", func(t *testing.T) {
		core := createMockCore()

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "audit/test/",
		}

		err := core.mount(ctx, entry)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot mount")
	})

	t.Run("mount singleton type", func(t *testing.T) {
		core := createMockCore()

		entry := &MountEntry{
			Class: mountClassSystem,
			Type:  "system",
			Path:  "test/",
		}

		err := core.mount(ctx, entry)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not mountable")
	})

	t.Run("mount successful auth backend", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["testauth"] = &mockAuthFactory{}

		entry := &MountEntry{
			Class:       mountClassAuth,
			Type:        "testauth",
			Path:        "myauth/",
			Description: "test auth",
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)
		assert.NotEmpty(t, entry.Accessor)

		// Verify it's in the mount table
		found, err := core.mounts.findByPath(ctx, "myauth/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "myauth/", found.Path)
	})

	t.Run("mount successful provider backend", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "myprovider/",
			Description: "test provider",
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)
		assert.NotEmpty(t, entry.Accessor)
	})

	t.Run("mount unsupported auth type", func(t *testing.T) {
		core := createMockCore()

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "unsupported",
			Path:  "test/",
		}

		err := core.mount(ctx, entry)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("mount unsupported provider type", func(t *testing.T) {
		core := createMockCore()

		entry := &MountEntry{
			Class: mountClassProvider,
			Type:  "unsupported",
			Path:  "test/",
		}

		err := core.mount(ctx, entry)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}

func TestCore_mountInternal(t *testing.T) {
	ctx := context.Background()

	t.Run("duplicate path - exact match", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry1 := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}

		err := core.mountInternal(ctx, entry1, MountTableNoUpdateStorage)
		require.NoError(t, err)

		entry2 := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}

		err = core.mountInternal(ctx, entry2, MountTableNoUpdateStorage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already in use")
	})

	t.Run("duplicate path - prefix conflict", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry1 := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "oauth/",
		}

		err := core.mountInternal(ctx, entry1, MountTableNoUpdateStorage)
		require.NoError(t, err)

		entry2 := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "oauth/github/",
		}

		err = core.mountInternal(ctx, entry2, MountTableNoUpdateStorage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already in use")
	})

	t.Run("with predefined accessor", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry := &MountEntry{
			Class:    mountClassAuth,
			Type:     "mock",
			Path:     "test/",
			Accessor: "custom_accessor_12345678",
		}

		err := core.mountInternal(ctx, entry, MountTableNoUpdateStorage)
		require.NoError(t, err)
		assert.Equal(t, "custom_accessor_12345678", entry.Accessor)
	})

	t.Run("backend creation returns nil", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["nilbackend"] = &mockAuthFactory{
			createFunc: func(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenStore token.TokenStore, roles *authorize.RoleRegistry, ac *authorize.AccessControl, am audit.AuditAccess) (logical.Backend, error) {
				return nil, nil
			},
		}

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "nilbackend",
			Path:  "test/",
		}

		err := core.mountInternal(ctx, entry, MountTableNoUpdateStorage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil backend")
	})

	t.Run("backend creation returns error", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["errorbackend"] = &mockAuthFactory{
			createFunc: func(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenStore token.TokenStore, roles *authorize.RoleRegistry, ac *authorize.AccessControl, am audit.AuditAccess) (logical.Backend, error) {
				return nil, fmt.Errorf("creation failed")
			},
		}

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "errorbackend",
			Path:  "test/",
		}

		err := core.mountInternal(ctx, entry, MountTableNoUpdateStorage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "creation failed")
	})
}

func TestCore_Unmount(t *testing.T) {
	ctx := context.Background()

	t.Run("unmount with trailing slash added", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		// Mount first
		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}
		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Unmount without trailing slash
		err = core.unmount(ctx, "test")
		require.NoError(t, err)
	})

	t.Run("unmount protected path sys", func(t *testing.T) {
		core := createMockCore()

		err := core.unmount(ctx, "sys/test/")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot unmount")
	})

	t.Run("unmount protected path auth", func(t *testing.T) {
		core := createMockCore()

		err := core.unmount(ctx, "auth/")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot unmount")
	})

	t.Run("unmount protected path audit", func(t *testing.T) {
		core := createMockCore()

		err := core.unmount(ctx, "audit/")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot unmount")
	})

	t.Run("unmount non-existent mount", func(t *testing.T) {
		core := createMockCore()

		err := core.unmount(ctx, "nonexistent/")
		assert.Error(t, err)
		assert.Equal(t, errNoMatchingMount, err)
	})

	t.Run("successful unmount", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		// Mount first
		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}
		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Unmount
		err = core.unmount(ctx, "test/")
		require.NoError(t, err)

		// Verify it's removed
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.Nil(t, found)

		// Verify router doesn't have it
		backend := core.router.MatchingBackend(ctx, "test/")
		assert.Nil(t, backend)
	})
}

func TestCore_taintMountEntry(t *testing.T) {
	ctx := context.Background()

	t.Run("taint existing mount", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}
		err := core.mount(ctx, entry)
		require.NoError(t, err)

		err = core.taintMountEntry(ctx, "test/", MountTableNoUpdateStorage)
		require.NoError(t, err)

		// Verify it's tainted
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.True(t, found.Tainted)
	})

	t.Run("taint non-existent mount", func(t *testing.T) {
		core := createMockCore()

		err := core.taintMountEntry(ctx, "nonexistent/", MountTableNoUpdateStorage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to taint entry")
	})
}

func TestCore_removeMountEntry(t *testing.T) {
	ctx := context.Background()

	t.Run("remove existing mount entry", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}
		err := core.mount(ctx, entry)
		require.NoError(t, err)

		err = core.removeMountEntry(ctx, "test/", MountTableNoUpdateStorage)
		require.NoError(t, err)

		// Verify it's removed
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.Nil(t, found)
	})

	t.Run("remove non-existent mount entry", func(t *testing.T) {
		core := createMockCore()

		err := core.removeMountEntry(ctx, "nonexistent/", MountTableNoUpdateStorage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to remove entry")
	})

	t.Run("remove last entry sets entries to nil", func(t *testing.T) {
		core := createMockCore()
		core.authMethods["mock"] = &mockAuthFactory{}

		entry := &MountEntry{
			Class: mountClassAuth,
			Type:  "mock",
			Path:  "test/",
		}
		err := core.mount(ctx, entry)
		require.NoError(t, err)

		err = core.removeMountEntry(ctx, "test/", MountTableNoUpdateStorage)
		require.NoError(t, err)

		assert.Nil(t, core.mounts.Entries)
	})
}

func TestCore_MountUnmount_Concurrent(t *testing.T) {
	ctx := context.Background()
	core := createMockCore()
	core.authMethods["mock"] = &mockAuthFactory{}

	var wg sync.WaitGroup
	numOps := 10

	// Mount multiple backends concurrently
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			entry := &MountEntry{
				Class:       mountClassAuth,
				Type:        "mock",
				Path:        fmt.Sprintf("concurrent-%d/", idx),
				Description: fmt.Sprintf("concurrent test %d", idx),
			}

			err := core.mount(ctx, entry)
			if err != nil {
				t.Errorf("Failed to mount: %v", err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all mounts exist
	assert.Len(t, core.mounts.Entries, numOps)

	// Unmount all concurrently
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			err := core.unmount(ctx, fmt.Sprintf("concurrent-%d/", idx))
			if err != nil {
				t.Errorf("Failed to unmount: %v", err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all mounts are removed
	assert.Nil(t, core.mounts.Entries)
}

func TestCore_MountWithConfig(t *testing.T) {
	ctx := context.Background()
	core := createMockCore()

	t.Run("mount with custom config", func(t *testing.T) {
		var receivedConfig map[string]any
		core.authMethods["configauth"] = &mockAuthFactory{
			createFunc: func(ctx context.Context, path, description, accessor string, config map[string]any, logger logger.Logger, tokenStore token.TokenStore, roles *authorize.RoleRegistry, ac *authorize.AccessControl, am audit.AuditAccess) (logical.Backend, error) {
				receivedConfig = config
				return newMockBackend(accessor), nil
			},
		}

		entry := &MountEntry{
			Class:       mountClassAuth,
			Type:        "configauth",
			Path:        "test/",
			Description: "test with config",
			Config: map[string]any{
				"key1": "value1",
				"key2": 42,
			},
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		assert.NotNil(t, receivedConfig)
		assert.Equal(t, "value1", receivedConfig["key1"])
		assert.Equal(t, 42, receivedConfig["key2"])
	})
}

func TestProtectedMounts(t *testing.T) {
	expected := []string{"audit/", "auth/", "sys/"}
	assert.Equal(t, expected, protectedMounts)
}

func TestSingletonMounts(t *testing.T) {
	expected := []string{"system"}
	assert.Equal(t, expected, singletonMounts)
}

func TestMountConstants(t *testing.T) {
	assert.Equal(t, "sys/", mountPathSystem)
	assert.Equal(t, "system", mountClassSystem)
	assert.Equal(t, "provider", mountClassProvider)
	assert.Equal(t, "auth", mountClassAuth)
	assert.Equal(t, "audit", mountClassAudit)
	assert.True(t, MountTableUpdateStorage)
	assert.False(t, MountTableNoUpdateStorage)
}

func TestCore_configureMount(t *testing.T) {
	ctx := context.Background()

	t.Run("tune mount with trailing slash added", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		// First mount a provider
		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "test/",
			Description: "test mount",
			Config:      map[string]any{"initial_key": "initial_value"},
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Now tune it without trailing slash
		tuneConfig := map[string]any{
			"new_key": "new_value",
		}

		err = core.configureMount(ctx, "test", tuneConfig)
		require.NoError(t, err)

		// Verify the config was updated
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "initial_value", found.Config["initial_key"])
		assert.Equal(t, "new_value", found.Config["new_key"])
	})

	t.Run("tune mount updates existing config", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		// Mount a provider with initial config
		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "aws/",
			Description: "test mount",
			Config: map[string]any{
				"ttl":     3600,
				"max_ttl": 7200,
			},
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Tune to update config
		tuneConfig := map[string]any{
			"ttl":        7200,
			"proxy_urls": []string{"http://proxy1", "http://proxy2"},
		}

		err = core.configureMount(ctx, "aws/", tuneConfig)
		require.NoError(t, err)

		// Verify the config was updated
		found, err := core.mounts.findByPath(ctx, "aws/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, 7200, found.Config["ttl"])           // Updated
		assert.Equal(t, 7200, found.Config["max_ttl"])       // Unchanged
		assert.NotNil(t, found.Config["proxy_urls"])         // Added
	})

	t.Run("tune mount with nil config initializes it", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		// Mount a provider without config
		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "test/",
			Description: "test mount",
			Config:      nil,
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Tune to add config
		tuneConfig := map[string]any{
			"new_key": "new_value",
		}

		err = core.configureMount(ctx, "test/", tuneConfig)
		require.NoError(t, err)

		// Verify config was created and updated
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.NotNil(t, found.Config)
		assert.Equal(t, "new_value", found.Config["new_key"])
	})

	t.Run("tune protected path sys fails", func(t *testing.T) {
		core := createMockCore()

		tuneConfig := map[string]any{
			"key": "value",
		}

		err := core.configureMount(ctx, "sys/test/", tuneConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot tune")
	})

	t.Run("tune protected path auth fails", func(t *testing.T) {
		core := createMockCore()

		tuneConfig := map[string]any{
			"key": "value",
		}

		err := core.configureMount(ctx, "auth/test/", tuneConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot tune")
	})

	t.Run("tune protected path audit fails", func(t *testing.T) {
		core := createMockCore()

		tuneConfig := map[string]any{
			"key": "value",
		}

		err := core.configureMount(ctx, "audit/test/", tuneConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot tune")
	})

	t.Run("tune non-existent mount fails", func(t *testing.T) {
		core := createMockCore()

		tuneConfig := map[string]any{
			"key": "value",
		}

		err := core.configureMount(ctx, "nonexistent/", tuneConfig)
		assert.Error(t, err)
		assert.Equal(t, errNoMatchingMount, err)
	})

	t.Run("tune with empty config succeeds", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		// Mount a provider
		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "test/",
			Description: "test mount",
			Config:      map[string]any{"initial": "value"},
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Tune with empty config
		tuneConfig := map[string]any{}

		err = core.configureMount(ctx, "test/", tuneConfig)
		require.NoError(t, err)

		// Verify original config is unchanged
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "value", found.Config["initial"])
	})

	t.Run("tune mount multiple times", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		// Mount a provider
		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "test/",
			Description: "test mount",
			Config:      map[string]any{"counter": 0},
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Tune multiple times
		for i := 1; i <= 3; i++ {
			tuneConfig := map[string]any{
				"counter": i,
				fmt.Sprintf("key_%d", i): fmt.Sprintf("value_%d", i),
			}

			err = core.configureMount(ctx, "test/", tuneConfig)
			require.NoError(t, err)
		}

		// Verify all updates were applied
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, 3, found.Config["counter"])
		assert.Equal(t, "value_1", found.Config["key_1"])
		assert.Equal(t, "value_2", found.Config["key_2"])
		assert.Equal(t, "value_3", found.Config["key_3"])
	})

	t.Run("tune mount concurrent access", func(t *testing.T) {
		core := createMockCore()
		core.providers["testprovider"] = &mockProviderFactory{}

		// Mount a provider
		entry := &MountEntry{
			Class:       mountClassProvider,
			Type:        "testprovider",
			Path:        "test/",
			Description: "test mount",
			Config:      make(map[string]any),
		}

		err := core.mount(ctx, entry)
		require.NoError(t, err)

		// Tune concurrently
		var wg sync.WaitGroup
		numGoroutines := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				tuneConfig := map[string]any{
					fmt.Sprintf("key_%d", id): fmt.Sprintf("value_%d", id),
				}
				err := core.configureMount(ctx, "test/", tuneConfig)
				assert.NoError(t, err)
			}(i)
		}

		wg.Wait()

		// Verify mount still exists and has config
		found, err := core.mounts.findByPath(ctx, "test/")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.NotNil(t, found.Config)
		// Should have at least some of the concurrent updates
		assert.NotEmpty(t, found.Config)
	})
}
