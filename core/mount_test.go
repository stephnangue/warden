package core

import (
	"context"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMountTable_NewMountTable tests creating a new mount table
func TestMountTable_NewMountTable(t *testing.T) {
	table := NewMountTable()
	require.NotNil(t, table)
	assert.NotNil(t, table.Entries)
	assert.Empty(t, table.Entries)
}

// TestMountTable_ShallowClone tests shallow cloning a mount table
func TestMountTable_ShallowClone(t *testing.T) {
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	clone := table.shallowClone()
	require.NotNil(t, clone)
	assert.Len(t, clone.Entries, 1)
	// Shallow clone should share the same pointer
	assert.Same(t, table.Entries[0], clone.Entries[0])
}

// TestMountTable_SetTaint tests setting taint on an entry
func TestMountTable_SetTaint(t *testing.T) {
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Set taint
	taintedEntry, err := table.setTaint(namespace.RootNamespaceID, "test/", true, mountStateUnmounting)
	require.NoError(t, err)
	require.NotNil(t, taintedEntry)
	assert.True(t, taintedEntry.Tainted)
	assert.Equal(t, mountStateUnmounting, taintedEntry.MountState)

	// Untaint
	untaintedEntry, err := table.setTaint(namespace.RootNamespaceID, "test/", false, "")
	require.NoError(t, err)
	require.NotNil(t, untaintedEntry)
	assert.False(t, untaintedEntry.Tainted)
	assert.Empty(t, untaintedEntry.MountState)
}

// TestMountTable_SetTaint_NotFound tests setting taint on non-existent entry
func TestMountTable_SetTaint_NotFound(t *testing.T) {
	table := NewMountTable()

	entry, err := table.setTaint(namespace.RootNamespaceID, "nonexistent/", true, "")
	require.NoError(t, err)
	assert.Nil(t, entry)
}

// TestMountTable_Remove tests removing an entry from mount table
func TestMountTable_Remove(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Remove the entry
	removed, err := table.remove(ctx, "test/")
	require.NoError(t, err)
	require.NotNil(t, removed)
	assert.Equal(t, "test/", removed.Path)
	assert.Empty(t, table.Entries)
}

// TestMountTable_Remove_NotFound tests removing non-existent entry
func TestMountTable_Remove_NotFound(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := NewMountTable()

	removed, err := table.remove(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Nil(t, removed)
}

// TestMountTable_FindByPath tests finding entry by path
func TestMountTable_FindByPath(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Find existing entry
	found, err := table.findByPath(ctx, "test/")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test/", found.Path)

	// Find non-existent entry
	notFound, err := table.findByPath(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Nil(t, notFound)
}

// TestMountTable_FindByBackendUUID tests finding entry by backend UUID
func TestMountTable_FindByBackendUUID(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := NewMountTable()
	entry := &MountEntry{
		Path:             "test/",
		Type:             "mock",
		Class:            mountClassProvider,
		UUID:             "test-uuid",
		BackendAwareUUID: "backend-uuid-123",
		Accessor:         "mock_12345678",
		NamespaceID:      namespace.RootNamespaceID,
		namespace:        namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Find existing entry
	found, err := table.findByBackendUUID(ctx, "backend-uuid-123")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "backend-uuid-123", found.BackendAwareUUID)

	// Find non-existent entry
	notFound, err := table.findByBackendUUID(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, notFound)
}

// TestMountTable_FindAllNamespaceMounts tests finding all mounts in a namespace
func TestMountTable_FindAllNamespaceMounts(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid-1",
		Accessor:    "mock_11111111",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid-2",
		Accessor:    "mock_22222222",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)

	mounts, err := table.findAllNamespaceMounts(ctx)
	require.NoError(t, err)
	assert.Len(t, mounts, 2)
}

// TestMountTable_SortEntriesByPath tests sorting entries by path
func TestMountTable_SortEntriesByPath(t *testing.T) {
	table := NewMountTable()
	table.Entries = append(table.Entries,
		&MountEntry{Path: "zzz/", namespace: namespace.RootNamespace},
		&MountEntry{Path: "aaa/", namespace: namespace.RootNamespace},
		&MountEntry{Path: "mmm/", namespace: namespace.RootNamespace},
	)

	sorted := table.sortEntriesByPath()
	assert.Equal(t, "aaa/", sorted.Entries[0].Path)
	assert.Equal(t, "mmm/", sorted.Entries[1].Path)
	assert.Equal(t, "zzz/", sorted.Entries[2].Path)
}

// TestMountEntry_Clone tests cloning a mount entry
func TestMountEntry_Clone(t *testing.T) {
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		Description: "Test mount",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
		Config: map[string]any{
			"key": "value",
		},
	}

	clone, err := entry.Clone()
	require.NoError(t, err)
	require.NotNil(t, clone)
	assert.Equal(t, entry.Path, clone.Path)
	assert.Equal(t, entry.Type, clone.Type)
	assert.Equal(t, entry.UUID, clone.UUID)
	// Deep clone should have independent config map
	clone.Config["key"] = "modified"
	assert.Equal(t, "value", entry.Config["key"], "original config should not be modified")
}

// TestMountEntry_Namespace tests getting namespace from mount entry
func TestMountEntry_Namespace(t *testing.T) {
	entry := &MountEntry{
		Path:        "test/",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	ns := entry.Namespace()
	require.NotNil(t, ns)
	assert.Equal(t, namespace.RootNamespaceID, ns.ID)
}

// TestMountEntry_APIPath tests getting API path for mount entry
func TestMountEntry_APIPath(t *testing.T) {
	t.Run("provider mount", func(t *testing.T) {
		entry := &MountEntry{
			Path:      "aws/",
			Class:     mountClassProvider,
			namespace: namespace.RootNamespace,
		}
		assert.Equal(t, "aws/", entry.APIPath())
	})

	t.Run("auth mount", func(t *testing.T) {
		entry := &MountEntry{
			Path:      "jwt/",
			Class:     mountClassAuth,
			namespace: namespace.RootNamespace,
		}
		assert.Equal(t, "auth/jwt/", entry.APIPath())
	})
}

// TestMountEntry_APIPathNoNamespace tests getting API path without namespace
func TestMountEntry_APIPathNoNamespace(t *testing.T) {
	t.Run("provider mount", func(t *testing.T) {
		entry := &MountEntry{
			Path:      "aws/",
			Class:     mountClassProvider,
			namespace: namespace.RootNamespace,
		}
		assert.Equal(t, "aws/", entry.APIPathNoNamespace())
	})

	t.Run("auth mount", func(t *testing.T) {
		entry := &MountEntry{
			Path:      "jwt/",
			Class:     mountClassAuth,
			namespace: namespace.RootNamespace,
		}
		assert.Equal(t, "auth/jwt/", entry.APIPathNoNamespace())
	})
}

// TestMountEntry_Deserialize tests deserializing a mount entry
func TestMountEntry_Deserialize(t *testing.T) {
	entry := &MountEntry{
		Path:      "test/",
		Type:      "mock",
		Class:     mountClassProvider,
		UUID:      "test-uuid",
		Accessor:  "mock_12345678",
		namespace: namespace.RootNamespace,
	}

	data := entry.Deserialize()
	assert.Equal(t, "test/", data["mount_path"])
	assert.Equal(t, "", data["mount_namespace"])
	assert.Equal(t, "test-uuid", data["uuid"])
	assert.Equal(t, "mock_12345678", data["accessor"])
	assert.Equal(t, "mock", data["mount_type"])
	assert.Equal(t, mountClassProvider, data["mount_class"])
}

// TestCore_Mount tests mounting a new backend
func TestCore_Mount(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock provider factory
	core.providers["mock"] = MockProviderFactory

	entry := &MountEntry{
		Path:  "test-provider",
		Type:  "mock",
		Class: mountClassProvider,
	}

	err := core.mount(ctx, entry)
	require.NoError(t, err)

	// Verify path was normalized
	assert.Equal(t, "test-provider/", entry.Path)
	// Verify UUID was generated
	assert.NotEmpty(t, entry.UUID)
	// Verify accessor was generated
	assert.NotEmpty(t, entry.Accessor)
}

// TestCore_Mount_ProtectedPath tests mounting to protected paths fails
func TestCore_Mount_ProtectedPath(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	testCases := []struct {
		name string
		path string
	}{
		{"sys path", "sys/test"},
		{"auth path", "auth/test"},
		{"audit path", "audit/test"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entry := &MountEntry{
				Path:  tc.path,
				Type:  "mock",
				Class: mountClassProvider,
			}
			err := core.mount(ctx, entry)
			require.Error(t, err)
		})
	}
}

// TestCore_Mount_SingletonType tests that singleton types cannot be mounted
func TestCore_Mount_SingletonType(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:  "custom-sys/",
		Type:  mountClassSystem,
		Class: mountClassSystem,
	}

	err := core.mount(ctx, entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not mountable")
}

// TestCore_Mount_ConflictingPath tests mounting to conflicting path fails
func TestCore_Mount_ConflictingPath(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock provider factory
	core.providers["mock"] = MockProviderFactory

	// Mount first
	entry1 := &MountEntry{
		Path:  "test/",
		Type:  "mock",
		Class: mountClassProvider,
	}
	err := core.mount(ctx, entry1)
	require.NoError(t, err)

	// Try to mount at same path
	entry2 := &MountEntry{
		Path:  "test/",
		Type:  "mock",
		Class: mountClassProvider,
	}
	err = core.mount(ctx, entry2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already in use")
}

// TestCore_Mount_NestedPath tests mounting at nested path fails
func TestCore_Mount_NestedPath(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock provider factory
	core.providers["mock"] = MockProviderFactory

	// Mount parent
	entry1 := &MountEntry{
		Path:  "parent/",
		Type:  "mock",
		Class: mountClassProvider,
	}
	err := core.mount(ctx, entry1)
	require.NoError(t, err)

	// Try to mount at nested path
	entry2 := &MountEntry{
		Path:  "parent/child/",
		Type:  "mock",
		Class: mountClassProvider,
	}
	err = core.mount(ctx, entry2)
	require.Error(t, err)
}

// TestCore_Unmount tests unmounting a backend
func TestCore_Unmount(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock provider factory
	core.providers["mock"] = MockProviderFactory

	// Mount first
	entry := &MountEntry{
		Path:  "test/",
		Type:  "mock",
		Class: mountClassProvider,
	}
	err := core.mount(ctx, entry)
	require.NoError(t, err)

	// Unmount
	err = core.unmount(ctx, "test/")
	require.NoError(t, err)

	// Verify it's gone
	found, err := core.mounts.findByPath(ctx, "test/")
	require.NoError(t, err)
	assert.Nil(t, found)
}

// TestCore_Unmount_ProtectedPath tests unmounting protected paths fails
func TestCore_Unmount_ProtectedPath(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	err := core.unmount(ctx, "sys/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot unmount")
}

// TestCore_Unmount_NotFound tests unmounting non-existent mount fails
func TestCore_Unmount_NotFound(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	err := core.unmount(ctx, "nonexistent/")
	require.Error(t, err)
}

// TestCore_GenerateMountAccessor pins the accessor shape per class: an auth
// method's and an audit device's carry the class in front, a provider's and
// the system mount's are the bare type.
func TestCore_GenerateMountAccessor(t *testing.T) {
	core := createTestCore(t)

	for _, tc := range []struct {
		class, entryType, want string
	}{
		{mountClassAuth, "jwt", `^auth_jwt_[0-9a-f]{8}$`},
		{mountClassAudit, "file", `^audit_file_[0-9a-f]{8}$`},
		{mountClassProvider, "vault", `^vault_[0-9a-f]{8}$`},
		{mountClassSystem, "system", `^system_[0-9a-f]{8}$`},
		{mountClassNSSystem, "ns_system", `^ns_system_[0-9a-f]{8}$`},
	} {
		t.Run(tc.class, func(t *testing.T) {
			accessor, err := core.generateMountAccessor(tc.class, tc.entryType)
			require.NoError(t, err)
			assert.Regexp(t, tc.want, accessor)
		})
	}
}

// TestCore_RequiredMountTable tests creating required mount table
func TestCore_RequiredMountTable(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table, err := core.requiredMountTable(ctx)
	require.NoError(t, err)
	require.NotNil(t, table)

	// Should have system mount
	assert.Len(t, table.Entries, 1)
	assert.Equal(t, "sys/", table.Entries[0].Path)
	assert.Equal(t, mountClassSystem, table.Entries[0].Type)
}

// systemBackendOf reads c.systemBackend under the lock that guards it.
func systemBackendOf(c *Core) *SystemBackend {
	c.mountsLock.RLock()
	defer c.mountsLock.RUnlock()
	return c.systemBackend
}

// TestCore_NamespaceSystemMountSharesBackend pins one system backend for every
// namespace: each namespace's sys/ is a handle on root's, and keeps its own
// ns_system mount entry.
func TestCore_NamespaceSystemMountSharesBackend(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	acme := nsModify(t, core, ctx, "acme", nil)
	dev := nsModify(t, core, ctx, "acme/dev", nil)

	shared := systemBackendOf(core)
	require.NotNil(t, shared)
	assert.Same(t, shared, core.router.MatchingBackend(ctx, "sys/"), "root's sys/ holds the backend itself")

	accessors := map[string]bool{}
	for _, ns := range []*namespace.Namespace{acme, dev} {
		nsCtx := namespace.ContextWithNamespace(context.Background(), ns)
		handle, ok := core.router.MatchingBackend(nsCtx, "sys/").(nsSystemBackend)
		require.True(t, ok, ns.Path)
		assert.Same(t, shared, handle.SystemBackend, ns.Path)
		assert.Same(t, shared.Backend, framework.ExtractBackend(handle), ns.Path)

		entry := core.router.MatchingMountEntry(nsCtx, "sys/")
		require.NotNil(t, entry, ns.Path)
		assert.Equal(t, mountClassNSSystem, entry.Class, ns.Path)
		assert.Equal(t, mountClassNSSystem, entry.Type, ns.Path)
		accessors[entry.Accessor] = true
	}
	assert.Len(t, accessors, 2, "each namespace's sys/ keeps its own accessor")

	// The handle replaces three of the backend's methods and promotes the
	// rest: only a field shadowing a method could hide one.
	assert.Equal(t, reflect.TypeOf(shared).NumMethod(), reflect.TypeOf(nsSystemBackend{}).NumMethod())
}

// TestCore_NamespaceSystemHandleOwnsNoLifecycle pins that a namespace never
// sets up, initializes or cleans up the backend every namespace shares: only
// root's mount does, once.
func TestCore_NamespaceSystemHandleOwnsNoLifecycle(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	shared := systemBackendOf(core)
	require.NotNil(t, shared)
	var initialized, cleaned atomic.Int32
	shared.InitializeFunc = func(context.Context) error { initialized.Add(1); return nil }
	shared.Clean = func(context.Context) { cleaned.Add(1) }

	acme := nsModify(t, core, ctx, "acme", nil)
	beta := nsModify(t, core, ctx, "beta", nil)
	assert.Zero(t, initialized.Load(), "creating a namespace does not initialize the shared backend")

	acmeCtx := namespace.ContextWithNamespace(context.Background(), acme)
	handle := core.router.MatchingBackend(acmeCtx, "sys/")
	require.NotNil(t, handle)
	require.NoError(t, handle.Setup(acmeCtx, &logical.BackendConfig{Config: map[string]any{"k": "v"}, Logger: core.logger}))
	assert.Nil(t, shared.Config(), "setting up a handle does not reconfigure the shared backend")

	require.NoError(t, core.namespaceStore.clearNamespaceResources(acmeCtx, acme))
	assert.Zero(t, cleaned.Load(), "deleting a namespace does not clean up the shared backend")
	assert.Nil(t, core.router.MatchingMountEntry(acmeCtx, "sys/"), "acme's sys/ is unmounted")

	resp, err := core.router.Route(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "sys/namespaces/beta"})
	require.NoError(t, err, "root's sys/ still answers")
	require.NotNil(t, resp)
	assert.Equal(t, "beta/", resp.Data["path"])
	betaCtx := namespace.ContextWithNamespace(context.Background(), beta)
	_, err = core.router.Route(betaCtx, &logical.Request{Operation: logical.ListOperation, Path: "sys/namespaces"})
	require.NoError(t, err, "a sibling namespace's sys/ still answers")

	require.NoError(t, core.unloadMounts(ctx))
	assert.Equal(t, int32(1), cleaned.Load(), "sealing cleans the shared backend up once, through root's mount")
	assert.Nil(t, systemBackendOf(core), "sealing forgets the backend, so no namespace is handed it again")
}

// TestCore_NamespaceSystemMountNeedsRootBackend pins that a namespace's sys/
// is never mounted without root's backend to hand it.
func TestCore_NamespaceSystemMountNeedsRootBackend(t *testing.T) {
	core := createTestCore(t)
	acme := &namespace.Namespace{ID: "acme-id", Path: "acme/"}
	entry := &MountEntry{Class: mountClassNSSystem, Type: mountClassNSSystem, Path: "sys/", NamespaceID: acme.ID, namespace: acme}

	core.mountsLock.Lock()
	core.systemBackend = nil
	_, err := core.newLogicalBackend(context.Background(), entry, nil)
	core.mountsLock.Unlock()

	require.ErrorContains(t, err, "system backend does not exist")
}

// TestCore_SetupMountsOrdersRootSystemFirst lists a namespace's sys/ ahead of
// root's: setup still mounts root's first, and the namespace's handle is on
// the backend built by this setup, not the one before it.
func TestCore_SetupMountsOrdersRootSystemFirst(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	acme := nsModify(t, core, ctx, "acme", nil)
	before := systemBackendOf(core)

	core.mountsLock.RLock()
	table := core.mounts.shallowClone()
	core.mountsLock.RUnlock()
	require.NoError(t, core.unloadMounts(ctx))

	slices.Reverse(table.Entries)
	require.Equal(t, mountClassNSSystem, table.Entries[0].Class, "precondition: a namespace's sys/ is listed first")
	core.mountsLock.Lock()
	core.mounts = table
	core.mountsLock.Unlock()
	require.NoError(t, core.setupMounts(ctx))

	after := systemBackendOf(core)
	require.NotNil(t, after)
	assert.NotSame(t, before, after)
	handle, ok := core.router.MatchingBackend(namespace.ContextWithNamespace(context.Background(), acme), "sys/").(nsSystemBackend)
	require.True(t, ok)
	assert.Same(t, after, handle.SystemBackend)
}

// TestCore_DefaultMountTable tests creating default mount table
func TestCore_DefaultMountTable(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := core.defaultMountTable(ctx)
	require.NotNil(t, table)

	// Should have required mounts
	assert.NotEmpty(t, table.Entries)
}

// TestCore_SplitNamespaceAndMountFromPath tests splitting namespace and mount
func TestCore_SplitNamespaceAndMountFromPath(t *testing.T) {
	core := createTestCore(t)

	result := core.splitNamespaceAndMountFromPath("", "sys/policies")
	assert.Equal(t, "sys/policies/", result.MountPath)
}

// TestSanitizePath tests path sanitization
func TestSanitizePath(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"test", "test/"},
		{"test/", "test/"},
		{"/test", "test/"},
		{"/test/", "test/"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizePath(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestCore_MountEntryView tests getting barrier view for mount entry
func TestCore_MountEntryView(t *testing.T) {
	core := createTestCore(t)

	t.Run("system mount", func(t *testing.T) {
		entry := &MountEntry{
			Class:       mountClassSystem,
			UUID:        "sys-uuid",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		view, err := core.mountEntryView(entry)
		require.NoError(t, err)
		require.NotNil(t, view)
		assert.Equal(t, systemBarrierPrefix, view.Prefix())
	})

	t.Run("provider mount", func(t *testing.T) {
		entry := &MountEntry{
			Class:       mountClassProvider,
			UUID:        "provider-uuid",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		view, err := core.mountEntryView(entry)
		require.NoError(t, err)
		require.NotNil(t, view)
		assert.Contains(t, view.Prefix(), providerBarrierPrefix)
	})

	t.Run("auth mount", func(t *testing.T) {
		entry := &MountEntry{
			Class:       mountClassAuth,
			UUID:        "auth-uuid",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		view, err := core.mountEntryView(entry)
		require.NoError(t, err)
		require.NotNil(t, view)
		assert.Contains(t, view.Prefix(), authBarrierPrefix)
	})

	t.Run("invalid mount class", func(t *testing.T) {
		entry := &MountEntry{
			Class:       "invalid",
			UUID:        "invalid-uuid",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		_, err := core.mountEntryView(entry)
		require.Error(t, err)
	})
}

// mixedClassTable builds a MountTable containing entries of every class so the
// accessor tests can confirm the filter is correct in both directions
// (returns the right entries; doesn't return the wrong ones).
func mixedClassTable(t *testing.T) *MountTable {
	t.Helper()
	table := NewMountTable()
	table.Entries = []*MountEntry{
		{
			Path: "jwt/", Type: "jwt", Class: mountClassAuth, UUID: "auth-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "cert/", Type: "cert", Class: mountClassAuth, UUID: "auth-2",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "vault/", Type: "vault", Class: mountClassProvider, UUID: "prov-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "aws/", Type: "aws", Class: mountClassProvider, UUID: "prov-2",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "sys/", Type: "system", Class: mountClassSystem, UUID: "sys-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
	}
	return table
}

func TestMountTable_findAllAuthMountsInNamespace_returnsAuthOnly(t *testing.T) {
	table := mixedClassTable(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	got, err := table.findAllAuthMountsInNamespace(ctx)
	require.NoError(t, err)
	require.Len(t, got, 2)

	// Order matches insertion order; assert by UUID for stability.
	assert.Equal(t, "auth-1", got[0].UUID)
	assert.Equal(t, "auth-2", got[1].UUID)
	for _, e := range got {
		assert.Equal(t, mountClassAuth, e.Class,
			"accessor must return only auth-class entries (got %s)", e.Class)
	}
}

func TestMountTable_findAllAuthMountsInNamespace_namespaceFiltered(t *testing.T) {
	otherNs := &namespace.Namespace{ID: "ns-other", Path: "other/"}
	table := NewMountTable()
	table.Entries = []*MountEntry{
		{
			Path: "jwt/", Type: "jwt", Class: mountClassAuth, UUID: "root-auth",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "jwt/", Type: "jwt", Class: mountClassAuth, UUID: "other-auth",
			NamespaceID: otherNs.ID, namespace: otherNs,
		},
	}

	rootCtx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	got, err := table.findAllAuthMountsInNamespace(rootCtx)
	require.NoError(t, err)
	require.Len(t, got, 1, "root namespace should see only its own auth mount")
	assert.Equal(t, "root-auth", got[0].UUID)

	otherCtx := namespace.ContextWithNamespace(context.Background(), otherNs)
	got, err = table.findAllAuthMountsInNamespace(otherCtx)
	require.NoError(t, err)
	require.Len(t, got, 1, "other namespace should see only its own auth mount")
	assert.Equal(t, "other-auth", got[0].UUID)
}

func TestMountTable_findAllAuthMountsInNamespace_emptyResult(t *testing.T) {
	// Table holds provider + system entries only; auth accessor returns empty.
	table := NewMountTable()
	table.Entries = []*MountEntry{
		{
			Path: "vault/", Class: mountClassProvider, UUID: "prov-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "sys/", Class: mountClassSystem, UUID: "sys-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
	}
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	got, err := table.findAllAuthMountsInNamespace(ctx)
	require.NoError(t, err)
	assert.NotNil(t, got, "must return non-nil empty slice (callers may JSON-marshal)")
	assert.Empty(t, got)
}

func TestMountTable_findAllAuthMountsInNamespace_emptyTable(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	got, err := table.findAllAuthMountsInNamespace(ctx)
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

func TestMountTable_findAllAuthMountsInNamespace_missingNamespaceContext(t *testing.T) {
	table := mixedClassTable(t)
	// Background context carries no namespace — accessor surfaces the
	// namespace-extraction error.
	_, err := table.findAllAuthMountsInNamespace(context.Background())
	assert.Error(t, err)
}

func TestMountTable_findAllProviderMountsInNamespace_returnsProviderOnly(t *testing.T) {
	table := mixedClassTable(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	got, err := table.findAllProviderMountsInNamespace(ctx)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "prov-1", got[0].UUID)
	assert.Equal(t, "prov-2", got[1].UUID)
	for _, e := range got {
		assert.Equal(t, mountClassProvider, e.Class)
	}
}

func TestMountTable_findAllProviderMountsInNamespace_doesNotReturnAuth(t *testing.T) {
	// Defense in depth: even with paths that look like they could collide
	// (jwt/ as both an auth method and a hypothetical provider mount name),
	// the provider accessor must never return auth entries.
	table := NewMountTable()
	table.Entries = []*MountEntry{
		{
			Path: "jwt/", Class: mountClassAuth, UUID: "auth-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
		{
			Path: "jwt/", Class: mountClassProvider, UUID: "prov-1",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		},
	}
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	got, err := table.findAllProviderMountsInNamespace(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "prov-1", got[0].UUID)
	assert.Equal(t, mountClassProvider, got[0].Class)
}

// ----------------------------------------------------------------------------
// Mount-table split tests (c.mounts / c.auth)
// ----------------------------------------------------------------------------

func TestCore_AuthTable_InitializedAtConstruction(t *testing.T) {
	core := createTestCore(t)
	require.NotNil(t, core.auth, "createTestCore must initialize c.auth alongside c.mounts")
	assert.NotNil(t, core.auth.Entries, "c.auth.Entries must be a non-nil empty slice")
	assert.Empty(t, core.auth.Entries, "fresh c.auth must hold zero entries")
}

func TestBackfillEntryFields_FillsMissing(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:  "test-jwt/",
		Type:  "jwt",
		Class: mountClassAuth,
		// Accessor, BackendAwareUUID, NamespaceID, namespace all empty.
	}

	changed, err := core.backfillEntryFields(ctx, entry)
	require.NoError(t, err)
	assert.True(t, changed, "helper must report changed=true when fields were filled")
	assert.Regexp(t, `^auth_jwt_[0-9a-f]{8}$`, entry.Accessor, "an auth entry's accessor must be filled with the auth_ prefix")
	assert.NotEmpty(t, entry.BackendAwareUUID, "BackendAwareUUID must be filled")
	assert.Equal(t, namespace.RootNamespaceID, entry.NamespaceID, "missing NamespaceID defaults to root")
	require.NotNil(t, entry.namespace, "namespace pointer must be resolved")
	assert.Equal(t, namespace.RootNamespaceID, entry.namespace.ID)
}

func TestBackfillEntryFields_NoOpWhenComplete(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// The accessor is an auth one assigned before auth_ was prefixed: it is
	// stored wherever the mount is referred to, so it must survive a load as is.
	entry := &MountEntry{
		Path:             "complete/",
		Type:             "jwt",
		Class:            mountClassAuth,
		UUID:             "fixed-uuid",
		Accessor:         "jwt_12345678",
		BackendAwareUUID: "fixed-backend-uuid",
		NamespaceID:      namespace.RootNamespaceID,
		namespace:        namespace.RootNamespace,
	}

	changed, err := core.backfillEntryFields(ctx, entry)
	require.NoError(t, err)
	assert.False(t, changed, "helper must report changed=false when nothing was filled")
	// Idempotence: the entry should be byte-identical.
	assert.Equal(t, "jwt_12345678", entry.Accessor)
	assert.Equal(t, "fixed-backend-uuid", entry.BackendAwareUUID)
}

func TestCore_Mount_AuthClass_RoutesToAuthTable(t *testing.T) {
	core := createTestCore(t)
	core.authMethods["mock"] = MockProviderFactory
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:  "test-auth",
		Type:  "mock",
		Class: mountClassAuth,
	}

	require.NoError(t, core.mount(ctx, entry))

	// Entry must land in c.auth, NOT c.mounts.
	core.authLock.RLock()
	found := false
	for _, e := range core.auth.Entries {
		if e.UUID == entry.UUID {
			found = true
			break
		}
	}
	core.authLock.RUnlock()
	assert.True(t, found, "auth-class entry must appear in c.auth after mount()")
	assert.Regexp(t, `^auth_mock_[0-9a-f]{8}$`, entry.Accessor, "an auth method's accessor names its class, unlike a provider's of the same type")

	core.mountsLock.RLock()
	for _, e := range core.mounts.Entries {
		assert.NotEqual(t, entry.UUID, e.UUID, "auth-class entry must NOT appear in c.mounts")
		assert.NotEqual(t, mountClassAuth, e.Class, "c.mounts must not hold any auth-class entries after the split")
	}
	core.mountsLock.RUnlock()
}

func TestCore_Mount_ProviderClass_RoutesToMountsTable(t *testing.T) {
	core := createTestCore(t)
	core.providers["mock"] = MockProviderFactory
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:  "test-provider",
		Type:  "mock",
		Class: mountClassProvider,
	}

	require.NoError(t, core.mount(ctx, entry))

	core.mountsLock.RLock()
	found := false
	for _, e := range core.mounts.Entries {
		if e.UUID == entry.UUID {
			found = true
			break
		}
	}
	core.mountsLock.RUnlock()
	assert.True(t, found, "provider-class entry must appear in c.mounts after mount()")
	assert.Regexp(t, `^mock_[0-9a-f]{8}$`, entry.Accessor, "a provider's accessor is its bare type, unlike an auth method's of the same type")

	core.authLock.RLock()
	for _, e := range core.auth.Entries {
		assert.NotEqual(t, entry.UUID, e.UUID, "provider-class entry must NOT appear in c.auth")
	}
	core.authLock.RUnlock()
}

func TestCore_Mount_AuditClass_Panics(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:  "test-audit",
		Type:  "file",
		Class: mountClassAudit,
	}

	// mount() must defensively panic for audit-class entries — audit goes
	// through EnableAudit, not the mount dispatcher.
	assert.Panics(t, func() {
		_ = core.mount(ctx, entry)
	}, "mount() with audit class must panic; audit must go through EnableAudit")
}

func TestCore_Unmount_AuthClass_DispatchesToAuthTable(t *testing.T) {
	core := createTestCore(t)
	core.authMethods["mock"] = MockProviderFactory
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{Path: "to-unmount", Type: "mock", Class: mountClassAuth}
	require.NoError(t, core.mount(ctx, entry))

	// Snapshot c.mounts.Entries length pre-unmount so we can confirm the
	// unmount doesn't accidentally touch the wrong table.
	core.mountsLock.RLock()
	mountsLenBefore := len(core.mounts.Entries)
	core.mountsLock.RUnlock()

	// User passes the path WITHOUT the auth/ prefix (handleAuthDelete sends
	// "to-unmount/" — unmountInternal detects auth via the checkMatch fallback).
	require.NoError(t, core.unmount(ctx, "to-unmount/"))

	// Entry gone from c.auth.
	core.authLock.RLock()
	for _, e := range core.auth.Entries {
		assert.NotEqual(t, entry.UUID, e.UUID, "auth entry must be removed from c.auth after unmount")
	}
	core.authLock.RUnlock()

	// c.mounts.Entries length is unchanged — we didn't accidentally touch
	// the wrong table.
	core.mountsLock.RLock()
	mountsLenAfter := len(core.mounts.Entries)
	core.mountsLock.RUnlock()
	assert.Equal(t, mountsLenBefore, mountsLenAfter, "unmount of auth entry must not modify c.mounts")
}

func TestCore_Unmount_ProviderClass_DispatchesToMountsTable(t *testing.T) {
	core := createTestCore(t)
	core.providers["mock"] = MockProviderFactory
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{Path: "to-unmount", Type: "mock", Class: mountClassProvider}
	require.NoError(t, core.mount(ctx, entry))

	core.authLock.RLock()
	authLenBefore := len(core.auth.Entries)
	core.authLock.RUnlock()

	require.NoError(t, core.unmount(ctx, "to-unmount/"))

	core.mountsLock.RLock()
	for _, e := range core.mounts.Entries {
		assert.NotEqual(t, entry.UUID, e.UUID, "provider entry must be removed from c.mounts after unmount")
	}
	core.mountsLock.RUnlock()

	core.authLock.RLock()
	authLenAfter := len(core.auth.Entries)
	core.authLock.RUnlock()
	assert.Equal(t, authLenBefore, authLenAfter, "unmount of provider entry must not modify c.auth")
}

// TestCore_Unmount_PrecedenceIsProviderFirst regresses against a future
// refactor accidentally swapping the unmountInternal checkMatch order. The
// rule: if both a provider mount at "jwt/" and an auth mount at "jwt/" exist
// (which they can — different router prefixes: "jwt/" vs "auth/jwt/"), a bare
// `c.unmount(ctx, "jwt/")` MUST hit the provider, not the auth mount.
func TestCore_Unmount_PrecedenceIsProviderFirst(t *testing.T) {
	core := createTestCore(t)
	core.providers["mock"] = MockProviderFactory
	core.authMethods["mock"] = MockProviderFactory
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	provider := &MountEntry{Path: "jwt", Type: "mock", Class: mountClassProvider}
	require.NoError(t, core.mount(ctx, provider))

	auth := &MountEntry{Path: "jwt", Type: "mock", Class: mountClassAuth}
	require.NoError(t, core.mount(ctx, auth))

	require.NoError(t, core.unmount(ctx, "jwt/"))

	// Provider should be gone from c.mounts.
	core.mountsLock.RLock()
	for _, e := range core.mounts.Entries {
		assert.NotEqual(t, provider.UUID, e.UUID, "provider 'jwt/' must be removed (precedence is provider-first)")
	}
	core.mountsLock.RUnlock()

	// Auth should still be present in c.auth — precedence rule says
	// the auth mount is NOT touched by a bare 'jwt/' unmount when a
	// provider at the same name exists.
	core.authLock.RLock()
	found := false
	for _, e := range core.auth.Entries {
		if e.UUID == auth.UUID {
			found = true
			break
		}
	}
	core.authLock.RUnlock()
	assert.True(t, found, "auth 'jwt/' must still exist after unmount('jwt/') hit the provider first")
}
