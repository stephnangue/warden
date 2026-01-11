package core

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
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

// TestCore_GenerateMountAccessor tests generating mount accessor
func TestCore_GenerateMountAccessor(t *testing.T) {
	core := createTestCore(t)

	accessor, err := core.generateMountAccessor("mock")
	require.NoError(t, err)
	assert.NotEmpty(t, accessor)
	assert.Contains(t, accessor, "mock_")
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
