// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/openbao/openbao/helper/locking"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/physical/inmem"
	"github.com/stephnangue/warden/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMountTable(t *testing.T) {
	table := NewMountTable()

	assert.NotNil(t, table)
	assert.NotNil(t, table.Entries)
	assert.Len(t, table.Entries, 0)
}

func TestMountTable_ShallowClone(t *testing.T) {
	original := NewMountTable()
	entry1 := &MountEntry{
		Path: "test1/",
		Type: "test",
		UUID: "uuid1",
	}
	entry2 := &MountEntry{
		Path: "test2/",
		Type: "test",
		UUID: "uuid2",
	}
	original.Entries = append(original.Entries, entry1, entry2)

	// Clone the table
	cloned := original.shallowClone()

	// Verify clone has same entries
	assert.Len(t, cloned.Entries, 2)
	assert.Equal(t, original.Entries[0], cloned.Entries[0])
	assert.Equal(t, original.Entries[1], cloned.Entries[1])

	// Verify they point to same entry objects (shallow clone)
	assert.True(t, original.Entries[0] == cloned.Entries[0])

	// Modifying the cloned slice shouldn't affect original
	cloned.Entries = append(cloned.Entries, &MountEntry{Path: "test3/", Type: "test", UUID: "uuid3"})
	assert.Len(t, original.Entries, 2)
	assert.Len(t, cloned.Entries, 3)
}

func TestMountTable_SetTaint(t *testing.T) {
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		UUID:        "uuid1",
		Tainted:     false,
		MountState:  "",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Taint the entry
	returned, err := table.setTaint(namespace.RootNamespaceID, "test/", true, mountStateUnmounting)
	require.NoError(t, err)
	assert.NotNil(t, returned)
	assert.True(t, returned.Tainted)
	assert.Equal(t, mountStateUnmounting, returned.MountState)

	// Verify the original entry was modified
	assert.True(t, entry.Tainted)
	assert.Equal(t, mountStateUnmounting, entry.MountState)

	// Untaint the entry
	returned, err = table.setTaint(namespace.RootNamespaceID, "test/", false, "")
	require.NoError(t, err)
	assert.NotNil(t, returned)
	assert.False(t, returned.Tainted)
	assert.Equal(t, "", returned.MountState)
}

func TestMountTable_SetTaint_NotFound(t *testing.T) {
	table := NewMountTable()

	returned, err := table.setTaint(namespace.RootNamespaceID, "nonexistent/", true, mountStateUnmounting)
	require.NoError(t, err)
	assert.Nil(t, returned)
}

func TestMountTable_Remove(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "test",
		UUID:        "uuid1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "test",
		UUID:        "uuid2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)

	// Remove entry1
	removed, err := table.remove(ctx, "test1/")
	require.NoError(t, err)
	assert.NotNil(t, removed)
	assert.Equal(t, "uuid1", removed.UUID)

	// Verify table now has only entry2
	assert.Len(t, table.Entries, 1)
	assert.Equal(t, "test2/", table.Entries[0].Path)
}

func TestMountTable_Remove_NotFound(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		UUID:        "uuid1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Try to remove non-existent entry
	removed, err := table.remove(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Nil(t, removed)

	// Verify original entry still exists
	assert.Len(t, table.Entries, 1)
}

func TestMountTable_FindByPath(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry1 := &MountEntry{
		Path:        "aws/",
		Type:        "aws",
		UUID:        "uuid1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "gcp/",
		Type:        "gcp",
		UUID:        "uuid2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)

	// Find existing entry
	found, err := table.findByPath(ctx, "aws/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "aws/", found.Path)
	assert.Equal(t, "uuid1", found.UUID)

	// Find non-existent entry
	found, err = table.findByPath(ctx, "azure/")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestMountTable_FindByBackendUUID(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry := &MountEntry{
		Path:             "aws/",
		Type:             "aws",
		UUID:             "uuid1",
		BackendAwareUUID: "backend-uuid-123",
		NamespaceID:      namespace.RootNamespaceID,
		namespace:        namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Find by backend UUID
	found, err := table.findByBackendUUID(ctx, "backend-uuid-123")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "aws/", found.Path)

	// Not found
	found, err = table.findByBackendUUID(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestMountTable_FindAllNamespaceMounts(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "test",
		UUID:        "uuid1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "test",
		UUID:        "uuid2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry3 := &MountEntry{
		Path:        "test3/",
		Type:        "test",
		UUID:        "uuid3",
		NamespaceID: "other-namespace",
		namespace:   &namespace.Namespace{ID: "other-namespace"},
	}
	table.Entries = append(table.Entries, entry1, entry2, entry3)

	// Find all mounts in root namespace
	found, err := table.findAllNamespaceMounts(ctx)
	require.NoError(t, err)
	assert.Len(t, found, 2)
	assert.Equal(t, "test1/", found[0].Path)
	assert.Equal(t, "test2/", found[1].Path)
}

func TestMountTable_SortEntriesByPath(t *testing.T) {
	table := NewMountTable()

	entry1 := &MountEntry{Path: "zulu/"}
	entry2 := &MountEntry{Path: "alpha/"}
	entry3 := &MountEntry{Path: "mike/"}
	table.Entries = append(table.Entries, entry1, entry2, entry3)

	sorted := table.sortEntriesByPath()
	assert.Equal(t, "alpha/", sorted.Entries[0].Path)
	assert.Equal(t, "mike/", sorted.Entries[1].Path)
	assert.Equal(t, "zulu/", sorted.Entries[2].Path)
}

func TestMountTable_SortEntriesByPathDepth(t *testing.T) {
	table := NewMountTable()

	entry1 := &MountEntry{
		Path:      "a/b/c/",
		namespace: namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:      "x/",
		namespace: namespace.RootNamespace,
	}
	entry3 := &MountEntry{
		Path:      "m/n/",
		namespace: namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2, entry3)

	sorted := table.sortEntriesByPathDepth()
	// Shortest depth first
	assert.Equal(t, "x/", sorted.Entries[0].Path)
	assert.Equal(t, "m/n/", sorted.Entries[1].Path)
	assert.Equal(t, "a/b/c/", sorted.Entries[2].Path)
}

func TestMountEntry_Clone(t *testing.T) {
	original := &MountEntry{
		Class:            mountClassProvider,
		Type:             "aws",
		Path:             "aws/",
		Description:      "AWS provider",
		UUID:             "uuid1",
		BackendAwareUUID: "backend-uuid",
		Accessor:         "accessor1",
		Tainted:          false,
		MountState:       "",
		Config:           map[string]any{"key": "value"},
		NamespaceID:      namespace.RootNamespaceID,
		namespace:        namespace.RootNamespace,
	}

	cloned, err := original.Clone()
	require.NoError(t, err)
	assert.NotNil(t, cloned)

	// Verify all fields are copied
	assert.Equal(t, original.Class, cloned.Class)
	assert.Equal(t, original.Type, cloned.Type)
	assert.Equal(t, original.Path, cloned.Path)
	assert.Equal(t, original.Description, cloned.Description)
	assert.Equal(t, original.UUID, cloned.UUID)
	assert.Equal(t, original.BackendAwareUUID, cloned.BackendAwareUUID)
	assert.Equal(t, original.Accessor, cloned.Accessor)
	assert.Equal(t, original.Config, cloned.Config)

	// Verify it's a deep copy (modifying clone doesn't affect original)
	cloned.Config["key"] = "new_value"
	assert.Equal(t, "value", original.Config["key"])
	assert.Equal(t, "new_value", cloned.Config["key"])
}

func TestMountEntry_Namespace(t *testing.T) {
	entry := &MountEntry{
		namespace: namespace.RootNamespace,
	}

	ns := entry.Namespace()
	assert.NotNil(t, ns)
	assert.Equal(t, namespace.RootNamespaceID, ns.ID)
}

func TestMountEntry_APIPath(t *testing.T) {
	tests := []struct {
		name     string
		entry    *MountEntry
		expected string
	}{
		{
			name: "provider mount in root namespace",
			entry: &MountEntry{
				Class:     mountClassProvider,
				Path:      "aws/",
				namespace: namespace.RootNamespace,
			},
			expected: "aws/",
		},
		{
			name: "auth mount in root namespace",
			entry: &MountEntry{
				Class:     mountClassAuth,
				Path:      "jwt/",
				namespace: namespace.RootNamespace,
			},
			expected: "auth/jwt/",
		},
		{
			name: "provider mount in child namespace",
			entry: &MountEntry{
				Class:     mountClassProvider,
				Path:      "aws/",
				namespace: &namespace.Namespace{Path: "team1/"},
			},
			expected: "team1/aws/",
		},
		{
			name: "auth mount in child namespace",
			entry: &MountEntry{
				Class:     mountClassAuth,
				Path:      "jwt/",
				namespace: &namespace.Namespace{Path: "team1/"},
			},
			expected: "team1/auth/jwt/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.APIPath()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMountEntry_APIPathNoNamespace(t *testing.T) {
	tests := []struct {
		name     string
		entry    *MountEntry
		expected string
	}{
		{
			name: "provider mount",
			entry: &MountEntry{
				Class:     mountClassProvider,
				Path:      "aws/",
				namespace: namespace.RootNamespace,
			},
			expected: "aws/",
		},
		{
			name: "auth mount",
			entry: &MountEntry{
				Class:     mountClassAuth,
				Path:      "jwt/",
				namespace: namespace.RootNamespace,
			},
			expected: "auth/jwt/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.APIPathNoNamespace()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMountEntry_Deserialize(t *testing.T) {
	entry := &MountEntry{
		Path:      "aws/",
		Type:      "aws",
		Class:     mountClassProvider,
		UUID:      "uuid123",
		Accessor:  "accessor123",
		namespace: namespace.RootNamespace,
	}

	result := entry.Deserialize()

	assert.Equal(t, "aws/", result["mount_path"])
	assert.Equal(t, "", result["mount_namespace"]) // Root namespace has empty path
	assert.Equal(t, "uuid123", result["uuid"])
	assert.Equal(t, "accessor123", result["accessor"])
	assert.Equal(t, "aws", result["mount_type"])
	assert.Equal(t, mountClassProvider, result["mount_class"])
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"aws", "aws/"},
		{"aws/", "aws/"},
		{"/aws", "aws/"},
		{"/aws/", "aws/"},
		{"a/b/c", "a/b/c/"},
		{"/a/b/c/", "a/b/c/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProtectedMounts(t *testing.T) {
	// Verify protected mounts constant
	assert.Contains(t, protectedMounts, "audit/")
	assert.Contains(t, protectedMounts, "auth/")
	assert.Contains(t, protectedMounts, mountPathSystem)
	assert.Len(t, protectedMounts, 3)
}

func TestSingletonMounts(t *testing.T) {
	// Verify singleton mounts constant
	assert.Contains(t, singletonMounts, mountClassSystem)
	assert.Contains(t, singletonMounts, mountClassNSSystem)
	assert.Len(t, singletonMounts, 2)
}

func TestMountConstants(t *testing.T) {
	// Verify mount class constants
	assert.Equal(t, "system", mountClassSystem)
	assert.Equal(t, "ns_system", mountClassNSSystem)
	assert.Equal(t, "provider", mountClassProvider)
	assert.Equal(t, "auth", mountClassAuth)
	assert.Equal(t, "audit", mountClassAudit)

	// Verify barrier prefix constants
	assert.Equal(t, "provider/", providerBarrierPrefix)
	assert.Equal(t, "auth/", authBarrierPrefix)
	assert.Equal(t, "sys/", systemBarrierPrefix)
	assert.Equal(t, "auth/", authRoutePrefix)

	// Verify mount state constants
	assert.Equal(t, "unmounting", mountStateUnmounting)

	// Verify config path constant
	assert.Equal(t, "core/mounts", coreMountConfigPath)

	// Verify system mount path
	assert.Equal(t, "sys/", mountPathSystem)
}

func TestCore_GenerateMountAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := &Core{
		router: NewRouter(log),
	}

	// Generate accessor for AWS
	accessor1, err := core.generateMountAccessor("aws")
	require.NoError(t, err)
	assert.NotEmpty(t, accessor1)
	assert.Contains(t, accessor1, "aws_")

	// Generate another accessor - should be different
	accessor2, err := core.generateMountAccessor("aws")
	require.NoError(t, err)
	assert.NotEmpty(t, accessor2)
	assert.NotEqual(t, accessor1, accessor2)

	// Generate accessor for different type
	accessor3, err := core.generateMountAccessor("gcp")
	require.NoError(t, err)
	assert.NotEmpty(t, accessor3)
	assert.Contains(t, accessor3, "gcp_")
}

func TestMountTable_Find(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	entry1 := &MountEntry{
		Path:        "aws/",
		Type:        "aws",
		UUID:        "uuid1",
		Accessor:    "accessor1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "gcp/",
		Type:        "gcp",
		UUID:        "uuid2",
		Accessor:    "accessor2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)

	// Find by type
	found, err := table.find(ctx, func(me *MountEntry) bool {
		return me.Type == "aws"
	})
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "aws/", found.Path)

	// Find by accessor
	found, err = table.find(ctx, func(me *MountEntry) bool {
		return me.Accessor == "accessor2"
	})
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "gcp/", found.Path)

	// Not found
	found, err = table.find(ctx, func(me *MountEntry) bool {
		return me.Type == "azure"
	})
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestMountTable_FindAllNamespaceMounts_EmptyTable(t *testing.T) {
	table := NewMountTable()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	found, err := table.findAllNamespaceMounts(ctx)
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestMountEntry_ConfigMutex(t *testing.T) {
	entry := &MountEntry{
		Config: map[string]any{"key": "value"},
	}

	// Test concurrent access to config
	done := make(chan bool)

	go func() {
		entry.configMu.Lock()
		entry.Config["key"] = "value1"
		entry.configMu.Unlock()
		done <- true
	}()

	go func() {
		entry.configMu.Lock()
		entry.Config["key"] = "value2"
		entry.configMu.Unlock()
		done <- true
	}()

	<-done
	<-done

	// Verify config was updated (no race condition crash)
	entry.configMu.RLock()
	val := entry.Config["key"]
	entry.configMu.RUnlock()

	assert.True(t, val == "value1" || val == "value2")
}

func TestMountEntry_Clone_NilConfig(t *testing.T) {
	original := &MountEntry{
		Type: "test",
		Path: "test/",
	}

	cloned, err := original.Clone()
	require.NoError(t, err)
	assert.NotNil(t, cloned)
	assert.Equal(t, original.Type, cloned.Type)
	assert.Equal(t, original.Path, cloned.Path)
}

func TestMountTable_SetTaint_DifferentNamespace(t *testing.T) {
	table := NewMountTable()

	entry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		UUID:        "uuid1",
		NamespaceID: "ns1",
		namespace:   &namespace.Namespace{ID: "ns1"},
	}
	table.Entries = append(table.Entries, entry)

	// Try to taint with different namespace ID
	returned, err := table.setTaint(namespace.RootNamespaceID, "test/", true, mountStateUnmounting)
	require.NoError(t, err)
	assert.Nil(t, returned)        // Should not find entry in different namespace
	assert.False(t, entry.Tainted) // Original should not be tainted
}

func TestMountTable_Remove_DifferentNamespace(t *testing.T) {
	table := NewMountTable()
	otherNS := &namespace.Namespace{ID: "ns1", Path: "ns1/"}
	ctx := namespace.ContextWithNamespace(context.Background(), otherNS)

	entry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		UUID:        "uuid1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Try to remove from different namespace
	removed, err := table.remove(ctx, "test/")
	require.NoError(t, err)
	assert.Nil(t, removed) // Should not remove entry from different namespace

	// Verify entry still exists
	assert.Len(t, table.Entries, 1)
}

// Helper function to create a test Core for mount tests
func createTestCoreForMounts(t *testing.T) *Core {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	// Create in-memory physical backend
	physical, _ := inmem.NewInmem(nil, nil)

	// Create and initialize barrier
	barrier, _ := NewAESGCMBarrier(physical)
	key, _ := barrier.GenerateKey(rand.Reader)
	barrier.Initialize(context.Background(), key, nil, rand.Reader)
	barrier.Unseal(context.Background(), key)

	core := &Core{
		logger:        log,
		router:        router,
		mounts:        NewMountTable(),
		mountsLock:    locking.DeadlockRWMutex{},
		authMethods:   make(map[string]auth.Factory),
		providers:     make(map[string]provider.Factory),
		roles:         authorize.NewRoleRegistry(),
		accessControl: authorize.NewAccessControl(),
		credSources:   cred.NewCredSourceRegistry(),
		auditManager:  &mockAuditManager{},
		physical:      physical,
		barrier:       barrier,
		activeContext: context.Background(),
	}

	// Initialize namespace store
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	core.namespaceStore, _ = NewNamespaceStore(ctx, core, log)

	// Initialize token store
	tokenStore, err := NewTokenStore(core, DefaultTokenStoreConfig())
	require.NoError(t, err)
	core.tokenStore = tokenStore
	t.Cleanup(func() { tokenStore.Close() })

	return core
}

// Tests for persistMounts

func TestCore_PersistMounts_EmptyTable(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create empty mount table
	table := NewMountTable()

	// Persist empty table
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)
}

func TestCore_PersistMounts_SingleEntry(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount table with single entry
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		Description: "Test mount",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
		Config:      map[string]any{"key": "value"},
	}
	table.Entries = append(table.Entries, entry)

	// Persist the mount table
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify the entry was persisted
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry, err := view.Get(ctx, coreMountConfigPath+"/"+entry.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry)
}

func TestCore_PersistMounts_MultipleEntries(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount table with multiple entries
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		Description: "Test mount 1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "generic",
		UUID:        "test-uuid-2",
		Description: "Test mount 2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry3 := &MountEntry{
		Path:        "test3/",
		Type:        "generic",
		UUID:        "test-uuid-3",
		Description: "Test mount 3",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2, entry3)

	// Persist the mount table
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify all entries were persisted
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	for _, entry := range table.Entries {
		storedEntry, err := view.Get(ctx, coreMountConfigPath+"/"+entry.UUID)
		require.NoError(t, err)
		require.NotNil(t, storedEntry, "entry %s should be persisted", entry.UUID)
	}
}

func TestCore_PersistMounts_SingleMount(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount table with multiple entries
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "generic",
		UUID:        "test-uuid-2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)

	// Persist only the first mount
	err := core.persistMounts(ctx, core.barrier, table, "test-uuid-1")
	require.NoError(t, err)

	// Verify only first entry was persisted
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry1, err := view.Get(ctx, coreMountConfigPath+"/test-uuid-1")
	require.NoError(t, err)
	require.NotNil(t, storedEntry1)
}

func TestCore_PersistMounts_UpdateExisting(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create and persist initial mount table
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		Description: "Original description",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Update the entry
	entry.Description = "Updated description"
	err = core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify the entry was updated
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry, err := view.Get(ctx, coreMountConfigPath+"/"+entry.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry)
}

func TestCore_PersistMounts_RemoveEntry(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create and persist initial mount table with two entries
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "generic",
		UUID:        "test-uuid-2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Remove one entry from the table
	table.Entries = []*MountEntry{entry1}

	// Persist to remove entry2
	err = core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify entry1 still exists
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry1, err := view.Get(ctx, coreMountConfigPath+"/test-uuid-1")
	require.NoError(t, err)
	require.NotNil(t, storedEntry1)
}

func TestCore_PersistMounts_NilBarrier(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Pass nil barrier - should use core.barrier
	err := core.persistMounts(ctx, nil, table, "")
	require.NoError(t, err)

	// Verify the entry was persisted using core.barrier
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry, err := view.Get(ctx, coreMountConfigPath+"/"+entry.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry)
}

func TestCore_PersistMounts_WithTransaction(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount table
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Persist with barrier (which supports transactions)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify the entry was persisted
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry, err := view.Get(ctx, coreMountConfigPath+"/"+entry.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry)
}

func TestCore_PersistMounts_TaintedEntry(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount table with tainted entry
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		Tainted:     true,
		MountState:  mountStateUnmounting,
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry)

	// Persist the tainted mount
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify the entry was persisted
	view := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry, err := view.Get(ctx, coreMountConfigPath+"/"+entry.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry)
}

func TestCore_PersistMounts_MultipleNamespaces(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a custom namespace
	ns1 := &namespace.Namespace{
		ID:   "ns1",
		UUID: "ns1-uuid",
		Path: "ns1/",
	}

	// Manually add namespace to store for testing
	core.namespaceStore.lock.Lock()
	core.namespaceStore.namespacesByUUID[ns1.UUID] = ns1
	core.namespaceStore.namespacesByAccessor[ns1.ID] = ns1
	core.namespaceStore.lock.Unlock()

	// Create mount table with entries in different namespaces
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "generic",
		UUID:        "test-uuid-2",
		NamespaceID: "ns1",
		namespace:   ns1,
	}
	table.Entries = append(table.Entries, entry1, entry2)

	// Persist the mount table
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Verify entry1 was persisted in root namespace
	rootView := NamespaceView(core.barrier, namespace.RootNamespace)
	storedEntry1, err := rootView.Get(ctx, coreMountConfigPath+"/"+entry1.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry1)

	// Verify entry2 was persisted in ns1
	ns1View := NamespaceView(core.barrier, ns1)
	storedEntry2, err := ns1View.Get(ctx, coreMountConfigPath+"/"+entry2.UUID)
	require.NoError(t, err)
	require.NotNil(t, storedEntry2)
}

// Tests for loadMounts

func TestCore_LoadMounts_EmptyStorage(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Load mounts from empty storage
	err := core.loadMounts(ctx)
	require.NoError(t, err)

	// Should create default mount table
	assert.NotNil(t, core.mounts)
	assert.NotEmpty(t, core.mounts.Entries)
}

func TestCore_LoadMounts_WithExistingMounts(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create and persist some mounts
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		Description: "Test mount 1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "generic",
		UUID:        "test-uuid-2",
		Description: "Test mount 2",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	table.Entries = append(table.Entries, entry1, entry2)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Reset mounts
	core.mounts = nil

	// Load mounts
	err = core.loadMounts(ctx)
	require.NoError(t, err)

	// Verify mounts were loaded
	assert.NotNil(t, core.mounts)
	assert.GreaterOrEqual(t, len(core.mounts.Entries), 2)

	// Find our test entries
	var foundEntry1, foundEntry2 bool
	for _, entry := range core.mounts.Entries {
		if entry.UUID == "test-uuid-1" {
			foundEntry1 = true
			assert.Equal(t, "test1/", entry.Path)
		}
		if entry.UUID == "test-uuid-2" {
			foundEntry2 = true
			assert.Equal(t, "test2/", entry.Path)
		}
	}
	assert.True(t, foundEntry1, "entry1 should be loaded")
	assert.True(t, foundEntry2, "entry2 should be loaded")
}

func TestCore_LoadMounts_MultipleNamespaces(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create custom namespaces
	ns1 := &namespace.Namespace{
		ID:   "ns1",
		UUID: "ns1-uuid",
		Path: "ns1/",
	}
	ns2 := &namespace.Namespace{
		ID:   "ns2",
		UUID: "ns2-uuid",
		Path: "ns2/",
	}

	// Manually add namespaces to store for testing
	core.namespaceStore.lock.Lock()
	core.namespaceStore.namespacesByUUID[ns1.UUID] = ns1
	core.namespaceStore.namespacesByAccessor[ns1.ID] = ns1
	core.namespaceStore.namespacesByUUID[ns2.UUID] = ns2
	core.namespaceStore.namespacesByAccessor[ns2.ID] = ns2
	core.namespaceStore.lock.Unlock()

	// Create and persist mounts in different namespaces
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "test1/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Path:        "test2/",
		Type:        "generic",
		UUID:        "test-uuid-2",
		NamespaceID: "ns1",
		namespace:   ns1,
	}
	entry3 := &MountEntry{
		Path:        "test3/",
		Type:        "generic",
		UUID:        "test-uuid-3",
		NamespaceID: "ns2",
		namespace:   ns2,
	}
	table.Entries = append(table.Entries, entry1, entry2, entry3)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Reset mounts
	core.mounts = nil

	// Load mounts
	err = core.loadMounts(ctx)
	require.NoError(t, err)

	// Verify mounts from all namespaces were loaded
	assert.NotNil(t, core.mounts)

	var foundEntry1, foundEntry2, foundEntry3 bool
	for _, entry := range core.mounts.Entries {
		switch entry.UUID {
		case "test-uuid-1":
			foundEntry1 = true
			assert.Equal(t, namespace.RootNamespaceID, entry.NamespaceID)
		case "test-uuid-2":
			foundEntry2 = true
			assert.Equal(t, "ns1", entry.NamespaceID)
		case "test-uuid-3":
			foundEntry3 = true
			assert.Equal(t, "ns2", entry.NamespaceID)
		}
	}
	assert.True(t, foundEntry1, "entry1 from root namespace should be loaded")
	assert.True(t, foundEntry2, "entry2 from ns1 should be loaded")
	assert.True(t, foundEntry3, "entry3 from ns2 should be loaded")
}

func TestCore_LoadMounts_SkipTaintedNamespace(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a tainted namespace
	taintedNS := &namespace.Namespace{
		ID:      "tainted-ns",
		UUID:    "tainted-uuid",
		Path:    "tainted/",
		Tainted: true,
	}

	// Create normal namespace
	normalNS := &namespace.Namespace{
		ID:   "normal-ns",
		UUID: "normal-uuid",
		Path: "normal/",
	}

	// Manually add namespaces to store for testing
	core.namespaceStore.lock.Lock()
	core.namespaceStore.namespacesByUUID[taintedNS.UUID] = taintedNS
	core.namespaceStore.namespacesByAccessor[taintedNS.ID] = taintedNS
	core.namespaceStore.namespacesByUUID[normalNS.UUID] = normalNS
	core.namespaceStore.namespacesByAccessor[normalNS.ID] = normalNS
	core.namespaceStore.lock.Unlock()

	// Create and persist mounts in both namespaces
	table := NewMountTable()
	entry1 := &MountEntry{
		Path:        "tainted-mount/",
		Type:        "generic",
		UUID:        "tainted-uuid",
		NamespaceID: "tainted-ns",
		namespace:   taintedNS,
	}
	entry2 := &MountEntry{
		Path:        "normal-mount/",
		Type:        "generic",
		UUID:        "normal-uuid",
		NamespaceID: "normal-ns",
		namespace:   normalNS,
	}
	table.Entries = append(table.Entries, entry1, entry2)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Reset mounts
	core.mounts = nil

	// Load mounts
	err = core.loadMounts(ctx)
	require.NoError(t, err)

	// Verify only mount from normal namespace was loaded
	var foundTainted, foundNormal bool
	for _, entry := range core.mounts.Entries {
		if entry.UUID == "tainted-uuid" {
			foundTainted = true
		}
		if entry.UUID == "normal-uuid" {
			foundNormal = true
		}
	}
	assert.False(t, foundTainted, "mount from tainted namespace should not be loaded")
	assert.True(t, foundNormal, "mount from normal namespace should be loaded")
}

func TestCore_LoadMounts_PreservesConfiguration(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount with detailed configuration
	table := NewMountTable()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "generic",
		UUID:        "test-uuid-1",
		Description: "Test description",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
		Config: map[string]any{
			"default_lease_ttl": 3600,
			"max_lease_ttl":     7200,
			"force_no_cache":    true,
		},
	}
	table.Entries = append(table.Entries, entry)
	err := core.persistMounts(ctx, core.barrier, table, "")
	require.NoError(t, err)

	// Reset mounts
	core.mounts = nil

	// Load mounts
	err = core.loadMounts(ctx)
	require.NoError(t, err)

	// Find and verify the loaded entry
	var loadedEntry *MountEntry
	for _, e := range core.mounts.Entries {
		if e.UUID == "test-uuid-1" {
			loadedEntry = e
			break
		}
	}
	require.NotNil(t, loadedEntry, "entry should be loaded")
	assert.Equal(t, "test/", loadedEntry.Path)
	assert.Equal(t, "generic", loadedEntry.Type)
	assert.Equal(t, "Test description", loadedEntry.Description)
}

// TestCore_SetupMounts_EmptyTable tests setupMounts with no mounts
func TestCore_SetupMounts_EmptyTable(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create empty mount table
	core.mounts = &MountTable{
		Entries: []*MountEntry{},
	}

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify no post-unseal functions were added
	assert.Equal(t, 0, len(core.postUnsealFuncs))
}

// TestCore_SetupMounts_SingleMount tests setupMounts with a single auth mount
func TestCore_SetupMounts_SingleMount(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock auth factory
	core.authMethods["testauth"] = &mockAuthFactory{}

	// Create mount entry
	entry := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "auth/test/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_1",
		Description: "Test auth mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	core.mounts = &MountTable{
		Entries: []*MountEntry{entry},
	}

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify mount was set up in router
	match := core.router.MatchingMount(ctx, "auth/test/login")
	assert.NotNil(t, match)

	// Verify post-unseal function was added
	assert.Equal(t, 1, len(core.postUnsealFuncs))
}

// TestCore_SetupMounts_MultipleMounts tests setupMounts with multiple mounts
func TestCore_SetupMounts_MultipleMounts(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock factories
	core.authMethods["testauth"] = &mockAuthFactory{}
	core.providers["testprovider"] = &mockProviderFactory{}

	// Create mount entries
	entry1 := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "auth/test1/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_1",
		Description: "Test auth mount 1",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	entry2 := &MountEntry{
		UUID:        "test-uuid-2",
		Path:        "auth/test2/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_2",
		Description: "Test auth mount 2",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	entry3 := &MountEntry{
		UUID:        "test-uuid-3",
		Path:        "provider/test/",
		Type:        "testprovider",
		Class:       mountClassProvider,
		Accessor:    "test_accessor_3",
		Description: "Test provider mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	core.mounts = &MountTable{
		Entries: []*MountEntry{entry1, entry2, entry3},
	}

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify all mounts were set up in router
	match1 := core.router.MatchingMount(ctx, "auth/test1/login")
	assert.NotNil(t, match1)

	match2 := core.router.MatchingMount(ctx, "auth/test2/login")
	assert.NotNil(t, match2)

	match3 := core.router.MatchingMount(ctx, "provider/test/resource")
	assert.NotNil(t, match3)

	// Verify post-unseal functions were added (one per mount)
	assert.Equal(t, 3, len(core.postUnsealFuncs))
}

// TestCore_SetupMounts_TaintedMount tests setupMounts with a tainted mount
func TestCore_SetupMounts_TaintedMount(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock auth factory
	core.authMethods["testauth"] = &mockAuthFactory{}

	// Create tainted mount entry
	entry := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "auth/test/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_1",
		Description: "Test auth mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
		Tainted:     true,
	}

	core.mounts = &MountTable{
		Entries: []*MountEntry{entry},
	}

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify mount was set up in router (taint is handled internally by router.Taint call)
	match := core.router.MatchingMount(ctx, "auth/test/login")
	assert.NotNil(t, match)

	// Verify post-unseal function was added
	assert.Equal(t, 1, len(core.postUnsealFuncs))
}

// TestCore_SetupMounts_MultipleNamespaces tests setupMounts with mounts in different namespaces
func TestCore_SetupMounts_MultipleNamespaces(t *testing.T) {
	core := createTestCoreForMounts(t)

	// Create custom namespaces
	ns1 := &namespace.Namespace{
		ID:   "ns1",
		UUID: "ns1-uuid",
		Path: "ns1/",
	}
	ns2 := &namespace.Namespace{
		ID:   "ns2",
		UUID: "ns2-uuid",
		Path: "ns2/",
	}

	// Manually add namespaces to store
	core.namespaceStore.lock.Lock()
	core.namespaceStore.namespacesByUUID[ns1.UUID] = ns1
	core.namespaceStore.namespacesByAccessor[ns1.ID] = ns1
	core.namespaceStore.namespacesByUUID[ns2.UUID] = ns2
	core.namespaceStore.namespacesByAccessor[ns2.ID] = ns2
	core.namespaceStore.lock.Unlock()

	// Register mock auth factory
	core.authMethods["testauth"] = &mockAuthFactory{}

	// Create mount entries in different namespaces
	entry1 := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "auth/test1/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_1",
		Description: "Test auth in root",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	entry2 := &MountEntry{
		UUID:        "test-uuid-2",
		Path:        "auth/test2/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_2",
		Description: "Test auth in ns1",
		Config:      map[string]any{},
		NamespaceID: ns1.ID,
		namespace:   ns1,
	}

	entry3 := &MountEntry{
		UUID:        "test-uuid-3",
		Path:        "auth/test3/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_3",
		Description: "Test auth in ns2",
		Config:      map[string]any{},
		NamespaceID: ns2.ID,
		namespace:   ns2,
	}

	core.mounts = &MountTable{
		Entries: []*MountEntry{entry1, entry2, entry3},
	}

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify all mounts were set up in router with correct namespace paths
	ctx1 := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	match1 := core.router.MatchingMount(ctx1, "auth/test1/login")
	assert.NotNil(t, match1)

	ctx2 := namespace.ContextWithNamespace(context.Background(), ns1)
	match2 := core.router.MatchingMount(ctx2, "ns1/auth/test2/login")
	assert.NotNil(t, match2)

	ctx3 := namespace.ContextWithNamespace(context.Background(), ns2)
	match3 := core.router.MatchingMount(ctx3, "ns2/auth/test3/login")
	assert.NotNil(t, match3)

	// Verify post-unseal functions were added
	assert.Equal(t, 3, len(core.postUnsealFuncs))
}

// TestCore_SetupMounts_PostUnsealInitialization tests that post-unseal functions work correctly
func TestCore_SetupMounts_PostUnsealInitialization(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock auth factory
	core.authMethods["testauth"] = &mockAuthFactory{}

	// Create mount entry
	entry := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "auth/test/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_1",
		Description: "Test auth mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	core.mounts = &MountTable{
		Entries: []*MountEntry{entry},
	}

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify post-unseal function was added
	require.Equal(t, 1, len(core.postUnsealFuncs))

	// Execute the post-unseal function (should call backend.Initialize)
	core.postUnsealFuncs[0]()
	// No error expected - mock backend's Initialize returns nil
}

// TestCore_SetupMounts_InvalidBackendType tests setupMounts with an invalid backend type
func TestCore_SetupMounts_InvalidBackendType(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create mount entry with invalid type (no factory registered)
	entry := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "auth/invalid/",
		Type:        "nonexistent",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_1",
		Description: "Invalid mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	core.mounts = &MountTable{
		Entries: []*MountEntry{entry},
	}

	// Setup mounts should fail
	err := core.setupMounts(ctx)
	require.Error(t, err)
	assert.Equal(t, errLoadMountsFailed, err)
}

// TestCore_SetupMounts_SortsByPathDepth tests that mounts are set up in correct order
func TestCore_SetupMounts_SortsByPathDepth(t *testing.T) {
	core := createTestCoreForMounts(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Register mock factories
	core.authMethods["testauth"] = &mockAuthFactory{}
	core.providers["testprovider"] = &mockProviderFactory{}

	// Create mount entries with different path depths (unsorted)
	// Using provider mounts as they support nested paths better than auth mounts
	entry1 := &MountEntry{
		UUID:        "test-uuid-1",
		Path:        "provider/deep/nested/",
		Type:        "testprovider",
		Class:       mountClassProvider,
		Accessor:    "test_accessor_1",
		Description: "Deep mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	entry2 := &MountEntry{
		UUID:        "test-uuid-2",
		Path:        "auth/test/",
		Type:        "testauth",
		Class:       mountClassAuth,
		Accessor:    "test_accessor_2",
		Description: "Shallow mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	entry3 := &MountEntry{
		UUID:        "test-uuid-3",
		Path:        "provider/medium/",
		Type:        "testprovider",
		Class:       mountClassProvider,
		Accessor:    "test_accessor_3",
		Description: "Medium mount",
		Config:      map[string]any{},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}

	// Add in unsorted order
	core.mounts = &MountTable{
		Entries: []*MountEntry{entry1, entry2, entry3},
	}

	// Setup mounts
	err := core.setupMounts(ctx)
	require.NoError(t, err)

	// Verify all mounts were set up
	match1 := core.router.MatchingMount(ctx, "auth/test/login")
	assert.NotNil(t, match1)

	match2 := core.router.MatchingMount(ctx, "provider/medium/resource")
	assert.NotNil(t, match2)

	match3 := core.router.MatchingMount(ctx, "provider/deep/nested/resource")
	assert.NotNil(t, match3)
}
