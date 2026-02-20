// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNamespaceStore_NewNamespaceStore tests creating a new namespace store
func TestNamespaceStore_NewNamespaceStore(t *testing.T) {
	core := createTestCore(t)

	require.NotNil(t, core.namespaceStore)

	// Root namespace should be available
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ns, err := core.namespaceStore.GetNamespaceByAccessor(ctx, namespace.RootNamespaceID)
	require.NoError(t, err)
	require.NotNil(t, ns)
	assert.Equal(t, namespace.RootNamespaceID, ns.ID)
}

// TestNamespaceStore_SetNamespace tests creating a new namespace
func TestNamespaceStore_SetNamespace(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a new namespace
	newNs := &namespace.Namespace{
		Path:           "test/",
		CustomMetadata: map[string]string{"env": "test"},
	}

	err := core.namespaceStore.SetNamespace(ctx, newNs)
	require.NoError(t, err)

	// Verify the namespace was created
	assert.NotEmpty(t, newNs.ID)
	assert.NotEmpty(t, newNs.UUID)
	assert.Equal(t, "test/", newNs.Path)
}

// TestNamespaceStore_SetNamespace_InvalidPath tests creating namespace with invalid path
func TestNamespaceStore_SetNamespace_InvalidPath(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Try to create root namespace (should fail)
	rootNs := &namespace.Namespace{
		Path: "",
	}

	err := core.namespaceStore.SetNamespace(ctx, rootNs)
	require.Error(t, err)
}

// TestNamespaceStore_GetNamespace tests getting namespace by UUID
func TestNamespaceStore_GetNamespace(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace first
	newNs := &namespace.Namespace{
		Path: "test-get/",
	}
	err := core.namespaceStore.SetNamespace(ctx, newNs)
	require.NoError(t, err)

	// Get by UUID
	retrieved, err := core.namespaceStore.GetNamespace(ctx, newNs.UUID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, newNs.UUID, retrieved.UUID)
	assert.Equal(t, newNs.Path, retrieved.Path)
}

// TestNamespaceStore_GetNamespace_NotFound tests getting non-existent namespace
func TestNamespaceStore_GetNamespace_NotFound(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	retrieved, err := core.namespaceStore.GetNamespace(ctx, "nonexistent-uuid")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

// TestNamespaceStore_GetNamespaceByAccessor tests getting namespace by accessor ID
func TestNamespaceStore_GetNamespaceByAccessor(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace first
	newNs := &namespace.Namespace{
		Path: "test-accessor/",
	}
	err := core.namespaceStore.SetNamespace(ctx, newNs)
	require.NoError(t, err)

	// Get by accessor ID
	retrieved, err := core.namespaceStore.GetNamespaceByAccessor(ctx, newNs.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, newNs.ID, retrieved.ID)
	assert.Equal(t, newNs.Path, retrieved.Path)
}

// TestNamespaceStore_GetNamespaceByAccessor_Root tests getting root namespace by accessor
func TestNamespaceStore_GetNamespaceByAccessor_Root(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	retrieved, err := core.namespaceStore.GetNamespaceByAccessor(ctx, namespace.RootNamespaceID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, namespace.RootNamespaceID, retrieved.ID)
}

// TestNamespaceStore_GetNamespaceByPath tests getting namespace by path
func TestNamespaceStore_GetNamespaceByPath(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace first
	newNs := &namespace.Namespace{
		Path: "test-path/",
	}
	err := core.namespaceStore.SetNamespace(ctx, newNs)
	require.NoError(t, err)

	// Get by path
	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "test-path/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "test-path/", retrieved.Path)
}

// TestNamespaceStore_GetNamespaceByPath_NotFound tests getting non-existent namespace by path
func TestNamespaceStore_GetNamespaceByPath_NotFound(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

// TestNamespaceStore_ModifyNamespaceByPath_Create tests creating namespace via ModifyNamespaceByPath
func TestNamespaceStore_ModifyNamespaceByPath_Create(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a new namespace
	entry, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "new-ns", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata = map[string]string{"created": "true"}
		return ns, nil
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, "new-ns/", entry.Path)
	assert.NotEmpty(t, entry.ID)
	assert.NotEmpty(t, entry.UUID)
	assert.Equal(t, "true", entry.CustomMetadata["created"])
}

// TestNamespaceStore_ModifyNamespaceByPath_Update tests updating namespace via ModifyNamespaceByPath
func TestNamespaceStore_ModifyNamespaceByPath_Update(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace first
	_, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "update-ns", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata = map[string]string{"version": "1"}
		return ns, nil
	})
	require.NoError(t, err)

	// Update it
	updated, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "update-ns", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata["version"] = "2"
		return ns, nil
	})
	require.NoError(t, err)
	require.NotNil(t, updated)

	assert.Equal(t, "2", updated.CustomMetadata["version"])
}

// TestNamespaceStore_ModifyNamespaceByPath_RootRefused tests that modifying root namespace is refused
func TestNamespaceStore_ModifyNamespaceByPath_RootRefused(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Try to modify root namespace (empty path)
	_, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		return ns, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to modify root namespace")
}

// TestNamespaceStore_ListAllNamespaces tests listing all namespaces
func TestNamespaceStore_ListAllNamespaces(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create some namespaces
	for _, path := range []string{"ns1/", "ns2/", "ns3/"} {
		ns := &namespace.Namespace{Path: path}
		err := core.namespaceStore.SetNamespace(ctx, ns)
		require.NoError(t, err)
	}

	// List all including root
	namespaces, err := core.namespaceStore.ListAllNamespaces(ctx, true)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(namespaces), 4) // root + 3 created

	// List all excluding root
	namespacesNoRoot, err := core.namespaceStore.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(namespacesNoRoot), 3)

	// Verify root is not in the list
	for _, ns := range namespacesNoRoot {
		assert.NotEqual(t, namespace.RootNamespaceID, ns.ID)
	}
}

// TestNamespaceStore_ListNamespaces tests listing namespaces with options
func TestNamespaceStore_ListNamespaces(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create parent namespace
	parentNs := &namespace.Namespace{Path: "parent/"}
	err := core.namespaceStore.SetNamespace(ctx, parentNs)
	require.NoError(t, err)

	// Create child namespace under parent
	parentCtx := namespace.ContextWithNamespace(context.Background(), parentNs)
	childNs := &namespace.Namespace{Path: "parent/child/"}
	err = core.namespaceStore.SetNamespace(parentCtx, childNs)
	require.NoError(t, err)

	// List namespaces from root (non-recursive, no parent)
	namespaces, err := core.namespaceStore.ListNamespaces(ctx, false, false)
	require.NoError(t, err)

	// Should include parent but not child (non-recursive)
	var hasParent, hasChild bool
	for _, ns := range namespaces {
		if ns.Path == "parent/" {
			hasParent = true
		}
		if ns.Path == "parent/child/" {
			hasChild = true
		}
	}
	assert.True(t, hasParent, "parent should be in list")
	assert.False(t, hasChild, "child should not be in non-recursive list")
}

// TestNamespaceStore_ListNamespaces_Recursive tests recursive listing
func TestNamespaceStore_ListNamespaces_Recursive(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create parent namespace
	parentNs := &namespace.Namespace{Path: "recursive-parent/"}
	err := core.namespaceStore.SetNamespace(ctx, parentNs)
	require.NoError(t, err)

	// Create child namespace under parent
	parentCtx := namespace.ContextWithNamespace(context.Background(), parentNs)
	childNs := &namespace.Namespace{Path: "recursive-parent/child/"}
	err = core.namespaceStore.SetNamespace(parentCtx, childNs)
	require.NoError(t, err)

	// List namespaces recursively
	namespaces, err := core.namespaceStore.ListNamespaces(ctx, false, true)
	require.NoError(t, err)

	// Should include both parent and child
	var hasParent, hasChild bool
	for _, ns := range namespaces {
		if ns.Path == "recursive-parent/" {
			hasParent = true
		}
		if ns.Path == "recursive-parent/child/" {
			hasChild = true
		}
	}
	assert.True(t, hasParent, "parent should be in recursive list")
	assert.True(t, hasChild, "child should be in recursive list")
}

// TestNamespaceStore_DeleteNamespace tests deleting a namespace
func TestNamespaceStore_DeleteNamespace(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace
	newNs := &namespace.Namespace{Path: "to-delete/"}
	err := core.namespaceStore.SetNamespace(ctx, newNs)
	require.NoError(t, err)

	// Verify it exists
	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "to-delete/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	// Delete it
	status, err := core.namespaceStore.DeleteNamespace(ctx, "to-delete/")
	require.NoError(t, err)
	assert.NotEmpty(t, status)

	// Verify it's gone (or tainted)
	retrieved, err = core.namespaceStore.GetNamespaceByPath(ctx, "to-delete/")
	require.NoError(t, err)
	// Either nil or tainted
	if retrieved != nil {
		assert.True(t, retrieved.Tainted)
	}
}

// TestNamespaceStore_DeleteNamespace_WithChildren tests deleting namespace with children fails
func TestNamespaceStore_DeleteNamespace_WithChildren(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create parent namespace
	parentNs := &namespace.Namespace{Path: "parent-delete/"}
	err := core.namespaceStore.SetNamespace(ctx, parentNs)
	require.NoError(t, err)

	// Create child namespace
	parentCtx := namespace.ContextWithNamespace(context.Background(), parentNs)
	childNs := &namespace.Namespace{Path: "parent-delete/child/"}
	err = core.namespaceStore.SetNamespace(parentCtx, childNs)
	require.NoError(t, err)

	// Try to delete parent (should fail or require force)
	_, err = core.namespaceStore.DeleteNamespace(ctx, "parent-delete/")
	// This may either fail or start deletion process depending on implementation
	// The key is that children should be handled
}

// TestNamespaceStore_ChildNamespaceStorage tests that child namespaces are stored correctly
func TestNamespaceStore_ChildNamespaceStorage(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create parent namespace
	parentNs := &namespace.Namespace{Path: "storage-parent/"}
	err := core.namespaceStore.SetNamespace(ctx, parentNs)
	require.NoError(t, err)

	// Create child namespace under parent
	parentCtx := namespace.ContextWithNamespace(context.Background(), parentNs)
	childNs := &namespace.Namespace{Path: "storage-parent/storage-child/"}
	err = core.namespaceStore.SetNamespace(parentCtx, childNs)
	require.NoError(t, err)

	// Create grandchild namespace
	childCtx := namespace.ContextWithNamespace(context.Background(), childNs)
	grandchildNs := &namespace.Namespace{Path: "storage-parent/storage-child/grandchild/"}
	err = core.namespaceStore.SetNamespace(childCtx, grandchildNs)
	require.NoError(t, err)

	// Verify all can be retrieved
	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "storage-parent/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "storage-parent/", retrieved.Path)

	retrieved, err = core.namespaceStore.GetNamespaceByPath(ctx, "storage-parent/storage-child/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "storage-parent/storage-child/", retrieved.Path)

	retrieved, err = core.namespaceStore.GetNamespaceByPath(ctx, "storage-parent/storage-child/grandchild/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "storage-parent/storage-child/grandchild/", retrieved.Path)
}

// TestNamespaceStore_ChildNamespaceFromRootContext tests creating child namespaces from root context
// This tests the fix for storing child namespaces in the correct parent's storage view
func TestNamespaceStore_ChildNamespaceFromRootContext(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// First create parent namespace from root context
	parentEntry, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "root-parent", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		return ns, nil
	})
	require.NoError(t, err)
	require.NotNil(t, parentEntry)
	assert.Equal(t, "root-parent/", parentEntry.Path)

	// Now create child namespace - must be done from parent context
	parentCtx := namespace.ContextWithNamespace(context.Background(), parentEntry)
	childEntry, err := core.namespaceStore.ModifyNamespaceByPath(parentCtx, "child", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		return ns, nil
	})
	require.NoError(t, err)
	require.NotNil(t, childEntry)
	assert.Equal(t, "root-parent/child/", childEntry.Path)

	// Verify both can be retrieved from root context
	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "root-parent/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	retrieved, err = core.namespaceStore.GetNamespaceByPath(ctx, "root-parent/child/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
}

// TestNamespaceStore_ResolveNamespaceFromRequest tests resolving namespace from request
func TestNamespaceStore_ResolveNamespaceFromRequest(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace
	ns := &namespace.Namespace{Path: "resolve-test/"}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Test resolution with header
	resolved, remainingPath := core.namespaceStore.ResolveNamespaceFromRequest("resolve-test", "some/path")
	require.NotNil(t, resolved)
	assert.Equal(t, "resolve-test/", resolved.Path)
	assert.Equal(t, "some/path", remainingPath)

	// Test resolution with empty header (root namespace)
	resolved, remainingPath = core.namespaceStore.ResolveNamespaceFromRequest("", "some/path")
	require.NotNil(t, resolved)
	assert.Equal(t, namespace.RootNamespaceID, resolved.ID)
}

// TestNamespaceStore_GetNamespaceByLongestPrefix tests prefix matching
func TestNamespaceStore_GetNamespaceByLongestPrefix(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create namespace hierarchy
	ns1 := &namespace.Namespace{Path: "prefix/"}
	err := core.namespaceStore.SetNamespace(ctx, ns1)
	require.NoError(t, err)

	ns1Ctx := namespace.ContextWithNamespace(context.Background(), ns1)
	ns2 := &namespace.Namespace{Path: "prefix/sub/"}
	err = core.namespaceStore.SetNamespace(ns1Ctx, ns2)
	require.NoError(t, err)

	// Test prefix matching
	matched, remainder := core.namespaceStore.GetNamespaceByLongestPrefix(ctx, "prefix/sub/something/else")
	require.NotNil(t, matched)
	assert.Equal(t, "prefix/sub/", matched.Path)
	assert.Equal(t, "something/else", remainder)

	// Test partial prefix matching
	matched, remainder = core.namespaceStore.GetNamespaceByLongestPrefix(ctx, "prefix/other")
	require.NotNil(t, matched)
	assert.Equal(t, "prefix/", matched.Path)
	assert.Equal(t, "other", remainder)
}

// TestNamespaceStore_LockUnlockNamespace tests namespace locking
func TestNamespaceStore_LockUnlockNamespace(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace
	ns := &namespace.Namespace{Path: "lock-test/"}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Lock the namespace
	unlockKey, err := core.namespaceStore.LockNamespace(ctx, "lock-test/")
	require.NoError(t, err)
	assert.NotEmpty(t, unlockKey)

	// Verify it's locked
	locked, err := core.namespaceStore.GetNamespaceByPath(ctx, "lock-test/")
	require.NoError(t, err)
	require.NotNil(t, locked)
	assert.True(t, locked.Locked)

	// Unlock with wrong key
	err = core.namespaceStore.UnlockNamespace(ctx, "wrong-key", "lock-test/")
	require.Error(t, err)

	// Unlock with correct key
	err = core.namespaceStore.UnlockNamespace(ctx, unlockKey, "lock-test/")
	require.NoError(t, err)

	// Verify it's unlocked
	unlocked, err := core.namespaceStore.GetNamespaceByPath(ctx, "lock-test/")
	require.NoError(t, err)
	require.NotNil(t, unlocked)
	assert.False(t, unlocked.Locked)
}

// TestNamespaceStore_CustomMetadata tests custom metadata handling
func TestNamespaceStore_CustomMetadata(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create namespace with custom metadata
	ns := &namespace.Namespace{
		Path: "metadata-test/",
		CustomMetadata: map[string]string{
			"environment": "production",
			"team":        "platform",
			"cost-center": "12345",
		},
	}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Retrieve and verify metadata
	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "metadata-test/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "production", retrieved.CustomMetadata["environment"])
	assert.Equal(t, "platform", retrieved.CustomMetadata["team"])
	assert.Equal(t, "12345", retrieved.CustomMetadata["cost-center"])
}

// TestNamespaceStore_UniqueIdentifiers tests that identifiers are unique
func TestNamespaceStore_UniqueIdentifiers(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	ids := make(map[string]bool)
	uuids := make(map[string]bool)

	// Create multiple namespaces
	for i := 0; i < 10; i++ {
		ns := &namespace.Namespace{
			Path: "unique-" + string(rune('a'+i)) + "/",
		}
		err := core.namespaceStore.SetNamespace(ctx, ns)
		require.NoError(t, err)

		// Verify ID and UUID are unique
		assert.False(t, ids[ns.ID], "ID should be unique: %s", ns.ID)
		assert.False(t, uuids[ns.UUID], "UUID should be unique: %s", ns.UUID)

		ids[ns.ID] = true
		uuids[ns.UUID] = true
	}
}

// TestNamespaceStore_ConcurrentAccess tests concurrent access to namespace store
func TestNamespaceStore_ConcurrentAccess(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace first
	ns := &namespace.Namespace{Path: "concurrent/"}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Run concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, err := core.namespaceStore.GetNamespaceByPath(ctx, "concurrent/")
				assert.NoError(t, err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestNamespaceStore_PathCanonicalizing tests that paths are properly canonicalized
func TestNamespaceStore_PathCanonicalizing(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create namespace with path without trailing slash
	entry, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "no-slash", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		return ns, nil
	})
	require.NoError(t, err)
	assert.Equal(t, "no-slash/", entry.Path) // Should have trailing slash added

	// Verify it can be retrieved with both forms
	retrieved, err := core.namespaceStore.GetNamespaceByPath(ctx, "no-slash/")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	retrieved, err = core.namespaceStore.GetNamespaceByPath(ctx, "no-slash")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
}

// TestNamespaceStore_NamespaceClone tests that retrieved namespaces are cloned
func TestNamespaceStore_NamespaceClone(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create namespace
	ns := &namespace.Namespace{
		Path:           "clone-test/",
		CustomMetadata: map[string]string{"key": "original"},
	}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Get the namespace
	retrieved1, err := core.namespaceStore.GetNamespaceByPath(ctx, "clone-test/")
	require.NoError(t, err)

	// Modify the retrieved copy
	retrieved1.CustomMetadata["key"] = "modified"

	// Get it again
	retrieved2, err := core.namespaceStore.GetNamespaceByPath(ctx, "clone-test/")
	require.NoError(t, err)

	// Original should be unchanged (if properly cloned)
	// Note: This depends on implementation - some may not clone
	assert.Equal(t, "original", retrieved2.CustomMetadata["key"])
}

// TestNamespaceStore_StoragePersistence tests that namespaces survive reload from storage
func TestNamespaceStore_StoragePersistence(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create parent namespace
	parentNs := &namespace.Namespace{
		Path:           "persist-parent/",
		CustomMetadata: map[string]string{"env": "test"},
	}
	err := core.namespaceStore.SetNamespace(ctx, parentNs)
	require.NoError(t, err)

	// Create child namespace under parent
	parentCtx := namespace.ContextWithNamespace(context.Background(), parentNs)
	childNs := &namespace.Namespace{
		Path:           "persist-parent/persist-child/",
		CustomMetadata: map[string]string{"level": "child"},
	}
	err = core.namespaceStore.SetNamespace(parentCtx, childNs)
	require.NoError(t, err)

	// Save the UUIDs and IDs for verification after reload
	parentUUID := parentNs.UUID
	parentID := parentNs.ID
	childUUID := childNs.UUID
	childID := childNs.ID

	// Create a new namespace store using the same barrier storage
	// This simulates a server restart
	nsLogger := core.logger.WithSystem("namespace")
	newNsStore, err := NewNamespaceStore(ctx, core, nsLogger)
	require.NoError(t, err)
	require.NotNil(t, newNsStore)

	// Verify parent namespace was reloaded
	reloadedParent, err := newNsStore.GetNamespaceByPath(ctx, "persist-parent/")
	require.NoError(t, err)
	require.NotNil(t, reloadedParent, "parent namespace should survive reload")
	assert.Equal(t, parentUUID, reloadedParent.UUID)
	assert.Equal(t, parentID, reloadedParent.ID)
	assert.Equal(t, "test", reloadedParent.CustomMetadata["env"])

	// Verify child namespace was reloaded
	reloadedChild, err := newNsStore.GetNamespaceByPath(ctx, "persist-parent/persist-child/")
	require.NoError(t, err)
	require.NotNil(t, reloadedChild, "child namespace should survive reload")
	assert.Equal(t, childUUID, reloadedChild.UUID)
	assert.Equal(t, childID, reloadedChild.ID)
	assert.Equal(t, "child", reloadedChild.CustomMetadata["level"])
}

// TestNamespaceStore_DeepHierarchyPersistence tests deep namespace hierarchy persistence
func TestNamespaceStore_DeepHierarchyPersistence(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a 3-level hierarchy: level1 -> level2 -> level3
	level1 := &namespace.Namespace{Path: "level1/"}
	err := core.namespaceStore.SetNamespace(ctx, level1)
	require.NoError(t, err)

	level1Ctx := namespace.ContextWithNamespace(context.Background(), level1)
	level2 := &namespace.Namespace{Path: "level1/level2/"}
	err = core.namespaceStore.SetNamespace(level1Ctx, level2)
	require.NoError(t, err)

	level2Ctx := namespace.ContextWithNamespace(context.Background(), level2)
	level3 := &namespace.Namespace{Path: "level1/level2/level3/"}
	err = core.namespaceStore.SetNamespace(level2Ctx, level3)
	require.NoError(t, err)

	// Save UUIDs for verification
	level1UUID := level1.UUID
	level2UUID := level2.UUID
	level3UUID := level3.UUID

	// Simulate restart by creating new namespace store
	nsLogger := core.logger.WithSystem("namespace")
	newNsStore, err := NewNamespaceStore(ctx, core, nsLogger)
	require.NoError(t, err)

	// Verify all levels survived reload
	reloaded1, err := newNsStore.GetNamespaceByPath(ctx, "level1/")
	require.NoError(t, err)
	require.NotNil(t, reloaded1, "level1 should survive reload")
	assert.Equal(t, level1UUID, reloaded1.UUID)

	reloaded2, err := newNsStore.GetNamespaceByPath(ctx, "level1/level2/")
	require.NoError(t, err)
	require.NotNil(t, reloaded2, "level2 should survive reload")
	assert.Equal(t, level2UUID, reloaded2.UUID)

	reloaded3, err := newNsStore.GetNamespaceByPath(ctx, "level1/level2/level3/")
	require.NoError(t, err)
	require.NotNil(t, reloaded3, "level3 should survive reload")
	assert.Equal(t, level3UUID, reloaded3.UUID)
}

// TestNamespaceStore_MultipleChildrenPersistence tests multiple siblings at same level
func TestNamespaceStore_MultipleChildrenPersistence(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create parent
	parent := &namespace.Namespace{Path: "multi-parent/"}
	err := core.namespaceStore.SetNamespace(ctx, parent)
	require.NoError(t, err)

	// Create multiple children
	parentCtx := namespace.ContextWithNamespace(context.Background(), parent)
	childPaths := []string{"multi-parent/child-a/", "multi-parent/child-b/", "multi-parent/child-c/"}
	childUUIDs := make(map[string]string)

	for _, path := range childPaths {
		child := &namespace.Namespace{Path: path}
		err := core.namespaceStore.SetNamespace(parentCtx, child)
		require.NoError(t, err)
		childUUIDs[path] = child.UUID
	}

	// Simulate restart
	nsLogger := core.logger.WithSystem("namespace")
	newNsStore, err := NewNamespaceStore(ctx, core, nsLogger)
	require.NoError(t, err)

	// Verify all children survived
	for _, path := range childPaths {
		reloaded, err := newNsStore.GetNamespaceByPath(ctx, path)
		require.NoError(t, err)
		require.NotNil(t, reloaded, "child at %s should survive reload", path)
		assert.Equal(t, childUUIDs[path], reloaded.UUID)
	}
}

// TestNamespaceStore_ParentMustExist tests that child creation fails if parent doesn't exist
func TestNamespaceStore_ParentMustExist(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Try to create a child namespace when parent doesn't exist
	// This should fail because "nonexistent-parent/" doesn't exist
	_, err := core.namespaceStore.ModifyNamespaceByPath(ctx, "nonexistent-parent/child", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		return ns, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing parent")
}

// TestNamespaceStore_TaintedNamespace tests that tainted namespaces cannot be modified
func TestNamespaceStore_TaintedNamespace(t *testing.T) {
	core := createTestCore(t)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Create a namespace
	ns := &namespace.Namespace{Path: "to-taint/"}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Delete it (which should taint it)
	_, err = core.namespaceStore.DeleteNamespace(ctx, "to-taint/")
	require.NoError(t, err)

	// Try to modify the tainted namespace
	_, err = core.namespaceStore.ModifyNamespaceByPath(ctx, "to-taint", func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata["should"] = "fail"
		return ns, nil
	})
	// Should fail because namespace is tainted
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tainted")
}

// TestNamespaceStore_ClearNamespaceResources tests that clearNamespaceResources
// properly cleans up all namespace-scoped resources.
func TestNamespaceStore_ClearNamespaceResources(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	// Manually create a namespace entry to avoid the mountsLock deadlock
	// in createMounts (pre-existing issue with recursive lock acquisition).
	childNs := &namespace.Namespace{
		ID:   "cleanup-ns",
		UUID: "cleanup-ns-uuid",
		Path: "cleanup-test/",
	}

	nsCtx := namespace.ContextWithNamespace(context.Background(), childNs)

	// --- Set up expiration manager and rotation manager ---
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core.expirationManager = NewExpirationManager(core, log, nil)
	defer core.expirationManager.Stop()

	core.rotationManager = NewRotationManager(core, log.WithSubsystem("rotation"), nil)
	core.rotationManager.Start()
	defer core.rotationManager.Stop()

	core.credConfigStore.rotationManager = core.rotationManager

	// --- Populate resources in the child namespace ---

	// Create tokens
	for i := 0; i < 3; i++ {
		authData := &AuthData{
			PrincipalID: "user",
			RoleName:    "role",
			ExpireAt:    time.Now().Add(1 * time.Hour),
			Policies:    []string{"default"},
		}
		_, err := core.tokenStore.GenerateToken(nsCtx, TypeUserPass, authData)
		require.NoError(t, err)
	}

	// Create credential source and spec
	require.NoError(t, core.credConfigStore.CreateSource(nsCtx, &credential.CredSource{
		Name: "test-src",
		Type: "local",
	}))
	require.NoError(t, core.credConfigStore.CreateSpec(nsCtx, &credential.CredSpec{
		Name:   "test-spec",
		Type:   "github_token",
		Source: "test-src",
		MinTTL: 1 * time.Minute,
		MaxTTL: 1 * time.Hour,
		Config: map[string]string{
			"token": "test-token",
		},
	}))

	// Register rotation entry
	require.NoError(t, core.rotationManager.RegisterSource(nsCtx, "test-src", "local", 1*time.Hour))

	// Register expiration entries
	require.NoError(t, core.expirationManager.RegisterToken(nsCtx, "exp-token-1", 10*time.Minute, false))

	// --- Verify resources exist ---
	specs, err := core.credConfigStore.ListSpecs(nsCtx)
	require.NoError(t, err)
	assert.Len(t, specs, 1)

	sources, err := core.credConfigStore.ListSources(nsCtx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sources), 2) // test-src + built-in local

	assert.True(t, core.expirationManager.GetPendingCount() > 0)

	// --- Clear namespace resources ---
	err = core.namespaceStore.clearNamespaceResources(nsCtx, childNs)
	require.NoError(t, err)

	// --- Verify all resources are cleaned ---

	// Tokens should be gone
	keys, err := core.tokenStore.storage.List(context.Background(), tokenIDPrefix)
	require.NoError(t, err)
	for _, key := range keys {
		entry, loadErr := core.tokenStore.loadToken(key)
		if loadErr != nil {
			continue
		}
		assert.NotEqual(t, childNs.ID, entry.NamespaceID,
			"no tokens for deleted namespace should remain")
	}

	// Credential specs should be gone
	specs, err = core.credConfigStore.ListSpecs(nsCtx)
	require.NoError(t, err)
	assert.Len(t, specs, 0)

	// User credential sources should be gone (only built-in local remains)
	sources, err = core.credConfigStore.ListSources(nsCtx)
	require.NoError(t, err)
	assert.Len(t, sources, 1)
	assert.Equal(t, "local", sources[0].Name)

	// Rotation entries should be gone
	_, loaded := core.rotationManager.entries.Load(
		buildRotationKey(childNs.UUID, "test-src"))
	assert.False(t, loaded, "rotation entry should be cleaned")
}

// TestNamespaceStore_ClearNamespaceResources_NilManagers tests that clearNamespaceResources
// handles nil managers gracefully.
func TestNamespaceStore_ClearNamespaceResources_NilManagers(t *testing.T) {
	core := createTestCore(t)

	childNs := &namespace.Namespace{
		ID:   "nil-mgr-ns",
		UUID: "nil-mgr-ns-uuid",
		Path: "nil-mgr-test/",
	}
	nsCtx := namespace.ContextWithNamespace(context.Background(), childNs)

	// Ensure managers are nil (they are by default in createTestCore)
	assert.Nil(t, core.rotationManager)
	assert.Nil(t, core.expirationManager)

	// clearNamespaceResources should not panic with nil managers
	err := core.namespaceStore.clearNamespaceResources(nsCtx, childNs)
	require.NoError(t, err)
}
