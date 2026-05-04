package core

import (
	"context"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFrameworkTestBackend constructs a minimal framework.Backend that satisfies
// logical.Backend, suitable for mounting in router tests.
func newFrameworkTestBackend(t *testing.T, name string) *framework.Backend {
	t.Helper()
	b := &framework.Backend{
		Help:         "test backend " + name,
		BackendType:  name,
		BackendClass: logical.ClassProvider,
		Paths: []*framework.Path{
			{
				Pattern: "config",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
							return &logical.Response{}, nil
						},
					},
				},
			},
		},
	}
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	require.NoError(t, b.Setup(context.Background(), &logical.BackendConfig{Logger: log, Config: map[string]any{}}))
	return b
}

// TestRouter_WalkFrameworkBackends_FindsMounts asserts the walker yields each
// framework-based mount in the caller's namespace exactly once and exposes
// the namespace-relative prefix.
func TestRouter_WalkFrameworkBackends_FindsMounts(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	awsBackend := newFrameworkTestBackend(t, "aws")
	azureBackend := newFrameworkTestBackend(t, "azure")

	for _, m := range []struct {
		prefix  string
		uuid    string
		backend logical.Backend
	}{
		{"aws/", "aws-uuid", awsBackend},
		{"azure/", "azure-uuid", azureBackend},
	} {
		entry := &MountEntry{
			Path: m.prefix, Type: "mock", Class: mountClassProvider,
			UUID: m.uuid, Accessor: "mock_" + m.uuid,
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		}
		view := &mockBarrierView{prefix: "provider/" + m.uuid + "/"}
		require.NoError(t, router.Mount(m.prefix, m.backend, entry, view))
	}

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	seen := map[string]string{}
	err := router.WalkFrameworkBackends(ctx, func(prefix string, b *framework.Backend) bool {
		seen[prefix] = b.BackendType
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, "aws", seen["aws/"], "aws mount should be visible at relative prefix \"aws/\"")
	assert.Equal(t, "azure", seen["azure/"], "azure mount should be visible at relative prefix \"azure/\"")
	assert.Len(t, seen, 2, "walker yielded duplicates or missed a mount: %v", seen)
}

// TestRouter_WalkFrameworkBackends_SkipsNonFramework asserts that mounts
// implementing logical.Backend but not *framework.Backend are silently
// skipped (audit devices, custom implementations).
func TestRouter_WalkFrameworkBackends_SkipsNonFramework(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	mock := newMockProvider()
	entry := &MountEntry{
		Path: "mock/", Type: "mock", Class: mountClassProvider,
		UUID: "mock-uuid", Accessor: "mock_acc",
		NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/mock-uuid/"}
	require.NoError(t, router.Mount("mock/", mock, entry, view))

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	count := 0
	err := router.WalkFrameworkBackends(ctx, func(prefix string, b *framework.Backend) bool {
		count++
		return true
	})
	require.NoError(t, err)
	assert.Zero(t, count, "non-framework backend should be skipped")
}

// TestRouter_WalkFrameworkBackends_StopEarly verifies the walker honors a
// false return as a stop signal (so callers can short-circuit on first match).
func TestRouter_WalkFrameworkBackends_StopEarly(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	for _, name := range []string{"aws", "azure", "gcp"} {
		entry := &MountEntry{
			Path: name + "/", Type: "mock", Class: mountClassProvider,
			UUID: name + "-uuid", Accessor: "mock_" + name,
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		}
		view := &mockBarrierView{prefix: "provider/" + name + "-uuid/"}
		require.NoError(t, router.Mount(name+"/", newFrameworkTestBackend(t, name), entry, view))
	}

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	count := 0
	err := router.WalkFrameworkBackends(ctx, func(prefix string, b *framework.Backend) bool {
		count++
		return false // stop after the first
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count, "walker should stop after callback returns false")
}

// TestRouter_WalkFrameworkBackends_NamespaceIsolation is the security-critical
// test: a tenant in namespace A must NOT see backends mounted in namespace B
// when they walk. Without this guarantee, the sys/schema endpoint would leak
// every tenant's mount tree to every other tenant.
func TestRouter_WalkFrameworkBackends_NamespaceIsolation(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	teamA := &namespace.Namespace{ID: "ns-team-a", UUID: "uuid-a", Path: "team-a/"}
	teamB := &namespace.Namespace{ID: "ns-team-b", UUID: "uuid-b", Path: "team-b/"}

	mount := func(t *testing.T, mp string, ns *namespace.Namespace, name string) {
		t.Helper()
		entry := &MountEntry{
			Path: mp, Type: "mock", Class: mountClassProvider,
			UUID: ns.ID + "-" + name + "-uuid", Accessor: "mock_" + ns.ID + "_" + name,
			NamespaceID: ns.ID, namespace: ns,
		}
		view := &mockBarrierView{prefix: "provider/" + entry.UUID + "/"}
		require.NoError(t, router.Mount(mp, newFrameworkTestBackend(t, name), entry, view))
	}

	mount(t, "aws/", teamA, "aws-a")
	mount(t, "azure/", teamA, "azure-a")
	mount(t, "aws/", teamB, "aws-b")

	collect := func(ns *namespace.Namespace) map[string]string {
		ctx := namespace.ContextWithNamespace(context.Background(), ns)
		seen := map[string]string{}
		err := router.WalkFrameworkBackends(ctx, func(prefix string, b *framework.Backend) bool {
			seen[prefix] = b.BackendType
			return true
		})
		require.NoError(t, err)
		return seen
	}

	a := collect(teamA)
	assert.Equal(t, map[string]string{"aws/": "aws-a", "azure/": "azure-a"}, a, "team-a should see only its own mounts")

	b := collect(teamB)
	assert.Equal(t, map[string]string{"aws/": "aws-b"}, b, "team-b should see only its own mount, not team-a's")
}

// TestRouter_WalkFrameworkBackends_RequiresNamespaceContext asserts the
// walker errors when the caller forgot to set a namespace on the context.
// Without this guard, a buggy caller could leak cross-tenant data.
func TestRouter_WalkFrameworkBackends_RequiresNamespaceContext(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	err := router.WalkFrameworkBackends(context.Background(), func(_ string, _ *framework.Backend) bool {
		t.Fatal("callback should not run when context lacks a namespace")
		return false
	})
	require.Error(t, err)
}

// TestNewRouter tests creating a new router
func TestNewRouter(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	require.NotNil(t, router)
	assert.NotNil(t, router.root)
	assert.NotNil(t, router.storagePrefix)
	assert.NotNil(t, router.mountUUIDCache)
	assert.NotNil(t, router.mountAccessorCache)
}

// TestRouter_Reset tests resetting the router
func TestRouter_Reset(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	// Add some entries first
	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}
	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	// Reset
	router.reset()

	// Verify it's empty
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	mount := router.MatchingMount(ctx, "test/")
	assert.Empty(t, mount)
}

// TestRouter_Mount tests mounting a backend
func TestRouter_Mount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	// Verify mount is accessible
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	mount := router.MatchingMount(ctx, "test/something")
	assert.Equal(t, "test/", mount)
}

// TestRouter_Mount_ValidationErrors tests mount validation
func TestRouter_Mount_ValidationErrors(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	t.Run("empty prefix", func(t *testing.T) {
		entry := &MountEntry{
			Path:        "",
			Type:        "mock",
			Class:       mountClassProvider,
			UUID:        "test-uuid",
			Accessor:    "mock_12345678",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		err := router.Mount("", backend, entry, view)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing prefix")
	})

	t.Run("empty storage prefix", func(t *testing.T) {
		entry := &MountEntry{
			Path:        "test/",
			Type:        "mock",
			Class:       mountClassProvider,
			UUID:        "test-uuid",
			Accessor:    "mock_12345678",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		emptyView := &mockBarrierView{prefix: ""}
		err := router.Mount("test/", backend, entry, emptyView)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing storage view prefix")
	})

	t.Run("empty UUID", func(t *testing.T) {
		entry := &MountEntry{
			Path:        "test/",
			Type:        "mock",
			Class:       mountClassProvider,
			UUID:        "",
			Accessor:    "mock_12345678",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		err := router.Mount("test/", backend, entry, view)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing mount identifier")
	})

	t.Run("empty accessor", func(t *testing.T) {
		entry := &MountEntry{
			Path:        "test/",
			Type:        "mock",
			Class:       mountClassProvider,
			UUID:        "test-uuid",
			Accessor:    "",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		err := router.Mount("test/", backend, entry, view)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing mount accessor")
	})
}

// TestRouter_Mount_NestedMount tests that nested mounts are rejected
func TestRouter_Mount_NestedMount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()

	// Mount parent
	entry1 := &MountEntry{
		Path:        "parent/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "parent-uuid",
		Accessor:    "mock_11111111",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view1 := &mockBarrierView{prefix: "provider/parent-uuid/"}
	err := router.Mount("parent/", backend, entry1, view1)
	require.NoError(t, err)

	// Try to mount nested
	entry2 := &MountEntry{
		Path:        "parent/child/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "child-uuid",
		Accessor:    "mock_22222222",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view2 := &mockBarrierView{prefix: "provider/child-uuid/"}
	err = router.Mount("parent/child/", backend, entry2, view2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot mount under existing mount")
}

// TestRouter_Unmount tests unmounting a backend
func TestRouter_Unmount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	// Unmount
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	err = router.Unmount(ctx, "test/")
	require.NoError(t, err)

	// Verify it's gone
	mount := router.MatchingMount(ctx, "test/something")
	assert.Empty(t, mount)
}

// TestRouter_Unmount_NotFound tests unmounting non-existent mount
func TestRouter_Unmount_NotFound(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	err := router.Unmount(ctx, "nonexistent/")
	require.NoError(t, err) // Should not error for non-existent mounts
}

// TestRouter_MatchingMount tests finding matching mount
func TestRouter_MatchingMount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "aws/",
		Type:        "aws",
		Class:       mountClassProvider,
		UUID:        "aws-uuid",
		Accessor:    "aws_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/aws-uuid/"}

	err := router.Mount("aws/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("exact match", func(t *testing.T) {
		mount := router.MatchingMount(ctx, "aws/")
		assert.Equal(t, "aws/", mount)
	})

	t.Run("prefix match", func(t *testing.T) {
		mount := router.MatchingMount(ctx, "aws/gateway/s3/bucket")
		assert.Equal(t, "aws/", mount)
	})

	t.Run("no match", func(t *testing.T) {
		mount := router.MatchingMount(ctx, "gcp/")
		assert.Empty(t, mount)
	})
}

// TestRouter_MatchingMountEntry tests finding matching mount entry
func TestRouter_MatchingMountEntry(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("found", func(t *testing.T) {
		foundEntry := router.MatchingMountEntry(ctx, "test/something")
		require.NotNil(t, foundEntry)
		assert.Equal(t, "test/", foundEntry.Path)
		assert.Equal(t, "mock", foundEntry.Type)
	})

	t.Run("not found", func(t *testing.T) {
		foundEntry := router.MatchingMountEntry(ctx, "nonexistent/")
		assert.Nil(t, foundEntry)
	})
}

// TestRouter_MatchingBackend tests finding matching backend
func TestRouter_MatchingBackend(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("found", func(t *testing.T) {
		foundBackend := router.MatchingBackend(ctx, "test/something")
		require.NotNil(t, foundBackend)
	})

	t.Run("not found", func(t *testing.T) {
		foundBackend := router.MatchingBackend(ctx, "nonexistent/")
		assert.Nil(t, foundBackend)
	})
}

// TestRouter_MatchingMountByAccessor tests finding mount by accessor
func TestRouter_MatchingMountByAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		foundEntry := router.MatchingMountByAccessor("mock_12345678")
		require.NotNil(t, foundEntry)
		assert.Equal(t, "test/", foundEntry.Path)
	})

	t.Run("not found", func(t *testing.T) {
		foundEntry := router.MatchingMountByAccessor("nonexistent")
		assert.Nil(t, foundEntry)
	})

	t.Run("empty accessor", func(t *testing.T) {
		foundEntry := router.MatchingMountByAccessor("")
		assert.Nil(t, foundEntry)
	})
}

// TestRouter_MatchingMountByUUID tests finding mount by UUID
func TestRouter_MatchingMountByUUID(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		foundEntry := router.MatchingMountByUUID("test-uuid")
		require.NotNil(t, foundEntry)
		assert.Equal(t, "test/", foundEntry.Path)
	})

	t.Run("not found", func(t *testing.T) {
		foundEntry := router.MatchingMountByUUID("nonexistent")
		assert.Nil(t, foundEntry)
	})

	t.Run("empty UUID", func(t *testing.T) {
		foundEntry := router.MatchingMountByUUID("")
		assert.Nil(t, foundEntry)
	})
}

// TestRouter_ValidateMountByAccessor tests validating mount by accessor
func TestRouter_ValidateMountByAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		response := router.ValidateMountByAccessor("mock_12345678")
		require.NotNil(t, response)
		assert.Equal(t, "mock_12345678", response.MountAccessor)
		assert.Equal(t, "mock", response.MountType)
		assert.Equal(t, "test/", response.MountPath)
	})

	t.Run("not found", func(t *testing.T) {
		response := router.ValidateMountByAccessor("nonexistent")
		assert.Nil(t, response)
	})

	t.Run("empty accessor", func(t *testing.T) {
		response := router.ValidateMountByAccessor("")
		assert.Nil(t, response)
	})
}

// TestRouter_MountConflict tests detecting mount conflicts
func TestRouter_MountConflict(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("exact conflict", func(t *testing.T) {
		conflict := router.MountConflict(ctx, "test/")
		assert.Equal(t, "test/", conflict)
	})

	t.Run("nested conflict", func(t *testing.T) {
		conflict := router.MountConflict(ctx, "test/nested/")
		assert.Equal(t, "test/", conflict)
	})

	t.Run("no conflict", func(t *testing.T) {
		conflict := router.MountConflict(ctx, "other/")
		assert.Empty(t, conflict)
	})
}

// TestRouter_Taint tests tainting a route
func TestRouter_Taint(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Taint the route
	err = router.Taint(ctx, "test/")
	require.NoError(t, err)

	// Route should still exist but be tainted
	mount := router.MatchingMount(ctx, "test/something")
	assert.Equal(t, "test/", mount)
}

// TestRouter_Untaint tests untainting a route
func TestRouter_Untaint(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// Taint then untaint
	err = router.Taint(ctx, "test/")
	require.NoError(t, err)

	err = router.Untaint(ctx, "test/")
	require.NoError(t, err)
}

// TestRouter_MatchingStorageByAPIPath tests finding storage by API path
func TestRouter_MatchingStorageByAPIPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("found", func(t *testing.T) {
		storage := router.MatchingStorageByAPIPath(ctx, "test/something")
		require.NotNil(t, storage)
	})

	t.Run("not found", func(t *testing.T) {
		storage := router.MatchingStorageByAPIPath(ctx, "nonexistent/")
		assert.Nil(t, storage)
	})
}

// TestRouter_MatchingStoragePrefixByAPIPath tests finding storage prefix by API path
func TestRouter_MatchingStoragePrefixByAPIPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("found", func(t *testing.T) {
		prefix, found := router.MatchingStoragePrefixByAPIPath(ctx, "test/something")
		assert.True(t, found)
		assert.Equal(t, "provider/test-uuid/", prefix)
	})

	t.Run("not found", func(t *testing.T) {
		_, found := router.MatchingStoragePrefixByAPIPath(ctx, "nonexistent/")
		assert.False(t, found)
	})
}

// TestRouter_Route tests routing a request
func TestRouter_Route(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("successful route", func(t *testing.T) {
		req := &logical.Request{
			Path:      "test/something",
			Operation: logical.ReadOperation,
		}
		resp, err := router.Route(ctx, req)
		// Mock provider returns nil response, which is fine
		require.NoError(t, err)
		assert.Nil(t, resp)
	})

	t.Run("route not found", func(t *testing.T) {
		req := &logical.Request{
			Path:      "nonexistent/",
			Operation: logical.ReadOperation,
		}
		_, err := router.Route(ctx, req)
		require.Error(t, err)
	})

	t.Run("tainted route fails", func(t *testing.T) {
		// Taint the route
		err := router.Taint(ctx, "test/")
		require.NoError(t, err)

		req := &logical.Request{
			Path:      "test/something",
			Operation: logical.ReadOperation,
		}
		resp, err := router.Route(ctx, req)
		require.Error(t, err)
		require.NotNil(t, resp)

		// Untaint for cleanup
		err = router.Untaint(ctx, "test/")
		require.NoError(t, err)
	})
}

// TestRouter_LoginPath tests checking login paths
func TestRouter_LoginPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := &mockBackendWithLoginPaths{}
	entry := &MountEntry{
		Path:        "auth/jwt/",
		Type:        "jwt",
		Class:       mountClassAuth,
		UUID:        "jwt-uuid",
		Accessor:    "jwt_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "auth/jwt-uuid/"}

	err := router.Mount("auth/jwt/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("login path", func(t *testing.T) {
		isLogin := router.LoginPath(ctx, "auth/jwt/login")
		assert.True(t, isLogin)
	})

	t.Run("non-login path", func(t *testing.T) {
		isLogin := router.LoginPath(ctx, "auth/jwt/config")
		assert.False(t, isLogin)
	})
}

// TestRouter_RootPath tests checking root paths
func TestRouter_RootPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := &mockBackendWithRootPaths{}
	entry := &MountEntry{
		Path:        "sys/",
		Type:        "system",
		Class:       mountClassSystem,
		UUID:        "sys-uuid",
		Accessor:    "sys_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "sys/"}

	err := router.Mount("sys/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("root path", func(t *testing.T) {
		isRoot := router.RootPath(ctx, "sys/seal")
		assert.True(t, isRoot)
	})

	t.Run("non-root path", func(t *testing.T) {
		isRoot := router.RootPath(ctx, "sys/mounts")
		assert.False(t, isRoot)
	})
}

// TestPathsToRadix tests converting paths to radix tree
func TestPathsToRadix(t *testing.T) {
	paths := []string{
		"login",
		"config/*",
		"roles/",
	}

	tree := pathsToRadix(paths)
	require.NotNil(t, tree)

	// Check exact match
	_, isPrefixMatch, found := tree.LongestPrefix("login")
	assert.True(t, found)
	assert.False(t, isPrefixMatch.(bool))

	// Check prefix match
	_, isPrefixMatch, found = tree.LongestPrefix("config/test")
	assert.True(t, found)
	assert.True(t, isPrefixMatch.(bool))
}

// TestIsValidUnauthenticatedPath tests validating unauthenticated paths
func TestIsValidUnauthenticatedPath(t *testing.T) {
	testCases := []struct {
		path  string
		valid bool
	}{
		{"login", true},
		{"login/*", true},
		{"+/callback", true},
		{"oidc/+/callback", true},
		{"**", false},       // multiple wildcards
		{"+*", false},       // invalid combination
		{"test*foo", false}, // * not at end
		{"+a", false},       // + adjacent to non-slash
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			valid, _ := isValidUnauthenticatedPath(tc.path)
			assert.Equal(t, tc.valid, valid)
		})
	}
}

// TestPathMatchesWildcardPath tests wildcard path matching
func TestPathMatchesWildcardPath(t *testing.T) {
	testCases := []struct {
		path     []string
		wcPath   []string
		isPrefix bool
		expected bool
	}{
		{[]string{"oidc", "callback"}, []string{"+", "callback"}, false, true},
		{[]string{"oidc", "other"}, []string{"+", "callback"}, false, false},
		{[]string{"a", "b", "c"}, []string{"+", "b"}, true, true},
		{[]string{"a"}, []string{"+", "b"}, false, false},
		{[]string{}, []string{"+", "b"}, false, false},
	}

	for _, tc := range testCases {
		result := pathMatchesWildcardPath(tc.path, tc.wcPath, tc.isPrefix)
		assert.Equal(t, tc.expected, result)
	}
}

// TestRouteEntry_SaltID tests salting IDs
func TestRouteEntry_SaltID(t *testing.T) {
	entry := &MountEntry{
		UUID: "test-uuid",
	}
	re := &routeEntry{
		mountEntry: entry,
	}

	saltedID := re.SaltID("test-id")
	assert.NotEmpty(t, saltedID)
	assert.NotEqual(t, "test-id", saltedID)
}

// mockBarrierView implements BarrierView for testing
type mockBarrierView struct {
	prefix string
	data   map[string]*sdklogical.StorageEntry
}

func (v *mockBarrierView) Prefix() string {
	return v.prefix
}

func (v *mockBarrierView) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, nil
}

func (v *mockBarrierView) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return nil, nil
}

func (v *mockBarrierView) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	if v.data == nil {
		return nil, nil
	}
	return v.data[key], nil
}

func (v *mockBarrierView) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	if v.data == nil {
		v.data = make(map[string]*sdklogical.StorageEntry)
	}
	v.data[entry.Key] = entry
	return nil
}

func (v *mockBarrierView) Delete(ctx context.Context, key string) error {
	if v.data != nil {
		delete(v.data, key)
	}
	return nil
}

func (v *mockBarrierView) SubView(prefix string) BarrierView {
	return &mockBarrierView{prefix: v.prefix + prefix}
}

func (v *mockBarrierView) GetReadOnlyErr() error {
	return nil
}

func (v *mockBarrierView) SetReadOnlyErr(err error) {}

// mockBackendWithLoginPaths implements logical.Backend with login paths
type mockBackendWithLoginPaths struct {
	mockProvider
}

func (m *mockBackendWithLoginPaths) SpecialPaths() *logical.Paths {
	return &logical.Paths{
		Unauthenticated: []string{
			"login",
		},
	}
}

// mockBackendWithRootPaths implements logical.Backend with root paths
type mockBackendWithRootPaths struct {
	mockProvider
}

func (m *mockBackendWithRootPaths) SpecialPaths() *logical.Paths {
	return &logical.Paths{
		Root: []string{
			"seal",
			"unseal",
		},
	}
}

// mockBackendWithStreamingPaths implements logical.Backend with streaming paths
type mockBackendWithStreamingPaths struct {
	mockProvider
}

func (m *mockBackendWithStreamingPaths) SpecialPaths() *logical.Paths {
	return &logical.Paths{
		Stream: []string{
			"gateway/*",
			"proxy/stream",
		},
	}
}

// TestRouter_StreamingPath tests checking streaming paths
func TestRouter_StreamingPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := &mockBackendWithStreamingPaths{}
	entry := &MountEntry{
		Path:        "aws/",
		Type:        "aws",
		Class:       mountClassProvider,
		UUID:        "aws-uuid",
		Accessor:    "aws_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/aws-uuid/"}

	err := router.Mount("aws/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("streaming path with prefix match", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "aws/gateway/s3/bucket")
		assert.True(t, isStreaming)
	})

	t.Run("streaming path with prefix match - another subpath", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "aws/gateway/ec2/instances")
		assert.True(t, isStreaming)
	})

	t.Run("streaming path with exact match", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "aws/proxy/stream")
		assert.True(t, isStreaming)
	})

	t.Run("non-streaming path", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "aws/config")
		assert.False(t, isStreaming)
	})

	t.Run("non-streaming path - proxy but different", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "aws/proxy/other")
		assert.False(t, isStreaming)
	})

	t.Run("non-existent mount", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "gcp/gateway/compute")
		assert.False(t, isStreaming)
	})
}

// TestRouter_StreamingPath_NoStreamingPaths tests that non-streaming backends return false
func TestRouter_StreamingPath_NoStreamingPaths(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	// Use a backend without streaming paths
	backend := newMockProvider()
	entry := &MountEntry{
		Path:        "test/",
		Type:        "mock",
		Class:       mountClassProvider,
		UUID:        "test-uuid",
		Accessor:    "mock_12345678",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	view := &mockBarrierView{prefix: "provider/test-uuid/"}

	err := router.Mount("test/", backend, entry, view)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("any path should not be streaming", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "test/anything")
		assert.False(t, isStreaming)
	})

	t.Run("gateway path should not be streaming without streaming config", func(t *testing.T) {
		isStreaming := router.StreamingPath(ctx, "test/gateway/s3")
		assert.False(t, isStreaming)
	})
}
