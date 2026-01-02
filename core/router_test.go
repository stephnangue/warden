// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBackend implements logical.Backend for testing
type mockBackend struct {
	backendType   string
	backendClass  string
	description   string
	accessor      string
	handleFunc    func(w http.ResponseWriter, r *http.Request) error
	setupCalled   bool
	cleanupCalled bool
}

func newMockBackend(backendType, backendClass string) *mockBackend {
	return &mockBackend{
		backendType:  backendType,
		backendClass: backendClass,
		description:  "Mock backend",
		accessor:     "mock_accessor",
	}
}

func (m *mockBackend) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	if m.handleFunc != nil {
		return m.handleFunc(w, r)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (m *mockBackend) GetType() string {
	return m.backendType
}

func (m *mockBackend) GetClass() string {
	return m.backendClass
}

func (m *mockBackend) GetDescription() string {
	return m.description
}

func (m *mockBackend) GetAccessor() string {
	return m.accessor
}

func (m *mockBackend) Cleanup(ctx context.Context) {
	m.cleanupCalled = true
}

func (m *mockBackend) Setup(ctx context.Context, conf map[string]any) error {
	m.setupCalled = true
	return nil
}

func (m *mockBackend) Initialize(ctx context.Context) error {
	return nil
}

func (m *mockBackend) Config() map[string]any {
	return map[string]any{}
}

// mockBarrierView implements BarrierView for testing
type mockBarrierView struct {
	prefix      string
	readOnlyErr error
}

func newMockBarrierView(prefix string) *mockBarrierView {
	return &mockBarrierView{prefix: prefix}
}

func (m *mockBarrierView) Prefix() string {
	return m.prefix
}

func (m *mockBarrierView) SubView(prefix string) BarrierView {
	return newMockBarrierView(m.prefix + prefix)
}

func (m *mockBarrierView) SetReadOnlyErr(err error) {
	m.readOnlyErr = err
}

func (m *mockBarrierView) GetReadOnlyErr() error {
	return m.readOnlyErr
}

func (m *mockBarrierView) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	return nil, nil
}

func (m *mockBarrierView) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	return nil
}

func (m *mockBarrierView) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *mockBarrierView) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, nil
}

func (m *mockBarrierView) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return nil, nil
}

// Helper function to create test context with namespace
func testRouterContext() context.Context {
	return namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
}

func TestNewRouter(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	assert.NotNil(t, router)
	assert.NotNil(t, router.root)
	assert.NotNil(t, router.storagePrefix)
	assert.NotNil(t, router.mountUUIDCache)
	assert.NotNil(t, router.mountAccessorCache)
	assert.Equal(t, log, router.logger)
}

func TestRouter_Mount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Verify the mount was added
	ctx := testRouterContext()
	matchingBackend := router.MatchingBackend(ctx, "test/foo")
	assert.NotNil(t, matchingBackend)
	assert.Equal(t, backend, matchingBackend)
}

func TestRouter_Mount_MissingPrefix(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("", backend, mountEntry, view)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing prefix")
}

func TestRouter_Mount_MissingStoragePrefix(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing storage view prefix")
}

func TestRouter_Mount_MissingUUID(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing mount identifier")
}

func TestRouter_Mount_MissingAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing mount accessor")
}

func TestRouter_Mount_NestedMount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend1 := newMockBackend("test1", "provider")
	view1 := newMockBarrierView("logical/uuid1/")

	mountEntry1 := &MountEntry{
		Path:        "parent/",
		Type:        "test1",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Parent mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("parent/", backend1, mountEntry1, view1)
	require.NoError(t, err)

	// Try to mount under existing mount
	backend2 := newMockBackend("test2", "provider")
	view2 := newMockBarrierView("logical/uuid2/")

	mountEntry2 := &MountEntry{
		Path:        "parent/child/",
		Type:        "test2",
		Class:       mountClassProvider,
		UUID:        "uuid2",
		Accessor:    "accessor2",
		Description: "Child mount",
		namespace:   namespace.RootNamespace,
	}

	err = router.Mount("parent/child/", backend2, mountEntry2, view2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot mount under existing mount")
}

func TestRouter_Unmount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Unmount
	ctx := testRouterContext()
	err = router.Unmount(ctx, "test/")
	require.NoError(t, err)

	// Verify cleanup was called
	assert.True(t, backend.cleanupCalled)

	// Verify the mount was removed
	matchingBackend := router.MatchingBackend(ctx, "test/foo")
	assert.Nil(t, matchingBackend)
}

func TestRouter_Unmount_NonExistent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	ctx := testRouterContext()
	err := router.Unmount(ctx, "nonexistent/")
	assert.NoError(t, err) // Should not error on non-existent mount
}

func TestRouter_MatchingBackend(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	// Test exact match
	matchingBackend := router.MatchingBackend(ctx, "test/")
	assert.Equal(t, backend, matchingBackend)

	// Test with subpath
	matchingBackend = router.MatchingBackend(ctx, "test/foo/bar")
	assert.Equal(t, backend, matchingBackend)

	// Test non-matching path
	matchingBackend = router.MatchingBackend(ctx, "other/")
	assert.Nil(t, matchingBackend)
}

func TestRouter_MatchingMount(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	mount := router.MatchingMount(ctx, "aws/foo")
	assert.Equal(t, "aws/", mount)

	mount = router.MatchingMount(ctx, "other/foo")
	assert.Equal(t, "", mount)
}

func TestRouter_MatchingMountByAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor123",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Test matching
	entry := router.MatchingMountByAccessor("accessor123")
	assert.NotNil(t, entry)
	assert.Equal(t, "accessor123", entry.Accessor)
	assert.Equal(t, "test/", entry.Path)

	// Test non-matching
	entry = router.MatchingMountByAccessor("nonexistent")
	assert.Nil(t, entry)

	// Test empty accessor
	entry = router.MatchingMountByAccessor("")
	assert.Nil(t, entry)
}

func TestRouter_MatchingMountByUUID(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid123",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Test matching
	entry := router.MatchingMountByUUID("uuid123")
	assert.NotNil(t, entry)
	assert.Equal(t, "uuid123", entry.UUID)
	assert.Equal(t, "test/", entry.Path)

	// Test non-matching
	entry = router.MatchingMountByUUID("nonexistent")
	assert.Nil(t, entry)

	// Test empty UUID
	entry = router.MatchingMountByUUID("")
	assert.Nil(t, entry)
}

func TestRouter_ValidateMountByAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "aws",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor123",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	// Test valid accessor
	resp := router.ValidateMountByAccessor("accessor123")
	assert.NotNil(t, resp)
	assert.Equal(t, "accessor123", resp.MountAccessor)
	assert.Equal(t, "aws", resp.MountType)
	assert.Equal(t, "aws/", resp.MountPath)

	// Test with auth mount
	authBackend := newMockBackend("jwt", "auth")
	authView := newMockBarrierView("auth/uuid2/")

	authEntry := &MountEntry{
		Path:        "jwt/",
		Type:        "jwt",
		Class:       mountClassAuth,
		UUID:        "uuid2",
		Accessor:    "auth_accessor",
		Description: "Auth mount",
		namespace:   namespace.RootNamespace,
	}

	err = router.Mount("jwt/", authBackend, authEntry, authView)
	require.NoError(t, err)

	resp = router.ValidateMountByAccessor("auth_accessor")
	assert.NotNil(t, resp)
	assert.Equal(t, "auth_accessor", resp.MountAccessor)
	assert.Equal(t, "jwt", resp.MountType)
	assert.Equal(t, "auth/jwt/", resp.MountPath) // Auth prefix added

	// Test non-existent accessor
	resp = router.ValidateMountByAccessor("nonexistent")
	assert.Nil(t, resp)

	// Test empty accessor
	resp = router.ValidateMountByAccessor("")
	assert.Nil(t, resp)
}

func TestRouter_Taint(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	// Taint the mount
	err = router.Taint(ctx, "test/")
	assert.NoError(t, err)

	// Verify backend is still returned (taint doesn't affect MatchingBackend)
	matchingBackend := router.MatchingBackend(ctx, "test/foo")
	assert.NotNil(t, matchingBackend)
}

func TestRouter_Untaint(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		Tainted:     true,
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	// Untaint the mount
	err = router.Untaint(ctx, "test/")
	assert.NoError(t, err)
}

func TestRouter_MountConflict(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	// Test exact match conflict
	conflict := router.MountConflict(ctx, "aws/")
	assert.Equal(t, "aws/", conflict)

	// Test prefix conflict
	conflict = router.MountConflict(ctx, "aws")
	assert.NotEmpty(t, conflict)

	// Test no conflict
	conflict = router.MountConflict(ctx, "gcp/")
	assert.Empty(t, conflict)
}

func TestRouter_MatchingStorage(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	// Test matching by API path
	storage := router.MatchingStorageByAPIPath(ctx, "test/foo")
	assert.NotNil(t, storage)
	assert.Equal(t, view, storage)

	// Test matching by storage path
	storage = router.MatchingStorageByStoragePath(ctx, "logical/uuid1/data")
	assert.NotNil(t, storage)
	assert.Equal(t, view, storage)

	// Test non-matching
	storage = router.MatchingStorageByAPIPath(ctx, "other/foo")
	assert.Nil(t, storage)
}

func TestRouter_MatchingMountEntry(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	entry := router.MatchingMountEntry(ctx, "test/foo")
	assert.NotNil(t, entry)
	assert.Equal(t, "test/", entry.Path)
	assert.Equal(t, "uuid1", entry.UUID)

	entry = router.MatchingMountEntry(ctx, "other/foo")
	assert.Nil(t, entry)
}

func TestRouter_MatchingStoragePrefixByAPIPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	prefix, found := router.MatchingStoragePrefixByAPIPath(ctx, "test/foo")
	assert.True(t, found)
	assert.Equal(t, "logical/uuid1/", prefix)

	prefix, found = router.MatchingStoragePrefixByAPIPath(ctx, "other/foo")
	assert.False(t, found)
	assert.Empty(t, prefix)
}

func TestRouter_MatchingAPIPrefixByStoragePath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	ns, mountPath, storagePrefix, found := router.MatchingAPIPrefixByStoragePath(ctx, "logical/uuid1/data")
	assert.True(t, found)
	assert.Equal(t, namespace.RootNamespace, ns)
	assert.Equal(t, "test/", mountPath)
	assert.Equal(t, "logical/uuid1/", storagePrefix)

	// Test with auth mount
	authBackend := newMockBackend("jwt", "auth")
	authView := newMockBarrierView("auth/uuid2/")

	authEntry := &MountEntry{
		Path:        "jwt/",
		Type:        "jwt",
		Class:       mountClassAuth,
		UUID:        "uuid2",
		Accessor:    "auth_accessor",
		Description: "Auth mount",
		namespace:   namespace.RootNamespace,
	}

	err = router.Mount("jwt/", authBackend, authEntry, authView)
	require.NoError(t, err)

	ns, mountPath, storagePrefix, found = router.MatchingAPIPrefixByStoragePath(ctx, "auth/uuid2/data")
	assert.True(t, found)
	assert.Equal(t, "auth/jwt/", mountPath) // Auth prefix added
	assert.Equal(t, "auth/uuid2/", storagePrefix)
}

func TestRouter_MatchingMountByAPIPath(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	ctx := testRouterContext()

	path := router.MatchingMountByAPIPath(ctx, "aws/foo/bar")
	assert.Equal(t, "aws/", path)

	path = router.MatchingMountByAPIPath(ctx, "other/foo")
	assert.Empty(t, path)
}

func TestRouter_Reset(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Reset the router
	router.reset()

	// Verify all mounts are gone
	ctx := testRouterContext()
	matchingBackend := router.MatchingBackend(ctx, "test/foo")
	assert.Nil(t, matchingBackend)

	entry := router.MatchingMountByAccessor("accessor1")
	assert.Nil(t, entry)

	entry = router.MatchingMountByUUID("uuid1")
	assert.Nil(t, entry)
}

func TestRouter_Route(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	// Create a backend that verifies the request
	var handledPath string
	backend := newMockBackend("test", "provider")
	backend.handleFunc = func(w http.ResponseWriter, r *http.Request) error {
		handledPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		return nil
	}

	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	// Create a test request
	// Note: Router expects paths without /v1/ prefix (that's stripped by request_handler)
	req := httptest.NewRequest(http.MethodGet, "/v1/aws/credentials/role1", nil)
	ctx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)
	// Strip /v1/ prefix like request_handler does
	req.URL.Path = strings.TrimPrefix(req.URL.Path, "/v1/")

	w := httptest.NewRecorder()

	// Route the request
	router.Route(w, req)

	// Verify the request was handled
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/credentials/role1", handledPath) // Path should be relative to mount
}

func TestRouter_Route_NotFound(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent/path", nil)
	ctx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	router.Route(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no route found")
}

func TestRouter_Route_TaintedBackend(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		Tainted:     true, // Mark as tainted
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/test/foo", nil)
	ctx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	router.Route(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no route found")
}

func TestRouter_Route_NilBackend(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	// Mount with nil backend
	err := router.Mount("test/", nil, mountEntry, view)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/test/foo", nil)
	ctx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	router.Route(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no route found")
}

func TestRouter_Route_WithTrailingSlash(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	var handledPath string
	backend := newMockBackend("test", "provider")
	backend.handleFunc = func(w http.ResponseWriter, r *http.Request) error {
		handledPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		return nil
	}

	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	// Request without trailing slash should still match
	req := httptest.NewRequest(http.MethodGet, "/v1/aws", nil)
	ctx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)
	// Strip /v1/ prefix like request_handler does
	req.URL.Path = strings.TrimPrefix(req.URL.Path, "/v1/")

	w := httptest.NewRecorder()

	router.Route(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/", handledPath)
}

func TestRouter_Route_OriginalPathInContext(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	var originalPath string
	backend := newMockBackend("test", "provider")
	backend.handleFunc = func(w http.ResponseWriter, r *http.Request) error {
		// Extract original path from context
		if val := r.Context().Value(logical.OriginalPath); val != nil {
			originalPath = val.(string)
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}

	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "aws/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("aws/", backend, mountEntry, view)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/aws/credentials/role1", nil)
	ctx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)
	// Strip /v1/ prefix like request_handler does
	req.URL.Path = strings.TrimPrefix(req.URL.Path, "/v1/")

	w := httptest.NewRecorder()

	router.Route(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/v1/aws/credentials/role1", originalPath)
}

func TestRouter_SaltID(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "test-uuid-123",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Get the route entry directly to test SaltID
	router.mu.RLock()
	_, raw, ok := router.root.LongestPrefix("test/")
	router.mu.RUnlock()
	require.True(t, ok)

	re := raw.(*routeEntry)

	// Test salting
	id := "test-id"
	saltedID := re.SaltID(id)

	// Verify it's different from original
	assert.NotEqual(t, id, saltedID)

	// Verify it's deterministic
	saltedID2 := re.SaltID(id)
	assert.Equal(t, saltedID, saltedID2)

	// Verify different IDs produce different salted values
	saltedID3 := re.SaltID("different-id")
	assert.NotEqual(t, saltedID, saltedID3)
}

func TestRouter_MultipleMounts(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	// Mount multiple backends
	for i, path := range []string{"aws/", "gcp/", "azure/"} {
		backend := newMockBackend("test", "provider")
		view := newMockBarrierView("logical/uuid" + string(rune('1'+i)) + "/")

		mountEntry := &MountEntry{
			Path:        path,
			Type:        "test",
			Class:       mountClassProvider,
			UUID:        "uuid" + string(rune('1'+i)),
			Accessor:    "accessor" + string(rune('1'+i)),
			Description: "Test mount " + path,
			namespace:   namespace.RootNamespace,
		}

		err := router.Mount(path, backend, mountEntry, view)
		require.NoError(t, err)
	}

	ctx := testRouterContext()

	// Verify all mounts are accessible
	for _, path := range []string{"aws/", "gcp/", "azure/"} {
		backend := router.MatchingBackend(ctx, path+"foo")
		assert.NotNil(t, backend, "Should find backend for path: %s", path)
	}
}

func TestRouter_Route_NoNamespaceContext(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	backend := newMockBackend("test", "provider")
	view := newMockBarrierView("logical/uuid1/")

	mountEntry := &MountEntry{
		Path:        "test/",
		Type:        "test",
		Class:       mountClassProvider,
		UUID:        "uuid1",
		Accessor:    "accessor1",
		Description: "Test mount",
		namespace:   namespace.RootNamespace,
	}

	err := router.Mount("test/", backend, mountEntry, view)
	require.NoError(t, err)

	// Create request without namespace in context
	req := httptest.NewRequest(http.MethodGet, "/v1/test/foo", nil)
	// Add OriginalPath but not namespace - should still fail on namespace check
	ctx := context.WithValue(req.Context(), logical.OriginalPath, req.URL.Path)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	router.Route(w, req)

	// Should fail because namespace extraction fails
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "namespace")
}
