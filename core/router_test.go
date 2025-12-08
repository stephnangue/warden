package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBackend is a test implementation of logical.Backend
type mockBackend struct {
	accessor    string
	typ         string
	class       string
	description string
	handleFunc  func(w http.ResponseWriter, r *http.Request) error
	cleanupFunc func()
	mu          sync.Mutex
	requests    []string // track requests for testing
	config      map[string]any
}

func newMockBackend(accessor string) *mockBackend {
	return &mockBackend{
		accessor:    accessor,
		typ:         "mock",
		class:       "test",
		description: "Mock backend for testing",
		requests:    make([]string, 0),
	}
}

func (m *mockBackend) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	m.mu.Lock()
	m.requests = append(m.requests, r.URL.Path)
	m.mu.Unlock()

	if m.handleFunc != nil {
		return m.handleFunc(w, r)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
	return nil
}

func (m *mockBackend) GetType() string {
	return m.typ
}

func (m *mockBackend) GetClass() string {
	return m.class
}

func (m *mockBackend) GetDescription() string {
	return m.description
}

func (m *mockBackend) GetAccessor() string {
	return m.accessor
}

func (m *mockBackend) Setup(conf map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Merge incoming config with existing config
	if m.config == nil {
		m.config = make(map[string]any)
	}
	for k, v := range conf {
		m.config[k] = v
	}
	return nil
}

func (m *mockBackend) Config() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config == nil {
		return map[string]any{}
	}

	// Return a copy
	config := make(map[string]any)
	for k, v := range m.config {
		config[k] = v
	}
	return config
}

func (m *mockBackend) Cleanup() {
	if m.cleanupFunc != nil {
		m.cleanupFunc()
	}
}

func (m *mockBackend) getRequests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.requests...)
}

func createTestRouter() (*Router, logger.Logger) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	router := NewRouter(log)
	return router, log
}

func TestNewRouter(t *testing.T) {
	router, _ := createTestRouter()

	assert.NotNil(t, router)
	assert.NotNil(t, router.root)
	assert.NotNil(t, router.mountAccessorCache)
	assert.NotNil(t, router.logger)
}

func TestRouter_Mount(t *testing.T) {
	router, _ := createTestRouter()

	t.Run("successful mount", func(t *testing.T) {
		backend := newMockBackend("accessor-1")
		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "secret/",
			Accessor: "accessor-1",
		}

		err := router.Mount("secret/", backend, mountEntry)
		require.NoError(t, err)

		// Verify backend can be retrieved
		ctx := context.Background()
		retrievedBackend := router.MatchingBackend(ctx, "secret/data")
		assert.NotNil(t, retrievedBackend)
		assert.Equal(t, backend, retrievedBackend)
	})

	t.Run("duplicate mount error", func(t *testing.T) {
		backend1 := newMockBackend("accessor-2")
		backend2 := newMockBackend("accessor-3")
		mountEntry1 := &MountEntry{
			Type:     "mock",
			Path:     "test/",
			Accessor: "accessor-2",
		}
		mountEntry2 := &MountEntry{
			Type:     "mock",
			Path:     "test/",
			Accessor: "accessor-3",
		}

		err := router.Mount("test/", backend1, mountEntry1)
		require.NoError(t, err)

		err = router.Mount("test/", backend2, mountEntry2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already mounted")
	})

	t.Run("mount multiple paths", func(t *testing.T) {
		backend1 := newMockBackend("accessor-4")
		backend2 := newMockBackend("accessor-5")
		mountEntry1 := &MountEntry{
			Type:     "mock",
			Path:     "path1/",
			Accessor: "accessor-4",
		}
		mountEntry2 := &MountEntry{
			Type:     "mock",
			Path:     "path2/",
			Accessor: "accessor-5",
		}

		err := router.Mount("path1/", backend1, mountEntry1)
		require.NoError(t, err)

		err = router.Mount("path2/", backend2, mountEntry2)
		require.NoError(t, err)

		ctx := context.Background()
		assert.Equal(t, backend1, router.MatchingBackend(ctx, "path1/data"))
		assert.Equal(t, backend2, router.MatchingBackend(ctx, "path2/data"))
	})
}

func TestRouter_Unmount(t *testing.T) {
	router, _ := createTestRouter()

	t.Run("successful unmount", func(t *testing.T) {
		backend := newMockBackend("accessor-10")
		cleanupCalled := false
		backend.cleanupFunc = func() {
			cleanupCalled = true
		}

		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "unmount/",
			Accessor: "accessor-10",
		}

		err := router.Mount("unmount/", backend, mountEntry)
		require.NoError(t, err)

		err = router.Unmount("unmount/")
		require.NoError(t, err)
		assert.True(t, cleanupCalled)

		// Verify backend is removed
		ctx := context.Background()
		retrievedBackend := router.MatchingBackend(ctx, "unmount/data")
		assert.Nil(t, retrievedBackend)
	})

	t.Run("unmount non-existent path", func(t *testing.T) {
		err := router.Unmount("nonexistent/")
		require.NoError(t, err) // Should not error
	})
}

func TestRouter_MatchingBackend(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-20")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "secret/",
		Accessor: "accessor-20",
	}

	err := router.Mount("secret/", backend, mountEntry)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("exact prefix match", func(t *testing.T) {
		result := router.MatchingBackend(ctx, "secret/")
		assert.Equal(t, backend, result)
	})

	t.Run("nested path match", func(t *testing.T) {
		result := router.MatchingBackend(ctx, "secret/data/key")
		assert.Equal(t, backend, result)
	})

	t.Run("no match", func(t *testing.T) {
		result := router.MatchingBackend(ctx, "other/path")
		assert.Nil(t, result)
	})

	t.Run("longest prefix match", func(t *testing.T) {
		nestedBackend := newMockBackend("accessor-21")
		nestedMountEntry := &MountEntry{
			Type:     "mock",
			Path:     "secret/nested/",
			Accessor: "accessor-21",
		}

		err := router.Mount("secret/nested/", nestedBackend, nestedMountEntry)
		require.NoError(t, err)

		// Should match the more specific backend
		result := router.MatchingBackend(ctx, "secret/nested/data")
		assert.Equal(t, nestedBackend, result)

		// Should still match the parent backend
		result = router.MatchingBackend(ctx, "secret/other/data")
		assert.Equal(t, backend, result)
	})
}

func TestRouter_MatchingMountByAccessor(t *testing.T) {
	router, _ := createTestRouter()

	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "test/",
		Accessor: "accessor-30",
	}
	backend := newMockBackend("accessor-30")

	err := router.Mount("test/", backend, mountEntry)
	require.NoError(t, err)

	t.Run("found by accessor", func(t *testing.T) {
		result := router.MatchingMountByAccessor("accessor-30")
		assert.NotNil(t, result)
		assert.Equal(t, mountEntry, result)
	})

	t.Run("not found", func(t *testing.T) {
		result := router.MatchingMountByAccessor("unknown")
		assert.Nil(t, result)
	})

	t.Run("empty accessor", func(t *testing.T) {
		result := router.MatchingMountByAccessor("")
		assert.Nil(t, result)
	})
}

func TestRouter_MountConflict(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-40")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "conflict/",
		Accessor: "accessor-40",
	}

	err := router.Mount("conflict/", backend, mountEntry)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("conflict exists", func(t *testing.T) {
		result := router.MountConflict(ctx, "conflict/data")
		assert.Equal(t, "conflict/", result)
	})

	t.Run("no conflict", func(t *testing.T) {
		result := router.MountConflict(ctx, "other/path")
		assert.Equal(t, "", result)
	})
}

func TestRouter_MatchingMount(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-50")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "mount/",
		Accessor: "accessor-50",
	}

	err := router.Mount("mount/", backend, mountEntry)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("matching mount found", func(t *testing.T) {
		result := router.MatchingMount(ctx, "mount/data/key")
		assert.Equal(t, "mount/", result)
	})

	t.Run("no matching mount", func(t *testing.T) {
		result := router.MatchingMount(ctx, "other/path")
		assert.Equal(t, "", result)
	})
}

func TestRouter_Taint(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-60")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "tainted/",
		Accessor: "accessor-60",
	}

	err := router.Mount("tainted/", backend, mountEntry)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("taint existing path", func(t *testing.T) {
		err := router.Taint(ctx, "tainted/data")
		assert.NoError(t, err)

		// Verify the backend is marked as tainted
		raw, ok := router.root.Get("tainted/")
		require.True(t, ok)
		re := raw.(*routeEntry)
		assert.True(t, re.tainted)
	})

	t.Run("taint non-existent path", func(t *testing.T) {
		err := router.Taint(ctx, "nonexistent/")
		assert.NoError(t, err) // Should not error
	})
}

func TestRouter_Untaint(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-70")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "untaint/",
		Accessor: "accessor-70",
	}

	err := router.Mount("untaint/", backend, mountEntry)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("untaint previously tainted path", func(t *testing.T) {
		// First taint it
		err := router.Taint(ctx, "untaint/data")
		require.NoError(t, err)

		// Then untaint it
		err = router.Untaint(ctx, "untaint/data")
		assert.NoError(t, err)

		// Verify the backend is not tainted
		raw, ok := router.root.Get("untaint/")
		require.True(t, ok)
		re := raw.(*routeEntry)
		assert.False(t, re.tainted)
	})

	t.Run("untaint non-existent path", func(t *testing.T) {
		err := router.Untaint(ctx, "nonexistent/")
		assert.NoError(t, err) // Should not error
	})
}

func TestRouter_Route(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-80")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "route/",
		Accessor: "accessor-80",
	}

	err := router.Mount("route/", backend, mountEntry)
	require.NoError(t, err)

	t.Run("successful route with v1 prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/route/data/key", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())

		// Verify the backend received the correct relative path
		requests := backend.getRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "/data/key", requests[0])
	})

	t.Run("successful route with auth prefix", func(t *testing.T) {
		authBackend := newMockBackend("accessor-81")
		authMountEntry := &MountEntry{
			Type:     "mock",
			Path:     "userpass/",
			Accessor: "accessor-81",
		}

		err := router.Mount("userpass/", authBackend, authMountEntry)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/userpass/login", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		requests := authBackend.getRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "/login", requests[0])
	})

	t.Run("route not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent/path", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "no route found")
	})

	t.Run("route with trailing slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/route/data/", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("route without v1 prefix adds slash for root lookup", func(t *testing.T) {
		// Mount a backend at root level
		rootBackend := newMockBackend("accessor-82")
		rootMountEntry := &MountEntry{
			Type:     "mock",
			Path:     "sys/",
			Accessor: "accessor-82",
		}

		err := router.Mount("sys/", rootBackend, rootMountEntry)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/v1/sys", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("route to tainted backend", func(t *testing.T) {
		taintedBackend := newMockBackend("accessor-83")
		taintedMountEntry := &MountEntry{
			Type:     "mock",
			Path:     "tainted/",
			Accessor: "accessor-83",
		}

		err := router.Mount("tainted/", taintedBackend, taintedMountEntry)
		require.NoError(t, err)

		ctx := context.Background()
		err = router.Taint(ctx, "tainted/")
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/v1/tainted/data", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "no route found")
	})

	t.Run("route with nil backend", func(t *testing.T) {
		// Manually insert a route entry with nil backend
		re := &routeEntry{
			backend: nil,
			mountEntry: &MountEntry{
				Type: "mock",
				Path: "nil/",
			},
		}
		router.root.Insert("nil/", re)

		req := httptest.NewRequest(http.MethodGet, "/v1/nil/data", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "no route found")
	})

	t.Run("backend handle request error", func(t *testing.T) {
		errorBackend := newMockBackend("accessor-84")
		errorBackend.handleFunc = func(w http.ResponseWriter, r *http.Request) error {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return fmt.Errorf("backend error")
		}

		errorMountEntry := &MountEntry{
			Type:     "mock",
			Path:     "error/",
			Accessor: "accessor-84",
		}

		err := router.Mount("error/", errorBackend, errorMountEntry)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/v1/error/data", nil)
		w := httptest.NewRecorder()

		router.Route(w, req)

		// Backend already wrote error response
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestRouter_Concurrent(t *testing.T) {
	router, _ := createTestRouter()

	t.Run("concurrent mounts and queries", func(t *testing.T) {
		var wg sync.WaitGroup
		numGoroutines := 10
		ctx := context.Background()

		// Mount backends concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				backend := newMockBackend(fmt.Sprintf("accessor-concurrent-%d", idx))
				mountEntry := &MountEntry{
					Type:     "mock",
					Path:     fmt.Sprintf("concurrent-%d/", idx),
					Accessor: fmt.Sprintf("accessor-concurrent-%d", idx),
				}

				err := router.Mount(fmt.Sprintf("concurrent-%d/", idx), backend, mountEntry)
				if err != nil {
					t.Errorf("Failed to mount: %v", err)
				}
			}(i)
		}

		wg.Wait()

		// Query backends concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				backend := router.MatchingBackend(ctx, fmt.Sprintf("concurrent-%d/data", idx))
				if backend == nil {
					t.Errorf("Failed to find backend for concurrent-%d", idx)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent routes", func(t *testing.T) {
		backend := newMockBackend("accessor-route-concurrent")
		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "concurrent-route/",
			Accessor: "accessor-route-concurrent",
		}

		err := router.Mount("concurrent-route/", backend, mountEntry)
		require.NoError(t, err)

		var wg sync.WaitGroup
		numRequests := 50

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v1/concurrent-route/data/%d", idx), nil)
				w := httptest.NewRecorder()

				router.Route(w, req)

				if w.Code != http.StatusOK {
					t.Errorf("Expected 200, got %d", w.Code)
				}
			}(i)
		}

		wg.Wait()

		// Verify all requests were handled
		requests := backend.getRequests()
		assert.Len(t, requests, numRequests)
	})

	t.Run("concurrent taint and untaint", func(t *testing.T) {
		backend := newMockBackend("accessor-taint-concurrent")
		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "taint-concurrent/",
			Accessor: "accessor-taint-concurrent",
		}

		err := router.Mount("taint-concurrent/", backend, mountEntry)
		require.NoError(t, err)

		ctx := context.Background()
		var wg sync.WaitGroup
		numOps := 20

		for i := 0; i < numOps; i++ {
			wg.Add(2)

			// Taint operation
			go func() {
				defer wg.Done()
				err := router.Taint(ctx, "taint-concurrent/")
				if err != nil {
					t.Errorf("Taint failed: %v", err)
				}
			}()

			// Untaint operation
			go func() {
				defer wg.Done()
				err := router.Untaint(ctx, "taint-concurrent/")
				if err != nil {
					t.Errorf("Untaint failed: %v", err)
				}
			}()
		}

		wg.Wait()

		// Just ensure no panics occurred
	})
}

func TestRouter_PathNormalization(t *testing.T) {
	router, _ := createTestRouter()
	backend := newMockBackend("accessor-norm")
	mountEntry := &MountEntry{
		Type:     "mock",
		Path:     "norm/",
		Accessor: "accessor-norm",
	}

	err := router.Mount("norm/", backend, mountEntry)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		requestPath  string
		expectedPath string
	}{
		{
			name:         "path with trailing slash",
			requestPath:  "/v1/norm/data/",
			expectedPath: "/data",
		},
		{
			name:         "path without trailing slash",
			requestPath:  "/v1/norm/data",
			expectedPath: "/data",
		},
		{
			name:         "nested path",
			requestPath:  "/v1/norm/data/key/subkey",
			expectedPath: "/data/key/subkey",
		},
		{
			name:         "root path",
			requestPath:  "/v1/norm/",
			expectedPath: "/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear previous requests
			backend.mu.Lock()
			backend.requests = make([]string, 0)
			backend.mu.Unlock()

			req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
			w := httptest.NewRecorder()

			router.Route(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			requests := backend.getRequests()
			require.Len(t, requests, 1)
			assert.Equal(t, tc.expectedPath, requests[0])
		})
	}
}

func TestRouter_MountWithoutTrailingSlash(t *testing.T) {
	router, _ := createTestRouter()

	t.Run("mount path without trailing slash", func(t *testing.T) {
		backend := newMockBackend("accessor-no-slash")
		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "noslash",
			Accessor: "accessor-no-slash",
		}

		// Mount without trailing slash
		err := router.Mount("noslash", backend, mountEntry)
		require.NoError(t, err)

		ctx := context.Background()

		// Should still be able to match the backend
		result := router.MatchingBackend(ctx, "noslash")
		assert.NotNil(t, result)
		assert.Equal(t, backend, result)

		// Should also match nested paths
		result = router.MatchingBackend(ctx, "noslash/data")
		assert.NotNil(t, result)
		assert.Equal(t, backend, result)
	})

	t.Run("route to mount without trailing slash", func(t *testing.T) {
		backend := newMockBackend("accessor-route-no-slash")
		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "route-noslash",
			Accessor: "accessor-route-no-slash",
		}

		err := router.Mount("route-noslash", backend, mountEntry)
		require.NoError(t, err)

		testCases := []struct {
			name         string
			requestPath  string
			expectedPath string
			expectCode   int
		}{
			{
				name:         "exact mount path",
				requestPath:  "/v1/route-noslash",
				expectedPath: "/",
				expectCode:   http.StatusOK,
			},
			{
				name:         "nested path",
				requestPath:  "/v1/route-noslash/data/key",
				expectedPath: "/data/key",
				expectCode:   http.StatusOK,
			},
			{
				name:         "with trailing slash",
				requestPath:  "/v1/route-noslash/",
				expectedPath: "/",
				expectCode:   http.StatusOK,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Clear previous requests
				backend.mu.Lock()
				backend.requests = make([]string, 0)
				backend.mu.Unlock()

				req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
				w := httptest.NewRecorder()

				router.Route(w, req)

				assert.Equal(t, tc.expectCode, w.Code)

				if tc.expectCode == http.StatusOK {
					requests := backend.getRequests()
					require.Len(t, requests, 1)
					assert.Equal(t, tc.expectedPath, requests[0])
				}
			})
		}
	})

	t.Run("mount and unmount without trailing slash", func(t *testing.T) {
		backend := newMockBackend("accessor-unmount-no-slash")
		cleanupCalled := false
		backend.cleanupFunc = func() {
			cleanupCalled = true
		}

		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "unmount-noslash",
			Accessor: "accessor-unmount-no-slash",
		}

		// Mount without trailing slash
		err := router.Mount("unmount-noslash", backend, mountEntry)
		require.NoError(t, err)

		// Unmount without trailing slash
		err = router.Unmount("unmount-noslash")
		require.NoError(t, err)
		assert.True(t, cleanupCalled)

		// Verify backend is removed
		ctx := context.Background()
		retrievedBackend := router.MatchingBackend(ctx, "unmount-noslash/data")
		assert.Nil(t, retrievedBackend)
	})

	t.Run("taint and untaint without trailing slash", func(t *testing.T) {
		backend := newMockBackend("accessor-taint-no-slash")
		mountEntry := &MountEntry{
			Type:     "mock",
			Path:     "taint-noslash",
			Accessor: "accessor-taint-no-slash",
		}

		err := router.Mount("taint-noslash", backend, mountEntry)
		require.NoError(t, err)

		ctx := context.Background()

		// Taint without trailing slash
		err = router.Taint(ctx, "taint-noslash")
		require.NoError(t, err)

		// Verify it's tainted - route should fail
		req := httptest.NewRequest(http.MethodGet, "/v1/taint-noslash/data", nil)
		w := httptest.NewRecorder()
		router.Route(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)

		// Untaint without trailing slash
		err = router.Untaint(ctx, "taint-noslash")
		require.NoError(t, err)

		// Verify it's untainted - route should work
		req = httptest.NewRequest(http.MethodGet, "/v1/taint-noslash/data", nil)
		w = httptest.NewRecorder()
		router.Route(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("mixed trailing slash mounts", func(t *testing.T) {
		backend1 := newMockBackend("accessor-mixed-1")
		backend2 := newMockBackend("accessor-mixed-2")

		mountEntry1 := &MountEntry{
			Type:     "mock",
			Path:     "mixed1",
			Accessor: "accessor-mixed-1",
		}
		mountEntry2 := &MountEntry{
			Type:     "mock",
			Path:     "mixed2/",
			Accessor: "accessor-mixed-2",
		}

		// Mount one without slash, one with
		err := router.Mount("mixed1", backend1, mountEntry1)
		require.NoError(t, err)

		err = router.Mount("mixed2/", backend2, mountEntry2)
		require.NoError(t, err)

		ctx := context.Background()

		// Both should work correctly
		result1 := router.MatchingBackend(ctx, "mixed1/data")
		assert.Equal(t, backend1, result1)

		result2 := router.MatchingBackend(ctx, "mixed2/data")
		assert.Equal(t, backend2, result2)

		// Route to both
		req1 := httptest.NewRequest(http.MethodGet, "/v1/mixed1/test", nil)
		w1 := httptest.NewRecorder()
		router.Route(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		req2 := httptest.NewRequest(http.MethodGet, "/v1/mixed2/test", nil)
		w2 := httptest.NewRecorder()
		router.Route(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})
}
