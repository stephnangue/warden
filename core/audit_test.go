package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/middleware"
	"github.com/openbao/openbao/helper/locking"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockCoreForAudit creates a Core instance configured for audit testing
func createMockCoreForAudit() *Core {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	return &Core{
		logger:        log,
		router:        router,
		mounts:        NewMountTable(),
		audit:         NewMountTable(),
		mountsLock:    locking.DeadlockRWMutex{},
		auditLock:     sync.RWMutex{},
		authMethods:   make(map[string]logical.Factory),
		providers:     make(map[string]logical.Factory),
		auditDevices:  make(map[string]audit.Factory),
		tokenStore:    nil, // Not needed for audit tests
		auditManager:  newMockAuditManagerFull(),
	}
}

// TestAuditRequest tests the auditRequest method
func TestAuditRequest(t *testing.T) {
	t.Run("audit request with body", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockManager := core.auditManager.(*mockAuditManagerFull)
		mockManager.logRequestResult = true

		body := `{"key": "value"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/test/path", strings.NewReader(body))
		req.RemoteAddr = "192.168.1.100:12345"
		req.Header.Set("Content-Type", "application/json")

		// Add request ID to context
		ctx := context.WithValue(req.Context(), middleware.RequestIDKey, "test-request-id")
		req = req.WithContext(ctx)

		ok := core.auditRequest(req)
		assert.True(t, ok)

		// Verify body is still readable after audit
		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(bodyBytes))
	})

	t.Run("audit request without body", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockManager := core.auditManager.(*mockAuditManagerFull)
		mockManager.logRequestResult = true

		req := httptest.NewRequest(http.MethodGet, "/v1/test/path", nil)
		req.RemoteAddr = "10.0.0.1:8080"

		ok := core.auditRequest(req)
		assert.True(t, ok)
	})

	t.Run("audit request with error", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockManager := core.auditManager.(*mockAuditManagerFull)
		mockManager.logRequestResult = false
		mockManager.logRequestErr = errors.New("audit failed")

		req := httptest.NewRequest(http.MethodGet, "/v1/test/path", nil)
		req.RemoteAddr = "127.0.0.1:3000"

		ok := core.auditRequest(req)
		assert.False(t, ok)
	})

	t.Run("audit request with IPv6 address", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockManager := core.auditManager.(*mockAuditManagerFull)
		mockManager.logRequestResult = true

		req := httptest.NewRequest(http.MethodGet, "/v1/test/path", nil)
		req.RemoteAddr = "[::1]:8080"

		ok := core.auditRequest(req)
		assert.True(t, ok)
	})

	t.Run("audit request with invalid remote addr", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockManager := core.auditManager.(*mockAuditManagerFull)
		mockManager.logRequestResult = true

		req := httptest.NewRequest(http.MethodGet, "/v1/test/path", nil)
		req.RemoteAddr = "invalid-addr" // No port, SplitHostPort will fail

		ok := core.auditRequest(req)
		assert.True(t, ok)
	})

	t.Run("audit request copies headers", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockManager := core.auditManager.(*mockAuditManagerFull)
		mockManager.logRequestResult = true

		req := httptest.NewRequest(http.MethodPost, "/v1/test/path", bytes.NewReader([]byte("test")))
		req.RemoteAddr = "192.168.1.1:8080"
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Custom-Header", "custom-value")

		ok := core.auditRequest(req)
		assert.True(t, ok)
	})
}

// TestEnableAudit tests the EnableAudit method
func TestEnableAudit(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("enable audit with trailing slash added", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "mock",
			Path:        "file",
			Description: "test audit",
			Config:      map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)
		assert.Equal(t, "file/", entry.Path)
	})

	t.Run("enable audit with empty path", func(t *testing.T) {
		core := createMockCoreForAudit()

		entry := &MountEntry{
			Class: mountClassAudit,
			Type:  "mock",
			Path:  "",
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend path must be specified")
	})

	t.Run("enable audit path already in use - exact match", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		// Add existing entry to audit table
		core.audit.Entries = append(core.audit.Entries, &MountEntry{
			Path: "existing/",
			Type: "mock",
		})

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "mock",
			Path:   "existing/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path already in use")
	})

	t.Run("enable audit path already in use - prefix conflict new is prefix", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		// Add existing entry to audit table
		core.audit.Entries = append(core.audit.Entries, &MountEntry{
			Path: "sql/mysql/",
			Type: "mock",
		})

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "mock",
			Path:   "sql/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path already in use")
	})

	t.Run("enable audit path already in use - prefix conflict existing is prefix", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		// Add existing entry to audit table
		core.audit.Entries = append(core.audit.Entries, &MountEntry{
			Path: "sql/",
			Type: "mock",
		})

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "mock",
			Path:   "sql/mysql/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path already in use")
	})

	t.Run("enable audit generates accessor", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "mock",
			Path:   "test/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)
		assert.NotEmpty(t, entry.Accessor)
		assert.True(t, strings.HasPrefix(entry.Accessor, "audit_mock_"))
	})

	t.Run("enable audit with predefined accessor", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		entry := &MountEntry{
			Class:    mountClassAudit,
			Type:     "mock",
			Path:     "test/",
			Accessor: "custom_accessor_12345678",
			Config:   map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)
		assert.Equal(t, "custom_accessor_12345678", entry.Accessor)
	})

	t.Run("enable audit unsupported type", func(t *testing.T) {
		core := createMockCoreForAudit()

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "unsupported",
			Path:   "test/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("enable audit backend creation returns nil", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["nilbackend"] = &mockAuditFactory{
			createFunc: func(ctx context.Context, mountPath, description, accessor string, config map[string]any) (audit.Device, error) {
				return nil, nil
			},
		}

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "nilbackend",
			Path:   "test/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil backend")
	})

	t.Run("enable audit backend creation returns error", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["errorbackend"] = &mockAuditFactory{
			createErr: errors.New("creation failed"),
		}

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "errorbackend",
			Path:   "test/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "creation failed")
	})

	t.Run("enable audit with test probe success", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockDevice := newMockAuditDevice("test")
		core.auditDevices["testdevice"] = &mockAuditFactory{
			device: mockDevice,
		}

		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "testdevice",
			Path:        "test/",
			Description: "test audit device",
			Config:      map[string]any{}, // No skip_test
		}

		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)

		// Verify the test probe was logged
		assert.Equal(t, 1, mockDevice.logRequestCalls)
	})

	t.Run("enable audit with test probe failure", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockDevice := newMockAuditDevice("test")
		mockDevice.logRequestErr = errors.New("test probe failed")
		core.auditDevices["faildevice"] = &mockAuditFactory{
			device: mockDevice,
		}

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "faildevice",
			Path:   "test/",
			Config: map[string]any{}, // No skip_test, so test will run
		}

		err := core.EnableAudit(ctx, entry, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit device failed test message")
	})

	t.Run("enable audit adds to audit table", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "mock",
			Path:   "test/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)

		assert.Len(t, core.audit.Entries, 1)
		assert.Equal(t, "test/", core.audit.Entries[0].Path)
	})

	t.Run("enable audit registers with audit manager", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}
		mockManager := core.auditManager.(*mockAuditManagerFull)

		entry := &MountEntry{
			Class:  mountClassAudit,
			Type:   "mock",
			Path:   "test/",
			Config: map[string]any{"skip_test": "true"},
		}

		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)

		devices := mockManager.ListDevices()
		assert.Contains(t, devices, "test/")
	})
}

// TestDisableAudit tests the DisableAudit method
func TestDisableAudit(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("disable audit with trailing slash added", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		// First enable the audit
		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "mock",
			Path:        "test/",
			Config:      map[string]any{"skip_test": "true"},
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)

		// Disable without trailing slash
		ok, err := core.DisableAudit(ctx, "test", false)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("disable audit with empty path", func(t *testing.T) {
		core := createMockCoreForAudit()

		ok, err := core.DisableAudit(ctx, "", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend path must be specified")
		assert.False(t, ok)
	})

	t.Run("disable non-existent audit", func(t *testing.T) {
		core := createMockCoreForAudit()

		ok, err := core.DisableAudit(ctx, "nonexistent/", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no matching backend")
		assert.False(t, ok)
	})

	t.Run("successful disable audit", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}
		mockManager := core.auditManager.(*mockAuditManagerFull)

		// First enable the audit
		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "mock",
			Path:        "test/",
			Config:      map[string]any{"skip_test": "true"},
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)

		// Verify it's registered
		assert.Contains(t, mockManager.ListDevices(), "test/")

		// Disable the audit
		ok, err := core.DisableAudit(ctx, "test/", false)
		require.NoError(t, err)
		assert.True(t, ok)

		// Verify it's removed from audit table
		assert.Len(t, core.audit.Entries, 0)

		// Verify it's unregistered from audit manager
		assert.NotContains(t, mockManager.ListDevices(), "test/")
	})

	t.Run("disable audit sets entries to nil when empty", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["mock"] = &mockAuditFactory{}

		// First enable the audit
		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "mock",
			Path:        "test/",
			Config:      map[string]any{"skip_test": "true"},
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		err := core.EnableAudit(ctx, entry, false)
		require.NoError(t, err)

		// Disable the audit
		ok, err := core.DisableAudit(ctx, "test/", false)
		require.NoError(t, err)
		assert.True(t, ok)

		// Verify entries is nil
		assert.Nil(t, core.audit.Entries)
	})
}

// TestNewAuditBackend tests the newAuditBackend method
func TestNewAuditBackend(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("create audit backend successfully", func(t *testing.T) {
		core := createMockCoreForAudit()
		mockDevice := newMockAuditDevice("test")
		core.auditDevices["mock"] = &mockAuditFactory{
			device: mockDevice,
		}

		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "mock",
			Path:        "test/",
			Description: "test device",
			Accessor:    "accessor_123",
			Config:      map[string]any{"key": "value"},
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}

		backend, err := core.newAuditBackend(ctx, entry)
		require.NoError(t, err)
		assert.NotNil(t, backend)
		assert.Equal(t, mockDevice, backend)
	})

	t.Run("unsupported audit type", func(t *testing.T) {
		core := createMockCoreForAudit()

		entry := &MountEntry{
			Class: mountClassAudit,
			Type:  "unsupported",
			Path:  "test/",
		}

		backend, err := core.newAuditBackend(ctx, entry)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.Contains(t, err.Error(), "audit device type not supported")
	})

	t.Run("factory creation error", func(t *testing.T) {
		core := createMockCoreForAudit()
		core.auditDevices["errortype"] = &mockAuditFactory{
			createErr: errors.New("factory error"),
		}

		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "errortype",
			Path:        "test/",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}

		backend, err := core.newAuditBackend(ctx, entry)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.Contains(t, err.Error(), "failed to create audit device")
	})

	t.Run("non-audit class returns nil backend", func(t *testing.T) {
		core := createMockCoreForAudit()

		entry := &MountEntry{
			Class:       "other",
			Type:        "mock",
			Path:        "test/",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}

		backend, err := core.newAuditBackend(ctx, entry)
		require.NoError(t, err)
		assert.Nil(t, backend)
	})
}

// TestEnableDisableAudit_Concurrent tests concurrent enable/disable operations
func TestEnableDisableAudit_Concurrent(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	core := createMockCoreForAudit()
	core.auditDevices["mock"] = &mockAuditFactory{}

	var wg sync.WaitGroup
	numOps := 10

	// Enable multiple audit devices concurrently
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			entry := &MountEntry{
				Class:       mountClassAudit,
				Type:        "mock",
				Path:        fmt.Sprintf("concurrent-%d/", idx),
				Description: fmt.Sprintf("concurrent test %d", idx),
				Config:      map[string]any{"skip_test": "true"},
				NamespaceID: namespace.RootNamespaceID,
				namespace:   namespace.RootNamespace,
			}

			err := core.EnableAudit(ctx, entry, false)
			if err != nil {
				t.Errorf("Failed to enable audit: %v", err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all audits exist
	assert.Len(t, core.audit.Entries, numOps)

	// Disable all concurrently
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			ok, err := core.DisableAudit(ctx, fmt.Sprintf("concurrent-%d/", idx), false)
			if err != nil {
				t.Errorf("Failed to disable audit: %v", err)
			}
			if !ok {
				t.Errorf("DisableAudit returned false")
			}
		}(i)
	}

	wg.Wait()

	// Verify all audits are removed
	assert.Nil(t, core.audit.Entries)
}
