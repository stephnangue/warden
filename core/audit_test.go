package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/locking"
	"github.com/stephnangue/warden/internal/namespace"
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
		logger:       log,
		router:       router,
		mounts:       NewMountTable(),
		audit:        NewMountTable(),
		mountsLock:   locking.DeadlockRWMutex{},
		auditLock:    sync.RWMutex{},
		authMethods:  make(map[string]logical.Factory),
		providers:    make(map[string]logical.Factory),
		auditDevices: make(map[string]audit.Factory),
		tokenStore:   nil, // Not needed for audit tests
		auditManager: newMockAuditManagerFull(),
	}
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

// =============================================================================
// buildAuditRequest Tests
// =============================================================================

func TestBuildAuditRequest_NilRequest(t *testing.T) {
	result := buildAuditRequest(nil, nil)
	assert.Nil(t, result)
}

func TestBuildAuditRequest_BasicFields(t *testing.T) {
	req := &logical.Request{
		RequestID:  "req-123",
		Operation:  logical.ReadOperation,
		Path:       "secret/data/foo",
		MountPoint: "secret/",
		MountType:  "kv",
		ClientIP:   "192.168.1.1",
		Data:       map[string]any{"key": "value"},
	}

	result := buildAuditRequest(req, nil)
	require.NotNil(t, result)
	assert.Equal(t, "req-123", result.ID)
	assert.Equal(t, "read", result.Operation)
	assert.Equal(t, "secret/data/foo", result.Path)
	assert.Equal(t, "secret/", result.MountPoint)
	assert.Equal(t, "kv", result.MountType)
	assert.Equal(t, "192.168.1.1", result.ClientIP)
	assert.Equal(t, "value", result.Data["key"])
}

func TestBuildAuditRequest_WithAuditPath(t *testing.T) {
	req := &logical.Request{
		Path:      "internal/path",
		AuditPath: "external/path",
	}
	result := buildAuditRequest(req, nil)
	assert.Equal(t, "external/path", result.Path)
}

func TestBuildAuditRequest_WithNamespace(t *testing.T) {
	req := &logical.Request{
		Path:       "secret/data/foo",
		MountPoint: "PROD/DEV/secret/",
	}
	ns := &namespace.Namespace{
		ID:   "ns-123",
		Path: "PROD/DEV/",
	}
	result := buildAuditRequest(req, ns)
	assert.Equal(t, "ns-123", result.NamespaceID)
	assert.Equal(t, "PROD/DEV/", result.NamespacePath)
	assert.Equal(t, "secret/", result.MountPoint)
}

func TestBuildAuditRequest_WithHTTPRequest(t *testing.T) {
	httpReq, _ := http.NewRequest("GET", "/v1/secret/data/foo", nil)
	httpReq.Header.Set("X-Request-Id", "ext-123")

	req := &logical.Request{
		Path:        "secret/data/foo",
		HTTPRequest: httpReq,
	}
	result := buildAuditRequest(req, nil)
	assert.Equal(t, "GET", result.Method)
	assert.NotNil(t, result.Headers)
	assert.Contains(t, result.Headers["X-Request-Id"], "ext-123")
}

// =============================================================================
// buildAuditResponse Tests
// =============================================================================

func TestBuildAuditResponse_NilResponse(t *testing.T) {
	result := buildAuditResponse(nil, nil, nil)
	assert.Nil(t, result)
}

func TestBuildAuditResponse_Basic(t *testing.T) {
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"key": "value"},
		Warnings:   []string{"warn1"},
	}
	result := buildAuditResponse(resp, nil, nil)
	require.NotNil(t, result)
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.Equal(t, "value", result.Data["key"])
	assert.Contains(t, result.Warnings, "warn1")
}

func TestBuildAuditResponse_WithCredential(t *testing.T) {
	resp := &logical.Response{StatusCode: http.StatusOK}
	cred := &credential.Credential{
		CredentialID: "cred-123",
		Type:         "aws",
		Category:     "dynamic",
		LeaseTTL:     time.Hour,
		LeaseID:      "lease-123",
		SourceName:   "aws-prod",
		SourceType:   "aws",
		SpecName:     "dev-spec",
		Revocable:    true,
		Data:         map[string]string{"key": "val"},
	}
	result := buildAuditResponse(resp, nil, cred)
	require.NotNil(t, result.Credential)
	assert.Equal(t, "cred-123", result.Credential.CredentialID)
	assert.Equal(t, "aws", result.Credential.Type)
	assert.Equal(t, int64(3600), result.Credential.LeaseTTL)
	assert.Equal(t, "val", result.Credential.Data["key"])
}

func TestBuildAuditResponse_WithAuthResult(t *testing.T) {
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Auth: &logical.Auth{
			TokenType:      "jwt_role",
			PrincipalID:    "user@example.com",
			RoleName:       "admin",
			Policies:       []string{"default", "admin"},
			TokenTTL:       time.Hour,
			CredentialSpec: "aws-dev",
		},
	}
	result := buildAuditResponse(resp, nil, nil)
	require.NotNil(t, result.AuthResult)
	assert.Equal(t, "jwt_role", result.AuthResult.TokenType)
	assert.Equal(t, "user@example.com", result.AuthResult.PrincipalID)
	assert.Equal(t, "admin", result.AuthResult.RoleName)
	assert.Equal(t, int64(3600), result.AuthResult.TokenTTL)
}

func TestBuildAuditResponse_WithUpstreamURL(t *testing.T) {
	resp := &logical.Response{StatusCode: http.StatusOK, Streamed: true}
	req := &logical.Request{UpstreamURL: "https://api.example.com/v1/chat"}
	result := buildAuditResponse(resp, req, nil)
	assert.Equal(t, "https://api.example.com/v1/chat", result.UpstreamURL)
	assert.True(t, result.Streamed)
}

func TestBuildAuditResponse_WithHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Headers:    headers,
	}
	result := buildAuditResponse(resp, nil, nil)
	assert.Contains(t, result.Headers["Content-Type"], "application/json")
}

// =============================================================================
// buildAuditAuth Tests
// =============================================================================

func TestBuildAuditAuth_NilBoth(t *testing.T) {
	result := buildAuditAuth(nil, nil)
	assert.Nil(t, result)
}

func TestBuildAuditAuth_FromTokenEntry(t *testing.T) {
	te := &logical.TokenEntry{
		ID:            "tok-123",
		Accessor:      "acc-123",
		Type:          "jwt_role",
		PrincipalID:   "user@example.com",
		RoleName:      "admin",
		Policies:      []string{"default"},
		NamespaceID:   "ns-1",
		NamespacePath: "PROD/",
		CreatedByIP:   "10.0.0.1",
		ExpireAt:      time.Now().Add(time.Hour),
	}

	result := buildAuditAuth(nil, te)
	require.NotNil(t, result)
	assert.Equal(t, "tok-123", result.TokenID)
	assert.Equal(t, "acc-123", result.TokenAccessor)
	assert.Equal(t, "user@example.com", result.PrincipalID)
	assert.Equal(t, "ns-1", result.NamespaceID)
	assert.Equal(t, "10.0.0.1", result.CreatedByIP)
	assert.Greater(t, result.ExpiresAt, int64(0))
	assert.Greater(t, result.TokenTTL, int64(0))
}

func TestBuildAuditAuth_FromAuth(t *testing.T) {
	auth := &logical.Auth{
		TokenAccessor: "auth-acc",
		TokenType:     "cert_role",
		PrincipalID:   "agent-1",
		RoleName:      "role-1",
		Policies:      []string{"p1", "p2"},
		PolicyResults: &sdklogical.PolicyResults{
			Allowed: true,
			GrantingPolicies: []sdklogical.PolicyInfo{
				{Name: "p1"},
			},
		},
	}

	result := buildAuditAuth(auth, nil)
	require.NotNil(t, result)
	assert.Equal(t, "auth-acc", result.TokenAccessor)
	assert.Equal(t, "cert_role", result.TokenType)
	assert.Equal(t, "agent-1", result.PrincipalID)
	assert.True(t, result.PolicyResults.Allowed)
	assert.Contains(t, result.PolicyResults.GrantingPolicies, "p1")
}

func TestBuildAuditAuth_AuthOverridesTE(t *testing.T) {
	te := &logical.TokenEntry{
		PrincipalID: "old-user",
		RoleName:    "old-role",
	}
	auth := &logical.Auth{
		PrincipalID: "new-user",
		RoleName:    "new-role",
	}
	result := buildAuditAuth(auth, te)
	assert.Equal(t, "new-user", result.PrincipalID)
	assert.Equal(t, "new-role", result.RoleName)
}

// =============================================================================
// buildAuditAuthResult Tests
// =============================================================================

func TestBuildAuditAuthResult_Nil(t *testing.T) {
	assert.Nil(t, buildAuditAuthResult(nil))
}

func TestBuildAuditAuthResult_Basic(t *testing.T) {
	auth := &logical.Auth{
		TokenType:      "jwt_role",
		PrincipalID:    "user",
		RoleName:       "admin",
		Policies:       []string{"default"},
		TokenTTL:       30 * time.Minute,
		CredentialSpec: "aws-dev",
	}
	result := buildAuditAuthResult(auth)
	require.NotNil(t, result)
	assert.Equal(t, "jwt_role", result.TokenType)
	assert.Equal(t, "user", result.PrincipalID)
	assert.Equal(t, int64(1800), result.TokenTTL)
	assert.Equal(t, "aws-dev", result.CredentialSpec)
}

// =============================================================================
// buildAuditCredential Tests
// =============================================================================

func TestBuildAuditCredential_Nil(t *testing.T) {
	assert.Nil(t, buildAuditCredential(nil))
}

func TestBuildAuditCredential_Basic(t *testing.T) {
	cred := &credential.Credential{
		CredentialID: "cred-1",
		Type:         "aws",
		Category:     "dynamic",
		LeaseTTL:     time.Hour,
		LeaseID:      "lease-1",
		TokenID:      "tok-1",
		SourceName:   "aws-prod",
		SourceType:   "aws",
		SpecName:     "dev",
		Revocable:    true,
		Data:         map[string]string{"access_key_id": "AKIA123"},
	}
	result := buildAuditCredential(cred)
	require.NotNil(t, result)
	assert.Equal(t, "cred-1", result.CredentialID)
	assert.Equal(t, "AKIA123", result.Data["access_key_id"])
	assert.True(t, result.Revocable)
}

func TestBuildAuditCredential_NilData(t *testing.T) {
	cred := &credential.Credential{
		CredentialID: "cred-1",
		Data:         nil,
	}
	result := buildAuditCredential(cred)
	require.NotNil(t, result)
	assert.Nil(t, result.Data)
}

// =============================================================================
// copyMapAny Tests
// =============================================================================

func TestCopyMapAny_Nil(t *testing.T) {
	assert.Nil(t, copyMapAny(nil))
}

func TestCopyMapAny_NonNil(t *testing.T) {
	original := map[string]any{"a": 1, "b": "two"}
	copied := copyMapAny(original)
	assert.Equal(t, original, copied)

	copied["c"] = 3
	assert.NotContains(t, original, "c")
}

// =============================================================================
// copyHeaders Tests
// =============================================================================

func TestCopyHeaders_Nil(t *testing.T) {
	assert.Nil(t, copyHeaders(nil))
}

func TestCopyHeaders_Basic(t *testing.T) {
	headers := http.Header{
		"Content-Type": []string{"application/json"},
		"X-Custom":     []string{"val1", "val2"},
	}
	copied := copyHeaders(headers)
	assert.Equal(t, []string{"application/json"}, copied["Content-Type"])
	assert.Equal(t, []string{"val1", "val2"}, copied["X-Custom"])

	copied["New-Header"] = []string{"new"}
	_, exists := headers["New-Header"]
	assert.False(t, exists)
}

func TestCopyHeaders_NilValues(t *testing.T) {
	headers := http.Header{
		"X-Empty": nil,
	}
	copied := copyHeaders(headers)
	assert.Nil(t, copied["X-Empty"])
}

// =============================================================================
// BarrierEncryptorAccess Tests
// =============================================================================

func TestNewBarrierEncryptorAccess(t *testing.T) {
	mock := &mockBarrierEncryptor{}
	access := NewBarrierEncryptorAccess(mock)
	require.NotNil(t, access)

	ctx := context.Background()

	ct, err := access.Encrypt(ctx, "key", []byte("plain"))
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted:plain"), ct)

	pt, err := access.Decrypt(ctx, "key", []byte("cipher"))
	require.NoError(t, err)
	assert.Equal(t, []byte("decrypted:cipher"), pt)
}

type mockBarrierEncryptor struct{}

func (m *mockBarrierEncryptor) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte("encrypted:"), plaintext...), nil
}

func (m *mockBarrierEncryptor) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	return append([]byte("decrypted:"), ciphertext...), nil
}

// =============================================================================
// buildResponseAuditEntry Tests
// =============================================================================

func TestBuildResponseAuditEntry(t *testing.T) {
	core := createMockCoreForAudit()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{
		RequestID: "req-1",
		Path:      "secret/data/foo",
	}
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"key": "val"},
	}

	entry := core.buildResponseAuditEntry(ctx, req, resp, nil, nil, nil)
	require.NotNil(t, entry)
	assert.Equal(t, "response", entry.Type)
	assert.NotNil(t, entry.Request)
	assert.NotNil(t, entry.Response)
	assert.Empty(t, entry.Error)
}

func TestBuildResponseAuditEntry_WithOuterErr(t *testing.T) {
	core := createMockCoreForAudit()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{Path: "secret/data/foo"}
	resp := &logical.Response{StatusCode: http.StatusInternalServerError}

	entry := core.buildResponseAuditEntry(ctx, req, resp, nil, nil, assert.AnError)
	assert.Equal(t, assert.AnError.Error(), entry.Error)
}

func TestBuildResponseAuditEntry_WithRespErr(t *testing.T) {
	core := createMockCoreForAudit()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{Path: "secret/data/foo"}
	resp := &logical.Response{
		StatusCode: http.StatusBadRequest,
		Err:        assert.AnError,
	}

	entry := core.buildResponseAuditEntry(ctx, req, resp, nil, nil, nil)
	assert.Equal(t, assert.AnError.Error(), entry.Error)
}

func TestBuildResponseAuditEntry_WithCredential(t *testing.T) {
	core := createMockCoreForAudit()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{
		Path: "secret/data/foo",
		Credential: &credential.Credential{
			CredentialID: "cred-1",
			Type:         "aws",
		},
	}
	resp := &logical.Response{StatusCode: http.StatusOK}

	entry := core.buildResponseAuditEntry(ctx, req, resp, nil, nil, nil)
	require.NotNil(t, entry.Response.Credential)
	assert.Equal(t, "cred-1", entry.Response.Credential.CredentialID)
}

// =============================================================================
// buildRequestAuditEntry Tests
// =============================================================================

func TestBuildRequestAuditEntry(t *testing.T) {
	core := createMockCoreForAudit()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{
		RequestID: "req-1",
		Operation: logical.CreateOperation,
		Path:      "auth/jwt/login",
	}

	entry := core.buildRequestAuditEntry(ctx, req, nil, nil, nil)
	require.NotNil(t, entry)
	assert.Equal(t, "request", entry.Type)
	assert.NotZero(t, entry.Timestamp)
}

func TestBuildRequestAuditEntry_WithError(t *testing.T) {
	core := createMockCoreForAudit()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	req := &logical.Request{Path: "test"}

	entry := core.buildRequestAuditEntry(ctx, req, nil, nil, assert.AnError)
	assert.Equal(t, assert.AnError.Error(), entry.Error)
}
