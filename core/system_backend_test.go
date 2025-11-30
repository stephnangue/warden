package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/openbao/openbao/helper/locking"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test core with all dependencies
func createTestCore(t *testing.T) *Core {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	router := NewRouter(log)
	tokenStore, err := token.NewRobustStore(log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { tokenStore.Close() })

	return &Core{
		logger:        log,
		router:        router,
		mounts:        NewMountTable(),
		mountsLock:    locking.DeadlockRWMutex{},
		authMethods:   make(map[string]auth.Factory),
		providers:     make(map[string]provider.Factory),
		tokenStore:    tokenStore,
		roles:         authorize.NewRoleRegistry(),
		accessControl: authorize.NewAccessControl(),
		credSources:   cred.NewCredSourceRegistry(),
		auditManager:  &mockAuditManager{},
	}
}

func TestNewSystemBackend(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	core := createTestCore(t)

	backend := NewSystemBackend(core, log)

	assert.NotNil(t, backend)
	assert.Equal(t, core, backend.core)
	assert.Equal(t, log, backend.logger)
	assert.NotNil(t, backend.router)
	assert.NotNil(t, backend.api)
	assert.NotNil(t, backend.handlers)
}

func TestSystemBackend_GetType(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	assert.Equal(t, "system", backend.GetType())
}

func TestSystemBackend_GetClass(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	assert.Equal(t, mountClassSystem, backend.GetClass())
}

func TestSystemBackend_GetDescription(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	description := backend.GetDescription()
	assert.NotEmpty(t, description)
	assert.Contains(t, description, "System backend")
}

func TestSystemBackend_GetAccessor(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	assert.Equal(t, "system", backend.GetAccessor())
}

func TestSystemBackend_Cleanup(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	// Should not panic
	backend.Cleanup()
}

func TestSystemHandlers_MountProvider_Success(t *testing.T) {
	core := createTestCore(t)

	// Register mock provider factory
	core.providers["testprovider"] = &mockProviderFactory{}

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &MountProviderInput{
		Path:        "test-provider",
		Type:        "testprovider",
		Description: "Test provider mount",
		Config:      map[string]any{"key": "value"},
	}

	// Call handler directly
	output, err := handlers.MountProvider(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "test-provider/", output.Body.Path)
	assert.NotEmpty(t, output.Body.Accessor)
	assert.Contains(t, output.Body.Message, "Successfully mounted")

	// Verify mount was created
	found, err := core.mounts.findByPath(context.Background(), "test-provider/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "testprovider", found.Type)
	assert.Equal(t, "Test provider mount", found.Description)
}

func TestSystemHandlers_MountProvider_Unauthorized(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization with insufficient permissions
	core.accessControl.AssignRole("regular-user", "market_reader")

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with insufficient permissions
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "regular-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "market_reader")

	// Create input
	input := &MountProviderInput{
		Path:        "test-provider",
		Type:        "testprovider",
		Description: "Test provider mount",
		Config:      map[string]any{"key": "value"},
	}

	// Call handler directly - should fail with authorization error
	output, err := handlers.MountProvider(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_MountProvider_InvalidPath(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with invalid path (starts with reserved prefix)
	input := &MountProviderInput{
		Path:        "sys/custom",
		Type:        "testprovider",
		Description: "Test provider mount",
		Config:      map[string]any{"key": "value"},
	}

	// Call handler directly - should fail with validation error
	output, err := handlers.MountProvider(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "reserved prefix")
}

func TestSystemHandlers_MountProvider_NestedPath(t *testing.T) {
	core := createTestCore(t)

	// Register mock provider factory
	core.providers["testprovider"] = &mockProviderFactory{}

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with nested path
	input := &MountProviderInput{
		Path:        "aws/production/us-east-1",
		Type:        "testprovider",
		Description: "Production AWS provider in us-east-1",
		Config:      map[string]any{"region": "us-east-1"},
	}

	// Call handler directly
	output, err := handlers.MountProvider(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "aws/production/us-east-1/", output.Body.Path)
	assert.NotEmpty(t, output.Body.Accessor)
	assert.Contains(t, output.Body.Message, "Successfully mounted")

	// Verify mount was created with nested path
	found, err := core.mounts.findByPath(context.Background(), "aws/production/us-east-1/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "testprovider", found.Type)
	assert.Equal(t, "Production AWS provider in us-east-1", found.Description)
}

func TestSystemHandlers_MountProvider_NoAuth(t *testing.T) {
	core := createTestCore(t)

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create context without authentication
	ctx := context.Background()

	// Create input
	input := &MountProviderInput{
		Path:        "test-provider",
		Type:        "testprovider",
		Description: "Test provider mount",
		Config:      map[string]any{"key": "value"},
	}

	// Call handler directly - should fail with authentication error
	output, err := handlers.MountProvider(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_UnmountProvider_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount provider first
	core.providers["testprovider"] = &mockProviderFactory{}
	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "test-provider/",
		Description: "Test provider",
	}
	err := core.mount(context.Background(), entry)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &UnmountProviderInput{
		Path: "test-provider",
	}

	// Call handler
	output, err := handlers.UnmountProvider(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Successfully unmounted")

	// Verify mount was removed
	found, err := core.mounts.findByPath(context.Background(), "test-provider/")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestSystemHandlers_UnmountProvider_Unauthorized(t *testing.T) {
	core := createTestCore(t)

	// Register and mount provider first
	core.providers["testprovider"] = &mockProviderFactory{}
	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "test-provider/",
		Description: "Test provider",
	}
	err := core.mount(context.Background(), entry)
	require.NoError(t, err)

	// Setup authorization with insufficient permissions
	core.accessControl.AssignRole("regular-user", "market_reader")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with insufficient permissions
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "regular-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "market_reader")

	// Create input
	input := &UnmountProviderInput{
		Path: "test-provider",
	}

	// Call handler - should fail
	output, err := handlers.UnmountProvider(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_UnmountProvider_NotFound(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input for non-existent mount
	input := &UnmountProviderInput{
		Path: "nonexistent",
	}

	// Call handler - should fail
	output, err := handlers.UnmountProvider(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Mount not found")
}

func TestSystemHandlers_GetMountInfo_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount provider first
	core.providers["testprovider"] = &mockProviderFactory{}
	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "test-provider/",
		Description: "Test provider",
		Config:      map[string]any{"key": "value"},
	}
	err := core.mount(context.Background(), entry)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &GetMountInput{
		Path: "test-provider",
	}

	// Call handler
	output, err := handlers.GetMountInfo(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "testprovider", output.Body.Type)
	assert.Equal(t, "test-provider/", output.Body.Path)
	assert.Equal(t, "Test provider", output.Body.Description)
	assert.NotEmpty(t, output.Body.Accessor)
}

func TestSystemHandlers_GetMountInfo_Unauthorized(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization with insufficient permissions
	core.accessControl.AssignRole("regular-user", "market_reader")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with insufficient permissions
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "regular-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "market_reader")

	// Create input
	input := &GetMountInput{
		Path: "test-provider",
	}

	// Call handler - should fail
	output, err := handlers.GetMountInfo(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_GetMountInfo_NotFound(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input for non-existent mount
	input := &GetMountInput{
		Path: "nonexistent",
	}

	// Call handler - should fail
	output, err := handlers.GetMountInfo(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Mount not found")
}

func TestSystemHandlers_ListMounts_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount multiple providers
	core.providers["testprovider"] = &mockProviderFactory{}

	entry1 := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "provider1/",
		Description: "Provider 1",
	}
	err := core.mount(context.Background(), entry1)
	require.NoError(t, err)

	entry2 := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "provider2/",
		Description: "Provider 2",
	}
	err = core.mount(context.Background(), entry2)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Call handler
	output, err := handlers.ListMounts(ctx, &struct{}{})
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Len(t, output.Body.Mounts, 2)
	assert.Contains(t, output.Body.Mounts, "provider1/")
	assert.Contains(t, output.Body.Mounts, "provider2/")
}

func TestSystemHandlers_ListMounts_Unauthorized(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization with insufficient permissions
	core.accessControl.AssignRole("regular-user", "market_reader")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with insufficient permissions
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "regular-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "market_reader")

	// Call handler - should fail
	output, err := handlers.ListMounts(ctx, &struct{}{})
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_ListMounts_FiltersNonProviders(t *testing.T) {
	core := createTestCore(t)

	// Register and mount both provider and auth mounts
	core.providers["testprovider"] = &mockProviderFactory{}
	core.authMethods["testauth"] = &mockAuthFactory{}

	providerEntry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "provider1/",
		Description: "Provider 1",
	}
	err := core.mount(context.Background(), providerEntry)
	require.NoError(t, err)

	authEntry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "auth1/",
		Description: "Auth 1",
	}
	err = core.mount(context.Background(), authEntry)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Call handler
	output, err := handlers.ListMounts(ctx, &struct{}{})
	require.NoError(t, err)
	assert.NotNil(t, output)

	// Should only contain provider mounts
	assert.Len(t, output.Body.Mounts, 1)
	assert.Contains(t, output.Body.Mounts, "provider1/")
	assert.NotContains(t, output.Body.Mounts, "auth1/")
}

func TestSystemHandlers_ListMounts_EmptyResult(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Call handler
	output, err := handlers.ListMounts(ctx, &struct{}{})
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotNil(t, output.Body.Mounts)
	assert.Len(t, output.Body.Mounts, 0)
}

func TestSystemHandlers_ConvertError(t *testing.T) {
	core := createTestCore(t)
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	tests := []struct {
		name           string
		inputError     error
		expectedStatus int
		expectedText   string
	}{
		{
			name:           "already in use",
			inputError:     &mountError{msg: "path already in use"},
			expectedStatus: http.StatusConflict,
			expectedText:   "Mount path conflict",
		},
		{
			name:           "no matching mount",
			inputError:     errNoMatchingMount,
			expectedStatus: http.StatusNotFound,
			expectedText:   "Mount not found",
		},
		{
			name:           "cannot mount",
			inputError:     &mountError{msg: "cannot mount at protected path"},
			expectedStatus: http.StatusForbidden,
			expectedText:   "Operation not permitted",
		},
		{
			name:           "not supported",
			inputError:     &mountError{msg: "type not supported"},
			expectedStatus: http.StatusBadRequest,
			expectedText:   "Invalid mount type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handlers.convertError(tt.inputError)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedText)
		})
	}
}

// mountError is a helper type for testing error conversion
type mountError struct {
	msg string
}

func (e *mountError) Error() string {
	return e.msg
}
