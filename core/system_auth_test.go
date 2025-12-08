package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemHandlers_MountAuth_Success(t *testing.T) {
	core := createTestCore(t)

	// Register mock auth factory
	core.authMethods["testauth"] = &mockAuthFactory{}

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
	input := &MountAuthInput{
		Path: "test-auth",
	}
	input.Body.Type = "testauth"
	input.Body.Description = "Test auth method mount"
	input.Body.Config = map[string]any{"key": "value"}

	// Call handler directly
	output, err := handlers.MountAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "test-auth/", output.Body.Path)
	assert.NotEmpty(t, output.Body.Accessor)
	assert.Contains(t, output.Body.Message, "Successfully mounted")

	// Verify mount was created
	found, err := core.mounts.findByPath(context.Background(), "test-auth/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "testauth", found.Type)
	assert.Equal(t, mountClassAuth, found.Class)
	assert.Equal(t, "Test auth method mount", found.Description)
}

func TestSystemHandlers_MountAuth_Unauthorized(t *testing.T) {
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
	input := &MountAuthInput{
		Path: "test-auth",
	}
	input.Body.Type = "testauth"
	input.Body.Description = "Test auth method mount"
	input.Body.Config = map[string]any{"key": "value"}

	// Call handler directly - should fail with authorization error
	output, err := handlers.MountAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_MountAuth_InvalidPath(t *testing.T) {
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
	input := &MountAuthInput{
		Path: "sys",
	}
	input.Body.Type = "testauth"
	input.Body.Description = "Test auth method mount"
	input.Body.Config = map[string]any{"key": "value"}

	// Call handler directly - should fail with validation error
	output, err := handlers.MountAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "reserved prefix")
}

func TestSystemHandlers_MountAuth_NoAuth(t *testing.T) {
	core := createTestCore(t)

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create context without authentication
	ctx := context.Background()

	// Create input
	input := &MountAuthInput{
		Path: "test-auth",
	}
	input.Body.Type = "testauth"
	input.Body.Description = "Test auth method mount"
	input.Body.Config = map[string]any{"key": "value"}

	// Call handler directly - should fail with authentication error
	output, err := handlers.MountAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_MountAuth_SingleSegmentPath(t *testing.T) {
	core := createTestCore(t)

	// Register mock auth factory
	core.authMethods["jwt"] = &mockAuthFactory{}

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

	// Create input with single segment path (hyphens allowed)
	input := &MountAuthInput{
		Path: "jwt-prod-auth",
	}
	input.Body.Type = "jwt"
	input.Body.Description = "JWT auth for production"
	input.Body.Config = map[string]any{}

	// Call handler directly - should succeed with single segment
	output, err := handlers.MountAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "jwt-prod-auth/", output.Body.Path)
	assert.NotEmpty(t, output.Body.Accessor)
	assert.Contains(t, output.Body.Message, "Successfully mounted")

	// Verify mount was created
	found, err := core.mounts.findByPath(context.Background(), "jwt-prod-auth/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "jwt", found.Type)
	assert.Equal(t, mountClassAuth, found.Class)
	assert.Equal(t, "JWT auth for production", found.Description)
}

func TestSystemHandlers_UnmountAuth_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
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
	input := &UnmountAuthInput{
		Path: "test-auth",
	}

	// Call handler
	output, err := handlers.UnmountAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Successfully unmounted")

	// Verify mount was removed
	found, err := core.mounts.findByPath(context.Background(), "test-auth/")
	require.NoError(t, err)
	assert.Nil(t, found)
}

func TestSystemHandlers_UnmountAuth_Unauthorized(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
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
	input := &UnmountAuthInput{
		Path: "test-auth",
	}

	// Call handler - should fail
	output, err := handlers.UnmountAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_UnmountAuth_NotFound(t *testing.T) {
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
	input := &UnmountAuthInput{
		Path: "nonexistent",
	}

	// Call handler - should fail
	output, err := handlers.UnmountAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "no matching mount")
}

func TestSystemHandlers_GetAuthInfo_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
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
	input := &GetAuthInput{
		Path: "test-auth",
	}

	// Call handler
	output, err := handlers.GetAuthInfo(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "testauth", output.Body.Type)
	assert.Equal(t, "test-auth/", output.Body.Path)
	assert.Equal(t, "Test auth method", output.Body.Description)
	assert.NotEmpty(t, output.Body.Accessor)
}

func TestSystemHandlers_GetAuthInfo_Unauthorized(t *testing.T) {
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
	input := &GetAuthInput{
		Path: "test-auth",
	}

	// Call handler - should fail
	output, err := handlers.GetAuthInfo(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_GetAuthInfo_NotFound(t *testing.T) {
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
	input := &GetAuthInput{
		Path: "nonexistent",
	}

	// Call handler - should fail
	output, err := handlers.GetAuthInfo(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Auth method mount not found")
}

func TestSystemHandlers_GetAuthInfo_WrongClass(t *testing.T) {
	core := createTestCore(t)

	// Register and mount a provider (not auth)
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

	// Try to get as auth method
	input := &GetAuthInput{
		Path: "test-provider",
	}

	// Call handler - should fail because it's not an auth mount
	output, err := handlers.GetAuthInfo(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Auth method mount not found")
}

func TestSystemHandlers_ListAuths_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount multiple auth methods
	core.authMethods["testauth"] = &mockAuthFactory{}

	entry1 := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "auth1/",
		Description: "Auth 1",
	}
	err := core.mount(context.Background(), entry1)
	require.NoError(t, err)

	entry2 := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "auth2/",
		Description: "Auth 2",
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
	output, err := handlers.ListAuths(ctx, &struct{}{})
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Len(t, output.Body.Mounts, 2)
	assert.Contains(t, output.Body.Mounts, "auth1/")
	assert.Contains(t, output.Body.Mounts, "auth2/")
}

func TestSystemHandlers_ListAuths_Unauthorized(t *testing.T) {
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
	output, err := handlers.ListAuths(ctx, &struct{}{})
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_ListAuths_FiltersNonAuth(t *testing.T) {
	core := createTestCore(t)

	// Register and mount both auth and provider mounts
	core.authMethods["testauth"] = &mockAuthFactory{}
	core.providers["testprovider"] = &mockProviderFactory{}

	authEntry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "auth1/",
		Description: "Auth 1",
	}
	err := core.mount(context.Background(), authEntry)
	require.NoError(t, err)

	providerEntry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "testprovider",
		Path:        "provider1/",
		Description: "Provider 1",
	}
	err = core.mount(context.Background(), providerEntry)
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
	output, err := handlers.ListAuths(ctx, &struct{}{})
	require.NoError(t, err)
	assert.NotNil(t, output)

	// Should only contain auth mounts
	assert.Len(t, output.Body.Mounts, 1)
	assert.Contains(t, output.Body.Mounts, "auth1/")
	assert.NotContains(t, output.Body.Mounts, "provider1/")
}

func TestSystemHandlers_ListAuths_EmptyResult(t *testing.T) {
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
	output, err := handlers.ListAuths(ctx, &struct{}{})
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotNil(t, output.Body.Mounts)
	assert.Len(t, output.Body.Mounts, 0)
}

func TestSystemHandlers_TuneAuth_Success(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
		Config: map[string]any{
			"token_ttl": 3600,
			"issuer":    "warden-v1",
		},
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

	// Create input with tune config
	input := &TuneAuthInput{
		Path: "test-auth",
	}
	input.Body = map[string]any{
		"token_ttl": 7200, // Update existing
		"max_ttl":   14400, // Add new
	}

	// Call handler
	output, err := handlers.ConfigureAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Successfully tuned auth method mount")

	// Verify config was updated
	found, err := core.mounts.findByPath(context.Background(), "test-auth/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, 7200, found.Config["token_ttl"])      // Updated
	assert.Equal(t, "warden-v1", found.Config["issuer"])  // Unchanged
	assert.Equal(t, 14400, found.Config["max_ttl"])       // Added
}

func TestSystemHandlers_TuneAuth_Unauthorized(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
		Config:      map[string]any{"key": "value"},
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
	input := &TuneAuthInput{
		Path: "test-auth",
	}
	input.Body = map[string]any{"new_key": "new_value"}

	// Call handler - should fail
	output, err := handlers.ConfigureAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_TuneAuth_NotFound(t *testing.T) {
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
	input := &TuneAuthInput{
		Path: "nonexistent",
	}
	input.Body = map[string]any{"key": "value"}

	// Call handler - should fail
	output, err := handlers.ConfigureAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "no matching mount")
}

func TestSystemHandlers_TuneAuth_ProtectedPath(t *testing.T) {
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

	// Try to tune protected path
	input := &TuneAuthInput{
		Path: "sys/test",
	}
	input.Body = map[string]any{"key": "value"}

	// Call handler - should fail
	output, err := handlers.ConfigureAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Operation not permitted")
}

func TestSystemHandlers_TuneAuth_EmptyConfig(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
		Config:      map[string]any{"original": "value"},
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

	// Create input with empty config
	input := &TuneAuthInput{
		Path: "test-auth",
	}
	input.Body = map[string]any{}

	// Call handler - should succeed
	output, err := handlers.ConfigureAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Successfully tuned auth method mount")

	// Verify original config is unchanged
	found, err := core.mounts.findByPath(context.Background(), "test-auth/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, "value", found.Config["original"])
}

func TestSystemHandlers_TuneAuth_NilConfig(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method with nil config
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
		Config:      nil,
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

	// Create input with config
	input := &TuneAuthInput{
		Path: "test-auth",
	}
	input.Body = map[string]any{
		"new_key": "new_value",
	}

	// Call handler - should succeed
	output, err := handlers.ConfigureAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Successfully tuned auth method mount")

	// Verify config was created and populated
	found, err := core.mounts.findByPath(context.Background(), "test-auth/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.NotNil(t, found.Config)
	assert.Equal(t, "new_value", found.Config["new_key"])
}

func TestSystemHandlers_TuneAuth_NoAuth(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
	}
	err := core.mount(context.Background(), entry)
	require.NoError(t, err)

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create context without authentication
	ctx := context.Background()

	// Create input
	input := &TuneAuthInput{
		Path: "test-auth",
	}
	input.Body = map[string]any{"key": "value"}

	// Call handler - should fail
	output, err := handlers.ConfigureAuth(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_TuneAuth_ComplexConfig(t *testing.T) {
	core := createTestCore(t)

	// Register and mount auth method first
	core.authMethods["testauth"] = &mockAuthFactory{}
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "testauth",
		Path:        "test-auth/",
		Description: "Test auth method",
		Config:      map[string]any{},
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

	// Create input with complex config
	input := &TuneAuthInput{
		Path: "test-auth",
	}
	input.Body = map[string]any{
		"allowed_domains": []string{"example.com", "test.com"},
		"token_ttl":       3600,
		"jwks": map[string]any{
			"url":      "https://example.com/.well-known/jwks.json",
			"cache_ttl": 86400,
		},
	}

	// Call handler
	output, err := handlers.ConfigureAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Successfully tuned auth method mount")

	// Verify complex config was stored
	found, err := core.mounts.findByPath(context.Background(), "test-auth/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.NotNil(t, found.Config["allowed_domains"])
	assert.Equal(t, 3600, found.Config["token_ttl"])
	assert.NotNil(t, found.Config["jwks"])
}
