package core

import (
	"context"
	"testing"

	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemHandlers_Init(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Test Init
	ctx := context.Background()
	input := &struct{}{}

	output, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.RootToken)
	assert.Contains(t, output.Body.RootToken, "cws.")

	// Verify token is valid
	principalID, roleName, err := tokenStore.ResolveToken(ctx, output.Body.RootToken, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "root", principalID)
	assert.Equal(t, "system_admin", roleName)
}

func TestSystemHandlers_Init_Multiple(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	ctx := context.Background()
	input := &struct{}{}

	// Generate first root token
	output1, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	token1 := output1.Body.RootToken

	// Attempt to generate second root token should fail (init-once guard)
	output2, err := handlers.Init(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output2)
	assert.Contains(t, err.Error(), "already initialized")

	// First token should still be valid
	principalID, roleName, err := tokenStore.ResolveToken(ctx, token1, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "root", principalID)
	assert.Equal(t, "system_admin", roleName)
}

func TestSystemHandlers_RevokeRootToken(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Generate root token first
	initOutput, err := handlers.Init(context.Background(), &struct{}{})
	require.NoError(t, err)
	rootToken := initOutput.Body.RootToken

	// Create context with root principal
	ctx := context.WithValue(context.Background(), SystemPrincipalIDKey, "root")
	input := &struct{}{}

	// Revoke root token
	output, err := handlers.RevokeRootToken(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "Root token successfully revoked", output.Body.Message)

	// Token should no longer be valid
	_, _, err = tokenStore.ResolveToken(context.Background(), rootToken, map[string]string{})
	assert.Error(t, err)
}

func TestSystemHandlers_RevokeRootToken_NonRootPrincipal(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")
	accessControl.AssignRole("user123", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Generate root token
	_, err = handlers.Init(context.Background(), &struct{}{})
	require.NoError(t, err)

	// Try to revoke with non-root principal (even though they have system_admin)
	ctx := context.WithValue(context.Background(), SystemPrincipalIDKey, "user123")
	input := &struct{}{}

	output, err := handlers.RevokeRootToken(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Only root principal can revoke root token")
}

func TestSystemHandlers_RevokeRootToken_NoPrincipal(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Generate root token
	_, err = handlers.Init(context.Background(), &struct{}{})
	require.NoError(t, err)

	// Try to revoke without principal in context
	ctx := context.Background()
	input := &struct{}{}

	output, err := handlers.RevokeRootToken(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Only root principal can revoke root token")
}

func TestSystemHandlers_RevokeRootToken_NoToken(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Try to revoke when no root token exists
	ctx := context.WithValue(context.Background(), SystemPrincipalIDKey, "root")
	input := &struct{}{}

	output, err := handlers.RevokeRootToken(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Failed to revoke root token")
}

func TestSystemHandlers_Init_OnlyOnce(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	tokenStore, err := token.NewRobustStore(log, token.DefaultConfig())
	require.NoError(t, err)
	defer tokenStore.Close()

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("root", "system_admin")

	core := &Core{
		storage:       store,
		tokenStore:    tokenStore,
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	ctx := context.Background()
	input := &struct{}{}

	// First init should succeed
	output1, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output1)
	assert.NotEmpty(t, output1.Body.RootToken)

	// Verify Warden is marked as initialized
	assert.True(t, core.IsInitialized())

	// Second init should fail
	output2, err := handlers.Init(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output2)
	assert.Contains(t, err.Error(), "already initialized")
}

func TestCore_IsInitialized(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	core := &Core{
		storage: store,
		logger:  log,
	}

	// Initially should not be initialized
	assert.False(t, core.IsInitialized())

	// After marking as initialized
	core.MarkInitialized()
	assert.True(t, core.IsInitialized())
}

func TestCore_MarkInitialized_Concurrent(t *testing.T) {
	// Setup
	log := logger.NewZerologLogger(logger.DefaultConfig())
	store := storage.NewMemoryStorage()
	store.Init(context.Background())

	core := &Core{
		storage: store,
		logger:  log,
	}

	// Test concurrent access to IsInitialized and MarkInitialized
	const goroutines = 100
	done := make(chan bool, goroutines)

	// Launch multiple goroutines trying to check/mark initialization
	for i := 0; i < goroutines; i++ {
		go func() {
			if !core.IsInitialized() {
				core.MarkInitialized()
			}
			done <- core.IsInitialized()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < goroutines; i++ {
		result := <-done
		assert.True(t, result)
	}

	// Final state should be initialized
	assert.True(t, core.IsInitialized())
}
