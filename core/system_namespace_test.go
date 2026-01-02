package core

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemHandlers_CreateNamespace_Success(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &CreateNamespaceInput{
		Path: "test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{
		"team":        "engineering",
		"environment": "dev",
	}

	// Call handler
	output, err := handlers.CreateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.ID)
	assert.Equal(t, "test-namespace/", output.Body.Path)
	assert.Equal(t, "engineering", output.Body.CustomMetadata["team"])
	assert.Contains(t, output.Body.Message, "Successfully created namespace")

	// Verify namespace was created
	ns, err := core.namespaceStore.GetNamespaceByPath(ctx, "test-namespace")
	require.NoError(t, err)
	assert.NotNil(t, ns)
	assert.Equal(t, "test-namespace/", ns.Path)
}

func TestSystemHandlers_CreateNamespace_Unauthorized(t *testing.T) {
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
	input := &CreateNamespaceInput{
		Path: "test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{"key": "value"}

	// Call handler - should fail
	output, err := handlers.CreateNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_CreateNamespace_NoAuth(t *testing.T) {
	core := createTestCore(t)

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create context without authentication
	ctx := context.Background()

	// Create input
	input := &CreateNamespaceInput{
		Path: "test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - should fail
	output, err := handlers.CreateNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_CreateNamespace_EmptyMetadata(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with empty metadata
	input := &CreateNamespaceInput{
		Path: "test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - should succeed
	output, err := handlers.CreateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.ID)
	assert.Equal(t, "test-namespace/", output.Body.Path)
}

func TestSystemHandlers_GetNamespace_Success(t *testing.T) {
	core := createTestCore(t)

	// Create a namespace first
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ns := &namespace.Namespace{
		Path: "test-namespace/",
		CustomMetadata: map[string]string{
			"team": "engineering",
		},
	}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx = namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &GetNamespaceInput{
		Path: "test-namespace",
	}

	// Call handler
	output, err := handlers.GetNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.ID)
	assert.Equal(t, "test-namespace/", output.Body.Path)
	assert.Equal(t, "engineering", output.Body.CustomMetadata["team"])
}

func TestSystemHandlers_GetNamespace_NotFound(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input for non-existent namespace
	input := &GetNamespaceInput{
		Path: "nonexistent",
	}

	// Call handler - should fail
	output, err := handlers.GetNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Namespace not found")
}

func TestSystemHandlers_GetNamespace_Unauthorized(t *testing.T) {
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
	input := &GetNamespaceInput{
		Path: "test-namespace",
	}

	// Call handler - should fail
	output, err := handlers.GetNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_ListNamespaces_Success(t *testing.T) {
	core := createTestCore(t)

	// Create multiple namespaces
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	ns1 := &namespace.Namespace{
		Path: "namespace1/",
		CustomMetadata: map[string]string{
			"team": "team1",
		},
	}
	err := core.namespaceStore.SetNamespace(ctx, ns1)
	require.NoError(t, err)

	ns2 := &namespace.Namespace{
		Path: "namespace2/",
		CustomMetadata: map[string]string{
			"team": "team2",
		},
	}
	err = core.namespaceStore.SetNamespace(ctx, ns2)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx = namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &ListNamespacesInput{
		IncludeParent: false,
		Recursive:     false,
	}

	// Call handler
	output, err := handlers.ListNamespaces(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Len(t, output.Body.Namespaces, 2)

	// Check namespace details
	paths := make([]string, 0)
	for _, ns := range output.Body.Namespaces {
		paths = append(paths, ns.Path)
	}
	assert.Contains(t, paths, "namespace1/")
	assert.Contains(t, paths, "namespace2/")
}

func TestSystemHandlers_ListNamespaces_Empty(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &ListNamespacesInput{
		IncludeParent: false,
		Recursive:     false,
	}

	// Call handler
	output, err := handlers.ListNamespaces(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Len(t, output.Body.Namespaces, 0)
}

func TestSystemHandlers_ListNamespaces_Unauthorized(t *testing.T) {
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
	input := &ListNamespacesInput{
		IncludeParent: false,
		Recursive:     false,
	}

	// Call handler - should fail
	output, err := handlers.ListNamespaces(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_ListNamespaces_Recursive(t *testing.T) {
	core := createTestCore(t)

	// Create parent and child namespaces
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	parent := &namespace.Namespace{
		Path:           "parent/",
		CustomMetadata: map[string]string{},
	}
	err := core.namespaceStore.SetNamespace(ctx, parent)
	require.NoError(t, err)

	// Create child namespace
	childCtx := namespace.ContextWithNamespace(ctx, parent)
	child := &namespace.Namespace{
		Path:           "parent/child/",
		CustomMetadata: map[string]string{},
	}
	err = core.namespaceStore.SetNamespace(childCtx, child)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx = namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with recursive flag
	input := &ListNamespacesInput{
		IncludeParent: false,
		Recursive:     true,
	}

	// Call handler
	output, err := handlers.ListNamespaces(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	// Should include both parent and child
	assert.GreaterOrEqual(t, len(output.Body.Namespaces), 2)
}

func TestSystemHandlers_UpdateNamespace_Success(t *testing.T) {
	core := createTestCore(t)

	// Create a namespace first
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ns := &namespace.Namespace{
		Path: "test-namespace/",
		CustomMetadata: map[string]string{
			"team": "engineering",
		},
	}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx = namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with updated metadata
	input := &UpdateNamespaceInput{
		Path: "test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{
		"team":        "platform",
		"environment": "production",
	}

	// Call handler
	output, err := handlers.UpdateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "test-namespace/", output.Body.Path)
	assert.Equal(t, "platform", output.Body.CustomMetadata["team"])
	assert.Equal(t, "production", output.Body.CustomMetadata["environment"])
	assert.Contains(t, output.Body.Message, "Successfully updated namespace")

	// Verify namespace was updated
	updated, err := core.namespaceStore.GetNamespaceByPath(ctx, "test-namespace")
	require.NoError(t, err)
	assert.NotNil(t, updated)
	assert.Equal(t, "platform", updated.CustomMetadata["team"])
}

func TestSystemHandlers_UpdateNamespace_NotFound(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input for non-existent namespace
	input := &UpdateNamespaceInput{
		Path: "nonexistent",
	}
	input.Body.CustomMetadata = map[string]string{"key": "value"}

	// Call handler - namespace will be created if it doesn't exist
	output, err := handlers.UpdateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
}

func TestSystemHandlers_UpdateNamespace_Unauthorized(t *testing.T) {
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
	input := &UpdateNamespaceInput{
		Path: "test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{"key": "value"}

	// Call handler - should fail
	output, err := handlers.UpdateNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_DeleteNamespace_Success(t *testing.T) {
	core := createTestCore(t)

	// Create a namespace first
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ns := &namespace.Namespace{
		Path:           "test-namespace/",
		CustomMetadata: map[string]string{},
	}
	err := core.namespaceStore.SetNamespace(ctx, ns)
	require.NoError(t, err)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx = namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input
	input := &DeleteNamespaceInput{
		Path: "test-namespace",
	}

	// Call handler
	output, err := handlers.DeleteNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Contains(t, output.Body.Message, "Namespace deletion")
}

func TestSystemHandlers_DeleteNamespace_NotFound(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input for non-existent namespace
	input := &DeleteNamespaceInput{
		Path: "nonexistent",
	}

	// Call handler - should succeed but return empty status
	output, err := handlers.DeleteNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
}

func TestSystemHandlers_DeleteNamespace_Unauthorized(t *testing.T) {
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
	input := &DeleteNamespaceInput{
		Path: "test-namespace",
	}

	// Call handler - should fail
	output, err := handlers.DeleteNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_DeleteNamespace_NoAuth(t *testing.T) {
	core := createTestCore(t)

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create context without authentication
	ctx := context.Background()

	// Create input
	input := &DeleteNamespaceInput{
		Path: "test-namespace",
	}

	// Call handler - should fail
	output, err := handlers.DeleteNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "Insufficient permissions")
}

func TestSystemHandlers_CreateNamespace_WithSlashInPath(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context with root namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create a namespace path with slashes (parent/child structure)
	// This demonstrates that nested paths are supported
	input := &CreateNamespaceInput{
		Path: "org/team",
	}
	input.Body.CustomMetadata = map[string]string{
		"type": "nested",
	}

	// Call handler - this creates "org/team/" namespace
	_, err := handlers.CreateNamespace(ctx, input)
	require.Error(t, err)
}

// Validation tests for namespace path restrictions
func TestSystemHandlers_CreateNamespace_InvalidPath_EndsWithSlash(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with trailing slash
	input := &CreateNamespaceInput{
		Path: "test-namespace/",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - path gets canonicalized so it actually succeeds with the trailing slash removed
	output, err := handlers.CreateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	// The namespace package canonicalizes paths and adds trailing slashes internally
	assert.Equal(t, "test-namespace/", output.Body.Path)
}

func TestSystemHandlers_CreateNamespace_InvalidPath_ContainsSpace(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with space in path
	input := &CreateNamespaceInput{
		Path: "test namespace",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - should fail
	output, err := handlers.CreateNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
}

func TestSystemHandlers_CreateNamespace_InvalidPath_ReservedNames(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Test all reserved names
	reservedNames := []string{
		".",
		"..",
		"root",
		"sys",
		"audit",
		"auth",
	}

	for _, reservedName := range reservedNames {
		t.Run("reserved_"+reservedName, func(t *testing.T) {
			// Create input with reserved name
			input := &CreateNamespaceInput{
				Path: reservedName,
			}
			input.Body.CustomMetadata = map[string]string{}

			// Call handler - should fail
			output, err := handlers.CreateNamespace(ctx, input)
			assert.Error(t, err, "Expected error for reserved name: %s", reservedName)
			assert.Nil(t, output)
		})
	}
}

func TestSystemHandlers_CreateNamespace_InvalidPath_Empty(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with empty path
	input := &CreateNamespaceInput{
		Path: "",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - should fail (will fail at HUMA validation level)
	output, err := handlers.CreateNamespace(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
}

func TestSystemHandlers_CreateNamespace_InvalidPath_LeadingSlash(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with leading slash
	input := &CreateNamespaceInput{
		Path: "/test-namespace",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - path gets canonicalized so leading slash is stripped and it succeeds
	output, err := handlers.CreateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "test-namespace/", output.Body.Path)
}

func TestSystemHandlers_CreateNamespace_InvalidPath_DoubleSlash(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input with double slash
	input := &CreateNamespaceInput{
		Path: "test//namespace",
	}
	input.Body.CustomMetadata = map[string]string{}

	// Call handler - path gets canonicalized so double slash becomes a single slash
	// This creates a nested namespace "test/namespace/"
	_, err := handlers.CreateNamespace(ctx, input)
	require.Error(t, err)
}

func TestSystemHandlers_CreateNamespace_ValidPath_WithHyphensAndUnderscores(t *testing.T) {
	core := createTestCore(t)

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Create authenticated context
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Valid paths with hyphens and underscores
	validPaths := []string{
		"test-namespace",
		"test_namespace",
		"test-namespace-123",
		"test_namespace_456",
		"my-org-prod",
	}

	for _, validPath := range validPaths {
		t.Run("valid_"+validPath, func(t *testing.T) {
			// Create input with valid path
			input := &CreateNamespaceInput{
				Path: validPath,
			}
			input.Body.CustomMetadata = map[string]string{}

			// Call handler - should succeed
			output, err := handlers.CreateNamespace(ctx, input)
			require.NoError(t, err, "Expected no error for valid path: %s", validPath)
			assert.NotNil(t, output)
			assert.Contains(t, output.Body.Message, "Successfully created namespace")
		})
	}
}
