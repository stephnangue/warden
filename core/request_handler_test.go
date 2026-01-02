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
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestRouting tests that requests are properly routed to the intended backend
// based on namespace resolution and path matching through the Core's ServeHTTP method.
func TestRequestRouting(t *testing.T) {
	tests := []struct {
		name            string
		setupNamespaces []testNamespace // namespaces to create before test
		setupProviders  []testMount     // provider mounts to create before test
		setupAuths      []testMount     // auth mounts to create before test
		request         []testRequest
	}{
		{
			name: "Scenario1: simple routing to sys/ and ns1/sys/ mounts",
			setupNamespaces: []testNamespace{
				{name: "ns1"},
			},
			setupProviders: []testMount{},
			setupAuths:     []testMount{},
			request: []testRequest{
				{name: "test_ns_without_header", method: http.MethodPost, path: "/v1/sys/namespaces/test", body: `{}`, statusCode: http.StatusOK},
				{name: "test_ns_already_created", method: http.MethodPost, path: "/v1/sys/namespaces/test", body: `{}`, statusCode: http.StatusOK},
				{name: "test_ns_in_ns1_with_header", method: http.MethodPost, path: "/v1/sys/namespaces/test", namespace: "ns1", body: `{}`, statusCode: http.StatusOK},
				{name: "test1_ns_without_header", method: http.MethodPost, path: "/v1/ns1/sys/namespaces/test1", body: `{}`, statusCode: http.StatusOK},
				{name: "test_ns_with_header_and_url", method: http.MethodPost, path: "/v1/ns1/sys/namespaces/test", namespace: "ns1", body: `{}`, statusCode: http.StatusNotFound},
			},
		},
		{
			name: "Scenario2: complex routing with nested namespaces",
			setupNamespaces: []testNamespace{
				{name: "ns1"},
				{name: "ns1/ns2"},
			},
			setupProviders: []testMount{},
			setupAuths:     []testMount{},
			request: []testRequest{
				{name: "test_ns_without_header_ns1/ns2", method: http.MethodPost, path: "/v1/sys/namespaces/test", namespace: "ns1/ns2", body: `{}`, statusCode: http.StatusOK},
				{name: "test1_ns_without_header_ns1_and_url_ns2", method: http.MethodPost, path: "/v1/ns2/sys/namespaces/test1", namespace: "ns1", body: `{}`, statusCode: http.StatusOK},
				{name: "test2_ns_without_header_and_url_ns1/ns2", method: http.MethodPost, path: "/v1/ns1/ns2/sys/namespaces/test2", body: `{}`, statusCode: http.StatusOK},
				{name: "test2/test3/test4_ns_without_header", method: http.MethodPost, path: "/v1/sys/namespaces/test2/test3/test4", body: `{}`, statusCode: http.StatusBadRequest},
				{name: "test2/test5_ns_without_header", method: http.MethodPost, path: "/v1/sys/namespaces/test2/test5", body: `{}`, statusCode: http.StatusBadRequest},
			},
		},
		{
			name: "Scenario3: routing to auth and provider backend ",
			setupNamespaces: []testNamespace{
				{name: "ns1"},
			},
			setupProviders: []testMount{
				{path: "aws", namespace: "ns1", backendType: "testprovider"},
			},
			setupAuths: []testMount{
				{path: "jwt", namespace: "ns1", backendType: "testauth"},
			},
			request: []testRequest{
				{name: "aws_gwt_without_slash_ns1_in_header", method: http.MethodPost, path: "/v1/aws/gateway", namespace: "ns1", statusCode: http.StatusOK},
				{name: "aws_gwt_without_slash_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/aws/gateway", statusCode: http.StatusOK},
				{name: "aws_gwt_with_slash_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/aws/gateway/", statusCode: http.StatusOK},
				{name: "aws_gwt_full_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/aws/gateway/action-test/?path=logic", statusCode: http.StatusOK},
				{name: "aws_prf_without_slash_ns1_in_header", method: http.MethodPost, path: "/v1/aws/profile", namespace: "ns1", statusCode: http.StatusOK},
				{name: "aws_prf_without_slash_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/aws/profile", statusCode: http.StatusOK},
				{name: "aws_prf_with_slash_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/aws/profile/", statusCode: http.StatusOK},
				{name: "aws_prf_full_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/aws/profile/action-test/?path=logic", statusCode: http.StatusNotFound},
				{name: "jwt_login_without_slash_ns1_in_header", method: http.MethodPost, path: "/v1/auth/jwt/test", namespace: "ns1", statusCode: http.StatusNotFound},
				{name: "jwt_login_without_slash_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/auth/jwt/login", statusCode: http.StatusOK},
				{name: "jwt_login_with_slash_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/auth/jwt/login/", statusCode: http.StatusOK},
				{name: "jwt_login_full_ns1_in_path", method: http.MethodGet, path: "/v1/ns1/auth/jwt/login/action-test/?path=logic", statusCode: http.StatusNotFound},
			},
		},
		{
			name: "Scenario4: complex routing of mounts with mutiple segment-path in nested namespaces",
			setupNamespaces: []testNamespace{
				{name: "ns1"},
				{name: "ns1/ns2"},
			},
			setupProviders: []testMount{
				{path: "aws/north", namespace: "", backendType: "testprovider"},
				{path: "aws/north/prod", namespace: "ns1", backendType: "testprovider"},
				{path: "aws/south/uat", namespace: "ns1/ns2", backendType: "testprovider"},
			},
			setupAuths: []testMount{
				{path: "jwt/north", namespace: "", backendType: "testauth"},
				{path: "jwt/north/nprod", namespace: "ns1", backendType: "testauth"},
				{path: "jwt/north/test", namespace: "ns1/ns2", backendType: "testauth"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core := createTestCore(t)

			// Setup namespaces
			for _, nsName := range tt.setupNamespaces {
				setupTestNamespace(t, core, nsName)
			}

			// Setup provider mounts
			for _, mount := range tt.setupProviders {
				setupTestProvider(t, core, mount)
			}

			// Setup auth mounts
			for _, mount := range tt.setupAuths {
				setupTestAuth(t, core, mount)
			}

			// Setup authentication for test requests
			core.accessControl.AssignRole("test-user", "system_admin")

			// Generate a test token for authentication
			ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
			testToken, err := core.tokenStore.GenerateToken(ctx, "warden_token", &logical.AuthData{
				PrincipalID: "test-user",
				RoleName:    "system_admin",
			})
			require.NoError(t, err)
			require.NotNil(t, testToken)

			// Execute each request in the test scenario
			for _, testReq := range tt.request {
				t.Run(testReq.name, func(t *testing.T) {
					// Create test request with body if provided
					var req *http.Request
					if testReq.body != "" {
						req = httptest.NewRequest(testReq.method, testReq.path, strings.NewReader(testReq.body))
						req.Header.Set("Content-Type", "application/json")
					} else {
						req = httptest.NewRequest(testReq.method, testReq.path, nil)
					}

					// Add namespace header if specified
					if testReq.namespace != "" {
						req.Header.Set("X-Warden-Namespace", testReq.namespace)
					}

					// Add authentication token to the request
					req.Header.Set("Authorization", "Bearer "+testToken.Data["token"])

					w := httptest.NewRecorder()

					// Execute through Core.ServeHTTP (full integration test)
					core.ServeHTTP(w, req)

					// Verify the response status
					assert.Equal(t, testReq.statusCode, w.Code,
						"Expected status %d but got %d. Path: %s, Namespace: %s, Response: %s",
						testReq.statusCode, w.Code, testReq.path, testReq.namespace, w.Body.String())
				})
			}
		})
	}
}

// Helper types and functions

// setupTestNamespace creates a namespace in the core
func setupTestNamespace(t *testing.T, core *Core, ns testNamespace) {

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

	// Create input with full path
	input := &CreateNamespaceInput{
		Path: ns.name,
	}

	// Call handler
	output, err := handlers.CreateNamespace(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.ID)

	// Expected path should have trailing slash
	expectedPath := ns.name + "/"
	assert.Equal(t, expectedPath, output.Body.Path)
	assert.Contains(t, output.Body.Message, "Successfully created namespace")

	// Verify namespace was created
	nsa, err := core.namespaceStore.GetNamespaceByPath(ctx, ns.name)
	require.NoError(t, err)
	assert.NotNil(t, nsa)
	assert.Equal(t, expectedPath, nsa.Path)
}

type testRequest struct {
	name       string
	method     string
	path       string
	namespace  string
	body       string // JSON body for the request
	statusCode int
}

type testNamespace struct {
	name string
}

// testMount represents a mount configuration for testing
type testMount struct {
	path        string
	backendType string
	namespace   string
}

// setupTestMount mounts a backend in the specified namespace
func setupTestProvider(t *testing.T, core *Core, mount testMount) {
	// Register mock provider factory
	core.providers["testprovider"] = &mockProviderFactory{}

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Get the target namespace for the mount
	var targetNs *namespace.Namespace
	if mount.namespace == "" {
		targetNs = namespace.RootNamespace
	} else {
		var err error
		targetNs, err = core.namespaceStore.GetNamespaceByPath(
			namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace),
			mount.namespace,
		)
		require.NoError(t, err)
	}

	// Create authenticated context with the target namespace
	ctx := namespace.ContextWithNamespace(context.Background(), targetNs)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input without WardenNamespace header - namespace comes from context
	input := &MountProviderInput{
		Path: mount.path,
	}
	input.Body.Type = mount.backendType
	input.Body.Description = "Test provider mount"
	input.Body.Config = map[string]any{"key": "value"}

	// Call handler directly
	output, err := handlers.MountProvider(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, mount.path+"/", output.Body.Path)
	assert.NotEmpty(t, output.Body.Accessor)
	assert.Contains(t, output.Body.Message, "Successfully mounted")

	nsCtx := namespace.ContextWithNamespace(context.Background(), targetNs)

	// Verify mount was created (use namespace context)
	found, err := core.mounts.findByPath(nsCtx, mount.path+"/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, mount.path+"/", found.Path)
	assert.Equal(t, "Test provider mount", found.Description)

	// Verify mount was mounted on the router
	// Try with trailing slash since mounts are stored with trailing slashes
	matchedMount := core.router.MatchingMount(nsCtx, mount.path+"/")
	require.NotEmpty(t, matchedMount, "mount should be registered on router")

	// Build expected path based on namespace
	expectedMount := mount.path + "/"
	if mount.namespace != "" {
		expectedMount = mount.namespace + "/" + mount.path + "/"
	}
	assert.Equal(t, expectedMount, matchedMount)
}

// setupTestAuth mounts an auth backend in the specified namespace
func setupTestAuth(t *testing.T, core *Core, mount testMount) {
	// Register mock auth factory
	core.authMethods["testauth"] = &mockAuthFactory{}

	// Setup authorization
	core.accessControl.AssignRole("admin-user", "system_admin")

	// Create handlers directly
	handlers := &SystemHandlers{
		core:   core,
		logger: core.logger,
	}

	// Get the target namespace for the mount
	var targetNs *namespace.Namespace
	if mount.namespace == "" {
		targetNs = namespace.RootNamespace
	} else {
		var err error
		targetNs, err = core.namespaceStore.GetNamespaceByPath(
			namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace),
			mount.namespace,
		)
		require.NoError(t, err)
	}

	// Create authenticated context with the target namespace
	ctx := namespace.ContextWithNamespace(context.Background(), targetNs)
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	// Create input without WardenNamespace header - namespace comes from context
	input := &MountAuthInput{
		Path: mount.path,
	}
	input.Body.Type = mount.backendType
	input.Body.Description = "Test auth mount"
	input.Body.Config = map[string]any{"key": "value"}

	// Call handler directly
	output, err := handlers.MountAuth(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, mount.path+"/", output.Body.Path)
	assert.NotEmpty(t, output.Body.Accessor)
	assert.Contains(t, output.Body.Message, "Successfully mounted")

	nsCtx := namespace.ContextWithNamespace(context.Background(), targetNs)

	// Verify mount was created (use namespace context)
	found, err := core.mounts.findByPath(nsCtx, mount.path+"/")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, mount.path+"/", found.Path)
	assert.Equal(t, mountClassAuth, found.Class)
	assert.Equal(t, "Test auth mount", found.Description)

	// Verify mount was mounted on the router (auth mounts are prefixed with "auth/")
	matchedMount := core.router.MatchingMount(nsCtx, authRoutePrefix+mount.path+"/")
	require.NotEmpty(t, matchedMount, "auth mount should be registered on router")

	// Build expected path based on namespace
	expectedMount := authRoutePrefix + mount.path + "/"
	if mount.namespace != "" {
		expectedMount = mount.namespace + "/" + authRoutePrefix + mount.path + "/"
	}
	assert.Equal(t, expectedMount, matchedMount)
}
