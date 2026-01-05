package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humamux"
	"github.com/gorilla/mux"
	"github.com/stephnangue/warden/logger"
)

// SystemBackend implements logical.Backend and provides system management operations
type SystemBackend struct {
	core     *Core
	logger   *logger.GatedLogger
	router   *mux.Router
	api      huma.API
	handlers *SystemHandlers
}

// SystemHandlers handles system backend operations
type SystemHandlers struct {
	core   *Core
	logger *logger.GatedLogger
}

// checkSystemAdmin verifies the authenticated principal has system_admin role
func (h *SystemHandlers) checkSystemAdmin(ctx context.Context) error {
	principalID, ok := ctx.Value(SystemPrincipalIDKey).(string)
	if !ok || principalID == "" {
		return fmt.Errorf("principal not found in context")
	}

	if !h.core.accessControl.IsAllowed(principalID, "system_admin") {
		h.logger.Warn("authorization failed: insufficient permissions",
			logger.String("principal_id", principalID),
			logger.String("required_role", "system_admin"))
		return fmt.Errorf("insufficient permissions: system_admin role required")
	}

	return nil
}

// NewSystemBackend creates a new system backend with HUMA integration
func NewSystemBackend(core *Core, log *logger.GatedLogger) *SystemBackend {
	// Create Gorilla Mux router
	router := mux.NewRouter()

	// Configure HUMA
	config := huma.DefaultConfig("Warden System API", "1.0.0")
	config.Info.Description = "System management API for performing system operations such as mounting providers and enabling auth methods"
	config.Servers = []*huma.Server{
		{URL: "http://localhost:5000/v1/sys", Description: "System API"},
	}
	config.Tags = []*huma.Tag{
		{Name: "mounts", Description: "Provider mount management"},
		{Name: "auth", Description: "Auth method management"},
		{Name: "namespaces", Description: "Namespace management"},
		{Name: "credentials", Description: "Credential management"},
	}

	// Add security scheme for Bearer token authentication
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "WARDEN_TOKEN",
			Description:  "Bearer token authentication using Warden tokens",
		},
	}

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	backend := &SystemBackend{
		core:     core,
		logger:   log,
		router:   router,
		api:      nil,
		handlers: handlers,
	}

	// Apply authentication middleware (with exemptions for bootstrap endpoints)
	router.Use(backend.AuthenticationMiddleware)

	// Create HUMA API with Gorilla Mux adapter
	api := humamux.New(router, config)
	backend.api = api

	// Register all endpoints
	backend.registerInitOperations()
	backend.registerProviderOperations()
	backend.registerAuthOperations()
	backend.registerNamespaceOperations()
	backend.registerCredentialOperations()

	return backend
}

// registerProviderOperations registers all providers management endpoints
func (s *SystemBackend) registerProviderOperations() {
	// POST /providers/{path...} - Enable provider
	huma.Register(s.api, huma.Operation{
		OperationID: "enable-provider",
		Method:      http.MethodPost,
		Path:        "/providers/{path:.+}",
		Summary:     "Enable a provider",
		Description: "Creates a new provider at the specified path. Requires system_admin role.",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.MountProvider)

	// DELETE /providers/{path...} - Disable provider
	huma.Register(s.api, huma.Operation{
		OperationID: "disable-provider",
		Method:      http.MethodDelete,
		Path:        "/providers/{path:.+}",
		Summary:     "Disable a provider",
		Description: "Removes a provider from the specified path. Requires system_admin role.",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UnmountProvider)

	// GET /providers/{path...} - Get provider info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-provider",
		Method:      http.MethodGet,
		Path:        "/providers/{path:.+}",
		Summary:     "Get provider information",
		Description: "Retrieves detailed information about a specific provider",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.GetMountInfo)

	// GET /providers - List providers
	huma.Register(s.api, huma.Operation{
		OperationID: "list-providers",
		Method:      http.MethodGet,
		Path:        "/providers",
		Summary:     "List all providers",
		Description: "Returns all enabled providers",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ListMounts)

	// PUT /providers/{path...}/config - Configure a provider
	huma.Register(s.api, huma.Operation{
		OperationID: "configure-provider",
		Method:      http.MethodPut,
		Path:        "/providers/{path:.+}/config",
		Summary:     "Configure a provider",
		Description: "Configure an existing provider enabled on the provided path",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ConfigureProvider)
}

// registerAuthOperations registers all auth method management endpoints
func (s *SystemBackend) registerAuthOperations() {
	// POST /auth/{path...} - Enable auth method
	huma.Register(s.api, huma.Operation{
		OperationID: "enable-auth",
		Method:      http.MethodPost,
		Path:        "/auth/{path:.+}",
		Summary:     "Enable an auth method",
		Description: "Creates a new auth method at the specified path. Supports nested paths. Requires system_admin role.",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.MountAuth)

	// DELETE /auth/{path...} - Disable auth method
	huma.Register(s.api, huma.Operation{
		OperationID: "disable-auth",
		Method:      http.MethodDelete,
		Path:        "/auth/{path:.+}",
		Summary:     "Disable an auth method",
		Description: "Removes an auth method from the specified path. Supports nested paths. Requires system_admin role.",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UnmountAuth)

	// GET /auth/{path...} - Get auth method info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-auth",
		Method:      http.MethodGet,
		Path:        "/auth/{path:.+}",
		Summary:     "Get auth method information",
		Description: "Retrieves detailed information about a specific auth method. Supports nested paths.",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.GetAuthInfo)

	// GET /auth - List auth methods
	huma.Register(s.api, huma.Operation{
		OperationID: "list-auth",
		Method:      http.MethodGet,
		Path:        "/auth",
		Summary:     "List all auth methods",
		Description: "Returns all enabled auth methods",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ListAuths)

	// PUT /auth/{path...}/config - Configure an auth method
	huma.Register(s.api, huma.Operation{
		OperationID: "configure-auth",
		Method:      http.MethodPut,
		Path:        "/auth/{path:.+}/config",
		Summary:     "Configure an auth method",
		Description: "Configure an existing auth method enabled on the provided path. Supports nested paths.",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ConfigureAuth)
}

// registerNamespaceOperations registers all namespace management endpoints
func (s *SystemBackend) registerNamespaceOperations() {
	// POST /namespaces/{path:.+} - Create namespace
	// {path:.+} is Gorilla Mux regex syntax - matches one or more chars including slashes
	huma.Register(s.api, huma.Operation{
		OperationID: "create-namespace",
		Method:      http.MethodPost,
		Path:        "/namespaces/{path:.+}",
		Summary:     "Create a namespace",
		Description: "Creates a new namespace at the specified path. Requires system_admin role.",
		Tags:        []string{"namespaces"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.CreateNamespace)

	// GET /namespaces/{path:.+} - Get namespace info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-namespace",
		Method:      http.MethodGet,
		Path:        "/namespaces/{path:.+}",
		Summary:     "Get namespace information",
		Description: "Retrieves detailed information about a specific namespace",
		Tags:        []string{"namespaces"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.GetNamespace)

	// GET /namespaces - List namespaces
	huma.Register(s.api, huma.Operation{
		OperationID: "list-namespaces",
		Method:      http.MethodGet,
		Path:        "/namespaces",
		Summary:     "List all namespaces",
		Description: "Returns all namespaces. Use query parameters to filter results.",
		Tags:        []string{"namespaces"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ListNamespaces)

	// PUT /namespaces/{path:.+} - Update namespace
	huma.Register(s.api, huma.Operation{
		OperationID: "update-namespace",
		Method:      http.MethodPut,
		Path:        "/namespaces/{path:.+}",
		Summary:     "Update a namespace",
		Description: "Updates metadata for an existing namespace. Requires system_admin role.",
		Tags:        []string{"namespaces"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UpdateNamespace)

	// DELETE /namespaces/{path:.+} - Delete namespace
	huma.Register(s.api, huma.Operation{
		OperationID: "delete-namespace",
		Method:      http.MethodDelete,
		Path:        "/namespaces/{path:.+}",
		Summary:     "Delete a namespace",
		Description: "Removes a namespace. The namespace must not contain child namespaces. Requires system_admin role.",
		Tags:        []string{"namespaces"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.DeleteNamespace)
}

// registerCredentialOperations registers all credential management endpoints
func (s *SystemBackend) registerCredentialOperations() {
	// Credential Sources

	// POST /credential/sources/{name} - Create credential source
	huma.Register(s.api, huma.Operation{
		OperationID: "create-credential-source",
		Method:      http.MethodPost,
		Path:        "/credential/sources/{name}",
		Summary:     "Create a credential source",
		Description: "Creates a new credential source at the specified name. Requires system_admin role.",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.CreateCredentialSource)

	// GET /credential/sources/{name} - Get credential source info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-credential-source",
		Method:      http.MethodGet,
		Path:        "/credential/sources/{name}",
		Summary:     "Get credential source information",
		Description: "Retrieves detailed information about a specific credential source",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.GetCredentialSource)

	// GET /credential/sources - List credential sources
	huma.Register(s.api, huma.Operation{
		OperationID: "list-credential-sources",
		Method:      http.MethodGet,
		Path:        "/credential/sources",
		Summary:     "List all credential sources",
		Description: "Returns all credential sources in the current namespace",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ListCredentialSources)

	// PUT /credential/sources/{name} - Update credential source
	huma.Register(s.api, huma.Operation{
		OperationID: "update-credential-source",
		Method:      http.MethodPut,
		Path:        "/credential/sources/{name}",
		Summary:     "Update a credential source",
		Description: "Updates an existing credential source. Requires system_admin role.",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UpdateCredentialSource)

	// DELETE /credential/sources/{name} - Delete credential source
	huma.Register(s.api, huma.Operation{
		OperationID: "delete-credential-source",
		Method:      http.MethodDelete,
		Path:        "/credential/sources/{name}",
		Summary:     "Delete a credential source",
		Description: "Removes a credential source. Cannot delete if still referenced by specs. Requires system_admin role.",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.DeleteCredentialSource)

	// Credential Specs

	// POST /credential/specs/{name} - Create credential spec
	huma.Register(s.api, huma.Operation{
		OperationID: "create-credential-spec",
		Method:      http.MethodPost,
		Path:        "/credential/specs/{name}",
		Summary:     "Create a credential spec",
		Description: "Creates a new credential specification at the specified name. Requires system_admin role.",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.CreateCredentialSpec)

	// GET /credential/specs/{name} - Get credential spec info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-credential-spec",
		Method:      http.MethodGet,
		Path:        "/credential/specs/{name}",
		Summary:     "Get credential spec information",
		Description: "Retrieves detailed information about a specific credential specification",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.GetCredentialSpec)

	// GET /credential/specs - List credential specs
	huma.Register(s.api, huma.Operation{
		OperationID: "list-credential-specs",
		Method:      http.MethodGet,
		Path:        "/credential/specs",
		Summary:     "List all credential specs",
		Description: "Returns all credential specifications in the current namespace",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ListCredentialSpecs)

	// PUT /credential/specs/{name} - Update credential spec
	huma.Register(s.api, huma.Operation{
		OperationID: "update-credential-spec",
		Method:      http.MethodPut,
		Path:        "/credential/specs/{name}",
		Summary:     "Update a credential spec",
		Description: "Updates an existing credential specification. Requires system_admin role.",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UpdateCredentialSpec)

	// DELETE /credential/specs/{name} - Delete credential spec
	huma.Register(s.api, huma.Operation{
		OperationID: "delete-credential-spec",
		Method:      http.MethodDelete,
		Path:        "/credential/specs/{name}",
		Summary:     "Delete a credential spec",
		Description: "Removes a credential specification. Requires system_admin role.",
		Tags:        []string{"credentials"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.DeleteCredentialSpec)
}

// HandleRequest implements logical.Backend interface
func (s *SystemBackend) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	s.router.ServeHTTP(w, r)
	return nil
}

// GetType implements logical.Backend interface
func (s *SystemBackend) GetType() string {
	return "system"
}

// GetClass implements logical.Backend interface
func (s *SystemBackend) GetClass() string {
	return mountClassSystem
}

// GetDescription implements logical.Backend interface
func (s *SystemBackend) GetDescription() string {
	return "System backend use to interact with the core of the system"
}

// GetAccessor implements logical.Backend interface
func (s *SystemBackend) GetAccessor() string {
	return "system"
}

// Cleanup implements logical.Backend interface
func (s *SystemBackend) Cleanup(ctx context.Context) {
	// No cleanup needed
}

// Setup implements logical.Backend interface
func (m *SystemBackend) Setup(ctx context.Context, conf map[string]any) error {
	return nil
}

func (m *SystemBackend) Initialize(ctx context.Context) error {
	return nil
}

// Config implements logical.Backend interface
func (s *SystemBackend) Config() map[string]any {
	// System backend has no configurable settings
	return map[string]any{}
}

// ValidateMountPath performs custom validation for mount paths
func ValidateMountPath(path string) error {
	// Strip trailing slash for validation (paths typically end with /)
	path = strings.TrimSuffix(path, "/")

	// Validate path doesn't contain reserved patterns
	reservedPaths := []string{"sys", "auth", "audit"}
	for _, reserved := range reservedPaths {
		if strings.HasPrefix(path, reserved) {
			return fmt.Errorf("path cannot start with reserved prefix: %s", reserved)
		}
	}

	// Ensure path doesn't start with special characters
	if strings.HasPrefix(path, "-") || strings.HasPrefix(path, "_") {
		return fmt.Errorf("path cannot start with hyphen or underscore")
	}

	return nil
}

// registerInitOperations registers the init endpoint
func (s *SystemBackend) registerInitOperations() {
	// POST /init - Initialize Warden and generate root token
	huma.Register(s.api, huma.Operation{
		OperationID: "init",
		Method:      http.MethodPost,
		Path:        "/init",
		Summary:     "Initialize Warden",
		Description: "Generates a root token for system administration. The root token has permanent system_admin privileges and is stored in-memory only.",
		Tags:        []string{"init"},
	}, s.handlers.Init)

	// POST /revoke-root-token - Revoke root token
	huma.Register(s.api, huma.Operation{
		OperationID: "revoke-root-token",
		Method:      http.MethodPost,
		Path:        "/revoke-root-token",
		Summary:     "Revoke root token",
		Description: "Revokes the current root token. Only callable by root principal. Requires Bearer token authentication.",
		Tags:        []string{"init"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.RevokeRootToken)
}
