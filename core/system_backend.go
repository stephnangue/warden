package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/stephnangue/warden/logger"
)

// SystemBackend implements logical.Backend and provides system management operations
type SystemBackend struct {
	core     *Core
	logger   logger.Logger
	router   *chi.Mux
	api      huma.API
	handlers *SystemHandlers
}

// SystemHandlers handles system backend operations
type SystemHandlers struct {
	core   *Core
	logger logger.Logger
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
func NewSystemBackend(core *Core, log logger.Logger) *SystemBackend {
	// Create Chi router
	router := chi.NewRouter()

	// Configure HUMA
	config := huma.DefaultConfig("Warden System API", "1.0.0")
	config.Info.Description = "System management API for performing system operations such as mounting providers and enabling auth methods"
	config.Servers = []*huma.Server{
		{URL: "http://localhost:5000/v1/sys", Description: "System API"},
	}
	config.Tags = []*huma.Tag{
		{Name: "mounts", Description: "Provider mount management"},
		{Name: "auth", Description: "Auth method management"},
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

	// Create HUMA API with Chi adapter
	api := humachi.New(router, config)
	backend.api = api

	// Register all endpoints
	backend.registerInitOperations()
	backend.registerProviderOperations()
	backend.registerAuthOperations()

	return backend
}

// registerProviderOperations registers all providers management endpoints
func (s *SystemBackend) registerProviderOperations() {
	// POST /providers/{path} - Enable provider
	huma.Register(s.api, huma.Operation{
		OperationID: "enable-provider",
		Method:      http.MethodPost,
		Path:        "/providers/{path}",
		Summary:     "Enable a provider",
		Description: "Creates a new provider at the specified path. Requires system_admin role.",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.MountProvider)

	// DELETE /providers/{path} - Disable provider
	huma.Register(s.api, huma.Operation{
		OperationID: "disable-provider",
		Method:      http.MethodDelete,
		Path:        "/providers/{path}",
		Summary:     "Disable a provider",
		Description: "Removes a provider from the specified path. Requires system_admin role.",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UnmountProvider)

	// GET /providers/{path} - Get provider info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-provider",
		Method:      http.MethodGet,
		Path:        "/providers/{path}",
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

	// PUT /providers/{path}/config - Configure a provider
	huma.Register(s.api, huma.Operation{
		OperationID: "configure-provider",
		Method:      http.MethodPut,
		Path:        "/providers/{path}/config",
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
	// POST /auth/{path} - Enable auth method
	huma.Register(s.api, huma.Operation{
		OperationID: "enable-auth",
		Method:      http.MethodPost,
		Path:        "/auth/{path}",
		Summary:     "Enable an auth method",
		Description: "Creates a new auth method at the specified path. Requires system_admin role.",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.MountAuth)

	// DELETE /auth/{path} - Disable auth method
	huma.Register(s.api, huma.Operation{
		OperationID: "disable-auth",
		Method:      http.MethodDelete,
		Path:        "/auth/{path}",
		Summary:     "Disable an auth method",
		Description: "Removes an auth method from the specified path. Requires system_admin role.",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.UnmountAuth)

	// GET /auth/{path} - Get auth method info
	huma.Register(s.api, huma.Operation{
		OperationID: "get-auth",
		Method:      http.MethodGet,
		Path:        "/auth/{path}",
		Summary:     "Get auth method information",
		Description: "Retrieves detailed information about a specific auth method",
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

	// PUT /auth/{path}/config - Configure an auth method
	huma.Register(s.api, huma.Operation{
		OperationID: "configure-auth",
		Method:      http.MethodPut,
		Path:        "/auth/{path}/config",
		Summary:     "Configure an auth method",
		Description: "Configure an existing auth method enabled on the provided path",
		Tags:        []string{"auth"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.ConfigureAuth)
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
func (s *SystemBackend) Cleanup() {
	// No cleanup needed
}

// Setup implements logical.Backend interface
func (m *SystemBackend) Setup(conf map[string]any) error {
	return  nil
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
