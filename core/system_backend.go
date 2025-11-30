package core

import (
	"net/http"

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
		api:      nil, // Will be set after middleware
		handlers: handlers,
	}

	// Apply authentication middleware to the base router
	router.Use(backend.AuthenticationMiddleware)

	// Create HUMA API with Chi adapter (after middleware is applied)
	api := humachi.New(router, config)
	backend.api = api

	backend.registerProviderOperations()

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

	// POST /providers/{path}/tune - Configure a provider
	huma.Register(s.api, huma.Operation{
		OperationID: "tune-provider",
		Method:      http.MethodPost,
		Path:        "/providers/{path}/tune",
		Summary:     "Configure a provider",
		Description: "Configure an existing provider enabled on the provided path",
		Tags:        []string{"providers"},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, s.handlers.TuneProvider)
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
