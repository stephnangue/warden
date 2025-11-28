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

	// Create HUMA API with Chi adapter
	api := humachi.New(router, config)

	// Create handlers
	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	backend := &SystemBackend{
		core:     core,
		logger:   log,
		router:   router,
		api:      api,
		handlers: handlers,
	}

	// Register Phase 1 operations (provider mounts)
	backend.registerMountOperations()

	return backend
}

// registerMountOperations registers all mount management endpoints
func (s *SystemBackend) registerMountOperations() {
	// Protected operations group (requires authentication)
	s.router.Group(func(r chi.Router) {
		// Apply authentication middleware
		r.Use(s.AuthenticationMiddleware)

		// POST /mounts/{path} - Mount provider (protected)
		huma.Register(s.api, huma.Operation{
			OperationID: "mount-provider",
			Method:      http.MethodPost,
			Path:        "/mounts/{path}",
			Summary:     "Mount a provider",
			Description: "Creates a new provider mount at the specified path. Requires system_admin role.",
			Tags:        []string{"mounts"},
			Security: []map[string][]string{
				{"bearerAuth": {}},
			},
		}, s.handlers.MountProvider)

		// DELETE /mounts/{path} - Unmount provider (protected)
		huma.Register(s.api, huma.Operation{
			OperationID: "unmount-provider",
			Method:      http.MethodDelete,
			Path:        "/mounts/{path}",
			Summary:     "Unmount a provider",
			Description: "Removes a provider mount from the specified path. Requires system_admin role.",
			Tags:        []string{"mounts"},
			Security: []map[string][]string{
				{"bearerAuth": {}},
			},
		}, s.handlers.UnmountProvider)
	})

	// Public operations (no authentication required)

	// GET /mounts/{path} - Get mount info (public)
	huma.Register(s.api, huma.Operation{
		OperationID: "get-mount",
		Method:      http.MethodGet,
		Path:        "/mounts/{path}",
		Summary:     "Get mount information",
		Description: "Retrieves detailed information about a specific mount",
		Tags:        []string{"mounts"},
	}, s.handlers.GetMountInfo)

	// GET /mounts - List mounts (public)
	huma.Register(s.api, huma.Operation{
		OperationID: "list-mounts",
		Method:      http.MethodGet,
		Path:        "/mounts",
		Summary:     "List all mounts",
		Description: "Returns all mounted providers",
		Tags:        []string{"mounts"},
	}, s.handlers.ListMounts)
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
