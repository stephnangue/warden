package core

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/stephnangue/warden/logger"
)

// PreInitHandler handles HTTP requests for bootstrap operations that must work
// before the system backend is mounted and while the core is sealed.
//
// This handler intercepts requests at the Core.ServeHTTP level, before routing
// occurs, allowing initialization and other bootstrap operations to proceed even
// when the system backend is not yet available.
//
// Currently handled endpoints:
//   - POST /sys/init - Initialize Warden with Shamir secret sharing
//
// Future endpoints that should be added here:
//   - GET /sys/init - Check init state
//   - GET /sys/seal-status - Check seal state
//   - GET /sys/health - Health check
//   - PUT /sys/seal - Manually seal Warden
//   - PUT /sys/unseal - Unseal with Shamir shares
type PreInitHandler struct {
	core    *Core
	logger  *logger.GatedLogger
	router  *chi.Mux      // Chi router for routing
	api     huma.API      // HUMA API for automatic JSON handling
	handler *SystemHandlers
}

// NewPreInitHandler creates a new pre-init handler with HUMA/Chi integration.
//
// The handler creates its own Chi router and HUMA API instance, separate from
// the system backend, to handle bootstrap operations independently.
func NewPreInitHandler(c *Core, log *logger.GatedLogger) *PreInitHandler {
	// Create Chi router
	router := chi.NewRouter()

	// Configure HUMA for pre-init operations
	config := huma.DefaultConfig("Warden Pre-Init API", "1.0.0")
	config.Info.Description = "Bootstrap operations that work before system initialization"
	config.Servers = []*huma.Server{
		{URL: "http://localhost:5000/v1/sys", Description: "Pre-Init API"},
	}
	config.Tags = []*huma.Tag{
		{Name: "bootstrap", Description: "Bootstrap operations before full initialization"},
	}

	// Create handler instance (reuses SystemHandlers.Init logic)
	handler := &SystemHandlers{
		core:   c,
		logger: log,
	}

	h := &PreInitHandler{
		core:    c,
		logger:  log,
		router:  router,
		handler: handler,
	}

	// Create HUMA API with Chi adapter
	api := humachi.New(router, config)
	h.api = api

	// Register init endpoint
	huma.Register(api, huma.Operation{
		OperationID: "pre-init",
		Method:      http.MethodPost,
		Path:        "/init",
		Summary:     "Initialize Warden (Pre-Init)",
		Description: "Initializes Warden before system backend is mounted. " +
			"This endpoint generates root token and unseal keys using Shamir secret sharing.",
		Tags: []string{"bootstrap"},
	}, handler.Init)

	log.Debug("pre-init handler created and registered")

	return h
}

// TryHandle attempts to handle pre-init requests.
//
// It checks if the incoming request is for a bootstrap endpoint (currently
// only /sys/init) and handles it directly using HUMA/Chi. For all other
// requests, it returns false to indicate that normal routing should proceed.
//
// Returns:
//   - handled: true if the request was handled by this handler, false otherwise
//   - error: any error that occurred during handling (currently always nil)
func (h *PreInitHandler) TryHandle(w http.ResponseWriter, r *http.Request) (bool, error) {
	// Normalize path (handle both /v1/sys/init and /sys/init)
	path := strings.TrimPrefix(r.URL.Path, "/v1")

	// Only handle paths starting with /sys/
	if !strings.HasPrefix(path, "/sys/") {
		return false, nil  // Not our responsibility
	}

	// Remove /sys/ prefix for routing within our Chi router
	// e.g., /sys/init -> /init
	relativePath := strings.TrimPrefix(path, "/sys")

	// Check if this is an init request
	if relativePath != "/init" || r.Method != http.MethodPost {
		return false, nil  // Not handled by pre-init
	}

	h.logger.Debug("pre-init handler intercepting /sys/init request",
		logger.String("original_path", r.URL.Path),
		logger.String("method", r.Method),
	)

	// Update request URL for Chi routing
	originalPath := r.URL.Path
	r.URL.Path = relativePath

	// Route through HUMA/Chi (handles JSON automatically)
	h.router.ServeHTTP(w, r)

	// Restore original path
	r.URL.Path = originalPath

	return true, nil  // Request was handled
}
