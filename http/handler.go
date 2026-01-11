package http

import (
	"net/http"
	"strings"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// HandlerProperties contains configuration for the HTTP handler
type HandlerProperties struct {
	Core   *core.Core
	Logger *logger.GatedLogger
}

// Handler creates and returns the main HTTP handler for Warden.
func Handler(props *HandlerProperties) http.Handler {
	mux := http.NewServeMux()
	core := props.Core
	log := props.Logger

	// System init endpoint - handles initialization before system is ready
	// This must be registered before the /v1/sys/ catch-all
	mux.Handle("/v1/sys/init", handleSysInit(core, log))

	// System backend endpoints - catch-all for /v1/sys/
	// Handles providers, auth, namespaces, credentials, etc.
	mux.Handle("/v1/sys/", handleLogical(core, log))

	// Logical backend endpoints - catch-all for /v1/
	// Handles provider-specific operations (e.g., /v1/aws/, /v1/provider/)
	mux.Handle("/v1/", handleLogical(core, log))

	// Wrap with generic handler middleware
	handler := wrapGenericHandler(core, mux, log)

	return handler
}

// wrapGenericHandler wraps the main handler with cross-cutting concerns:
// - Request logging
// - Panic recovery
// - Request ID injection
// - Cache-Control headers
func wrapGenericHandler(core *core.Core, handler http.Handler, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Validate request path
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			respondError(w, http.StatusNotFound, "path must begin with /v1/")
			return
		}

		handler.ServeHTTP(w, r)
	})
}
