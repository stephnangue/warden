package core

import (
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/logger"
)

// ServeHTTP makes the Core an http.Handler
func (c *Core) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ok := c.auditRequest(req)
	if !ok {
		c.logger.Warn("No audit device processed the request", logger.String("request_id", middleware.GetReqID(req.Context())))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Try pre-init handler first (handles bootstrap operations like /sys/init)
	// These operations must work even when sealed
	if c.preInitHandler != nil {
		handled, err := c.preInitHandler.TryHandle(w, req)
		if err != nil {
			c.logger.Error("pre-init handler error",
				logger.Err(err),
				logger.String("path", req.URL.Path),
				logger.String("method", req.Method),
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if handled {
			// Request was handled by pre-init handler, return early
			return
		}
	}

	// Check if the core is sealed - all non-bootstrap paths require unsealed state
	if c.Sealed() {
		http.Error(w, "Warden is sealed", http.StatusServiceUnavailable)
		return
	}

	c.router.Route(w, req)
}
