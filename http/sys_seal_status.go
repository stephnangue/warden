package http

import (
	"net/http"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// SealStatusResponse represents the response from the seal-status endpoint.
type SealStatusResponse struct {
	Sealed      bool `json:"sealed"`
	Initialized bool `json:"initialized"`
	HAEnabled   bool `json:"ha_enabled"`
}

// handleSysSealStatus returns an HTTP handler for the /v1/sys/seal-status endpoint.
func handleSysSealStatus(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		initialized, err := c.Initialized(r.Context())
		if err != nil {
			log.Error("failed to check initialization status", logger.Err(err))
			respondError(w, http.StatusInternalServerError, "failed to check initialization status")
			return
		}

		respondOk(w, &SealStatusResponse{
			Sealed:      c.Sealed(),
			Initialized: initialized,
			HAEnabled:   c.HAEnabled(),
		})
	})
}
