package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// ReadyResponse represents the response from the readiness endpoint.
type ReadyResponse struct {
	Ready         bool  `json:"ready"`
	Initialized   bool  `json:"initialized"`
	Sealed        bool  `json:"sealed"`
	Standby       bool  `json:"standby"`
	ServerTimeUTC int64 `json:"server_time_utc"`
}

// handleSysReady returns an HTTP handler for the /v1/sys/ready endpoint.
// Unlike /v1/sys/health which returns 429 for standby nodes, this endpoint
// returns 200 for any unsealed, initialized node (active or standby).
// This is intended for Kubernetes readiness probes and load balancers that
// should route to all unsealed nodes (since standby nodes can forward requests).
//
// Status codes:
//   - 200: initialized and unsealed (active or standby)
//   - 503: sealed or not initialized
func handleSysReady(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		initialized, err := c.Initialized(r.Context())
		if err != nil {
			log.Error("failed to check initialization status", logger.Err(err))
			respondError(w, http.StatusInternalServerError, "failed to check initialization status")
			return
		}

		sealed := c.Sealed()
		standby := c.Standby()
		ready := initialized && !sealed

		statusCode := http.StatusOK
		if !ready {
			statusCode = http.StatusServiceUnavailable
		}

		resp := &ReadyResponse{
			Ready:         ready,
			Initialized:   initialized,
			Sealed:        sealed,
			Standby:       standby,
			ServerTimeUTC: time.Now().UTC().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		if r.Method != http.MethodHead {
			json.NewEncoder(w).Encode(resp)
		}
	})
}
