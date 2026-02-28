package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// HealthResponse represents the response from the health endpoint.
type HealthResponse struct {
	Initialized   bool  `json:"initialized"`
	Sealed        bool  `json:"sealed"`
	Standby       bool  `json:"standby"`
	ServerTimeUTC int64 `json:"server_time_utc"`
}

// handleSysHealth returns an HTTP handler for the /v1/sys/health endpoint.
// Status codes follow Vault/OpenBao convention:
//   - 200: initialized, unsealed, active
//   - 429: standby node (unsealed but not active)
//   - 501: not initialized
//   - 503: sealed
func handleSysHealth(c *core.Core, log *logger.GatedLogger) http.Handler {
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

		// Determine status code
		statusCode := http.StatusOK
		switch {
		case !initialized:
			statusCode = http.StatusNotImplemented // 501
		case sealed:
			statusCode = http.StatusServiceUnavailable // 503
		case standby:
			statusCode = http.StatusTooManyRequests // 429
		}

		// Support custom status codes via query parameters
		if sc := parseHealthStatusOverrides(r, initialized, sealed, standby); sc != 0 {
			statusCode = sc
		}

		resp := &HealthResponse{
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

// parseHealthStatusOverrides checks query parameters for status code overrides.
// This is useful for load balancers that need specific codes for routing.
func parseHealthStatusOverrides(r *http.Request, initialized, sealed, standby bool) int {
	q := r.URL.Query()

	// ?standbyok makes standby nodes return 200
	if standby && q.Get("standbyok") == "true" {
		return http.StatusOK
	}

	if v := q.Get("standbycode"); v != "" && standby {
		if code, err := strconv.Atoi(v); err == nil && code >= 100 && code < 600 {
			return code
		}
	}
	if v := q.Get("sealedcode"); v != "" && sealed {
		if code, err := strconv.Atoi(v); err == nil && code >= 100 && code < 600 {
			return code
		}
	}
	if v := q.Get("uninitcode"); v != "" && !initialized {
		if code, err := strconv.Atoi(v); err == nil && code >= 100 && code < 600 {
			return code
		}
	}

	return 0
}
