package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// HealthResponse represents the response from the health endpoint.
//
// Fields beyond {initialized, sealed, standby, server_time} are populated
// when the corresponding feature is available: ha_enabled/is_leader/
// leader_address/active_time come from the HA backend, version from the
// build-time version passed in via HandlerProperties.
type HealthResponse struct {
	Initialized   bool   `json:"initialized"`
	Sealed        bool   `json:"sealed"`
	Standby       bool   `json:"standby"`
	HAEnabled     bool   `json:"ha_enabled"`
	IsLeader      bool   `json:"is_leader"`
	LeaderAddress string `json:"leader_address,omitempty"`
	ActiveTime    string `json:"active_time,omitempty"`
	Version       string `json:"version,omitempty"`
	ServerTime    string `json:"server_time"`
}

// handleSysHealth returns an HTTP handler for the /v1/sys/health endpoint.
// Status codes follow Vault/OpenBao convention:
//   - 200: initialized, unsealed, active
//   - 429: standby node (unsealed but not active)
//   - 501: not initialized
//   - 503: sealed
func handleSysHealth(c *core.Core, log *logger.GatedLogger, version string) http.Handler {
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
			Initialized: initialized,
			Sealed:      sealed,
			Standby:     standby,
			HAEnabled:   c.HAEnabled(),
			Version:     version,
			ServerTime:  time.Now().UTC().Format(time.RFC3339),
		}

		// Leader lookup is only meaningful when HA is configured AND the node
		// is unsealed. A sealed node's c.Leader() returns consts.ErrSealed,
		// which we don't want to log on every k8s probe.
		if resp.HAEnabled && !sealed {
			isLeader, leaderAddr, _, err := c.Leader()
			if err != nil && !errors.Is(err, core.ErrHANotEnabled) {
				log.Warn("failed to read HA leader state for /sys/health", logger.Err(err))
			} else if err == nil {
				resp.IsLeader = isLeader
				resp.LeaderAddress = leaderAddr
				if isLeader {
					resp.ActiveTime = c.ActiveTime().Format(time.RFC3339)
				}
			}
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
//
// Overrides are applied in severity order: uninitialized > sealed > standby.
// A more severe condition wins over a less severe override — in particular
// ?standbyok=true does NOT return 200 for a sealed or uninitialized node,
// because a sealed node naturally has standby=true (it can never acquire
// the HA lock), and Kubernetes readiness probes relying on ?standbyok=true
// would otherwise route traffic to pods that cannot serve.
//
// A return of 0 means "no override applies" — the caller should use the
// base status code computed by the switch in handleSysHealth.
func parseHealthStatusOverrides(r *http.Request, initialized, sealed, standby bool) int {
	q := r.URL.Query()

	if !initialized {
		return parseCustomCode(q.Get("uninitcode"))
	}
	if sealed {
		return parseCustomCode(q.Get("sealedcode"))
	}
	if standby {
		if q.Get("standbyok") == "true" {
			return http.StatusOK
		}
		return parseCustomCode(q.Get("standbycode"))
	}
	return 0
}

// parseCustomCode parses a query-parameter value as an HTTP status code,
// returning 0 (no override) for empty, unparseable, or out-of-range values.
func parseCustomCode(v string) int {
	if v == "" {
		return 0
	}
	code, err := strconv.Atoi(v)
	if err != nil || code < 100 || code >= 600 {
		return 0
	}
	return code
}
