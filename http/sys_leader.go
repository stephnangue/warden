package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// LeaderResponse represents the response from the leader endpoint.
type LeaderResponse struct {
	HAEnabled     bool   `json:"ha_enabled"`
	IsSelf        bool   `json:"is_self"`
	LeaderAddress string `json:"leader_address"`
	ActiveTime    string `json:"active_time,omitempty"`
}

// handleSysLeader returns an HTTP handler for the /v1/sys/leader endpoint.
func handleSysLeader(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		isLeader, leaderAddr, _, err := c.Leader()
		if err != nil {
			if errors.Is(err, core.ErrHANotEnabled) {
				respondOk(w, &LeaderResponse{HAEnabled: false})
				return
			}
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		resp := &LeaderResponse{
			HAEnabled:     true,
			IsSelf:        isLeader,
			LeaderAddress: leaderAddr,
		}

		if isLeader {
			resp.ActiveTime = c.ActiveTime().Format(time.RFC3339)
		}

		respondOk(w, resp)
	})
}
