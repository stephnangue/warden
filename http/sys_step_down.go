package http

import (
	"errors"
	"net/http"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// handleSysStepDown returns an HTTP handler for the /v1/sys/step-down endpoint.
// It causes the active node to step down from leadership.
func handleSysStepDown(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if err := c.StepDown(r); err != nil {
			if errors.Is(err, core.ErrHANotEnabled) {
				respondError(w, http.StatusBadRequest, "HA not enabled")
				return
			}
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
