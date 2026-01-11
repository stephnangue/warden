package http

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents a JSON error response
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// respondError writes an error response with the given status code and message.
func respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := &ErrorResponse{
		Errors: []string{message},
	}

	json.NewEncoder(w).Encode(resp)
}

// respondOk writes a successful JSON response with status 200.
func respondOk(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
