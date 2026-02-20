package http

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/middleware"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// handleLogical returns an HTTP handler for logical backend operations.
// It processes requests to both /v1/sys/ (system backend) and /v1/ (provider and auth backends).
//
// The handler:
//  1. Builds a logical request from the HTTP request
//  2. Sends the logical request to core.HandleRequest for processing
//  3. Writes the logical.Response back to the HTTP response
func handleLogical(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject unsupported HTTP methods
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions,
			http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete, "LIST":
			// allowed
		default:
			respondError(w, http.StatusMethodNotAllowed, "method "+r.Method+" not allowed")
			return
		}

		// Build the logical request from the HTTP request
		req := buildLogicalRequest(w, r)

		// Send the logical request to the core for processing
		resp, err := c.HandleRequest(r.Context(), req)
		if err != nil {
			statusCode := errorToStatusCode(err)
			respondError(w, statusCode, err.Error())
			return
		}

		// Write the logical response back to the HTTP response
		writeLogicalResponse(w, resp)
	})
}

// buildLogicalRequest creates a logical.Request from an HTTP request.
// It does not parse the body - that is left to the backend handlers.
func buildLogicalRequest(w http.ResponseWriter, r *http.Request) *logical.Request {
	// Determine the operation type from HTTP method
	op := operationFromHTTPMethod(r)

	// Get the path (strip /v1/ prefix)
	path := strings.TrimPrefix(r.URL.Path, "/v1/")

	// Extract client IP
	clientIP := extractClientIP(r)

	// Wrap ResponseWriter to capture status code for streaming requests.
	// This enables accurate audit logging of the real HTTP status code.
	srw := logical.NewStatusRecordingWriter(w)

	// Build the logical request
	return &logical.Request{
		Operation:      op,
		Path:           path,
		HTTPRequest:    r,
		ResponseWriter: srw,
		ClientIP:       clientIP,
		RequestID:      middleware.GetReqID(r.Context()),
	}
}

// operationFromHTTPMethod maps HTTP methods to logical operations.
func operationFromHTTPMethod(r *http.Request) logical.Operation {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// HEAD and OPTIONS are read-like operations (metadata, CORS preflight).
		// Check for HELP operation via query parameter (namespaced to avoid upstream conflicts).
		if r.URL.Query().Get("warden-help") == "1" || r.URL.Query().Get("warden-help") == "true" {
			return logical.HelpOperation
		}
		// Check for LIST operation via query parameter or header.
		if r.URL.Query().Get("warden-list") == "true" || r.Header.Get("X-Warden-Request") == "LIST" {
			return logical.ListOperation
		}
		return logical.ReadOperation
	case http.MethodPost:
		return logical.CreateOperation
	case http.MethodPut:
		return logical.UpdateOperation
	case http.MethodPatch:
		return logical.PatchOperation
	case http.MethodDelete:
		return logical.DeleteOperation
	case "LIST":
		return logical.ListOperation
	default:
		return logical.ReadOperation
	}
}

// extractClientIP extracts the client IP from the request.
// It checks X-Real-IP header first (set by reverse proxies),
// then X-Forwarded-For, then falls back to RemoteAddr.
func extractClientIP(r *http.Request) string {
	// Check X-Real-IP first (commonly set by nginx)
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP != "" {
		return clientIP
	}

	// Check X-Forwarded-For
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the list
		if idx := strings.Index(forwarded, ","); idx != -1 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}

	// Fall back to RemoteAddr
	clientIP = r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	return clientIP
}

// errorToStatusCode maps errors to appropriate HTTP status codes.
func errorToStatusCode(err error) int {
	switch {
	case errors.Is(err, sdklogical.ErrUnsupportedOperation):
		return http.StatusMethodNotAllowed
	case errors.Is(err, sdklogical.ErrUnsupportedPath):
		return http.StatusNotFound
	case errors.Is(err, sdklogical.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, sdklogical.ErrInvalidRequest):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// writeLogicalResponse writes the logical.Response to the HTTP response.
// It copies headers, status code, and body from the logical response.
func writeLogicalResponse(w http.ResponseWriter, resp *logical.Response) {
	if resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// If the response was streamed, the backend already wrote to the response writer
	if resp.Streamed {
		return
	}

	// Copy headers from the logical response
	for key, values := range resp.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Determine the body to write
	var body []byte
	if resp.Body != nil && len(resp.Body) > 0 {
		body = resp.Body
	} else if resp.Err != nil {
		// Serialize error to JSON
		w.Header().Set("Content-Type", "application/json")
		jsonBody, err := json.Marshal(map[string]any{"errors": []string{resp.Err.Error()}})
		if err == nil {
			body = jsonBody
		}
	} else if resp.Data != nil {
		// Serialize Data to JSON if Body is not set
		w.Header().Set("Content-Type", "application/json")
		jsonBody, err := json.Marshal(map[string]any{"data": resp.Data})
		if err == nil {
			body = jsonBody
		}
	}

	// Write status code
	if resp.StatusCode > 0 {
		w.WriteHeader(resp.StatusCode)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Write body
	if len(body) > 0 {
		w.Write(body)
	}
}
