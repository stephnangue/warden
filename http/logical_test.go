// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
	"encoding/json"
	"errors"
	"fmt"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// operationFromHTTPMethod Tests
// =============================================================================

func TestOperationFromHTTPMethod_GET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.ReadOperation, op)
}

func TestOperationFromHTTPMethod_GET_WithListQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?warden-list=true", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.ListOperation, op)
}

func TestOperationFromHTTPMethod_GET_WithListHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data", nil)
	req.Header.Set("X-Warden-Request", "LIST")
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.ListOperation, op)
}

func TestOperationFromHTTPMethod_GET_WithListQueryFalse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?warden-list=false", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.ReadOperation, op)
}

func TestOperationFromHTTPMethod_POST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.CreateOperation, op)
}

func TestOperationFromHTTPMethod_PUT(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.UpdateOperation, op)
}

func TestOperationFromHTTPMethod_PATCH(t *testing.T) {
	req := httptest.NewRequest(http.MethodPatch, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.PatchOperation, op)
}

func TestOperationFromHTTPMethod_DELETE(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.DeleteOperation, op)
}

func TestOperationFromHTTPMethod_LIST(t *testing.T) {
	req := httptest.NewRequest("LIST", "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	assert.Equal(t, logical.ListOperation, op)
}

func TestOperationFromHTTPMethod_UnknownMethod(t *testing.T) {
	req := httptest.NewRequest("UNKNOWN", "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	// Unknown methods default to ReadOperation
	assert.Equal(t, logical.ReadOperation, op)
}

func TestOperationFromHTTPMethod_HEAD(t *testing.T) {
	req := httptest.NewRequest(http.MethodHead, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	// HEAD maps to ReadOperation (read-like, same as GET without body)
	assert.Equal(t, logical.ReadOperation, op)
}

func TestOperationFromHTTPMethod_OPTIONS(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	// OPTIONS maps to ReadOperation (read-like, CORS preflight / metadata)
	assert.Equal(t, logical.ReadOperation, op)
}

// =============================================================================
// extractClientIP Tests
// =============================================================================

func TestExtractClientIP_FromXRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractClientIP(req)
	assert.Equal(t, "10.0.0.1", ip)
}

func TestExtractClientIP_FromXForwardedFor_Single(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.2")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractClientIP(req)
	assert.Equal(t, "10.0.0.2", ip)
}

func TestExtractClientIP_FromXForwardedFor_Multiple(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.4, 10.0.0.5")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractClientIP(req)
	// Should return the first IP in the list
	assert.Equal(t, "10.0.0.3", ip)
}

func TestExtractClientIP_FromXForwardedFor_WithSpaces(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Forwarded-For", "  10.0.0.6  ")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractClientIP(req)
	assert.Equal(t, "10.0.0.6", ip)
}

func TestExtractClientIP_FromRemoteAddr_WithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	ip := extractClientIP(req)
	assert.Equal(t, "192.168.1.100", ip)
}

func TestExtractClientIP_FromRemoteAddr_IPv6WithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.RemoteAddr = "[::1]:54321"

	ip := extractClientIP(req)
	assert.Equal(t, "::1", ip)
}

func TestExtractClientIP_FromRemoteAddr_NoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.RemoteAddr = "192.168.1.200"

	ip := extractClientIP(req)
	// When SplitHostPort fails, returns the original RemoteAddr
	assert.Equal(t, "192.168.1.200", ip)
}

func TestExtractClientIP_Priority(t *testing.T) {
	// X-Real-IP takes priority over X-Forwarded-For and RemoteAddr
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Real-IP", "1.1.1.1")
	req.Header.Set("X-Forwarded-For", "2.2.2.2")
	req.RemoteAddr = "3.3.3.3:12345"

	ip := extractClientIP(req)
	assert.Equal(t, "1.1.1.1", ip)
}

func TestExtractClientIP_XForwardedForPriority(t *testing.T) {
	// X-Forwarded-For takes priority over RemoteAddr when X-Real-IP is not set
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Forwarded-For", "2.2.2.2")
	req.RemoteAddr = "3.3.3.3:12345"

	ip := extractClientIP(req)
	assert.Equal(t, "2.2.2.2", ip)
}

// =============================================================================
// buildLogicalRequest Tests
// =============================================================================

func TestBuildLogicalRequest_BasicGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/mykey", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	assert.Equal(t, logical.ReadOperation, logicalReq.Operation)
	assert.Equal(t, "secret/data/mykey", logicalReq.Path)
	assert.Equal(t, "192.168.1.1", logicalReq.ClientIP)
	assert.Equal(t, req, logicalReq.HTTPRequest)
	// ResponseWriter is wrapped in StatusRecordingWriter for status code capture
	srw, ok := logicalReq.ResponseWriter.(*logical.StatusRecordingWriter)
	assert.True(t, ok, "ResponseWriter should be wrapped in StatusRecordingWriter")
	assert.Equal(t, w, srw.Unwrap())
}

func TestBuildLogicalRequest_POST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/jwt/login", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	assert.Equal(t, logical.CreateOperation, logicalReq.Operation)
	assert.Equal(t, "auth/jwt/login", logicalReq.Path)
	assert.Equal(t, "10.0.0.1", logicalReq.ClientIP)
}

func TestBuildLogicalRequest_LIST(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?warden-list=true", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	assert.Equal(t, logical.ListOperation, logicalReq.Operation)
	assert.Equal(t, "secret/data", logicalReq.Path)
}

func TestBuildLogicalRequest_SysPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/providers", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	assert.Equal(t, logical.ReadOperation, logicalReq.Operation)
	assert.Equal(t, "sys/providers", logicalReq.Path)
}

func TestBuildLogicalRequest_WithXRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("X-Real-IP", "10.10.10.10")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	assert.Equal(t, "10.10.10.10", logicalReq.ClientIP)
}

func TestBuildLogicalRequest_NestedPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/v1/aws/gateway/s3/bucket/key/nested/path", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	assert.Equal(t, logical.UpdateOperation, logicalReq.Operation)
	assert.Equal(t, "aws/gateway/s3/bucket/key/nested/path", logicalReq.Path)
}

// =============================================================================
// writeLogicalResponse Tests
// =============================================================================

func TestWriteLogicalResponse_NilResponse(t *testing.T) {
	w := httptest.NewRecorder()

	writeLogicalResponse(w, nil)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestWriteLogicalResponse_EmptyResponse(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestWriteLogicalResponse_WithStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusCreated,
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestWriteLogicalResponse_WithBody(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"data": "test"}`),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"data": "test"}`, w.Body.String())
}

func TestWriteLogicalResponse_WithHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":  []string{"application/json"},
			"X-Custom":      []string{"value1", "value2"},
			"Cache-Control": []string{"no-cache"},
		},
		Body: []byte(`{}`),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, []string{"value1", "value2"}, w.Header().Values("X-Custom"))
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

func TestWriteLogicalResponse_ErrorStatus(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusBadRequest,
		Body:       []byte(`{"errors": ["invalid request"]}`),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request")
}

func TestWriteLogicalResponse_ServerError(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       []byte(`{"errors": ["internal error"]}`),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestWriteLogicalResponse_ZeroStatusCodeDefaultsToOK(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: 0, // Not set
		Body:       []byte(`{"ok": true}`),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWriteLogicalResponse_EmptyBody(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Body:       []byte{},
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestWriteLogicalResponse_NilBody(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Body:       nil,
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

// =============================================================================
// Integration Tests for handleLogical
// =============================================================================

// MockCore is a minimal implementation for testing
type MockCore struct {
	handleRequestFunc func() (*logical.Response, error)
}

// =============================================================================
// Table-Driven Tests
// =============================================================================

func TestOperationFromHTTPMethod_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		queryParam string
		header     string
		expected   logical.Operation
	}{
		{"GET returns Read", http.MethodGet, "", "", logical.ReadOperation},
		{"GET with warden-list=true returns List", http.MethodGet, "warden-list=true", "", logical.ListOperation},
		{"GET with X-Warden-Request LIST returns List", http.MethodGet, "", "LIST", logical.ListOperation},
		{"GET with warden-help=1 returns Help", http.MethodGet, "warden-help=1", "", logical.HelpOperation},
		{"GET with warden-help=true returns Help", http.MethodGet, "warden-help=true", "", logical.HelpOperation},
		{"GET with warden-help=false returns Read", http.MethodGet, "warden-help=false", "", logical.ReadOperation},
		{"GET with warden-help=0 returns Read", http.MethodGet, "warden-help=0", "", logical.ReadOperation},
		{"Help takes priority over list", http.MethodGet, "warden-help=1&warden-list=true", "", logical.HelpOperation},
		{"POST returns Create", http.MethodPost, "", "", logical.CreateOperation},
		{"PUT returns Update", http.MethodPut, "", "", logical.UpdateOperation},
		{"PATCH returns Patch", http.MethodPatch, "", "", logical.PatchOperation},
		{"DELETE returns Delete", http.MethodDelete, "", "", logical.DeleteOperation},
		{"LIST method returns List", "LIST", "", "", logical.ListOperation},
		{"HEAD maps to Read", http.MethodHead, "", "", logical.ReadOperation},
		{"OPTIONS maps to Read", http.MethodOptions, "", "", logical.ReadOperation},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := "/v1/test"
			if tc.queryParam != "" {
				url += "?" + tc.queryParam
			}
			req := httptest.NewRequest(tc.method, url, nil)
			if tc.header != "" {
				req.Header.Set("X-Warden-Request", tc.header)
			}

			op := operationFromHTTPMethod(req)
			assert.Equal(t, tc.expected, op)
		})
	}
}

func TestExtractClientIP_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		xRealIP       string
		xForwardedFor string
		remoteAddr    string
		expected      string
	}{
		{"X-Real-IP takes priority", "1.1.1.1", "2.2.2.2", "3.3.3.3:1234", "1.1.1.1"},
		{"X-Forwarded-For when no X-Real-IP", "", "2.2.2.2", "3.3.3.3:1234", "2.2.2.2"},
		{"First IP from X-Forwarded-For chain", "", "1.1.1.1, 2.2.2.2, 3.3.3.3", "4.4.4.4:1234", "1.1.1.1"},
		{"RemoteAddr when no headers", "", "", "192.168.1.1:5000", "192.168.1.1"},
		{"IPv6 RemoteAddr", "", "", "[::1]:5000", "::1"},
		{"RemoteAddr without port", "", "", "10.0.0.1", "10.0.0.1"},
		{"Trimmed X-Forwarded-For", "", "  10.0.0.1  ", "1.1.1.1:1234", "10.0.0.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if tc.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}
			req.RemoteAddr = tc.remoteAddr

			ip := extractClientIP(req)
			assert.Equal(t, tc.expected, ip)
		})
	}
}

func TestBuildLogicalRequest_PathStripping(t *testing.T) {
	tests := []struct {
		urlPath      string
		expectedPath string
	}{
		{"/v1/secret/data", "secret/data"},
		{"/v1/sys/init", "sys/init"},
		{"/v1/auth/jwt/login", "auth/jwt/login"},
		{"/v1/aws/gateway/s3", "aws/gateway/s3"},
		{"/v1/", ""},
		{"/v1/a", "a"},
	}

	for _, tc := range tests {
		t.Run(tc.urlPath, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.urlPath, nil)
			req.RemoteAddr = "127.0.0.1:8080"
			w := httptest.NewRecorder()

			logicalReq := buildLogicalRequest(w, req)

			assert.Equal(t, tc.expectedPath, logicalReq.Path)
		})
	}
}

// =============================================================================
// Unsupported Method Rejection Tests
// =============================================================================

func TestHandleLogical_RejectsUnsupportedMethods(t *testing.T) {
	// handleLogical rejects unsupported methods before accessing core,
	// so we can pass nil core for these tests.
	handler := handleLogical(nil, nil, nil)

	unsupportedMethods := []string{
		http.MethodConnect,
		http.MethodTrace,
		"PURGE",
		"PROPFIND",
		"CUSTOM",
	}

	for _, method := range unsupportedMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/v1/test", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Contains(t, w.Body.String(), "not allowed")
		})
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestBuildLogicalRequest_PreservesHTTPRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	// HTTPRequest should be the same object
	require.NotNil(t, logicalReq.HTTPRequest)
	assert.Equal(t, "Bearer token123", logicalReq.HTTPRequest.Header.Get("Authorization"))
	assert.Equal(t, "application/json", logicalReq.HTTPRequest.Header.Get("Content-Type"))
}

func TestBuildLogicalRequest_PreservesResponseWriter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()

	logicalReq := buildLogicalRequest(w, req)

	// ResponseWriter should be the same object
	require.NotNil(t, logicalReq.ResponseWriter)

	// Verify we can write to it
	logicalReq.ResponseWriter.WriteHeader(http.StatusAccepted)
	assert.Equal(t, http.StatusAccepted, w.Code)
}

func TestWriteLogicalResponse_MultipleHeaderValues(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Set-Cookie": []string{"session=abc123", "user=john"},
		},
	}

	writeLogicalResponse(w, resp)

	cookies := w.Header().Values("Set-Cookie")
	assert.Len(t, cookies, 2)
	assert.Contains(t, cookies, "session=abc123")
	assert.Contains(t, cookies, "user=john")
}

func TestWriteLogicalResponse_LargeBody(t *testing.T) {
	w := httptest.NewRecorder()

	// Create a large body (1MB)
	largeBody := make([]byte, 1024*1024)
	for i := range largeBody {
		largeBody[i] = 'x'
	}

	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Body:       largeBody,
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, len(largeBody), w.Body.Len())
}

func TestWriteLogicalResponse_BinaryBody(t *testing.T) {
	w := httptest.NewRecorder()

	// Binary data with null bytes
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00}

	resp := &logical.Response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/octet-stream"},
		},
		Body: binaryData,
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, binaryData, w.Body.Bytes())
}

func TestErrorToStatusCode_UnsupportedOperation(t *testing.T) {
	assert.Equal(t, http.StatusMethodNotAllowed, errorToStatusCode(sdklogical.ErrUnsupportedOperation))
}

func TestErrorToStatusCode_UnsupportedPath(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, errorToStatusCode(sdklogical.ErrUnsupportedPath))
}

func TestErrorToStatusCode_PermissionDenied(t *testing.T) {
	assert.Equal(t, http.StatusForbidden, errorToStatusCode(sdklogical.ErrPermissionDenied))
}

func TestErrorToStatusCode_InvalidRequest(t *testing.T) {
	assert.Equal(t, http.StatusBadRequest, errorToStatusCode(sdklogical.ErrInvalidRequest))
}

func TestErrorToStatusCode_GenericError(t *testing.T) {
	assert.Equal(t, http.StatusInternalServerError, errorToStatusCode(errors.New("something broke")))
}

func TestErrorToStatusCode_WrappedErrors(t *testing.T) {
	wrapped := fmt.Errorf("handler: %w", sdklogical.ErrPermissionDenied)
	assert.Equal(t, http.StatusForbidden, errorToStatusCode(wrapped))

	wrapped2 := fmt.Errorf("handler: %w", sdklogical.ErrInvalidRequest)
	assert.Equal(t, http.StatusBadRequest, errorToStatusCode(wrapped2))

	wrapped3 := fmt.Errorf("handler: %w", sdklogical.ErrUnsupportedPath)
	assert.Equal(t, http.StatusNotFound, errorToStatusCode(wrapped3))

	wrapped4 := fmt.Errorf("handler: %w", sdklogical.ErrUnsupportedOperation)
	assert.Equal(t, http.StatusMethodNotAllowed, errorToStatusCode(wrapped4))
}

// =============================================================================
// writeLogicalResponse Tests (Err, Data, Streamed)
// =============================================================================

func TestWriteLogicalResponse_WithErr(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Err: errors.New("something failed"),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string][]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, []string{"something failed"}, body["errors"])
}

func TestWriteLogicalResponse_WithErrAndStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		StatusCode: http.StatusBadRequest,
		Err:        errors.New("invalid input"),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid input")
}

func TestWriteLogicalResponse_WithData(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Data: map[string]any{
			"key":   "value",
			"count": 42,
		},
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "value", body["data"]["key"])
	assert.Equal(t, float64(42), body["data"]["count"])
}

func TestWriteLogicalResponse_BodyTakesPriorityOverData(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Body: []byte(`{"custom":"body"}`),
		Data: map[string]any{"should": "be ignored"},
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, `{"custom":"body"}`, w.Body.String())
}

func TestWriteLogicalResponse_BodyTakesPriorityOverErr(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Body: []byte(`{"custom":"body"}`),
		Err:  errors.New("should be ignored"),
	}

	writeLogicalResponse(w, resp)

	assert.Equal(t, `{"custom":"body"}`, w.Body.String())
}

func TestWriteLogicalResponse_Streamed(t *testing.T) {
	w := httptest.NewRecorder()
	// Simulate that the backend already wrote to the response writer
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("streamed content"))

	resp := &logical.Response{
		Streamed:   true,
		StatusCode: http.StatusCreated, // should be ignored
		Body:       []byte("should not appear"),
	}

	writeLogicalResponse(w, resp)

	// The function should return early without writing anything additional.
	// The recorder already has what the backend wrote.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "streamed content", w.Body.String())
}

func TestWriteLogicalResponse_ErrTakesPriorityOverData(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Err:  errors.New("error wins"),
		Data: map[string]any{"should": "be ignored"},
	}

	writeLogicalResponse(w, resp)

	assert.Contains(t, w.Body.String(), "error wins")
	assert.NotContains(t, w.Body.String(), "ignored")
}

// =============================================================================
// JSON struct tests
// =============================================================================

func TestWriteLogicalResponse_DataWithNestedMap(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Data: map[string]any{
			"nested": map[string]any{
				"inner": "value",
			},
		},
	}

	writeLogicalResponse(w, resp)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data := body["data"].(map[string]any)
	nested := data["nested"].(map[string]any)
	assert.Equal(t, "value", nested["inner"])
}

func TestWriteLogicalResponse_DataEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &logical.Response{
		Data: map[string]any{},
	}

	writeLogicalResponse(w, resp)

	// Empty map is still serialized
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"data":{}`)
}

// =============================================================================
// HandlerProperties struct test
// =============================================================================

func TestHandleLogical_SealedCore(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleLogical(c, log, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/providers", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Sealed core returns an error response via writeLogicalResponse
	assert.Contains(t, w.Body.String(), "sealed")
}

func TestHandleLogical_AllowedMethods(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleLogical(c, log, nil)

	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, "LIST",
		http.MethodHead, http.MethodOptions,
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/v1/sys/providers", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			// Should NOT be 405 (sealed error is fine)
			assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

// =============================================================================
// handleSysInitPut Tests (with real core)
// =============================================================================

func TestHandleLogical_ErrorToStatusCode_Integration(t *testing.T) {
	// handleLogical with a sealed core calls HandleRequest which returns
	// an error response (not an error). This covers the writeLogicalResponse
	// path. The error-to-status-code path requires HandleRequest to return
	// a Go error, which happens with ErrStandby (tested via standby forwarding)
	// or other internal errors. We already test errorToStatusCode directly.
	// This test just confirms the full handler path works end-to-end.
	c, log := createTestCoreForHTTP(t)
	handler := handleLogical(c, log, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Sealed core -> error response with "sealed" message
	assert.Contains(t, w.Body.String(), "sealed")
}
