// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
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
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?list=true", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?list=false", nil)
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
	// HEAD defaults to ReadOperation
	assert.Equal(t, logical.ReadOperation, op)
}

func TestOperationFromHTTPMethod_OPTIONS(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/v1/secret/data", nil)
	op := operationFromHTTPMethod(req)
	// OPTIONS defaults to ReadOperation
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
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?list=true", nil)
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
		{"GET with list=true returns List", http.MethodGet, "list=true", "", logical.ListOperation},
		{"GET with X-Warden-Request LIST returns List", http.MethodGet, "", "LIST", logical.ListOperation},
		{"POST returns Create", http.MethodPost, "", "", logical.CreateOperation},
		{"PUT returns Update", http.MethodPut, "", "", logical.UpdateOperation},
		{"PATCH returns Patch", http.MethodPatch, "", "", logical.PatchOperation},
		{"DELETE returns Delete", http.MethodDelete, "", "", logical.DeleteOperation},
		{"LIST method returns List", "LIST", "", "", logical.ListOperation},
		{"HEAD defaults to Read", http.MethodHead, "", "", logical.ReadOperation},
		{"CONNECT defaults to Read", http.MethodConnect, "", "", logical.ReadOperation},
		{"TRACE defaults to Read", http.MethodTrace, "", "", logical.ReadOperation},
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
		name         string
		xRealIP      string
		xForwardedFor string
		remoteAddr   string
		expected     string
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
