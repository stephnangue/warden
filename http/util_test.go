// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// respondError Tests
// =============================================================================

func TestRespondError_Basic(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusBadRequest, "invalid input")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Errors, 1)
	assert.Equal(t, "invalid input", resp.Errors[0])
}

func TestRespondError_NotFound(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusNotFound, "resource not found")

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "resource not found", resp.Errors[0])
}

func TestRespondError_InternalServerError(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusInternalServerError, "something went wrong")

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "something went wrong", resp.Errors[0])
}

func TestRespondError_Unauthorized(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusUnauthorized, "authentication required")

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "authentication required", resp.Errors[0])
}

func TestRespondError_Forbidden(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusForbidden, "permission denied")

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "permission denied", resp.Errors[0])
}

func TestRespondError_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusMethodNotAllowed, "method not allowed")

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "method not allowed", resp.Errors[0])
}

func TestRespondError_EmptyMessage(t *testing.T) {
	w := httptest.NewRecorder()

	respondError(w, http.StatusBadRequest, "")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Errors, 1)
	assert.Equal(t, "", resp.Errors[0])
}

func TestRespondError_LongMessage(t *testing.T) {
	w := httptest.NewRecorder()

	longMessage := "This is a very long error message that contains a lot of details about what went wrong. It includes information about the specific field that caused the error, the expected format, and suggestions for how to fix the issue. The message might also include technical details that could help with debugging."

	respondError(w, http.StatusBadRequest, longMessage)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, longMessage, resp.Errors[0])
}

func TestRespondError_SpecialCharacters(t *testing.T) {
	w := httptest.NewRecorder()

	specialMessage := `error with "quotes" and <tags> and special chars: 日本語 émojis 🚀`

	respondError(w, http.StatusBadRequest, specialMessage)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, specialMessage, resp.Errors[0])
}

// =============================================================================
// respondOk Tests
// =============================================================================

func TestRespondOk_WithData(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]interface{}{
		"key":   "value",
		"count": 42,
	}

	respondOk(w, data)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["key"])
	assert.Equal(t, float64(42), resp["count"]) // JSON numbers are float64
}

func TestRespondOk_NilData(t *testing.T) {
	w := httptest.NewRecorder()

	respondOk(w, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Empty(t, w.Body.String())
}

func TestRespondOk_EmptyMap(t *testing.T) {
	w := httptest.NewRecorder()

	respondOk(w, map[string]interface{}{})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 0)
}

func TestRespondOk_WithStruct(t *testing.T) {
	w := httptest.NewRecorder()

	type TestData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	data := TestData{
		Name:  "test",
		Value: 123,
	}

	respondOk(w, data)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp TestData
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test", resp.Name)
	assert.Equal(t, 123, resp.Value)
}

func TestRespondOk_WithSlice(t *testing.T) {
	w := httptest.NewRecorder()

	data := []string{"one", "two", "three"}

	respondOk(w, data)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, []string{"one", "two", "three"}, resp)
}

func TestRespondOk_WithNestedData(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"value": "deep",
			},
		},
	}

	respondOk(w, data)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	level1, ok := resp["level1"].(map[string]interface{})
	require.True(t, ok)
	level2, ok := level1["level2"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "deep", level2["value"])
}

func TestRespondOk_WithBooleans(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]interface{}{
		"initialized": true,
		"sealed":      false,
	}

	respondOk(w, data)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, true, resp["initialized"])
	assert.Equal(t, false, resp["sealed"])
}

// =============================================================================
// ErrorResponse Tests
// =============================================================================

func TestErrorResponse_Structure(t *testing.T) {
	resp := ErrorResponse{
		Errors: []string{"error1", "error2"},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ErrorResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Errors, 2)
	assert.Equal(t, "error1", decoded.Errors[0])
	assert.Equal(t, "error2", decoded.Errors[1])
}

func TestErrorResponse_EmptyErrors(t *testing.T) {
	resp := ErrorResponse{
		Errors: []string{},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Should have an empty array, not null
	assert.Contains(t, string(data), `"errors":[]`)
}

func TestErrorResponse_NilErrors(t *testing.T) {
	resp := ErrorResponse{
		Errors: nil,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Nil slice is marshaled as null in JSON
	assert.Contains(t, string(data), `"errors":null`)
}

// =============================================================================
// Table-Driven Tests
// =============================================================================

func TestRespondError_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{"200 OK", http.StatusOK, "success"},
		{"201 Created", http.StatusCreated, "resource created"},
		{"400 Bad Request", http.StatusBadRequest, "invalid request"},
		{"401 Unauthorized", http.StatusUnauthorized, "not authenticated"},
		{"403 Forbidden", http.StatusForbidden, "access denied"},
		{"404 Not Found", http.StatusNotFound, "not found"},
		{"405 Method Not Allowed", http.StatusMethodNotAllowed, "method not allowed"},
		{"409 Conflict", http.StatusConflict, "resource conflict"},
		{"422 Unprocessable Entity", http.StatusUnprocessableEntity, "validation failed"},
		{"429 Too Many Requests", http.StatusTooManyRequests, "rate limited"},
		{"500 Internal Server Error", http.StatusInternalServerError, "internal error"},
		{"502 Bad Gateway", http.StatusBadGateway, "bad gateway"},
		{"503 Service Unavailable", http.StatusServiceUnavailable, "service unavailable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			respondError(w, tc.statusCode, tc.message)

			assert.Equal(t, tc.statusCode, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var resp ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tc.message, resp.Errors[0])
		})
	}
}
