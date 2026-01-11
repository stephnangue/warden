// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// wrapGenericHandler Tests
// =============================================================================

func TestWrapGenericHandler_ValidV1Path(t *testing.T) {
	// Create a simple inner handler that sets a header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner-Called", "true")
		w.WriteHeader(http.StatusOK)
	})

	// Wrap it
	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with valid /v1/ path
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Inner handler should have been called
	assert.Equal(t, "true", w.Header().Get("X-Inner-Called"))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWrapGenericHandler_InvalidPath_NoV1Prefix(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner-Called", "true")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with path without /v1/ prefix
	req := httptest.NewRequest(http.MethodGet, "/api/secret/data", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Inner handler should NOT have been called
	assert.Empty(t, w.Header().Get("X-Inner-Called"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWrapGenericHandler_InvalidPath_RootPath(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner-Called", "true")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with root path
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("X-Inner-Called"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWrapGenericHandler_InvalidPath_V2Prefix(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner-Called", "true")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with /v2/ prefix (should fail)
	req := httptest.NewRequest(http.MethodGet, "/v2/secret/data", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("X-Inner-Called"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWrapGenericHandler_JustV1(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner-Called", "true")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with just /v1/ path
	req := httptest.NewRequest(http.MethodGet, "/v1/", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, "true", w.Header().Get("X-Inner-Called"))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWrapGenericHandler_SysPath(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with sys path
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/init", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, "/v1/sys/init", w.Header().Get("X-Path"))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWrapGenericHandler_ErrorResponse_Format(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Test with invalid path
	req := httptest.NewRequest(http.MethodGet, "/invalid", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "path must begin with /v1/")
}

// =============================================================================
// Path Pattern Tests
// =============================================================================

func TestWrapGenericHandler_PathPatterns(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		expectPass   bool
		expectedCode int
	}{
		{"/v1/ prefix passes", "/v1/test", true, http.StatusOK},
		{"/v1/sys/ prefix passes", "/v1/sys/init", true, http.StatusOK},
		{"/v1/auth/ prefix passes", "/v1/auth/jwt/login", true, http.StatusOK},
		{"/v1/aws/ prefix passes", "/v1/aws/gateway/s3", true, http.StatusOK},
		{"Root path fails", "/", false, http.StatusNotFound},
		{"/api/ prefix fails", "/api/test", false, http.StatusNotFound},
		{"/v2/ prefix fails", "/v2/test", false, http.StatusNotFound},
		{"/v1 without slash fails", "/v1test", false, http.StatusNotFound},
		{"Double slash /v1// passes", "/v1//test", true, http.StatusOK},
		{"/health fails", "/health", false, http.StatusNotFound},
		{"/metrics fails", "/metrics", false, http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Inner-Called", "true")
				w.WriteHeader(http.StatusOK)
			})

			wrapped := wrapGenericHandler(nil, inner, nil)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()

			wrapped.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedCode, w.Code, "Path: %s", tc.path)
			if tc.expectPass {
				assert.Equal(t, "true", w.Header().Get("X-Inner-Called"))
			} else {
				assert.Empty(t, w.Header().Get("X-Inner-Called"))
			}
		})
	}
}

// =============================================================================
// HTTP Methods Tests
// =============================================================================

func TestWrapGenericHandler_AllMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
		"LIST", // Custom method
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Method", r.Method)
				w.WriteHeader(http.StatusOK)
			})

			wrapped := wrapGenericHandler(nil, inner, nil)

			req := httptest.NewRequest(method, "/v1/test", nil)
			w := httptest.NewRecorder()

			wrapped.ServeHTTP(w, req)

			// All methods should pass through for valid paths
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, method, w.Header().Get("X-Method"))
		})
	}
}

// =============================================================================
// Request Forwarding Tests
// =============================================================================

func TestWrapGenericHandler_ForwardsHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back specific headers
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-ContentType", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Bearer token123", w.Header().Get("X-Echo-Auth"))
	assert.Equal(t, "application/json", w.Header().Get("X-Echo-ContentType"))
}

func TestWrapGenericHandler_ForwardsQueryParams(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-List", r.URL.Query().Get("list"))
		w.Header().Set("X-Echo-Limit", r.URL.Query().Get("limit"))
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/test?list=true&limit=100", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Echo-List"))
	assert.Equal(t, "100", w.Header().Get("X-Echo-Limit"))
}

// =============================================================================
// Response Tests
// =============================================================================

func TestWrapGenericHandler_InnerSetsCookies(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
		})
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "session", cookies[0].Name)
	assert.Equal(t, "abc123", cookies[0].Value)
}

func TestWrapGenericHandler_InnerWritesBody(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, `{"status": "ok"}`, w.Body.String())
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestWrapGenericHandler_CaseSensitivity(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// /V1/ should fail (case sensitive)
	req := httptest.NewRequest(http.MethodGet, "/V1/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWrapGenericHandler_PathWithFragment(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Fragments are not sent to server, but test URL handling
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWrapGenericHandler_LongPath(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := wrapGenericHandler(nil, inner, nil)

	// Very long path with valid characters
	longSegment := ""
	for i := 0; i < 500; i++ {
		longSegment += "a"
	}
	longPath := "/v1/secret/" + longSegment + "/data"

	req := httptest.NewRequest(http.MethodGet, longPath, nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
