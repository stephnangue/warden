// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"syscall"
	"testing"

	"fmt"

	"github.com/stephnangue/warden/logger"
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
	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

			wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

			wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

	wrapped := wrapGenericHandler(nil, inner, nil, nil)

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

// =============================================================================
// isConnectionError Tests
// =============================================================================

func TestIsConnectionError_Nil(t *testing.T) {
	assert.False(t, isConnectionError(nil))
}

func TestIsConnectionError_ConnectionRefused(t *testing.T) {
	assert.True(t, isConnectionError(syscall.ECONNREFUSED))
}

func TestIsConnectionError_ConnectionReset(t *testing.T) {
	assert.True(t, isConnectionError(syscall.ECONNRESET))
}

func TestIsConnectionError_ConnectionAborted(t *testing.T) {
	assert.True(t, isConnectionError(syscall.ECONNABORTED))
}

func TestIsConnectionError_EOF(t *testing.T) {
	assert.True(t, isConnectionError(io.EOF))
	assert.True(t, isConnectionError(io.ErrUnexpectedEOF))
}

func TestIsConnectionError_NetOpError(t *testing.T) {
	opErr := &net.OpError{
		Op:  "read",
		Net: "tcp",
		Err: errors.New("connection reset by peer"),
	}
	assert.True(t, isConnectionError(opErr))
}

func TestIsConnectionError_GenericError(t *testing.T) {
	assert.False(t, isConnectionError(errors.New("some random error")))
}

func TestIsConnectionError_WrappedConnectionRefused(t *testing.T) {
	inner := syscall.ECONNREFUSED
	wrapped := errors.Join(errors.New("proxy error"), inner)
	assert.True(t, isConnectionError(wrapped))
}

// =============================================================================
// Proxy Director Tests
// =============================================================================

// TestProxyDirectorPreservesHostHeader verifies that the standby proxy Director
// preserves the original Host header instead of rewriting it to the target.
// This is critical for AWS SigV4: the client signs the Host header, so rewriting
// it would cause signature verification to fail on the leader.
func TestProxyDirectorPreservesHostHeader(t *testing.T) {
	var receivedHost string
	var receivedForwardedHost string

	// Mock "leader" backend that records the Host header it receives.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedForwardedHost = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	// Build a proxy with the same Director logic as standbyForwarder.getProxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host
			// Must NOT set req.Host — this is the fix under test.

			req.Header.Set("X-Forwarded-Host", req.Host)

			if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
		},
	}

	// Send a request with a specific Host header (simulating the client's
	// original address, e.g., standby node or load balancer).
	req := httptest.NewRequest(http.MethodGet, "/v1/aws/gateway", nil)
	req.Host = "standby.example.com:8510"
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "standby.example.com:8510", receivedHost,
		"backend should receive the original Host header, not the proxy target")
	assert.Equal(t, "standby.example.com:8510", receivedForwardedHost,
		"X-Forwarded-Host should contain the original Host")
}

// TestProxyDirectorSetsForwardingHeaders verifies that X-Forwarded-For and
// X-Forwarded-Proto are set correctly by the Director.
func TestProxyDirectorSetsForwardingHeaders(t *testing.T) {
	var receivedXFF string
	var receivedXFP string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		receivedXFP = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host

			req.Header.Set("X-Forwarded-Host", req.Host)

			if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Go's httputil.ReverseProxy appends its own X-Forwarded-For entry
	// after the Director runs, so the value may contain duplicates.
	assert.Contains(t, receivedXFF, "192.168.1.100")
	assert.Equal(t, "http", receivedXFP)
}

// TestProxyDirectorHandlesBareIPRemoteAddr verifies that the Director correctly
// sets X-Forwarded-For when RemoteAddr is a bare IP (no port), as happens after
// middleware.RealIP rewrites RemoteAddr from X-Forwarded-For headers.
func TestProxyDirectorHandlesBareIPRemoteAddr(t *testing.T) {
	var receivedXFF string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host

			// Replicate the fixed Director logic from handler.go
			clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil {
				if ip := net.ParseIP(req.RemoteAddr); ip != nil {
					clientIP = req.RemoteAddr
				}
			}
			if clientIP != "" {
				if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
					req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
				} else {
					req.Header.Set("X-Forwarded-For", clientIP)
				}
			}
		},
	}

	t.Run("bare_IPv4", func(t *testing.T) {
		// Simulate middleware.RealIP stripping the port
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.RemoteAddr = "192.168.1.100" // no port
		w := httptest.NewRecorder()

		proxy.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, receivedXFF, "192.168.1.100")
	})

	t.Run("bare_IPv4_with_prior_XFF", func(t *testing.T) {
		// LB already set X-Forwarded-For, RealIP stripped port
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.RemoteAddr = "10.0.0.50"
		req.Header.Set("X-Forwarded-For", "203.0.113.10")
		w := httptest.NewRecorder()

		proxy.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, receivedXFF, "203.0.113.10")
		assert.Contains(t, receivedXFF, "10.0.0.50")
	})

	t.Run("with_port_still_works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.RemoteAddr = "192.168.1.100:54321"
		w := httptest.NewRecorder()

		proxy.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, receivedXFF, "192.168.1.100")
	})
}

func TestRespondStandby_BasicRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w := httptest.NewRecorder()

	respondStandby(w, req, "https://leader.example.com:8200")

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	loc := w.Header().Get("Location")
	assert.Equal(t, "https://leader.example.com:8200/v1/sys/health", loc)
}

func TestRespondStandby_PreservesQueryParams(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data?version=2&format=json", nil)
	w := httptest.NewRecorder()

	respondStandby(w, req, "https://leader.example.com:8200")

	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "version=2")
	assert.Contains(t, loc, "format=json")
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
}

func TestRespondStandby_InvalidLeaderAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()

	respondStandby(w, req, "://invalid-url")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "invalid leader address")
}

func TestRespondStandby_PreservesPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/v1/aws/gateway/s3/bucket/key", nil)
	w := httptest.NewRecorder()

	respondStandby(w, req, "http://10.0.0.1:8200")

	loc := w.Header().Get("Location")
	assert.Equal(t, "http://10.0.0.1:8200/v1/aws/gateway/s3/bucket/key", loc)
}

// =============================================================================
// standbyAllowedPaths Tests
// =============================================================================

func TestStandbyAllowedPaths_Contents(t *testing.T) {
	expected := []string{
		"/v1/sys/health",
		"/v1/sys/ready",
		"/v1/sys/leader",
		"/v1/sys/seal-status",
		"/v1/sys/init",
	}
	for _, p := range expected {
		assert.True(t, standbyAllowedPaths[p], "expected %s to be allowed on standby", p)
	}
	assert.Equal(t, len(expected), len(standbyAllowedPaths))
}

func TestStandbyAllowedPaths_NotAllowed(t *testing.T) {
	notAllowed := []string{
		"/v1/sys/step-down",
		"/v1/sys/providers",
		"/v1/aws/gateway",
		"/v1/secret/data",
	}
	for _, p := range notAllowed {
		assert.False(t, standbyAllowedPaths[p], "expected %s to NOT be allowed on standby", p)
	}
}

// =============================================================================
// isConnectionError Tests (additional coverage)
// =============================================================================

func TestIsConnectionError_DialOpError(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	assert.True(t, isConnectionError(err))
}

func TestIsConnectionError_WriteOpError(t *testing.T) {
	err := &net.OpError{Op: "write", Net: "tcp", Err: errors.New("broken pipe")}
	assert.True(t, isConnectionError(err))
}

func TestIsConnectionError_LookupOpError(t *testing.T) {
	// DNS lookup errors should NOT be connection errors
	err := &net.OpError{Op: "lookup", Net: "ip", Err: errors.New("no such host")}
	assert.False(t, isConnectionError(err))
}

func TestIsConnectionError_WrappedEOF(t *testing.T) {
	err := fmt.Errorf("proxy: %w", io.EOF)
	assert.True(t, isConnectionError(err))
}

func TestIsConnectionError_WrappedUnexpectedEOF(t *testing.T) {
	err := fmt.Errorf("proxy: %w", io.ErrUnexpectedEOF)
	assert.True(t, isConnectionError(err))
}

func TestIsConnectionError_WrappedConnReset(t *testing.T) {
	err := fmt.Errorf("transport: %w", syscall.ECONNRESET)
	assert.True(t, isConnectionError(err))
}

func TestIsConnectionError_WrappedConnAborted(t *testing.T) {
	err := fmt.Errorf("transport: %w", syscall.ECONNABORTED)
	assert.True(t, isConnectionError(err))
}

func TestIsConnectionError_TLSOpError(t *testing.T) {
	// TLS handshake errors (op != dial/read/write) should NOT be connection errors
	err := &net.OpError{Op: "remote error", Net: "tcp", Err: errors.New("tls: bad certificate")}
	assert.False(t, isConnectionError(err))
}

// =============================================================================
// errorToStatusCode Tests
// =============================================================================

func TestHandlerProperties_Defaults(t *testing.T) {
	props := &HandlerProperties{}
	assert.Nil(t, props.Core)
	assert.Nil(t, props.Logger)
	assert.Nil(t, props.ClusterTLSConfigFunc)
	assert.Equal(t, 0, int(props.ForwardingTimeout))
}

// =============================================================================
// Helper: create a minimal core for HTTP handler tests
// =============================================================================

func TestHandler_InvalidPath(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := Handler(&HandlerProperties{Core: c, Logger: log})

	req := httptest.NewRequest(http.MethodGet, "/not-v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_HealthEndpoint(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := Handler(&HandlerProperties{Core: c, Logger: log})

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Not initialized -> 501
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandler_ReadyEndpoint(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := Handler(&HandlerProperties{Core: c, Logger: log})

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/ready", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandler_LeaderEndpoint(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := Handler(&HandlerProperties{Core: c, Logger: log})

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/leader", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_SealStatusEndpoint(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := Handler(&HandlerProperties{Core: c, Logger: log})

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/seal-status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// =============================================================================
// handleLogical Tests (with real core)
// =============================================================================

func TestHandler_InitEndpoint(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := Handler(&HandlerProperties{Core: c, Logger: log})

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/init", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestForwardToActive_NoLeader(t *testing.T) {
	// Core without HA -> Leader() returns ErrHANotEnabled
	c, _ := createTestCoreForHTTP(t)
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	fwd := newStandbyForwarder(log, nil, 30)

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()

	forwardToActive(c, fwd, w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "no active node found")
}

// =============================================================================
// getProxy Director & ErrorHandler Tests (via actual proxy request)
// =============================================================================

func TestWrapGenericHandler_StandbyForwarding(t *testing.T) {
	// Core starts in standby mode. Non-allowed paths should trigger forwardToActive.
	c, log := createTestCoreForHTTP(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	fwd := newStandbyForwarder(log, nil, 30)

	wrapped := wrapGenericHandler(c, inner, log, fwd)

	// /v1/sys/providers is NOT in standbyAllowedPaths, so should forward
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/providers", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	// forwardToActive with no HA -> 503
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "no active node found")
}

func TestWrapGenericHandler_StandbyAllowedPath(t *testing.T) {
	// Allowed paths should pass through even in standby mode
	c, log := createTestCoreForHTTP(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner", "yes")
		w.WriteHeader(http.StatusOK)
	})
	fwd := newStandbyForwarder(log, nil, 30)

	wrapped := wrapGenericHandler(c, inner, log, fwd)

	// /v1/sys/health IS in standbyAllowedPaths
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	// Should reach inner handler
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "yes", w.Header().Get("X-Inner"))
}
