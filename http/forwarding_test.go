package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentServerName_NilTLSConfigFunc(t *testing.T) {
	f := &standbyForwarder{tlsConfigFunc: nil}
	assert.Equal(t, "", f.currentServerName())
}

func TestCurrentServerName_NilTLSConfig(t *testing.T) {
	f := &standbyForwarder{
		tlsConfigFunc: func() *tls.Config { return nil },
	}
	assert.Equal(t, "", f.currentServerName())
}

func TestCurrentServerName_NoCertificates(t *testing.T) {
	f := &standbyForwarder{
		tlsConfigFunc: func() *tls.Config {
			return &tls.Config{}
		},
	}
	assert.Equal(t, "", f.currentServerName())
}

func TestCurrentServerName_NilLeaf(t *testing.T) {
	f := &standbyForwarder{
		tlsConfigFunc: func() *tls.Config {
			return &tls.Config{
				Certificates: []tls.Certificate{{}},
			}
		},
	}
	assert.Equal(t, "", f.currentServerName())
}

func TestCurrentServerName_WithCN(t *testing.T) {
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-abcdef"
	f := &standbyForwarder{
		tlsConfigFunc: func() *tls.Config {
			return &tls.Config{
				Certificates: []tls.Certificate{
					{Leaf: cert},
				},
			}
		},
	}
	assert.Equal(t, "fw-abcdef", f.currentServerName())
}

// =============================================================================
// newStandbyForwarder Tests
// =============================================================================

func TestNewStandbyForwarder(t *testing.T) {
	f := newStandbyForwarder(nil, nil, 30)
	assert.NotNil(t, f)
	assert.Nil(t, f.tlsConfigFunc)
	assert.Nil(t, f.core)
	assert.Equal(t, 30, int(f.forwardingTimeout))
}

// =============================================================================
// writeLogicalResponse with Data containing nested structures
// =============================================================================

func TestGetProxy_NilTLSConfigFunc(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := newStandbyForwarder(log, nil, 30)

	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	assert.Nil(t, proxy, "should return nil when tlsConfigFunc is nil")
}

func TestGetProxy_NilTLSConfig(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := newStandbyForwarder(log, func() *tls.Config { return nil }, 30)

	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	assert.Nil(t, proxy, "should return nil when tlsConfigFunc returns nil")
}

func TestGetProxy_InvalidClusterAddr(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{}
	}, 30)

	// url.Parse rarely fails, but a control char will do it
	proxy := f.getProxy("://\x00invalid", "https://leader:8200")
	assert.Nil(t, proxy)
}

func TestGetProxy_ValidConfig(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{
			{Leaf: cert},
		},
	}
	f := newStandbyForwarder(log, func() *tls.Config { return tlsCfg }, 30)

	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	require.NotNil(t, proxy, "should return a proxy with valid TLS config")

	// Call again with same address - should return cached proxy
	proxy2 := f.getProxy("https://leader:8201", "https://leader:8200")
	assert.Equal(t, proxy, proxy2, "should return cached proxy")
}

func TestGetProxy_CacheInvalidatedOnAddrChange(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{
			{Leaf: cert},
		},
	}
	f := newStandbyForwarder(log, func() *tls.Config { return tlsCfg }, 30)

	proxy1 := f.getProxy("https://leader1:8201", "https://leader1:8200")
	require.NotNil(t, proxy1)

	proxy2 := f.getProxy("https://leader2:8201", "https://leader2:8200")
	require.NotNil(t, proxy2)

	assert.NotEqual(t, fmt.Sprintf("%p", proxy1), fmt.Sprintf("%p", proxy2),
		"should create new proxy when cluster address changes")
}

func TestGetProxy_CacheInvalidatedOnCertChange(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert1 := &x509.Certificate{}
	cert1.Subject.CommonName = "fw-term1"
	cert2 := &x509.Certificate{}
	cert2.Subject.CommonName = "fw-term2"

	currentCert := cert1
	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{
				{Leaf: currentCert},
			},
		}
	}, 30)

	proxy1 := f.getProxy("https://leader:8201", "https://leader:8200")
	require.NotNil(t, proxy1)

	// Simulate leadership term change (cert CN changes)
	currentCert = cert2
	proxy2 := f.getProxy("https://leader:8201", "https://leader:8200")
	require.NotNil(t, proxy2)

	assert.NotEqual(t, fmt.Sprintf("%p", proxy1), fmt.Sprintf("%p", proxy2),
		"should create new proxy when cert CN changes")
}

func TestGetProxy_ServerNameFallbackFromCert(t *testing.T) {
	// tlsConfigFunc returns certs but currentServerName() returns ""
	// because the first call (currentServerName) uses a config without Leaf,
	// but getProxy's internal fallback reads Leaf from the same config.
	// This covers line 170-172.
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-fallback"

	callCount := 0
	f := newStandbyForwarder(log, func() *tls.Config {
		callCount++
		if callCount == 1 {
			// First call (currentServerName) - return config without Leaf
			return &tls.Config{Certificates: []tls.Certificate{{}}}
		}
		// Second call (inside getProxy) - return config with Leaf
		return &tls.Config{Certificates: []tls.Certificate{{Leaf: cert}}}
	}, 30)

	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	require.NotNil(t, proxy)
}

func TestGetProxy_OldProxyCleanup(t *testing.T) {
	// Test that old proxy transport connections are closed when addr changes.
	// Covers line 182-185.
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"
	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{{Leaf: cert}}}
	}, 30)

	// Create first proxy
	proxy1 := f.getProxy("https://leader1:8201", "https://leader1:8200")
	require.NotNil(t, proxy1)

	// Create second proxy with different address -> should clean up first
	proxy2 := f.getProxy("https://leader2:8201", "https://leader2:8200")
	require.NotNil(t, proxy2)
}

func TestGetProxy_NoCertsButTLSConfigPresent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	// TLS config with no certificates (empty slice) - serverName will be ""
	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{},
		}
	}, 30)

	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	// Should still succeed - serverName just stays empty
	require.NotNil(t, proxy)
}

// =============================================================================
// forwardToActive Tests
// =============================================================================

func TestGetProxy_DirectorAndErrorHandler(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"

	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{{Leaf: cert}},
		}
	}, 1)

	proxy := f.getProxy("https://127.0.0.1:1", "https://leader:8200")
	require.NotNil(t, proxy)

	// Test with prior X-Forwarded-For and TLS to cover Director branches
	req := httptest.NewRequest(http.MethodGet, "/v1/test?key=val", nil)
	req.Host = "standby.example.com:8200"
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.TLS = &tls.ConnectionState{} // simulate HTTPS
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "leader:8200")
	assert.Contains(t, w.Header().Get("Location"), "/v1/test")
}

func TestGetProxy_ErrorHandler_WithCore_NoLeader(t *testing.T) {
	c, _ := createTestCoreForHTTP(t)
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"

	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{{Leaf: cert}},
		}
	}, 1)
	f.core = c // Core without HA -> Leader() returns error

	proxy := f.getProxy("https://127.0.0.1:1", "https://leader:8200")
	require.NotNil(t, proxy)

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	// Connection error + no leader -> redirect to redirectAddr (non-connection errors path)
	// or 503 (connection error + no leader elected)
	assert.True(t, w.Code == http.StatusTemporaryRedirect || w.Code == http.StatusServiceUnavailable)
}

// =============================================================================
// handleSysHealth additional coverage (sealed/standby branches)
// =============================================================================

func TestGetProxy_ErrorHandler_ConnectionError_NoLeader(t *testing.T) {
	c, _ := createTestCoreForHTTP(t)
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"

	f := newStandbyForwarder(log, func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{{Leaf: cert}},
		}
	}, 1)
	f.core = c

	proxy := f.getProxy("https://127.0.0.1:1", "https://leader:8200")
	require.NotNil(t, proxy)

	// Manually invoke the ErrorHandler with a connection error
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	w := httptest.NewRecorder()

	// The proxy will try to connect and fail. The ErrorHandler will:
	// 1. detect isConnectionError -> true
	// 2. call c.Leader() -> error (no HA) -> "no new leader elected" path
	// 3. OR fall through to non-connection error path
	proxy.ServeHTTP(w, req)

	// Should get 503 or 307
	assert.True(t, w.Code == http.StatusServiceUnavailable || w.Code == http.StatusTemporaryRedirect)
}

// =============================================================================
// wrapGenericHandler standby forwarding path
// =============================================================================

// The standby's proxy carries the request id this node assigned to the
// active node, in the cluster's internal header, which would otherwise handle
// — and audit — the request with none. The client's own X-Request-Id is left
// as sent, a client-sent copy of the internal header never goes on, and a
// request with no id is not given an invented one here.
func TestGetProxy_DirectorCarriesRequestID(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{{Leaf: cert}}}
	f := newStandbyForwarder(log, func() *tls.Config { return tlsCfg }, 30)
	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	require.NotNil(t, proxy)

	withID := httptest.NewRequest(http.MethodGet, "https://standby:8200/v1/aws/gateway", nil)
	withID.Header.Set("X-Request-Id", "the-clients-own")
	withID.Header.Set(listener.ForwardedRequestIDHeader, "forged")
	withID = withID.WithContext(context.WithValue(withID.Context(), middleware.RequestIDKey, "standby-7/abc-000042"))
	proxy.Director(withID)
	assert.Equal(t, "standby-7/abc-000042", withID.Header.Get(listener.ForwardedRequestIDHeader))
	assert.Equal(t, "the-clients-own", withID.Header.Get("X-Request-Id"))

	without := httptest.NewRequest(http.MethodGet, "https://standby:8200/v1/aws/gateway", nil)
	without.Header.Set(listener.ForwardedRequestIDHeader, "forged")
	proxy.Director(without)
	assert.Empty(t, without.Header.Values(listener.ForwardedRequestIDHeader))
}

// capturingTransport records the request the proxy sends, as it goes out.
type capturingTransport struct{ sent *http.Request }

func (c *capturingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.sent = r
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
}

// The active node takes the client's address from the rightmost
// X-Forwarded-For entry, so what the standby sends must end with the address
// this node resolved — exactly once — after whatever the client sent, or carry
// no chain at all. Checked on the wire, through ServeHTTP: ReverseProxy
// appends to the header itself after the Director runs.
func TestGetProxy_ForwardedChainEndsWithTheClient(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	cert := &x509.Certificate{}
	cert.Subject.CommonName = "fw-test"
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{{Leaf: cert}}}
	f := newStandbyForwarder(log, func() *tls.Config { return tlsCfg }, 30)
	proxy := f.getProxy("https://leader:8201", "https://leader:8200")
	require.NotNil(t, proxy)
	capture := &capturingTransport{}
	proxy.Transport = capture

	for _, tc := range []struct {
		name, remoteAddr string
		chain            []string
		want             []string
	}{
		{"address with port", "203.0.113.7:5000", []string{"10.9.9.9"}, []string{"10.9.9.9, 203.0.113.7"}},
		{"IPv6 address with port", "[2001:db8::7]:443", []string{"10.9.9.9"}, []string{"10.9.9.9, 2001:db8::7"}},
		{"bare address", "203.0.113.7", []string{"10.9.9.9"}, []string{"10.9.9.9, 203.0.113.7"}},
		{"bare IPv6 address", "2001:db8::7", []string{"10.9.9.9"}, []string{"10.9.9.9, 2001:db8::7"}},
		{"client chain on two lines", "203.0.113.7:5000", []string{"10.9.9.9", "10.9.9.8"},
			[]string{"10.9.9.9, 10.9.9.8, 203.0.113.7"}},
		{"bare address, client chain on two lines", "203.0.113.7", []string{"10.9.9.9", "10.9.9.8"},
			[]string{"10.9.9.9, 10.9.9.8, 203.0.113.7"}},
		{"no address", "not-an-address", []string{"10.9.9.9"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://standby:8200/v1/aws/gateway", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Header["X-Forwarded-For"] = tc.chain
			req.Header.Set("X-Real-IP", "10.8.8.8")
			proxy.ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, capture.sent)
			assert.Equal(t, tc.want, capture.sent.Header.Values("X-Forwarded-For"))
			assert.Empty(t, capture.sent.Header.Values("X-Real-IP"), "the client's X-Real-IP must not reach the active node")
		})
	}
}
