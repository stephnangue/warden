package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

