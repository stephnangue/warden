package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestClusterTLSConfig creates a self-signed P-521 cert and key
// pair suitable for cluster mTLS testing, returning a *tls.Config.
func generateTestClusterTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test-cluster"},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
			Leaf:        parsed,
		}},
		RootCAs:    pool,
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
}

// =============================================================================
// NewClusterListener Tests
// =============================================================================

func TestNewClusterListener_Success(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	tlsCfg := generateTestClusterTLSConfig(t)
	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       "127.0.0.1:0",
		Handler:       http.DefaultServeMux,
		TLSConfigFunc: func() *tls.Config { return tlsCfg },
	})

	require.NoError(t, err)
	require.NotNil(t, ln)
	assert.Equal(t, "127.0.0.1:0", ln.Addr())
	assert.Equal(t, "cluster", ln.Type())
}

func TestNewClusterListener_NilTLSConfigFunc(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       "127.0.0.1:0",
		Handler:       http.DefaultServeMux,
		TLSConfigFunc: nil,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS config function")
	assert.Nil(t, ln)
}

func TestClusterListener_Type(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       "127.0.0.1:0",
		Handler:       http.DefaultServeMux,
		TLSConfigFunc: func() *tls.Config { return nil },
	})
	require.NoError(t, err)
	assert.Equal(t, "cluster", ln.Type())
}

func TestClusterListener_StopIdempotent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	tlsCfg := generateTestClusterTLSConfig(t)
	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       "127.0.0.1:0",
		Handler:       http.DefaultServeMux,
		TLSConfigFunc: func() *tls.Config { return tlsCfg },
	})
	require.NoError(t, err)

	// Start in background
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- ln.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Stop should succeed
	err = ln.Stop()
	assert.NoError(t, err)

	// Second stop should also succeed (idempotent)
	err = ln.Stop()
	assert.NoError(t, err)

	cancel()
}

// =============================================================================
// mTLS Enforcement Tests
// =============================================================================

func TestClusterListener_mTLS_AcceptsValidClient(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	tlsCfg := generateTestClusterTLSConfig(t)

	// Create a handler that responds with 200
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Find a free port
	freePort := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort)

	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       addr,
		Handler:       handler,
		TLSConfigFunc: func() *tls.Config { return tlsCfg },
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Create a client with the same cert (valid mTLS peer)
	clientTLS := &tls.Config{
		Certificates: tlsCfg.Certificates,
		RootCAs:      tlsCfg.RootCAs,
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/v1/sys/health", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(body))
}

func TestClusterListener_mTLS_RejectsNoClientCert(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	tlsCfg := generateTestClusterTLSConfig(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	freePort := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort)

	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       addr,
		Handler:       handler,
		TLSConfigFunc: func() *tls.Config { return tlsCfg },
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Client with NO client certificate but trusting the server cert
	clientTLS := &tls.Config{
		RootCAs: tlsCfg.RootCAs,
		// No Certificates — should be rejected
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
		Timeout:   5 * time.Second,
	}

	_, err = client.Get(fmt.Sprintf("https://%s/v1/sys/health", addr))
	assert.Error(t, err, "connection without client cert should be rejected")
}

func TestClusterListener_mTLS_RejectsWrongClientCert(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	serverTLSCfg := generateTestClusterTLSConfig(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	freePort := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort)

	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       addr,
		Handler:       handler,
		TLSConfigFunc: func() *tls.Config { return serverTLSCfg },
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Generate a different, unrelated cert for the client
	wrongCert := generateTestClusterTLSConfig(t)

	clientTLS := &tls.Config{
		Certificates: wrongCert.Certificates, // wrong cert
		RootCAs:      serverTLSCfg.RootCAs,   // trust the server
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
		Timeout:   5 * time.Second,
	}

	_, err = client.Get(fmt.Sprintf("https://%s/v1/sys/health", addr))
	assert.Error(t, err, "connection with wrong client cert should be rejected")
}

// =============================================================================
// Dynamic TLS Config Tests
// =============================================================================

func TestClusterListener_DynamicTLSConfig(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	// Start with first config
	tlsCfg1 := generateTestClusterTLSConfig(t)
	currentCfg := tlsCfg1

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	freePort := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort)

	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:  log,
		Address: addr,
		Handler: handler,
		TLSConfigFunc: func() *tls.Config {
			return currentCfg
		},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// First request with config 1 — should succeed
	client1 := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: tlsCfg1.Certificates,
			RootCAs:      tlsCfg1.RootCAs,
		}},
		Timeout: 5 * time.Second,
	}
	resp, err := client1.Get(fmt.Sprintf("https://%s/v1/test", addr))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Rotate to a new config (simulating leadership transition)
	tlsCfg2 := generateTestClusterTLSConfig(t)
	currentCfg = tlsCfg2

	// Request with config 2 — should succeed (dynamic config picks up new cert)
	client2 := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: tlsCfg2.Certificates,
			RootCAs:      tlsCfg2.RootCAs,
		}},
		Timeout: 5 * time.Second,
	}
	resp, err = client2.Get(fmt.Sprintf("https://%s/v1/test", addr))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClusterListener_TLSConfigFunc_ReturnsNil(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	freePort := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort)

	// TLS config func always returns nil (identity not yet available)
	ln, err := NewClusterListener(ClusterListenerConfig{
		Logger:        log,
		Address:       addr,
		Handler:       handler,
		TLSConfigFunc: func() *tls.Config { return nil },
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Any TLS connection should fail because GetConfigForClient returns nil
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
		Timeout:   5 * time.Second,
	}

	_, err = client.Get(fmt.Sprintf("https://%s/v1/test", addr))
	assert.Error(t, err, "connection should fail when TLS identity is not available")
}

// =============================================================================
// Helpers
// =============================================================================

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
