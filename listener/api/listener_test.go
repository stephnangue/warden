package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// NewApiListener Tests
// =============================================================================

func TestNewApiListener_PlainHTTP(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:  log,
		Address: "127.0.0.1:0",
	}, http.DefaultServeMux)

	require.NoError(t, err)
	require.NotNil(t, ln)
	assert.Equal(t, "127.0.0.1:0", ln.Addr())
	assert.Equal(t, "api", ln.Type())
	assert.False(t, ln.tlsEnabled)
}

func TestNewApiListener_TLSEnabled(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, _ := generateTestCertFiles(t)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:      log,
		Address:     "127.0.0.1:0",
		TLSEnabled:  true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, http.DefaultServeMux)

	require.NoError(t, err)
	require.NotNil(t, ln)
	assert.True(t, ln.tlsEnabled)
	assert.NotNil(t, ln.server.TLSConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), ln.server.TLSConfig.MinVersion)
}

func TestNewApiListener_TLSEnabled_MissingCertFile(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:     log,
		Address:    "127.0.0.1:0",
		TLSEnabled: true,
		TLSKeyFile: "/some/key.pem",
	}, http.DefaultServeMux)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tls_cert_file")
	assert.Nil(t, ln)
}

func TestNewApiListener_TLSEnabled_MissingKeyFile(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:      log,
		Address:     "127.0.0.1:0",
		TLSEnabled:  true,
		TLSCertFile: "/some/cert.pem",
	}, http.DefaultServeMux)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tls_key_file")
	assert.Nil(t, ln)
}

func TestNewApiListener_TLSWithClientCA(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, caFile := generateTestCertFiles(t)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:          log,
		Address:         "127.0.0.1:0",
		TLSEnabled:      true,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: caFile,
	}, http.DefaultServeMux)

	require.NoError(t, err)
	require.NotNil(t, ln)
	assert.Equal(t, tls.RequireAndVerifyClientCert, ln.server.TLSConfig.ClientAuth)
	assert.NotNil(t, ln.server.TLSConfig.ClientCAs)
}

func TestNewApiListener_TLSWithInvalidClientCA(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, _ := generateTestCertFiles(t)

	// Write a file with invalid PEM content
	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	os.WriteFile(badCA, []byte("not a certificate"), 0o600)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:          log,
		Address:         "127.0.0.1:0",
		TLSEnabled:      true,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: badCA,
	}, http.DefaultServeMux)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
	assert.Nil(t, ln)
}

func TestNewApiListener_TLSWithMissingClientCAFile(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, _ := generateTestCertFiles(t)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:          log,
		Address:         "127.0.0.1:0",
		TLSEnabled:      true,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: "/nonexistent/ca.pem",
	}, http.DefaultServeMux)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read tls_client_ca_file")
	assert.Nil(t, ln)
}

// =============================================================================
// TLS Server Tests
// =============================================================================

func TestApiListener_HTTPS_AcceptsConnection(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, _ := generateTestCertFiles(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:      log,
		Address:     addr,
		TLSEnabled:  true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Client trusting the test CA
	caCert, err := os.ReadFile(certFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		}},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/test", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(body))
}

func TestApiListener_HTTPS_RejectsPlainHTTP(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, _ := generateTestCertFiles(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:      log,
		Address:     addr,
		TLSEnabled:  true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Plain HTTP to an HTTPS server should get a 400 Bad Request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/test", addr))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// =============================================================================
// mTLS Tests
// =============================================================================

func TestApiListener_mTLS_AcceptsValidClientCert(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, caFile := generateTestCertFiles(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "mtls-ok")
	})

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:          log,
		Address:         addr,
		TLSEnabled:      true,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: caFile,
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Load the same cert as client cert (self-signed CA scenario)
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
		}},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/test", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "mtls-ok", string(body))
}

func TestApiListener_mTLS_RejectsNoClientCert(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, caFile := generateTestCertFiles(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:          log,
		Address:         addr,
		TLSEnabled:      true,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		TLSClientCAFile: caFile,
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	// Client trusts the server but provides no client cert
	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		}},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get(fmt.Sprintf("https://%s/test", addr))
	assert.Error(t, err, "connection without client cert should be rejected")
}

// =============================================================================
// Stop Idempotent Test
// =============================================================================

func TestApiListener_StopIdempotent(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	certFile, keyFile, _ := generateTestCertFiles(t)

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:      log,
		Address:     addr,
		TLSEnabled:  true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, http.DefaultServeMux)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	err = ln.Stop()
	assert.NoError(t, err)

	// Second stop should also succeed (idempotent)
	err = ln.Stop()
	assert.NoError(t, err)
}

func TestApiListener_PlainHTTP_Serves(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "plain-ok")
	})

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := NewApiListener(ApiListenerConfig{
		Logger:  log,
		Address: addr,
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ln.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	defer ln.Stop()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/test", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "plain-ok", string(body))
}

// =============================================================================
// Helpers
// =============================================================================

// generateTestCertFiles creates a self-signed cert/key pair and writes them
// to temporary files. Returns paths to cert, key, and CA (same as cert for
// self-signed) files.
func generateTestCertFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test-api-listener"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	dir := t.TempDir()

	// Write cert PEM
	certFile = filepath.Join(dir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))

	// Write key PEM
	keyFile = filepath.Join(dir, "key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	// CA file is the same as cert (self-signed)
	caFile = certFile

	return certFile, keyFile, caFile
}

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
