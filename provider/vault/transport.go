package vault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var (
	sharedTransport *http.Transport
	transportOnce   sync.Once
)

func initTransport() {
	transportOnce.Do(func() {
		t, _ := newVaultTransport("", false)
		sharedTransport = t
	})
}

// newVaultTransport creates an HTTP transport optimized for Vault workloads
func newVaultTransport(caData string, tlsSkipVerify bool) (*http.Transport, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
		InsecureSkipVerify: tlsSkipVerify,
	}

	if caData != "" {
		pemBytes, err := base64.StdEncoding.DecodeString(caData)
		if err != nil {
			return nil, fmt.Errorf("ca_data is not valid base64: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ca_data contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{
		// Connection pool settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     0, // Unlimited outbound connections
		IdleConnTimeout:     90 * time.Second,

		// TLS configuration
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,

		// Dialer settings
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// Timeout settings to prevent hanging requests
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,

		// HTTP/2 optimization
		ForceAttemptHTTP2: true,
	}

	// Enable HTTP/2 with error handling
	if err := http2.ConfigureTransport(transport); err != nil {
		// Log error but don't fail - will fall back to HTTP/1.1
		log.Printf("Failed to configure HTTP/2: %v", err)
	}

	return transport, nil
}

// ShutdownHTTPTransport should be called during application shutdown
func ShutdownHTTPTransport() {
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
