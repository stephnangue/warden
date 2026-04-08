package aws

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
		sharedTransport = newTransport()
	})
}

// newTransport creates an HTTP transport optimized for AWS workloads
func newTransport() *http.Transport {
	transport := &http.Transport{
		// Connection pool settings
		// Higher limits for parallel AWS API calls
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     0,                // Unlimited outbound connections
		IdleConnTimeout:     90 * time.Second, // AWS recommends < 120s

		// TLS configuration
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Enable session resumption for faster TLS handshakes
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		},

		// Dialer settings
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// Timeout settings to prevent hanging requests
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,

		// HTTP/2 optimization
		ForceAttemptHTTP2: true,
	}

	// Enable HTTP/2 with error handling
	if err := http2.ConfigureTransport(transport); err != nil {
		// Log error but don't fail - will fall back to HTTP/1.1
		log.Printf("Failed to configure HTTP/2: %v", err)
	}

	return transport
}

// newTransportWithTLS creates an HTTP transport with custom TLS configuration.
func newTransportWithTLS(caData string, skipVerify bool) (*http.Transport, error) {
	t := newTransport()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
		InsecureSkipVerify: skipVerify,
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

	t.TLSClientConfig = tlsConfig
	return t, nil
}

// ShutdownHTTPTransport should be called during application shutdown
func ShutdownHTTPTransport() {
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
