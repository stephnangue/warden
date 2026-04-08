package vault

import (
	"crypto/tls"
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
		sharedTransport = newVaultTransport(false)
	})
}

// newVaultTransport creates an HTTP transport optimized for Vault workloads
func newVaultTransport(tlsSkipVerify bool) *http.Transport {
	transport := &http.Transport{
		// Connection pool settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     0, // Unlimited outbound connections
		IdleConnTimeout:     90 * time.Second,

		// TLS configuration
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Enable session resumption for faster TLS handshakes
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
			InsecureSkipVerify: tlsSkipVerify,
		},

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

	return transport
}

// ShutdownHTTPTransport should be called during application shutdown
func ShutdownHTTPTransport() {
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
