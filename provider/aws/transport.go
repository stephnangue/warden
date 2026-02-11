package aws

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

var (
	sharedTransport        *http.Transport
	transportCleanupCtx    context.Context
	transportCleanupCancel context.CancelFunc
)

func init() {
	sharedTransport = newTransport()

	// Start background cleanup with proper lifecycle management
	transportCleanupCtx, transportCleanupCancel = context.WithCancel(context.Background())
	go cleanupIdleConnections(transportCleanupCtx, sharedTransport)
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

// cleanupIdleConnections periodically closes idle connections
func cleanupIdleConnections(ctx context.Context, transport *http.Transport) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			transport.CloseIdleConnections()
		}
	}
}

// ShutdownHTTPTransport should be called during application shutdown
func ShutdownHTTPTransport() {
	if transportCleanupCancel != nil {
		transportCleanupCancel()
	}
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
