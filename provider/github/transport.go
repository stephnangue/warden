package github

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
	sharedTransport = newGitHubTransport()

	// Start background cleanup with proper lifecycle management
	transportCleanupCtx, transportCleanupCancel = context.WithCancel(context.Background())
	go cleanupIdleConnections(transportCleanupCtx, sharedTransport)
}

// newGitHubTransport creates an HTTP transport optimized for GitHub API workloads
func newGitHubTransport() *http.Transport {
	transport := &http.Transport{
		// Connection pool settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     0, // Unlimited outbound connections
		IdleConnTimeout:     90 * time.Second,

		// TLS configuration
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		},

		// Dialer settings
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// Timeout settings
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,

		// HTTP/2 optimization
		ForceAttemptHTTP2: true,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("Failed to configure HTTP/2 for GitHub transport: %v", err)
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
