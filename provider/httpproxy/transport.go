package httpproxy

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// NewTransport creates a new HTTP transport suitable for API proxy workloads.
// Each provider package should call this once at package init time to create
// a shared transport for all instances of that provider type.
func NewTransport() *http.Transport {
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

		// Timeout settings — higher for AI inference (streaming responses can be slow)
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,

		// HTTP/2 optimization
		ForceAttemptHTTP2: true,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("Failed to configure HTTP/2 for httpproxy transport: %v", err)
	}

	return transport
}

// StartCleanup starts a background goroutine that periodically closes idle connections.
// Returns a cancel function to stop the cleanup goroutine.
func StartCleanup(transport *http.Transport) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
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
	}()
	return cancel
}

// ShutdownTransport stops the cleanup goroutine and closes idle connections.
func ShutdownTransport(transport *http.Transport, cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
	if transport != nil {
		transport.CloseIdleConnections()
	}
}
