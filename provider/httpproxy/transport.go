package httpproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
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

// NewTransportWithTLS creates a transport with custom TLS configuration.
// Used when a provider instance has ca_data or tls_skip_verify set, creating
// a per-instance transport instead of sharing the default one.
func NewTransportWithTLS(caData string, skipVerify bool) (*http.Transport, error) {
	t := NewTransport()

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
