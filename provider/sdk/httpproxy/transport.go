package httpproxy

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/stephnangue/warden/framework"
)

// newBaseTransport creates an HTTP transport with shared pool/dialer/timeout
// settings but without TLS or HTTP/2 configuration applied.
func newBaseTransport() *http.Transport {
	return &http.Transport{
		// Connection pool settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     0, // Unlimited outbound connections
		IdleConnTimeout:     90 * time.Second,

		// TLS handshake timeout
		TLSHandshakeTimeout: 10 * time.Second,

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
}

// NewTransport creates a new HTTP transport suitable for API proxy workloads.
// Each provider package should call this once at package init time to create
// a shared transport for all instances of that provider type.
func NewTransport() *http.Transport {
	transport := newBaseTransport()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
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
	t := newBaseTransport()

	tlsConfig, err := framework.NewTLSClientConfig(caData, skipVerify)
	if err != nil {
		return nil, err
	}

	t.TLSClientConfig = tlsConfig

	// Configure HTTP/2 after TLSClientConfig is set so the h2 wiring binds to the
	// correct tls.Config. How that wiring is recorded depends on the compiling
	// toolchain — a protocol set on the transport, or an ALPN entry on the TLS
	// config — so read it back through a helper rather than by field.
	if err := http2.ConfigureTransport(t); err != nil {
		log.Printf("Failed to configure HTTP/2 for httpproxy TLS transport: %v", err)
	}

	return t, nil
}

// ShutdownTransport closes idle connections on the transport.
// Called during application shutdown for a clean exit.
func ShutdownTransport(transport *http.Transport) {
	if transport != nil {
		transport.CloseIdleConnections()
	}
}

// DefaultNewTransport creates a standard transport and returns it
// with a shutdown function. Used as the default when ProviderSpec.NewTransport is nil.
func DefaultNewTransport() (*http.Transport, func()) {
	t := NewTransport()
	return t, func() { ShutdownTransport(t) }
}
