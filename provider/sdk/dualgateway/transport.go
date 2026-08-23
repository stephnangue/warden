package dualgateway

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/stephnangue/warden/framework"
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

// newBaseTransport builds the pool, dialer and timeout profile every dual-mode
// gateway transport shares, with neither TLS nor HTTP/2 applied. Both are the
// caller's to add, in that order: ConfigureTransport binds to whichever
// tls.Config is installed when it runs, so assigning one afterwards leaves the
// h2 wiring pointing at the config it replaced.
func newBaseTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,

		TLSHandshakeTimeout: 10 * time.Second,

		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

func newTransport() *http.Transport {
	transport := newBaseTransport()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("Failed to configure HTTP/2: %v", err)
	}

	return transport
}

// newTransportWithTLS builds a transport for one mount whose upstream needs
// trust settings the shared one cannot carry — a private authority, or
// verification disabled for a local test endpoint. Same profile as the shared
// transport in every other respect.
func newTransportWithTLS(caData string, skipVerify bool) (*http.Transport, error) {
	tlsConfig, err := framework.NewTLSClientConfig(caData, skipVerify)
	if err != nil {
		return nil, err
	}

	transport := newBaseTransport()
	transport.TLSClientConfig = tlsConfig

	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("Failed to configure HTTP/2: %v", err)
	}

	return transport, nil
}

// ShutdownHTTPTransport should be called during application shutdown.
func ShutdownHTTPTransport() {
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
