package dualgateway

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
		sharedTransport = newTransport()
	})
}

func newTransport() *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,

		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		},

		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("Failed to configure HTTP/2: %v", err)
	}

	return transport
}

// ShutdownHTTPTransport should be called during application shutdown.
func ShutdownHTTPTransport() {
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
