// Package httputil provides HTTP client utilities shared across Warden:
// auth methods (e.g. kubernetes TokenReview), credential drivers
// (e.g. AWS STS, GCP token exchange), and provider SDKs. The helpers
// here are deliberately format-neutral and do not depend on the
// credential package — callers extract config values themselves and
// pass typed primitives.
package httputil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Pool sized for concurrent calls to one upstream: a source's mints on cache
// misses, a rotation's burst. The standard library keeps two idle connections per
// host, so every connection past the second is closed after use and the next call
// pays a new handshake.
const (
	maxIdleConns        = 100
	maxIdleConnsPerHost = 50
	idleConnTimeout     = 90 * time.Second
)

// BuildHTTPClient returns an *http.Client configured for calls that may
// need a non-system root CA bundle and/or TLS verification disabled.
//
//   - caPEM is the PEM-encoded CA bundle as raw bytes. Pass nil/empty
//     to use the system roots.
//   - skipVerify disables certificate validation (test/dev only).
//   - timeout is the per-request timeout. Pass 0 to use no timeout
//     (the client will block until the connection terminates).
//
// Every call returns a client with its own transport and connection pool, so
// CloseIdleConnections on it releases only its own connections — never those of
// another client, or of the process-wide default transport. Requests honour the
// HTTPS_PROXY, HTTP_PROXY and NO_PROXY environment variables whatever the TLS
// settings.
//
// Returns an error if caPEM is non-empty but contains no valid PEM
// certificates.
func BuildHTTPClient(caPEM []byte, skipVerify bool, timeout time.Duration) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Resumes a session on reconnect instead of a full handshake.
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	if skipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("ca bundle contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: newTransport(tlsConfig),
	}, nil
}

// newTransport builds a pooled transport around tlsConfig. The client's Timeout
// bounds a whole call, so no response-header timeout is set here.
func newTransport(tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// A custom TLS config otherwise turns HTTP/2 off.
		ForceAttemptHTTP2: true,
		// An HTTP/2 connection an intermediary dropped silently would hang every
		// request multiplexed on it until the client's Timeout, and is not marked
		// broken the way an HTTP/1 connection is after a read error. A ping after
		// 30s without a frame finds it.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second},
	}
}
