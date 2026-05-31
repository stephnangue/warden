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
	"net/http"
	"time"
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
// Returns an error if caPEM is non-empty but contains no valid PEM
// certificates.
func BuildHTTPClient(caPEM []byte, skipVerify bool, timeout time.Duration) (*http.Client, error) {
	if len(caPEM) == 0 && !skipVerify {
		return &http.Client{Timeout: timeout}, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

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
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}
