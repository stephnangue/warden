// Package spiffetls builds an in-memory, auto-rotating TLS serving identity from
// the SPIFFE Workload API (go-spiffe's workloadapi.X509Source), wired into a
// tls.Config via the GetCertificate callback so the current X509-SVID is fetched
// on every handshake and no key or cert is ever written to disk.
//
// The package deliberately does NO client-SVID validation: when client-cert
// capture is enabled it requests (but does not verify or require) the peer cert,
// leaving authentication and authorization to the auth method. It imports only
// go-spiffe and crypto/tls — never any auth/* package.
package spiffetls

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// DefaultStartupTimeout bounds how long NewSource waits (and retries) for the
// first SVID before failing closed.
const DefaultStartupTimeout = 10 * time.Second

// Source owns a workloadapi.X509Source and exposes it as an x509svid.Source.
// One Source can back multiple listeners that share the same Workload API
// socket. It must be Close()d to stop the background rotation stream.
type Source struct {
	x *workloadapi.X509Source
}

// NewSource dials the SPIFFE Workload API and returns a Source backed by an
// auto-rotating X509Source. It blocks until the first SVID is received or
// startupTimeout elapses; while the socket is unreachable the underlying client
// retries with backoff, so startupTimeout doubles as the retry budget. A
// persistent outage fails closed with a wrapped error (there is no disk-cert
// fallback).
//
// socketAddr is the Workload API endpoint (e.g. "unix:///run/spire/agent.sock").
// When empty, go-spiffe reads the SPIFFE_ENDPOINT_SOCKET environment variable.
//
// parentCtx governs only startup; the ongoing rotation watch runs on an internal
// context and is stopped by Close(), so callers may pass a request-scoped or
// process-scoped context without affecting rotation.
func NewSource(parentCtx context.Context, socketAddr string, startupTimeout time.Duration) (*Source, error) {
	if startupTimeout <= 0 {
		startupTimeout = DefaultStartupTimeout
	}

	var opts []workloadapi.X509SourceOption
	if socketAddr != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)))
	}

	ctx, cancel := context.WithTimeout(parentCtx, startupTimeout)
	defer cancel()

	x, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("spiffetls: workload API X509 source unavailable (socket %s): %w", displaySocket(socketAddr), err)
	}
	return &Source{x: x}, nil
}

// Close stops the rotation stream and releases the underlying connection.
func (s *Source) Close() error {
	return s.x.Close()
}

// GetX509SVID implements x509svid.Source by delegating to the workload source,
// returning the current in-memory SVID.
func (s *Source) GetX509SVID() (*x509svid.SVID, error) {
	return s.x.GetX509SVID()
}

var _ x509svid.Source = (*Source)(nil)

// BuildServerTLSConfig builds a server tls.Config whose GetCertificate callback
// resolves the serving SVID from svid on every handshake (transparent rotation).
//
// When requestClientCert is true the config requests and captures the peer's
// client cert (tls.RequestClientCert) WITHOUT verifying or requiring it: the cert
// lands in ConnectionState.PeerCertificates for the auth method to validate, and
// clients without a cert still connect. The TLS layer performs no peer
// validation by design.
func BuildServerTLSConfig(svid x509svid.Source, requestClientCert bool) *tls.Config {
	cfg := tlsconfig.TLSServerConfig(svid)
	if requestClientCert {
		cfg.ClientAuth = tls.RequestClientCert
	}
	return cfg
}

func displaySocket(addr string) string {
	if addr == "" {
		return "$SPIFFE_ENDPOINT_SOCKET"
	}
	return addr
}
