package spiffetls

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/spiffe/spiffetest"
)

// --- in-memory x509svid.Source fakes ---

type staticSource struct{ svid *x509svid.SVID }

func (s staticSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

type funcSource func() (*x509svid.SVID, error)

func (f funcSource) GetX509SVID() (*x509svid.SVID, error) { return f() }

func tlsCertOf(svid *x509svid.SVID) tls.Certificate {
	chain := make([][]byte, len(svid.Certificates))
	for i, c := range svid.Certificates {
		chain[i] = c.Raw
	}
	return tls.Certificate{Certificate: chain, PrivateKey: svid.PrivateKey}
}

// startTLSServer serves handler over TLS using cfg and returns the address and a
// stop func. The raw TCP listener is wrapped with cfg so the SPIFFE GetCertificate
// callback drives the handshake, mirroring the API listener.
func startTLSServer(t *testing.T, cfg *tls.Config, handler http.Handler) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: handler}
	go srv.Serve(tls.NewListener(ln, cfg))
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// --- builder shape ---

func TestBuildServerTLSConfig_ServerAuth(t *testing.T) {
	ca, caKey := spiffetest.CA(t)
	svid := spiffetest.SVID(t, ca, caKey, "spiffe://example.org/warden")

	cfg := BuildServerTLSConfig(staticSource{svid}, false)

	require.NotNil(t, cfg.GetCertificate, "serving cert must come from GetCertificate")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth, "server-auth must not request a client cert")
	assert.Nil(t, cfg.VerifyPeerCertificate, "listener must not verify peers")
	assert.Nil(t, cfg.ClientCAs)
}

func TestBuildServerTLSConfig_RequestClientCert(t *testing.T) {
	ca, caKey := spiffetest.CA(t)
	svid := spiffetest.SVID(t, ca, caKey, "spiffe://example.org/warden")

	cfg := BuildServerTLSConfig(staticSource{svid}, true)

	require.NotNil(t, cfg.GetCertificate)
	assert.Equal(t, tls.RequestClientCert, cfg.ClientAuth, "must request but not require/verify the peer cert")
	assert.Nil(t, cfg.VerifyPeerCertificate, "no TLS-layer peer validation")
	assert.Nil(t, cfg.ClientCAs, "no peer CA; the auth method validates the SVID")
}

// --- real handshakes ---

func TestServerAuth_Serves(t *testing.T) {
	ca, caKey := spiffetest.CA(t)
	svid := spiffetest.SVID(t, ca, caKey, "spiffe://example.org/warden")
	bundle := spiffetest.Bundle(t, "example.org", ca)

	addr, _ := startTLSServer(t, BuildServerTLSConfig(staticSource{svid}, false),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))

	// A SPIFFE-aware client: verifies the server SVID against the bundle and
	// skips hostname verification (the SVID has a URI SAN, no DNS SAN).
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeAny())},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("https://" + addr)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(body))
}

// TestCaptureWithoutValidation is the crux of the layering decision: with
// request-client-cert on, the listener captures whatever the peer presents
// (a valid SVID, a foreign SVID, a non-SVID cert, or nothing) and NEVER rejects
// it — leaving authentication to the auth method.
func TestCaptureWithoutValidation(t *testing.T) {
	ca, caKey := spiffetest.CA(t)
	serverSVID := spiffetest.SVID(t, ca, caKey, "spiffe://example.org/warden")
	serverBundle := spiffetest.Bundle(t, "example.org", ca)

	// Handler echoes "<#peer-certs>|<first-uri-san>" so we can assert what was captured.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, uri := 0, ""
		if r.TLS != nil {
			n = len(r.TLS.PeerCertificates)
			if n > 0 && len(r.TLS.PeerCertificates[0].URIs) > 0 {
				uri = r.TLS.PeerCertificates[0].URIs[0].String()
			}
		}
		fmt.Fprintf(w, "%d|%s", n, uri)
	})
	addr, _ := startTLSServer(t, BuildServerTLSConfig(staticSource{serverSVID}, true), handler)

	// Distinct CAs/domains for the client certs; the server trusts none of them.
	otherCA, otherKey := spiffetest.CA(t)
	validClient := spiffetest.SVID(t, otherCA, otherKey, "spiffe://example.org/client")
	foreignClient := spiffetest.SVID(t, otherCA, otherKey, "spiffe://other.org/client")
	classicLeaf, classicKey := spiffetest.LeafCert(t, otherCA, otherKey, "") // no URI SAN

	cases := []struct {
		name    string
		cert    *tls.Certificate
		wantN   string
		wantURI string
	}{
		{"valid client SVID", ptr(tlsCertOf(validClient)), "1", "spiffe://example.org/client"},
		{"foreign-domain SVID", ptr(tlsCertOf(foreignClient)), "1", "spiffe://other.org/client"},
		{"non-SVID classic cert", &tls.Certificate{Certificate: [][]byte{classicLeaf.Raw}, PrivateKey: classicKey}, "1", ""},
		{"no client cert", nil, "0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientCfg := tlsconfig.TLSClientConfig(serverBundle, tlsconfig.AuthorizeAny())
			if tc.cert != nil {
				clientCfg.Certificates = []tls.Certificate{*tc.cert}
			}
			client := &http.Client{
				Transport: &http.Transport{TLSClientConfig: clientCfg, DisableKeepAlives: true},
				Timeout:   5 * time.Second,
			}
			resp, err := client.Get("https://" + addr)
			require.NoError(t, err, "handshake must succeed regardless of the client cert")
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, tc.wantN+"|"+tc.wantURI, string(body))
		})
	}
}

// TestPerHandshakeFreshness proves the wiring re-reads the source on every
// handshake (transparent rotation) without a real Workload API.
func TestPerHandshakeFreshness(t *testing.T) {
	ca, caKey := spiffetest.CA(t)
	first := spiffetest.SVID(t, ca, caKey, "spiffe://example.org/warden")
	second := spiffetest.SVID(t, ca, caKey, "spiffe://example.org/warden")
	require.NotEqual(t, first.Certificates[0].SerialNumber, second.Certificates[0].SerialNumber)
	bundle := spiffetest.Bundle(t, "example.org", ca)

	var calls int32
	src := funcSource(func() (*x509svid.SVID, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return first, nil
		}
		return second, nil
	})

	addr, _ := startTLSServer(t, BuildServerTLSConfig(src, false),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// DisableKeepAlives forces a fresh handshake per request.
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeAny()), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}

	serial := func() string {
		resp, err := client.Get("https://" + addr)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.NotNil(t, resp.TLS)
		require.NotEmpty(t, resp.TLS.PeerCertificates)
		return resp.TLS.PeerCertificates[0].SerialNumber.String()
	}

	s1, s2 := serial(), serial()
	assert.Equal(t, first.Certificates[0].SerialNumber.String(), s1)
	assert.Equal(t, second.Certificates[0].SerialNumber.String(), s2)
	assert.NotEqual(t, s1, s2, "each handshake should serve the then-current SVID")
}

// TestNewSource_FailClosed confirms an unreachable socket fails closed within the
// startup budget rather than hanging or falling back.
func TestNewSource_FailClosed(t *testing.T) {
	start := time.Now()
	src, err := NewSource(context.Background(), "unix:///nonexistent/warden-spiffetest.sock", 500*time.Millisecond)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, src)
	assert.Contains(t, err.Error(), "unavailable")
	assert.Less(t, elapsed, 5*time.Second, "should fail within ~startupTimeout, not hang")
}

func ptr(c tls.Certificate) *tls.Certificate { return &c }
