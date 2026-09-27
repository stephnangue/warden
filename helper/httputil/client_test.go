package httputil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCAPEM returns a self-signed CA certificate as raw PEM bytes.
func generateTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// countingServer is a local server that counts the connections clients open to it.
// HTTP/2 stays off: with it on, a pooled client multiplexes over one connection and
// the count would compare protocols rather than connection reuse.
func countingServer(tb testing.TB, useTLS bool) (*httptest.Server, *atomic.Int64) {
	tb.Helper()
	var opened atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			opened.Add(1)
		}
	}
	// A client closing idle connections mid-handshake is expected here; its log line
	// would split a benchmark result line.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if useTLS {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	tb.Cleanup(srv.Close)
	return srv, &opened
}

// serverCAPEM is the PEM of a TLS test server's certificate, to trust it by caPEM.
func serverCAPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

// drain makes one request and reads the response fully, so its connection can be
// reused. A non-2xx answer is an error.
func drain(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

// Every combination of TLS settings yields the same pooled transport; only the trust
// settings differ.
func TestBuildHTTPClient_Transport(t *testing.T) {
	caPEM := generateTestCAPEM(t)
	cases := []struct {
		name       string
		caPEM      []byte
		skipVerify bool
	}{
		{"system roots", nil, false},
		{"skip verify", nil, true},
		{"custom CA", caPEM, false},
		{"custom CA and skip verify", caPEM, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := BuildHTTPClient(tc.caPEM, tc.skipVerify, 30*time.Second)
			require.NoError(t, err)
			assert.Equal(t, 30*time.Second, client.Timeout)

			tr, ok := client.Transport.(*http.Transport)
			require.True(t, ok, "a client must own its transport, not fall back to the default one")
			assert.Equal(t, maxIdleConns, tr.MaxIdleConns)
			assert.Equal(t, maxIdleConnsPerHost, tr.MaxIdleConnsPerHost)
			assert.Equal(t, idleConnTimeout, tr.IdleConnTimeout)
			assert.Equal(t, 10*time.Second, tr.TLSHandshakeTimeout)
			assert.NotNil(t, tr.DialContext)
			assert.True(t, tr.ForceAttemptHTTP2, "a custom TLS config must not turn HTTP/2 off")
			require.NotNil(t, tr.HTTP2)
			assert.Equal(t, 30*time.Second, tr.HTTP2.SendPingTimeout)

			// The standard library reads the proxy environment once per process, so
			// setting it here would prove nothing; check the policy is the standard one.
			require.NotNil(t, tr.Proxy, "requests must honour the proxy environment")
			assert.Equal(t, reflect.ValueOf(http.ProxyFromEnvironment).Pointer(), reflect.ValueOf(tr.Proxy).Pointer())

			cfg := tr.TLSClientConfig
			require.NotNil(t, cfg)
			assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
			assert.NotNil(t, cfg.ClientSessionCache)
			assert.Equal(t, tc.skipVerify, cfg.InsecureSkipVerify)
			assert.Equal(t, tc.caPEM != nil, cfg.RootCAs != nil)
		})
	}
}

func TestBuildHTTPClient_InvalidPEM(t *testing.T) {
	_, err := BuildHTTPClient([]byte("not a PEM certificate"), false, 30*time.Second)
	require.Error(t, err)
}

// Clients never share a transport: closing one's idle connections must not reach
// another's, or the process-wide default transport's.
func TestBuildHTTPClient_IndependentTransports(t *testing.T) {
	a, err := BuildHTTPClient(nil, false, 0)
	require.NoError(t, err)
	b, err := BuildHTTPClient(nil, false, 0)
	require.NoError(t, err)
	assert.NotSame(t, a.Transport, b.Transport)
	assert.NotSame(t, http.DefaultTransport, a.Transport)
	assert.NotSame(t, http.DefaultTransport, b.Transport)
}

// gatedServer holds every request until `want` of them are in flight at once, so a
// round of `want` concurrent requests needs `want` connections at the same moment.
// That makes connection reuse measurable without depending on how the scheduler
// happens to overlap free-running requests.
type gatedServer struct {
	*httptest.Server
	opened atomic.Int64

	mu      sync.Mutex
	want    int
	arrived int
	release chan struct{}
}

func newGatedServer(t *testing.T, want int) *gatedServer {
	t.Helper()
	g := &gatedServer{want: want, release: make(chan struct{})}
	g.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		g.mu.Lock()
		g.arrived++
		release := g.release
		if g.arrived == g.want {
			close(g.release)
			g.release = make(chan struct{})
			g.arrived = 0
		}
		g.mu.Unlock()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			http.Error(w, "the round never filled", http.StatusGatewayTimeout)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	g.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			g.opened.Add(1)
		}
	}
	g.Config.ErrorLog = log.New(io.Discard, "", 0)
	g.StartTLS() // HTTP/2 stays off: one request per connection is what is counted
	t.Cleanup(g.Close)
	return g
}

// A burst of concurrent calls to one upstream leaves its connections pooled for the
// next burst, instead of closing all but two of them.
func TestBuildHTTPClient_ReusesConnections(t *testing.T) {
	const concurrency, rounds = 16, 5
	srv := newGatedServer(t, concurrency)
	client, err := BuildHTTPClient(serverCAPEM(srv.Server), false, 10*time.Second)
	require.NoError(t, err)
	defer client.CloseIdleConnections()

	burst := func() {
		t.Helper()
		var wg sync.WaitGroup
		errs := make([]error, concurrency)
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = drain(client, srv.URL)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
	}

	burst()
	require.Equal(t, int64(concurrency), srv.opened.Load(), "the first burst needs one connection per call")

	for r := 0; r < rounds; r++ {
		burst()
	}
	// Each later burst needs all 16 connections at once. Two idle per host would
	// dial at least 14 per burst — 70 or more here. A pooled transport reuses them:
	// a connection is back in the pool before its body read returns EOF, so none
	// should be dialled at all, and the bound is simply far from the old behaviour.
	opened := srv.opened.Load() - concurrency
	assert.LessOrEqual(t, opened, int64(concurrency),
		"%d more bursts of %d opened %d new connections", rounds, concurrency, opened)
}

// Closing one client's idle connections leaves another's alone. Checked by whether
// the next request opens a connection, rather than by waiting for one to close.
func TestBuildHTTPClient_CloseIdleConnectionsIsolated(t *testing.T) {
	srv, opened := countingServer(t, false)
	first, err := BuildHTTPClient(nil, false, 10*time.Second)
	require.NoError(t, err)
	second, err := BuildHTTPClient(nil, false, 10*time.Second)
	require.NoError(t, err)
	defer second.CloseIdleConnections()

	require.NoError(t, drain(first, srv.URL))
	require.NoError(t, drain(second, srv.URL))
	require.Equal(t, int64(2), opened.Load())

	first.CloseIdleConnections()

	require.NoError(t, drain(second, srv.URL))
	assert.Equal(t, int64(2), opened.Load(), "the second client still had its idle connection")

	require.NoError(t, drain(first, srv.URL))
	assert.Equal(t, int64(3), opened.Load(), "the first client's connection was closed")
	first.CloseIdleConnections()
}
