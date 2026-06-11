package cert

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fedTestTD = "partner.example.org"

// countingEndpoint serves body over TLS and counts the requests it receives.
func countingEndpoint(t *testing.T, body []byte) (*httptest.Server, *int64) {
	t.Helper()
	var n int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&n, 1)
		_, _ = w.Write(body)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &n
}

// fastLoopBackend returns a spiffe-mode backend with a federated https_web trust
// domain pointing at a counting endpoint, and loop intervals shrunk so the loop
// refreshes every tick (the bundle carries no sequence, so each fetch re-applies).
func fastLoopBackend(t *testing.T) (*certAuthBackend, context.Context, *int64, *x509.Certificate) {
	caCert, caKey, _ := testCA(t)
	srv, fetches := countingEndpoint(t, marshalBundle(t, fedTestTD, []*x509.Certificate{caCert}, 0))

	b, ctx := spiffeFederationBackend(t)
	b.fedTickInterval = 5 * time.Millisecond
	b.fedMinRefresh = time.Millisecond
	b.fedDefaultRefresh = time.Millisecond
	writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    fedTestTD,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})
	svid := testSVID(t, caCert, caKey, "spiffe://"+fedTestTD+"/ns/x/sa/y")
	return b, ctx, fetches, svid
}

func requireEventuallyVerifies(t *testing.T, b *certAuthBackend, svid *x509.Certificate) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, _, err := verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, fedTestTD), nil)
		return err == nil
	}, 2*time.Second, 5*time.Millisecond)
}

// assertStopped checks that refreshing has frozen: it counted at least once, and
// after a stop no further fetches happen.
func assertStopped(t *testing.T, fetches *int64) {
	t.Helper()
	time.Sleep(20 * time.Millisecond) // let any in-flight fetch finish
	n := atomic.LoadInt64(fetches)
	require.Greater(t, n, int64(0), "loop never refreshed")
	time.Sleep(40 * time.Millisecond) // several tick intervals
	assert.Equal(t, n, atomic.LoadInt64(fetches), "refresh loop kept running after stop")
}

// TestFederationRefreshDue covers the per-tick due logic without timing.
func TestFederationRefreshDue(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	srv, fetches := countingEndpoint(t, marshalBundle(t, fedTestTD, []*x509.Certificate{caCert}, 1))

	b, ctx := spiffeFederationBackend(t)
	writeTrustDomain(t, b, ctx, map[string]any{
		"name":                    fedTestTD,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})

	// Never fetched -> due -> primes the verification set.
	b.refreshDueTrustDomains(ctx)
	require.Equal(t, int64(1), atomic.LoadInt64(fetches))
	svid := testSVID(t, caCert, caKey, "spiffe://"+fedTestTD+"/ns/x/sa/y")
	_, _, err := verifySPIFFE(b.snapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, fedTestTD), nil)
	require.NoError(t, err)

	// Just refreshed (default interval) -> not due -> no second fetch.
	b.refreshDueTrustDomains(ctx)
	assert.Equal(t, int64(1), atomic.LoadInt64(fetches))
}

func TestFederationLoop_StopFederationRefresh(t *testing.T) {
	b, ctx, fetches, svid := fastLoopBackend(t)
	b.startFederationRefresh(ctx)
	requireEventuallyVerifies(t, b, svid)
	b.stopFederationRefresh()
	assertStopped(t, fetches)
}

func TestFederationLoop_StopsOnContextCancel(t *testing.T) {
	b, ctx, fetches, svid := fastLoopBackend(t)
	loopCtx, cancel := context.WithCancel(ctx)
	b.startFederationRefresh(loopCtx) // simulates the active context
	requireEventuallyVerifies(t, b, svid)
	cancel() // simulates step-down
	assertStopped(t, fetches)
}

func TestFederationLoop_CleanStops(t *testing.T) {
	b, ctx, fetches, svid := fastLoopBackend(t)
	b.startFederationRefresh(ctx)
	requireEventuallyVerifies(t, b, svid)
	b.Cleanup(context.Background()) // framework Cleanup -> Clean -> stopFederationRefresh
	assertStopped(t, fetches)
}
