package spiffe

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

// --- on-demand fetch + apply ---

func TestFederation_HTTPSWeb(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	const td = "partner.example.org"
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 1), nil)

	m, ctx := newTestManager(t)
	resp := writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	svid := testSVID(t, caCert, caKey, "spiffe://"+td+"/ns/default/sa/api")

	// Before the first fetch the trust domain has no authorities -> fails closed.
	_, _, err := VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.Error(t, err)

	rr := refreshTrustDomain(t, m, ctx, td)
	require.Equal(t, http.StatusOK, rr.StatusCode)
	assert.Equal(t, true, rr.Data["changed"])

	id, _, err := VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://"+td+"/ns/default/sa/api", id.String())
}

// Federation also delivers JWT authorities: an endpoint serving a JWKS with a
// jwt-svid key lets the trust domain verify a JWT-SVID after a refresh.
func TestFederation_JWTBundle(t *testing.T) {
	auth := newJWTAuthority(t)
	const td = "partner.example.org"
	srv := startBundleEndpoint(t, []byte(auth.bundleJSON(t, td, 1)), nil)

	m, ctx := newTestManager(t)
	writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})

	token := auth.sign(t, "spiffe://"+td+"/ns/default/sa/api", []string{"warden"}, time.Now().Add(time.Hour))

	// Before the fetch, no JWT authority is loaded -> fails closed.
	_, err := VerifyJWTSVID(m.SnapshotBundleSet(), token, []string{"warden"}, mustTD(t, td), nil)
	require.Error(t, err)

	rr := refreshTrustDomain(t, m, ctx, td)
	require.Equal(t, http.StatusOK, rr.StatusCode)
	assert.Equal(t, true, rr.Data["changed"])

	svid, err := VerifyJWTSVID(m.SnapshotBundleSet(), token, []string{"warden"}, mustTD(t, td), nil)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://"+td+"/ns/default/sa/api", svid.ID.String())
}

func TestFederation_HTTPSSpiffe(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	const td = "partner.example.org"
	endpointID := "spiffe://" + td + "/spire/server"
	endpointCert := endpointSVIDCert(t, caCert, caKey, endpointID)
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 1), &endpointCert)

	m, ctx := newTestManager(t)
	resp := writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_spiffe",
		"endpoint_spiffe_id":      endpointID,
		"bundle_pem":              caPEM, // bootstrap, authenticates the endpoint SVID
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rr := refreshTrustDomain(t, m, ctx, td)
	require.Equal(t, http.StatusOK, rr.StatusCode)
	assert.Equal(t, true, rr.Data["changed"])

	svid := testSVID(t, caCert, caKey, "spiffe://"+td+"/ns/default/sa/api")
	_, _, err := VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err)
}

func TestFederation_HTTPSSpiffe_WrongEndpointID(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	const td = "partner.example.org"
	endpointCert := endpointSVIDCert(t, caCert, caKey, "spiffe://"+td+"/spire/server")
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 1), &endpointCert)

	m, ctx := newTestManager(t)
	writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_spiffe",
		"endpoint_spiffe_id":      "spiffe://" + td + "/spire/wrong",
		"bundle_pem":              caPEM,
	})

	rr := refreshTrustDomain(t, m, ctx, td)
	assert.Equal(t, http.StatusBadGateway, rr.StatusCode)
}

func TestFederation_SequenceDedup(t *testing.T) {
	caCert, _, _ := testCA(t)
	const td = "partner.example.org"
	srv := startBundleEndpoint(t, marshalBundle(t, td, []*x509.Certificate{caCert}, 5), nil)

	m, ctx := newTestManager(t)
	writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})

	first := refreshTrustDomain(t, m, ctx, td)
	assert.Equal(t, true, first.Data["changed"])

	second := refreshTrustDomain(t, m, ctx, td) // same sequence -> no change
	assert.Equal(t, false, second.Data["changed"])
}

func TestFederation_EmptyBundleKeepsLastGood(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	const td = "partner.example.org"
	good := marshalBundle(t, td, []*x509.Certificate{caCert}, 1)
	empty := marshalBundle(t, td, nil, 2) // valid bundle, but no authorities

	var body atomic.Value
	body.Store(good)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body.Load().([]byte))
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)

	m, ctx := newTestManager(t)
	writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    td,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})
	require.Equal(t, http.StatusOK, refreshTrustDomain(t, m, ctx, td).StatusCode)

	svid := testSVID(t, caCert, caKey, "spiffe://"+td+"/ns/x/sa/y")
	_, _, err := VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err) // good bundle is active

	// The endpoint now serves an authority-less bundle: refresh must reject it...
	body.Store(empty)
	assert.Equal(t, http.StatusBadGateway, refreshTrustDomain(t, m, ctx, td).StatusCode)

	// ...and the last-good bundle must remain active.
	_, _, err = VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, td), nil)
	require.NoError(t, err)
}

func TestFederation_RefreshRejectsStaticTrustDomain(t *testing.T) {
	_, _, caPEM := testCA(t)
	const td = "static.example.org"
	m, ctx := newTestManager(t)
	writeTrustDomain(t, m, ctx, map[string]any{"name": td, "bundle_pem": caPEM})

	rr := refreshTrustDomain(t, m, ctx, td)
	assert.Equal(t, http.StatusBadRequest, rr.StatusCode)
	assert.Contains(t, rr.Err.Error(), "no bundle endpoint")
}

// --- background refresh loop ---

// fastLoopManager returns a Manager with a federated https_web trust domain
// pointing at a counting endpoint, and loop intervals shrunk so the loop
// refreshes every tick (the bundle carries no sequence, so each fetch re-applies).
func fastLoopManager(t *testing.T) (*Manager, context.Context, *int64, *x509.Certificate) {
	caCert, caKey, _ := testCA(t)
	srv, fetches := countingEndpoint(t, marshalBundle(t, fedTestTD, []*x509.Certificate{caCert}, 0))

	m, ctx := newTestManager(t)
	m.tickInterval = 5 * time.Millisecond
	m.minRefresh = time.Millisecond
	m.defaultRefresh = time.Millisecond
	writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    fedTestTD,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})
	svid := testSVID(t, caCert, caKey, "spiffe://"+fedTestTD+"/ns/x/sa/y")
	return m, ctx, fetches, svid
}

func requireEventuallyVerifies(t *testing.T, m *Manager, svid *x509.Certificate) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, _, err := VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, fedTestTD), nil)
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

	m, ctx := newTestManager(t)
	writeTrustDomain(t, m, ctx, map[string]any{
		"name":                    fedTestTD,
		"bundle_endpoint_url":     srv.URL,
		"bundle_endpoint_profile": "https_web",
		"web_pki_ca_pem":          certPEM(srv.Certificate()),
	})

	// Never fetched -> due -> primes the verification set.
	m.refreshDueTrustDomains(ctx)
	require.Equal(t, int64(1), atomic.LoadInt64(fetches))
	svid := testSVID(t, caCert, caKey, "spiffe://"+fedTestTD+"/ns/x/sa/y")
	_, _, err := VerifyX509SVID(m.SnapshotBundleSet(), []*x509.Certificate{svid}, mustTD(t, fedTestTD), nil)
	require.NoError(t, err)

	// Just refreshed (default interval) -> not due -> no second fetch.
	m.refreshDueTrustDomains(ctx)
	assert.Equal(t, int64(1), atomic.LoadInt64(fetches))
}

func TestFederationLoop_Stop(t *testing.T) {
	m, ctx, fetches, svid := fastLoopManager(t)
	m.StartFederationRefresh(ctx)
	requireEventuallyVerifies(t, m, svid)
	m.Stop()
	assertStopped(t, fetches)
}

func TestFederationLoop_StopsOnContextCancel(t *testing.T) {
	m, ctx, fetches, svid := fastLoopManager(t)
	loopCtx, cancel := context.WithCancel(ctx)
	m.StartFederationRefresh(loopCtx) // simulates the active context
	requireEventuallyVerifies(t, m, svid)
	cancel() // simulates step-down
	assertStopped(t, fetches)
}
