package dualgateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

// startPrivateCAServer starts a TLS server whose certificate is signed by a CA
// no system root store knows about — the shape of a Cloudflare-compatible store
// or a private IBM COS endpoint. Returns the server and its CA as the
// base64-encoded PEM the ca_data config field takes.
func startPrivateCAServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dualgateway-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)

	// httptest.NewTLSServer generates its own certificate and cannot be handed
	// one, so the server is built unstarted and its TLS config supplied first.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{srvDER},
			PrivateKey:  srvKey,
		}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	return srv, base64.StdEncoding.EncodeToString(caPEM)
}

// B6, and the assertion that matters: the handshake itself. A mount carrying
// the authority that signed its upstream reaches it; the same mount without one
// cannot, because the shared transport only ever trusted the system roots.
func TestTLS_PrivateCAIsTrustedOnlyWhenConfigured(t *testing.T) {
	srv, caData := startPrivateCAServer(t)

	t.Run("with ca_data", func(t *testing.T) {
		b := createBackendWithConfig(t, headerAuthSpec, map[string]any{
			"test_url": srv.URL,
			"ca_data":  caData,
		})

		resp, err := roundTrip(t, b, srv.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("without ca_data", func(t *testing.T) {
		b := createBackendWithConfig(t, headerAuthSpec, map[string]any{
			"test_url": srv.URL,
		})

		_, err := roundTrip(t, b, srv.URL)
		require.Error(t, err, "an unknown authority must not be trusted")
		assert.Contains(t, err.Error(), "certificate")
	})
}

// roundTrip drives the transport the gateway legs use, which is the only thing
// that distinguishes a mount that trusts its upstream from one that does not.
func roundTrip(t *testing.T, b *dualgatewayBackend, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	return b.Transport().RoundTrip(req)
}

// The mount rides the shared transport unless it asks for its own. Asserting on
// b.Transport() could not show this: that returns a stable wrapper, identical
// before and after any swap.
func TestTLS_SharedTransportUnlessOverridden(t *testing.T) {
	b := createBackend(t, headerAuthSpec)
	assert.Nil(t, b.installedTransport, "no TLS overrides means no per-mount transport")

	writeConfig(t, b, map[string]any{"tls_skip_verify": true})
	assert.NotNil(t, b.installedTransport, "tls_skip_verify alone earns a per-mount transport")

	// And it is given back when the overrides go away.
	writeConfig(t, b, map[string]any{"tls_skip_verify": false})
	assert.Nil(t, b.installedTransport)
}

// A config write that cannot be applied must change nothing. The transport is
// built before any state is touched precisely so a mount serving traffic is not
// left pointing at an upstream it can no longer reach.
func TestTLS_InvalidCADataLeavesMountUntouched(t *testing.T) {
	live := createBackendWithConfig(t, headerAuthSpec, map[string]any{
		"test_url": "https://custom.test.com",
	})

	// Well-formed base64 carrying a well-formed PEM block that holds no usable
	// certificate: past validateConfig's pem.Decode, refused by the cert pool.
	// The failure therefore lands inside the apply, which is where the
	// build-before-mutate ordering has to hold.
	resp, err := live.handleConfigWrite(context.Background(), &logical.Request{},
		makeFieldData(live.pathConfig(), map[string]any{
			"test_url": "https://moved.test.com",
			"ca_data":  base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nbm9wZQ==\n-----END CERTIFICATE-----\n")),
		}))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	assert.Equal(t, "https://custom.test.com", live.providerURL,
		"a rejected write must not have moved the URL either")
	assert.Nil(t, live.installedTransport)
}

// The same input at mount time fails the mount outright rather than producing a
// backend that cannot reach its upstream.
func TestTLS_InvalidCADataFailsTheMount(t *testing.T) {
	factory := NewFactory(headerAuthSpec)
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      createTestLogger(),
		Config: map[string]any{
			"test_url": "https://custom.test.com",
			"ca_data":  "not-base64-at-all!!",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_data")
}

// A mount whose stored config will not load must refuse traffic. Core logs an
// Initialize failure and carries on, so the alternative is a mount serving on
// spec defaults — the vendor's public endpoint — while still injecting real
// credentials.
func TestInitialize_UnloadableConfigRefusesRequests(t *testing.T) {
	storage := newInmemStorage()
	entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
		"test_url": "https://custom.test.com",
		// Decodes as base64 into a well-formed PEM block that holds no usable
		// certificate: past the validator, refused when the pool is built.
		"ca_data": base64.StdEncoding.EncodeToString(
			[]byte("-----BEGIN CERTIFICATE-----\nbm9wZQ==\n-----END CERTIFICATE-----\n")),
	})
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	factory := NewFactory(headerAuthSpec)
	raw, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	})
	require.NoError(t, err)
	b := raw.(*dualgatewayBackend)

	require.Error(t, b.Initialize(context.Background()))

	rec := httptest.NewRecorder()
	b.handleGateway(context.Background(), &logical.Request{
		HTTPRequest:    httptest.NewRequest("GET", "/gateway/anything", nil),
		ResponseWriter: rec,
	})

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a mount that could not load its config must not fall back to the vendor default")
}

// Trust must survive a restart. The stored config is replayed through the same
// apply path on unseal — without that, a private-CA mount works until the first
// restart and then silently falls back to the system roots.
func TestTLS_SurvivesInitializeFromStorage(t *testing.T) {
	srv, caData := startPrivateCAServer(t)

	storage := newInmemStorage()
	entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
		"test_url":        srv.URL,
		"max_body_size":   float64(1048576), // JSON round-trips numbers as float64
		"timeout":         "45s",
		"auto_auth_path":  "auth/cert/",
		"default_role":    "reader",
		"tls_skip_verify": false,
		"ca_data":         caData,
	})
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	factory := NewFactory(headerAuthSpec)
	raw, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	})
	require.NoError(t, err)
	b := raw.(*dualgatewayBackend)
	require.NoError(t, b.Initialize(context.Background()))

	resp, err := roundTrip(t, b, srv.URL)
	require.NoError(t, err, "the stored authority must be rebuilt on load")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The rest of the stored entry must come back with it.
	got := readConfig(t, b)
	assert.Equal(t, int64(1048576), got["max_body_size"])
	assert.Equal(t, "45s", got["timeout"])
	assert.Equal(t, "auth/cert/", got["auto_auth_path"])
}
