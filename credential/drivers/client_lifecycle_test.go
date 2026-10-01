package drivers

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
)

// closeCountingServer answers every request and counts the connections it sees
// closed. /version accepts only "Bearer valid-token", as a Kubernetes API server
// would for the source token.
func closeCountingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var closed atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/version" && r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"kind":"Status","code":401}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"gitVersion": "v1.29.0"})
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed {
			closed.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &closed
}

// get makes one request and drains it, leaving the connection idle in the pool.
func get(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp, err := client.Get(url)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
}

func awaitClosed(t *testing.T, closed *atomic.Int64, atLeast int64, why string) {
	t.Helper()
	require.Eventually(t, func() bool { return closed.Load() >= atLeast },
		2*time.Second, 10*time.Millisecond, why)
}

func builtClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := BuildHTTPClient(credential.NewConfig(map[string]string{}), 5*time.Second)
	require.NoError(t, err)
	return c
}

// Every driver releases its client's pooled connections when it is closed — on
// source update or delete, or after a validation build.
func TestDriverCleanup_ClosesIdleConnections(t *testing.T) {
	cases := []struct {
		name   string
		driver func(*http.Client) credential.SourceDriver
	}{
		{"aws", func(c *http.Client) credential.SourceDriver { return &AWSDriver{httpClient: c} }},
		{"ibm", func(c *http.Client) credential.SourceDriver { return &IBMDriver{httpClient: c} }},
		{"vault", func(c *http.Client) credential.SourceDriver { return &VaultDriver{httpClient: c} }},
		{"openai", func(c *http.Client) credential.SourceDriver { return &OpenAIDriver{httpClient: c} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, closed := closeCountingServer(t)
			client := builtClient(t)
			get(t, client, srv.URL)

			require.NoError(t, tc.driver(client).Cleanup(context.Background()))
			awaitClosed(t, closed, 1, "Cleanup must close the driver's idle connections")
		})
	}
}

// The vault driver's API client keeps a pool of its own, closed along with the
// driver's other client.
func TestVaultDriverCleanup_ClosesAPIClient(t *testing.T) {
	srv, closed := closeCountingServer(t)
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	apiClient, err := api.NewClient(cfg)
	require.NoError(t, err)
	_, err = apiClient.Logical().ReadWithContext(context.Background(), "sys/anything")
	require.NoError(t, err)

	d := &VaultDriver{vault: apiClient, httpClient: builtClient(t)}
	require.NoError(t, d.Cleanup(context.Background()))
	awaitClosed(t, closed, 1, "Cleanup must close the API client's idle connections")
}

// A rotation that changes the TLS settings replaces the client; the replaced one
// must not keep its connections.
func TestKubernetesDriver_CommitRotation_ClosesReplacedClient(t *testing.T) {
	srv, closed := closeCountingServer(t)
	old := builtClient(t)
	d := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: credential.NewConfig(map[string]string{
				"kubernetes_url": srv.URL,
				"token":          "old-token",
			}),
		},
		httpClient: old,
	}

	// The new token is verified over the current client, which leaves it an idle
	// connection; the new TLS setting then replaces that client.
	require.NoError(t, d.CommitRotation(context.Background(), map[string]string{
		"kubernetes_url":  srv.URL,
		"token":           "valid-token",
		"tls_skip_verify": "true",
	}))
	assert.NotSame(t, old, d.httpClientSnapshot())
	awaitClosed(t, closed, 1, "the replaced client's idle connections must be closed")
}

// A driver whose connection check fails is discarded; it must not leave the check's
// connection open.
func TestKubernetesDriverFactory_Create_FailedCheckClosesClient(t *testing.T) {
	srv, closed := closeCountingServer(t)
	_, err := (&KubernetesDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"kubernetes_url": srv.URL,
		"token":          "wrong-token",
	}), newTestLogger(t))
	require.Error(t, err)
	awaitClosed(t, closed, 1, "a discarded driver must close the connection its check opened")
}
