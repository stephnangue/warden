package kubernetes

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// closeCountingServer counts the connections it sees closed, to observe a client
// releasing its idle connections.
func closeCountingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var closed atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
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

// useClient makes one request on the live config's client, leaving an idle
// connection in its pool.
func useClient(t *testing.T, b *kubernetesAuthBackend, url string) *http.Client {
	t.Helper()
	b.configMu.RLock()
	client := b.config.httpClient
	b.configMu.RUnlock()
	resp, err := client.Get(url)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	return client
}

func awaitClosed(t *testing.T, closed *atomic.Int64, atLeast int64, why string) {
	t.Helper()
	require.Eventually(t, func() bool { return closed.Load() >= atLeast },
		2*time.Second, 10*time.Millisecond, why)
}

// Each config write builds a new TokenReview client; the one it replaces must not
// keep its connections open.
func TestInstallConfig_ClosesReplacedClient(t *testing.T) {
	srv, closed := closeCountingServer(t)
	b, ctx := newTestBackend(t)
	conf := map[string]any{"kubernetes_host": srv.URL, "tls_skip_verify": true}

	require.NoError(t, b.setupConfig(ctx, conf))
	old := useClient(t, b, srv.URL)

	require.NoError(t, b.setupConfig(ctx, conf))
	awaitClosed(t, closed, 1, "replacing the config must close the old client's idle connections")

	b.configMu.RLock()
	require.NotSame(t, old, b.config.httpClient)
	b.configMu.RUnlock()
}

// Unmount and seal release the live client's connections.
func TestClean_ClosesLiveClient(t *testing.T) {
	srv, closed := closeCountingServer(t)
	b, ctx := newTestBackend(t)
	require.NoError(t, b.setupConfig(ctx, map[string]any{"kubernetes_host": srv.URL, "tls_skip_verify": true}))
	useClient(t, b, srv.URL)

	b.Cleanup(context.Background())
	awaitClosed(t, closed, 1, "Clean must close the live client's idle connections")

	// The config stays: the next request dials again rather than failing.
	useClient(t, b, srv.URL)
}
