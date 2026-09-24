package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// failingStorage refuses every write.
type failingStorage struct{ *inmemStorage }

func (failingStorage) Put(context.Context, *sdklogical.StorageEntry) error {
	return errors.New("storage unavailable")
}

func writeConfig(b *kubernetesAuthBackend, raw map[string]any) *logical.Response {
	resp, _ := b.handleConfigWrite(context.Background(), &logical.Request{},
		&framework.FieldData{Raw: raw, Schema: b.pathConfig().Fields})
	return resp
}

// A write that cannot be persisted is not installed either: TokenReviews keep
// going to the cluster that storage names. Before, the new config — host, TLS
// client and all — was live by the time the storage write failed.
func TestConfigWrite_UnpersistedWriteNotApplied(t *testing.T) {
	b, _ := newTestBackend(t)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"kubernetes_host": "https://10.0.0.1:6443", "tls_skip_verify": true,
	}).StatusCode)
	before := b.config
	b.storageView = failingStorage{newInmemStorage()}

	resp := writeConfig(b, map[string]any{"kubernetes_host": "https://10.9.9.9:6443"})
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Same(t, before, b.config, "an unpersisted write must not have been installed")
}

// Two partial writes racing each merge onto the configuration the other left,
// so neither loses the other's key. Before, both could merge onto the same
// snapshot and the second to install undid the first.
func TestConfigWrite_ConcurrentPartialWritesKeepEveryKey(t *testing.T) {
	for i := 0; i < 50; i++ {
		b, _ := newTestBackend(t)
		require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
			"kubernetes_host": "https://10.0.0.1:6443", "tls_skip_verify": true,
		}).StatusCode)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			writeConfig(b, map[string]any{"default_role": "reader"})
		}()
		go func() {
			defer wg.Done()
			<-start
			writeConfig(b, map[string]any{"issuer": "https://kubernetes.default.svc"})
		}()
		close(start)
		wg.Wait()

		require.Equal(t, "reader", b.config.DefaultRole, "iteration %d lost the default_role write", i)
		require.Equal(t, "https://kubernetes.default.svc", b.config.Issuer, "iteration %d lost the issuer write", i)
	}
}
