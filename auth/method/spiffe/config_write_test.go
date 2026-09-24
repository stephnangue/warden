package spiffe

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

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

func writeConfig(b *spiffeAuthBackend, raw map[string]any) *logical.Response {
	resp, _ := b.handleConfigWrite(context.Background(), &logical.Request{},
		&framework.FieldData{Raw: raw, Schema: b.pathConfig().Fields})
	return resp
}

// A write that cannot be persisted is not installed either. Before, the new
// config was live by the time the storage write failed.
func TestConfigWrite_UnpersistedWriteNotApplied(t *testing.T) {
	b, _ := createTestBackend(t)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"default_role": "reader"}).StatusCode)
	before := b.config
	b.storageView = failingStorage{newInmemStorage()}

	resp := writeConfig(b, map[string]any{"default_role": "admin"})
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Same(t, before, b.config, "an unpersisted write must not have been installed")
}

// Two partial writes racing each merge onto the configuration the other left,
// so neither loses the other's key. Before, both could merge onto the same
// snapshot and the second to install undid the first.
func TestConfigWrite_ConcurrentPartialWritesKeepEveryKey(t *testing.T) {
	for i := 0; i < 50; i++ {
		b, _ := createTestBackend(t)

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
			writeConfig(b, map[string]any{"token_ttl": 600})
		}()
		close(start)
		wg.Wait()

		require.Equal(t, "reader", b.config.DefaultRole, "iteration %d lost the default_role write", i)
		require.Equal(t, 10*time.Minute, b.config.TokenTTL, "iteration %d lost the token_ttl write", i)
	}
}
