package cert

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

func writeConfig(b *certAuthBackend, raw map[string]any) *logical.Response {
	resp, _ := b.handleConfigWrite(context.Background(), &logical.Request{},
		&framework.FieldData{Raw: raw, Schema: b.pathConfig().Fields})
	return resp
}

// A write that cannot be persisted is not installed either: logins keep being
// judged by what storage holds. Before, the new config was live by the time
// the storage write failed.
func TestConfigWrite_UnpersistedWriteNotApplied(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, _ := createTestBackend(t)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"trusted_ca_pem": caPEM, "ocsp_timeout": "3s",
	}).StatusCode)
	before := b.config
	b.storageView = failingStorage{newInmemStorage()}

	resp := writeConfig(b, map[string]any{"ocsp_timeout": "4s", "revocation_mode": "crl"})
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Same(t, before, b.config, "an unpersisted write must not have been installed")
	assert.Nil(t, b.config.revocationChecker)
}

// Two partial writes racing each merge onto the configuration the other left,
// so neither loses the other's key. Before, both could merge onto the same
// snapshot and the second to install undid the first.
func TestConfigWrite_ConcurrentPartialWritesKeepEveryKey(t *testing.T) {
	_, _, caPEM := testCA(t)
	for i := 0; i < 50; i++ {
		b, _ := createTestBackend(t)
		require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"trusted_ca_pem": caPEM}).StatusCode)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			writeConfig(b, map[string]any{"ocsp_timeout": "3s"})
		}()
		go func() {
			defer wg.Done()
			<-start
			writeConfig(b, map[string]any{"principal_claim": "dns_san"})
		}()
		close(start)
		wg.Wait()

		require.Equal(t, "3s", b.config.OCSPTimeout, "iteration %d lost the ocsp_timeout write", i)
		require.Equal(t, "dns_san", b.config.PrincipalClaim, "iteration %d lost the principal_claim write", i)
	}
}

// Logins run while config writes switch revocation checking on and off; run
// under -race. Before, the revocation checker was replaced outside the lock
// that logins read it under.
func TestLogin_ConcurrentWithConfigWrites(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")
	b, ctx := createTestBackend(t)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"trusted_ca_pem": caPEM}).StatusCode)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			mode := "none"
			if i%2 == 0 {
				mode = "crl"
			}
			writeConfig(b, map[string]any{"revocation_mode": mode})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, err := b.handleLogin(ctx,
				&logical.Request{HTTPRequest: newCertHTTPRequest(t, clientCert)},
				&framework.FieldData{Raw: map[string]any{}, Schema: b.pathLogin().Fields})
			assert.NoError(t, err)
		}
	}()
	wg.Wait()
}
