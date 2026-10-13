package azure

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forwardRecorder answers 200 and records the host each forwarded request
// went to, and the Authorization it carried.
type forwardRecorder struct {
	hosts []string
	auth  []string
}

func (f *forwardRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	f.hosts = append(f.hosts, r.URL.Host)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func gatewayRequest(path string) (*logical.Request, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	return &logical.Request{
		HTTPRequest:    httptest.NewRequest(http.MethodGet, path, nil),
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAzureBearerToken,
			Data: map[string]string{"access_token": "eyJ.entra.token"},
		},
	}, rec
}

// The host in the gateway path is the client's, and the request leaves for it
// carrying the Entra token: a host off the allowlist is refused before any
// token is attached, and nothing is forwarded.
func TestHandleGateway_HostAllowlist(t *testing.T) {
	for _, tc := range []struct {
		host   string
		status int
	}{
		{"management.azure.com", http.StatusOK},
		{"graph.microsoft.com", http.StatusOK},
		{"myvault.vault.azure.net", http.StatusOK},
		{"mystorage.blob.core.windows.net", http.StatusOK},
		{"my-resource.openai.azure.com", http.StatusOK},
		{"my-resource.services.ai.azure.com", http.StatusOK},
		{"attacker.example", http.StatusForbidden},
		// A VM's public DNS name: a host under azure.com a customer controls.
		{"attacker.eastus.cloudapp.azure.com", http.StatusForbidden},
		// A storage account's static website serves customer content.
		{"attacker.z13.web.core.windows.net", http.StatusForbidden},
		{"management.azure.com.attacker.example", http.StatusForbidden},
		{"169.254.169.254", http.StatusBadRequest},
		{"localhost", http.StatusBadRequest},
		{"management.azure.com:8443", http.StatusBadRequest},
		{"x@management.azure.com", http.StatusBadRequest},
		{"Management.azure.com", http.StatusBadRequest},
		// Both end in an allowed suffix once decoded, yet would be sent to
		// attacker.example: the hostname check, not the allowlist, stops them.
		{"attacker.example%23.management.azure.com", http.StatusBadRequest},
		{"management.azure.com%40attacker.example", http.StatusBadRequest},
	} {
		t.Run(tc.host, func(t *testing.T) {
			upstream := &forwardRecorder{}
			b := setupBackend(t)
			b.StreamingBackend.InitProxy(upstream)

			req, rec := gatewayRequest("/azure/gateway/" + tc.host + "/v1/x")
			b.handleGateway(context.Background(), req)

			assert.Equal(t, tc.status, rec.Code, rec.Body.String())
			if tc.status == http.StatusOK {
				require.Equal(t, []string{tc.host}, upstream.hosts)
				assert.Equal(t, "Bearer eyJ.entra.token", upstream.auth[0])
			} else {
				assert.Empty(t, upstream.hosts, "the request was forwarded")
			}
		})
	}
}

// A Graph $batch body carries requests path policy never sees, so it is refused
// on a Graph host whatever the policy allowed, in every spelling; ARM's own
// /batch, and Graph paths that merely resemble it, still go through.
func TestHandleGateway_GraphBatchRefused(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/azure/gateway/graph.microsoft.com/v1.0/$batch", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/beta/$batch", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/V1.0/$Batch/", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/v1.0/me/../$batch", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/v1.0/%24batch", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/v1.0%5C$batch", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/v1.0/$batch;x=1", http.StatusBadRequest},
		{"/azure/gateway/graph.microsoft.com/v1.0/me/messages", http.StatusOK},
		{"/azure/gateway/management.azure.com/batch", http.StatusOK},
	} {
		t.Run(tc.path, func(t *testing.T) {
			upstream := &forwardRecorder{}
			b := setupBackend(t)
			b.StreamingBackend.InitProxy(upstream)

			req, rec := gatewayRequest(tc.path)
			req.HTTPRequest.Method = http.MethodPost
			b.handleGateway(context.Background(), req)

			assert.Equal(t, tc.status, rec.Code, rec.Body.String())
			if tc.status != http.StatusOK {
				assert.Empty(t, upstream.hosts, "a refused batch must not be forwarded")
				assert.Contains(t, rec.Body.String(), "$batch")
			}
		})
	}
}

// An operator's allowlist replaces the default, and an empty one restores it.
func TestConfigWrite_HostAllowlist(t *testing.T) {
	storage := newInmemStorage()
	b := configuredBackend(storage)
	upstream := &forwardRecorder{}
	b.StreamingBackend.InitProxy(upstream)
	reach := func(host string) int {
		req, rec := gatewayRequest("/azure/gateway/" + host + "/v1/x")
		b.handleGateway(context.Background(), req)
		return rec.Code
	}

	resp := writeConfig(b, map[string]interface{}{framework.HostAllowlistKey: []interface{}{".private.example.com"}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.StatusOK, reach("api.private.example.com"))
	assert.Equal(t, http.StatusForbidden, reach("management.azure.com"))

	read, err := b.handleConfigRead(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{".private.example.com"}, read.Data[framework.HostAllowlistKey])

	// A suffix without its leading dot is refused, and changes nothing.
	resp = writeConfig(b, map[string]interface{}{framework.HostAllowlistKey: []interface{}{"management.azure.com"}})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, http.StatusOK, reach("api.private.example.com"))

	// A write that does not name the allowlist keeps it, running and stored.
	resp = writeConfig(b, map[string]interface{}{"timeout": 60})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.StatusForbidden, reach("management.azure.com"))
	restarted := setupBackend(t)
	restarted.StorageView = storage
	require.NoError(t, restarted.Initialize(context.Background()))
	assert.Equal(t, []string{".private.example.com"}, restarted.hostAllowlist())

	resp = writeConfig(b, map[string]interface{}{framework.HostAllowlistKey: []interface{}{}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.StatusOK, reach("management.azure.com"))
	assert.Equal(t, http.StatusForbidden, reach("api.private.example.com"))
}

// The operator's allowlist survives a restart; a mount that never named one
// keeps following the default.
func TestInitialize_HostAllowlist(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"auto_auth_path":           "auth/jwt/",
		framework.HostAllowlistKey: []string{".private.example.com"},
	})
	require.NoError(t, storage.Put(context.Background(), entry))
	b := setupBackend(t)
	b.StorageView = storage
	require.NoError(t, b.Initialize(context.Background()))
	assert.Equal(t, []string{".private.example.com"}, b.hostAllowlist())

	fresh := setupBackend(t)
	fresh.StorageView = newInmemStorage()
	require.NoError(t, fresh.Initialize(context.Background()))
	assert.Equal(t, defaultAllowedHostSuffixes, fresh.hostAllowlist())
	assert.Nil(t, fresh.configuredHostAllowlist())

	// A stored allowlist that does not parse falls back to the default, and
	// the rest of the stored config still loads.
	tampered := newInmemStorage()
	entry, _ = sdklogical.StorageEntryJSON("config", map[string]any{
		"auto_auth_path":           "auth/cert/",
		framework.HostAllowlistKey: []string{"*"},
	})
	require.NoError(t, tampered.Put(context.Background(), entry))
	b = setupBackend(t)
	b.StorageView = tampered
	require.NoError(t, b.Initialize(context.Background()))
	assert.Equal(t, defaultAllowedHostSuffixes, b.hostAllowlist())
	assert.Equal(t, "auth/cert/", b.TransparentConfig().AutoAuthPath)
}

// The allowlist can be set when the provider is mounted, and a bad one stops
// the mount.
func TestFactory_HostAllowlist(t *testing.T) {
	b, err := Factory(context.Background(), &logical.BackendConfig{
		Logger: testLogger(),
		Config: map[string]any{framework.HostAllowlistKey: []any{".private.example.com"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{".private.example.com"}, b.(*azureBackend).hostAllowlist())

	_, err = Factory(context.Background(), &logical.BackendConfig{
		Logger: testLogger(),
		Config: map[string]any{framework.HostAllowlistKey: []any{"*"}},
	})
	require.Error(t, err)
}
